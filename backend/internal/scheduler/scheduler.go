package scheduler

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/logger"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/proxypool"
	"github.com/reconmaster/backend/internal/scanner"
	"github.com/reconmaster/backend/internal/services"
	"github.com/robfig/cron/v3"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Scheduler 调度器
type Scheduler struct {
	cron               *cron.Cron
	taskService        *services.TaskService
	runningMonitors    map[string]bool // 正在执行的监控任务 ID
	runningMonitorsMux sync.Mutex
}

var ErrMonitorAlreadyRunning = errors.New("monitor is already running")

// NewScheduler 创建调度器
func NewScheduler(taskService *services.TaskService) *Scheduler {
	return &Scheduler{
		cron:            cron.New(),
		taskService:     taskService,
		runningMonitors: make(map[string]bool),
	}
}

// Start 启动调度器
func (s *Scheduler) Start() {
	logger.Info("Scheduler started")

	// 启动监控任务检查
	s.cron.AddFunc("@every 1m", s.checkMonitorTasks)

	// 启动计划任务检查
	s.cron.AddFunc("@every 1m", s.checkScheduledTasks)

	s.cron.Start()
}

// Stop 停止调度器
func (s *Scheduler) Stop() {
	s.cron.Stop()
	logger.Info("Scheduler stopped")
}

// checkMonitorTasks 检查并执行监控任务
func (s *Scheduler) checkMonitorTasks() {
	var monitors []models.Monitor

	// 查询活跃的监控任务
	if err := database.DB.Where("status = ?", models.MonitorStatusActive).Find(&monitors).Error; err != nil {
		logger.Error("Failed to load active monitors: %v", err)
		return
	}

	now := time.Now()

	for _, monitor := range monitors {
		// 检查是否需要执行
		if monitor.NextRunTime != nil && now.After(*monitor.NextRunTime) {
			logger.Info("Executing monitor task: %s (RunCount: %d)", monitor.Name, monitor.RunCount)
			if err := s.launchMonitor(&monitor, now); err != nil && !errors.Is(err, ErrMonitorAlreadyRunning) {
				logger.Error("Failed to launch monitor %s: %v", monitor.Name, err)
			}
		} else if monitor.NextRunTime == nil {
			// 首次执行，设置下次运行时间
			nextRun := now.Add(time.Duration(monitor.Interval) * time.Second)
			monitor.NextRunTime = &nextRun
			if err := database.DB.Save(&monitor).Error; err != nil {
				logger.Error("Failed to initialize next run for monitor %s: %v", monitor.Name, err)
			}
		}
	}
}

// RunMonitorNow queues one monitor through the same concurrency and accounting
// path used by scheduled runs.
func (s *Scheduler) RunMonitorNow(monitorID string) error {
	var monitor models.Monitor
	if err := database.DB.First(&monitor, "id = ?", strings.TrimSpace(monitorID)).Error; err != nil {
		return err
	}
	return s.launchMonitor(&monitor, time.Now())
}

func (s *Scheduler) launchMonitor(monitor *models.Monitor, now time.Time) error {
	s.runningMonitorsMux.Lock()
	if s.runningMonitors[monitor.ID] {
		s.runningMonitorsMux.Unlock()
		return ErrMonitorAlreadyRunning
	}
	s.runningMonitors[monitor.ID] = true
	s.runningMonitorsMux.Unlock()

	monitor.LastRunTime = &now
	monitor.RunCount++
	nextRun := now.Add(time.Duration(monitor.Interval) * time.Second)
	monitor.NextRunTime = &nextRun
	monitor.LastError = ""
	if err := database.DB.Save(monitor).Error; err != nil {
		s.runningMonitorsMux.Lock()
		delete(s.runningMonitors, monitor.ID)
		s.runningMonitorsMux.Unlock()
		return err
	}
	go s.executeMonitorWithErrorHandling(monitor)
	return nil
}

// executeMonitorWithErrorHandling 执行监控任务（带错误处理）
func (s *Scheduler) executeMonitorWithErrorHandling(monitor *models.Monitor) {
	// 执行完成后清理运行标记
	defer func() {
		s.runningMonitorsMux.Lock()
		delete(s.runningMonitors, monitor.ID)
		s.runningMonitorsMux.Unlock()

		if r := recover(); r != nil {
			logger.Error("Monitor task panic: %v", r)
			publicMessage := "Monitor execution failed unexpectedly"
			if err := database.DB.Model(monitor).Update("last_error", publicMessage).Error; err != nil {
				logger.Error("Failed to persist monitor panic status: %v", err)
			}
			if err := s.recordMonitorResult(monitor, &models.MonitorResult{MonitorID: monitor.ID, ChangeType: "error", Description: publicMessage, Data: publicMessage}); err != nil {
				logger.Error("Failed to persist monitor panic result: %v", err)
			}
		}
	}()

	// 执行监控
	if err := s.executeMonitor(monitor); err != nil {
		logger.Error("Monitor task failed: %s - %v", monitor.Name, err)
		publicMessage := publicMonitorError(err)
		if err := database.DB.Model(monitor).Update("last_error", publicMessage).Error; err != nil {
			logger.Error("Failed to persist monitor error status: %v", err)
		}
		if err := s.recordMonitorResult(monitor, &models.MonitorResult{MonitorID: monitor.ID, ChangeType: "error", Description: fmt.Sprintf("监控 %s 执行失败", monitor.Name), Data: publicMessage}); err != nil {
			logger.Error("Failed to persist monitor error result: %v", err)
		}
	}
}

func publicMonitorError(err error) string {
	if services.IsMonitorInputError(err) || errors.Is(err, scanner.ErrGithubTokenNotConfigured) || errors.Is(err, scanner.ErrGithubIntegrationDisabled) {
		return err.Error()
	}
	return "Monitor execution failed"
}

func (s *Scheduler) recordMonitorResult(monitor *models.Monitor, result *models.MonitorResult) error {
	if err := database.DB.Create(result).Error; err != nil {
		return err
	}
	if result.ChangeType == "check" {
		return nil
	}
	selection := services.AllNotificationChannels()
	if raw := strings.TrimSpace(monitor.NotificationConfig); raw != "" {
		var monitorConfig models.NotificationConfig
		if err := json.Unmarshal([]byte(raw), &monitorConfig); err != nil {
			logger.Error("Invalid notification config for monitor %s: %v", monitor.Name, err)
			return nil
		}
		selection = services.NotificationSelection{Webhook: monitorConfig.EnableWebhook, DingTalk: monitorConfig.EnableDingDing, Feishu: monitorConfig.EnableFeishu}
	}
	notifier, err := services.LoadNotificationService(database.DB)
	if err != nil {
		logger.Error("Failed to load notification settings: %v", err)
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	severity := "medium"
	if result.ChangeType == "error" {
		severity = "high"
	}
	results := notifier.Send(ctx, services.NotificationEvent{
		Type: result.ChangeType, Title: "资产监控事件", Message: result.Description, Severity: severity,
		Target: monitor.Target, SourceID: monitor.ID, OccurredAt: result.CreatedAt,
		Data: map[string]any{"monitor_name": monitor.Name, "monitor_type": monitor.Type, "result": result.Data},
	}, selection)
	for _, delivery := range results {
		if !delivery.Success {
			logger.Error("Monitor notification failed: monitor=%s channel=%s error=%s", monitor.Name, delivery.Channel, delivery.Error)
		}
	}
	return nil
}

// executeMonitor 执行监控任务
func (s *Scheduler) executeMonitor(monitor *models.Monitor) error {
	logger.Info("Monitor task executing: %s (type: %s)", monitor.Name, monitor.Type)
	previousScopeID, previousTarget := monitor.ScopeID, monitor.Target
	targets, err := services.AuthorizeMonitorExecution(database.DB, monitor)
	if err != nil {
		return err
	}
	if monitor.ScopeID != previousScopeID || monitor.Target != previousTarget {
		if err := database.DB.Model(monitor).Updates(map[string]any{"scope_id": monitor.ScopeID, "target": monitor.Target}).Error; err != nil {
			return fmt.Errorf("persist monitor authorization: %w", err)
		}
	}
	if err := s.queueMonitorScan(monitor, targets); err != nil {
		if errors.Is(err, services.ErrTriggeredTaskActive) {
			logger.Info("Monitor scan task is still active; duplicate queueing skipped: %s", monitor.Name)
		} else {
			return err
		}
	}
	if monitor.AssetGroupID != nil && *monitor.AssetGroupID != "" {
		return s.executeAssetGroupMonitor(monitor, targets)
	}

	// 根据监控类型执行不同的逻辑
	switch monitor.Type {
	case models.MonitorTypeDomain:
		return s.executeDomainMonitor(monitor)
	case models.MonitorTypeIP:
		return s.executeIPMonitor(monitor)
	case models.MonitorTypeSite:
		return s.executeSiteMonitor(monitor)
	case models.MonitorTypeGithub:
		return s.executeGithubMonitor(monitor)
	case models.MonitorTypeWIH:
		return s.executeWIHMonitor(monitor)
	case models.MonitorTypeCVE:
		return s.executeCVEMonitor(monitor)
	default:
		return fmt.Errorf("unknown monitor type: %s", monitor.Type)
	}
}

func (s *Scheduler) queueMonitorScan(monitor *models.Monitor, targets []string) error {
	if s.taskService == nil || !services.MonitorRequiresScanScope(monitor.Type) || strings.TrimSpace(monitor.Options) == "" {
		return nil
	}
	target := strings.Join(targets, ",")
	options, enabled, err := monitorScanTaskOptions(monitor.Options, target)
	if err != nil || !enabled {
		return err
	}
	task, err := s.taskService.CreateUniqueTriggeredQueuedTask(
		fmt.Sprintf("%s (监控扫描)", monitor.Name), target, "", monitor.ScopeID, options,
		models.TaskOrigin{Source: models.TaskTriggerMonitor, ID: monitor.ID},
	)
	if err != nil {
		return err
	}
	logger.Info("Monitor scan queued monitor=%s task=%s", monitor.ID, task.ID)
	return nil
}

func monitorScanTaskOptions(raw, target string) (models.TaskOptions, bool, error) {
	var selected models.MonitorOptions
	if err := json.Unmarshal([]byte(raw), &selected); err != nil {
		return models.TaskOptions{}, false, services.MonitorInputErrorf("monitor scan options are invalid")
	}
	enabled := selected.EnableDomainBrute || selected.EnablePortScan || selected.EnableSiteDetect || selected.EnableScreenshot || selected.EnablePoCscan
	if !enabled {
		return models.TaskOptions{}, false, nil
	}
	return models.TaskOptions{
		Target:              target,
		EnableDomainBrute:   selected.EnableDomainBrute,
		DomainBruteType:     "big",
		EnablePortScan:      true,
		PortScanType:        "top100",
		EnableServiceDetect: selected.EnablePortScan,
		EnableSiteDetect:    selected.EnableSiteDetect || selected.EnableScreenshot || selected.EnablePoCscan,
		EnableScreenshot:    selected.EnableScreenshot,
		EnablePoCDetection:  selected.EnablePoCscan,
	}, true, nil
}

type cveMonitorSnapshot struct {
	CheckedAt time.Time            `json:"checked_at"`
	CVEs      []services.CVERecord `json:"cves"`
}

// executeCVEMonitor keeps a compact NVD snapshot and emits one bounded alert
// per run so a popular product keyword cannot flood notification channels.
func (s *Scheduler) executeCVEMonitor(monitor *models.Monitor) error {
	var previous cveMonitorSnapshot
	var lastCheck models.MonitorResult
	checkResult := database.DB.Where("monitor_id = ? AND change_type = ?", monitor.ID, "check").Order("created_at DESC").First(&lastCheck)
	if checkResult.Error != nil && !errors.Is(checkResult.Error, gorm.ErrRecordNotFound) {
		return fmt.Errorf("load previous CVE monitor snapshot: %w", checkResult.Error)
	}
	if checkResult.Error == nil && strings.TrimSpace(lastCheck.Data) != "" {
		if err := decodeMonitorSnapshot(lastCheck.Data, &previous); err != nil {
			return fmt.Errorf("decode previous CVE monitor snapshot: %w", err)
		}
	}
	now := time.Now().UTC()
	since := now.Add(-7 * 24 * time.Hour)
	if !previous.CheckedAt.IsZero() {
		since = previous.CheckedAt.Add(-5 * time.Minute)
	}
	service := services.NewCVEMonitorService()
	records, err := service.Search(context.Background(), monitor.Target, since)
	if err != nil {
		return err
	}
	changes := services.DiffCVERecords(previous.CVEs, records)
	if !previous.CheckedAt.IsZero() && len(changes) > 0 {
		const maxAlertChanges = 50
		alertChanges := changes
		if len(alertChanges) > maxAlertChanges {
			alertChanges = alertChanges[:maxAlertChanges]
		}
		changeType := "modified"
		for _, change := range alertChanges {
			if change.Kind == "new" {
				changeType = "new"
				break
			}
		}
		payload, _ := json.Marshal(map[string]any{"changes": alertChanges, "truncated": len(changes) > len(alertChanges)})
		if err := s.recordMonitorResult(monitor, &models.MonitorResult{
			MonitorID: monitor.ID, ChangeType: changeType,
			Description: fmt.Sprintf("CVE 监控发现 %d 个产品相关更新", len(changes)), Data: string(payload),
		}); err != nil {
			return err
		}
	}
	snapshot, err := json.Marshal(cveMonitorSnapshot{CheckedAt: now, CVEs: services.MergeCVERecords(previous.CVEs, records)})
	if err != nil {
		return err
	}
	return s.recordMonitorResult(monitor, &models.MonitorResult{
		MonitorID: monitor.ID, ChangeType: "check", Description: fmt.Sprintf("CVE 监控检查 %d 条记录", len(records)), Data: string(snapshot),
	})
}

func (s *Scheduler) executeAssetGroupMonitor(monitor *models.Monitor, targets []string) error {
	var group models.AssetGroup
	if err := database.DB.First(&group, "id = ?", *monitor.AssetGroupID).Error; err != nil {
		return fmt.Errorf("asset group not found: %w", err)
	}
	state := make(map[string]any, len(targets))
	for _, target := range targets {
		switch monitor.Type {
		case models.MonitorTypeDomain:
			ips, err := net.LookupHost(target)
			if err != nil {
				state[target] = map[string]string{"status": "unavailable"}
				continue
			}
			sort.Strings(ips)
			state[target] = ips
		case models.MonitorTypeIP:
			state[target] = scanCommonPorts(target)
		case models.MonitorTypeSite:
			value, err := inspectSite(monitor, target)
			if err != nil {
				return err
			}
			state[target] = value
		}
	}
	snapshot, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode monitor snapshot: %w", err)
	}
	currentData := string(snapshot)
	var lastResult models.MonitorResult
	if err := loadPreviousMonitorResult(monitor.ID, "check", &lastResult); err != nil {
		return fmt.Errorf("load previous asset group monitor snapshot: %w", err)
	}
	if lastResult.Data != "" && lastResult.Data != currentData {
		if err := s.recordMonitorResult(monitor, &models.MonitorResult{MonitorID: monitor.ID, ChangeType: "modified", Description: fmt.Sprintf("资产组 %s 的 %s 状态发生变化", group.Name, monitor.Type), Data: currentData}); err != nil {
			return err
		}
	}
	return s.recordMonitorResult(monitor, &models.MonitorResult{MonitorID: monitor.ID, ChangeType: "check", Description: fmt.Sprintf("资产组 %s 检查完成，共 %d 个目标", group.Name, len(targets)), Data: currentData})
}

func scanCommonPorts(target string) []int {
	ports := []int{80, 443, 22, 21, 3306, 3389, 8080, 8443}
	openPorts := make([]int, 0)
	for _, port := range ports {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(target, fmt.Sprintf("%d", port)), 2*time.Second)
		if err == nil {
			conn.Close()
			openPorts = append(openPorts, port)
		}
	}
	return openPorts
}

func inspectSite(monitor *models.Monitor, target string) (map[string]any, error) {
	client := monitorHTTPClient(monitor)
	resp, err := client.Get(target)
	if err != nil {
		if services.IsMonitorInputError(err) {
			return nil, err
		}
		return map[string]any{"status": "unavailable"}, nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return map[string]any{"status": resp.StatusCode, "body": "unavailable"}, nil
	}
	hash := sha256.Sum256(body)
	return map[string]any{"status": resp.StatusCode, "content_hash": fmt.Sprintf("%x", hash[:])}, nil
}

func monitorHTTPClient(monitor *models.Monitor) *http.Client {
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: proxypool.ConfigureTransport(&http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}),
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("site redirect limit exceeded")
			}
			validation, err := services.NewScanScopeService().Validate(monitor.ScopeID, request.URL.String())
			if err != nil {
				return err
			}
			return services.ScanScopeBlockedError(validation)
		},
	}
}

// executeDomainMonitor 执行域名监控
func (s *Scheduler) executeDomainMonitor(monitor *models.Monitor) error {
	logger.Info("Domain monitor: %s", monitor.Target)

	// 查询当前域名解析
	ips, err := net.LookupHost(monitor.Target)
	if err != nil {
		logger.Error("Domain lookup failed: %v", err)
		return fmt.Errorf("domain lookup failed: %w", err)
	}
	// 查询上次的记录
	var lastResult models.MonitorResult
	if err := loadPreviousMonitorResult(monitor.ID, "", &lastResult); err != nil {
		return fmt.Errorf("load previous domain monitor snapshot: %w", err)
	}

	currentIPs := domainMonitorSnapshot(ips)

	// 对比变化
	if lastResult.Data != currentIPs && lastResult.Data != "" {
		// 发现变化
		result := &models.MonitorResult{
			MonitorID:   monitor.ID,
			ChangeType:  "modified",
			Description: fmt.Sprintf("域名 %s 的IP地址发生变化", monitor.Target),
			Data:        fmt.Sprintf("旧IP: %s, 新IP: %s", lastResult.Data, currentIPs),
		}
		if err := s.recordMonitorResult(monitor, result); err != nil {
			return err
		}
		logger.Info("Domain change detected: %s", monitor.Target)
	}

	// 保存当前状态
	result := &models.MonitorResult{
		MonitorID:   monitor.ID,
		ChangeType:  "check",
		Description: fmt.Sprintf("域名 %s 检查完成", monitor.Target),
		Data:        currentIPs,
	}
	return s.recordMonitorResult(monitor, result)
}

func domainMonitorSnapshot(ips []string) string {
	sortedIPs := append([]string(nil), ips...)
	sort.Strings(sortedIPs)
	return strings.Join(sortedIPs, ",")
}

// executeIPMonitor 执行IP监控
func (s *Scheduler) executeIPMonitor(monitor *models.Monitor) error {
	logger.Info("IP monitor: %s", monitor.Target)

	// 扫描该IP的开放端口（使用快速扫描）
	commonPorts := []int{80, 443, 22, 21, 3306, 3389, 8080, 8443}
	var openPorts []int

	for _, port := range commonPorts {
		address := net.JoinHostPort(monitor.Target, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err == nil {
			conn.Close()
			openPorts = append(openPorts, port)
		}
	}

	// 查询上次的记录
	var lastResult models.MonitorResult
	if err := loadPreviousMonitorResult(monitor.ID, "", &lastResult); err != nil {
		return fmt.Errorf("load previous IP monitor snapshot: %w", err)
	}

	currentPorts := fmt.Sprintf("%v", openPorts)

	// 对比变化
	if lastResult.Data != currentPorts && lastResult.Data != "" {
		result := &models.MonitorResult{
			MonitorID:   monitor.ID,
			ChangeType:  "modified",
			Description: fmt.Sprintf("IP %s 的开放端口发生变化", monitor.Target),
			Data:        fmt.Sprintf("旧端口: %s, 新端口: %s", lastResult.Data, currentPorts),
		}
		if err := s.recordMonitorResult(monitor, result); err != nil {
			return err
		}
		logger.Info("IP ports change detected: %s", monitor.Target)
	}

	// 保存当前状态
	result := &models.MonitorResult{
		MonitorID:   monitor.ID,
		ChangeType:  "check",
		Description: fmt.Sprintf("IP %s 检查完成，开放端口: %v", monitor.Target, openPorts),
		Data:        currentPorts,
	}
	return s.recordMonitorResult(monitor, result)
}

// executeSiteMonitor 执行站点监控
func (s *Scheduler) executeSiteMonitor(monitor *models.Monitor) error {
	logger.Info("Site monitor: %s", monitor.Target)

	client := monitorHTTPClient(monitor)

	resp, err := client.Get(monitor.Target)
	if err != nil {
		logger.Error("Site request failed: %v", err)
		return fmt.Errorf("site request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return fmt.Errorf("read site response failed: %w", err)
	}
	statusCode := resp.StatusCode
	currentData := siteMonitorData(statusCode, body)

	// 查询上次的记录
	var lastResult models.MonitorResult
	if err := loadPreviousMonitorResult(monitor.ID, "", &lastResult); err != nil {
		return fmt.Errorf("load previous site monitor snapshot: %w", err)
	}

	// 对比变化
	if lastResult.Data != currentData && lastResult.Data != "" {
		result := &models.MonitorResult{
			MonitorID:   monitor.ID,
			ChangeType:  "modified",
			Description: fmt.Sprintf("站点 %s 内容发生变化", monitor.Target),
			Data:        currentData,
		}
		if err := s.recordMonitorResult(monitor, result); err != nil {
			return err
		}
		logger.Info("Site change detected: %s", monitor.Target)
	}

	// 保存当前状态
	result := &models.MonitorResult{
		MonitorID:   monitor.ID,
		ChangeType:  "check",
		Description: fmt.Sprintf("站点 %s 检查完成", monitor.Target),
		Data:        currentData,
	}
	return s.recordMonitorResult(monitor, result)
}

func siteMonitorData(statusCode int, body []byte) string {
	digest := sha256.Sum256(body)
	return fmt.Sprintf("status:%d,hash:%x", statusCode, digest[:])
}

const (
	githubMonitorInspectLimit = 12
	githubMonitorConcurrency  = 4
)

type githubLeakFinding struct {
	Fingerprint string `json:"fingerprint"`
	Repository  string `json:"repository"`
	Path        string `json:"path"`
	URL         string `json:"url"`
	Evidence    string `json:"evidence"`
	Severity    string `json:"severity"`
}

type githubMonitorSnapshot struct {
	Version          int                 `json:"version"`
	CheckedAt        time.Time           `json:"checked_at"`
	Query            string              `json:"query"`
	SearchTotal      int                 `json:"search_total"`
	Inspected        int                 `json:"inspected"`
	InspectionErrors int                 `json:"inspection_errors"`
	Findings         []githubLeakFinding `json:"findings"`
}

func (s *Scheduler) executeGithubMonitor(monitor *models.Monitor) error {
	logger.Info("Github monitor: %s", monitor.Target)
	githubMonitor, err := scanner.NewGithubMonitorFromSettings(database.DB)
	if err != nil {
		return err
	}
	result, err := githubMonitor.SearchKeyword(monitor.Target, 30)
	if err != nil {
		return fmt.Errorf("github search failed: %w", err)
	}
	items := result.Items
	if len(items) > githubMonitorInspectLimit {
		items = items[:githubMonitorInspectLimit]
	}
	inspected := githubMonitor.InspectSearchItems(items, githubMonitorConcurrency)
	snapshot := githubMonitorSnapshot{Version: 1, CheckedAt: time.Now(), Query: monitor.Target, SearchTotal: result.TotalCount, Inspected: len(inspected), Findings: make([]githubLeakFinding, 0)}
	for _, inspection := range inspected {
		if inspection.Err != nil {
			snapshot.InspectionErrors++
			continue
		}
		if len(inspection.Leaks) == 0 {
			continue
		}
		item := inspection.Item
		evidence := scanner.GithubLeakSummary(inspection.Leaks)
		finding := githubLeakFinding{
			Repository: boundedMonitorText(item.Repository.FullName, 200),
			Path:       boundedMonitorText(item.Path, 500),
			URL:        safeGithubResultURL(item.HTMLURL),
			Evidence:   evidence,
			Severity:   scanner.GithubLeakSeverity(inspection.Leaks),
		}
		finding.Fingerprint = githubFindingFingerprint(finding)
		snapshot.Findings = append(snapshot.Findings, finding)
	}
	if len(inspected) > 0 && snapshot.InspectionErrors == len(inspected) {
		return fmt.Errorf("github content inspection failed for every candidate")
	}
	sort.Slice(snapshot.Findings, func(i, j int) bool { return snapshot.Findings[i].Fingerprint < snapshot.Findings[j].Fingerprint })

	var lastResult models.MonitorResult
	if err := database.DB.Where("monitor_id = ? AND change_type = ?", monitor.ID, "check").Order("created_at DESC").First(&lastResult).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("load previous GitHub monitor snapshot: %w", err)
	}
	var previous githubMonitorSnapshot
	if lastResult.Data != "" {
		if err := decodeMonitorSnapshot(lastResult.Data, &previous); err != nil {
			return fmt.Errorf("decode previous GitHub monitor snapshot: %w", err)
		}
	}
	newFindings := diffGithubFindings(snapshot.Findings, previous.Findings)
	if len(newFindings) > 0 {
		eventSnapshot := snapshot
		eventSnapshot.Findings = newFindings
		eventData, err := json.Marshal(eventSnapshot)
		if err != nil {
			return fmt.Errorf("encode GitHub leak event: %w", err)
		}
		if err := s.recordMonitorResult(monitor, &models.MonitorResult{
			MonitorID: monitor.ID, ChangeType: "new",
			Description: fmt.Sprintf("GitHub 确认 %d 个新的敏感泄露文件", len(newFindings)), Data: string(eventData),
		}); err != nil {
			return err
		}
		logger.Info("Confirmed new GitHub leaks: %s (%d)", monitor.Target, len(newFindings))
	}
	snapshotData, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("encode GitHub monitor snapshot: %w", err)
	}
	return s.recordMonitorResult(monitor, &models.MonitorResult{
		MonitorID: monitor.ID, ChangeType: "check",
		Description: fmt.Sprintf("GitHub 检索 %d 条，核验 %d 条，确认 %d 条", result.TotalCount, snapshot.Inspected, len(snapshot.Findings)), Data: string(snapshotData),
	})
}

func githubFindingFingerprint(finding githubLeakFinding) string {
	digest := sha256.Sum256([]byte(finding.Repository + "\x00" + finding.Path + "\x00" + finding.URL + "\x00" + finding.Evidence))
	return fmt.Sprintf("%x", digest[:12])
}

func diffGithubFindings(current, previous []githubLeakFinding) []githubLeakFinding {
	seen := make(map[string]struct{}, len(previous))
	for _, finding := range previous {
		seen[finding.Fingerprint] = struct{}{}
	}
	result := make([]githubLeakFinding, 0)
	for _, finding := range current {
		if _, exists := seen[finding.Fingerprint]; !exists {
			result = append(result, finding)
		}
	}
	return result
}

func boundedMonitorText(value string, maxRunes int) string {
	value = strings.TrimSpace(value)
	runes := []rune(value)
	if len(runes) > maxRunes {
		return string(runes[:maxRunes])
	}
	return value
}

func safeGithubResultURL(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "https" || (parsed.Hostname() != "github.com" && parsed.Hostname() != "www.github.com") || parsed.User != nil {
		return ""
	}
	return parsed.String()
}

// executeWIHMonitor 执行WIH监控
func (s *Scheduler) executeWIHMonitor(monitor *models.Monitor) error {
	logger.Info("WIH monitor: %s", monitor.Target)

	// 创建WIH扫描器
	wih := scanner.NewWebInfoHunter("")

	// 执行扫描
	ctx := &scanner.ScanContext{
		Logger: log.Default(),
		DB:     database.DB,
	}

	results, err := wih.ScanWithURLValidator(ctx, []string{monitor.Target}, func(target string) error {
		validation, err := services.NewScanScopeService().Validate(monitor.ScopeID, target)
		if err != nil {
			return err
		}
		return services.ScanScopeBlockedError(validation)
	})
	if err != nil {
		logger.Error("WIH scan failed: %v", err)
		return fmt.Errorf("WIH scan failed: %w", err)
	}

	// 统计发现的信息
	totalFindings := 0
	for _, r := range results {
		totalFindings += len(r.Subdomains) + len(r.AccessKeys) +
			len(r.SecretKeys) + len(r.APIKeys) + len(r.APIEndpoints)
	}

	// 查询上次的记录
	var lastResult models.MonitorResult
	if err := loadPreviousMonitorResult(monitor.ID, "", &lastResult); err != nil {
		return fmt.Errorf("load previous WIH monitor snapshot: %w", err)
	}

	currentData := fmt.Sprintf("%d", totalFindings)

	// 如果发现新信息
	if lastResult.Data != currentData && totalFindings > 0 {
		monitorResult := &models.MonitorResult{
			MonitorID:   monitor.ID,
			ChangeType:  "new",
			Description: fmt.Sprintf("WIH发现新的信息: %d 项", totalFindings),
			Data:        currentData,
		}
		if err := s.recordMonitorResult(monitor, monitorResult); err != nil {
			return err
		}
		logger.Info("New WIH findings: %s (%d)", monitor.Target, totalFindings)
	}

	// 保存当前状态
	checkResult := &models.MonitorResult{
		MonitorID:   monitor.ID,
		ChangeType:  "check",
		Description: fmt.Sprintf("WIH监控完成: %s", monitor.Target),
		Data:        currentData,
	}
	return s.recordMonitorResult(monitor, checkResult)
}

func loadPreviousMonitorResult(monitorID, changeType string, destination *models.MonitorResult) error {
	query := database.DB.Where("monitor_id = ?", monitorID)
	if changeType != "" {
		query = query.Where("change_type = ?", changeType)
	}
	err := query.Order("created_at DESC").First(destination).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	return err
}

func decodeMonitorSnapshot(raw string, destination any) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return json.Unmarshal([]byte(raw), destination)
}

// checkScheduledTasks 检查并执行计划任务
func (s *Scheduler) checkScheduledTasks() {
	now := time.Now()
	for {
		claimed, err := s.claimAndQueueScheduledTask(now)
		if err != nil {
			logger.Error("Failed to queue scheduled task: %v", err)
			return
		}
		if !claimed {
			return
		}
	}
}

// claimAndQueueScheduledTask advances one due schedule and creates its queued
// task in the same transaction. Row locking prevents duplicate claims across
// server instances, while the transaction prevents a crash window between the
// schedule cursor and durable queue writes.
func (s *Scheduler) claimAndQueueScheduledTask(now time.Time) (bool, error) {
	if database.DB == nil {
		return false, errors.New("scheduler database is unavailable")
	}
	if s.taskService == nil {
		return false, errors.New("task service is unavailable")
	}
	tx := database.DB.Begin()
	if tx.Error != nil {
		return false, tx.Error
	}
	defer tx.Rollback()
	var tasks []models.ScheduledTask
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
		Where("is_enabled = ? AND next_run_at IS NOT NULL AND next_run_at <= ?", true, now).
		Order("next_run_at ASC").Limit(1).Find(&tasks).Error; err != nil {
		return false, err
	}
	if len(tasks) == 0 {
		return false, nil
	}
	scheduledTask := tasks[0]
	updates := map[string]any{"last_run_at": now}
	if scheduledTask.CronType == "once" {
		updates["is_enabled"] = false
		updates["next_run_at"] = nil
	} else {
		nextRun, err := s.calculateNextRunFrom(scheduledTask.CronExpr, scheduledTask.CronType, now)
		if err != nil {
			// Invalid schedules must not remain due and fail every minute.
			updates["is_enabled"] = false
			updates["next_run_at"] = nil
			if err := s.recordScheduledResultTx(tx, scheduledTask.ID, nil, "failed", err.Error(), now); err != nil {
				return false, err
			}
			if err := tx.Model(&models.ScheduledTask{}).Where("id = ?", scheduledTask.ID).Updates(updates).Error; err != nil {
				return false, err
			}
			if err := tx.Commit().Error; err != nil {
				return false, err
			}
			logger.Error("Disabled invalid scheduled task %s: %v", scheduledTask.Name, err)
			return true, nil
		}
		updates["next_run_at"] = nextRun
	}

	active, activeErr := services.ActiveTriggeredTaskExists(tx, models.TaskTriggerSchedule, scheduledTask.ID)
	if activeErr != nil {
		return false, activeErr
	}
	var queuedTask *models.Task
	var queueErr error
	status := "success"
	message := "Task created and queued successfully"
	if active {
		status = "skipped"
		message = "Previous scheduled task is still queued or running"
	} else {
		queuedTask, queueErr = s.taskService.CreateTaskInScopeTxWithOrigin(
			tx,
			fmt.Sprintf("%s (计划任务)", scheduledTask.Name),
			scheduledTask.TaskOptions.Target,
			scheduledTask.PolicyID,
			scheduledTask.ScopeID,
			scheduledTask.TaskOptions,
			models.TaskStatusQueued,
			models.TaskOrigin{Source: models.TaskTriggerSchedule, ID: scheduledTask.ID, ActorID: scheduledTask.CreatedBy},
		)
	}
	if queueErr != nil {
		if !services.IsTaskInputError(queueErr) {
			return false, queueErr
		}
		status = "failed"
		message = queueErr.Error()
	}
	if err := tx.Model(&models.ScheduledTask{}).Where("id = ?", scheduledTask.ID).Updates(updates).Error; err != nil {
		return false, err
	}
	if err := s.recordScheduledResultTx(tx, scheduledTask.ID, queuedTask, status, message, now); err != nil {
		return false, err
	}
	if err := tx.Commit().Error; err != nil {
		return false, err
	}
	if queuedTask != nil {
		s.taskService.WakeTaskQueue()
		logger.Info("Task queued for scheduled task %s: %s", scheduledTask.Name, queuedTask.ID)
	} else {
		logger.Error("Scheduled task %s was not queued: %s", scheduledTask.Name, message)
	}
	return true, nil
}

func (s *Scheduler) recordScheduledResultTx(tx *gorm.DB, scheduledTaskID string, task *models.Task, status, message string, startedAt time.Time) error {
	endTime := time.Now()
	counter := "run_count"
	if status == "failed" {
		counter = "fail_count"
	}
	if err := tx.Model(&models.ScheduledTask{}).Where("id = ?", scheduledTaskID).
		UpdateColumn(counter, gorm.Expr(counter+" + 1")).Error; err != nil {
		return err
	}
	entry := &models.ScheduledTaskLog{ScheduledTaskID: scheduledTaskID, Status: status, Message: message, StartTime: startedAt, EndTime: &endTime}
	if task != nil {
		entry.TaskID = task.ID
	}
	return tx.Create(entry).Error
}

// calculateNextRun 计算下次运行时间
func (s *Scheduler) calculateNextRun(cronExpr, cronType string) (*time.Time, error) {
	return s.calculateNextRunFrom(cronExpr, cronType, time.Now())
}

func (s *Scheduler) calculateNextRunFrom(cronExpr, cronType string, from time.Time) (*time.Time, error) {
	if cronType == "once" {
		return nil, nil
	}

	if cronExpr == "" {
		return nil, fmt.Errorf("cron expression is empty")
	}

	parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	schedule, err := parser.Parse(cronExpr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cron expression: %w", err)
	}

	nextRun := schedule.Next(from)
	return &nextRun, nil
}
