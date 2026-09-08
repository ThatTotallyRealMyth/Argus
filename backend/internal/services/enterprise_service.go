package services

import (
	"context"
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
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/proxypool"
	"gorm.io/gorm/clause"
)

const (
	enterpriseProviderICP = "icp_query"
	enterpriseMaxResults  = 10000
	enterpriseMaxBody     = 8 << 20
)

var enterpriseKinds = map[string]string{
	"web":  "web",
	"app":  "app",
	"mapp": "miniapp",
	"kapp": "quickapp",
}

type enterpriseScanInputError struct{ message string }

func (err enterpriseScanInputError) Error() string { return err.message }

func IsEnterpriseScanInputError(err error) bool {
	var inputError enterpriseScanInputError
	return errors.As(err, &inputError) || IsTaskInputError(err)
}

type EnterpriseProviderStatus struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Configured bool   `json:"configured"`
	Enabled    bool   `json:"enabled"`
}

type EnterpriseService struct {
	taskService  *TaskService
	assetCatalog *AssetCatalogService
	ctx          context.Context
	cancel       context.CancelFunc
	wake         chan struct{}
	stop         chan struct{}
	done         chan struct{}
	closeOnce    sync.Once
	client       *http.Client
}

func NewEnterpriseService(taskService *TaskService) *EnterpriseService {
	ctx, cancel := context.WithCancel(context.Background())
	service := &EnterpriseService{
		taskService:  taskService,
		assetCatalog: NewAssetCatalogService(),
		ctx:          ctx,
		cancel:       cancel,
		wake:         make(chan struct{}, 1),
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
		client:       &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{}},
	}
	if database.DB != nil {
		var interrupted []models.EnterpriseQuery
		if err := database.DB.Where("status = ?", models.EnterpriseQueryRunning).Find(&interrupted).Error; err != nil {
			log.Printf("Failed to recover interrupted enterprise queries: %v", err)
		}
		for i := range interrupted {
			service.finish(&interrupted[i], models.EnterpriseQueryFailed, "Query was interrupted by a service restart")
		}
		go service.worker()
	} else {
		close(service.done)
	}
	return service
}

func (s *EnterpriseService) Close() {
	s.closeOnce.Do(func() {
		s.cancel()
		close(s.stop)
		<-s.done
	})
}

func (s *EnterpriseService) ProviderStatus() ([]EnterpriseProviderStatus, error) {
	endpoint, _, enabled, err := enterpriseICPSettings()
	if err != nil {
		return nil, err
	}
	return []EnterpriseProviderStatus{{
		ID: enterpriseProviderICP, Name: "ICP_Query", Configured: endpoint != "", Enabled: endpoint != "" && enabled,
	}}, nil
}

func (s *EnterpriseService) CreateQuery(name, keyword, provider string, kinds []string, createdBy string) (*models.EnterpriseQuery, error) {
	keyword = strings.TrimSpace(keyword)
	name = strings.TrimSpace(name)
	if keyword == "" {
		return nil, errors.New("company keyword is required")
	}
	if name == "" {
		name = keyword
	}
	if provider == "" {
		provider = enterpriseProviderICP
	}
	if provider != enterpriseProviderICP {
		return nil, fmt.Errorf("unsupported enterprise provider: %s", provider)
	}
	normalizedKinds, err := normalizeEnterpriseKinds(kinds)
	if err != nil {
		return nil, err
	}
	statuses, err := s.ProviderStatus()
	if err != nil {
		return nil, err
	}
	if !statuses[0].Enabled {
		return nil, errors.New("ICP_Query provider is not configured or enabled")
	}
	query := &models.EnterpriseQuery{Name: name, Keyword: keyword, Provider: provider, QueryTypes: normalizedKinds, Status: models.EnterpriseQueryQueued, CreatedBy: createdBy}
	if err := database.DB.Create(query).Error; err != nil {
		return nil, fmt.Errorf("create enterprise query: %w", err)
	}
	s.signal()
	return query, nil
}

func normalizeEnterpriseKinds(kinds []string) ([]string, error) {
	if len(kinds) == 0 {
		return []string{"web"}, nil
	}
	seen := make(map[string]bool)
	result := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		kind = strings.ToLower(strings.TrimSpace(kind))
		if _, ok := enterpriseKinds[kind]; !ok {
			return nil, fmt.Errorf("unsupported query type: %s", kind)
		}
		if !seen[kind] {
			seen[kind] = true
			result = append(result, kind)
		}
	}
	return result, nil
}

func (s *EnterpriseService) DeleteQuery(id string) error {
	tx := database.DB.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer tx.Rollback()
	var query models.EnterpriseQuery
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&query, "id = ?", id).Error; err != nil {
		return err
	}
	if query.Status == models.EnterpriseQueryQueued || query.Status == models.EnterpriseQueryRunning {
		return errors.New("query not found or still running")
	}
	if err := tx.Where("query_id = ?", id).Delete(&models.EnterpriseAsset{}).Error; err != nil {
		return err
	}
	result := tx.Delete(&models.EnterpriseQuery{}, "id = ?", id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return errors.New("query not found or still running")
	}
	return tx.Commit().Error
}

func (s *EnterpriseService) LaunchScan(assetIDs []string, name, policyID, scopeID string, options models.TaskOptions, start bool, actorID string) (*models.Task, []string, error) {
	if len(assetIDs) == 0 {
		return nil, nil, enterpriseScanInputError{message: "select at least one enterprise asset"}
	}
	if len(assetIDs) > 2000 {
		return nil, nil, enterpriseScanInputError{message: "at most 2000 assets can be scanned at once"}
	}
	var assets []models.EnterpriseAsset
	if err := database.DB.Where("id IN ?", assetIDs).Find(&assets).Error; err != nil {
		return nil, nil, err
	}
	targets := enterpriseScanTargets(assets)
	if len(targets) == 0 {
		return nil, nil, enterpriseScanInputError{message: "selected assets do not contain scannable domains"}
	}
	if strings.TrimSpace(name) == "" {
		name = fmt.Sprintf("Enterprise asset scanning-%s", time.Now().Format("20060102-150405"))
	}
	triggerID := ""
	if len(assets) > 0 {
		triggerID = assets[0].QueryID
		for _, asset := range assets[1:] {
			if asset.QueryID != triggerID {
				triggerID = ""
				break
			}
		}
	}
	origin := models.TaskOrigin{Source: models.TaskTriggerEnterprise, ID: triggerID, ActorID: strings.TrimSpace(actorID)}
	var task *models.Task
	var err error
	if start {
		task, err = s.taskService.CreateQueuedTaskInScopeWithOrigin(name, strings.Join(targets, ","), policyID, scopeID, options, origin)
	} else {
		task, err = s.taskService.CreateTaskInScopeWithOrigin(name, strings.Join(targets, ","), policyID, scopeID, options, origin)
	}
	if err != nil {
		return nil, nil, err
	}
	return task, targets, nil
}

func (s *EnterpriseService) worker() {
	defer close(s.done)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		default:
		}
		id, claimed, err := claimEnterpriseQuery()
		if err != nil {
			log.Printf("Enterprise query worker failed to claim work: %v", err)
		}
		if claimed {
			s.execute(id)
			continue
		}
		select {
		case <-s.wake:
		case <-ticker.C:
		case <-s.stop:
			return
		}
	}
}

func claimEnterpriseQuery() (string, bool, error) {
	tx := database.DB.Begin()
	if tx.Error != nil {
		return "", false, tx.Error
	}
	defer tx.Rollback()
	var rows []models.EnterpriseQuery
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).Where("status = ?", models.EnterpriseQueryQueued).Order("updated_at ASC").Limit(1).Find(&rows).Error; err != nil {
		return "", false, err
	}
	if len(rows) == 0 {
		return "", false, nil
	}
	now := time.Now()
	result := tx.Model(&models.EnterpriseQuery{}).Where("id = ? AND status = ?", rows[0].ID, models.EnterpriseQueryQueued).Updates(map[string]any{"status": models.EnterpriseQueryRunning, "started_at": &now, "ended_at": nil, "error_msg": ""})
	if result.Error != nil || result.RowsAffected != 1 {
		return "", false, result.Error
	}
	if err := tx.Commit().Error; err != nil {
		return "", false, err
	}
	return rows[0].ID, true, nil
}

func (s *EnterpriseService) execute(id string) {
	var query models.EnterpriseQuery
	if err := database.DB.First(&query, "id = ?", id).Error; err != nil {
		return
	}
	endpoint, headers, enabled, err := enterpriseICPSettings()
	if err != nil || !enabled || endpoint == "" {
		if err == nil {
			err = errors.New("ICP_Query provider is not configured or enabled")
		}
		s.finish(&query, models.EnterpriseQueryFailed, err.Error())
		return
	}
	errorsByKind := make([]string, 0)
	succeeded := 0
	for _, kind := range query.QueryTypes {
		assets, fetchErr := s.fetchICP(s.ctx, endpoint, headers, query.Keyword, kind)
		if fetchErr != nil {
			if s.ctx.Err() != nil {
				return
			}
			errorsByKind = append(errorsByKind, kind+": "+fetchErr.Error())
			continue
		}
		succeeded++
		for i := range assets {
			assets[i].QueryID = query.ID
			assets[i].Provider = query.Provider
			if err := database.DB.Clauses(clause.OnConflict{DoNothing: true}).Create(&assets[i]).Error; err != nil {
				errorsByKind = append(errorsByKind, kind+": store result: "+err.Error())
				break
			}
		}
	}
	status := enterpriseQueryCompletionStatus(succeeded)
	s.finish(&query, status, strings.Join(errorsByKind, "; "))
}

func enterpriseQueryCompletionStatus(succeeded int) models.EnterpriseQueryStatus {
	if succeeded == 0 {
		return models.EnterpriseQueryFailed
	}
	return models.EnterpriseQueryCompleted
}

func enterpriseScanTargets(assets []models.EnterpriseAsset) []string {
	seen := make(map[string]bool)
	targets := make([]string, 0, len(assets))
	for _, asset := range assets {
		if domain := normalizeEnterpriseDomain(asset.Domain); domain != "" && !seen[domain] {
			seen[domain] = true
			targets = append(targets, domain)
		}
	}
	sort.Strings(targets)
	return targets
}

func (s *EnterpriseService) finish(query *models.EnterpriseQuery, status models.EnterpriseQueryStatus, message string) {
	var counts []struct {
		Kind  string
		Count int64
	}
	if err := database.DB.Model(&models.EnterpriseAsset{}).Select("kind, count(*) AS count").Where("query_id = ?", query.ID).Group("kind").Scan(&counts).Error; err != nil {
		log.Printf("Failed to count enterprise query %s assets: %v", query.ID, err)
	}
	updates := map[string]any{"status": status, "ended_at": time.Now(), "error_msg": message, "total_count": int64(0), "domain_count": int64(0), "app_count": int64(0), "mini_app_count": int64(0), "quick_app_count": int64(0)}
	for _, count := range counts {
		updates["total_count"] = updates["total_count"].(int64) + count.Count
		switch count.Kind {
		case "web":
			updates["domain_count"] = count.Count
		case "app":
			updates["app_count"] = count.Count
		case "miniapp":
			updates["mini_app_count"] = count.Count
		case "quickapp":
			updates["quick_app_count"] = count.Count
		}
	}
	if err := database.DB.Model(query).Updates(updates).Error; err != nil {
		log.Printf("Failed to finish enterprise query %s: %v", query.ID, err)
	}
}

func (s *EnterpriseService) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func enterpriseICPSettings() (string, map[string]string, bool, error) {
	var settings []models.Setting
	if err := database.DB.Where("key IN ?", []string{models.SettingKeyEnterpriseICPURL, models.SettingKeyEnterpriseICPHeaders, models.SettingKeyEnterpriseICPEnabled}).Find(&settings).Error; err != nil {
		return "", nil, false, err
	}
	values := make(map[string]string)
	for _, setting := range settings {
		value := setting.Value
		if setting.IsEncrypted && value != "" {
			decrypted, err := decryptNotificationSetting(value)
			if err != nil {
				return "", nil, false, fmt.Errorf("decrypt %s: %w", setting.Key, err)
			}
			value = decrypted
		}
		values[setting.Key] = value
	}
	endpoint := strings.TrimRight(strings.TrimSpace(values[models.SettingKeyEnterpriseICPURL]), "/")
	enabledValue, exists := values[models.SettingKeyEnterpriseICPEnabled]
	enabled := !exists || !isFalseSetting(enabledValue)
	headers := make(map[string]string)
	if raw := strings.TrimSpace(values[models.SettingKeyEnterpriseICPHeaders]); raw != "" {
		if err := json.Unmarshal([]byte(raw), &headers); err != nil {
			return "", nil, false, errors.New("enterprise provider headers must be a JSON object")
		}
	}
	return endpoint, headers, enabled, nil
}

func isFalseSetting(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "false", "0", "off", "no", "disabled":
		return true
	default:
		return false
	}
}

func (s *EnterpriseService) fetchICP(ctx context.Context, endpoint string, headers map[string]string, keyword, queryKind string) ([]models.EnterpriseAsset, error) {
	u, err := url.Parse(endpoint + "/query/" + url.PathEscape(queryKind))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("enterprise provider URL must use http or https")
	}
	params := u.Query()
	params.Set("search", keyword)
	u.RawQuery = params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		if strings.EqualFold(key, "host") || strings.EqualFold(key, "content-length") {
			continue
		}
		req.Header.Set(key, value)
	}
	client := s.client
	if !isLoopbackHost(u.Hostname()) {
		client = &http.Client{Timeout: s.client.Timeout, Transport: proxypool.ConfigureTransport(&http.Transport{})}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("provider returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, enterpriseMaxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > enterpriseMaxBody {
		return nil, errors.New("provider response exceeds 8 MiB")
	}
	return parseICPResponse(body, queryKind)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func parseICPResponse(body []byte, queryKind string) ([]models.EnterpriseAsset, error) {
	var envelope struct {
		Code   int             `json:"code"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("decode provider response: %w", err)
	}
	if envelope.Code != 0 && envelope.Code != http.StatusOK {
		return nil, fmt.Errorf("provider returned code %d", envelope.Code)
	}
	items := make([]map[string]any, 0)
	if err := json.Unmarshal(envelope.Params, &items); err != nil {
		var wrapper struct {
			List []map[string]any `json:"list"`
		}
		if wrapperErr := json.Unmarshal(envelope.Params, &wrapper); wrapperErr != nil {
			return nil, errors.New("provider params must be an array or contain list")
		}
		items = wrapper.List
	}
	if len(items) > enterpriseMaxResults {
		items = items[:enterpriseMaxResults]
	}
	storedKind, ok := enterpriseKinds[queryKind]
	if !ok {
		return nil, fmt.Errorf("unsupported query type: %s", queryKind)
	}
	seen := make(map[string]bool)
	assets := make([]models.EnterpriseAsset, 0, len(items))
	for _, item := range items {
		company := firstString(item, "unitName", "companyName", "company", "company_name")
		name := firstString(item, "serviceName", "appName", "name")
		license := firstString(item, "serviceLicence", "mainLicence", "license")
		domain := normalizeEnterpriseDomain(firstString(item, "domain", "website", "url"))
		canonical := domain
		if canonical == "" {
			canonical = strings.ToLower(strings.Join([]string{company, name, license}, "|"))
		}
		canonical = strings.Trim(canonical, "|")
		if canonical == "" || seen[canonical] {
			continue
		}
		seen[canonical] = true
		raw, _ := json.Marshal(item)
		assets = append(assets, models.EnterpriseAsset{Kind: storedKind, CanonicalKey: canonical, CompanyName: company, Name: name, Domain: domain, License: license, RawData: string(raw)})
	}
	return assets, nil
}

func firstString(item map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := item[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func normalizeEnterpriseDomain(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	u, err := url.Parse(value)
	if err != nil {
		return ""
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return ""
	}
	return host
}
