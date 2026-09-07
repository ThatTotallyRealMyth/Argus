package services

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/scanner"
)

// TaskService 任务服务
type TaskService struct {
	runningTasks    map[string]context.CancelFunc
	runningTasksMux sync.RWMutex
	wsHandler       scanner.ProgressHandler // WebSocket handler
	wsHandlerMu     sync.RWMutex
	queueWake       chan struct{}
	queueStop       chan struct{}
	queueWG         sync.WaitGroup
	queueStopOnce   sync.Once
	workerCount     int
	assetCatalog    *AssetCatalogService
	scopeGuard      *ScanScopeService
}

// NewTaskService 创建任务服务
func NewTaskService() *TaskService {
	service := &TaskService{
		runningTasks: make(map[string]context.CancelFunc),
		queueWake:    make(chan struct{}, 1),
		queueStop:    make(chan struct{}),
		workerCount:  configuredTaskWorkerCount(),
		assetCatalog: NewAssetCatalogService(),
		scopeGuard:   NewScanScopeService(),
	}
	service.startTaskQueue()
	return service
}

// SetWebSocketHandler 设置WebSocket处理器
func (s *TaskService) SetWebSocketHandler(handler scanner.ProgressHandler) {
	s.wsHandlerMu.Lock()
	defer s.wsHandlerMu.Unlock()
	s.wsHandler = handler
}

func (s *TaskService) webSocketHandler() scanner.ProgressHandler {
	s.wsHandlerMu.RLock()
	defer s.wsHandlerMu.RUnlock()
	return s.wsHandler
}

// CancelTask 取消正在运行的任务
func (s *TaskService) CancelTask(taskID string) error {
	s.runningTasksMux.RLock()
	cancelFunc, exists := s.runningTasks[taskID]
	s.runningTasksMux.RUnlock()
	if exists {
		log.Printf("Cancelling task %s", taskID)
		cancelFunc()
	}
	if database.DB == nil {
		if exists {
			return nil
		}
		return fmt.Errorf("task database is not initialized")
	}

	result := database.DB.Model(&models.Task{}).
		Where("id = ? AND status IN ?", taskID, []models.TaskStatus{models.TaskStatusPending, models.TaskStatusQueued, models.TaskStatusRunning}).
		Updates(map[string]any{
			"status":    models.TaskStatusCancelled,
			"ended_at":  time.Now(),
			"error_msg": "Task was cancelled by user",
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 1 {
		return nil
	}
	return taskInputErrorf("task %s is not cancellable", taskID)
}

func (s *TaskService) IsTaskRunning(taskID string) bool {
	s.runningTasksMux.RLock()
	defer s.runningTasksMux.RUnlock()
	_, exists := s.runningTasks[taskID]
	return exists
}

// ExecuteTask 执行任务
func (s *TaskService) ExecuteTask(taskID string) {
	log.Printf("========== ExecuteTask called for task: %s ==========", taskID)

	// 获取任务
	var task models.Task
	if err := database.DB.First(&task, "id = ?", taskID).Error; err != nil {
		log.Printf("Failed to find task %s: %v", taskID, err)
		return
	}
	if task.Status != models.TaskStatusRunning {
		log.Printf("Task %s will not execute with status %s", taskID, task.Status)
		return
	}

	// Port scanning is a core platform capability and is mandatory for every task.
	task.Options.EnablePortScan = true
	if task.Options.PortScanType == "" {
		task.Options.PortScanType = "top100"
	}

	log.Printf("Task found: ID=%s, Name=%s, Target=%s", task.ID, task.Name, task.Target)
	log.Printf("Task options: EnablePortScan=%v, PortScanType=%s",
		task.Options.EnablePortScan, task.Options.PortScanType)

	// 创建可取消的context
	ctx, cancel := context.WithCancel(context.Background())

	// 注册到运行任务列表
	s.runningTasksMux.Lock()
	if _, exists := s.runningTasks[taskID]; exists {
		s.runningTasksMux.Unlock()
		cancel()
		log.Printf("Task %s is already running", taskID)
		return
	}
	s.runningTasks[taskID] = cancel
	s.runningTasksMux.Unlock()

	// 任务结束后清理
	defer func() {
		s.runningTasksMux.Lock()
		delete(s.runningTasks, taskID)
		s.runningTasksMux.Unlock()
	}()

	// 任务可能在被 Worker 领取后、注册取消函数前遭到取消或删除。
	var currentStatus models.TaskStatus
	if err := database.DB.Model(&models.Task{}).Select("status").Where("id = ?", taskID).Scan(&currentStatus).Error; err != nil {
		cancel()
		log.Printf("Failed to verify task %s before execution: %v", taskID, err)
		return
	}
	if currentStatus != models.TaskStatusRunning {
		cancel()
		log.Printf("Task %s will not execute after status changed to %s", taskID, currentStatus)
		return
	}
	validation, scopeErr := s.ValidateScopeTarget(task.ScopeID, task.Target)
	if scopeErr == nil {
		scopeErr = ScanScopeBlockedError(validation)
	}
	if scopeErr != nil {
		endedAt := time.Now()
		publicError := scopeErr.Error()
		if !IsScanScopeInputError(scopeErr) && !IsTaskInputError(scopeErr) {
			publicError = "Scan scope validation failed"
		}
		task.Status = models.TaskStatusFailed
		task.EndedAt = &endedAt
		task.ErrorMsg = publicError
		if err := s.persistTaskTerminalState(&task); err != nil {
			log.Printf("Failed to persist scope validation failure for task %s: %v", task.ID, err)
			if handler := s.webSocketHandler(); handler != nil {
				handler.BroadcastTaskComplete(task.ID, string(models.TaskStatusFailed), "Failed to persist task status")
			}
			return
		}
		log.Printf("Task %s blocked by scan scope validation: %v", task.ID, scopeErr)
		if handler := s.webSocketHandler(); handler != nil {
			handler.BroadcastTaskComplete(task.ID, string(task.Status), task.ErrorMsg)
		}
		return
	}
	task.ScopeID = validation.ScopeID
	task.Target = validation.NormalizedTarget

	taskLogger, taskLogRecorder := newTaskLogger(task.ID)
	defer taskLogRecorder.Close()
	taskLogger.Printf("任务开始：%s，目标：%s", task.Name, task.Target)

	// 执行扫描
	err := s.executeScanner(ctx, &task, taskLogger)

	// 更新任务状态
	endTime := time.Now()
	task.EndedAt = &endTime

	// 检查是否被取消
	if ctx.Err() == context.Canceled {
		task.Status = models.TaskStatusCancelled
		task.ErrorMsg = "Task was cancelled by user"
		log.Printf("Task %s was cancelled", task.ID)
		taskLogger.Printf("任务已取消")
	} else if err != nil {
		task.Status = models.TaskStatusFailed
		task.ErrorMsg = publicTaskExecutionError(err)
		log.Printf("Task %s failed: %v", task.ID, err)
		taskLogger.Printf("任务执行失败：%s", task.ErrorMsg)
	} else {
		task.Status = models.TaskStatusCompleted
		task.Progress = 100
		log.Printf("Task %s completed successfully", task.ID)
		taskLogger.Printf("任务执行完成")
	}

	if err := s.persistTaskTerminalState(&task); err != nil {
		log.Printf("Failed to persist terminal state for task %s: %v", task.ID, err)
		if handler := s.webSocketHandler(); handler != nil {
			handler.BroadcastTaskComplete(task.ID, string(models.TaskStatusFailed), "Failed to persist task status")
		}
		return
	}
	if s.assetCatalog != nil {
		if err := s.assetCatalog.SyncTask(task.ID); err != nil {
			log.Printf("Failed to sync task %s into asset catalog: %v", task.ID, err)
		}
	}
	if handler := s.webSocketHandler(); handler != nil {
		handler.BroadcastTaskComplete(task.ID, string(task.Status), task.ErrorMsg)
	}
}

// persistTaskTerminalState makes cancellation win over a concurrently finishing
// worker and never overwrites a terminal state written by another request.
func (s *TaskService) persistTaskTerminalState(task *models.Task) error {
	if database.DB == nil {
		return fmt.Errorf("task database is not initialized")
	}
	updates := map[string]any{
		"status":    task.Status,
		"progress":  task.Progress,
		"ended_at":  task.EndedAt,
		"error_msg": task.ErrorMsg,
	}
	query := database.DB.Model(&models.Task{}).Where("id = ? AND status = ?", task.ID, models.TaskStatusRunning)
	result := query.Updates(updates)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 1 {
		return nil
	}

	var current models.Task
	if err := database.DB.Select("status", "progress", "ended_at", "error_msg").First(&current, "id = ?", task.ID).Error; err != nil {
		return err
	}
	if current.Status != models.TaskStatusCancelled {
		return fmt.Errorf("task terminal state already changed to %s", current.Status)
	}
	// A concurrent cancellation is authoritative. Mirror it into the in-memory
	// task so catalog synchronization and WebSocket output agree with the DB.
	mirrorPersistedTaskState(task, current)
	return nil
}

func mirrorPersistedTaskState(task *models.Task, persisted models.Task) {
	task.Status = persisted.Status
	task.Progress = persisted.Progress
	task.EndedAt = persisted.EndedAt
	task.ErrorMsg = persisted.ErrorMsg
	if task.Status == models.TaskStatusCancelled && task.ErrorMsg == "" {
		task.ErrorMsg = "Task was cancelled by user"
	}
}

// executeScanner 执行扫描引擎
func (s *TaskService) executeScanner(ctx context.Context, task *models.Task, taskLogger *log.Logger) error {
	validateTarget, err := s.scopeGuard.BuildValidator(task.ScopeID)
	if err != nil {
		return fmt.Errorf("build scan scope validator: %w", err)
	}
	// Scanner implementations carry mutable client and timeout configuration.
	// A per-task engine prevents concurrent jobs from changing each other's state.
	scanEngine := scanner.NewEngine()

	// 创建进度通道
	progressChan := make(chan *scanner.ScanProgress, 100)

	// 如果有WebSocket handler，注册进度通道
	if handler := s.webSocketHandler(); handler != nil {
		handler.RegisterProgressChannel(task.ID, progressChan)
		defer handler.UnregisterProgressChannel(task.ID)
	}

	scanCtx := &scanner.ScanContext{
		Task:           task,
		DB:             database.DB,
		Logger:         taskLogger,
		Ctx:            ctx,          // 传递取消context
		ProgressChan:   progressChan, // 传递进度通道
		ValidateTarget: validateTarget,
	}

	// 检查任务是否已被取消的辅助函数
	checkCancelled := func() error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}

	// 0. 被动扫描（如果启用）
	if task.Options.EnablePassiveScan {
		if err := checkCancelled(); err != nil {
			return err
		}
		taskLogger.Printf("开始被动扫描")
		if err := scanEngine.RunPassiveScan(scanCtx); err != nil {
			taskLogger.Printf("被动扫描失败：%v", err) // 不中断任务
		}
		if err := s.updateProgress(ctx, task, 10); err != nil {
			return err
		}
	}

	// 1. 域名发现
	if task.Options.EnableDomainBrute || task.Options.EnableDomainPlugins {
		if err := checkCancelled(); err != nil {
			return err
		}
		taskLogger.Printf("开始域名发现")
		if err := scanEngine.DiscoverDomains(scanCtx); err != nil {
			return fmt.Errorf("domain discovery failed: %w", err)
		}
		if err := s.updateProgress(ctx, task, 20); err != nil {
			return err
		}
	}

	// 2. IP解析
	if err := checkCancelled(); err != nil {
		return err
	}
	taskLogger.Printf("开始 IP 解析")
	if err := scanEngine.ResolveIPs(scanCtx); err != nil {
		return fmt.Errorf("IP resolution failed: %w", err)
	}
	if err := s.updateProgress(ctx, task, 35); err != nil {
		return err
	}

	// 2.5. C段扫描
	if task.Options.EnableCSegment {
		if err := checkCancelled(); err != nil {
			return err
		}
		taskLogger.Printf("开始 C 段扫描")
		if err := scanEngine.ScanCSegment(scanCtx); err != nil {
			taskLogger.Printf("C 段扫描失败：%v", err) // 不中断任务
		}
	}
	if err := s.updateProgress(ctx, task, 40); err != nil {
		return err
	}

	// 3. 端口扫描（平台核心能力，始终执行）
	if err := checkCancelled(); err != nil {
		return err
	}
	taskLogger.Printf("开始端口扫描")
	if err := scanEngine.ScanPorts(scanCtx); err != nil {
		return fmt.Errorf("port scan failed: %w", err)
	}
	if err := s.updateProgress(ctx, task, 60); err != nil {
		return err
	}

	// 4. 服务识别
	if task.Options.EnableServiceDetect {
		if err := checkCancelled(); err != nil {
			return err
		}
		taskLogger.Printf("开始服务识别")
		if err := scanEngine.DetectServices(scanCtx); err != nil {
			return fmt.Errorf("service detection failed: %w", err)
		}
		if err := s.updateProgress(ctx, task, 70); err != nil {
			return err
		}
	}

	// 5. 站点识别
	if task.Options.EnableSiteDetect {
		if err := checkCancelled(); err != nil {
			return err
		}
		taskLogger.Printf("开始站点识别")
		if err := scanEngine.DetectSites(scanCtx); err != nil {
			return fmt.Errorf("site detection failed: %w", err)
		}
		if err := s.updateProgress(ctx, task, 80); err != nil {
			return err
		}
	}

	// 6. 操作系统识别
	if task.Options.EnableOSDetect {
		if err := checkCancelled(); err != nil {
			return err
		}
		taskLogger.Printf("开始操作系统识别")
		if err := scanEngine.DetectOS(scanCtx); err != nil {
			taskLogger.Printf("操作系统识别失败：%v", err)
		}
	}

	// 7. 站点截图
	if task.Options.EnableScreenshot {
		if err := checkCancelled(); err != nil {
			return err
		}
		taskLogger.Printf("开始站点截图")
		if err := scanEngine.TakeScreenshots(scanCtx); err != nil {
			taskLogger.Printf("站点截图失败：%v", err) // 不中断任务
		}
	}

	if err := s.updateProgress(ctx, task, 85); err != nil {
		return err
	}

	// 8. 漏洞检测
	if task.Options.EnableFileLeak {
		if err := checkCancelled(); err != nil {
			return err
		}
		taskLogger.Printf("开始文件泄露检测")
		if err := scanEngine.CheckFileLeaks(scanCtx); err != nil {
			taskLogger.Printf("文件泄露检测失败：%v", err) // 不中断任务
		}
	}

	if err := s.updateProgress(ctx, task, 90); err != nil {
		return err
	}

	// 9. Host碰撞检测
	if task.Options.EnableHostCollision {
		if err := checkCancelled(); err != nil {
			return err
		}
		taskLogger.Printf("开始 Host 碰撞检测")
		if err := scanEngine.CheckHostCollision(scanCtx); err != nil {
			taskLogger.Printf("Host 碰撞检测失败：%v", err)
		}
	}

	// 9.5. 子域名接管检测
	if err := checkCancelled(); err != nil {
		return err
	}
	taskLogger.Printf("开始子域名接管检测")
	if err := scanEngine.CheckSubdomainTakeover(scanCtx); err != nil {
		taskLogger.Printf("子域名接管检测失败：%v", err)
	}

	// 10. 智能PoC检测 (基于指纹匹配,替代Nuclei/XPOC/Afrog)
	if task.Options.EnablePoCDetection {
		if err := checkCancelled(); err != nil {
			return err
		}
		taskLogger.Printf("开始智能 PoC 检测")
		if err := scanEngine.RunPoCScanning(scanCtx); err != nil {
			taskLogger.Printf("PoC 检测失败：%v", err) // 不中断任务
		}
	}

	if err := s.updateProgress(ctx, task, 92); err != nil {
		return err
	}

	// 13. 自定义脚本
	if task.Options.EnableCustomScript && task.Options.CustomScriptPath != "" {
		if err := checkCancelled(); err != nil {
			return err
		}
		if validateTarget != nil {
			return taskInputErrorf("custom scripts are disabled for scope-enforced tasks because their outbound requests cannot be constrained")
		}
		taskLogger.Printf("开始自定义脚本：%s", task.Options.CustomScriptPath)
		if err := scanEngine.RunCustomScript(scanCtx, task.Options.CustomScriptPath); err != nil {
			taskLogger.Printf("自定义脚本失败：%v", err) // 不中断任务
		}
	}

	if err := s.updateProgress(ctx, task, 96); err != nil {
		return err
	}

	// 14. WebInfoHunter (如果启用)
	if task.Options.EnableWIH {
		if err := checkCancelled(); err != nil {
			return err
		}
		taskLogger.Printf("开始 WebInfoHunter")
		if err := s.runWebInfoHunter(scanCtx); err != nil {
			taskLogger.Printf("WebInfoHunter 失败：%v", err)
		}
	}

	if err := s.updateProgress(ctx, task, 98); err != nil {
		return err
	}

	// 15. 资产测绘（最后执行，生成资产画像）
	if err := checkCancelled(); err != nil {
		return err
	}
	taskLogger.Printf("开始生成资产画像")
	if err := scanEngine.MapAssets(scanCtx); err != nil {
		taskLogger.Printf("资产画像生成失败：%v", err)
	}

	if err := s.updateProgress(ctx, task, 100); err != nil {
		return err
	}
	return nil
}

func publicTaskExecutionError(err error) string {
	if IsTaskInputError(err) {
		return err.Error()
	}
	return "Task execution failed"
}

// runWebInfoHunter 运行WebInfoHunter
func (s *TaskService) runWebInfoHunter(ctx *scanner.ScanContext) error {
	// 获取所有站点
	var sites []models.Site
	if err := ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&sites).Error; err != nil {
		return fmt.Errorf("load sites for WebInfoHunter: %w", err)
	}

	if len(sites) == 0 {
		return nil
	}

	urls := make([]string, len(sites))
	for i, site := range sites {
		urls[i] = site.URL
	}

	// 创建WIH扫描器
	wih := scanner.NewWebInfoHunter("")

	// 执行扫描
	results, err := wih.ScanWithURLValidator(ctx, urls, ctx.ValidateTarget)
	if err != nil {
		return err
	}

	// 保存结果
	return wih.SaveResults(ctx, results)
}

// updateProgress 更新任务进度
func (s *TaskService) updateProgress(ctx context.Context, task *models.Task, progress int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	result := database.DB.Model(&models.Task{}).
		Where("id = ? AND status = ?", task.ID, models.TaskStatusRunning).
		Update("progress", progress)
	if result.Error != nil {
		return fmt.Errorf("persist task progress: %w", result.Error)
	}
	if result.RowsAffected != 1 {
		if err := ctx.Err(); err != nil {
			return err
		}
		return fmt.Errorf("task is no longer running")
	}
	task.Progress = progress

	// 通过WebSocket推送进度更新
	if handler := s.webSocketHandler(); handler != nil {
		handler.BroadcastProgress(task.ID, progress, fmt.Sprintf("Progress: %d%%", progress))
	}
	return nil
}
