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

// TaskService Task services
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

// NewTaskService creates a task service.
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

// SetWebSocketHandler SettingsWebSocketProcessor
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

// CancelTask Cancel running jobs
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

// ExecuteTask Tasking
func (s *TaskService) ExecuteTask(taskID string) {
	log.Printf("========== ExecuteTask called for task: %s ==========", taskID)

	// Get Tasks
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

	// Create Cancelablecontext
	ctx, cancel := context.WithCancel(context.Background())

	// Create the scan context.
	s.runningTasksMux.Lock()
	if _, exists := s.runningTasks[taskID]; exists {
		s.runningTasksMux.Unlock()
		cancel()
		log.Printf("Task %s is already running", taskID)
		return
	}
	s.runningTasks[taskID] = cancel
	s.runningTasksMux.Unlock()

	// Clean up after mission
	defer func() {
		s.runningTasksMux.Lock()
		delete(s.runningTasks, taskID)
		s.runningTasksMux.Unlock()
	}()

	// Mission may be compromised. Worker After receiving, Cancelled or deleted before registering cancellation.
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
	taskLogger.Printf("Mission begins.: %s, Objective: %s", task.Name, task.Target)

	// Execute Scan
	err := s.executeScanner(ctx, &task, taskLogger)

	// Update Task Status
	endTime := time.Now()
	task.EndedAt = &endTime

	// Check if it's canceled
	if ctx.Err() == context.Canceled {
		task.Status = models.TaskStatusCancelled
		task.ErrorMsg = "Task was cancelled by user"
		log.Printf("Task %s was cancelled", task.ID)
		taskLogger.Printf("Task canceled")
	} else if err != nil {
		task.Status = models.TaskStatusFailed
		task.ErrorMsg = publicTaskExecutionError(err)
		log.Printf("Task %s failed: %v", task.ID, err)
		taskLogger.Printf("Mission execution failed: %s", task.ErrorMsg)
	} else {
		task.Status = models.TaskStatusCompleted
		task.Progress = 100
		log.Printf("Task %s completed successfully", task.ID)
		taskLogger.Printf("Mission accomplished")
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

// executeScanner Execute Scan Engine
func (s *TaskService) executeScanner(ctx context.Context, task *models.Task, taskLogger *log.Logger) error {
	validateTarget, err := s.scopeGuard.BuildValidator(task.ScopeID)
	if err != nil {
		return fmt.Errorf("build scan scope validator: %w", err)
	}
	// Scanner implementations carry mutable client and timeout configuration.
	// A per-task engine prevents concurrent jobs from changing each other's state.
	scanEngine := scanner.NewEngine()

	// Create Progress Channel
	progressChan := make(chan *scanner.ScanProgress, 100)

	// If there is,WebSocket handler, Register Progress Channel
	if handler := s.webSocketHandler(); handler != nil {
		handler.RegisterProgressChannel(task.ID, progressChan)
		defer handler.UnregisterProgressChannel(task.ID)
	}

	scanCtx := &scanner.ScanContext{
		Task:           task,
		DB:             database.DB,
		Logger:         taskLogger,
		Ctx:            ctx,          // Transfer Cancelcontext
		ProgressChan:   progressChan, // Pass Progress Channel
		ValidateTarget: validateTarget,
	}

	// Checks if the task has been cancelled
	checkCancelled := func() error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}

	// 0. Passive Scan (If enabled)
	if task.Options.EnablePassiveScan {
		if err := checkCancelled(); err != nil {
			return err
		}
		taskLogger.Printf("Start passive scan.")
		if err := scanEngine.RunPassiveScan(scanCtx); err != nil {
			taskLogger.Printf("Passive scan failed: %v", err) // Do not interrupt the mission
		}
		if err := s.updateProgress(ctx, task, 10); err != nil {
			return err
		}
	}

	// 1. Domain name found
	if task.Options.EnableDomainBrute || task.Options.EnableDomainPlugins {
		if err := checkCancelled(); err != nil {
			return err
		}
		taskLogger.Printf("Start Domain Name Discover")
		if err := scanEngine.DiscoverDomains(scanCtx); err != nil {
			return fmt.Errorf("domain discovery failed: %w", err)
		}
		if err := s.updateProgress(ctx, task, 20); err != nil {
			return err
		}
	}

	// 2. Resolve IP addresses.
	if err := checkCancelled(); err != nil {
		return err
	}
	taskLogger.Printf("Start IP Parsing")
	if err := scanEngine.ResolveIPs(scanCtx); err != nil {
		return fmt.Errorf("IP resolution failed: %w", err)
	}
	if err := s.updateProgress(ctx, task, 35); err != nil {
		return err
	}

	// 2.5. CParagraph Scan
	if task.Options.EnableCSegment {
		if err := checkCancelled(); err != nil {
			return err
		}
		taskLogger.Printf("Start C Paragraph Scan")
		if err := scanEngine.ScanCSegment(scanCtx); err != nil {
			taskLogger.Printf("C Paragraph scan failed: %v", err) // Do not interrupt the mission
		}
	}
	if err := s.updateProgress(ctx, task, 40); err != nil {
		return err
	}

	// 3. Port Scan (Platform core competencies, Always do)
	if err := checkCancelled(); err != nil {
		return err
	}
	taskLogger.Printf("Start Port Scanning")
	if err := scanEngine.ScanPorts(scanCtx); err != nil {
		return fmt.Errorf("port scan failed: %w", err)
	}
	if err := s.updateProgress(ctx, task, 60); err != nil {
		return err
	}

	// 4. Service recognition
	if task.Options.EnableServiceDetect {
		if err := checkCancelled(); err != nil {
			return err
		}
		taskLogger.Printf("Start Service Recognition")
		if err := scanEngine.DetectServices(scanCtx); err != nil {
			return fmt.Errorf("service detection failed: %w", err)
		}
		if err := s.updateProgress(ctx, task, 70); err != nil {
			return err
		}
	}

	// 5. Site recognition
	if task.Options.EnableSiteDetect {
		if err := checkCancelled(); err != nil {
			return err
		}
		taskLogger.Printf("Start site recognition")
		if err := scanEngine.DetectSites(scanCtx); err != nil {
			return fmt.Errorf("site detection failed: %w", err)
		}
		if err := s.updateProgress(ctx, task, 80); err != nil {
			return err
		}
	}

	// 6. Operational system recognition
	if task.Options.EnableOSDetect {
		if err := checkCancelled(); err != nil {
			return err
		}
		taskLogger.Printf("Start operating system recognition")
		if err := scanEngine.DetectOS(scanCtx); err != nil {
			taskLogger.Printf("Operation system recognition failed: %v", err)
		}
	}

	// 7. Site Screenshot
	if task.Options.EnableScreenshot {
		if err := checkCancelled(); err != nil {
			return err
		}
		taskLogger.Printf("Start Site Screenshot")
		if err := scanEngine.TakeScreenshots(scanCtx); err != nil {
			taskLogger.Printf("Site screenshot failed: %v", err) // Do not interrupt the mission
		}
	}

	if err := s.updateProgress(ctx, task, 85); err != nil {
		return err
	}

	// 8. Gap detection
	if task.Options.EnableFileLeak {
		if err := checkCancelled(); err != nil {
			return err
		}
		taskLogger.Printf("Start file leak detection.")
		if err := scanEngine.CheckFileLeaks(scanCtx); err != nil {
			taskLogger.Printf("File leak detection failed: %v", err) // Do not interrupt the mission
		}
	}

	if err := s.updateProgress(ctx, task, 90); err != nil {
		return err
	}

	// 9. HostCollision detection
	if task.Options.EnableHostCollision {
		if err := checkCancelled(); err != nil {
			return err
		}
		taskLogger.Printf("Start Host Collision detection")
		if err := scanEngine.CheckHostCollision(scanCtx); err != nil {
			taskLogger.Printf("Host Collision test failed.: %v", err)
		}
	}

	// 9.5. Subdomain name takes over the test
	if err := checkCancelled(); err != nil {
		return err
	}
	taskLogger.Printf("Start subdomain name taking over the test")
	if err := scanEngine.CheckSubdomainTakeover(scanCtx); err != nil {
		taskLogger.Printf("Failed to take over the subdomain name test: %v", err)
	}

	// 10. SmartPoCTest (It's based on a fingerprint match.,AlternativeNuclei/XPOC/Afrog)
	if task.Options.EnablePoCDetection {
		if err := checkCancelled(); err != nil {
			return err
		}
		taskLogger.Printf("Start Smart PoC Test")
		if err := scanEngine.RunPoCScanning(scanCtx); err != nil {
			taskLogger.Printf("PoC Failed to detect: %v", err) // Do not interrupt the mission
		}
	}

	if err := s.updateProgress(ctx, task, 92); err != nil {
		return err
	}

	// 13. Custom Scripts
	if task.Options.EnableCustomScript && task.Options.CustomScriptPath != "" {
		if err := checkCancelled(); err != nil {
			return err
		}
		if validateTarget != nil {
			return taskInputErrorf("custom scripts are disabled for scope-enforced tasks because their outbound requests cannot be constrained")
		}
		taskLogger.Printf("Start Custom Script: %s", task.Options.CustomScriptPath)
		if err := scanEngine.RunCustomScript(scanCtx, task.Options.CustomScriptPath); err != nil {
			taskLogger.Printf("Custom Script Failed: %v", err) // Do not interrupt the mission
		}
	}

	if err := s.updateProgress(ctx, task, 96); err != nil {
		return err
	}

	// 14. WebInfoHunter (If enabled)
	if task.Options.EnableWIH {
		if err := checkCancelled(); err != nil {
			return err
		}
		taskLogger.Printf("Start WebInfoHunter")
		if err := s.runWebInfoHunter(scanCtx); err != nil {
			taskLogger.Printf("WebInfoHunter Failed: %v", err)
		}
	}

	if err := s.updateProgress(ctx, task, 98); err != nil {
		return err
	}

	// 15. Asset mapping (Final implementation, Generate asset portraits)
	if err := checkCancelled(); err != nil {
		return err
	}
	taskLogger.Printf("Start generating asset portraits")
	if err := scanEngine.MapAssets(scanCtx); err != nil {
		taskLogger.Printf("Failed to generate asset portraits: %v", err)
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

// runWebInfoHunter RunWebInfoHunter
func (s *TaskService) runWebInfoHunter(ctx *scanner.ScanContext) error {
	// Get All Sites
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

	// CreateWIHScanner
	wih := scanner.NewWebInfoHunter("")

	// Execute Scan
	results, err := wih.ScanWithURLValidator(ctx, urls, ctx.ValidateTarget)
	if err != nil {
		return err
	}

	// Save Results
	return wih.SaveResults(ctx, results)
}

// updateProgress Update Task Progress
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

	// ThroughWebSocket& Add Progress Update
	if handler := s.webSocketHandler(); handler != nil {
		handler.BroadcastProgress(task.ID, progress, fmt.Sprintf("Progress: %d%%", progress))
	}
	return nil
}
