package services

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"gorm.io/gorm"
)

type taskInputError struct{ message string }

var ErrTriggeredTaskActive = errors.New("a task from this trigger is already active")

func (err taskInputError) Error() string { return err.message }

func taskInputErrorf(format string, values ...any) error {
	return taskInputError{message: fmt.Sprintf(format, values...)}
}

func IsTaskInputError(err error) bool {
	var inputError taskInputError
	return errors.As(err, &inputError) || errors.Is(err, ErrTriggeredTaskActive) || IsScanScopeInputError(err)
}

// CreateTask applies the same policy and invariant handling for every caller.
func (s *TaskService) CreateTask(name, target, policyID string, options models.TaskOptions) (*models.Task, error) {
	return s.CreateTaskInScope(name, target, policyID, "", options)
}

// CreateTaskInScope validates and stores a task against an explicit or default authorization boundary.
func (s *TaskService) CreateTaskInScope(name, target, policyID, scopeID string, options models.TaskOptions) (*models.Task, error) {
	return s.createTaskInScope(name, target, policyID, scopeID, options, models.TaskStatusPending, models.TaskOrigin{})
}

// CreateQueuedTaskInScope atomically creates a task in the durable queue.
func (s *TaskService) CreateQueuedTaskInScope(name, target, policyID, scopeID string, options models.TaskOptions) (*models.Task, error) {
	task, err := s.createTaskInScope(name, target, policyID, scopeID, options, models.TaskStatusQueued, models.TaskOrigin{})
	if err == nil {
		s.signalTaskQueue()
	}
	return task, err
}

func (s *TaskService) CreateTaskInScopeWithOrigin(name, target, policyID, scopeID string, options models.TaskOptions, origin models.TaskOrigin) (*models.Task, error) {
	return s.createTaskInScope(name, target, policyID, scopeID, options, models.TaskStatusPending, origin)
}

func (s *TaskService) CreateQueuedTaskInScopeWithOrigin(name, target, policyID, scopeID string, options models.TaskOptions, origin models.TaskOrigin) (*models.Task, error) {
	task, err := s.createTaskInScope(name, target, policyID, scopeID, options, models.TaskStatusQueued, origin)
	if err == nil {
		s.signalTaskQueue()
	}
	return task, err
}

// CreateUniqueTriggeredQueuedTask atomically prevents a monitor or schedule
// from filling the queue while an earlier task from the same trigger is active.
func (s *TaskService) CreateUniqueTriggeredQueuedTask(name, target, policyID, scopeID string, options models.TaskOptions, origin models.TaskOrigin) (*models.Task, error) {
	if strings.TrimSpace(origin.Source) == "" || strings.TrimSpace(origin.ID) == "" {
		return nil, taskInputErrorf("task trigger source and id are required")
	}
	if database.DB == nil {
		return nil, errors.New("task database is unavailable")
	}
	tx := database.DB.Begin()
	if tx.Error != nil {
		return nil, fmt.Errorf("begin triggered task creation: %w", tx.Error)
	}
	defer tx.Rollback()
	if err := lockTaskTrigger(tx, origin); err != nil {
		return nil, err
	}
	active, err := ActiveTriggeredTaskExists(tx, origin.Source, origin.ID)
	if err != nil {
		return nil, err
	}
	if active {
		return nil, fmt.Errorf("%w: %s/%s", ErrTriggeredTaskActive, origin.Source, origin.ID)
	}
	task, err := s.CreateTaskInScopeTxWithOrigin(tx, name, target, policyID, scopeID, options, models.TaskStatusQueued, origin)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("commit triggered task creation: %w", err)
	}
	s.signalTaskQueue()
	return task, nil
}

func (s *TaskService) createTaskInScope(name, target, policyID, scopeID string, options models.TaskOptions, status models.TaskStatus, origin models.TaskOrigin) (*models.Task, error) {
	if database.DB == nil {
		return nil, errors.New("task database is unavailable")
	}
	tx := database.DB.Begin()
	if tx.Error != nil {
		return nil, fmt.Errorf("begin task creation: %w", tx.Error)
	}
	defer tx.Rollback()
	task, err := s.CreateTaskInScopeTxWithOrigin(tx, name, target, policyID, scopeID, options, status, origin)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("commit task creation: %w", err)
	}
	return task, nil
}

// CreateTaskInScopeTx validates and creates a pending or queued task inside a
// caller-owned transaction. The caller must commit and wake the queue.
func (s *TaskService) CreateTaskInScopeTx(tx *gorm.DB, name, target, policyID, scopeID string, options models.TaskOptions, status models.TaskStatus) (*models.Task, error) {
	return s.CreateTaskInScopeTxWithOrigin(tx, name, target, policyID, scopeID, options, status, models.TaskOrigin{})
}

func (s *TaskService) CreateTaskInScopeTxWithOrigin(tx *gorm.DB, name, target, policyID, scopeID string, options models.TaskOptions, status models.TaskStatus, origin models.TaskOrigin) (*models.Task, error) {
	name = strings.TrimSpace(name)
	target = strings.TrimSpace(target)
	if name == "" {
		return nil, taskInputErrorf("task name is required")
	}
	if target == "" {
		return nil, taskInputErrorf("task target is required")
	}
	if tx == nil {
		return nil, errors.New("task transaction is unavailable")
	}
	if status != models.TaskStatusPending && status != models.TaskStatusQueued {
		return nil, taskInputErrorf("invalid initial task status: %s", status)
	}
	if err := lockScanScopeChanges(tx); err != nil {
		return nil, fmt.Errorf("lock scan scope: %w", err)
	}
	guard := s.scopeGuard
	if guard == nil {
		guard = NewScanScopeService()
	}
	validation, err := guard.validateWithDB(tx, scopeID, target)
	if err != nil {
		return nil, err
	}
	if err := ScanScopeBlockedError(validation); err != nil {
		return nil, err
	}
	target = validation.NormalizedTarget
	scopeID = validation.ScopeID

	if policyID != "" {
		var policy models.Policy
		if err := tx.First(&policy, "id = ?", policyID).Error; err != nil {
			return nil, taskInputErrorf("policy not found: %s", policyID)
		}
		options = ApplyPolicyConfig(policy.Config, options)
	}

	options.EnablePortScan = true
	if options.PortScanType == "" {
		options.PortScanType = "top100"
	}
	task := &models.Task{
		Name:          name,
		Target:        target,
		PolicyID:      policyID,
		ScopeID:       scopeID,
		TriggerSource: strings.TrimSpace(origin.Source),
		TriggerID:     strings.TrimSpace(origin.ID),
		CreatedBy:     strings.TrimSpace(origin.ActorID),
		Options:       options,
		Status:        status,
	}
	if err := tx.Create(task).Error; err != nil {
		return nil, fmt.Errorf("create task: %w", err)
	}
	return task, nil
}

func ActiveTriggeredTaskExists(tx *gorm.DB, source, triggerID string) (bool, error) {
	var count int64
	err := tx.Model(&models.Task{}).
		Where("trigger_source = ? AND trigger_id = ? AND status IN ?", strings.TrimSpace(source), strings.TrimSpace(triggerID), []models.TaskStatus{models.TaskStatusQueued, models.TaskStatusRunning}).
		Count(&count).Error
	return count > 0, err
}

func lockTaskTrigger(tx *gorm.DB, origin models.TaskOrigin) error {
	if tx.Dialector.Name() != "postgres" {
		return nil
	}
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(strings.TrimSpace(origin.Source) + "\x00" + strings.TrimSpace(origin.ID)))
	if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", int64(hash.Sum64())).Error; err != nil {
		return fmt.Errorf("lock task trigger: %w", err)
	}
	return nil
}

// StartTask queues a pending task and rejects duplicate executions.
func (s *TaskService) StartTask(taskID string) error {
	var task models.Task
	if err := database.DB.Select("id", "target", "scope_id", "status").First(&task, "id = ?", taskID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return taskInputErrorf("task not found: %s", taskID)
		}
		return fmt.Errorf("load task for start: %w", err)
	}
	if task.Status != models.TaskStatusPending {
		return taskInputErrorf("cannot start task with status %s", task.Status)
	}
	validation, err := s.ValidateScopeTarget(task.ScopeID, task.Target)
	if err != nil {
		return err
	}
	if err := ScanScopeBlockedError(validation); err != nil {
		return err
	}
	result := database.DB.Model(&models.Task{}).
		Where("id = ? AND status = ?", taskID, models.TaskStatusPending).
		Updates(map[string]any{"status": models.TaskStatusQueued, "scope_id": validation.ScopeID, "target": validation.NormalizedTarget, "started_at": nil, "ended_at": nil, "error_msg": "", "progress": 0})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		var task models.Task
		if err := database.DB.Select("status").First(&task, "id = ?", taskID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return taskInputErrorf("task not found: %s", taskID)
			}
			return fmt.Errorf("reload task after start conflict: %w", err)
		}
		return taskInputErrorf("cannot start task with status %s", task.Status)
	}
	s.signalTaskQueue()
	return nil
}

// RetryTask creates a fresh queued task from a terminal task without mutating
// the original task or its collected assets.
func (s *TaskService) RetryTask(taskID string) (*models.Task, error) {
	var source models.Task
	if err := database.DB.First(&source, "id = ?", strings.TrimSpace(taskID)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, taskInputErrorf("task not found: %s", taskID)
		}
		return nil, fmt.Errorf("load task for retry: %w", err)
	}
	if !isRetryableTaskStatus(source.Status) {
		return nil, taskInputErrorf("cannot retry task with status %s", source.Status)
	}

	task, err := s.CreateQueuedTaskInScopeWithOrigin(source.Name, source.Target, source.PolicyID, source.ScopeID, source.Options, models.TaskOrigin{Source: models.TaskTriggerRetry, ID: source.ID, ActorID: source.CreatedBy})
	if err != nil {
		return nil, err
	}
	task.Progress = 0
	task.StartedAt = nil
	task.EndedAt = nil
	task.ErrorMsg = ""
	return task, nil
}

// WakeTaskQueue allows a caller that committed queued work in its own
// transaction to wake local workers immediately.
func (s *TaskService) WakeTaskQueue() {
	s.signalTaskQueue()
}

func isRetryableTaskStatus(status models.TaskStatus) bool {
	switch status {
	case models.TaskStatusCompleted, models.TaskStatusFailed, models.TaskStatusCancelled:
		return true
	default:
		return false
	}
}

func (s *TaskService) ValidateScopeTarget(scopeID, target string) (*ScanScopeValidation, error) {
	guard := s.scopeGuard
	if guard == nil {
		guard = NewScanScopeService()
	}
	return guard.Validate(scopeID, target)
}

// DeletePendingTask removes a newly-created task only if no caller has queued it yet.
func (s *TaskService) DeletePendingTask(taskID string) error {
	return database.DB.Where("id = ? AND status = ?", taskID, models.TaskStatusPending).Delete(&models.Task{}).Error
}

// DeleteTask stops a running task and removes all task-owned data atomically.
func (s *TaskService) DeleteTask(taskID string) error {
	var task models.Task
	if err := database.DB.First(&task, "id = ?", taskID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return taskInputErrorf("task not found: %s", taskID)
		}
		return fmt.Errorf("load task for deletion: %w", err)
	}
	if task.Status == models.TaskStatusQueued || task.Status == models.TaskStatusRunning {
		if err := s.CancelTask(taskID); err != nil {
			return fmt.Errorf("cancel task before deletion: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for s.IsTaskRunning(taskID) {
			select {
			case <-ctx.Done():
				return fmt.Errorf("task did not stop before deletion")
			case <-time.After(50 * time.Millisecond):
			}
		}
	}

	tx := database.DB.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	rollback := func(err error) error { tx.Rollback(); return err }
	leadReferences, err := promotedTaskLeadReferences(tx, taskID)
	if err != nil {
		return rollback(err)
	}
	if s.assetCatalog != nil {
		if err := s.assetCatalog.RemoveTask(tx, taskID); err != nil {
			return rollback(err)
		}
	}
	assets := []struct {
		assetType string
		model     any
	}{
		{"domain", &models.Domain{}}, {"ip", &models.IP{}}, {"port", &models.Port{}}, {"site", &models.Site{}},
	}
	for _, asset := range assets {
		subquery := tx.Model(asset.model).Select("id").Where("task_id = ?", taskID)
		if err := tx.Where("asset_type = ? AND asset_id IN (?)", asset.assetType, subquery).Delete(&models.AssetTagRelation{}).Error; err != nil {
			return rollback(err)
		}
		if err := tx.Where("asset_type = ? AND asset_id IN (?)", asset.assetType, subquery).Delete(&models.AssetGroupItem{}).Error; err != nil {
			return rollback(err)
		}
	}
	for _, model := range []any{&models.Domain{}, &models.IP{}, &models.Port{}, &models.Site{}, &models.URL{}, &models.CrawlerResult{}, &models.HTTPTransaction{}, &models.Vulnerability{}, &models.SensitiveMatch{}, &models.PoCExecutionLog{}, &models.TaskLog{}} {
		if err := tx.Where("task_id = ?", taskID).Delete(model).Error; err != nil {
			return rollback(err)
		}
	}
	if err := resetDeletedTaskLeadTriages(tx, leadReferences); err != nil {
		return rollback(err)
	}
	result := tx.Delete(&models.Task{}, "id = ?", taskID)
	if result.Error != nil {
		return rollback(result.Error)
	}
	if result.RowsAffected != 1 {
		return rollback(fmt.Errorf("task not found: %s", taskID))
	}
	return tx.Commit().Error
}

type taskLeadReference struct {
	AssetID string
	LeadID  string
}

func promotedTaskLeadReferences(db *gorm.DB, taskID string) ([]taskLeadReference, error) {
	var references []taskLeadReference
	err := db.Model(&models.PoCExecutionLog{}).
		Select("DISTINCT asset_id, lead_id").
		Where("task_id = ? AND asset_id <> '' AND lead_id <> '' AND vulnerability_id <> ''", taskID).
		Scan(&references).Error
	return references, err
}

func resetDeletedTaskLeadTriages(db *gorm.DB, references []taskLeadReference) error {
	for _, reference := range references {
		var remaining int64
		if err := db.Model(&models.PoCExecutionLog{}).
			Where("asset_id = ? AND lead_id = ? AND result = ? AND vulnerability_id <> ''", reference.AssetID, reference.LeadID, "vulnerable").
			Count(&remaining).Error; err != nil {
			return err
		}
		if remaining > 0 {
			continue
		}
		var assetCount int64
		if err := db.Model(&models.AssetEntity{}).Where("id = ?", reference.AssetID).Count(&assetCount).Error; err != nil {
			return err
		}
		if assetCount == 0 {
			if err := db.Where("asset_id = ? AND lead_id = ?", reference.AssetID, reference.LeadID).Delete(&models.AssetLeadTriage{}).Error; err != nil {
				return err
			}
			continue
		}
		if err := db.Model(&models.AssetLeadTriage{}).
			Where("asset_id = ? AND lead_id = ? AND status = ?", reference.AssetID, reference.LeadID, models.AssetLeadStatusValidated).
			Update("status", models.AssetLeadStatusNew).Error; err != nil {
			return err
		}
	}
	return nil
}

// ApplyPolicyConfig merges a reusable policy into task options.
func ApplyPolicyConfig(config models.PolicyConfig, options models.TaskOptions) models.TaskOptions {
	if config.EnableDomainBrute {
		options.EnableDomainBrute = true
		if options.DomainBruteType == "" {
			options.DomainBruteType = config.DomainBruteType
		}
		options.SmartDictGen = config.SmartDictGen
	}
	if config.EnablePortScan && options.PortScanType == "" {
		options.PortScanType = config.PortScanType
	}
	options.EnablePortScan = true
	options.EnableServiceDetect = config.EnableServiceDetect
	options.EnableOSDetect = config.EnableOSDetect
	options.EnableSSLCert = config.EnableSSLCert
	options.EnableDomainPlugins = config.EnableDomainPlugins
	if len(config.DomainPlugins) > 0 && len(options.DomainPlugins) == 0 {
		options.DomainPlugins = config.DomainPlugins
	}
	options.EnableARLHistory = config.EnableARLHistory
	options.SkipCDN = config.SkipCDN
	options.EnableSiteDetect = config.EnableSiteDetect
	options.EnableSearchEngine = config.EnableSearchEngine
	options.EnableCrawler = config.EnableCrawler
	options.EnableScreenshot = config.EnableScreenshot
	options.EnableFileLeak = config.EnableFileLeak
	if options.FileLeakDict == "" {
		options.FileLeakDict = config.FileLeakDict
	}
	options.EnableHostCollision = config.EnableHostCollision
	options.EnablePoCDetection = config.EnablePoCDetection
	options.EnableWIH = config.EnableWIH
	return options
}
