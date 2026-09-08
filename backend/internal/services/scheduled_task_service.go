package services

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/logger"
	"github.com/reconmaster/backend/internal/models"
	"github.com/robfig/cron/v3"
	"gorm.io/gorm"
)

const (
	maxScheduledTaskNameRunes        = 255
	maxScheduledTaskDescriptionBytes = 10000
	minimumScheduledTaskInterval     = time.Minute
)

var ErrScheduledTaskNotFound = errors.New("scheduled task not found")

type scheduledTaskInputError struct{ message string }

func (err scheduledTaskInputError) Error() string { return err.message }

func scheduledTaskInputErrorf(format string, values ...any) error {
	return scheduledTaskInputError{message: fmt.Sprintf(format, values...)}
}

func IsScheduledTaskInputError(err error) bool {
	var inputError scheduledTaskInputError
	return errors.As(err, &inputError) || errors.Is(err, ErrScheduledTaskNotFound) || IsTaskInputError(err) || IsScanScopeInputError(err)
}

type ScheduledTaskDefinition struct {
	Name        string
	Description string
	CronType    string
	CronExpr    string
	PolicyID    string
	ScopeID     string
	TaskOptions models.TaskOptions
}

type ScheduledTaskService struct {
	taskService *TaskService
	now         func() time.Time
}

func NewScheduledTaskService(taskService *TaskService) *ScheduledTaskService {
	return &ScheduledTaskService{taskService: taskService, now: time.Now}
}

func (s *ScheduledTaskService) Create(definition ScheduledTaskDefinition, createdBy string) (*models.ScheduledTask, error) {
	prepared, nextRun, err := s.prepare(definition)
	if err != nil {
		return nil, err
	}
	task := &models.ScheduledTask{
		Name: prepared.Name, Description: prepared.Description, CronType: prepared.CronType,
		CronExpr: prepared.CronExpr, PolicyID: prepared.PolicyID, ScopeID: prepared.ScopeID,
		TaskOptions: prepared.TaskOptions, IsEnabled: true, NextRunAt: nextRun,
		CreatedBy: strings.TrimSpace(createdBy),
	}
	if err := database.DB.Create(task).Error; err != nil {
		return nil, fmt.Errorf("create scheduled task: %w", err)
	}
	return task, nil
}

func (s *ScheduledTaskService) Update(id string, definition ScheduledTaskDefinition) (*models.ScheduledTask, error) {
	var task models.ScheduledTask
	if err := database.DB.First(&task, "id = ?", strings.TrimSpace(id)).Error; err != nil {
		return nil, scheduledTaskLookupError(err)
	}
	prepared, nextRun, err := s.prepare(definition)
	if err != nil {
		return nil, err
	}
	task.Name = prepared.Name
	task.Description = prepared.Description
	task.CronType = prepared.CronType
	task.CronExpr = prepared.CronExpr
	task.PolicyID = prepared.PolicyID
	task.ScopeID = prepared.ScopeID
	task.TaskOptions = prepared.TaskOptions
	task.NextRunAt = nextRun
	if err := database.DB.Save(&task).Error; err != nil {
		return nil, fmt.Errorf("update scheduled task: %w", err)
	}
	return &task, nil
}

func (s *ScheduledTaskService) SetEnabled(id string, enabled bool) (*models.ScheduledTask, error) {
	id = strings.TrimSpace(id)
	if _, err := s.SetEnabledMany([]string{id}, enabled); err != nil {
		return nil, err
	}
	var task models.ScheduledTask
	if err := database.DB.First(&task, "id = ?", id).Error; err != nil {
		return nil, scheduledTaskLookupError(err)
	}
	return &task, nil
}

func (s *ScheduledTaskService) Delete(id string) error {
	_, err := s.DeleteMany([]string{id})
	return err
}

func (s *ScheduledTaskService) SetEnabledMany(ids []string, enabled bool) (int64, error) {
	ids, err := normalizeScheduledTaskIDs(ids)
	if err != nil {
		return 0, err
	}
	var tasks []models.ScheduledTask
	if err := database.DB.Where("id IN ?", ids).Find(&tasks).Error; err != nil {
		return 0, fmt.Errorf("load scheduled tasks: %w", err)
	}
	if len(tasks) != len(ids) {
		return 0, fmt.Errorf("%w: one or more ids", ErrScheduledTaskNotFound)
	}
	type preparedUpdate struct {
		id      string
		updates map[string]any
	}
	preparedUpdates := make([]preparedUpdate, 0, len(tasks))
	for _, task := range tasks {
		updates := map[string]any{"is_enabled": enabled}
		if enabled {
			prepared, nextRun, prepareErr := s.prepare(ScheduledTaskDefinition{
				Name: task.Name, Description: task.Description, CronType: task.CronType,
				CronExpr: task.CronExpr, PolicyID: task.PolicyID, ScopeID: task.ScopeID,
				TaskOptions: task.TaskOptions,
			})
			if prepareErr != nil {
				return 0, prepareErr
			}
			updates["scope_id"] = prepared.ScopeID
			updates["task_target"] = prepared.TaskOptions.Target
			updates["next_run_at"] = nextRun
		}
		preparedUpdates = append(preparedUpdates, preparedUpdate{id: task.ID, updates: updates})
	}
	err = database.DB.Transaction(func(tx *gorm.DB) error {
		for _, update := range preparedUpdates {
			result := tx.Model(&models.ScheduledTask{}).Where("id = ?", update.id).Updates(update.updates)
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				return scheduledTaskInputErrorf("scheduled task not found")
			}
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("update scheduled task status: %w", err)
	}
	return int64(len(preparedUpdates)), nil
}

func (s *ScheduledTaskService) DeleteMany(ids []string) (int64, error) {
	ids, err := normalizeScheduledTaskIDs(ids)
	if err != nil {
		return 0, err
	}
	tx := database.DB.Begin()
	if tx.Error != nil {
		return 0, tx.Error
	}
	defer tx.Rollback()
	if err := tx.Where("scheduled_task_id IN ?", ids).Delete(&models.ScheduledTaskLog{}).Error; err != nil {
		return 0, fmt.Errorf("delete scheduled task logs: %w", err)
	}
	result := tx.Delete(&models.ScheduledTask{}, "id IN ?", ids)
	if result.Error != nil {
		return 0, fmt.Errorf("delete scheduled task: %w", result.Error)
	}
	if result.RowsAffected != int64(len(ids)) {
		return 0, fmt.Errorf("%w: one or more ids", ErrScheduledTaskNotFound)
	}
	if err := tx.Commit().Error; err != nil {
		return 0, err
	}
	return result.RowsAffected, nil
}

func (s *ScheduledTaskService) RunNow(id string) (*models.Task, error) {
	if s == nil || s.taskService == nil {
		return nil, errors.New("scheduled task runner is unavailable")
	}
	var scheduledTask models.ScheduledTask
	if err := database.DB.First(&scheduledTask, "id = ?", strings.TrimSpace(id)).Error; err != nil {
		return nil, scheduledTaskLookupError(err)
	}
	startTime := s.currentTime()
	task, err := s.taskService.CreateUniqueTriggeredQueuedTask(
		fmt.Sprintf("%s (Run Manually)", scheduledTask.Name), scheduledTask.TaskOptions.Target,
		scheduledTask.PolicyID, scheduledTask.ScopeID, scheduledTask.TaskOptions,
		models.TaskOrigin{Source: models.TaskTriggerSchedule, ID: scheduledTask.ID, ActorID: scheduledTask.CreatedBy},
	)
	if err != nil {
		publicMessage := "Failed to start task"
		if IsTaskInputError(err) {
			publicMessage = err.Error()
		}
		status, failed := "failed", true
		if errors.Is(err, ErrTriggeredTaskActive) {
			status, failed = "skipped", false
		}
		_ = s.recordRun(&scheduledTask, task, status, publicMessage, startTime, failed)
		return nil, err
	}
	if err := s.recordRun(&scheduledTask, task, "success", "Task created and started successfully", startTime, false); err != nil {
		logger.Error("Scheduled task run audit failed scheduled_task_id=%q task_id=%q error=%v", scheduledTask.ID, task.ID, err)
	}
	return task, nil
}

func (s *ScheduledTaskService) prepare(definition ScheduledTaskDefinition) (ScheduledTaskDefinition, *time.Time, error) {
	if s == nil || s.taskService == nil {
		return definition, nil, errors.New("scheduled task service is unavailable")
	}
	definition.Name = strings.TrimSpace(definition.Name)
	definition.Description = strings.TrimSpace(definition.Description)
	definition.CronType = strings.TrimSpace(definition.CronType)
	definition.CronExpr = strings.TrimSpace(definition.CronExpr)
	definition.PolicyID = strings.TrimSpace(definition.PolicyID)
	definition.ScopeID = strings.TrimSpace(definition.ScopeID)
	if definition.Name == "" || len([]rune(definition.Name)) > maxScheduledTaskNameRunes {
		return definition, nil, scheduledTaskInputErrorf("scheduled task name is required and must not exceed %d characters", maxScheduledTaskNameRunes)
	}
	if len(definition.Description) > maxScheduledTaskDescriptionBytes {
		return definition, nil, scheduledTaskInputErrorf("scheduled task description is too large")
	}
	cronExpr, nextRun, err := NormalizeScheduledCron(definition.CronType, definition.CronExpr, s.currentTime())
	if err != nil {
		return definition, nil, err
	}
	definition.CronExpr = cronExpr
	if definition.PolicyID != "" {
		var count int64
		if err := database.DB.Model(&models.Policy{}).Where("id = ?", definition.PolicyID).Count(&count).Error; err != nil {
			return definition, nil, fmt.Errorf("validate scheduled task policy: %w", err)
		}
		if count != 1 {
			return definition, nil, scheduledTaskInputErrorf("policy not found: %s", definition.PolicyID)
		}
	}
	validation, err := s.taskService.ValidateScopeTarget(definition.ScopeID, definition.TaskOptions.Target)
	if err == nil {
		err = ScanScopeBlockedError(validation)
	}
	if err != nil {
		return definition, nil, err
	}
	definition.ScopeID = validation.ScopeID
	definition.TaskOptions.Target = validation.NormalizedTarget
	definition.TaskOptions.EnablePortScan = true
	if definition.TaskOptions.PortScanType == "" {
		definition.TaskOptions.PortScanType = "top100"
	}
	return definition, nextRun, nil
}

func NormalizeScheduledCron(cronType, customExpr string, now time.Time) (string, *time.Time, error) {
	var expression string
	switch strings.TrimSpace(cronType) {
	case "once":
		next := now
		return "", &next, nil
	case "daily":
		expression = "0 0 2 * * *"
	case "weekly":
		expression = "0 0 2 * * 1"
	case "monthly":
		expression = "0 0 2 1 * *"
	case "custom":
		expression = strings.TrimSpace(customExpr)
		if expression == "" {
			return "", nil, scheduledTaskInputErrorf("custom cron expression is required")
		}
	default:
		return "", nil, scheduledTaskInputErrorf("invalid cron type: %s", cronType)
	}
	parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	schedule, err := parser.Parse(expression)
	if err != nil {
		return "", nil, scheduledTaskInputErrorf("invalid cron expression: %v", err)
	}
	next := schedule.Next(now)
	if schedule.Next(next).Sub(next) < minimumScheduledTaskInterval {
		return "", nil, scheduledTaskInputErrorf("scheduled task interval must be at least one minute")
	}
	return expression, &next, nil
}

func (s *ScheduledTaskService) recordRun(scheduledTask *models.ScheduledTask, task *models.Task, status, message string, startedAt time.Time, failed bool) error {
	endTime := s.currentTime()
	return database.DB.Transaction(func(tx *gorm.DB) error {
		updates := map[string]any{"last_run_at": startedAt}
		if failed {
			updates["fail_count"] = gorm.Expr("fail_count + 1")
		} else {
			updates["run_count"] = gorm.Expr("run_count + 1")
		}
		if err := tx.Model(&models.ScheduledTask{}).Where("id = ?", scheduledTask.ID).Updates(updates).Error; err != nil {
			return err
		}
		entry := &models.ScheduledTaskLog{
			ScheduledTaskID: scheduledTask.ID, Status: status, Message: message,
			StartTime: startedAt, EndTime: &endTime,
		}
		if task != nil {
			entry.TaskID = task.ID
		}
		return tx.Create(entry).Error
	})
}

func (s *ScheduledTaskService) currentTime() time.Time {
	if s != nil && s.now != nil {
		return s.now()
	}
	return time.Now()
}

func scheduledTaskLookupError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrScheduledTaskNotFound
	}
	return fmt.Errorf("load scheduled task: %w", err)
}

func normalizeScheduledTaskIDs(ids []string) ([]string, error) {
	if len(ids) == 0 || len(ids) > 200 {
		return nil, scheduledTaskInputErrorf("scheduled task ids must contain between 1 and 200 values")
	}
	seen := make(map[string]struct{}, len(ids))
	normalized := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			return nil, scheduledTaskInputErrorf("scheduled task id is required")
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		normalized = append(normalized, id)
	}
	return normalized, nil
}
