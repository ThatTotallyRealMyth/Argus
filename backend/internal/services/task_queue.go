package services

import (
	"log"
	"time"

	"github.com/reconmaster/backend/internal/config"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"gorm.io/gorm/clause"
)

const taskQueuePollInterval = 2 * time.Second

func configuredTaskWorkerCount() int {
	workers := 1
	if config.GlobalConfig != nil && config.GlobalConfig.Scanner.MaxConcurrentTasks > 0 {
		workers = config.GlobalConfig.Scanner.MaxConcurrentTasks
	}
	return normalizeTaskWorkerCount(workers)
}

func normalizeTaskWorkerCount(workers int) int {
	if workers < 1 {
		return 1
	}
	if workers > 64 {
		return 64
	}
	return workers
}

func (s *TaskService) startTaskQueue() {
	if database.DB == nil || s.workerCount <= 0 {
		return
	}
	now := time.Now()
	result := database.DB.Model(&models.Task{}).
		Where("status = ?", models.TaskStatusRunning).
		Updates(map[string]any{
			"status":    models.TaskStatusFailed,
			"ended_at":  &now,
			"error_msg": "Task execution was interrupted by a service restart",
		})
	if result.Error != nil {
		log.Printf("Failed to recover interrupted tasks: %v", result.Error)
	} else if result.RowsAffected > 0 {
		log.Printf("Marked %d interrupted task(s) as failed", result.RowsAffected)
	}

	for worker := 0; worker < s.workerCount; worker++ {
		s.queueWG.Add(1)
		go s.taskWorker(worker + 1)
	}
	log.Printf("Task queue started with %d worker(s)", s.workerCount)
}

func (s *TaskService) taskWorker(worker int) {
	defer s.queueWG.Done()
	ticker := time.NewTicker(taskQueuePollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.queueStop:
			return
		default:
		}

		taskID, claimed, err := s.claimQueuedTask()
		if err != nil {
			log.Printf("Task worker %d failed to claim work: %v", worker, err)
			select {
			case <-time.After(time.Second):
			case <-s.queueStop:
				return
			}
			continue
		}
		if claimed {
			log.Printf("Task worker %d claimed task %s", worker, taskID)
			s.ExecuteTask(taskID)
			continue
		}

		select {
		case <-s.queueWake:
		case <-ticker.C:
		case <-s.queueStop:
			return
		}
	}
}

func (s *TaskService) claimQueuedTask() (string, bool, error) {
	tx := database.DB.Begin()
	if tx.Error != nil {
		return "", false, tx.Error
	}
	defer tx.Rollback()

	var tasks []models.Task
	err := tx.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
		Where("status = ?", models.TaskStatusQueued).
		Order("updated_at ASC").
		Limit(1).
		Find(&tasks).Error
	if err != nil {
		return "", false, err
	}
	if len(tasks) == 0 {
		return "", false, nil
	}
	task := tasks[0]

	now := time.Now()
	result := tx.Model(&models.Task{}).
		Where("id = ? AND status = ?", task.ID, models.TaskStatusQueued).
		Updates(map[string]any{
			"status":     models.TaskStatusRunning,
			"started_at": &now,
			"ended_at":   nil,
			"error_msg":  "",
			"progress":   0,
		})
	if result.Error != nil {
		return "", false, result.Error
	}
	if result.RowsAffected != 1 {
		return "", false, nil
	}
	if err := tx.Commit().Error; err != nil {
		return "", false, err
	}
	return task.ID, true, nil
}

func (s *TaskService) signalTaskQueue() {
	if s.queueWake == nil {
		return
	}
	select {
	case s.queueWake <- struct{}{}:
	default:
	}
}

func (s *TaskService) WorkerCount() int {
	return s.workerCount
}

func (s *TaskService) Close() {
	s.queueStopOnce.Do(func() {
		s.runningTasksMux.RLock()
		cancellations := make([]func(), 0, len(s.runningTasks))
		for _, cancel := range s.runningTasks {
			cancellations = append(cancellations, cancel)
		}
		s.runningTasksMux.RUnlock()
		for _, cancel := range cancellations {
			cancel()
		}
		if s.queueStop != nil {
			close(s.queueStop)
		}
		s.queueWG.Wait()
	})
}
