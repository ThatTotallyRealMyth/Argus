package services

import (
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"gorm.io/gorm"
)

const taskLogBatchSize = 50

type taskLogRecorder struct {
	db       *gorm.DB
	taskID   string
	mu       sync.Mutex
	buffer   []models.TaskLog
	sequence int64
}

func newTaskLogger(taskID string) (*log.Logger, *taskLogRecorder) {
	recorder := &taskLogRecorder{db: database.DB, taskID: taskID, buffer: make([]models.TaskLog, 0, taskLogBatchSize)}
	return log.New(io.MultiWriter(log.Default().Writer(), recorder), "", log.LstdFlags), recorder
}

func (w *taskLogRecorder) Write(payload []byte) (int, error) {
	if w.db == nil || w.taskID == "" {
		return len(payload), nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	forceFlush := false
	for _, line := range strings.Split(string(payload), "\n") {
		message := strings.TrimSpace(line)
		if message == "" {
			continue
		}
		message = stripLogTimestamp(message)
		if message == "" {
			continue
		}
		level := "info"
		lower := strings.ToLower(message)
		if strings.Contains(lower, "failed") || strings.Contains(lower, "error") || strings.Contains(message, "Failed") || strings.Contains(message, "Error") {
			level = "error"
		} else if strings.Contains(lower, "warning") || strings.Contains(lower, "skipping") || strings.Contains(message, "Warning") || strings.Contains(message, "Skip") {
			level = "warning"
		}
		w.sequence++
		w.buffer = append(w.buffer, models.TaskLog{
			TaskID: w.taskID, Sequence: w.sequence, Level: level, Message: message, CreatedAt: time.Now(),
		})
		forceFlush = forceFlush || strings.HasPrefix(message, "Start") || strings.HasPrefix(message, "Tasks")
	}
	if forceFlush || len(w.buffer) >= taskLogBatchSize {
		w.flushLocked()
	}
	return len(payload), nil
}

func stripLogTimestamp(message string) string {
	if len(message) < 19 || message[4] != '/' || message[7] != '/' || message[10] != ' ' || message[13] != ':' || message[16] != ':' {
		return message
	}
	if len(message) == 19 {
		return ""
	}
	if message[19] == ' ' {
		return strings.TrimSpace(message[20:])
	}
	return message
}

func (w *taskLogRecorder) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.flushLocked()
}

func (w *taskLogRecorder) flushLocked() {
	if len(w.buffer) == 0 || w.db == nil {
		return
	}
	batch := append([]models.TaskLog(nil), w.buffer...)
	w.buffer = w.buffer[:0]
	if err := w.db.CreateInBatches(&batch, taskLogBatchSize).Error; err != nil {
		w.buffer = append(batch, w.buffer...)
		log.Printf("Failed to persist task %s logs: %v", w.taskID, err)
	}
}
