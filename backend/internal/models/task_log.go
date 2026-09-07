package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// TaskLog stores the scanner output that belongs to one task run.
type TaskLog struct {
	ID        string    `gorm:"primaryKey;type:uuid" json:"id"`
	TaskID    string    `gorm:"type:uuid;not null;index:idx_task_logs_order,priority:1" json:"task_id"`
	Sequence  int64     `gorm:"not null;default:0;index:idx_task_logs_order,priority:2" json:"sequence"`
	Level     string    `gorm:"type:varchar(16);not null;default:'info';index" json:"level"`
	Message   string    `gorm:"type:text;not null" json:"message"`
	CreatedAt time.Time `gorm:"index" json:"created_at"`
}

func (l *TaskLog) BeforeCreate(tx *gorm.DB) error {
	if l.ID == "" {
		l.ID = uuid.NewString()
	}
	return nil
}

func (TaskLog) TableName() string { return "task_logs" }
