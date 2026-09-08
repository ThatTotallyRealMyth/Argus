package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ScheduledTask Mission planning model
type ScheduledTask struct {
	ID          string         `gorm:"type:varchar(36);primaryKey" json:"id"`
	Name        string         `gorm:"type:varchar(255);not null" json:"name"`
	Description string         `gorm:"type:text" json:"description"`
	CronType    string         `gorm:"type:varchar(50);not null" json:"cron_type"`        // once, daily, weekly, monthly, custom
	CronExpr    string         `gorm:"type:varchar(100)" json:"cron_expr"`                // cronExpression, ForcustomType
	PolicyID    string         `gorm:"type:varchar(36);index" json:"policy_id,omitempty"` // Linking strategyID
	ScopeID     string         `gorm:"type:varchar(36);index" json:"scope_id,omitempty"`  // Authorized scan range
	TaskOptions TaskOptions    `gorm:"embedded;embeddedPrefix:task_" json:"task_options"` // Task Configuration
	IsEnabled   bool           `gorm:"default:true" json:"is_enabled"`
	LastRunAt   *time.Time     `json:"last_run_at,omitempty"`
	NextRunAt   *time.Time     `json:"next_run_at,omitempty"`
	RunCount    int            `gorm:"default:0" json:"run_count"`
	FailCount   int            `gorm:"default:0" json:"fail_count"`
	CreatedBy   string         `gorm:"type:varchar(36)" json:"created_by"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// TableName Specifying a tab name
func (ScheduledTask) TableName() string {
	return "scheduled_tasks"
}

// BeforeCreate Create a pre-hand hook
func (st *ScheduledTask) BeforeCreate(tx *gorm.DB) error {
	if st.ID == "" {
		st.ID = uuid.New().String()
	}
	return nil
}

// ScheduledTaskLog Planned Task Execution Log
type ScheduledTaskLog struct {
	ID              string     `gorm:"type:varchar(36);primaryKey" json:"id"`
	ScheduledTaskID string     `gorm:"type:varchar(36);not null;index" json:"scheduled_task_id"`
	TaskID          string     `gorm:"type:varchar(36);index" json:"task_id"`   // Actual created tasksID
	Status          string     `gorm:"type:varchar(50);not null" json:"status"` // success, failed
	Message         string     `gorm:"type:text" json:"message"`
	StartTime       time.Time  `json:"start_time"`
	EndTime         *time.Time `json:"end_time,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// TableName Specifying a tab name
func (ScheduledTaskLog) TableName() string {
	return "scheduled_task_logs"
}

// BeforeCreate Create a pre-hand hook
func (l *ScheduledTaskLog) BeforeCreate(tx *gorm.DB) error {
	if l.ID == "" {
		l.ID = uuid.New().String()
	}
	return nil
}
