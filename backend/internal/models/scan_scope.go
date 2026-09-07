package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ScanScope defines the authorized network boundary applied to scan tasks.
type ScanScope struct {
	ID          string    `gorm:"primaryKey;type:uuid" json:"id"`
	Name        string    `gorm:"type:varchar(255);not null;uniqueIndex" json:"name"`
	Description string    `gorm:"type:text" json:"description,omitempty"`
	AllowRules  []string  `gorm:"type:jsonb;serializer:json;not null;default:'[]'" json:"allow_rules"`
	DenyRules   []string  `gorm:"type:jsonb;serializer:json;not null;default:'[]'" json:"deny_rules"`
	IsDefault   bool      `gorm:"not null;default:false;index" json:"is_default"`
	CreatedBy   string    `gorm:"type:varchar(36)" json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (scope *ScanScope) BeforeCreate(tx *gorm.DB) error {
	if scope.ID == "" {
		scope.ID = uuid.NewString()
	}
	return nil
}

func (ScanScope) TableName() string { return "scan_scopes" }
