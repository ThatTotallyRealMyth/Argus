package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Fingerprint Fingerprint Model
type Fingerprint struct {
	ID          string         `gorm:"type:varchar(36);primaryKey" json:"id"`
	Name        string         `gorm:"type:varchar(255);not null;uniqueIndex:idx_fingerprint_unique" json:"name"`
	Category    string         `gorm:"type:varchar(100);not null;index" json:"category"`
	DSL         []string       `gorm:"type:text;serializer:json" json:"dsl"` // DSLRule array (Allow empty space to move)
	Description string         `gorm:"type:text" json:"description"`
	IsEnabled   bool           `gorm:"default:true" json:"is_enabled"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// TableName Specifying a tab name
func (Fingerprint) TableName() string {
	return "fingerprints"
}

// BeforeCreate Create a pre-hand hook
func (f *Fingerprint) BeforeCreate(tx *gorm.DB) error {
	if f.ID == "" {
		f.ID = uuid.New().String()
	}
	return nil
}

