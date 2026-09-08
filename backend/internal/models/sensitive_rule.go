package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SensitiveRuleType Type of rule
type SensitiveRuleType string

const (
	SensitiveRuleTypeRegex   SensitiveRuleType = "regex"   // Regular Expression
	SensitiveRuleTypeKeyword SensitiveRuleType = "keyword" // Keywords Match
)

// SensitiveRuleSeverity Serious Level
type SensitiveRuleSeverity string

const (
	SensitiveRuleSeverityHigh   SensitiveRuleSeverity = "high"   // High risk
	SensitiveRuleSeverityMedium SensitiveRuleSeverity = "medium" // - It's dangerous.
	SensitiveRuleSeverityLow    SensitiveRuleSeverity = "low"    // Low risk.
)

// SensitiveRule Model of sensitive information rules
type SensitiveRule struct {
	ID          string                `gorm:"type:varchar(36);primaryKey" json:"id"`
	Name        string                `gorm:"type:varchar(255);not null;index" json:"name"`               // Rule name
	Type        SensitiveRuleType     `gorm:"type:varchar(50);not null;default:'regex'" json:"type"`      // Type of rule
	Pattern     string                `gorm:"type:text;not null" json:"pattern"`                          // Match Mode (Regular or keyword)
	Description string                `gorm:"type:text" json:"description"`                               // Rule description
	Severity    SensitiveRuleSeverity `gorm:"type:varchar(50);not null;default:'medium'" json:"severity"` // Serious Level
	IsEnabled   bool                  `gorm:"default:true;index" json:"is_enabled"`                       // Whether to enable
	IsBuiltIn   bool                  `gorm:"default:false" json:"is_built_in"`                           // Built-in rules (The built-in rule cannot be deleted)
	MatchCount  int                   `gorm:"default:0" json:"match_count"`                               // Matching Statistics
	Category    string                `gorm:"type:varchar(100);index" json:"category"`                    // Classification (Like: APIKey, Certificate, Databases, etc.)
	Example     string                `gorm:"type:text" json:"example"`                                   // Example: (For explanation)
	CreatedBy   string                `gorm:"type:varchar(36)" json:"created_by"`
	CreatedAt   time.Time             `json:"created_at"`
	UpdatedAt   time.Time             `json:"updated_at"`
	DeletedAt   gorm.DeletedAt        `gorm:"index" json:"deleted_at,omitempty"`
}

// TableName Specifying a tab name
func (SensitiveRule) TableName() string {
	return "sensitive_rules"
}

// BeforeCreate GORM hook - Auto-generated before creationID
func (sr *SensitiveRule) BeforeCreate(tx *gorm.DB) error {
	if sr.ID == "" {
		sr.ID = uuid.New().String()
	}
	return nil
}

// SensitiveMatch Sensitive information matching records
type SensitiveMatch struct {
	ID          string    `gorm:"type:varchar(36);primaryKey" json:"id"`
	TaskID      string    `gorm:"type:varchar(36);index" json:"task_id"` // TasksID
	RuleID      string    `gorm:"type:varchar(36);index" json:"rule_id"` // RulesID
	RuleName    string    `gorm:"type:varchar(255)" json:"rule_name"`    // Rule name (The snapshot.)
	URL         string    `gorm:"type:text" json:"url"`                  // FoundURL
	MatchedText string    `gorm:"type:text" json:"matched_text"`         // Matching text (Disaminative.)
	Context     string    `gorm:"type:text" json:"context"`              // Context
	Location    string    `gorm:"type:varchar(100)" json:"location"`     // Location (body/header/js/comment)
	Severity    string    `gorm:"type:varchar(50)" json:"severity"`      // Serious Level (The snapshot.)
	CreatedAt   time.Time `json:"created_at"`
}

// TableName Specifying a tab name
func (SensitiveMatch) TableName() string {
	return "sensitive_matches"
}

// BeforeCreate GORM hook
func (sm *SensitiveMatch) BeforeCreate(tx *gorm.DB) error {
	if sm.ID == "" {
		sm.ID = uuid.New().String()
	}
	return nil
}
