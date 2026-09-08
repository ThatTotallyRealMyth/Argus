package models

import (
	"strings"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

// PoC PoCModel
type PoC struct {
	ID               string         `gorm:"type:varchar(36);primaryKey" json:"id"`
	Name             string         `gorm:"type:varchar(255);not null;index" json:"name"`
	Category         string         `gorm:"type:varchar(100);not null;index" json:"category"`
	Severity         string         `gorm:"type:varchar(50);not null" json:"severity"` // critical, high, medium, low, info
	CVE              string         `gorm:"type:varchar(50);index" json:"cve"`
	Product          string         `gorm:"type:varchar(255);index" json:"product"`
	AffectedVersions string         `gorm:"type:varchar(1000)" json:"affected_versions"`
	Author           string         `gorm:"type:varchar(100)" json:"author"`
	Description      string         `gorm:"type:text" json:"description"`
	Reference        string         `gorm:"type:text" json:"reference"`
	PoCType          string         `gorm:"type:varchar(50);not null" json:"poc_type"` // nuclei, xray, custom
	PoCContent       string         `gorm:"type:text;not null" json:"poc_content"`
	Tags             string         `gorm:"type:varchar(500)" json:"tags"`                      // Comma separated
	Fingerprints     string         `gorm:"type:varchar(1000)" json:"fingerprints"`             // Associated fingerprint name,Comma separated,For Smart Matching
	AppNames         string         `gorm:"type:varchar(1000);index" json:"app_names"`          // Apply name keywords,Comma separated
	MatchMode        string         `gorm:"type:varchar(20);default:'fuzzy'" json:"match_mode"` // Match Mode: exact(Precision), fuzzy(Blur), keyword(Keywords)
	IsEnabled        bool           `gorm:"default:true" json:"is_enabled"`
	CreatedBy        string         `gorm:"type:varchar(36)" json:"created_by"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
	DeletedAt        gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// TableName Specifying a tab name
func (PoC) TableName() string {
	return "pocs"
}

// BeforeCreate Create a pre-hand hook
func (p *PoC) BeforeCreate(tx *gorm.DB) error {
	if p.ID == "" {
		p.ID = uuid.New().String()
	}
	return nil
}

// BeforeSave normalizes legacy Nuclei templates that were stored with escaped line breaks.
func (p *PoC) BeforeSave(tx *gorm.DB) error {
	p.PoCContent = normalizePoCContent(p.PoCType, p.PoCContent)
	return nil
}

// AfterFind keeps legacy records usable in the editor and scanner before they are saved again.
func (p *PoC) AfterFind(tx *gorm.DB) error {
	p.PoCContent = normalizePoCContent(p.PoCType, p.PoCContent)
	return nil
}

func normalizePoCContent(pocType, content string) string {
	if !strings.EqualFold(strings.TrimSpace(pocType), "nuclei") || strings.ContainsAny(content, "\r\n") || !strings.Contains(content, `\n`) {
		return content
	}

	candidate := strings.ReplaceAll(content, `\r\n`, "\n")
	candidate = strings.ReplaceAll(candidate, `\n`, "\n")
	candidate = strings.ReplaceAll(candidate, `\r`, "\n")

	var document map[string]interface{}
	if err := yaml.Unmarshal([]byte(candidate), &document); err != nil {
		return content
	}
	id, hasID := document["id"].(string)
	_, hasInfo := document["info"]
	if !hasID || strings.TrimSpace(id) == "" || !hasInfo {
		return content
	}
	return candidate
}

// PoCExecutionLog PoCExecute Log
type PoCExecutionLog struct {
	ID               string    `gorm:"type:varchar(36);primaryKey" json:"id"`
	PoCID            string    `gorm:"type:varchar(36);not null;index" json:"poc_id"`
	VulnerabilityID  string    `gorm:"type:varchar(36);index" json:"vulnerability_id,omitempty"`
	AssetID          string    `gorm:"type:varchar(36);index" json:"asset_id,omitempty"`
	LeadID           string    `gorm:"type:varchar(512);index" json:"lead_id,omitempty"`
	TaskID           string    `gorm:"type:varchar(36);index" json:"task_id"`
	ScopeID          string    `gorm:"type:varchar(36);index" json:"scope_id,omitempty"`
	InvocationSource string    `gorm:"type:varchar(32);index" json:"invocation_source,omitempty"`
	ActorID          string    `gorm:"type:varchar(36);index" json:"actor_id,omitempty"`
	Target           string    `gorm:"type:varchar(500);not null" json:"target"`
	Result           string    `gorm:"type:varchar(50);not null" json:"result"` // vulnerable, safe, error
	Details          string    `gorm:"type:text" json:"details"`
	CreatedAt        time.Time `json:"created_at"`
}

// TableName Specifying a tab name
func (PoCExecutionLog) TableName() string {
	return "poc_execution_logs"
}

// BeforeCreate Create a pre-hand hook
func (l *PoCExecutionLog) BeforeCreate(tx *gorm.DB) error {
	if l.ID == "" {
		l.ID = uuid.New().String()
	}
	return nil
}
