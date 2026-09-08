package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// TaskStatus Task Status
type TaskStatus string

const (
	TaskStatusPending   TaskStatus = "pending"
	TaskStatusQueued    TaskStatus = "queued"
	TaskStatusRunning   TaskStatus = "running"
	TaskStatusCompleted TaskStatus = "completed"
	TaskStatusFailed    TaskStatus = "failed"
	TaskStatusCancelled TaskStatus = "cancelled"
)

const (
	TaskTriggerManual     = "manual"
	TaskTriggerMCP        = "mcp"
	TaskTriggerMonitor    = "monitor"
	TaskTriggerSchedule   = "schedule"
	TaskTriggerEnterprise = "enterprise"
	TaskTriggerRetry      = "retry"
)

type TaskOrigin struct {
	Source  string
	ID      string
	ActorID string
}

// Task Mission Model
type Task struct {
	ID            string      `gorm:"primaryKey;type:uuid" json:"id"`
	Name          string      `gorm:"type:varchar(255);not null" json:"name"`
	Target        string      `gorm:"type:text;not null" json:"target"`                  // IP, IPParagraph or domain name, Multiple Comma Separated
	PolicyID      string      `gorm:"type:varchar(36);index" json:"policy_id,omitempty"` // Linking strategyID
	ScopeID       string      `gorm:"type:varchar(36);index" json:"scope_id,omitempty"`  // Authorized scan range; Empty value for compatibility mode
	TriggerSource string      `gorm:"type:varchar(32);index:idx_tasks_trigger,priority:1" json:"trigger_source,omitempty"`
	TriggerID     string      `gorm:"type:varchar(64);index:idx_tasks_trigger,priority:2" json:"trigger_id,omitempty"`
	CreatedBy     string      `gorm:"type:varchar(36);index" json:"created_by,omitempty"`
	Status        TaskStatus  `gorm:"type:varchar(50);default:'pending';index:idx_tasks_queue,priority:1" json:"status"`
	Options       TaskOptions `gorm:"embedded;embeddedPrefix:opt_" json:"options"`
	Progress      int         `gorm:"default:0" json:"progress"`                // 0-100
	AssetProfile  string      `gorm:"type:text" json:"asset_profile,omitempty"` // Asset portraitJSON
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `gorm:"index:idx_tasks_queue,priority:2" json:"updated_at"`
	StartedAt     *time.Time  `json:"started_at,omitempty"`
	EndedAt       *time.Time  `json:"ended_at,omitempty"`
	ErrorMsg      string      `gorm:"type:text" json:"error_msg,omitempty"`
}

// TaskOptions Task Options
type TaskOptions struct {
	// Objective
	Target string `json:"target"` // IP, IPParagraph or domain name, Multiple Comma Separated

	// Domain Blast
	DomainBruteType   string `json:"domain_brute_type"` // big, test
	EnableDomainBrute bool   `json:"enable_domain_brute"`
	SmartDictGen      bool   `json:"smart_dict_gen"`

	// Port Scan
	PortScanType   string `json:"port_scan_type"` // all, top1000, top100, test
	EnablePortScan bool   `json:"enable_port_scan"`
	EnableCSegment bool   `json:"enable_c_segment"` // EnableCParagraph Scan

	// Service recognition
	EnableServiceDetect bool `json:"enable_service_detect"`
	EnableOSDetect      bool `json:"enable_os_detect"`
	EnableSSLCert       bool `json:"enable_ssl_cert"`

	// Domain name query plugin
	EnableDomainPlugins bool     `json:"enable_domain_plugins"`
	DomainPlugins       []string `gorm:"type:text;serializer:json" json:"domain_plugins"` // alienvault, certspotter, crtsh, fofa, hunter, custom_space_apiWait.

	// ARLHistory Query
	EnableARLHistory bool `json:"enable_arl_history"`

	// CDN
	SkipCDN bool `json:"skip_cdn"`

	// Site recognition
	EnableSiteDetect   bool `json:"enable_site_detect"`
	EnableSearchEngine bool `json:"enable_search_engine"`
	EnableCrawler      bool `json:"enable_crawler"`
	CrawlerDepth       int  `json:"crawler_depth"` // Crawling depth, Default3
	CrawlerPages       int  `json:"crawler_pages"` // Maximum number of pages, Default100
	EnableScreenshot   bool `json:"enable_screenshot"`

	// Risk detection
	EnableFileLeak      bool   `json:"enable_file_leak"`
	FileLeakDict        string `json:"file_leak_dict"`
	EnableHostCollision bool   `json:"enable_host_collision"`

	// Advanced Functions
	EnablePoCDetection bool   `json:"enable_poc_detection"` // SmartPoCTest(AlternativeNuclei/XPOC/Afrog)
	EnableCustomScript bool   `json:"enable_custom_script"`
	CustomScriptPath   string `json:"custom_script_path"`
	EnableWIH          bool   `json:"enable_wih"`

	// Passive Scan
	EnablePassiveScan bool `json:"enable_passive_scan"`
}

// BeforeCreate GORMHook.
func (t *Task) BeforeCreate(tx *gorm.DB) error {
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	return nil
}

// TableName Specifying a tab name
func (Task) TableName() string {
	return "tasks"
}
