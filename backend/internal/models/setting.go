package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Setting System Settings Model
type Setting struct {
	ID          string         `gorm:"type:varchar(36);primaryKey" json:"id"`
	Category    string         `gorm:"type:varchar(50);not null;index" json:"category"` // api, notification, scanner, dictionary
	Key         string         `gorm:"type:varchar(100);not null;uniqueIndex" json:"key"`
	Value       string         `gorm:"type:text" json:"value"`
	Configured  bool           `gorm:"-" json:"configured,omitempty"`
	Description string         `gorm:"type:varchar(255)" json:"description"`
	IsEncrypted bool           `gorm:"default:false" json:"is_encrypted"` // Whether or not to encrypt storage (API KeyWait.)
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// TableName Specifying a tab name
func (Setting) TableName() string {
	return "settings"
}

// BeforeCreate Create a pre-hand hook
func (s *Setting) BeforeCreate(tx *gorm.DB) error {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	return nil
}

// Dictionary Dictionary Model
type Dictionary struct {
	ID          string         `gorm:"type:varchar(36);primaryKey" json:"id"`
	Name        string         `gorm:"type:varchar(100);not null" json:"name"`
	Type        string         `gorm:"type:varchar(50);not null" json:"type"` // domain, port, file_leak
	FilePath    string         `gorm:"type:varchar(255);not null" json:"file_path"`
	Size        int64          `json:"size"`       // File Size (Bytes)
	LineCount   int            `json:"line_count"` // Lines
	IsDefault   bool           `gorm:"default:false" json:"is_default"`
	Description string         `gorm:"type:text" json:"description"`
	CreatedBy   string         `gorm:"type:varchar(36)" json:"created_by"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// TableName Specifying a tab name
func (Dictionary) TableName() string {
	return "dictionaries"
}

// BeforeCreate Create a pre-hand hook
func (d *Dictionary) BeforeCreate(tx *gorm.DB) error {
	if d.ID == "" {
		d.ID = uuid.New().String()
	}
	return nil
}

// SettingCategory Set classification constant
const (
	SettingCategoryAPI          = "api"
	SettingCategoryNotification = "notification"
	SettingCategoryScanner      = "scanner"
	SettingCategoryDictionary   = "dictionary"
	SettingCategorySecurity     = "security"
)

// Default setting keyname
const (
	// APIConfigure
	SettingKeyFOFAEmail             = "fofa_email"
	SettingKeyFOFAKey               = "fofa_key"
	SettingKeyHunterKey             = "hunter_api_key"
	SettingKeyQuakeKey              = "quake_api_key"
	SettingKeyZoomEyeKey            = "zoomeye_api_key"
	SettingKeyCustomSpaceAPIURL     = "custom_space_api_url"
	SettingKeyCustomSpaceAPIHeaders = "custom_space_api_headers"
	SettingKeyGitHubToken           = "github_token"
	SettingKeyGitHubEnabled         = "github_enabled"
	SettingKeyShodanKey             = "shodan_api_key"
	SettingKeyVirusTotalKey         = "virustotal_api_key"
	SettingKeyEnterpriseICPURL      = "enterprise_icp_api_url"
	SettingKeyEnterpriseICPHeaders  = "enterprise_icp_api_headers"
	SettingKeyEnterpriseICPEnabled  = "enterprise_icp_enabled"

	// Notification Configuration
	SettingKeyWebhookEnabled  = "webhook_enabled"
	SettingKeyWebhookURL      = "webhook_url"
	SettingKeyWebhookSecret   = "webhook_secret"
	SettingKeyDingDingEnabled = "dingding_enabled"
	SettingKeyDingDingWebhook = "dingding_webhook"
	SettingKeyDingDingSecret  = "dingding_secret"
	SettingKeyFeishuEnabled   = "feishu_enabled"
	SettingKeyFeishuWebhook   = "feishu_webhook"
	SettingKeyFeishuSecret    = "feishu_secret"
	SettingKeyEmailEnabled    = "email_enabled"
	SettingKeyEmailSMTPServer = "email_smtp_server"
	SettingKeyEmailSMTPPort   = "email_smtp_port"
	SettingKeyEmailUsername   = "email_username"
	SettingKeyEmailPassword   = "email_password"
	SettingKeyEmailFrom       = "email_from"

	// Scanner Configuration
	SettingKeyDomainBruteConcurrent = "domain_brute_concurrent"
	SettingKeyPortScanConcurrent    = "port_scan_concurrent"
	SettingKeySiteDetectConcurrent  = "site_detect_concurrent"

	// Security Configuration
	SettingKeyBlackIPs     = "black_ips"
	SettingKeyBlackDomains = "black_domains"
)
