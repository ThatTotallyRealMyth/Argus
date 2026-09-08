package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Policy Policy Configuration Model
type Policy struct {
	ID          string         `gorm:"type:varchar(36);primaryKey" json:"id"`
	Name        string         `gorm:"type:varchar(255);not null;uniqueIndex" json:"name"`
	Description string         `gorm:"type:text" json:"description"`
	Config      PolicyConfig   `gorm:"embedded;embeddedPrefix:config_" json:"config"`
	IsDefault   bool           `gorm:"default:false" json:"is_default"`
	CreatedBy   string         `gorm:"type:varchar(36)" json:"created_by"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// PolicyConfig Policy Configuration Details
type PolicyConfig struct {
	// Domain Blast Configuration
	DomainBruteType   string `json:"domain_brute_type"` // big, test
	EnableDomainBrute bool   `json:"enable_domain_brute"`
	SmartDictGen      bool   `json:"smart_dict_gen"`

	// Port Scan Configuration
	PortScanType   string `json:"port_scan_type"` // all, top1000, top100, test
	EnablePortScan bool   `json:"enable_port_scan"`

	// Service Recognition Configuration
	EnableServiceDetect bool `json:"enable_service_detect"`
	EnableOSDetect      bool `json:"enable_os_detect"`
	EnableSSLCert       bool `json:"enable_ssl_cert"`

	// Domain name query plugin
	EnableDomainPlugins bool     `json:"enable_domain_plugins"`
	DomainPlugins       []string `gorm:"type:text;serializer:json" json:"domain_plugins"` // Plugin List: crtsh, fofa, hunter, custom_space_apiWait.

	// ARLHistory Query
	EnableARLHistory bool `json:"enable_arl_history"`

	// CDN
	SkipCDN bool `json:"skip_cdn"`

	// Site recognition
	EnableSiteDetect   bool `json:"enable_site_detect"`
	EnableSearchEngine bool `json:"enable_search_engine"`
	EnableCrawler      bool `json:"enable_crawler"`
	EnableScreenshot   bool `json:"enable_screenshot"`

	// Risk detection
	EnableFileLeak      bool   `json:"enable_file_leak"`
	FileLeakDict        string `json:"file_leak_dict"`
	EnableHostCollision bool   `json:"enable_host_collision"`

	// Advanced Functions
	EnablePoCDetection bool `json:"enable_poc_detection"` // SmartPoCTest
	EnableWIH          bool `json:"enable_wih"`
}

// TableName Specifying a tab name
func (Policy) TableName() string {
	return "policies"
}

// BeforeCreate Create a pre-hand hook
func (p *Policy) BeforeCreate(tx *gorm.DB) error {
	if p.ID == "" {
		p.ID = uuid.New().String()
	}
	return nil
}
