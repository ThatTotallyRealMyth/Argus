package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// MonitorType Type of monitoring
type MonitorType string

const (
	MonitorTypeDomain MonitorType = "domain"
	MonitorTypeIP     MonitorType = "ip"
	MonitorTypeSite   MonitorType = "site"
	MonitorTypeGithub MonitorType = "github"
	MonitorTypeWIH    MonitorType = "wih"
	MonitorTypeCVE    MonitorType = "cve"
)

// MonitorStatus Monitor Status
type MonitorStatus string

const (
	MonitorStatusActive  MonitorStatus = "active"
	MonitorStatusPaused  MonitorStatus = "paused"
	MonitorStatusStopped MonitorStatus = "stopped"
)

// MonitorOptions Monitor Options
type MonitorOptions struct {
	EnableDomainBrute bool `json:"enable_domain_brute"` // Enable subdomain brute force
	EnablePortScan    bool `json:"enable_port_scan"`    // Enable port scan
	EnableSiteDetect  bool `json:"enable_site_detect"`  // Enable site recognition
	EnableScreenshot  bool `json:"enable_screenshot"`   // Enable site screenshot
	EnablePoCscan     bool `json:"enable_poc_scan"`     // EnablePOCTest
}

// NotificationConfig Notification Configuration
type NotificationConfig struct {
	EnableWebhook  bool     `json:"enable_webhook"`  // UniversalWebhookAnnouncements
	EnableDingDing bool     `json:"enable_dingding"` // Nailing call.
	EnableFeishu   bool     `json:"enable_feishu"`   // Flight letter notification
	EnableEmail    bool     `json:"enable_email"`    // Send email notifications.
	EmailReceivers []string `json:"email_receivers"` // Mail Receiver
}

// Monitor Surveillance Tasks
type Monitor struct {
	ID                 string        `gorm:"primaryKey;type:uuid" json:"id"`
	Name               string        `gorm:"type:varchar(255);not null" json:"name"`
	Type               MonitorType   `gorm:"type:varchar(50);not null" json:"type"`
	Target             string        `gorm:"type:text;not null" json:"target"`
	Status             MonitorStatus `gorm:"type:varchar(50);default:'active'" json:"status"`
	Interval           int           `gorm:"not null" json:"interval"`                         // Monitor interval (sec)
	Options            string        `gorm:"type:text" json:"options"`                         // JSONMonitor Options for Format
	NotificationConfig string        `gorm:"type:text" json:"notification_config"`             // JSONNotification Configuration in Format
	AssetGroupID       *string       `gorm:"type:uuid" json:"asset_group_id,omitempty"`        // Asset ClusterID
	ScopeID            string        `gorm:"type:varchar(36);index" json:"scope_id,omitempty"` // Authorized scan range; Only web surveillance uses
	RunCount           int           `gorm:"default:0" json:"run_count"`                       // Runs
	LastRunTime        *time.Time    `json:"last_run_time,omitempty"`
	NextRunTime        *time.Time    `json:"next_run_time,omitempty"`
	LastError          string        `gorm:"type:text" json:"last_error,omitempty"` // Last Error
	CreatedAt          time.Time     `json:"created_at"`
	UpdatedAt          time.Time     `json:"updated_at"`
}

func (m *Monitor) BeforeCreate(tx *gorm.DB) error {
	if m.ID == "" {
		m.ID = uuid.New().String()
	}
	return nil
}

func (Monitor) TableName() string {
	return "monitors"
}

// MonitorResult Monitor results
type MonitorResult struct {
	ID          string    `gorm:"primaryKey;type:uuid" json:"id"`
	MonitorID   string    `gorm:"type:uuid;index;not null" json:"monitor_id"`
	ChangeType  string    `gorm:"type:varchar(100)" json:"change_type"` // new, modified, deleted
	Description string    `gorm:"type:text" json:"description"`
	Data        string    `gorm:"type:text" json:"data"` // JSONChange data in format
	CreatedAt   time.Time `json:"created_at"`
}

func (mr *MonitorResult) BeforeCreate(tx *gorm.DB) error {
	if mr.ID == "" {
		mr.ID = uuid.New().String()
	}
	return nil
}

func (MonitorResult) TableName() string {
	return "monitor_results"
}

// AssetGroup Asset Cluster
type AssetGroup struct {
	ID          string    `gorm:"primaryKey;type:uuid" json:"id"`
	Name        string    `gorm:"type:varchar(255);not null;unique" json:"name"`
	Description string    `gorm:"type:text" json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (ag *AssetGroup) BeforeCreate(tx *gorm.DB) error {
	if ag.ID == "" {
		ag.ID = uuid.New().String()
	}
	return nil
}

func (AssetGroup) TableName() string {
	return "asset_groups"
}

// AssetGroupItem Asset Cluster Item
type AssetGroupItem struct {
	ID        string    `gorm:"primaryKey;type:uuid" json:"id"`
	GroupID   string    `gorm:"type:uuid;not null;uniqueIndex:idx_group_asset" json:"group_id"`
	AssetType string    `gorm:"type:varchar(50);not null;uniqueIndex:idx_group_asset" json:"asset_type"` // domain, ip, site, canonical
	AssetID   string    `gorm:"type:uuid;not null;uniqueIndex:idx_group_asset" json:"asset_id"`
	CreatedAt time.Time `json:"created_at"`
}

func (agi *AssetGroupItem) BeforeCreate(tx *gorm.DB) error {
	if agi.ID == "" {
		agi.ID = uuid.New().String()
	}
	return nil
}

func (AssetGroupItem) TableName() string {
	return "asset_group_items"
}
