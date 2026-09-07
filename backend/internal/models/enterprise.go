package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type EnterpriseQueryStatus string

const (
	EnterpriseQueryQueued    EnterpriseQueryStatus = "queued"
	EnterpriseQueryRunning   EnterpriseQueryStatus = "running"
	EnterpriseQueryCompleted EnterpriseQueryStatus = "completed"
	EnterpriseQueryFailed    EnterpriseQueryStatus = "failed"
)

type EnterpriseQuery struct {
	ID            string                `gorm:"primaryKey;type:uuid" json:"id"`
	Name          string                `gorm:"type:varchar(255);not null" json:"name"`
	Keyword       string                `gorm:"type:varchar(255);not null;index" json:"keyword"`
	Provider      string                `gorm:"type:varchar(50);not null;index" json:"provider"`
	QueryTypes    []string              `gorm:"type:jsonb;serializer:json" json:"query_types"`
	Status        EnterpriseQueryStatus `gorm:"type:varchar(32);not null;index:idx_enterprise_query_queue,priority:1" json:"status"`
	TotalCount    int64                 `gorm:"not null;default:0" json:"total_count"`
	DomainCount   int64                 `gorm:"not null;default:0" json:"domain_count"`
	AppCount      int64                 `gorm:"not null;default:0" json:"app_count"`
	MiniAppCount  int64                 `gorm:"not null;default:0" json:"mini_app_count"`
	QuickAppCount int64                 `gorm:"not null;default:0" json:"quick_app_count"`
	SyncedCount   int64                 `gorm:"not null;default:0" json:"synced_count"`
	ErrorMsg      string                `gorm:"type:text" json:"error_msg,omitempty"`
	CreatedBy     string                `gorm:"type:varchar(36)" json:"created_by,omitempty"`
	StartedAt     *time.Time            `json:"started_at,omitempty"`
	EndedAt       *time.Time            `json:"ended_at,omitempty"`
	CreatedAt     time.Time             `json:"created_at"`
	UpdatedAt     time.Time             `gorm:"index:idx_enterprise_query_queue,priority:2" json:"updated_at"`
}

func (query *EnterpriseQuery) BeforeCreate(tx *gorm.DB) error {
	if query.ID == "" {
		query.ID = uuid.NewString()
	}
	return nil
}

func (EnterpriseQuery) TableName() string { return "enterprise_queries" }

type EnterpriseAsset struct {
	ID           string    `gorm:"primaryKey;type:uuid" json:"id"`
	QueryID      string    `gorm:"type:uuid;not null;uniqueIndex:idx_enterprise_asset_identity,priority:1;index" json:"query_id"`
	Provider     string    `gorm:"type:varchar(50);not null;uniqueIndex:idx_enterprise_asset_identity,priority:2;index" json:"provider"`
	Kind         string    `gorm:"type:varchar(50);not null;uniqueIndex:idx_enterprise_asset_identity,priority:3;index" json:"kind"`
	CanonicalKey string    `gorm:"type:text;not null;uniqueIndex:idx_enterprise_asset_identity,priority:4" json:"canonical_key"`
	CompanyName  string    `gorm:"type:varchar(500);index" json:"company_name,omitempty"`
	Name         string    `gorm:"type:varchar(500);index" json:"name,omitempty"`
	Domain       string    `gorm:"type:varchar(500);index" json:"domain,omitempty"`
	License      string    `gorm:"type:varchar(255);index" json:"license,omitempty"`
	RawData      string    `gorm:"type:jsonb;not null;default:'{}'" json:"raw_data"`
	CreatedAt    time.Time `json:"created_at"`
}

func (asset *EnterpriseAsset) BeforeCreate(tx *gorm.DB) error {
	if asset.ID == "" {
		asset.ID = uuid.NewString()
	}
	return nil
}

func (EnterpriseAsset) TableName() string { return "enterprise_assets" }
