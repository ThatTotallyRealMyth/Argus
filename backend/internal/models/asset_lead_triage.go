package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	AssetLeadStatusNew           = "new"
	AssetLeadStatusInvestigating = "investigating"
	AssetLeadStatusValidated     = "validated"
	AssetLeadStatusIgnored       = "ignored"
)

// AssetLeadTriage stores the hunter's state for a dynamically derived lead.
type AssetLeadTriage struct {
	ID        string    `gorm:"primaryKey;type:uuid" json:"id"`
	AssetID   string    `gorm:"type:uuid;not null;uniqueIndex:idx_asset_lead_triage_identity,priority:1;index" json:"asset_id"`
	LeadID    string    `gorm:"type:varchar(512);not null;uniqueIndex:idx_asset_lead_triage_identity,priority:2" json:"lead_id"`
	Status    string    `gorm:"type:varchar(32);not null;default:'new';index" json:"status"`
	Note      string    `gorm:"type:text;not null;default:''" json:"note"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (t *AssetLeadTriage) BeforeCreate(tx *gorm.DB) error {
	if t.ID == "" {
		t.ID = uuid.NewString()
	}
	if t.Status == "" {
		t.Status = AssetLeadStatusNew
	}
	return nil
}

func (AssetLeadTriage) TableName() string { return "asset_lead_triages" }
