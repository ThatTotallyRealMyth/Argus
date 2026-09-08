package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AssetTag Asset label
type AssetTag struct {
	ID          string    `gorm:"primaryKey;type:uuid" json:"id"`
	Name        string    `gorm:"type:varchar(100);not null;uniqueIndex" json:"name"`
	Color       string    `gorm:"type:varchar(20);default:'#3B82F6'" json:"color"` // Tab Colour
	Description string    `gorm:"type:text" json:"description,omitempty"`
	Category    string    `gorm:"type:varchar(50)" json:"category,omitempty"` // Tab Classification: Line of operations, Importance, Environment, etc.
	CreatedBy   string    `gorm:"type:uuid" json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (at *AssetTag) BeforeCreate(tx *gorm.DB) error {
	if at.ID == "" {
		at.ID = uuid.New().String()
	}
	return nil
}

func (AssetTag) TableName() string {
	return "asset_tags"
}

// AssetTagRelation Assets-label association
type AssetTagRelation struct {
	ID        string    `gorm:"primaryKey;type:uuid" json:"id"`
	TagID     string    `gorm:"type:uuid;not null;index:idx_tag" json:"tag_id"`
	AssetType string    `gorm:"type:varchar(50);not null;index:idx_asset" json:"asset_type"` // domain, ip, site, port
	AssetID   string    `gorm:"type:uuid;not null;index:idx_asset" json:"asset_id"`
	CreatedBy string    `gorm:"type:uuid" json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func (atr *AssetTagRelation) BeforeCreate(tx *gorm.DB) error {
	if atr.ID == "" {
		atr.ID = uuid.New().String()
	}
	return nil
}

func (AssetTagRelation) TableName() string {
	return "asset_tag_relations"
}

// CreateTagRequest Create Tab Request
type CreateTagRequest struct {
	Name        string `json:"name" binding:"required"`
	Color       string `json:"color"`
	Description string `json:"description"`
	Category    string `json:"category"`
}

// UpdateTagRequest Update Tab Request
type UpdateTagRequest struct {
	Name        string `json:"name"`
	Color       string `json:"color"`
	Description string `json:"description"`
	Category    string `json:"category"`
}

// AddAssetTagRequest Request for the labeling of assets
type AddAssetTagRequest struct {
	TagIDs    []string `json:"tag_ids" binding:"required"`
	AssetType string   `json:"asset_type" binding:"required"` // domain, ip, site, port
	AssetID   string   `json:"asset_id" binding:"required"`
}
