package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const DefaultAssetScope = "default"

// AssetEntity is the canonical identity shared by observations from many tasks.
type AssetEntity struct {
	ID                 string    `gorm:"primaryKey;type:uuid" json:"id"`
	ScopeID            string    `gorm:"type:varchar(64);not null;default:'default';uniqueIndex:idx_asset_entity_identity,priority:1" json:"scope_id"`
	Kind               string    `gorm:"type:varchar(32);not null;uniqueIndex:idx_asset_entity_identity,priority:2;index" json:"kind"`
	CanonicalKey       string    `gorm:"type:text;not null;uniqueIndex:idx_asset_entity_identity,priority:3" json:"canonical_key"`
	DisplayValue       string    `gorm:"type:text;not null" json:"display_value"`
	Status             string    `gorm:"type:varchar(32);not null;default:'active';index" json:"status"`
	RiskScore          int       `gorm:"not null;default:0;index" json:"risk_score"`
	VulnerabilityCount int64     `gorm:"not null;default:0" json:"vulnerability_count"`
	CriticalCount      int64     `gorm:"not null;default:0" json:"critical_count"`
	HighCount          int64     `gorm:"not null;default:0" json:"high_count"`
	ChangeCount        int64     `gorm:"not null;default:0" json:"change_count"`
	ObservationCount   int64     `gorm:"not null;default:0" json:"observation_count"`
	LastTaskID         string    `gorm:"type:uuid;index" json:"last_task_id,omitempty"`
	LastOriginType     string    `gorm:"type:varchar(32);not null;default:'task';index" json:"last_origin_type"`
	CurrentData        string    `gorm:"type:jsonb;not null;default:'{}'" json:"current_data"`
	FirstSeenAt        time.Time `gorm:"not null;index" json:"first_seen_at"`
	LastSeenAt         time.Time `gorm:"not null;index" json:"last_seen_at"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

func (a *AssetEntity) BeforeCreate(tx *gorm.DB) error {
	if a.ID == "" {
		a.ID = uuid.NewString()
	}
	if a.ScopeID == "" {
		a.ScopeID = DefaultAssetScope
	}
	if a.LastOriginType == "" {
		a.LastOriginType = "task"
	}
	return nil
}

func (AssetEntity) TableName() string { return "asset_entities" }

// AssetObservation records where and when a task or external discovery observed an entity.
type AssetObservation struct {
	ID          string    `gorm:"primaryKey;type:uuid" json:"id"`
	AssetID     string    `gorm:"type:uuid;not null;uniqueIndex:idx_asset_observation_source,priority:1;index" json:"asset_id"`
	TaskID      string    `gorm:"type:uuid;not null;uniqueIndex:idx_asset_observation_source,priority:2;index" json:"task_id"`
	OriginType  string    `gorm:"type:varchar(32);not null;default:'task';index" json:"origin_type"`
	SourceType  string    `gorm:"type:varchar(64);not null;uniqueIndex:idx_asset_observation_source,priority:3" json:"source_type"`
	SourceRef   string    `gorm:"type:varchar(128);not null;uniqueIndex:idx_asset_observation_source,priority:4" json:"source_ref"`
	Payload     string    `gorm:"type:jsonb;not null;default:'{}'" json:"payload"`
	PayloadHash string    `gorm:"type:varchar(64);not null;index" json:"payload_hash"`
	StateData   string    `gorm:"type:jsonb;not null;default:'{}'" json:"state_data"`
	StateHash   string    `gorm:"type:varchar(64);not null;default:'';index" json:"state_hash"`
	ObservedAt  time.Time `gorm:"not null;index" json:"observed_at"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (o *AssetObservation) BeforeCreate(tx *gorm.DB) error {
	if o.ID == "" {
		o.ID = uuid.NewString()
	}
	if o.OriginType == "" {
		o.OriginType = "task"
	}
	return nil
}

func (AssetObservation) TableName() string { return "asset_observations" }

// CanonicalAssetRelation connects canonical entities without task-local IDs.
type CanonicalAssetRelation struct {
	ID               string    `gorm:"primaryKey;type:uuid" json:"id"`
	FromAssetID      string    `gorm:"type:uuid;not null;uniqueIndex:idx_asset_relation_identity,priority:1;index" json:"from_asset_id"`
	RelationType     string    `gorm:"type:varchar(64);not null;uniqueIndex:idx_asset_relation_identity,priority:2;index" json:"relation_type"`
	ToAssetID        string    `gorm:"type:uuid;not null;uniqueIndex:idx_asset_relation_identity,priority:3;index" json:"to_asset_id"`
	LastTaskID       string    `gorm:"type:uuid;index" json:"last_task_id,omitempty"`
	ObservationCount int64     `gorm:"not null;default:0" json:"observation_count"`
	FirstSeenAt      time.Time `gorm:"not null" json:"first_seen_at"`
	LastSeenAt       time.Time `gorm:"not null;index" json:"last_seen_at"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func (r *CanonicalAssetRelation) BeforeCreate(tx *gorm.DB) error {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	return nil
}

func (CanonicalAssetRelation) TableName() string { return "asset_relations" }

// AssetRelationObservation preserves the task evidence behind a relation.
type AssetRelationObservation struct {
	ID         string    `gorm:"primaryKey;type:uuid" json:"id"`
	RelationID string    `gorm:"type:uuid;not null;uniqueIndex:idx_relation_observation_source,priority:1;index" json:"relation_id"`
	TaskID     string    `gorm:"type:uuid;not null;uniqueIndex:idx_relation_observation_source,priority:2;index" json:"task_id"`
	SourceType string    `gorm:"type:varchar(64);not null;uniqueIndex:idx_relation_observation_source,priority:3" json:"source_type"`
	SourceRef  string    `gorm:"type:varchar(128);not null;uniqueIndex:idx_relation_observation_source,priority:4" json:"source_ref"`
	ObservedAt time.Time `gorm:"not null;index" json:"observed_at"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (o *AssetRelationObservation) BeforeCreate(tx *gorm.DB) error {
	if o.ID == "" {
		o.ID = uuid.NewString()
	}
	return nil
}

func (AssetRelationObservation) TableName() string { return "asset_relation_observations" }

// AssetVulnerabilityLink records why a vulnerability contributes to an asset's risk.
type AssetVulnerabilityLink struct {
	ID              string    `gorm:"primaryKey;type:uuid" json:"id"`
	AssetID         string    `gorm:"type:uuid;not null;uniqueIndex:idx_asset_vulnerability_link,priority:1;index" json:"asset_id"`
	VulnerabilityID string    `gorm:"type:uuid;not null;uniqueIndex:idx_asset_vulnerability_link,priority:2;index" json:"vulnerability_id"`
	TaskID          string    `gorm:"type:uuid;not null;index" json:"task_id"`
	MatchType       string    `gorm:"type:varchar(64);not null" json:"match_type"`
	Severity        string    `gorm:"type:varchar(32);not null;index" json:"severity"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func (l *AssetVulnerabilityLink) BeforeCreate(tx *gorm.DB) error {
	if l.ID == "" {
		l.ID = uuid.NewString()
	}
	return nil
}

func (AssetVulnerabilityLink) TableName() string { return "asset_vulnerability_links" }

// AssetChange is a deterministic timeline event rebuilt from primary observations.
type AssetChange struct {
	ID                    string    `gorm:"primaryKey;type:uuid" json:"id"`
	AssetID               string    `gorm:"type:uuid;not null;uniqueIndex:idx_asset_change_observation,priority:1;index" json:"asset_id"`
	CurrentObservationID  string    `gorm:"type:uuid;not null;uniqueIndex:idx_asset_change_observation,priority:2;index" json:"current_observation_id"`
	PreviousObservationID *string   `gorm:"type:uuid;index" json:"previous_observation_id,omitempty"`
	TaskID                string    `gorm:"type:uuid;not null;index" json:"task_id"`
	OriginType            string    `gorm:"type:varchar(32);not null;default:'task';index" json:"origin_type"`
	EventType             string    `gorm:"type:varchar(32);not null;index" json:"event_type"`
	ChangedFields         []string  `gorm:"type:jsonb;serializer:json" json:"changed_fields"`
	BeforeData            string    `gorm:"type:jsonb;not null;default:'{}'" json:"before_data"`
	AfterData             string    `gorm:"type:jsonb;not null;default:'{}'" json:"after_data"`
	ObservedAt            time.Time `gorm:"not null;index" json:"observed_at"`
	CreatedAt             time.Time `json:"created_at"`
}

func (c *AssetChange) BeforeCreate(tx *gorm.DB) error {
	if c.ID == "" {
		c.ID = uuid.NewString()
	}
	if c.OriginType == "" {
		c.OriginType = "task"
	}
	return nil
}

func (AssetChange) TableName() string { return "asset_changes" }
