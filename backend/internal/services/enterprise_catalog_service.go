package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type enterpriseDomainObservation struct {
	EnterpriseAssetID string `json:"enterprise_asset_id"`
	QueryID           string `json:"query_id"`
	Provider          string `json:"provider"`
	Kind              string `json:"enterprise_kind"`
	Domain            string `json:"domain"`
	CompanyName       string `json:"company_name,omitempty"`
	Name              string `json:"name,omitempty"`
	License           string `json:"license,omitempty"`
	RawData           any    `json:"raw_data,omitempty"`
}

type EnterpriseCatalogSyncResult struct {
	RequestedCount      int      `json:"requested_count"`
	SyncedCount         int      `json:"synced_count"`
	CreatedGroupMembers int      `json:"created_group_members"`
	CanonicalAssetIDs   []string `json:"canonical_asset_ids"`
	SkippedAssetIDs     []string `json:"skipped_asset_ids,omitempty"`
	GroupID             string   `json:"group_id,omitempty"`
	GroupName           string   `json:"group_name,omitempty"`
}

type enterpriseSyncInputError struct{ message string }

func (e enterpriseSyncInputError) Error() string { return e.message }

func enterpriseSyncInputErrorf(format string, values ...any) error {
	return enterpriseSyncInputError{message: fmt.Sprintf(format, values...)}
}

func IsEnterpriseSyncInputError(err error) bool {
	var inputError enterpriseSyncInputError
	return errors.As(err, &inputError)
}

func (s *EnterpriseService) SyncAssets(assetIDs []string, groupID, newGroupName string) (*EnterpriseCatalogSyncResult, error) {
	requested, err := normalizeEnterpriseAssetIDs(assetIDs)
	if err != nil {
		return nil, err
	}
	groupID = strings.TrimSpace(groupID)
	newGroupName = strings.TrimSpace(newGroupName)
	if groupID != "" && newGroupName != "" {
		return nil, enterpriseSyncInputErrorf("group_id and new_group_name are mutually exclusive")
	}
	if len([]rune(newGroupName)) > 255 {
		return nil, enterpriseSyncInputErrorf("new group name is too long")
	}
	if database.DB == nil || s.assetCatalog == nil {
		return nil, errors.New("asset catalog is unavailable")
	}

	tx := database.DB.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer tx.Rollback()
	if err := tx.Exec("SELECT pg_advisory_xact_lock(hashtext(?))", "enterprise-catalog-sync").Error; err != nil {
		return nil, err
	}
	group, err := resolveEnterpriseSyncGroup(tx, groupID, newGroupName)
	if err != nil {
		return nil, err
	}

	var records []models.EnterpriseAsset
	if err := tx.Where("id IN ?", requested).Find(&records).Error; err != nil {
		return nil, err
	}
	byID := make(map[string]models.EnterpriseAsset, len(records))
	for _, record := range records {
		byID[record.ID] = record
	}
	result := &EnterpriseCatalogSyncResult{RequestedCount: len(requested), CanonicalAssetIDs: []string{}, SkippedAssetIDs: []string{}}
	if group != nil {
		result.GroupID, result.GroupName = group.ID, group.Name
	}
	canonicalIDs := make(map[string]bool)
	queryIDs := make(map[string]bool)
	for _, requestedID := range requested {
		record, exists := byID[requestedID]
		domain := ""
		if exists {
			domain = normalizeEnterpriseDomain(record.Domain)
		}
		if !exists || domain == "" {
			result.SkippedAssetIDs = append(result.SkippedAssetIDs, requestedID)
			continue
		}
		observedAt := record.CreatedAt
		if observedAt.IsZero() {
			observedAt = time.Now()
		}
		var raw any
		if json.Unmarshal([]byte(record.RawData), &raw) != nil {
			raw = record.RawData
		}
		observation := enterpriseDomainObservation{
			EnterpriseAssetID: record.ID, QueryID: record.QueryID, Provider: record.Provider, Kind: record.Kind,
			Domain: domain, CompanyName: record.CompanyName, Name: record.Name, License: record.License, RawData: raw,
		}
		entity, err := s.assetCatalog.observeAssetWithOrigin(tx, "domain", canonicalDomain(domain), domain, record.QueryID, "enterprise_query", "enterprise_domain", record.ID, observation, observedAt)
		if err != nil {
			return nil, fmt.Errorf("sync enterprise asset %s: %w", record.ID, err)
		}
		if entity == nil {
			result.SkippedAssetIDs = append(result.SkippedAssetIDs, requestedID)
			continue
		}
		result.SyncedCount++
		queryIDs[record.QueryID] = true
		if !canonicalIDs[entity.ID] {
			canonicalIDs[entity.ID] = true
			result.CanonicalAssetIDs = append(result.CanonicalAssetIDs, entity.ID)
		}
		if group != nil {
			item := models.AssetGroupItem{GroupID: group.ID, AssetType: "canonical", AssetID: entity.ID}
			created := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&item)
			if created.Error != nil {
				return nil, created.Error
			}
			result.CreatedGroupMembers += int(created.RowsAffected)
		}
	}
	if result.SyncedCount == 0 {
		return nil, enterpriseSyncInputErrorf("selected assets do not contain synchronizable domains")
	}
	if err := s.assetCatalog.rebuildAssetChanges(tx, result.CanonicalAssetIDs); err != nil {
		return nil, err
	}
	for queryID := range queryIDs {
		var count int64
		if err := tx.Model(&models.AssetObservation{}).Where("task_id = ? AND origin_type = ?", queryID, "enterprise_query").Distinct("asset_id").Count(&count).Error; err != nil {
			return nil, err
		}
		if err := tx.Model(&models.EnterpriseQuery{}).Where("id = ?", queryID).Update("synced_count", count).Error; err != nil {
			return nil, err
		}
	}
	if err := tx.Commit().Error; err != nil {
		return nil, err
	}
	return result, nil
}

func normalizeEnterpriseAssetIDs(assetIDs []string) ([]string, error) {
	if len(assetIDs) == 0 {
		return nil, enterpriseSyncInputErrorf("select at least one enterprise asset")
	}
	if len(assetIDs) > 2000 {
		return nil, enterpriseSyncInputErrorf("at most 2000 assets can be synchronized at once")
	}
	seen := make(map[string]bool, len(assetIDs))
	result := make([]string, 0, len(assetIDs))
	for _, id := range assetIDs {
		id = strings.TrimSpace(id)
		if _, err := uuid.Parse(id); err != nil {
			return nil, enterpriseSyncInputErrorf("invalid enterprise asset ID: %s", id)
		}
		if !seen[id] {
			seen[id] = true
			result = append(result, id)
		}
	}
	return result, nil
}

func resolveEnterpriseSyncGroup(tx *gorm.DB, groupID, newGroupName string) (*models.AssetGroup, error) {
	if groupID != "" {
		var group models.AssetGroup
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&group, "id = ?", groupID).Error; err != nil {
			return nil, enterpriseSyncInputErrorf("asset group not found")
		}
		return &group, nil
	}
	if newGroupName == "" {
		return nil, nil
	}
	var group models.AssetGroup
	result := tx.Where("name = ?", newGroupName).Limit(1).Find(&group)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 1 {
		return &group, nil
	}
	group = models.AssetGroup{Name: newGroupName, Description: "由企业资产发现同步创建"}
	if err := tx.Create(&group).Error; err != nil {
		return nil, err
	}
	return &group, nil
}
