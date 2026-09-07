package services

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/reconmaster/backend/internal/models"
	"gorm.io/gorm"
)

func canonicalObservationState(kind, sourceType string, value any) any {
	if sourceType == "enterprise_domain" {
		if item, ok := value.(enterpriseDomainObservation); ok {
			return map[string]any{
				"domain": item.Domain, "company_name": item.CompanyName, "name": item.Name,
				"license": item.License, "provider": item.Provider, "enterprise_kind": item.Kind,
			}
		}
	}
	if kind != sourceType {
		return value
	}
	switch kind {
	case "domain":
		if item, ok := value.(models.Domain); ok {
			return map[string]any{
				"domain": canonicalDomain(item.Domain), "ip_address": canonicalIP(item.IPAddress), "cdn": item.CDN,
				"takeover_vulnerable": item.TakeoverVulnerable, "takeover_service": strings.TrimSpace(item.TakeoverService),
				"takeover_cname": canonicalDomain(item.TakeoverCNAME), "takeover_severity": strings.ToLower(strings.TrimSpace(item.TakeoverSeverity)),
			}
		}
	case "ip":
		if item, ok := value.(models.IP); ok {
			return map[string]any{
				"ip_address": canonicalIP(item.IPAddress), "domain": canonicalDomain(item.Domain), "os": strings.TrimSpace(item.OS),
				"cdn": item.CDN, "location": strings.TrimSpace(item.Location),
			}
		}
	case "port":
		if item, ok := value.(models.Port); ok {
			protocol := strings.ToLower(strings.TrimSpace(item.Protocol))
			if protocol == "" {
				protocol = "tcp"
			}
			return map[string]any{
				"endpoint": net.JoinHostPort(canonicalIP(item.IPAddress), strconv.Itoa(item.Port)), "protocol": protocol,
				"service": strings.TrimSpace(item.Service), "version": strings.TrimSpace(item.Version),
				"banner_sha256": contentSHA256(item.Banner), "ssl_cert_sha256": contentSHA256(item.SSLCert),
			}
		}
	case "site":
		if item, ok := value.(models.Site); ok {
			fingerprints := append([]string{}, item.Fingerprints...)
			if fingerprint := strings.TrimSpace(item.Fingerprint); fingerprint != "" {
				fingerprints = append(fingerprints, fingerprint)
			}
			fingerprints = normalizedStrings(fingerprints)
			return map[string]any{
				"url": canonicalSite(item.URL), "title": strings.TrimSpace(item.Title), "status_code": item.StatusCode,
				"ip": canonicalIP(item.IP), "content_type": strings.ToLower(strings.TrimSpace(item.ContentType)),
				"server": strings.TrimSpace(item.Server), "fingerprints": fingerprints, "has_screenshot": strings.TrimSpace(item.Screenshot) != "",
			}
		}
	}
	return value
}

func contentSHA256(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func normalizedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func (s *AssetCatalogService) rebuildTaskAssetChanges(db *gorm.DB, taskID string) error {
	assetIDs, err := observedAssetIDsForTask(db, taskID)
	if err != nil {
		return err
	}
	return s.rebuildAssetChanges(db, assetIDs)
}

func observedAssetIDsForTask(db *gorm.DB, taskID string) ([]string, error) {
	var assetIDs []string
	err := db.Model(&models.AssetObservation{}).Where("task_id = ?", taskID).Distinct().Pluck("asset_id", &assetIDs).Error
	return assetIDs, err
}

func (s *AssetCatalogService) rebuildAssetChanges(db *gorm.DB, assetIDs []string) error {
	assetIDs = normalizedStrings(assetIDs)
	for _, assetID := range assetIDs {
		if err := db.Exec("SELECT pg_advisory_xact_lock(hashtext(?))", "asset-change:"+assetID).Error; err != nil {
			return err
		}
		var existingChanges []models.AssetChange
		if err := db.Where("asset_id = ?", assetID).Find(&existingChanges).Error; err != nil {
			return err
		}
		existingByObservation := make(map[string]models.AssetChange, len(existingChanges))
		for _, change := range existingChanges {
			existingByObservation[change.CurrentObservationID] = change
		}
		if err := db.Where("asset_id = ?", assetID).Delete(&models.AssetChange{}).Error; err != nil {
			return err
		}
		var asset models.AssetEntity
		result := db.Limit(1).Find(&asset, "id = ?", assetID)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			continue
		}
		var observations []models.AssetObservation
		if err := db.Where("asset_id = ? AND source_type = ? AND state_hash <> ''", assetID, asset.Kind).
			Order("observed_at ASC, id ASC").Find(&observations).Error; err != nil {
			return err
		}
		if len(observations) == 0 {
			if err := db.Where("asset_id = ? AND source_type = ? AND state_hash <> ''", assetID, "enterprise_domain").
				Order("observed_at ASC, id ASC").Find(&observations).Error; err != nil {
				return err
			}
		}
		if len(observations) == 0 {
			var fallback models.AssetObservation
			fallbackResult := db.Where("asset_id = ? AND state_hash <> ''", assetID).Order("observed_at ASC, id ASC").Limit(1).Find(&fallback)
			if fallbackResult.Error != nil {
				return fallbackResult.Error
			}
			if fallbackResult.RowsAffected == 1 {
				observations = append(observations, fallback)
			}
		}
		var previous *models.AssetObservation
		var modifiedCount int64
		for index := range observations {
			current := &observations[index]
			existing := existingByObservation[current.ID]
			if previous == nil {
				if err := db.Create(&models.AssetChange{
					ID:      existing.ID,
					AssetID: assetID, CurrentObservationID: current.ID, TaskID: current.TaskID, OriginType: current.OriginType, EventType: "discovered",
					ChangedFields: []string{}, BeforeData: "{}", AfterData: current.StateData, ObservedAt: current.ObservedAt,
					CreatedAt: existing.CreatedAt,
				}).Error; err != nil {
					return err
				}
				previous = current
				continue
			}
			if current.StateHash != previous.StateHash {
				previousObservationID := previous.ID
				if err := db.Create(&models.AssetChange{
					ID:      existing.ID,
					AssetID: assetID, CurrentObservationID: current.ID, PreviousObservationID: &previousObservationID,
					TaskID: current.TaskID, OriginType: current.OriginType, EventType: "modified", ChangedFields: changedStateFields(previous.StateData, current.StateData),
					BeforeData: previous.StateData, AfterData: current.StateData, ObservedAt: current.ObservedAt,
					CreatedAt: existing.CreatedAt,
				}).Error; err != nil {
					return err
				}
				modifiedCount++
			}
			previous = current
		}
		if err := db.Model(&models.AssetEntity{}).Where("id = ?", assetID).Update("change_count", modifiedCount).Error; err != nil {
			return err
		}
	}
	return nil
}

func changedStateFields(beforeData, afterData string) []string {
	var before, after map[string]any
	if json.Unmarshal([]byte(beforeData), &before) != nil || json.Unmarshal([]byte(afterData), &after) != nil {
		return []string{"state"}
	}
	keys := make(map[string]struct{}, len(before)+len(after))
	for key := range before {
		keys[key] = struct{}{}
	}
	for key := range after {
		keys[key] = struct{}{}
	}
	changed := make([]string, 0, len(keys))
	for key := range keys {
		if !reflect.DeepEqual(before[key], after[key]) {
			changed = append(changed, key)
		}
	}
	sort.Strings(changed)
	return changed
}
