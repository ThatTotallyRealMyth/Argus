package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type AssetCatalogService struct{}

func NewAssetCatalogService() *AssetCatalogService { return &AssetCatalogService{} }

func canonicalDomain(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func canonicalIP(value string) string {
	parsed := net.ParseIP(strings.TrimSpace(value))
	if parsed == nil {
		return ""
	}
	return parsed.String()
}

func canonicalSite(value string) string {
	raw := strings.TrimSpace(value)
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return strings.ToLower(raw)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if port != "" && !((parsed.Scheme == "http" && port == "80") || (parsed.Scheme == "https" && port == "443")) {
		host = net.JoinHostPort(host, port)
	}
	parsed.Host = host
	parsed.Fragment = ""
	if parsed.Path == "/" {
		parsed.Path = ""
	}
	return parsed.String()
}

func observationTime(createdAt, updatedAt time.Time) time.Time {
	if !updatedAt.IsZero() {
		return updatedAt
	}
	if !createdAt.IsZero() {
		return createdAt
	}
	return time.Now()
}

func marshalObservation(kind, sourceType string, value any) (string, string, string, string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", "", "", "", err
	}
	payloadSum := sha256.Sum256(payload)
	state, err := json.Marshal(canonicalObservationState(kind, sourceType, value))
	if err != nil {
		return "", "", "", "", err
	}
	stateSum := sha256.Sum256(state)
	return string(payload), hex.EncodeToString(payloadSum[:]), string(state), hex.EncodeToString(stateSum[:]), nil
}

func (s *AssetCatalogService) observeAsset(db *gorm.DB, kind, key, display, taskID, sourceType, sourceRef string, value any, observedAt time.Time) (*models.AssetEntity, error) {
	return s.observeAssetWithOrigin(db, kind, key, display, taskID, "task", sourceType, sourceRef, value, observedAt)
}

func (s *AssetCatalogService) observeAssetWithOrigin(db *gorm.DB, kind, key, display, originID, originType, sourceType, sourceRef string, value any, observedAt time.Time) (*models.AssetEntity, error) {
	if key == "" || originID == "" || sourceRef == "" {
		return nil, nil
	}
	if originType == "" {
		originType = "task"
	}
	payload, payloadHash, stateData, stateHash, err := marshalObservation(kind, sourceType, value)
	if err != nil {
		return nil, err
	}
	entity := models.AssetEntity{
		ScopeID:        models.DefaultAssetScope,
		Kind:           kind,
		CanonicalKey:   key,
		DisplayValue:   strings.TrimSpace(display),
		Status:         "active",
		LastTaskID:     originID,
		LastOriginType: originType,
		CurrentData:    payload,
		FirstSeenAt:    observedAt,
		LastSeenAt:     observedAt,
	}
	updates := clause.Assignments(map[string]any{
		"display_value":    gorm.Expr("CASE WHEN EXCLUDED.last_seen_at >= asset_entities.last_seen_at THEN EXCLUDED.display_value ELSE asset_entities.display_value END"),
		"current_data":     gorm.Expr("CASE WHEN EXCLUDED.last_seen_at >= asset_entities.last_seen_at THEN EXCLUDED.current_data ELSE asset_entities.current_data END"),
		"last_task_id":     gorm.Expr("CASE WHEN EXCLUDED.last_seen_at >= asset_entities.last_seen_at THEN EXCLUDED.last_task_id ELSE asset_entities.last_task_id END"),
		"last_origin_type": gorm.Expr("CASE WHEN EXCLUDED.last_seen_at >= asset_entities.last_seen_at THEN EXCLUDED.last_origin_type ELSE asset_entities.last_origin_type END"),
		"first_seen_at":    gorm.Expr("LEAST(asset_entities.first_seen_at, EXCLUDED.first_seen_at)"),
		"last_seen_at":     gorm.Expr("GREATEST(asset_entities.last_seen_at, EXCLUDED.last_seen_at)"),
		"status":           "active",
		"updated_at":       time.Now(),
	})
	if err := db.Clauses(
		clause.OnConflict{
			Columns:   []clause.Column{{Name: "scope_id"}, {Name: "kind"}, {Name: "canonical_key"}},
			DoUpdates: updates,
		},
		clause.Returning{Columns: []clause.Column{{Name: "id"}}},
	).Create(&entity).Error; err != nil {
		return nil, err
	}

	observation := models.AssetObservation{
		AssetID:     entity.ID,
		TaskID:      originID,
		OriginType:  originType,
		SourceType:  sourceType,
		SourceRef:   sourceRef,
		Payload:     payload,
		PayloadHash: payloadHash,
		StateData:   stateData,
		StateHash:   stateHash,
		ObservedAt:  observedAt,
	}
	if err := db.Clauses(
		clause.OnConflict{
			Columns:   []clause.Column{{Name: "asset_id"}, {Name: "task_id"}, {Name: "source_type"}, {Name: "source_ref"}},
			DoUpdates: clause.AssignmentColumns([]string{"origin_type", "payload", "payload_hash", "state_data", "state_hash", "observed_at", "updated_at"}),
		},
		clause.Returning{Columns: []clause.Column{{Name: "id"}}},
	).Create(&observation).Error; err != nil {
		return nil, err
	}
	var observationCount int64
	if err := db.Model(&models.AssetObservation{}).Where("asset_id = ?", entity.ID).Count(&observationCount).Error; err != nil {
		return nil, err
	}
	if err := db.Model(&models.AssetEntity{}).Where("id = ?", entity.ID).Update("observation_count", observationCount).Error; err != nil {
		return nil, err
	}
	entity.ObservationCount = observationCount
	return &entity, nil
}

func (s *AssetCatalogService) relate(db *gorm.DB, from *models.AssetEntity, relationType string, to *models.AssetEntity, taskID, sourceType, sourceRef string, observedAt time.Time) error {
	if from == nil || to == nil || from.ID == to.ID {
		return nil
	}
	relation := models.CanonicalAssetRelation{
		FromAssetID:  from.ID,
		RelationType: relationType,
		ToAssetID:    to.ID,
		LastTaskID:   taskID,
		FirstSeenAt:  observedAt,
		LastSeenAt:   observedAt,
	}
	if err := db.Clauses(
		clause.OnConflict{
			Columns: []clause.Column{{Name: "from_asset_id"}, {Name: "relation_type"}, {Name: "to_asset_id"}},
			DoUpdates: clause.Assignments(map[string]any{
				"last_task_id":  gorm.Expr("CASE WHEN EXCLUDED.last_seen_at >= asset_relations.last_seen_at THEN EXCLUDED.last_task_id ELSE asset_relations.last_task_id END"),
				"first_seen_at": gorm.Expr("LEAST(asset_relations.first_seen_at, EXCLUDED.first_seen_at)"),
				"last_seen_at":  gorm.Expr("GREATEST(asset_relations.last_seen_at, EXCLUDED.last_seen_at)"),
				"updated_at":    time.Now(),
			}),
		},
		clause.Returning{Columns: []clause.Column{{Name: "id"}}},
	).Create(&relation).Error; err != nil {
		return err
	}
	source := models.AssetRelationObservation{
		RelationID: relation.ID, TaskID: taskID, SourceType: sourceType, SourceRef: sourceRef, ObservedAt: observedAt,
	}
	if err := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "relation_id"}, {Name: "task_id"}, {Name: "source_type"}, {Name: "source_ref"}},
		DoUpdates: clause.AssignmentColumns([]string{"observed_at", "updated_at"}),
	}).Create(&source).Error; err != nil {
		return err
	}
	var observationCount int64
	if err := db.Model(&models.AssetRelationObservation{}).Where("relation_id = ?", relation.ID).Count(&observationCount).Error; err != nil {
		return err
	}
	return db.Model(&models.CanonicalAssetRelation{}).Where("id = ?", relation.ID).Update("observation_count", observationCount).Error
}

func (s *AssetCatalogService) SyncTask(taskID string) error {
	if database.DB == nil {
		return fmt.Errorf("asset catalog database is not initialized")
	}
	tx := database.DB.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer tx.Rollback()
	if err := lockAssetCatalogTask(tx, taskID); err != nil {
		return err
	}
	if err := s.syncTask(tx, taskID); err != nil {
		return err
	}
	return tx.Commit().Error
}

func lockAssetCatalogTask(db *gorm.DB, taskID string) error {
	return db.Exec("SELECT pg_advisory_xact_lock(hashtext(?))", "asset-catalog:"+taskID).Error
}

func (s *AssetCatalogService) syncTask(db *gorm.DB, taskID string) error {

	var domains []models.Domain
	if err := db.Where("task_id = ?", taskID).Find(&domains).Error; err != nil {
		return err
	}
	for _, domain := range domains {
		observedAt := observationTime(domain.CreatedAt, domain.UpdatedAt)
		domainEntity, err := s.observeAsset(db, "domain", canonicalDomain(domain.Domain), domain.Domain, taskID, "domain", domain.ID, domain, observedAt)
		if err != nil {
			return err
		}
		if ipKey := canonicalIP(domain.IPAddress); ipKey != "" {
			ipEntity, err := s.observeAsset(db, "ip", ipKey, ipKey, taskID, "domain_ip", domain.ID, map[string]any{"ip_address": ipKey, "domain": domain.Domain, "source": domain.Source}, observedAt)
			if err != nil {
				return err
			}
			if err := s.relate(db, domainEntity, "resolves_to", ipEntity, taskID, "domain", domain.ID, observedAt); err != nil {
				return err
			}
		}
	}

	var ips []models.IP
	if err := db.Where("task_id = ?", taskID).Find(&ips).Error; err != nil {
		return err
	}
	for _, ip := range ips {
		observedAt := observationTime(ip.CreatedAt, ip.UpdatedAt)
		ipEntity, err := s.observeAsset(db, "ip", canonicalIP(ip.IPAddress), ip.IPAddress, taskID, "ip", ip.ID, ip, observedAt)
		if err != nil {
			return err
		}
		if domainKey := canonicalDomain(ip.Domain); domainKey != "" {
			domainEntity, err := s.observeAsset(db, "domain", domainKey, ip.Domain, taskID, "ip_domain", ip.ID, map[string]any{"domain": ip.Domain, "ip_address": ip.IPAddress, "source": ip.Source}, observedAt)
			if err != nil {
				return err
			}
			if err := s.relate(db, domainEntity, "resolves_to", ipEntity, taskID, "ip", ip.ID, observedAt); err != nil {
				return err
			}
		}
	}

	var ports []models.Port
	if err := db.Where("task_id = ?", taskID).Find(&ports).Error; err != nil {
		return err
	}
	for _, port := range ports {
		observedAt := observationTime(port.CreatedAt, port.UpdatedAt)
		ipKey := canonicalIP(port.IPAddress)
		if ipKey == "" || port.Port < 1 || port.Port > 65535 {
			continue
		}
		protocol := strings.ToLower(strings.TrimSpace(port.Protocol))
		if protocol == "" {
			protocol = "tcp"
		}
		ipEntity, err := s.observeAsset(db, "ip", ipKey, ipKey, taskID, "port_ip", port.ID, map[string]any{"ip_address": ipKey, "source": "port_scan"}, observedAt)
		if err != nil {
			return err
		}
		portKey := net.JoinHostPort(ipKey, strconv.Itoa(port.Port)) + "/" + protocol
		portEntity, err := s.observeAsset(db, "port", portKey, net.JoinHostPort(ipKey, strconv.Itoa(port.Port))+"/"+protocol, taskID, "port", port.ID, port, observedAt)
		if err != nil {
			return err
		}
		if err := s.relate(db, ipEntity, "exposes", portEntity, taskID, "port", port.ID, observedAt); err != nil {
			return err
		}
	}

	var sites []models.Site
	if err := db.Where("task_id = ?", taskID).Find(&sites).Error; err != nil {
		return err
	}
	sitesByOrigin := make(map[string]*models.AssetEntity)
	for _, site := range sites {
		observedAt := observationTime(site.CreatedAt, site.UpdatedAt)
		siteEntity, err := s.observeAsset(db, "site", canonicalSite(site.URL), site.URL, taskID, "site", site.ID, site, observedAt)
		if err != nil {
			return err
		}
		if ipKey := canonicalIP(site.IP); ipKey != "" {
			ipEntity, err := s.observeAsset(db, "ip", ipKey, ipKey, taskID, "site_ip", site.ID, map[string]any{"ip_address": ipKey, "site": site.URL, "source": "site_detect"}, observedAt)
			if err != nil {
				return err
			}
			if err := s.relate(db, siteEntity, "hosted_on", ipEntity, taskID, "site", site.ID, observedAt); err != nil {
				return err
			}
		}
		if origin := canonicalSiteOrigin(site.URL); origin != "" {
			sitesByOrigin[origin] = siteEntity
		}
	}

	// Crawler paths and API endpoints are first-class assets. This preserves
	// path-level attack surface instead of collapsing everything into a site.
	var crawlerResults []models.CrawlerResult
	if err := db.Where("task_id = ?", taskID).Find(&crawlerResults).Error; err != nil {
		return err
	}
	var transactions []models.HTTPTransaction
	if err := db.Where("task_id = ?", taskID).Order("created_at DESC").Find(&transactions).Error; err != nil {
		return err
	}
	transactionByCrawler := make(map[string]models.HTTPTransaction)
	for _, transaction := range transactions {
		if transaction.CrawlerResultID == "" {
			continue
		}
		if _, exists := transactionByCrawler[transaction.CrawlerResultID]; !exists {
			transactionByCrawler[transaction.CrawlerResultID] = transaction
		}
	}
	for _, result := range crawlerResults {
		urlKey := canonicalSite(result.URL)
		if urlKey == "" || result.ID == "" {
			continue
		}
		observedAt := observationTime(result.CreatedAt, time.Time{})
		value := map[string]any{
			"url": result.URL, "method": result.Method, "status_code": result.StatusCode,
			"content_type": result.ContentType, "content_length": result.ContentLength,
			"response_time_ms": result.ResponseTimeMs, "source": result.Source,
			"has_params": result.HasParams, "has_form": result.HasForm,
		}
		if transaction, ok := transactionByCrawler[result.ID]; ok {
			value["http_evidence"] = map[string]any{
				"status_code": transaction.ResponseStatusCode, "content_type": transaction.ResponseContentType,
				"content_length": transaction.ResponseContentLength, "response_time_ms": transaction.ResponseTimeMs,
				"body_sha256": transaction.ResponseBodySHA256, "body_stored": transaction.ResponseBodyStored,
				"body_truncated": transaction.ResponseBodyTruncated,
			}
		}
		urlEntity, err := s.observeAsset(db, "url", urlKey, result.URL, taskID, "crawler_url", result.ID, value, observedAt)
		if err != nil {
			return err
		}
		if siteEntity := sitesByOrigin[canonicalSiteOrigin(result.URL)]; siteEntity != nil {
			if err := s.relate(db, urlEntity, "located_on", siteEntity, taskID, "crawler_url", result.ID, observedAt); err != nil {
				return err
			}
		}
	}
	if err := s.syncTaskVulnerabilities(db, taskID); err != nil {
		return err
	}
	return s.rebuildTaskAssetChanges(db, taskID)
}

func (s *AssetCatalogService) RemoveTask(db *gorm.DB, taskID string) error {
	if db == nil {
		return fmt.Errorf("asset catalog database is not initialized")
	}
	if err := lockAssetCatalogTask(db, taskID); err != nil {
		return err
	}
	var assetRows []struct{ AssetID string }
	if err := db.Model(&models.AssetObservation{}).Distinct("asset_id").Where("task_id = ?", taskID).Scan(&assetRows).Error; err != nil {
		return err
	}
	var relationRows []struct{ RelationID string }
	if err := db.Model(&models.AssetRelationObservation{}).Distinct("relation_id").Where("task_id = ?", taskID).Scan(&relationRows).Error; err != nil {
		return err
	}
	var findingAssetIDs []string
	if err := db.Model(&models.AssetVulnerabilityLink{}).Where("task_id = ?", taskID).Distinct().Pluck("asset_id", &findingAssetIDs).Error; err != nil {
		return err
	}
	if err := db.Where("task_id = ?", taskID).Delete(&models.AssetVulnerabilityLink{}).Error; err != nil {
		return err
	}
	if err := db.Where("task_id = ?", taskID).Delete(&models.AssetRelationObservation{}).Error; err != nil {
		return err
	}
	if err := db.Where("task_id = ?", taskID).Delete(&models.AssetObservation{}).Error; err != nil {
		return err
	}

	for _, row := range relationRows {
		var count int64
		if err := db.Model(&models.AssetRelationObservation{}).Where("relation_id = ?", row.RelationID).Count(&count).Error; err != nil {
			return err
		}
		if count == 0 {
			if err := db.Delete(&models.CanonicalAssetRelation{}, "id = ?", row.RelationID).Error; err != nil {
				return err
			}
			continue
		}
		var latest models.AssetRelationObservation
		if err := db.Where("relation_id = ?", row.RelationID).Order("observed_at DESC").First(&latest).Error; err != nil {
			return err
		}
		var bounds struct{ FirstSeenAt, LastSeenAt time.Time }
		if err := db.Model(&models.AssetRelationObservation{}).
			Select("MIN(observed_at) AS first_seen_at, MAX(observed_at) AS last_seen_at").
			Where("relation_id = ?", row.RelationID).Scan(&bounds).Error; err != nil {
			return err
		}
		if err := db.Model(&models.CanonicalAssetRelation{}).Where("id = ?", row.RelationID).Updates(map[string]any{
			"observation_count": count, "last_task_id": latest.TaskID, "first_seen_at": bounds.FirstSeenAt, "last_seen_at": bounds.LastSeenAt,
		}).Error; err != nil {
			return err
		}
	}

	for _, row := range assetRows {
		var count int64
		if err := db.Model(&models.AssetObservation{}).Where("asset_id = ?", row.AssetID).Count(&count).Error; err != nil {
			return err
		}
		if count == 0 {
			if err := db.Where("asset_id = ?", row.AssetID).Delete(&models.AssetLeadTriage{}).Error; err != nil {
				return err
			}
			if err := db.Where("asset_type = ? AND asset_id = ?", "canonical", row.AssetID).Delete(&models.AssetGroupItem{}).Error; err != nil {
				return err
			}
			relationQuery := db.Model(&models.CanonicalAssetRelation{}).Select("id").Where("from_asset_id = ? OR to_asset_id = ?", row.AssetID, row.AssetID)
			if err := db.Where("relation_id IN (?)", relationQuery).Delete(&models.AssetRelationObservation{}).Error; err != nil {
				return err
			}
			if err := db.Where("from_asset_id = ? OR to_asset_id = ?", row.AssetID, row.AssetID).Delete(&models.CanonicalAssetRelation{}).Error; err != nil {
				return err
			}
			if err := db.Delete(&models.AssetEntity{}, "id = ?", row.AssetID).Error; err != nil {
				return err
			}
			continue
		}
		var latest models.AssetObservation
		if err := db.Where("asset_id = ?", row.AssetID).Order("observed_at DESC").First(&latest).Error; err != nil {
			return err
		}
		var bounds struct{ FirstSeenAt, LastSeenAt time.Time }
		if err := db.Model(&models.AssetObservation{}).
			Select("MIN(observed_at) AS first_seen_at, MAX(observed_at) AS last_seen_at").
			Where("asset_id = ?", row.AssetID).Scan(&bounds).Error; err != nil {
			return err
		}
		if err := db.Model(&models.AssetEntity{}).Where("id = ?", row.AssetID).Updates(map[string]any{
			"observation_count": count, "last_task_id": latest.TaskID, "current_data": latest.Payload,
			"last_origin_type": latest.OriginType,
			"first_seen_at":    bounds.FirstSeenAt, "last_seen_at": bounds.LastSeenAt,
		}).Error; err != nil {
			return err
		}
	}
	for _, row := range assetRows {
		findingAssetIDs = append(findingAssetIDs, row.AssetID)
	}
	if err := s.recomputeAssetRisk(db, findingAssetIDs); err != nil {
		return err
	}
	return s.rebuildAssetChanges(db, findingAssetIDs)
}

func (s *AssetCatalogService) BackfillLegacyAssets(ctx context.Context) error {
	if database.DB == nil {
		return fmt.Errorf("asset catalog database is not initialized")
	}
	var rows []struct{ TaskID string }
	err := database.DB.Raw(`
		SELECT DISTINCT task_id FROM (
			SELECT task_id FROM domains
			UNION ALL SELECT task_id FROM ips
			UNION ALL SELECT task_id FROM ports
			UNION ALL SELECT task_id FROM sites
		) legacy_assets WHERE task_id IS NOT NULL AND task_id::text <> ''`).Scan(&rows).Error
	if err != nil {
		return err
	}
	for index, row := range rows {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := s.SyncTask(row.TaskID); err != nil {
			return fmt.Errorf("sync legacy task %s: %w", row.TaskID, err)
		}
		if (index+1)%100 == 0 {
			log.Printf("Asset catalog backfill processed %d/%d task(s)", index+1, len(rows))
		}
	}
	log.Printf("Asset catalog backfill completed for %d task(s)", len(rows))
	return nil
}
