package services

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/reconmaster/backend/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var dangerousAssetPorts = map[int]struct{}{
	21: {}, 22: {}, 23: {}, 135: {}, 445: {}, 1433: {}, 3306: {}, 3389: {}, 5432: {}, 6379: {}, 27017: {},
}

type vulnerabilityTarget struct {
	siteKey string
	origin  string
	domain  string
	ip      string
	portKey string
}

func parseVulnerabilityTarget(raw string) vulnerabilityTarget {
	raw = strings.TrimSpace(raw)
	parsed, err := url.Parse(raw)
	if err != nil {
		return vulnerabilityTarget{}
	}
	if parsed.Hostname() == "" && !strings.Contains(raw, "://") {
		parsed, err = url.Parse("//" + raw)
		if err != nil {
			return vulnerabilityTarget{}
		}
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return vulnerabilityTarget{}
	}
	target := vulnerabilityTarget{}
	if ip := canonicalIP(host); ip != "" {
		target.ip = ip
	} else {
		target.domain = canonicalDomain(host)
	}
	if parsed.Scheme != "" {
		target.siteKey = canonicalSite(raw)
		target.origin = canonicalSiteOrigin(raw)
	}
	port := parsed.Port()
	if port == "" {
		switch strings.ToLower(parsed.Scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	if target.ip != "" && port != "" {
		target.portKey = net.JoinHostPort(target.ip, port) + "/tcp"
	}
	return target
}

func canonicalSiteOrigin(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
		return ""
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if port != "" && !((scheme == "http" && port == "80") || (scheme == "https" && port == "443")) {
		host = net.JoinHostPort(host, port)
	}
	return scheme + "://" + host
}

func (s *AssetCatalogService) syncTaskVulnerabilities(db *gorm.DB, taskID string) error {
	var previousLinks []models.AssetVulnerabilityLink
	if err := db.Where("task_id = ?", taskID).Find(&previousLinks).Error; err != nil {
		return err
	}
	previousAssetIDs := make([]string, 0, len(previousLinks))
	previousByIdentity := make(map[string]models.AssetVulnerabilityLink, len(previousLinks))
	for _, link := range previousLinks {
		previousAssetIDs = append(previousAssetIDs, link.AssetID)
		previousByIdentity[link.AssetID+"\x00"+link.VulnerabilityID] = link
	}
	if err := db.Where("task_id = ?", taskID).Delete(&models.AssetVulnerabilityLink{}).Error; err != nil {
		return err
	}

	var taskAssetIDs []string
	if err := db.Model(&models.AssetObservation{}).Where("task_id = ?", taskID).Distinct().Pluck("asset_id", &taskAssetIDs).Error; err != nil {
		return err
	}
	var taskAssets []models.AssetEntity
	if len(taskAssetIDs) > 0 {
		if err := db.Where("id IN ?", taskAssetIDs).Find(&taskAssets).Error; err != nil {
			return err
		}
	}

	byKindAndKey := make(map[string]*models.AssetEntity, len(taskAssets))
	taskAssetSet := make(map[string]struct{}, len(taskAssets))
	sitesByOrigin := make(map[string][]*models.AssetEntity)
	for index := range taskAssets {
		asset := &taskAssets[index]
		taskAssetSet[asset.ID] = struct{}{}
		byKindAndKey[asset.Kind+"\x00"+asset.CanonicalKey] = asset
		if asset.Kind == "site" {
			if origin := canonicalSiteOrigin(asset.CanonicalKey); origin != "" {
				sitesByOrigin[origin] = append(sitesByOrigin[origin], asset)
			}
		}
	}

	var vulnerabilities []models.Vulnerability
	if err := db.Where("task_id = ?", taskID).Find(&vulnerabilities).Error; err != nil {
		return err
	}
	affectedAssetIDs := append([]string{}, previousAssetIDs...)
	affectedAssetIDs = append(affectedAssetIDs, taskAssetIDs...)
	for _, vulnerability := range vulnerabilities {
		if vulnerability.Source == "poc-verification" {
			var verifiedAssetIDs []string
			if err := db.Model(&models.PoCExecutionLog{}).
				Where("task_id = ? AND vulnerability_id = ? AND asset_id <> ''", taskID, vulnerability.ID).
				Distinct().Pluck("asset_id", &verifiedAssetIDs).Error; err != nil {
				return err
			}
			for _, assetID := range verifiedAssetIDs {
				if _, belongsToTask := taskAssetSet[assetID]; !belongsToTask {
					continue
				}
				previous := previousByIdentity[assetID+"\x00"+vulnerability.ID]
				link := models.AssetVulnerabilityLink{
					ID: previous.ID, AssetID: assetID, VulnerabilityID: vulnerability.ID, TaskID: taskID,
					MatchType: "poc_validated", Severity: strings.ToLower(strings.TrimSpace(vulnerability.Severity)), CreatedAt: previous.CreatedAt,
				}
				if err := db.Clauses(clause.OnConflict{
					Columns:   []clause.Column{{Name: "asset_id"}, {Name: "vulnerability_id"}},
					DoUpdates: clause.AssignmentColumns([]string{"task_id", "match_type", "severity", "updated_at"}),
				}).Create(&link).Error; err != nil {
					return err
				}
				affectedAssetIDs = append(affectedAssetIDs, assetID)
			}
			continue
		}
		target := parseVulnerabilityTarget(vulnerability.URL)
		matches := make(map[string]string)
		addMatch := func(asset *models.AssetEntity, matchType string) {
			if asset != nil {
				matches[asset.ID] = matchType
			}
		}
		addMatch(byKindAndKey["domain\x00"+target.domain], "hostname")
		addMatch(byKindAndKey["ip\x00"+target.ip], "host_ip")
		addMatch(byKindAndKey["port\x00"+target.portKey], "endpoint")
		addMatch(byKindAndKey["url\x00"+target.siteKey], "exact_url")
		if exactSite := byKindAndKey["site\x00"+target.siteKey]; exactSite != nil {
			addMatch(exactSite, "exact_site")
		} else {
			for _, site := range sitesByOrigin[target.origin] {
				addMatch(site, "site_origin")
			}
		}
		for assetID, matchType := range matches {
			previous := previousByIdentity[assetID+"\x00"+vulnerability.ID]
			link := models.AssetVulnerabilityLink{
				ID:      previous.ID,
				AssetID: assetID, VulnerabilityID: vulnerability.ID, TaskID: taskID,
				MatchType: matchType, Severity: strings.ToLower(strings.TrimSpace(vulnerability.Severity)),
				CreatedAt: previous.CreatedAt,
			}
			if err := db.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "asset_id"}, {Name: "vulnerability_id"}},
				DoUpdates: clause.AssignmentColumns([]string{"task_id", "match_type", "severity", "updated_at"}),
			}).Create(&link).Error; err != nil {
				return err
			}
			affectedAssetIDs = append(affectedAssetIDs, assetID)
		}
	}
	return s.recomputeAssetRisk(db, affectedAssetIDs)
}

func (s *AssetCatalogService) recomputeAssetRisk(db *gorm.DB, assetIDs []string) error {
	seen := make(map[string]struct{}, len(assetIDs))
	for _, assetID := range assetIDs {
		if assetID == "" {
			continue
		}
		if _, ok := seen[assetID]; ok {
			continue
		}
		seen[assetID] = struct{}{}
		var asset models.AssetEntity
		result := db.Limit(1).Find(&asset, "id = ?", assetID)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			continue
		}
		var rows []struct {
			Severity string
			Count    int64
		}
		if err := db.Table("asset_vulnerability_links AS links").
			Select("links.severity, COUNT(*) AS count").
			Joins("JOIN vulnerabilities ON vulnerabilities.id = links.vulnerability_id").
			Where("links.asset_id = ? AND vulnerabilities.status NOT IN ?", assetID, []string{models.VulnerabilityStatusResolved, models.VulnerabilityStatusFalsePositive}).
			Group("links.severity").Scan(&rows).Error; err != nil {
			return err
		}
		counts := make(map[string]int64, len(rows))
		var total int64
		for _, row := range rows {
			counts[row.Severity] = row.Count
			total += row.Count
		}
		exposureBonus, err := assetExposureRiskBonus(db, asset)
		if err != nil {
			return err
		}
		score := vulnerabilityRiskScore(counts, total) + exposureBonus
		if score > 100 {
			score = 100
		}
		if err := db.Model(&models.AssetEntity{}).Where("id = ?", assetID).Updates(map[string]any{
			"risk_score": score, "vulnerability_count": total,
			"critical_count": counts["critical"], "high_count": counts["high"],
		}).Error; err != nil {
			return err
		}
	}
	return nil
}

func vulnerabilityRiskScore(counts map[string]int64, total int64) int {
	base := 0
	switch {
	case counts["critical"] > 0:
		base = 90
	case counts["high"] > 0:
		base = 70
	case counts["medium"] > 0:
		base = 45
	case counts["low"] > 0:
		base = 20
	case counts["info"] > 0:
		base = 5
	}
	if total > 1 {
		bonus := int((total - 1) * 2)
		if bonus > 10 {
			bonus = 10
		}
		base += bonus
	}
	return base
}

func assetExposureRiskBonus(db *gorm.DB, asset models.AssetEntity) (int, error) {
	switch asset.Kind {
	case "domain":
		var count int64
		if err := db.Model(&models.AssetObservation{}).
			Where("asset_id = ? AND payload @> ?::jsonb", asset.ID, `{"takeover_vulnerable":true}`).
			Count(&count).Error; err != nil {
			return 0, err
		}
		if count > 0 {
			return 20, nil
		}
	case "port":
		if port, ok := canonicalPortNumber(asset.CanonicalKey); ok {
			if _, dangerous := dangerousAssetPorts[port]; dangerous {
				return 10, nil
			}
		}
	case "ip":
		var portKeys []string
		if err := db.Table("asset_relations AS relations").
			Select("ports.canonical_key").
			Joins("JOIN asset_entities AS ports ON ports.id = relations.to_asset_id").
			Where("relations.from_asset_id = ? AND relations.relation_type = ? AND ports.kind = ?", asset.ID, "exposes", "port").
			Pluck("ports.canonical_key", &portKeys).Error; err != nil {
			return 0, err
		}
		bonus := 0
		for _, key := range portKeys {
			if port, ok := canonicalPortNumber(key); ok {
				if _, dangerous := dangerousAssetPorts[port]; dangerous {
					bonus += 5
				}
			}
		}
		if bonus > 20 {
			bonus = 20
		}
		return bonus, nil
	}
	return 0, nil
}

func canonicalPortNumber(key string) (int, bool) {
	endpoint := strings.TrimSuffix(key, "/tcp")
	endpoint = strings.TrimSuffix(endpoint, "/udp")
	_, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return 0, false
	}
	port, err := strconv.Atoi(portText)
	return port, err == nil
}
