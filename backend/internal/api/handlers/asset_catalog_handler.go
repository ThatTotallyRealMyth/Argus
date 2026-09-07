package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/scanner"
	"github.com/reconmaster/backend/internal/services"
)

type AssetCatalogHandler struct{}

func NewAssetCatalogHandler() *AssetCatalogHandler { return &AssetCatalogHandler{} }

func (h *AssetCatalogHandler) List(c *gin.Context) {
	page, pageSize := parsePagination(c, 20, 200)
	kind := c.Query("kind")
	query := database.DB.Model(&models.AssetEntity{}).Where("scope_id = ?", models.DefaultAssetScope)
	if kind != "" && kind != "all" {
		query = query.Where("kind = ?", kind)
	}
	if search := c.Query("search"); search != "" {
		query = query.Where("display_value ILIKE ? OR canonical_key ILIKE ?", "%"+search+"%", "%"+search+"%")
	}
	var ok bool
	query, ok = applyAdvancedSearch(c, query,
		map[string]string{"kind": "kind", "value": "display_value", "status": "status", "risk": "risk_score", "vulnerabilities": "vulnerability_count", "changes": "change_count", "observations": "observation_count"},
		[]string{"kind", "display_value", "canonical_key", "status"})
	if !ok {
		return
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count canonical assets"})
		return
	}
	var assets []models.AssetEntity
	if err := query.Order("last_seen_at DESC, display_value ASC").Limit(pageSize).Offset((page - 1) * pageSize).Find(&assets).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch canonical assets"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"assets":      assets,
		"total":       total,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": int((total + int64(pageSize) - 1) / int64(pageSize)),
	})
}

func (h *AssetCatalogHandler) Stats(c *gin.Context) {
	var rows []struct {
		Kind  string
		Count int64
	}
	if err := database.DB.Model(&models.AssetEntity{}).
		Select("kind, COUNT(*) AS count").
		Where("scope_id = ?", models.DefaultAssetScope).
		Group("kind").Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to calculate canonical asset statistics"})
		return
	}
	stats := gin.H{"total": int64(0), "domains": int64(0), "ips": int64(0), "ports": int64(0), "sites": int64(0), "urls": int64(0)}
	for _, row := range rows {
		stats["total"] = stats["total"].(int64) + row.Count
		switch row.Kind {
		case "domain":
			stats["domains"] = row.Count
		case "ip":
			stats["ips"] = row.Count
		case "port":
			stats["ports"] = row.Count
		case "site":
			stats["sites"] = row.Count
		case "url":
			stats["urls"] = row.Count
		}
	}
	var observations, relations, vulnerabilityLinks, changes, atRisk, critical, high int64
	if err := database.DB.Model(&models.AssetObservation{}).Count(&observations).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count asset observations"})
		return
	}
	if err := database.DB.Model(&models.CanonicalAssetRelation{}).Count(&relations).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count asset relations"})
		return
	}
	if err := database.DB.Model(&models.AssetVulnerabilityLink{}).Count(&vulnerabilityLinks).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count asset vulnerability links"})
		return
	}
	if err := database.DB.Model(&models.AssetChange{}).Where("event_type = ?", "modified").Count(&changes).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count asset changes"})
		return
	}
	assetQuery := database.DB.Model(&models.AssetEntity{}).Where("scope_id = ?", models.DefaultAssetScope)
	if err := assetQuery.Where("risk_score > 0").Count(&atRisk).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count risky assets"})
		return
	}
	if err := database.DB.Model(&models.AssetEntity{}).Where("scope_id = ? AND critical_count > 0", models.DefaultAssetScope).Count(&critical).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count critical assets"})
		return
	}
	if err := database.DB.Model(&models.AssetEntity{}).Where("scope_id = ? AND high_count > 0", models.DefaultAssetScope).Count(&high).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count high-risk assets"})
		return
	}
	stats["observations"] = observations
	stats["relations"] = relations
	stats["vulnerability_links"] = vulnerabilityLinks
	stats["changes"] = changes
	stats["at_risk"] = atRisk
	stats["critical"] = critical
	stats["high"] = high
	c.JSON(http.StatusOK, stats)
}

type catalogRelationView struct {
	ID           string             `json:"id"`
	Direction    string             `json:"direction"`
	RelationType string             `json:"relation_type"`
	Asset        models.AssetEntity `json:"asset"`
	LastTaskID   string             `json:"last_task_id,omitempty"`
	FirstSeenAt  time.Time          `json:"first_seen_at"`
	LastSeenAt   time.Time          `json:"last_seen_at"`
}

type catalogFindingView struct {
	ID                     string     `json:"id"`
	VulnerabilityID        string     `json:"vulnerability_id"`
	TaskID                 string     `json:"task_id"`
	Severity               string     `json:"severity"`
	Status                 string     `json:"status"`
	Title                  string     `json:"title"`
	URL                    string     `json:"url"`
	Type                   string     `json:"type"`
	Source                 string     `json:"source"`
	MatchType              string     `json:"match_type"`
	Description            string     `json:"description,omitempty"`
	Payload                string     `json:"payload,omitempty"`
	Proof                  string     `json:"proof,omitempty"`
	TriageNote             string     `json:"triage_note,omitempty"`
	TriageUpdatedAt        *time.Time `json:"triage_updated_at,omitempty"`
	LastVerifiedAt         *time.Time `json:"last_verified_at,omitempty"`
	LastVerificationResult string     `json:"last_verification_result,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`
}

func (h *AssetCatalogHandler) Get(c *gin.Context) {
	assetID := c.Param("id")
	var asset models.AssetEntity
	if err := database.DB.First(&asset, "id = ?", assetID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Canonical asset not found"})
		return
	}
	var observations []models.AssetObservation
	if err := database.DB.Where("asset_id = ?", assetID).Order("observed_at DESC").Limit(100).Find(&observations).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch asset observations"})
		return
	}
	var primaryObservation models.AssetObservation
	primaryResult := database.DB.Where("asset_id = ? AND source_type = ?", assetID, asset.Kind).
		Order("observed_at DESC, id DESC").Limit(1).Find(&primaryObservation)
	if primaryResult.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch primary asset snapshot"})
		return
	}
	if primaryResult.RowsAffected == 1 {
		asset.CurrentData = primaryObservation.Payload
	}
	var changes []models.AssetChange
	if err := database.DB.Where("asset_id = ?", assetID).Order("observed_at DESC").Limit(100).Find(&changes).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch asset changes"})
		return
	}
	var relations []models.CanonicalAssetRelation
	if err := database.DB.Where("from_asset_id = ? OR to_asset_id = ?", assetID, assetID).Order("last_seen_at DESC").Limit(100).Find(&relations).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch asset relations"})
		return
	}
	relatedIDs := make([]string, 0, len(relations))
	for _, relation := range relations {
		if relation.FromAssetID == assetID {
			relatedIDs = append(relatedIDs, relation.ToAssetID)
		} else {
			relatedIDs = append(relatedIDs, relation.FromAssetID)
		}
	}
	var relatedAssets []models.AssetEntity
	if len(relatedIDs) > 0 {
		if err := database.DB.Where("id IN ?", relatedIDs).Find(&relatedAssets).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch related assets"})
			return
		}
	}
	assetMap := make(map[string]models.AssetEntity, len(relatedAssets))
	for _, related := range relatedAssets {
		assetMap[related.ID] = related
	}
	views := make([]catalogRelationView, 0, len(relations))
	for _, relation := range relations {
		direction := "outgoing"
		relatedID := relation.ToAssetID
		if relation.ToAssetID == assetID {
			direction = "incoming"
			relatedID = relation.FromAssetID
		}
		views = append(views, catalogRelationView{
			ID: relation.ID, Direction: direction, RelationType: relation.RelationType,
			Asset: assetMap[relatedID], LastTaskID: relation.LastTaskID, FirstSeenAt: relation.FirstSeenAt, LastSeenAt: relation.LastSeenAt,
		})
	}
	var findings []catalogFindingView
	if err := database.DB.Table("asset_vulnerability_links AS links").
		Select("links.id, links.vulnerability_id, links.task_id, links.severity, links.match_type, vulnerabilities.status, vulnerabilities.title, vulnerabilities.url, vulnerabilities.type, vulnerabilities.source, vulnerabilities.description, vulnerabilities.payload, vulnerabilities.proof, vulnerabilities.triage_note, vulnerabilities.triage_updated_at, vulnerabilities.last_verified_at, vulnerabilities.last_verification_result, vulnerabilities.created_at").
		Joins("JOIN vulnerabilities ON vulnerabilities.id = links.vulnerability_id").
		Where("links.asset_id = ?", assetID).
		Order("CASE links.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, vulnerabilities.created_at DESC").
		Limit(100).Scan(&findings).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch asset vulnerabilities"})
		return
	}
	executions, err := services.LoadAssetLeadPoCExecutions(database.DB, assetID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch PoC verification history"})
		return
	}
	leadFindings := make([]services.AssetLeadFinding, 0, len(findings))
	for _, finding := range findings {
		leadFindings = append(leadFindings, services.AssetLeadFinding{
			ID: finding.ID, VulnerabilityID: finding.VulnerabilityID, TaskID: finding.TaskID, Severity: finding.Severity, Status: finding.Status, Title: finding.Title,
			URL: finding.URL, Type: finding.Type, Source: finding.Source, MatchType: finding.MatchType, CreatedAt: finding.CreatedAt,
		})
	}
	leadRelations := make([]services.AssetLeadRelation, 0, len(views))
	for _, relation := range views {
		leadRelations = append(leadRelations, services.AssetLeadRelation{
			RelationType: relation.RelationType, Asset: relation.Asset, LastTaskID: relation.LastTaskID, LastSeenAt: relation.LastSeenAt,
		})
	}
	matchedPoCs := []models.PoC{}
	if fingerprints := services.AssetLeadFingerprints(asset); len(fingerprints) > 0 {
		var err error
		matchedPoCs, err = scanner.NewPoCMatcher().MatchPoCsByFingerprints(fingerprints)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to match asset PoCs"})
			return
		}
	}
	leads := services.BuildAssetAttackLeads(asset, changes, leadFindings, leadRelations, matchedPoCs)
	triages, err := services.LoadAssetLeadTriages(database.DB, []string{asset.ID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch lead triage state"})
		return
	}
	services.ApplyAssetLeadTriages(leads, triages)
	c.JSON(http.StatusOK, gin.H{"asset": asset, "observations": observations, "relations": views, "findings": findings, "changes": changes, "executions": executions, "leads": leads})
}
