package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/services"
)

const assetLeadCandidateLimit = 1000

type AssetLeadHandler struct{}

func NewAssetLeadHandler() *AssetLeadHandler { return &AssetLeadHandler{} }

// List returns a ranked, triage-aware queue derived from canonical asset evidence.
func (h *AssetLeadHandler) List(c *gin.Context) {
	page, pageSize := parsePagination(c, 25, 100)
	var candidateTotal int64
	assetQuery := database.DB.Model(&models.AssetEntity{}).Where("scope_id = ?", models.DefaultAssetScope)
	if err := assetQuery.Count(&candidateTotal).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count lead candidates"})
		return
	}
	var assets []models.AssetEntity
	if err := assetQuery.Order("risk_score DESC, last_seen_at DESC, display_value ASC").Limit(assetLeadCandidateLimit).Find(&assets).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch lead candidates"})
		return
	}
	leads, err := services.BuildAssetLeadQueue(database.DB, assets)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to build attack lead queue"})
		return
	}
	triages, err := services.LoadAssetLeadTriages(database.DB, services.AssetIDs(assets))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch lead triage state"})
		return
	}
	services.ApplyAssetLeadTriages(leads, triages)
	leads = services.CollapseDuplicateAssetAttackLeads(leads)
	stats := services.SummarizeAssetAttackLeads(leads)
	filtered := services.FilterAndSortAssetAttackLeads(leads, services.AssetLeadQueueFilter{
		Status: c.Query("status"), Severity: c.Query("severity"), Type: c.Query("type"), Query: c.Query("q"),
	})
	total := len(filtered)
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	c.JSON(http.StatusOK, gin.H{
		"leads": filtered[start:end], "stats": stats, "total": total, "page": page, "page_size": pageSize,
		"total_pages": (total + pageSize - 1) / pageSize, "candidate_assets": len(assets), "truncated": candidateTotal > int64(len(assets)),
	})
}

func (h *AssetLeadHandler) UpdateTriage(c *gin.Context) {
	var req services.AssetLeadTriageUpdate
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	saved, updatedCount, err := services.UpdateAssetLeadTriages(database.DB, req)
	if errors.Is(err, services.ErrInvalidAssetLeadTriage) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid lead triage payload"})
		return
	}
	if errors.Is(err, services.ErrCanonicalAssetNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Canonical asset not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save lead triage"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"triage": saved, "updated_count": updatedCount})
}

type updateFindingTriageRequest struct {
	Status string `json:"status" binding:"required"`
	Note   string `json:"note"`
}

func (h *AssetLeadHandler) UpdateFindingTriage(c *gin.Context) {
	var req updateFindingTriageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid finding triage payload"})
		return
	}
	finding, assetIDs, err := services.UpdateFindingTriage(database.DB, services.FindingTriageInput{
		VulnerabilityID: c.Param("id"), Status: req.Status, Note: req.Note, ActorID: c.GetString("user_id"),
	})
	if errors.Is(err, services.ErrInvalidFindingTriage) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid finding triage payload"})
		return
	}
	if errors.Is(err, services.ErrFindingNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Finding not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update finding triage"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"finding": finding, "asset_ids": assetIDs})
}

type executeAssetLeadPoCRequest struct {
	AssetID string `json:"asset_id" binding:"required"`
	LeadID  string `json:"lead_id" binding:"required"`
	Confirm bool   `json:"confirm"`
}

// ExecutePoC verifies a canonical lead through the task-bound authorization path.
func (h *AssetLeadHandler) ExecutePoC(c *gin.Context) {
	var req executeAssetLeadPoCRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !req.Confirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "PoC execution requires confirm=true"})
		return
	}
	result, execErr := services.ExecuteAssetLeadPoC(database.DB, nil, services.AssetLeadPoCExecutionInput{
		AssetID: req.AssetID, LeadID: req.LeadID, InvocationSource: "web", ActorID: c.GetString("user_id"),
	})
	if result == nil {
		if errors.Is(execErr, services.ErrAssetLeadNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Asset lead not found"})
			return
		}
		if services.IsScanScopeInputError(execErr) || errors.Is(execErr, services.ErrInvalidAssetLeadRef) || errors.Is(execErr, services.ErrAssetLeadPoCBlocked) {
			c.JSON(http.StatusBadRequest, gin.H{"error": execErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to authorize PoC execution"})
		return
	}
	if errors.Is(execErr, services.ErrAssetLeadPoCAudit) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "PoC execution completed but the audit record could not be saved", "result": result.Result, "details": result.Details, "audit_saved": false})
		return
	}
	if execErr != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "PoC execution failed", "result": result.Result, "details": result.Details, "execution_log": result.ExecutionLog})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"result": result.Result, "details": result.Details, "execution_log": result.ExecutionLog, "lead": result.Lead,
		"finding": result.Finding, "finding_link": result.FindingLink, "finding_created": result.FindingNew,
	})
}
