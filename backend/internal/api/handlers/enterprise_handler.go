package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/logger"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/services"
)

type EnterpriseHandler struct {
	service *services.EnterpriseService
}

func NewEnterpriseHandler(service *services.EnterpriseService) *EnterpriseHandler {
	return &EnterpriseHandler{service: service}
}

func (h *EnterpriseHandler) Providers(c *gin.Context) {
	providers, err := h.service.ProviderStatus()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"providers": providers})
}

func (h *EnterpriseHandler) CreateQuery(c *gin.Context) {
	var request struct {
		Name       string   `json:"name"`
		Keyword    string   `json:"keyword" binding:"required"`
		Provider   string   `json:"provider"`
		QueryTypes []string `json:"query_types"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	query, err := h.service.CreateQuery(request.Name, request.Keyword, request.Provider, request.QueryTypes, c.GetString("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"query": query})
}

func (h *EnterpriseHandler) ListQueries(c *gin.Context) {
	page, pageSize := parsePagination(c, 20, 100)
	query := database.DB.Model(&models.EnterpriseQuery{})
	if status := strings.TrimSpace(c.Query("status")); status != "" && status != "all" {
		query = query.Where("status = ?", status)
	}
	var ok bool
	query, ok = applyAdvancedSearch(c, query,
		map[string]string{"name": "name", "keyword": "keyword", "provider": "provider", "status": "status"},
		[]string{"name", "keyword", "provider", "status"})
	if !ok {
		return
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var rows []models.EnterpriseQuery
	if err := query.Order("created_at DESC").Limit(pageSize).Offset((page - 1) * pageSize).Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var stats struct {
		TotalAssets int64 `json:"total_assets"`
		Domains     int64 `json:"domains"`
		Apps        int64 `json:"apps"`
		MiniApps    int64 `json:"mini_apps"`
		QuickApps   int64 `json:"quick_apps"`
	}
	if err := database.DB.Model(&models.EnterpriseQuery{}).Select("COALESCE(SUM(total_count), 0) AS total_assets, COALESCE(SUM(domain_count), 0) AS domains, COALESCE(SUM(app_count), 0) AS apps, COALESCE(SUM(mini_app_count), 0) AS mini_apps, COALESCE(SUM(quick_app_count), 0) AS quick_apps").Scan(&stats).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"queries": rows, "total": total, "page": page, "page_size": pageSize, "total_pages": (total + int64(pageSize) - 1) / int64(pageSize), "stats": stats})
}

func (h *EnterpriseHandler) GetQuery(c *gin.Context) {
	var query models.EnterpriseQuery
	if err := database.DB.First(&query, "id = ?", c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "enterprise query not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"query": query})
}

func (h *EnterpriseHandler) DeleteQuery(c *gin.Context) {
	if err := h.service.DeleteQuery(c.Param("id")); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Enterprise query deleted"})
}

func (h *EnterpriseHandler) ListAssets(c *gin.Context) {
	page, pageSize := parsePagination(c, 50, 200)
	query := database.DB.Model(&models.EnterpriseAsset{})
	if queryID := strings.TrimSpace(c.Query("query_id")); queryID != "" {
		query = query.Where("query_id = ?", queryID)
	}
	if kind := strings.TrimSpace(c.Query("kind")); kind != "" && kind != "all" {
		query = query.Where("kind = ?", kind)
	}
	if c.Query("scannable") == "true" {
		query = query.Where("domain <> ''")
	}
	var ok bool
	query, ok = applyAdvancedSearch(c, query,
		map[string]string{"company": "company_name", "name": "name", "domain": "domain", "license": "license", "kind": "kind"},
		[]string{"company_name", "name", "domain", "license"})
	if !ok {
		return
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var rows []models.EnterpriseAsset
	if err := query.Order("created_at DESC").Limit(pageSize).Offset((page - 1) * pageSize).Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"assets": rows, "total": total, "page": page, "page_size": pageSize, "total_pages": (total + int64(pageSize) - 1) / int64(pageSize)})
}

func (h *EnterpriseHandler) LaunchScan(c *gin.Context) {
	var request struct {
		AssetIDs []string           `json:"asset_ids" binding:"required"`
		Name     string             `json:"name"`
		PolicyID string             `json:"policy_id"`
		ScopeID  string             `json:"scope_id"`
		Options  models.TaskOptions `json:"options"`
		Start    bool               `json:"start"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	task, targets, err := h.service.LaunchScan(request.AssetIDs, request.Name, request.PolicyID, request.ScopeID, request.Options, request.Start, c.GetString("user_id"))
	if err != nil {
		if services.IsEnterpriseScanInputError(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		logger.Error("Enterprise scan handoff failed user_id=%q requested=%d error=%v", c.GetString("user_id"), len(request.AssetIDs), err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create enterprise scan task"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"task": task, "targets": targets, "target_count": len(targets)})
}

func (h *EnterpriseHandler) SyncAssets(c *gin.Context) {
	var request struct {
		AssetIDs     []string `json:"asset_ids" binding:"required"`
		GroupID      string   `json:"group_id"`
		NewGroupName string   `json:"new_group_name"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := h.service.SyncAssets(request.AssetIDs, request.GroupID, request.NewGroupName)
	if err != nil {
		if services.IsEnterpriseSyncInputError(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		logger.Error("Enterprise catalog sync failed user_id=%q username=%q requested=%d error=%v", c.GetString("user_id"), c.GetString("username"), len(request.AssetIDs), err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sync enterprise assets"})
		return
	}
	logger.Info("Enterprise catalog sync user_id=%q username=%q requested=%d synced=%d group_id=%q", c.GetString("user_id"), c.GetString("username"), result.RequestedCount, result.SyncedCount, result.GroupID)
	c.JSON(http.StatusOK, result)
}
