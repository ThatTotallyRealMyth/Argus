package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/services"
	"gorm.io/gorm"
)

// AssetProfileHandler 资产画像处理器
type AssetProfileHandler struct {
	service *services.AssetProfileService
}

// NewAssetProfileHandler 创建资产画像处理器
func NewAssetProfileHandler() *AssetProfileHandler {
	return &AssetProfileHandler{
		service: services.NewAssetProfileService(),
	}
}

func validAssetProfileType(assetType string) bool {
	switch assetType {
	case "domain", "ip", "port", "site":
		return true
	default:
		return false
	}
}

func writeAssetProfileError(c *gin.Context, err error) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Asset not found"})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to build asset intelligence"})
}

// GetAssetProfile 获取资产画像
// GET /api/v1/assets/profile?asset_type=domain&asset_id=xxx
func (h *AssetProfileHandler) GetAssetProfile(c *gin.Context) {
	assetType := c.Query("asset_type")
	assetID := c.Query("asset_id")

	if assetType == "" || assetID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset_type and asset_id are required"})
		return
	}
	if !validAssetProfileType(assetType) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported asset_type"})
		return
	}

	profile, err := h.service.GetAssetProfile(assetType, assetID)
	if err != nil {
		writeAssetProfileError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"profile": profile})
}

// GetAssetRelations 获取资产关系
// GET /api/v1/assets/relations?asset_type=domain&asset_id=xxx
func (h *AssetProfileHandler) GetAssetRelations(c *gin.Context) {
	assetType := c.Query("asset_type")
	assetID := c.Query("asset_id")

	if assetType == "" || assetID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset_type and asset_id are required"})
		return
	}
	if !validAssetProfileType(assetType) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported asset_type"})
		return
	}

	relations, err := h.service.GetAssetRelations(assetType, assetID)
	if err != nil {
		writeAssetProfileError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"relations": relations})
}

// GetAssetGraph 获取资产关系图谱
// GET /api/v1/assets/graph?asset_type=domain&asset_id=xxx&depth=2
func (h *AssetProfileHandler) GetAssetGraph(c *gin.Context) {
	assetType := c.Query("asset_type")
	assetID := c.Query("asset_id")
	depthStr := c.Query("depth")

	if assetType == "" || assetID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset_type and asset_id are required"})
		return
	}
	if !validAssetProfileType(assetType) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported asset_type"})
		return
	}

	depth := 2
	if depthStr != "" {
		var err error
		depth, err = strconv.Atoi(depthStr)
		if err != nil || depth < 1 || depth > 5 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "depth must be between 1 and 5"})
			return
		}
	}

	graph, err := h.service.GetAssetGraph(assetType, assetID, depth)
	if err != nil {
		writeAssetProfileError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"graph": graph})
}

// AnalyzeCSegment C段分析
// GET /api/v1/assets/c-segment?task_id=xxx&ip=192.168.1.100
func (h *AssetProfileHandler) AnalyzeCSegment(c *gin.Context) {
	taskID := c.Query("task_id")
	ip := c.Query("ip")

	if taskID == "" || ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "task_id and ip are required"})
		return
	}

	analysis, err := h.service.AnalyzeCSegment(taskID, ip)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"analysis": analysis})
}
