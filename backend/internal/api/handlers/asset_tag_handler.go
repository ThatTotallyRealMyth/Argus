package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/middleware"
	"github.com/reconmaster/backend/internal/models"
)

// AssetTagHandler Asset Label Processor
type AssetTagHandler struct{}

// NewAssetTagHandler Create an asset label handler
func NewAssetTagHandler() *AssetTagHandler {
	return &AssetTagHandler{}
}

// ListTags Fetch Tab List
func (h *AssetTagHandler) ListTags(c *gin.Context) {
	category := c.Query("category")
	page, pageSize := parsePagination(c, 20, 100)

	query := database.DB.Model(&models.AssetTag{})

	if category != "" {
		query = query.Where("category = ?", category)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count tags"})
		return
	}
	var tags []models.AssetTag
	if err := query.Order("created_at DESC").Limit(pageSize).Offset((page - 1) * pageSize).Find(&tags).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch tags"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tags": tags, "total": total, "page": page, "page_size": pageSize, "total_pages": int((total + int64(pageSize) - 1) / int64(pageSize))})
}

// CreateTag Create Tab
func (h *AssetTagHandler) CreateTag(c *gin.Context) {
	var req models.CreateTagRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := middleware.GetCurrentUserID(c)

	tag := models.AssetTag{
		Name:        req.Name,
		Color:       req.Color,
		Description: req.Description,
		Category:    req.Category,
		CreatedBy:   userID,
	}

	if tag.Color == "" {
		tag.Color = "#3B82F6" // Default Blue
	}

	if err := database.DB.Create(&tag).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create tag"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"tag": tag})
}

// UpdateTag Update Tab
func (h *AssetTagHandler) UpdateTag(c *gin.Context) {
	id := c.Param("id")

	var req models.UpdateTagRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var tag models.AssetTag
	if err := database.DB.First(&tag, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tag not found"})
		return
	}

	// Update Fields
	if req.Name != "" {
		tag.Name = req.Name
	}
	if req.Color != "" {
		tag.Color = req.Color
	}
	if req.Description != "" {
		tag.Description = req.Description
	}
	if req.Category != "" {
		tag.Category = req.Category
	}

	if err := database.DB.Save(&tag).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update tag"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tag": tag})
}

// DeleteTag Remove Tab
func (h *AssetTagHandler) DeleteTag(c *gin.Context) {
	id := c.Param("id")

	tx := database.DB.Begin()
	if tx.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start transaction"})
		return
	}
	if err := tx.Where("tag_id = ?", id).Delete(&models.AssetTagRelation{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete tag relations"})
		return
	}
	result := tx.Delete(&models.AssetTag{}, "id = ?", id)
	if result.Error != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete tag"})
		return
	}
	if result.RowsAffected == 0 {
		tx.Rollback()
		c.JSON(http.StatusNotFound, gin.H{"error": "Tag not found"})
		return
	}
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Tag deleted successfully"})
}

// AddAssetTags Adding a label to an asset
func (h *AssetTagHandler) AddAssetTags(c *gin.Context) {
	var req models.AddAssetTagRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := middleware.GetCurrentUserID(c)
	if len(req.TagIDs) > 50 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At most 50 tags can be attached"})
		return
	}
	validTypes := map[string]bool{"domain": true, "ip": true, "site": true, "port": true}
	if !validTypes[req.AssetType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset_type"})
		return
	}
	unique := make([]string, 0, len(req.TagIDs))
	seen := make(map[string]bool)
	for _, id := range req.TagIDs {
		if id != "" && !seen[id] {
			seen[id] = true
			unique = append(unique, id)
		}
	}
	if len(unique) > 0 {
		var count int64
		if err := database.DB.Model(&models.AssetTag{}).Where("id IN ?", unique).Count(&count).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate tags"})
			return
		}
		if count != int64(len(unique)) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "One or more tags do not exist"})
			return
		}
	}

	tx := database.DB.Begin()
	if tx.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start transaction"})
		return
	}
	if err := tx.Where("asset_type = ? AND asset_id = ?", req.AssetType, req.AssetID).Delete(&models.AssetTagRelation{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to replace tags"})
		return
	}

	// Add New Tab
	for _, tagID := range unique {
		relation := models.AssetTagRelation{
			TagID:     tagID,
			AssetType: req.AssetType,
			AssetID:   req.AssetID,
			CreatedBy: userID,
		}
		if err := tx.Create(&relation).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to attach tags"})
			return
		}
	}
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit tags"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Tags added successfully"})
}

// GetAssetTags Label for acquiring assets
func (h *AssetTagHandler) GetAssetTags(c *gin.Context) {
	assetType := c.Query("asset_type")
	assetID := c.Query("asset_id")

	if assetType == "" || assetID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset_type and asset_id are required"})
		return
	}

	var relations []models.AssetTagRelation
	if err := database.DB.Where("asset_type = ? AND asset_id = ?", assetType, assetID).Limit(50).Find(&relations).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch asset tag relations"})
		return
	}

	tagIDs := make([]string, len(relations))
	for i, rel := range relations {
		tagIDs[i] = rel.TagID
	}

	var tags []models.AssetTag
	if len(tagIDs) > 0 {
		if err := database.DB.Where("id IN ?", tagIDs).Find(&tags).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch asset tags"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"tags": tags})
}

// SearchAssetsByTag Search assets from label
func (h *AssetTagHandler) SearchAssetsByTag(c *gin.Context) {
	tagID := c.Query("tag_id")
	assetType := c.Query("asset_type") // Optional, Filter asset type
	page, pageSize := parsePagination(c, 50, 100)

	if tagID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tag_id is required"})
		return
	}

	query := database.DB.Model(&models.AssetTagRelation{}).Where("tag_id = ?", tagID)

	if assetType != "" {
		query = query.Where("asset_type = ?", assetType)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count tagged assets"})
		return
	}
	var relations []models.AssetTagRelation
	if err := query.Order("created_at DESC").Limit(pageSize).Offset((page - 1) * pageSize).Find(&relations).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch tagged assets"})
		return
	}

	// Grouping by asset type
	result := map[string][]string{
		"domains": []string{},
		"ips":     []string{},
		"sites":   []string{},
		"ports":   []string{},
	}

	for _, rel := range relations {
		switch rel.AssetType {
		case "domain":
			result["domains"] = append(result["domains"], rel.AssetID)
		case "ip":
			result["ips"] = append(result["ips"], rel.AssetID)
		case "site":
			result["sites"] = append(result["sites"], rel.AssetID)
		case "port":
			result["ports"] = append(result["ports"], rel.AssetID)
		}
	}

	c.JSON(http.StatusOK, gin.H{"assets": result, "total": total, "page": page, "page_size": pageSize, "total_pages": int((total + int64(pageSize) - 1) / int64(pageSize))})
}

// GetTagStats Get label statistics
func (h *AssetTagHandler) GetTagStats(c *gin.Context) {
	tagID := c.Param("id")

	var tag models.AssetTag
	if err := database.DB.First(&tag, "id = ?", tagID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tag not found"})
		return
	}

	// Count the assets associated with the label
	var stats struct {
		TotalAssets int64 `json:"total_assets"`
		DomainCount int64 `json:"domain_count"`
		IPCount     int64 `json:"ip_count"`
		SiteCount   int64 `json:"site_count"`
		PortCount   int64 `json:"port_count"`
	}

	counts := []struct {
		assetType string
		value     *int64
	}{
		{value: &stats.TotalAssets},
		{assetType: "domain", value: &stats.DomainCount},
		{assetType: "ip", value: &stats.IPCount},
		{assetType: "site", value: &stats.SiteCount},
		{assetType: "port", value: &stats.PortCount},
	}
	for _, count := range counts {
		query := database.DB.Model(&models.AssetTagRelation{}).Where("tag_id = ?", tagID)
		if count.assetType != "" {
			query = query.Where("asset_type = ?", count.assetType)
		}
		if err := query.Count(count.value).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load tag statistics"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"tag":   tag,
		"stats": stats,
	})
}
