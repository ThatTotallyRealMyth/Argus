package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
)

type AssetGroupHandler struct{}

func NewAssetGroupHandler() *AssetGroupHandler { return &AssetGroupHandler{} }

func (h *AssetGroupHandler) List(c *gin.Context) {
	var groups []models.AssetGroup
	query := database.DB.Order("created_at DESC")
	if search := strings.TrimSpace(c.Query("search")); search != "" {
		query = query.Where("name LIKE ?", "%"+search+"%")
	}
	var ok bool
	query, ok = applyAdvancedSearch(c, query,
		map[string]string{"name": "name", "description": "description"},
		[]string{"name", "description"})
	if !ok {
		return
	}
	if err := query.Find(&groups).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list asset groups"})
		return
	}
	type result struct {
		models.AssetGroup
		MemberCount int64            `json:"member_count"`
		AssetCounts map[string]int64 `json:"asset_counts"`
	}
	type countRow struct {
		GroupID   string `gorm:"column:group_id"`
		AssetType string `gorm:"column:asset_type"`
		Count     int64  `gorm:"column:count"`
	}
	var countRows []countRow
	if len(groups) > 0 {
		if err := database.DB.Model(&models.AssetGroupItem{}).
			Select("group_id, asset_type, COUNT(*) AS count").
			Where("group_id IN ? AND asset_type <> ?", groupIDs(groups), "canonical").
			Group("group_id, asset_type").Scan(&countRows).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to count asset group members"})
			return
		}
	}
	var canonicalCountRows []countRow
	if len(groups) > 0 {
		if err := database.DB.Table("asset_group_items AS items").
			Select("items.group_id, assets.kind AS asset_type, COUNT(*) AS count").
			Joins("JOIN asset_entities AS assets ON assets.id = items.asset_id").
			Where("items.group_id IN ? AND items.asset_type = ?", groupIDs(groups), "canonical").
			Group("items.group_id, assets.kind").Scan(&canonicalCountRows).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to count canonical asset group members"})
			return
		}
		countRows = append(countRows, canonicalCountRows...)
	}
	countsByGroup := make(map[string]map[string]int64, len(groups))
	for _, row := range countRows {
		if countsByGroup[row.GroupID] == nil {
			countsByGroup[row.GroupID] = map[string]int64{}
		}
		countsByGroup[row.GroupID][row.AssetType] += row.Count
	}
	items := make([]result, 0, len(groups))
	for _, group := range groups {
		counts := map[string]int64{"domain": 0, "ip": 0, "port": 0, "site": 0}
		for assetType, count := range countsByGroup[group.ID] {
			counts[assetType] = count
		}
		memberCount := counts["domain"] + counts["ip"] + counts["port"] + counts["site"]
		items = append(items, result{AssetGroup: group, MemberCount: memberCount, AssetCounts: counts})
	}
	c.JSON(http.StatusOK, gin.H{"groups": items, "total": len(items)})
}

func groupIDs(groups []models.AssetGroup) []string {
	ids := make([]string, 0, len(groups))
	for _, group := range groups {
		ids = append(ids, group.ID)
	}
	return ids
}

func (h *AssetGroupHandler) Create(c *gin.Context) {
	var input struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	group := models.AssetGroup{Name: strings.TrimSpace(input.Name), Description: strings.TrimSpace(input.Description)}
	if group.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset group name cannot be empty"})
		return
	}
	if err := database.DB.Create(&group).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "asset group name already exists"})
		return
	}
	c.JSON(http.StatusCreated, group)
}

func (h *AssetGroupHandler) Update(c *gin.Context) {
	var group models.AssetGroup
	if database.DB.First(&group, "id = ?", c.Param("id")).Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "asset group not found"})
		return
	}
	var input struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	group.Name, group.Description = strings.TrimSpace(input.Name), strings.TrimSpace(input.Description)
	if group.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset group name cannot be empty"})
		return
	}
	if err := database.DB.Save(&group).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "asset group name already exists"})
		return
	}
	c.JSON(http.StatusOK, group)
}

func (h *AssetGroupHandler) Delete(c *gin.Context) {
	tx := database.DB.Begin()
	if tx.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start asset group deletion"})
		return
	}
	if err := tx.Where("group_id = ?", c.Param("id")).Delete(&models.AssetGroupItem{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete group members"})
		return
	}
	result := tx.Delete(&models.AssetGroup{}, "id = ?", c.Param("id"))
	if result.Error != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete asset group"})
		return
	}
	if result.RowsAffected == 0 {
		tx.Rollback()
		c.JSON(http.StatusNotFound, gin.H{"error": "asset group not found"})
		return
	}
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to commit asset group deletion"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "asset group deleted"})
}

func (h *AssetGroupHandler) AddMembers(c *gin.Context) {
	var input struct {
		AssetType string   `json:"asset_type" binding:"required"`
		AssetIDs  []string `json:"asset_ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if input.AssetType != "domain" && input.AssetType != "ip" && input.AssetType != "site" && input.AssetType != "canonical" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid asset_type", "field": "asset_type", "allowed": []string{"domain", "ip", "site", "canonical"}, "example": gin.H{"asset_type": "canonical", "asset_ids": []string{"asset-uuid"}}})
		return
	}
	if len(input.AssetIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset_ids must contain at least one ID", "field": "asset_ids"})
		return
	}
	if len(input.AssetIDs) > 1000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at most 1000 assets can be added at once", "field": "asset_ids", "received": len(input.AssetIDs)})
		return
	}
	groupID := c.Param("id")
	var group models.AssetGroup
	if err := database.DB.First(&group, "id = ?", groupID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "asset group not found"})
		return
	}

	type itemError struct {
		AssetID string `json:"asset_id"`
		Error   string `json:"error"`
	}
	created := make([]string, 0, len(input.AssetIDs))
	skipped := make([]string, 0)
	errors := make([]itemError, 0)
	seen := make(map[string]struct{}, len(input.AssetIDs))
	requestedIDs := make([]string, 0, len(input.AssetIDs))
	for _, id := range input.AssetIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			errors = append(errors, itemError{AssetID: id, Error: "asset ID is empty"})
			continue
		}
		if _, exists := seen[id]; exists {
			skipped = append(skipped, id)
			continue
		}
		seen[id] = struct{}{}
		requestedIDs = append(requestedIDs, id)
	}
	existingAssets := make(map[string]struct{}, len(requestedIDs))
	if len(requestedIDs) > 0 {
		var lookupErr error
		switch input.AssetType {
		case "domain":
			var rows []models.Domain
			lookupErr = database.DB.Select("id").Where("id IN ?", requestedIDs).Find(&rows).Error
			for _, row := range rows {
				existingAssets[row.ID] = struct{}{}
			}
		case "ip":
			var rows []models.IP
			lookupErr = database.DB.Select("id").Where("id IN ?", requestedIDs).Find(&rows).Error
			for _, row := range rows {
				existingAssets[row.ID] = struct{}{}
			}
		case "site":
			var rows []models.Site
			lookupErr = database.DB.Select("id").Where("id IN ?", requestedIDs).Find(&rows).Error
			for _, row := range rows {
				existingAssets[row.ID] = struct{}{}
			}
		case "canonical":
			var rows []models.AssetEntity
			lookupErr = database.DB.Select("id").Where("id IN ?", requestedIDs).Find(&rows).Error
			for _, row := range rows {
				existingAssets[row.ID] = struct{}{}
			}
		}
		if lookupErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to validate assets"})
			return
		}
	}
	var existingItems []models.AssetGroupItem
	if len(requestedIDs) > 0 {
		if err := database.DB.Where("group_id = ? AND asset_type = ? AND asset_id IN ?", groupID, input.AssetType, requestedIDs).Find(&existingItems).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to inspect existing group members"})
			return
		}
	}
	existingMemberships := make(map[string]struct{}, len(existingItems))
	for _, item := range existingItems {
		existingMemberships[item.AssetID] = struct{}{}
	}
	newItems := make([]models.AssetGroupItem, 0, len(requestedIDs))
	for _, id := range requestedIDs {
		if _, ok := existingAssets[id]; !ok {
			errors = append(errors, itemError{AssetID: id, Error: fmt.Sprintf("%s asset not found", input.AssetType)})
			continue
		}
		if _, ok := existingMemberships[id]; ok {
			skipped = append(skipped, id)
			continue
		}
		newItems = append(newItems, models.AssetGroupItem{GroupID: groupID, AssetType: input.AssetType, AssetID: id})
		created = append(created, id)
	}
	if len(newItems) > 0 {
		if err := database.DB.CreateInBatches(&newItems, 200).Error; err != nil {
			for _, id := range created {
				errors = append(errors, itemError{AssetID: id, Error: "failed to add asset"})
			}
			created = created[:0]
		}
	}
	c.JSON(http.StatusOK, gin.H{"created": created, "created_count": len(created), "skipped": skipped, "errors": errors})
}

func (h *AssetGroupHandler) ListMembers(c *gin.Context) {
	var group models.AssetGroup
	if err := database.DB.First(&group, "id = ?", c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "asset group not found"})
		return
	}
	var items []models.AssetGroupItem
	if err := database.DB.Where("group_id = ?", c.Param("id")).Order("created_at DESC").Find(&items).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list group members"})
		return
	}
	type member struct {
		models.AssetGroupItem
		Label       string `json:"label"`
		Kind        string `json:"kind"`
		AssetSource string `json:"asset_source"`
	}
	result := make([]member, 0, len(items))
	domainIDs, ipIDs, siteIDs, canonicalIDs := make([]string, 0), make([]string, 0), make([]string, 0), make([]string, 0)
	for _, item := range items {
		switch item.AssetType {
		case "domain":
			domainIDs = append(domainIDs, item.AssetID)
		case "ip":
			ipIDs = append(ipIDs, item.AssetID)
		case "site":
			siteIDs = append(siteIDs, item.AssetID)
		case "canonical":
			canonicalIDs = append(canonicalIDs, item.AssetID)
		}
	}
	domains, ips, sites := make(map[string]string), make(map[string]string), make(map[string]string)
	canonicalAssets := make(map[string]models.AssetEntity)
	if len(domainIDs) > 0 {
		var rows []models.Domain
		if err := database.DB.Select("id, domain").Where("id IN ?", domainIDs).Find(&rows).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load domain members"})
			return
		}
		for _, row := range rows {
			domains[row.ID] = row.Domain
		}
	}
	if len(ipIDs) > 0 {
		var rows []models.IP
		if err := database.DB.Select("id, ip_address").Where("id IN ?", ipIDs).Find(&rows).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load IP members"})
			return
		}
		for _, row := range rows {
			ips[row.ID] = row.IPAddress
		}
	}
	if len(siteIDs) > 0 {
		var rows []models.Site
		if err := database.DB.Select("id, url").Where("id IN ?", siteIDs).Find(&rows).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load site members"})
			return
		}
		for _, row := range rows {
			sites[row.ID] = row.URL
		}
	}
	if len(canonicalIDs) > 0 {
		var rows []models.AssetEntity
		if err := database.DB.Select("id, kind, display_value").Where("id IN ?", canonicalIDs).Find(&rows).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load catalog members"})
			return
		}
		for _, row := range rows {
			canonicalAssets[row.ID] = row
		}
	}
	for _, item := range items {
		label := "[asset deleted]"
		kind := item.AssetType
		assetSource := "task"
		switch item.AssetType {
		case "domain":
			if value, ok := domains[item.AssetID]; ok {
				label = value
			}
		case "ip":
			if value, ok := ips[item.AssetID]; ok {
				label = value
			}
		case "site":
			if value, ok := sites[item.AssetID]; ok {
				label = value
			}
		case "canonical":
			assetSource = "catalog"
			if value, ok := canonicalAssets[item.AssetID]; ok {
				label = value.DisplayValue
				kind = value.Kind
			}
		}
		result = append(result, member{AssetGroupItem: item, Label: label, Kind: kind, AssetSource: assetSource})
	}
	c.JSON(http.StatusOK, gin.H{"items": result, "total": len(result)})
}

func (h *AssetGroupHandler) DeleteMember(c *gin.Context) {
	result := database.DB.Delete(&models.AssetGroupItem{}, "id = ? AND group_id = ?", c.Param("member_id"), c.Param("id"))
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete group member"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "group member not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "group member deleted"})
}
