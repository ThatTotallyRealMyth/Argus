package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/logger"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/services"
)

type MonitorRunner interface {
	RunMonitorNow(string) error
}

// MonitorHandler Monitor processor
type MonitorHandler struct{ runner MonitorRunner }

// NewMonitorHandler Create Monitor Processor
func NewMonitorHandler(runners ...MonitorRunner) *MonitorHandler {
	handler := &MonitorHandler{}
	if len(runners) > 0 {
		handler.runner = runners[0]
	}
	return handler
}

func (h *MonitorHandler) RunNow(c *gin.Context) {
	if h.runner == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Monitor runner is unavailable"})
		return
	}
	if err := h.runner.RunMonitorNow(c.Param("id")); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"message": "Monitor execution queued"})
}

// CreateMonitorRequest Create a request for surveillance
type CreateMonitorRequest struct {
	Name               string                     `json:"name" binding:"required"`
	Type               models.MonitorType         `json:"type"`
	Target             string                     `json:"target"`
	Interval           int                        `json:"interval" binding:"required,min=1"` // Units: Hours
	AssetGroupID       string                     `json:"asset_group_id"`
	ScopeID            string                     `json:"scope_id"`
	Options            *models.MonitorOptions     `json:"options"`
	NotificationConfig *models.NotificationConfig `json:"notification_config"`
}

// UpdateMonitorRequest Update Control Request
type UpdateMonitorRequest struct {
	Name               string                     `json:"name"`
	Type               models.MonitorType         `json:"type"`
	Target             string                     `json:"target"`
	Interval           int                        `json:"interval"`
	AssetGroupID       *string                    `json:"asset_group_id"`
	ScopeID            *string                    `json:"scope_id"`
	Options            *models.MonitorOptions     `json:"options"`
	NotificationConfig *models.NotificationConfig `json:"notification_config"`
}

// CreateMonitor Create a monitoring task
func (h *MonitorHandler) CreateMonitor(c *gin.Context) {
	var req CreateMonitorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// No Type Specified, Default Asdomain
	if req.Type == "" {
		req.Type = models.MonitorTypeDomain
	}
	// Convertinterval: The front is an hour., Backend storage as seconds
	intervalInSeconds := req.Interval * 3600

	// Sequenceoptions
	var optionsJSON string
	if req.Options != nil {
		optionsBytes, _ := json.Marshal(req.Options)
		optionsJSON = string(optionsBytes)
	}

	// Sequencenotification config
	var notificationJSON string
	if req.NotificationConfig != nil {
		notificationBytes, _ := json.Marshal(req.NotificationConfig)
		notificationJSON = string(notificationBytes)
	}

	var assetGroupID *string
	if groupID := strings.TrimSpace(req.AssetGroupID); groupID != "" {
		assetGroupID = &groupID
	}
	monitor := &models.Monitor{
		Name:               req.Name,
		Type:               req.Type,
		Target:             req.Target,
		Interval:           intervalInSeconds,
		AssetGroupID:       assetGroupID,
		ScopeID:            req.ScopeID,
		Options:            optionsJSON,
		NotificationConfig: notificationJSON,
		Status:             models.MonitorStatusActive,
		RunCount:           0,
	}

	if err := services.SaveMonitor(database.DB, monitor); err != nil {
		writeMonitorSaveError(c, err, "create")
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Monitor created successfully",
		"monitor": monitor,
	})
}

// ListMonitors List all surveillance tasks
func (h *MonitorHandler) ListMonitors(c *gin.Context) {
	status := c.Query("status")
	monitorType := c.Query("type")

	// Page Break Parameters
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "20")

	var pageInt, pageSizeInt int
	fmt.Sscanf(page, "%d", &pageInt)
	fmt.Sscanf(pageSize, "%d", &pageSizeInt)
	if pageInt < 1 {
		pageInt = 1
	}
	if pageSizeInt < 1 {
		pageSizeInt = 20
	}
	if pageSizeInt > 200 {
		pageSizeInt = 200
	}

	query := database.DB.Model(&models.Monitor{})

	if status != "" {
		query = query.Where("status = ?", status)
	}

	if monitorType != "" {
		query = query.Where("type = ?", monitorType)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count monitors"})
		return
	}

	var monitors []models.Monitor
	offset := (pageInt - 1) * pageSizeInt
	if err := query.Order("created_at DESC").
		Limit(pageSizeInt).
		Offset(offset).
		Find(&monitors).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch monitors"})
		return
	}

	totalPages := int((total + int64(pageSizeInt) - 1) / int64(pageSizeInt))

	c.JSON(http.StatusOK, gin.H{
		"monitors":    monitors,
		"total":       total,
		"page":        pageInt,
		"page_size":   pageSizeInt,
		"total_pages": totalPages,
	})
}

// GetMonitor Get the details of the surveillance.
func (h *MonitorHandler) GetMonitor(c *gin.Context) {
	monitorID := c.Param("id")

	var monitor models.Monitor
	if err := database.DB.First(&monitor, "id = ?", monitorID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Monitor not found"})
		return
	}

	c.JSON(http.StatusOK, monitor)
}

// UpdateMonitorStatus Update monitoring status
func (h *MonitorHandler) UpdateMonitorStatus(c *gin.Context) {
	monitorID := c.Param("id")

	var req struct {
		Status models.MonitorStatus `json:"status" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Status != models.MonitorStatusActive && req.Status != models.MonitorStatusPaused && req.Status != models.MonitorStatusStopped {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid monitor status", "allowed": []models.MonitorStatus{models.MonitorStatusActive, models.MonitorStatusPaused, models.MonitorStatusStopped}})
		return
	}

	result := database.DB.Model(&models.Monitor{}).Where("id = ?", monitorID).Update("status", req.Status)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update monitor status"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Monitor not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Monitor status updated successfully"})
}

// UpdateMonitor Update Control Task
func (h *MonitorHandler) UpdateMonitor(c *gin.Context) {
	monitorID := c.Param("id")

	var monitor models.Monitor
	if err := database.DB.First(&monitor, "id = ?", monitorID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Monitor not found"})
		return
	}

	var req UpdateMonitorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update Fields
	if req.Name != "" {
		monitor.Name = req.Name
	}
	if req.Type != "" {
		monitor.Type = req.Type
	}
	monitor.Target = strings.TrimSpace(req.Target)
	if req.AssetGroupID != nil {
		groupID := strings.TrimSpace(*req.AssetGroupID)
		if groupID == "" {
			monitor.AssetGroupID = nil
		} else {
			monitor.AssetGroupID = &groupID
		}
	}
	if req.ScopeID != nil {
		monitor.ScopeID = strings.TrimSpace(*req.ScopeID)
	}
	if !services.MonitorRequiresScanScope(monitor.Type) {
		monitor.ScopeID = ""
	}
	if req.Interval > 0 {
		monitor.Interval = req.Interval * 3600 // Convert to Second
	}
	// Updateoptions
	if req.Options != nil {
		optionsBytes, _ := json.Marshal(req.Options)
		monitor.Options = string(optionsBytes)
	}

	// Updatenotification config
	if req.NotificationConfig != nil {
		notificationBytes, _ := json.Marshal(req.NotificationConfig)
		monitor.NotificationConfig = string(notificationBytes)
	}

	if err := services.SaveMonitor(database.DB, &monitor); err != nil {
		writeMonitorSaveError(c, err, "update")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Monitor updated successfully",
		"monitor": monitor,
	})
}

func writeMonitorSaveError(c *gin.Context, err error, action string) {
	if services.IsMonitorInputError(err) {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	logger.Error("Monitor action=%s failed user_id=%q error=%v", action, c.GetString("user_id"), err)
	c.JSON(http.StatusInternalServerError, gin.H{"error": "Monitor operation failed"})
}

// DeleteMonitor Remove Monitor Task
func (h *MonitorHandler) DeleteMonitor(c *gin.Context) {
	monitorID := c.Param("id")

	// Delete monitoring and its results
	tx := database.DB.Begin()
	if tx.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start monitor deletion"})
		return
	}

	// Delete the monitoring results
	if err := tx.Delete(&models.MonitorResult{}, "monitor_id = ?", monitorID).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete monitor results"})
		return
	}

	// Remove Monitor
	result := tx.Delete(&models.Monitor{}, "id = ?", monitorID)
	if result.Error != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete monitor"})
		return
	}
	if result.RowsAffected == 0 {
		tx.Rollback()
		c.JSON(http.StatusNotFound, gin.H{"error": "Monitor not found"})
		return
	}
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit monitor deletion"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Monitor deleted successfully"})
}

// BatchDeleteMonitors Batch Delete Monitor Tasks
func (h *MonitorHandler) BatchDeleteMonitors(c *gin.Context) {
	var req struct {
		MonitorIDs []string `json:"monitor_ids" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(req.MonitorIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No monitor IDs provided"})
		return
	}

	tx := database.DB.Begin()
	if tx.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start monitor deletion"})
		return
	}

	// Delete all relevant outcomes
	if err := tx.Where("monitor_id IN ?", req.MonitorIDs).Delete(&models.MonitorResult{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete monitor results"})
		return
	}

	// Remove all surveillance
	if err := tx.Where("id IN ?", req.MonitorIDs).Delete(&models.Monitor{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete monitors"})
		return
	}

	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit monitor deletion"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Monitors deleted successfully",
		"count":   len(req.MonitorIDs),
	})
}

// ListMonitorResults List the results of the surveillance
func (h *MonitorHandler) ListMonitorResults(c *gin.Context) {
	monitorID := c.Param("id")

	var results []models.MonitorResult
	if err := database.DB.Where("monitor_id = ?", monitorID).
		Order("created_at DESC").
		Limit(100).
		Find(&results).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch monitor results"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"results": results})
}
