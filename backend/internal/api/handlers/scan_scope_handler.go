package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/logger"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/services"
	"gorm.io/gorm"
)

type ScanScopeHandler struct {
	service *services.ScanScopeService
}

func NewScanScopeHandler() *ScanScopeHandler {
	return &ScanScopeHandler{service: services.NewScanScopeService()}
}

type scanScopeRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	AllowRules  []string `json:"allow_rules"`
	DenyRules   []string `json:"deny_rules"`
	IsDefault   bool     `json:"is_default"`
}

func (h *ScanScopeHandler) List(c *gin.Context) {
	var scopes []models.ScanScope
	if err := database.DB.Order("is_default DESC, updated_at DESC, name ASC").Find(&scopes).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list scan scopes"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"scopes": scopes, "total": len(scopes)})
}

func (h *ScanScopeHandler) Create(c *gin.Context) {
	var request scanScopeRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan scope request"})
		return
	}
	var count int64
	if err := database.DB.Model(&models.ScanScope{}).Count(&count).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create scan scope"})
		return
	}
	scope := models.ScanScope{
		Name: strings.TrimSpace(request.Name), Description: request.Description, AllowRules: request.AllowRules,
		DenyRules: request.DenyRules, IsDefault: request.IsDefault || count == 0, CreatedBy: c.GetString("user_id"),
	}
	if err := services.SaveScanScope(database.DB, &scope); err != nil {
		handleScanScopeError(c, err, "create")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"scope": scope})
}

func (h *ScanScopeHandler) Update(c *gin.Context) {
	var request scanScopeRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan scope request"})
		return
	}
	scope := models.ScanScope{
		ID: c.Param("id"), Name: strings.TrimSpace(request.Name), Description: request.Description,
		AllowRules: request.AllowRules, DenyRules: request.DenyRules, IsDefault: request.IsDefault,
	}
	if err := services.SaveScanScope(database.DB, &scope); err != nil {
		handleScanScopeError(c, err, "update")
		return
	}
	if err := database.DB.First(&scope, "id = ?", scope.ID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reload scan scope"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"scope": scope})
}

func (h *ScanScopeHandler) Delete(c *gin.Context) {
	if err := services.DeleteScanScope(database.DB, c.Param("id")); err != nil {
		if services.IsScanScopeInputError(err) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		logger.Error("Scan scope delete failed id=%q error=%v", c.Param("id"), err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete scan scope"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Scan scope deleted"})
}

func (h *ScanScopeHandler) SetDefault(c *gin.Context) {
	if err := services.SetDefaultScanScope(database.DB, c.Param("id")); err != nil {
		handleScanScopeError(c, err, "set_default")
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Default scan scope updated"})
}

func (h *ScanScopeHandler) Validate(c *gin.Context) {
	var request struct {
		ScopeID    string   `json:"scope_id"`
		Name       string   `json:"name"`
		AllowRules []string `json:"allow_rules"`
		DenyRules  []string `json:"deny_rules"`
		Target     string   `json:"target"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan scope validation request"})
		return
	}
	var result *services.ScanScopeValidation
	var err error
	if strings.TrimSpace(request.ScopeID) != "" {
		result, err = h.service.Validate(request.ScopeID, request.Target)
	} else if len(request.AllowRules) > 0 || len(request.DenyRules) > 0 {
		result, err = services.ValidateScanScopePreview(models.ScanScope{Name: request.Name, AllowRules: request.AllowRules, DenyRules: request.DenyRules}, request.Target)
	} else {
		result, err = h.service.Validate("", request.Target)
	}
	if err != nil {
		handleScanScopeError(c, err, "validate")
		return
	}
	c.JSON(http.StatusOK, result)
}

func handleScanScopeError(c *gin.Context, err error, action string) {
	if services.IsScanScopeInputError(err) || errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	logger.Error("Scan scope action=%s failed error=%v", action, err)
	c.JSON(http.StatusInternalServerError, gin.H{"error": "Scan scope operation failed"})
}
