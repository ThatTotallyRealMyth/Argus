package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/logger"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/scanner"
	"gorm.io/gorm"
)

// GitHubMonitorHandler GitHubMonitor processor
type GitHubMonitorHandler struct{}

// NewGitHubMonitorHandler CreateGitHubMonitor processor
func NewGitHubMonitorHandler() *GitHubMonitorHandler {
	return &GitHubMonitorHandler{}
}

// CreateGitHubMonitorRequest CreateGitHubSurveillance request
type CreateGitHubMonitorRequest struct {
	Name       string `json:"name" binding:"required"`
	Keywords   string `json:"keywords" binding:"required"`
	SearchType string `json:"search_type" binding:"required"`
	Language   string `json:"language"`
	User       string `json:"user"`
	Repository string `json:"repository"`
	Extension  string `json:"extension"`
	Interval   int    `json:"interval" binding:"required,min=600"` // Minimum10min
}

// ListGitHubMonitors List allGitHubSurveillance
func (h *GitHubMonitorHandler) ListGitHubMonitors(c *gin.Context) {
	searchType := c.Query("search_type")
	isEnabled := c.Query("is_enabled")

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

	query := database.DB.Model(&models.GitHubMonitor{})

	if searchType != "" {
		query = query.Where("search_type = ?", searchType)
	}
	if isEnabled != "" {
		query = query.Where("is_enabled = ?", isEnabled == "true")
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count GitHub monitors"})
		return
	}

	var monitors []models.GitHubMonitor
	offset := (pageInt - 1) * pageSizeInt
	if err := query.Order("created_at DESC").
		Limit(pageSizeInt).
		Offset(offset).
		Find(&monitors).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch GitHub monitors"})
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

// GetGitHubMonitor Fetching individualGitHubSurveillance
func (h *GitHubMonitorHandler) GetGitHubMonitor(c *gin.Context) {
	id := c.Param("id")

	var monitor models.GitHubMonitor
	if err := database.DB.First(&monitor, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "GitHub monitor not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get GitHub monitor"})
		return
	}

	c.JSON(http.StatusOK, monitor)
}

// CreateGitHubMonitor CreateGitHubSurveillance
func (h *GitHubMonitorHandler) CreateGitHubMonitor(c *gin.Context) {
	var req CreateGitHubMonitorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Authenticate Search Type
	validSearchTypes := map[string]bool{
		"code": true, "repository": true, "issue": true,
	}
	if !validSearchTypes[req.SearchType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid search_type"})
		return
	}

	nextRun := time.Now().Add(time.Duration(req.Interval) * time.Second)

	monitor := &models.GitHubMonitor{
		Name:       req.Name,
		Keywords:   req.Keywords,
		SearchType: req.SearchType,
		Language:   req.Language,
		User:       req.User,
		Repository: req.Repository,
		Extension:  req.Extension,
		IsEnabled:  true,
		Interval:   req.Interval,
		NextRunAt:  &nextRun,
		RunCount:   0,
	}

	if err := database.DB.Create(monitor).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create GitHub monitor"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "GitHub monitor created successfully",
		"monitor": monitor,
	})
}

// UpdateGitHubMonitor UpdateGitHubSurveillance
func (h *GitHubMonitorHandler) UpdateGitHubMonitor(c *gin.Context) {
	id := c.Param("id")

	var monitor models.GitHubMonitor
	if err := database.DB.First(&monitor, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "GitHub monitor not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get GitHub monitor"})
		return
	}

	var req CreateGitHubMonitorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Authenticate Search Type
	validSearchTypes := map[string]bool{
		"code": true, "repository": true, "issue": true,
	}
	if !validSearchTypes[req.SearchType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid search_type"})
		return
	}

	// Update Fields
	monitor.Name = req.Name
	monitor.Keywords = req.Keywords
	monitor.SearchType = req.SearchType
	monitor.Language = req.Language
	monitor.User = req.User
	monitor.Repository = req.Repository
	monitor.Extension = req.Extension
	monitor.Interval = req.Interval

	if err := database.DB.Save(&monitor).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update GitHub monitor"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "GitHub monitor updated successfully",
		"monitor": monitor,
	})
}

// DeleteGitHubMonitor DeleteGitHubSurveillance
func (h *GitHubMonitorHandler) DeleteGitHubMonitor(c *gin.Context) {
	id := c.Param("id")

	if err := database.DB.Delete(&models.GitHubMonitor{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete GitHub monitor"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "GitHub monitor deleted successfully"})
}

// ToggleGitHubMonitorStatus ToggleGitHubMonitor Status
func (h *GitHubMonitorHandler) ToggleGitHubMonitorStatus(c *gin.Context) {
	id := c.Param("id")

	var monitor models.GitHubMonitor
	if err := database.DB.First(&monitor, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "GitHub monitor not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get GitHub monitor"})
		return
	}

	monitor.IsEnabled = !monitor.IsEnabled
	if err := database.DB.Save(&monitor).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update GitHub monitor status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "GitHub monitor status updated successfully",
		"is_enabled": monitor.IsEnabled,
	})
}

// ListGitHubMonitorResults List the results of the surveillance
func (h *GitHubMonitorHandler) ListGitHubMonitorResults(c *gin.Context) {
	monitorID := c.Param("id")
	isRead := c.Query("is_read")

	query := database.DB.Model(&models.GitHubMonitorResult{}).Where("monitor_id = ?", monitorID)

	if isRead != "" {
		query = query.Where("is_read = ?", isRead == "true")
	}

	var results []models.GitHubMonitorResult
	if err := query.Order("created_at DESC").Limit(100).Find(&results).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch results"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"results": results,
		"total":   len(results),
	})
}

// MarkResultAsRead Mark result as read
func (h *GitHubMonitorHandler) MarkResultAsRead(c *gin.Context) {
	resultID := c.Param("result_id")

	if err := database.DB.Model(&models.GitHubMonitorResult{}).
		Where("id = ?", resultID).
		Update("is_read", true).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to mark as read"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Result marked as read"})
}

// GetGitHubMonitorStats FetchGitHubMonitoring statistics
func (h *GitHubMonitorHandler) GetGitHubMonitorStats(c *gin.Context) {
	var totalMonitors int64
	var activeMonitors int64
	var totalResults int64
	var unreadResults int64
	counts := []*gorm.DB{
		database.DB.Model(&models.GitHubMonitor{}).Count(&totalMonitors),
		database.DB.Model(&models.GitHubMonitor{}).Where("is_enabled = ?", true).Count(&activeMonitors),
		database.DB.Model(&models.GitHubMonitorResult{}).Count(&totalResults),
		database.DB.Model(&models.GitHubMonitorResult{}).Where("is_read = ?", false).Count(&unreadResults),
	}
	for _, result := range counts {
		if result.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load GitHub monitor statistics"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_monitors":  totalMonitors,
		"active_monitors": activeMonitors,
		"total_results":   totalResults,
		"unread_results":  unreadResults,
	})
}

// RunGitHubMonitor Run ManuallyGitHubSurveillance
func (h *GitHubMonitorHandler) RunGitHubMonitor(c *gin.Context) {
	id := c.Param("id")

	var monitor models.GitHubMonitor
	if err := database.DB.First(&monitor, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "GitHub monitor not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get GitHub monitor"})
		return
	}

	keywords := make([]string, 0)
	for _, keyword := range strings.Split(monitor.Keywords, ",") {
		keyword = strings.TrimSpace(keyword)
		if keyword != "" {
			keywords = append(keywords, keyword)
		}
	}
	if len(keywords) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "monitor has no searchable keywords"})
		return
	}
	githubMonitor, err := scanner.NewGithubMonitorFromSettings(database.DB)
	if err != nil {
		if errors.Is(err, scanner.ErrGithubTokenNotConfigured) || errors.Is(err, scanner.ErrGithubIntegrationDisabled) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		logger.Error("GitHub monitor credential load failed monitor_id=%q error=%v", monitor.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load GitHub credentials"})
		return
	}
	created := 0
	for _, keyword := range keywords {
		query := keyword
		if monitor.Language != "" {
			query += " language:" + monitor.Language
		}
		if monitor.User != "" {
			query += " user:" + monitor.User
		}
		if monitor.Repository != "" {
			query += " repo:" + monitor.Repository
		}
		if monitor.Extension != "" {
			query += " extension:" + strings.TrimPrefix(monitor.Extension, ".")
		}
		result, err := githubMonitor.SearchKeyword(query, 30)
		if err != nil {
			logger.Error("GitHub monitor search failed monitor_id=%q error=%v", monitor.ID, err)
			c.JSON(http.StatusBadGateway, gin.H{"error": "GitHub search failed"})
			return
		}
		candidates := make([]scanner.GithubSearchItem, 0, len(result.Items))
		for _, item := range result.Items {
			var exists int64
			if err := database.DB.Model(&models.GitHubMonitorResult{}).Where("monitor_id = ? AND url = ?", monitor.ID, item.HTMLURL).Count(&exists).Error; err != nil {
				logger.Error("GitHub monitor deduplication failed monitor_id=%q error=%v", monitor.ID, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to inspect existing GitHub monitor results"})
				return
			}
			if exists > 0 {
				continue
			}
			candidates = append(candidates, item)
		}
		for _, inspected := range githubMonitor.InspectSearchItems(candidates, 6) {
			if inspected.Err != nil || len(inspected.Leaks) == 0 {
				continue
			}
			item := inspected.Item
			entry := &models.GitHubMonitorResult{
				MonitorID:   monitor.ID,
				Title:       item.Name,
				URL:         item.HTMLURL,
				Repository:  item.Repository.FullName,
				FilePath:    item.Path,
				Description: item.Repository.Description,
				Language:    monitor.Language,
				MatchedText: scanner.GithubLeakSummary(inspected.Leaks),
			}
			if err := database.DB.Create(entry).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save GitHub result"})
				return
			}
			created++
		}
	}

	now := time.Now()
	nextRun := now.Add(time.Duration(monitor.Interval) * time.Second)
	monitor.LastRunAt, monitor.NextRunAt = &now, &nextRun
	monitor.RunCount++
	if err := database.DB.Save(&monitor).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update monitor"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "GitHub monitor executed successfully",
		"monitor":     monitor,
		"new_results": created,
	})
}
