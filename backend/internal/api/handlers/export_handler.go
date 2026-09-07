package handlers

import (
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/export"
	"github.com/reconmaster/backend/internal/models"
	"gorm.io/gorm"
)

// ExportHandler 导出处理器
type ExportHandler struct {
	exporter *export.Exporter
}

// NewExportHandler 创建导出处理器
func NewExportHandler() *ExportHandler {
	exp := export.NewExporter("./exports")
	// 启动定期清理：每6小时清理超过24小时的导出文件
	exp.StartPeriodicCleanup(6*time.Hour, 24*time.Hour)
	return &ExportHandler{
		exporter: exp,
	}
}

// ExportTask 导出任务数据
func (h *ExportHandler) ExportTask(c *gin.Context) {
	taskID := c.Param("id")
	format := c.DefaultQuery("format", "json") // json, csv, html

	// 获取任务
	var task models.Task
	if err := database.DB.First(&task, "id = ?", taskID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load task"})
		return
	}

	var filename string
	var err error

	switch format {
	case "json":
		exportData, loadErr := loadTaskExportData(taskID, &task, true)
		if loadErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load export data"})
			return
		}
		filename, err = h.exporter.ExportToJSON(exportData)
	case "csv":
		filename, err = h.exportTaskCSV(c.DefaultQuery("type", "domains"), taskID)
		if errors.Is(err, errInvalidExportType) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid export type"})
			return
		}
	case "html":
		exportData, loadErr := loadTaskExportData(taskID, &task, false)
		if loadErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load export data"})
			return
		}
		filename, err = h.exporter.GenerateReport(exportData)
	case "all":
		exportData, loadErr := loadTaskExportData(taskID, &task, true)
		if loadErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load export data"})
			return
		}
		files, exportErr := h.exporter.ExportAll(exportData)
		if exportErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Export failed"})
			return
		}
		for key, value := range files {
			files[key] = filepath.Base(value)
		}
		c.JSON(http.StatusOK, gin.H{
			"message": "Export completed",
			"files":   files,
		})
		return
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid format"})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Export failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "Export completed",
		"filename": filepath.Base(filename),
	})
}

var errInvalidExportType = errors.New("invalid export type")

func (h *ExportHandler) exportTaskCSV(exportType, taskID string) (string, error) {
	switch exportType {
	case "domains":
		var items []models.Domain
		if err := database.DB.Where("task_id = ?", taskID).Find(&items).Error; err != nil {
			return "", err
		}
		return h.exporter.ExportDomainsToCSV(items, taskID)
	case "ips":
		var items []models.IP
		if err := database.DB.Where("task_id = ?", taskID).Find(&items).Error; err != nil {
			return "", err
		}
		return h.exporter.ExportIPsToCSV(items, taskID)
	case "ports":
		var items []models.Port
		if err := database.DB.Where("task_id = ?", taskID).Find(&items).Error; err != nil {
			return "", err
		}
		return h.exporter.ExportPortsToCSV(items, taskID)
	case "sites":
		var items []models.Site
		if err := database.DB.Where("task_id = ?", taskID).Find(&items).Error; err != nil {
			return "", err
		}
		return h.exporter.ExportSitesToCSV(items, taskID)
	case "urls":
		var items []models.CrawlerResult
		if err := database.DB.Where("task_id = ?", taskID).Find(&items).Error; err != nil {
			return "", err
		}
		return h.exporter.ExportURLsToCSV(items, taskID)
	case "http":
		var items []models.HTTPTransaction
		if err := database.DB.Select(
			"url", "method", "response_status_code", "response_content_type",
			"response_content_length", "response_time_ms", "source", "created_at",
		).Where("task_id = ?", taskID).Find(&items).Error; err != nil {
			return "", err
		}
		return h.exporter.ExportHTTPTransactionsToCSV(items, taskID)
	case "vulnerabilities":
		var items []models.Vulnerability
		if err := database.DB.Where("task_id = ?", taskID).Find(&items).Error; err != nil {
			return "", err
		}
		return h.exporter.ExportVulnerabilitiesToCSV(items, taskID)
	default:
		return "", errInvalidExportType
	}
}

func loadTaskExportData(taskID string, task *models.Task, includeHTTPBodies bool) (*export.ExportData, error) {
	data := &export.ExportData{Task: task, ExportTime: time.Now()}
	queries := []struct {
		value any
		into  any
	}{
		{&models.Domain{}, &data.Domains},
		{&models.IP{}, &data.IPs},
		{&models.Port{}, &data.Ports},
		{&models.Site{}, &data.Sites},
		{&models.CrawlerResult{}, &data.URLs},
		{&models.Vulnerability{}, &data.Vulnerabilities},
	}
	for _, query := range queries {
		if err := database.DB.Model(query.value).Where("task_id = ?", taskID).Find(query.into).Error; err != nil {
			return nil, err
		}
	}
	if err := database.DB.Where("task_id = ?", taskID).
		Order("created_at ASC, sequence ASC, id ASC").
		Find(&data.TaskLogs).Error; err != nil {
		return nil, err
	}
	httpQuery := database.DB.Where("task_id = ?", taskID)
	if !includeHTTPBodies {
		httpQuery = httpQuery.Select(
			"id", "task_id", "crawler_result_id", "url", "method", "source",
			"response_status_code", "response_content_type", "response_content_length",
			"response_body_stored", "response_body_truncated", "response_body_sha256",
			"response_time_ms", "created_at",
		)
	}
	if err := httpQuery.Find(&data.HTTPTransactions).Error; err != nil {
		return nil, err
	}
	return data, nil
}

// DownloadExport 下载导出文件
func (h *ExportHandler) DownloadExport(c *gin.Context) {
	filename := c.Query("file")
	if filename == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Filename required"})
		return
	}
	if !validExportFilename(filename) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid filename"})
		return
	}
	filePath := filepath.Join("./exports", filename)
	c.Header("Cache-Control", "no-store")
	c.FileAttachment(filePath, filename)
}

func validExportFilename(filename string) bool {
	if filename == "" || filename != filepath.Base(filename) || containsPathTraversal(filename) {
		return false
	}
	extension := strings.ToLower(filepath.Ext(filename))
	if strings.TrimSuffix(filename, extension) == "" {
		return false
	}
	switch extension {
	case ".json", ".csv", ".html":
		return true
	default:
		return false
	}
}

// containsPathTraversal 检查路径遍历
func containsPathTraversal(path string) bool {
	// 空路径
	if len(path) == 0 {
		return true
	}
	// 绝对路径
	if path[0] == '/' || path[0] == '\\' {
		return true
	}
	if strings.ContainsAny(path, `/\\`) {
		return true
	}
	// 包含路径遍历序列
	if strings.Contains(path, "..") {
		return true
	}
	// 包含空字节
	if strings.ContainsRune(path, 0) {
		return true
	}
	// 包含 URL 编码的路径遍历
	if strings.Contains(strings.ToLower(path), "%2e%2e") ||
		strings.Contains(strings.ToLower(path), "%2f") ||
		strings.Contains(strings.ToLower(path), "%5c") {
		return true
	}
	return false
}
