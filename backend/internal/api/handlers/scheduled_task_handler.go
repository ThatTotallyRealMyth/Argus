package handlers

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/logger"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/services"
	"gorm.io/gorm"
)

// ScheduledTaskHandler 计划任务处理器
type ScheduledTaskHandler struct {
	service *services.ScheduledTaskService
}

// NewScheduledTaskHandler 创建计划任务处理器
func NewScheduledTaskHandler(taskService *services.TaskService) *ScheduledTaskHandler {
	return &ScheduledTaskHandler{service: services.NewScheduledTaskService(taskService)}
}

// CreateScheduledTaskRequest 创建计划任务请求
type CreateScheduledTaskRequest struct {
	Name        string             `json:"name" binding:"required"`
	Description string             `json:"description"`
	CronType    string             `json:"cron_type" binding:"required"`
	CronExpr    string             `json:"cron_expr"`
	PolicyID    string             `json:"policy_id"` // 可选：关联的策略ID
	ScopeID     string             `json:"scope_id"`  // 可选：授权扫描范围；空值使用默认范围
	TaskOptions models.TaskOptions `json:"task_options" binding:"required"`
}

// ListScheduledTasks 列出所有计划任务
func (h *ScheduledTaskHandler) ListScheduledTasks(c *gin.Context) {
	cronType := c.Query("cron_type")
	isEnabled := c.Query("is_enabled")

	// 分页参数
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

	query := database.DB.Model(&models.ScheduledTask{})

	if cronType != "" && cronType != "all" {
		query = query.Where("cron_type = ?", cronType)
	}
	if isEnabled != "" && isEnabled != "all" {
		query = query.Where("is_enabled = ?", isEnabled == "true")
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count scheduled tasks"})
		return
	}

	var tasks []models.ScheduledTask
	offset := (pageInt - 1) * pageSizeInt
	if err := query.Order("created_at DESC").
		Limit(pageSizeInt).
		Offset(offset).
		Find(&tasks).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch scheduled tasks"})
		return
	}

	totalPages := int((total + int64(pageSizeInt) - 1) / int64(pageSizeInt))

	c.JSON(http.StatusOK, gin.H{
		"scheduled_tasks": tasks,
		"total":           total,
		"page":            pageInt,
		"page_size":       pageSizeInt,
		"total_pages":     totalPages,
	})
}

// GetScheduledTask 获取单个计划任务
func (h *ScheduledTaskHandler) GetScheduledTask(c *gin.Context) {
	id := c.Param("id")

	var task models.ScheduledTask
	if err := database.DB.First(&task, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Scheduled task not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get scheduled task"})
		return
	}

	c.JSON(http.StatusOK, task)
}

// CreateScheduledTask 创建计划任务
func (h *ScheduledTaskHandler) CreateScheduledTask(c *gin.Context) {
	var req CreateScheduledTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	scheduledTask, err := h.service.Create(scheduledTaskDefinition(req), c.GetString("user_id"))
	if err != nil {
		writeScheduledTaskError(c, err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":        "Scheduled task created successfully",
		"scheduled_task": scheduledTask,
	})
}

func writeScheduledTaskError(c *gin.Context, err error) {
	if errors.Is(err, services.ErrScheduledTaskNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": services.ErrScheduledTaskNotFound.Error()})
		return
	}
	if services.IsScheduledTaskInputError(err) {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	logger.Error("Scheduled task operation failed user_id=%q error=%v", c.GetString("user_id"), err)
	c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process scheduled task"})
}

// UpdateScheduledTask 更新计划任务
func (h *ScheduledTaskHandler) UpdateScheduledTask(c *gin.Context) {
	id := c.Param("id")

	var req CreateScheduledTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	task, err := h.service.Update(id, scheduledTaskDefinition(req))
	if err != nil {
		writeScheduledTaskError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":        "Scheduled task updated successfully",
		"scheduled_task": task,
	})
}

// DeleteScheduledTask 删除计划任务
func (h *ScheduledTaskHandler) DeleteScheduledTask(c *gin.Context) {
	if err := h.service.Delete(c.Param("id")); err != nil {
		writeScheduledTaskError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Scheduled task deleted successfully"})
}

// ToggleScheduledTaskStatus 切换计划任务状态
func (h *ScheduledTaskHandler) ToggleScheduledTaskStatus(c *gin.Context) {
	id := c.Param("id")

	var task models.ScheduledTask
	if err := database.DB.First(&task, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Scheduled task not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get scheduled task"})
		return
	}

	updatedTask, err := h.service.SetEnabled(task.ID, !task.IsEnabled)
	if err != nil {
		writeScheduledTaskError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Scheduled task status updated successfully",
		"is_enabled": updatedTask.IsEnabled,
	})
}

// RunScheduledTaskNow 立即运行计划任务
func (h *ScheduledTaskHandler) RunScheduledTaskNow(c *gin.Context) {
	task, err := h.service.RunNow(c.Param("id"))
	if err != nil {
		logger.Error("Scheduled task manual run failed user_id=%q scheduled_task_id=%q error=%v", c.GetString("user_id"), c.Param("id"), err)
		writeScheduledTaskError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Scheduled task executed successfully",
		"task":    task,
	})
}

// GetScheduledTaskLogs 获取计划任务执行日志
func (h *ScheduledTaskHandler) GetScheduledTaskLogs(c *gin.Context) {
	id := c.Param("id")

	var logs []models.ScheduledTaskLog
	if err := database.DB.Where("scheduled_task_id = ?", id).
		Order("created_at DESC").
		Limit(100).
		Find(&logs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch logs"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":  logs,
		"total": len(logs),
	})
}

// GetScheduledTaskStats 获取计划任务统计
func (h *ScheduledTaskHandler) GetScheduledTaskStats(c *gin.Context) {
	var stats struct {
		TotalTasks  int64 `gorm:"column:total_tasks"`
		ActiveTasks int64 `gorm:"column:active_tasks"`
		TotalRuns   int64 `gorm:"column:total_runs"`
		TotalFails  int64 `gorm:"column:total_fails"`
	}
	if err := database.DB.Model(&models.ScheduledTask{}).
		Select("COUNT(*) AS total_tasks, COALESCE(SUM(CASE WHEN is_enabled THEN 1 ELSE 0 END), 0) AS active_tasks, COALESCE(SUM(run_count), 0) AS total_runs, COALESCE(SUM(fail_count), 0) AS total_fails").
		Scan(&stats).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to calculate scheduled task statistics"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"total_tasks":  stats.TotalTasks,
		"active_tasks": stats.ActiveTasks,
		"total_runs":   stats.TotalRuns,
		"total_fails":  stats.TotalFails,
	})
}

// BatchDeleteScheduledTasks 批量删除计划任务
func (h *ScheduledTaskHandler) BatchDeleteScheduledTasks(c *gin.Context) {
	var req struct {
		IDs []string `json:"ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	count, err := h.service.DeleteMany(req.IDs)
	if err != nil {
		writeScheduledTaskError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Scheduled tasks deleted successfully",
		"count":   count,
	})
}

func scheduledTaskDefinition(req CreateScheduledTaskRequest) services.ScheduledTaskDefinition {
	return services.ScheduledTaskDefinition{
		Name: req.Name, Description: req.Description, CronType: req.CronType,
		CronExpr: req.CronExpr, PolicyID: req.PolicyID, ScopeID: req.ScopeID,
		TaskOptions: req.TaskOptions,
	}
}

// BatchToggleScheduledTasks 批量切换计划任务状态
func (h *ScheduledTaskHandler) BatchToggleScheduledTasks(c *gin.Context) {
	var req struct {
		IDs       []string `json:"ids" binding:"required"`
		IsEnabled bool     `json:"is_enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	count, err := h.service.SetEnabledMany(req.IDs, req.IsEnabled)
	if err != nil {
		writeScheduledTaskError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Scheduled tasks status updated successfully",
		"count":      count,
		"is_enabled": req.IsEnabled,
	})
}
