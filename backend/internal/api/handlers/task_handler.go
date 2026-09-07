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

// CreateTaskRequest 创建任务请求
type CreateTaskRequest struct {
	Name     string             `json:"name" binding:"required"`
	Target   string             `json:"target" binding:"required"`
	PolicyID string             `json:"policy_id"` // 可选：关联的策略ID
	ScopeID  string             `json:"scope_id"`  // 可选：授权扫描范围；空值使用默认范围
	Options  models.TaskOptions `json:"options"`
	StartNow bool               `json:"start_now"`
}

// TaskHandler 任务处理器
type TaskHandler struct {
	taskService *services.TaskService
}

// NewTaskHandler 创建任务处理器
func NewTaskHandler(taskService *services.TaskService) *TaskHandler {
	return &TaskHandler{
		taskService: taskService,
	}
}

// CreateTask 创建新任务
func (h *TaskHandler) CreateTask(c *gin.Context) {
	var req CreateTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var task *models.Task
	var err error
	origin := models.TaskOrigin{Source: models.TaskTriggerManual, ActorID: c.GetString("user_id")}
	if req.StartNow {
		task, err = h.taskService.CreateQueuedTaskInScopeWithOrigin(req.Name, req.Target, req.PolicyID, req.ScopeID, req.Options, origin)
	} else {
		task, err = h.taskService.CreateTaskInScopeWithOrigin(req.Name, req.Target, req.PolicyID, req.ScopeID, req.Options, origin)
	}
	if err != nil {
		if services.IsTaskInputError(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		logger.Error("Task create failed user_id=%q error=%v", c.GetString("user_id"), err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create task"})
		return
	}

	message := "Task created successfully. Please start it manually."
	if req.StartNow {
		message = "Task created and queued successfully."
	}
	c.JSON(http.StatusCreated, gin.H{"message": message, "task": task})
}

// policyConfigToTaskOptions 将策略配置转换为任务选项
func policyConfigToTaskOptions(policyConfig models.PolicyConfig, baseOptions models.TaskOptions) models.TaskOptions {
	return services.ApplyPolicyConfig(policyConfig, baseOptions)
}

// GetTask 获取任务详情
func (h *TaskHandler) GetTask(c *gin.Context) {
	taskID := c.Param("id")

	var task models.Task
	if err := database.DB.First(&task, "id = ?", taskID).Error; err != nil {
		writeTaskLookupError(c, err)
		return
	}

	c.JSON(http.StatusOK, task)
}

// GetTaskLogs returns persisted scanner output for a task.
func (h *TaskHandler) GetTaskLogs(c *gin.Context) {
	taskID := c.Param("id")
	page, pageSize := parsePagination(c, 100, 500)
	query := database.DB.Model(&models.TaskLog{}).Where("task_id = ?", taskID)
	if level := c.Query("level"); level != "" {
		query = query.Where("level = ?", level)
	}
	if search := c.Query("search"); search != "" {
		query = query.Where("message ILIKE ?", "%"+search+"%")
	}
	var ok bool
	query, ok = applyAdvancedSearch(c, query,
		map[string]string{"level": "level", "message": "message"},
		[]string{"message", "level"})
	if !ok {
		return
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count task logs"})
		return
	}
	var logs []models.TaskLog
	if err := query.Order("created_at DESC, sequence DESC, id DESC").Limit(pageSize).Offset((page - 1) * pageSize).Find(&logs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch task logs"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"logs": logs, "total": total, "page": page, "page_size": pageSize,
		"total_pages": int((total + int64(pageSize) - 1) / int64(pageSize)),
	})
}

// ListTasks 列出所有任务
func (h *TaskHandler) ListTasks(c *gin.Context) {
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "20")
	status := c.Query("status")
	sortBy := c.Query("sort_by")
	sortOrder := c.Query("sort_order")

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

	query := database.DB.Model(&models.Task{})

	if status != "" && status != "all" {
		query = query.Where("status = ?", status)
	}
	var ok bool
	query, ok = applyAdvancedSearch(c, query,
		map[string]string{"name": "name", "target": "target", "status": "status", "error": "error_msg"},
		[]string{"name", "target", "status", "error_msg"})
	if !ok {
		return
	}
	allowedSorts := map[string]bool{"name": true, "target": true, "status": true, "progress": true, "created_at": true, "updated_at": true}
	if !allowedSorts[sortBy] {
		sortBy = "created_at"
	}
	if sortOrder != "asc" {
		sortOrder = "desc"
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count tasks"})
		return
	}

	var tasks []models.Task
	offset := (pageInt - 1) * pageSizeInt
	if err := query.Order(sortBy + " " + sortOrder).
		Limit(pageSizeInt).
		Offset(offset).
		Find(&tasks).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch tasks"})
		return
	}

	totalPages := int((total + int64(pageSizeInt) - 1) / int64(pageSizeInt))

	c.JSON(http.StatusOK, gin.H{
		"tasks":       tasks,
		"total":       total,
		"page":        pageInt,
		"page_size":   pageSizeInt,
		"total_pages": totalPages,
	})
}

// DeleteTask 删除任务及其所有相关资产数据
func (h *TaskHandler) DeleteTask(c *gin.Context) {
	taskID := c.Param("id")
	if err := h.taskService.DeleteTask(taskID); err != nil {
		if services.IsTaskInputError(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		logger.Error("Task deletion failed user_id=%q task_id=%q error=%v", c.GetString("user_id"), taskID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete task"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Task and all related assets deleted successfully"})
}

// CancelTask 取消任务
func (h *TaskHandler) CancelTask(c *gin.Context) {
	taskID := c.Param("id")

	if err := h.taskService.CancelTask(taskID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Task cancelled successfully"})
}

// StartTask 手动启动任务
func (h *TaskHandler) StartTask(c *gin.Context) {
	taskID := c.Param("id")

	// 检查任务是否存在
	var task models.Task
	if err := database.DB.First(&task, "id = ?", taskID).Error; err != nil {
		writeTaskLookupError(c, err)
		return
	}

	// 只允许启动 pending 状态的任务
	if task.Status != models.TaskStatusPending {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Cannot start task with status: %s. Only pending tasks can be started.", task.Status),
		})
		return
	}

	if err := h.taskService.StartTask(task.ID); err != nil {
		if services.IsTaskInputError(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		logger.Error("Task start failed user_id=%q task_id=%q error=%v", c.GetString("user_id"), task.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start task"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Task queued successfully",
		"task_id": taskID,
	})
}

func writeTaskLookupError(c *gin.Context, err error) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load task"})
}

// RetryTask creates and queues a fresh task from an existing terminal task.
func (h *TaskHandler) RetryTask(c *gin.Context) {
	task, err := h.taskService.RetryTask(c.Param("id"))
	if err != nil {
		if services.IsTaskInputError(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		logger.Error("Task retry failed user_id=%q task_id=%q error=%v", c.GetString("user_id"), c.Param("id"), err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retry task"})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"message":        "Task retry queued successfully",
		"source_task_id": c.Param("id"),
		"task":           task,
	})
}

// GetTaskStats 获取任务统计信息
func (h *TaskHandler) GetTaskStats(c *gin.Context) {
	var stats struct {
		Total     int64 `json:"total"`
		Pending   int64 `json:"pending"`
		Queued    int64 `json:"queued"`
		Running   int64 `json:"running"`
		Completed int64 `json:"completed"`
		Failed    int64 `json:"failed"`
	}

	var rows []struct {
		Status models.TaskStatus
		Count  int64
	}
	if err := database.DB.Model(&models.Task{}).Select("status, COUNT(*) AS count").Group("status").Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to calculate task statistics"})
		return
	}
	for _, row := range rows {
		switch row.Status {
		case models.TaskStatusPending:
			stats.Pending = row.Count
		case models.TaskStatusQueued:
			stats.Queued = row.Count
		case models.TaskStatusRunning:
			stats.Running = row.Count
		case models.TaskStatusCompleted:
			stats.Completed = row.Count
		case models.TaskStatusFailed:
			stats.Failed = row.Count
		}
		stats.Total += row.Count
	}

	c.JSON(http.StatusOK, stats)
}

// BatchDeleteTasks 批量删除任务
func (h *TaskHandler) BatchDeleteTasks(c *gin.Context) {
	var req struct {
		TaskIDs []string `json:"task_ids" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if len(req.TaskIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No task IDs provided"})
		return
	}
	if len(req.TaskIDs) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At most 100 tasks can be deleted at once"})
		return
	}

	// 批量处理任务删除
	successCount := 0
	failedTasks := []string{}

	seen := make(map[string]bool)
	for _, taskID := range req.TaskIDs {
		if taskID == "" || seen[taskID] {
			continue
		}
		seen[taskID] = true
		if err := h.taskService.DeleteTask(taskID); err != nil {
			failedTasks = append(failedTasks, taskID)
			continue
		}
		successCount++
	}

	c.JSON(http.StatusOK, gin.H{
		"message":       fmt.Sprintf("Successfully deleted %d/%d tasks", successCount, len(req.TaskIDs)),
		"success_count": successCount,
		"failed_tasks":  failedTasks,
	})
}
