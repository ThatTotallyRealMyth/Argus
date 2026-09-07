package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/reconmaster/backend/internal/auth"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/middleware"
	"github.com/reconmaster/backend/internal/models"
	"gorm.io/gorm"
)

// AuthHandler 认证处理器
type AuthHandler struct{}

// NewAuthHandler 创建认证处理器
func NewAuthHandler() *AuthHandler {
	return &AuthHandler{}
}

// Login 用户登录
func (h *AuthHandler) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}

	// 查找用户
	var user models.User
	if err := database.DB.Where("username = ?", req.Username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "登录服务暂不可用"})
		return
	}

	// 检查账号状态
	if !user.IsActive() {
		c.JSON(http.StatusForbidden, gin.H{"error": "账号已被禁用"})
		return
	}

	// 验证密码
	if !user.CheckPassword(req.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	// 生成token
	token, err := auth.GenerateToken(user.ID, user.Username, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成令牌失败"})
		return
	}

	// Persist the login timestamp and session atomically so a returned token is
	// always backed by a session row.
	now := time.Now()
	user.LastLogin = &now
	session := models.UserSession{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Token:     auth.HashToken(token),
		IP:        c.ClientIP(),
		UserAgent: c.GetHeader("User-Agent"),
		ExpiresAt: time.Now().Add(auth.TokenExpiration),
	}
	tx := database.DB.Begin()
	if tx.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建会话失败"})
		return
	}
	loginUpdate := tx.Model(&models.User{}).Where("id = ?", user.ID).Update("last_login", now)
	if loginUpdate.Error != nil || loginUpdate.RowsAffected != 1 {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新登录状态失败"})
		return
	}
	if err := tx.Create(&session).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建会话失败"})
		return
	}
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "登录提交失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user":  user,
	})
}

// Register 用户注册
func (h *AuthHandler) Register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}

	// 检查用户名是否已存在
	var count int64
	if err := database.DB.Model(&models.User{}).Where("username = ?", req.Username).Count(&count).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "检查用户名失败"})
		return
	}
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户名已存在"})
		return
	}

	// 检查邮箱是否已存在
	if err := database.DB.Model(&models.User{}).Where("email = ?", req.Email).Count(&count).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "检查邮箱失败"})
		return
	}
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "邮箱已被使用"})
		return
	}

	// 创建用户
	user := models.User{
		ID:       uuid.New().String(),
		Username: req.Username,
		Email:    req.Email,
		Nickname: req.Nickname,
		Role:     "user",
		Status:   "active",
	}

	if err := user.SetPassword(req.Password); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "密码加密失败"})
		return
	}

	// 生成token
	token, err := auth.GenerateToken(user.ID, user.Username, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成令牌失败"})
		return
	}
	session := models.UserSession{
		ID: uuid.New().String(), UserID: user.ID, Token: auth.HashToken(token),
		IP: c.ClientIP(), UserAgent: c.GetHeader("User-Agent"),
		ExpiresAt: time.Now().Add(auth.TokenExpiration),
	}
	tx := database.DB.Begin()
	if tx.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建用户失败"})
		return
	}
	if err := tx.Create(&user).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建用户失败"})
		return
	}
	if err := tx.Create(&session).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建会话失败"})
		return
	}
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "注册提交失败"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"token": token,
		"user":  user,
	})
}

// GetCurrentUser 获取当前用户信息
func (h *AuthHandler) GetCurrentUser(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)

	var user models.User
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		writeUserLookupError(c, err)
		return
	}

	c.JSON(http.StatusOK, user)
}

// UpdateProfile 更新用户资料
func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)

	var req models.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}

	var user models.User
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		writeUserLookupError(c, err)
		return
	}

	// 更新字段
	if req.Nickname != "" {
		user.Nickname = req.Nickname
	}
	if req.Email != "" {
		user.Email = req.Email
	}
	if req.Avatar != "" {
		user.Avatar = req.Avatar
	}

	if err := database.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新失败"})
		return
	}
	c.JSON(http.StatusOK, user)
}

// UpdatePassword 修改密码
func (h *AuthHandler) UpdatePassword(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)

	var req models.UpdatePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}

	var user models.User
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		writeUserLookupError(c, err)
		return
	}

	// 验证旧密码
	if !user.CheckPassword(req.OldPassword) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "原密码错误"})
		return
	}

	// 设置新密码
	if err := user.SetPassword(req.NewPassword); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "密码加密失败"})
		return
	}

	// 清除强制修改密码标识
	user.MustChangePassword = false

	tx := database.DB.Begin()
	if tx.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法开始密码更新事务"})
		return
	}
	if err := tx.Save(&user).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新失败"})
		return
	}
	if err := tx.Where("user_id = ?", user.ID).Delete(&models.UserSession{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "密码更新失败"})
		return
	}
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "密码更新提交失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "密码修改成功"})
}

func writeUserLookupError(c *gin.Context, err error) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": "查询用户失败"})
}

// Logout 用户登出
func (h *AuthHandler) Logout(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 {
			token := parts[1]
			// 删除会话
			if err := database.DB.Where("token = ?", auth.HashToken(token)).Delete(&models.UserSession{}).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "登出失败"})
				return
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "登出成功"})
}

// ListUsers 用户列表（管理员）
func (h *AuthHandler) ListUsers(c *gin.Context) {
	var users []models.User

	query := database.DB.Model(&models.User{})

	page, pageSize := parsePagination(c, 20, 100)

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询用户数量失败"})
		return
	}

	offset := (page - 1) * pageSize
	if err := query.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询用户失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"users": users,
		"total": total,
		"page":  page, "page_size": pageSize,
		"total_pages": int((total + int64(pageSize) - 1) / int64(pageSize)),
	})
}

// UpdateUserStatus 更新用户状态（管理员）
func (h *AuthHandler) UpdateUserStatus(c *gin.Context) {
	userID := c.Param("id")
	status := c.Query("status")

	if status != "active" && status != "disabled" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的状态"})
		return
	}

	tx := database.DB.Begin()
	if tx.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新失败"})
		return
	}
	result := tx.Model(&models.User{}).Where("id = ?", userID).Update("status", status)
	if result.Error != nil || result.RowsAffected != 1 {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新失败"})
		return
	}
	if status == "disabled" {
		if err := tx.Where("user_id = ?", userID).Delete(&models.UserSession{}).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "撤销会话失败"})
			return
		}
	}
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新提交失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}
