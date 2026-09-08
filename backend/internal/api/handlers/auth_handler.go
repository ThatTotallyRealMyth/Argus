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

// AuthHandler Authentication Processor
type AuthHandler struct{}

// NewAuthHandler Create Authentication Processor
func NewAuthHandler() *AuthHandler {
	return &AuthHandler{}
}

// Login User Login
func (h *AuthHandler) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error in requesting parameter"})
		return
	}

	// Find User
	var user models.User
	if err := database.DB.Where("username = ?", req.Username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Username or password error"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Login service is not available"})
		return
	}

	// Check account status
	if !user.IsActive() {
		c.JSON(http.StatusForbidden, gin.H{"error": "Account disabled"})
		return
	}

	// Authentication password
	if !user.CheckPassword(req.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Username or password error"})
		return
	}

	// Generatetoken
	token, err := auth.GenerateToken(user.ID, user.Username, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate the token"})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}
	loginUpdate := tx.Model(&models.User{}).Where("id = ?", user.ID).Update("last_login", now)
	if loginUpdate.Error != nil || loginUpdate.RowsAffected != 1 {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update login status"})
		return
	}
	if err := tx.Create(&session).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Login submission failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user":  user,
	})
}

// Register User Registration
func (h *AuthHandler) Register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error in requesting parameter"})
		return
	}

	// Check if username exists
	var count int64
	if err := database.DB.Model(&models.User{}).Where("username = ?", req.Username).Count(&count).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check username"})
		return
	}
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username Exists"})
		return
	}

	// Check if the mailbox exists
	if err := database.DB.Model(&models.User{}).Where("email = ?", req.Email).Count(&count).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check mailbox"})
		return
	}
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Mailbox is already in use"})
		return
	}

	// Create User
	user := models.User{
		ID:       uuid.New().String(),
		Username: req.Username,
		Email:    req.Email,
		Nickname: req.Nickname,
		Role:     "user",
		Status:   "active",
	}

	if err := user.SetPassword(req.Password); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Password encryption failed"})
		return
	}

	// Generatetoken
	token, err := auth.GenerateToken(user.ID, user.Username, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate the token"})
		return
	}
	session := models.UserSession{
		ID: uuid.New().String(), UserID: user.ID, Token: auth.HashToken(token),
		IP: c.ClientIP(), UserAgent: c.GetHeader("User-Agent"),
		ExpiresAt: time.Now().Add(auth.TokenExpiration),
	}
	tx := database.DB.Begin()
	if tx.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}
	if err := tx.Create(&user).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}
	if err := tx.Create(&session).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration submission failed"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"token": token,
		"user":  user,
	})
}

// GetCurrentUser Fetching current user information
func (h *AuthHandler) GetCurrentUser(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)

	var user models.User
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		writeUserLookupError(c, err)
		return
	}

	c.JSON(http.StatusOK, user)
}

// UpdateProfile Update User Information
func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)

	var req models.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error in requesting parameter"})
		return
	}

	var user models.User
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		writeUserLookupError(c, err)
		return
	}

	// Update Fields
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Update Failed"})
		return
	}
	c.JSON(http.StatusOK, user)
}

// UpdatePassword Change Password
func (h *AuthHandler) UpdatePassword(c *gin.Context) {
	userID := middleware.GetCurrentUserID(c)

	var req models.UpdatePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error in requesting parameter"})
		return
	}

	var user models.User
	if err := database.DB.First(&user, "id = ?", userID).Error; err != nil {
		writeUserLookupError(c, err)
		return
	}

	// Authenticate Old Password
	if !user.CheckPassword(req.OldPassword) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Original password error"})
		return
	}

	// Set New Password
	if err := user.SetPassword(req.NewPassword); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Password encryption failed"})
		return
	}

	// Clear mandatory password changes
	user.MustChangePassword = false

	tx := database.DB.Begin()
	if tx.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not start password update"})
		return
	}
	if err := tx.Save(&user).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Update Failed"})
		return
	}
	if err := tx.Where("user_id = ?", user.ID).Delete(&models.UserSession{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Password update failed"})
		return
	}
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Password update submission failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password modified successfully"})
}

func writeUserLookupError(c *gin.Context, err error) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "User does not exist"})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": "Query user failed"})
}

// Logout User Logout
func (h *AuthHandler) Logout(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 {
			token := parts[1]
			// Remove Session
			if err := database.DB.Where("token = ?", auth.HashToken(token)).Delete(&models.UserSession{}).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Logout Failed"})
				return
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logout Success"})
}

// ListUsers User List (Administrator)
func (h *AuthHandler) ListUsers(c *gin.Context) {
	var users []models.User

	query := database.DB.Model(&models.User{})

	page, pageSize := parsePagination(c, 20, 100)

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Querying user number failed"})
		return
	}

	offset := (page - 1) * pageSize
	if err := query.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Query user failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"users": users,
		"total": total,
		"page":  page, "page_size": pageSize,
		"total_pages": int((total + int64(pageSize) - 1) / int64(pageSize)),
	})
}

// UpdateUserStatus Update User Status (Administrator)
func (h *AuthHandler) UpdateUserStatus(c *gin.Context) {
	userID := c.Param("id")
	status := c.Query("status")

	if status != "active" && status != "disabled" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state"})
		return
	}

	tx := database.DB.Begin()
	if tx.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Update Failed"})
		return
	}
	result := tx.Model(&models.User{}).Where("id = ?", userID).Update("status", status)
	if result.Error != nil || result.RowsAffected != 1 {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Update Failed"})
		return
	}
	if status == "disabled" {
		if err := tx.Where("user_id = ?", userID).Delete(&models.UserSession{}).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Undo session failed"})
			return
		}
	}
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Update Submission Failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Update Success"})
}
