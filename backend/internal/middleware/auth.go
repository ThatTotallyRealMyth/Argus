package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/auth"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
)

// AuthRequired Authenticate intermediates
func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Fetch from Requesttoken
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No authentication medals provided"})
			c.Abort()
			return
		}

		// Bearer tokenFormat
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication token format error"})
			c.Abort()
			return
		}

		token := parts[1]

		// Parsingtoken
		claims, err := auth.ParseToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authentication token"})
			c.Abort()
			return
		}
		if !hasActiveSession(token, claims.UserID) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session expired"})
			c.Abort()
			return
		}

		// Place user information in context
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)

		c.Next()
	}
}

// AdminRequired restricts a route to administrators.
func AdminRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists || role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Require administrator privileges"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// GetCurrentUserID Fetch Current UserID
func GetCurrentUserID(c *gin.Context) string {
	if userID, exists := c.Get("user_id"); exists {
		return userID.(string)
	}
	return ""
}

// GetCurrentUsername Fetching current username
func GetCurrentUsername(c *gin.Context) string {
	if username, exists := c.Get("username"); exists {
		return username.(string)
	}
	return ""
}

// FlexibleAuth Flexible authentication intermediates
// Support Authorization header (Bearer) and ?token= query Parameters
// For WebSocket Could not set custom in browser with static files etc. header The scene.
func FlexibleAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := ""

		// 1. Priority from Authorization header Fetch
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && parts[0] == "Bearer" {
				token = parts[1]
			}
		}

		// 2. Back to query Parameters (WebSocket / img Tag scene)
		if token == "" {
			token = c.Query("token")
		}

		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No authentication medals provided"})
			c.Abort()
			return
		}

		claims, err := auth.ParseToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authentication token"})
			c.Abort()
			return
		}
		if !hasActiveSession(token, claims.UserID) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session expired"})
			c.Abort()
			return
		}

		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)
		c.Next()
	}
}

func hasActiveSession(token, userID string) bool {
	if database.DB == nil {
		return false
	}
	var count int64
	err := database.DB.Model(&models.UserSession{}).
		Where("token = ? AND user_id = ? AND expires_at > ?", auth.HashToken(token), userID, time.Now()).
		Count(&count).Error
	if err != nil || count != 1 {
		return false
	}
	var user models.User
	if err := database.DB.Select("status").First(&user, "id = ?", userID).Error; err != nil {
		return false
	}
	return user.IsActive()
}

// IsAdmin Whether to be a administrator
func IsAdmin(c *gin.Context) bool {
	if role, exists := c.Get("role"); exists {
		return role == "admin"
	}
	return false
}
