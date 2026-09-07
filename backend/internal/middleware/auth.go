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

// AuthRequired 认证中间件
func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从请求头获取token
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未提供认证令牌"})
			c.Abort()
			return
		}

		// Bearer token格式
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "认证令牌格式错误"})
			c.Abort()
			return
		}

		token := parts[1]

		// 解析token
		claims, err := auth.ParseToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的认证令牌"})
			c.Abort()
			return
		}
		if !hasActiveSession(token, claims.UserID) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "会话已失效"})
			c.Abort()
			return
		}

		// 将用户信息存入上下文
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)

		c.Next()
	}
}

// AdminRequired 管理员权限中间件
func AdminRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists || role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "需要管理员权限"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// GetCurrentUserID 获取当前用户ID
func GetCurrentUserID(c *gin.Context) string {
	if userID, exists := c.Get("user_id"); exists {
		return userID.(string)
	}
	return ""
}

// GetCurrentUsername 获取当前用户名
func GetCurrentUsername(c *gin.Context) string {
	if username, exists := c.Get("username"); exists {
		return username.(string)
	}
	return ""
}

// FlexibleAuth 灵活认证中间件
// 支持 Authorization header (Bearer) 和 ?token= query 参数
// 用于 WebSocket 和静态文件等在浏览器中无法设置自定义 header 的场景
func FlexibleAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := ""

		// 1. 优先从 Authorization header 获取
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && parts[0] == "Bearer" {
				token = parts[1]
			}
		}

		// 2. 回退到 query 参数（WebSocket / img 标签场景）
		if token == "" {
			token = c.Query("token")
		}

		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未提供认证令牌"})
			c.Abort()
			return
		}

		claims, err := auth.ParseToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的认证令牌"})
			c.Abort()
			return
		}
		if !hasActiveSession(token, claims.UserID) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "会话已失效"})
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

// IsAdmin 是否为管理员
func IsAdmin(c *gin.Context) bool {
	if role, exists := c.Get("role"); exists {
		return role == "admin"
	}
	return false
}
