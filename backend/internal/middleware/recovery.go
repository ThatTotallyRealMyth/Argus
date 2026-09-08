package middleware

import (
	"fmt"
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// Recovery Restore Middle
func Recovery(logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				// Fetch Stack Information
				stack := debug.Stack()

				// Record Error
				logger.WithFields(logrus.Fields{
					"error": err,
					"stack": string(stack),
					"path":  c.Request.URL.Path,
				}).Error("PANIC RECOVERED")

				// Back to Error Response
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": fmt.Sprintf("Internal server error: %v", err),
				})
				c.Abort()
			}
		}()
		c.Next()
	}
}
