package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// Logger Midpoint Log
func Logger(logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start Time
		startTime := time.Now()

		// Processing of requests
		c.Next()

		// End of time
		endTime := time.Now()

		// Implementation time
		latencyTime := endTime.Sub(startTime)

		// Method of request
		reqMethod := c.Request.Method

		// Request route
		reqUri := c.Request.RequestURI

		// Status Code
		statusCode := c.Writer.Status()

		// RequestIP
		clientIP := c.ClientIP()

		// Log Format
		logger.WithFields(logrus.Fields{
			"status_code":  statusCode,
			"latency_time": latencyTime,
			"client_ip":    clientIP,
			"req_method":   reqMethod,
			"req_uri":      reqUri,
		}).Info("HTTP REQUEST")
	}
}
