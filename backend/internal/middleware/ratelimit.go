package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiter Speed limit
type RateLimiter struct {
	visitors map[string]*Visitor
	mu       sync.RWMutex
	rate     int
	burst    int
}

// Visitor Visitors
type Visitor struct {
	tokens     int
	lastUpdate time.Time
}

// NewRateLimiter Create Speed Limit
func NewRateLimiter(rate, burst int) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*Visitor),
		rate:     rate,
		burst:    burst,
	}

	// Regular clean-up
	go rl.cleanupVisitors()

	return rl
}

// Allow Check whether requests are allowed
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	if !exists {
		rl.visitors[ip] = &Visitor{
			tokens:     rl.burst - 1,
			lastUpdate: time.Now(),
		}
		return true
	}

	// Acoustic Bar
	now := time.Now()
	elapsed := now.Sub(v.lastUpdate)
	tokensToAdd := int(elapsed.Seconds()) * rl.rate

	v.tokens += tokensToAdd
	if v.tokens > rl.burst {
		v.tokens = rl.burst
	}

	v.lastUpdate = now

	if v.tokens > 0 {
		v.tokens--
		return true
	}

	return false
}

// cleanupVisitors Clear expired visitors
func (rl *RateLimiter) cleanupVisitors() {
	for {
		time.Sleep(time.Minute)
		rl.mu.Lock()
		for ip, v := range rl.visitors {
			if time.Since(v.lastUpdate) > time.Hour {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// RateLimit Intermediate Speed Limit
func RateLimit(rl *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !rl.Allow(ip) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many requests",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}
