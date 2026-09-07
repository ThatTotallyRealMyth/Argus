package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSecurityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(SecurityHeaders())
	router.GET("/health", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health", nil))

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"Permissions-Policy":     "camera=(), microphone=(), geolocation=()",
	}
	for key, value := range want {
		if got := recorder.Header().Get(key); got != value {
			t.Fatalf("%s = %q, want %q", key, got, value)
		}
	}
	csp := recorder.Header().Get("Content-Security-Policy")
	for _, directive := range []string{"frame-ancestors 'none'", "object-src 'none'", "connect-src 'self' ws: wss:"} {
		if !strings.Contains(csp, directive) {
			t.Fatalf("CSP %q does not contain %q", csp, directive)
		}
	}
}
