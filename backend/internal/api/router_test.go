package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/reconmaster/backend/internal/config"
	"github.com/reconmaster/backend/internal/services"
)

func TestRedactedRequestURIHidesCredentialQueryParameters(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "/api/v1/ws/progress?token=jwt-secret&target=example.com&api_key=another-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := redactedRequestURI(request)
	if got != "/api/v1/ws/progress?api_key=%5BREDACTED%5D&target=example.com&token=%5BREDACTED%5D" {
		t.Fatalf("unexpected redacted URI: %s", got)
	}
	if got == request.URL.RequestURI() {
		t.Fatal("credential query parameters were not redacted")
	}
}

func TestRouterServesPackagedCursorAssets(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "web", "dist", "cursors", "eclipse-pointer.svg")); err != nil {
		t.Skip("frontend distribution has not been built")
	}
	previousConfig := config.GlobalConfig
	config.GlobalConfig = &config.Config{Encryption: config.EncryptionConfig{Key: "01234567890123456789012345678901"}}
	t.Cleanup(func() { config.GlobalConfig = previousConfig })
	service := services.NewTaskService()
	defer service.Close()
	enterpriseService := services.NewEnterpriseService(service)
	defer enterpriseService.Close()
	router := SetupRouter(service, enterpriseService, nil, nil)
	request := httptest.NewRequest(http.MethodGet, "/cursors/eclipse-pointer.svg", nil)
	response := httptest.NewRecorder()
	workingDirectory, _ := os.Getwd()
	defer os.Chdir(workingDirectory)
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "image/svg+xml" {
		t.Fatalf("cursor asset response = %d %q", response.Code, response.Header().Get("Content-Type"))
	}
}

func TestIsPathOrSubpathAvoidsPrefixCollisions(t *testing.T) {
	if !isPathOrSubpath("/api/v1/tasks", "/api") {
		t.Fatal("expected API subpath to match")
	}
	if isPathOrSubpath("/apiary", "/api") {
		t.Fatal("unrelated prefix should not match")
	}
	if !isPathOrSubpath("/mcp", "/mcp") || !isPathOrSubpath("/mcp/session", "/mcp") {
		t.Fatal("expected MCP path and subpath to match")
	}
}
