package services

import (
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestNormalizeMonitorTargetsByType(t *testing.T) {
	tests := []struct {
		name        string
		monitorType models.MonitorType
		target      string
		want        string
		wantError   bool
	}{
		{name: "domain", monitorType: models.MonitorTypeDomain, target: "EXAMPLE.com.", want: "example.com"},
		{name: "ip", monitorType: models.MonitorTypeIP, target: "2001:0db8::1", want: "2001:db8::1"},
		{name: "site", monitorType: models.MonitorTypeSite, target: "HTTPS://EXAMPLE.com/path", want: "https://example.com/path"},
		{name: "domain rejects URL", monitorType: models.MonitorTypeDomain, target: "https://example.com", wantError: true},
		{name: "ip rejects CIDR", monitorType: models.MonitorTypeIP, target: "192.0.2.0/24", wantError: true},
		{name: "site rejects credentials", monitorType: models.MonitorTypeSite, target: "https://user:pass@example.com", wantError: true},
		{name: "github rejects multiline", monitorType: models.MonitorTypeGithub, target: "example.com\ntoken", wantError: true},
		{name: "cve normalizes list", monitorType: models.MonitorTypeCVE, target: " nginx, grafana ", want: "nginx, grafana"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := normalizeMonitorTarget(test.monitorType, test.target)
			if test.wantError {
				if err == nil || !IsMonitorInputError(err) {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err != nil || value != test.want {
				t.Fatalf("value/error = %q/%v, want %q", value, err, test.want)
			}
		})
	}
}

func TestExternalIntelligenceMonitorRejectsScanScope(t *testing.T) {
	monitor := &models.Monitor{Name: "GitHub", Type: models.MonitorTypeGithub, Target: "example.com api_key", ScopeID: "scope-id", Status: models.MonitorStatusActive, Interval: 3600}
	_, err := AuthorizeMonitorExecution(nil, monitor)
	if err == nil || !IsMonitorInputError(err) || !strings.Contains(err.Error(), "apply only") {
		t.Fatalf("scope applicability error = %v", err)
	}
}

func TestMonitorAssetGroupRequiresDatabase(t *testing.T) {
	groupID := "group-id"
	monitor := &models.Monitor{Name: "Group", Type: models.MonitorTypeDomain, AssetGroupID: &groupID, Status: models.MonitorStatusActive, Interval: 3600}
	if _, err := AuthorizeMonitorExecution(nil, monitor); err == nil || !strings.Contains(err.Error(), "database is unavailable") {
		t.Fatalf("nil database error = %v", err)
	}
}

func TestMonitorScopePostgresLifecycle(t *testing.T) {
	dsn := os.Getenv("ASSET_CATALOG_INTEGRATION_DSN")
	if dsn == "" {
		t.Skip("set ASSET_CATALOG_INTEGRATION_DSN to run PostgreSQL monitor scope coverage")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open integration database: %v", err)
	}
	if err := db.AutoMigrate(&models.ScanScope{}, &models.Monitor{}); err != nil {
		t.Fatalf("migrate monitor scope integration schema: %v", err)
	}
	previousDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = previousDB })

	suffix := uuid.NewString()
	scope := &models.ScanScope{Name: "monitor-scope-" + suffix, AllowRules: []string{"*.example.com"}}
	if err := SaveScanScope(db, scope); err != nil {
		t.Fatal(err)
	}
	monitor := &models.Monitor{Name: "monitor-" + suffix, Type: models.MonitorTypeSite, Target: "HTTPS://API.example.com/path", ScopeID: scope.ID, Status: models.MonitorStatusActive, Interval: 3600}
	t.Cleanup(func() {
		db.Delete(&models.Monitor{}, "id = ?", monitor.ID)
		db.Delete(&models.ScanScope{}, "id = ?", scope.ID)
	})
	if err := SaveMonitor(db, monitor); err != nil {
		t.Fatal(err)
	}
	if monitor.ScopeID != scope.ID || monitor.Target != "https://api.example.com/path" {
		t.Fatalf("monitor scope/target = %s/%s", monitor.ScopeID, monitor.Target)
	}
	if err := DeleteScanScope(db, scope.ID); err == nil || !strings.Contains(err.Error(), "referenced") {
		t.Fatalf("delete referenced scope error = %v", err)
	}
	scope.DenyRules = []string{"api.example.com"}
	if err := SaveScanScope(db, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := AuthorizeMonitorExecution(db, monitor); err == nil || !IsScanScopeInputError(err) {
		t.Fatalf("monitor execution after scope change error = %v", err)
	}
}
