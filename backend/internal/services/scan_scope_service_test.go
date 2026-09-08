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

func TestScanScopeDomainRulesAndDenyPrecedence(t *testing.T) {
	scope := models.ScanScope{Name: "Program A", AllowRules: []string{"example.com", "*.example.com"}, DenyRules: []string{"admin.example.com", "*.internal.example.com"}}
	validation, err := ValidateScanScopePreview(scope, "EXAMPLE.com, https://api.example.com/path, admin.example.com, x.internal.example.com, outside.test")
	if err != nil {
		t.Fatal(err)
	}
	if validation.Allowed {
		t.Fatal("mixed target set should be blocked")
	}
	want := map[string]bool{
		"example.com": true, "https://api.example.com/path": true, "admin.example.com": false,
		"x.internal.example.com": false, "outside.test": false,
	}
	for _, decision := range validation.Targets {
		if decision.Allowed != want[decision.Normalized] {
			t.Fatalf("decision for %s = %v, want %v (%s)", decision.Normalized, decision.Allowed, want[decision.Normalized], decision.Reason)
		}
	}
}

func TestScanScopeWildcardDoesNotIncludeApex(t *testing.T) {
	validation, err := ValidateScanScopePreview(models.ScanScope{Name: "Subdomains", AllowRules: []string{"*.example.com"}}, "example.com, api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if validation.Targets[0].Allowed || !validation.Targets[1].Allowed {
		t.Fatalf("unexpected wildcard decisions: %#v", validation.Targets)
	}
}

func TestScanScopeCIDRContainmentAndNormalization(t *testing.T) {
	scope := models.ScanScope{Name: "Network", AllowRules: []string{"203.0.113.0/24", "2001:db8::/32"}, DenyRules: []string{"203.0.113.50"}}
	validation, err := ValidateScanScopePreview(scope, "203.0.113.7:443, 203.0.113.50, 203.0.113.128/25, 203.0.112.0/23, [2001:db8::10]")
	if err != nil {
		t.Fatal(err)
	}
	want := []bool{true, false, true, false, true}
	for index, decision := range validation.Targets {
		if decision.Allowed != want[index] {
			t.Fatalf("decision %d (%s) = %v, want %v", index, decision.Normalized, decision.Allowed, want[index])
		}
	}
}

func TestScanScopeRejectsPathSpecificRule(t *testing.T) {
	_, _, err := NormalizeScanScopeRules([]string{"https://example.com/only-this-path"}, nil)
	if err == nil || !IsScanScopeInputError(err) {
		t.Fatalf("path-specific URL rule error = %v", err)
	}
}

func TestScanScopeNormalizesAndDeduplicatesTargets(t *testing.T) {
	validation, err := ValidateScanScopePreview(models.ScanScope{Name: "URL", AllowRules: []string{"example.com"}}, "https://EXAMPLE.com/a, https://example.com/a, example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if !validation.Allowed || validation.NormalizedTarget != "https://example.com/a,example.com:443" || len(validation.Targets) != 2 {
		t.Fatalf("unexpected normalized validation: %#v", validation)
	}
}

func TestBuiltScanScopeValidatorBlocksDerivedTargets(t *testing.T) {
	validate := buildScanScopeValidator(models.ScanScope{Name: "Task", AllowRules: []string{"example.com", "192.0.2.0/24"}, DenyRules: []string{"192.0.2.50"}})
	for _, target := range []string{"https://example.com/path", "192.0.2.10"} {
		if err := validate(target); err != nil {
			t.Fatalf("allowed target %q: %v", target, err)
		}
	}
	for _, target := range []string{"https://outside.example/path", "192.0.2.50", "192.0.3.1"} {
		if err := validate(target); err == nil || !IsScanScopeInputError(err) {
			t.Fatalf("blocked target %q error = %v", target, err)
		}
	}
}

func TestTaskScopePostgresLifecycle(t *testing.T) {
	dsn := os.Getenv("ASSET_CATALOG_INTEGRATION_DSN")
	if dsn == "" {
		t.Skip("set ASSET_CATALOG_INTEGRATION_DSN to run PostgreSQL scan scope coverage")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open integration database: %v", err)
	}
	if err := db.AutoMigrate(&models.ScanScope{}, &models.Task{}, &models.Monitor{}); err != nil {
		t.Fatalf("migrate scan scope integration schema: %v", err)
	}
	previousDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = previousDB })
	var previousDefault models.ScanScope
	db.Where("is_default = ?", true).Limit(1).Find(&previousDefault)

	suffix := uuid.NewString()
	scope := &models.ScanScope{Name: "scope-" + suffix, AllowRules: []string{"*.example.com"}, DenyRules: []string{"blocked.example.com"}, IsDefault: true}
	if err := SaveScanScope(db, scope); err != nil {
		t.Fatal(err)
	}
	var taskID string
	t.Cleanup(func() {
		if taskID != "" {
			db.Delete(&models.Task{}, "id = ?", taskID)
		}
		db.Delete(&models.ScanScope{}, "id = ?", scope.ID)
		if previousDefault.ID != "" {
			db.Model(&models.ScanScope{}).Where("id = ?", previousDefault.ID).Update("is_default", true)
		}
	})

	service := &TaskService{scopeGuard: NewScanScopeService()}
	if _, err := service.CreateTaskInScope("blocked", "blocked.example.com", "", "", models.TaskOptions{}); err == nil || !IsScanScopeInputError(err) {
		t.Fatalf("blocked target error = %v", err)
	}
	task, err := service.CreateTaskInScope("allowed", "https://API.example.com/path", "", "", models.TaskOptions{})
	if err != nil {
		t.Fatal(err)
	}
	taskID = task.ID
	if task.ScopeID != scope.ID || task.Target != "https://api.example.com/path" {
		t.Fatalf("task scope/target = %s/%s", task.ScopeID, task.Target)
	}

	scope.IsDefault = false
	if err := SaveScanScope(db, scope); err == nil || !IsScanScopeInputError(err) || !strings.Contains(err.Error(), "cannot be unset") {
		t.Fatalf("unset default scope error = %v", err)
	}
	scope.IsDefault = true

	scope.DenyRules = append(scope.DenyRules, "api.example.com")
	if err := SaveScanScope(db, scope); err != nil {
		t.Fatal(err)
	}
	if err := service.StartTask(task.ID); err == nil || !strings.Contains(err.Error(), "Targets are beyond the scope of the mandate.") {
		t.Fatalf("start after scope change error = %v", err)
	}
}
