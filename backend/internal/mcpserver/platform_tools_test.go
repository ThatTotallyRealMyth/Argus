package mcpserver

import (
	"testing"

	"github.com/reconmaster/backend/internal/models"
)

func TestValidatePlatformRecord(t *testing.T) {
	validPolicy := &models.Policy{Name: "default", Config: models.PolicyConfig{PortScanType: "top100"}}
	if err := validatePlatformRecord(validPolicy); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	if !validPolicy.Config.EnablePortScan {
		t.Fatal("port scanning invariant not applied")
	}
	if err := validatePlatformRecord(&models.Monitor{Name: "CVE watch", Target: "nginx", Type: models.MonitorTypeCVE, Status: models.MonitorStatusActive, Interval: 3600}); err != nil {
		t.Fatalf("valid CVE monitor rejected: %v", err)
	}

	cases := []struct {
		name   string
		record any
	}{
		{"monitor interval", &models.Monitor{Name: "m", Target: "example.com", Type: models.MonitorTypeDomain, Status: models.MonitorStatusActive, Interval: 1}},
		{"invalid poc severity", &models.PoC{Name: "p", Category: "web", Severity: "fatal", PoCType: "custom", PoCContent: "x"}},
		{"empty fingerprint dsl", &models.Fingerprint{Name: "f", Category: "web"}},
		{"invalid regex", &models.SensitiveRule{Name: "r", Type: models.SensitiveRuleTypeRegex, Severity: models.SensitiveRuleSeverityHigh, Pattern: "["}},
		{"invalid color", &models.AssetTag{Name: "tag", Color: "red"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := validatePlatformRecord(test.record); err == nil {
				t.Fatal("invalid record accepted")
			}
		})
	}
}

func TestValidatePoCAffectedVersionMetadata(t *testing.T) {
	poc := &models.PoC{
		Name:             "CVE test",
		Category:         "web",
		Severity:         "high",
		PoCType:          "nuclei",
		PoCContent:       "id: cve-test\ninfo:\n  name: CVE test\n  severity: high",
		Product:          "Example Server",
		AffectedVersions: ">=1.0,<1.4.2",
	}
	if err := validatePlatformRecord(poc); err != nil {
		t.Fatalf("valid PoC metadata rejected: %v", err)
	}
	if poc.MatchMode != "fuzzy" {
		t.Fatalf("expected default fuzzy match mode, got %q", poc.MatchMode)
	}

	poc.MatchMode = "unknown"
	if err := validatePlatformRecord(poc); err == nil {
		t.Fatal("invalid match mode accepted")
	}
}

func TestLibraryResource(t *testing.T) {
	for _, library := range []string{"fingerprints", "pocs"} {
		if resource, err := libraryResource(library); err != nil || resource != library {
			t.Fatalf("library %q rejected: resource=%q err=%v", library, resource, err)
		}
	}
	if _, err := libraryResource("settings"); err == nil {
		t.Fatal("unsupported library accepted")
	}
}
