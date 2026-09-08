package scanner

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/reconmaster/backend/internal/models"
)

func TestScanContextTargetListNormalizesWithoutExpanding(t *testing.T) {
	ctx := &ScanContext{Task: &models.Task{Target: " example.com, 192.0.2.1/30, https://example.com/api, example.com, , 2001:db8::1 "}}
	want := []string{"example.com", "192.0.2.1/30", "https://example.com/api", "2001:db8::1"}
	if got := ctx.TargetList(); !reflect.DeepEqual(got, want) {
		t.Fatalf("target list mismatch: got=%v want=%v", got, want)
	}
}

func TestResolveIPsStopsBeforeExpansionWhenCancelled(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	ctx := &ScanContext{
		Task: &models.Task{Target: "10.0.0.0/16"},
		Ctx:  cancelled,
	}
	err := NewEngine().ResolveIPs(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestIsIPCIDRTargetDoesNotTreatURLPathAsCIDR(t *testing.T) {
	if !isIPCIDRTarget("192.0.2.0/30") {
		t.Fatal("IPv4 CIDR was not recognized")
	}
	if !isIPCIDRTarget("2001:db8::/126") {
		t.Fatal("IPv6 CIDR was not recognized")
	}
	if isIPCIDRTarget("https://example.com/api/v1") {
		t.Fatal("URL path was incorrectly recognized as CIDR")
	}
}

func TestDomainTargetNormalizesHostInputs(t *testing.T) {
	tests := map[string]string{
		"Example.COM":                    "example.com",
		"https://portal.example.com/app": "portal.example.com",
		"api.example.com:8443":           "api.example.com",
	}
	for input, want := range tests {
		got, ok := domainTarget(input)
		if !ok || got != want {
			t.Fatalf("domainTarget(%q) = %q, %v; want %q, true", input, got, ok, want)
		}
	}
	for _, input := range []string{"192.0.2.1", "192.0.2.0/24", "https://192.0.2.1/app"} {
		if got, ok := domainTarget(input); ok {
			t.Fatalf("domainTarget(%q) unexpectedly accepted %q", input, got)
		}
	}
}
