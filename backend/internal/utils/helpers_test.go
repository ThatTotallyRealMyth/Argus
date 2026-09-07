package utils

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestParseTargetExpandsIPv4CIDR(t *testing.T) {
	got, err := ParseTarget("example.com, 192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.com", "192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("targets mismatch: got=%v want=%v", got, want)
	}
}

func TestParseTargetExpandsIPv6CIDR(t *testing.T) {
	got, err := ParseTarget("2001:db8::/126")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("targets mismatch: got=%v want=%v", got, want)
	}
}

func TestParseTargetRejectsOversizedCIDR(t *testing.T) {
	if _, err := ParseTarget("10.0.0.0/8"); err == nil {
		t.Fatal("expected oversized CIDR to be rejected")
	}
}

func TestParseTargetKeepsURLAndRejectsMalformedIPCIDR(t *testing.T) {
	got, err := ParseTarget("https://example.com/api, 10.0.0.1/33")
	if err == nil {
		t.Fatal("expected malformed IP CIDR to be rejected")
	}
	if got != nil {
		t.Fatalf("expected no partial targets on error: %v", got)
	}

	got, err = ParseTarget("https://example.com/api")
	if err != nil || !reflect.DeepEqual(got, []string{"https://example.com/api"}) {
		t.Fatalf("URL target changed: got=%v err=%v", got, err)
	}
}

func TestParseTargetContextHonorsCancellationDuringCIDRExpansion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ParseTargetContext(ctx, "192.0.2.0/16")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}
