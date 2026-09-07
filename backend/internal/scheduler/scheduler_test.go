package scheduler

import (
	"testing"
	"time"

	"github.com/reconmaster/backend/internal/scanner"
)

func TestCalculateNextRunFromUsesClaimTime(t *testing.T) {
	scheduler := NewScheduler(nil)
	from := time.Date(2026, time.July, 22, 12, 34, 56, 0, time.UTC)
	next, err := scheduler.calculateNextRunFrom("0 */5 * * * *", "custom", from)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, time.July, 22, 12, 35, 0, 0, time.UTC)
	if next == nil || !next.Equal(want) {
		t.Fatalf("next run = %v, want %v", next, want)
	}
}

func TestMonitorScanOptionsCreateExecutableTaskConfiguration(t *testing.T) {
	options, enabled, err := monitorScanTaskOptions(`{"enable_domain_brute":true,"enable_port_scan":true,"enable_site_detect":false,"enable_screenshot":true,"enable_poc_scan":true}`, "example.test")
	if err != nil || !enabled {
		t.Fatalf("monitor options rejected: enabled=%v err=%v", enabled, err)
	}
	if options.Target != "example.test" || !options.EnableDomainBrute || !options.EnablePortScan || !options.EnableServiceDetect || !options.EnableSiteDetect || !options.EnableScreenshot || !options.EnablePoCDetection {
		t.Fatalf("monitor options were not mapped to the task pipeline: %#v", options)
	}
	if options.PortScanType != "top100" || options.DomainBruteType != "big" {
		t.Fatalf("monitor scan defaults are incomplete: %#v", options)
	}
}

func TestMonitorScanOptionsCanKeepLightweightMonitorOnly(t *testing.T) {
	options, enabled, err := monitorScanTaskOptions(`{}`, "example.test")
	if err != nil || enabled || options.Target != "" || options.EnablePortScan || options.EnableDomainBrute {
		t.Fatalf("empty monitor options unexpectedly queued a scan: options=%#v enabled=%v err=%v", options, enabled, err)
	}
	if _, _, err := monitorScanTaskOptions(`{"enable_port_scan":`, "example.test"); err == nil {
		t.Fatal("invalid monitor options were accepted")
	}
}

func TestCalculateNextRunFromRejectsInvalidSchedule(t *testing.T) {
	scheduler := NewScheduler(nil)
	if _, err := scheduler.calculateNextRunFrom("not-a-cron", "custom", time.Now()); err == nil {
		t.Fatal("invalid cron expression was accepted")
	}
}

func TestSiteMonitorContentHashChangesWhenBodyChanges(t *testing.T) {
	first := []byte("AAAA")
	second := []byte("BBBB")
	firstValue := siteMonitorData(200, first)
	secondValue := siteMonitorData(200, second)
	if firstValue == secondValue {
		t.Fatal("different response bodies produced the same site monitor value")
	}
}

func TestGithubFindingDiffUsesEvidenceFingerprint(t *testing.T) {
	first := githubLeakFinding{Repository: "acme/app", Path: ".env", URL: "https://github.com/acme/app/blob/main/.env", Evidence: "confirmed:api_key=1", Severity: "high"}
	first.Fingerprint = githubFindingFingerprint(first)
	unchanged := first
	changed := first
	changed.Evidence = "confirmed:api_key=1,private_key=1"
	changed.Fingerprint = githubFindingFingerprint(changed)
	if got := diffGithubFindings([]githubLeakFinding{unchanged}, []githubLeakFinding{first}); len(got) != 0 {
		t.Fatalf("unchanged finding treated as new: %#v", got)
	}
	if got := diffGithubFindings([]githubLeakFinding{changed}, []githubLeakFinding{first}); len(got) != 1 || got[0].Fingerprint == first.Fingerprint {
		t.Fatalf("changed evidence was not detected: %#v", got)
	}
}

func TestSafeGithubResultURLRejectsUntrustedHosts(t *testing.T) {
	if got := safeGithubResultURL("https://github.com/acme/app/blob/main/.env"); got == "" {
		t.Fatal("valid GitHub URL was rejected")
	}
	for _, value := range []string{"javascript:alert(1)", "https://github.com.evil.test/file", "https://user@github.com/file", "http://github.com/file"} {
		if got := safeGithubResultURL(value); got != "" {
			t.Fatalf("unsafe URL accepted: %q -> %q", value, got)
		}
	}
}

func TestGithubConfigurationErrorsAreSafeForMonitorHistory(t *testing.T) {
	if got := publicMonitorError(scanner.ErrGithubTokenNotConfigured); got != scanner.ErrGithubTokenNotConfigured.Error() {
		t.Fatalf("configuration error was hidden: %q", got)
	}
}

func TestDomainMonitorIPSnapshotIsOrderIndependent(t *testing.T) {
	first := domainMonitorSnapshot([]string{"2001:db8::2", "192.0.2.1", "2001:db8::1"})
	second := domainMonitorSnapshot([]string{"2001:db8::1", "2001:db8::2", "192.0.2.1"})
	if first != second {
		t.Fatal("same DNS result set produced different snapshots")
	}
}

func TestDecodeMonitorSnapshotRejectsCorruptHistory(t *testing.T) {
	var snapshot githubMonitorSnapshot
	if err := decodeMonitorSnapshot(`{"version":1}`, &snapshot); err != nil || snapshot.Version != 1 {
		t.Fatalf("valid snapshot failed: snapshot=%#v err=%v", snapshot, err)
	}
	if err := decodeMonitorSnapshot(`{"version":`, &snapshot); err == nil {
		t.Fatal("corrupt monitor history was accepted")
	}
}
