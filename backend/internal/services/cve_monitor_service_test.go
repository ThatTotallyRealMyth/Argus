package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseCVEKeywords(t *testing.T) {
	keywords := ParseCVEKeywords(" nginx, nginx\nGrafana , apache http server ")
	if len(keywords) != 3 || keywords[0] != "nginx" || keywords[1] != "Grafana" {
		t.Fatalf("keywords = %#v", keywords)
	}
}

func TestCVEMonitorSearchDeduplicatesAndParsesNVD(t *testing.T) {
	var queryCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queryCount++
		if r.URL.Query().Get("lastModStartDate") == "" || r.URL.Query().Get("lastModEndDate") == "" {
			t.Fatal("missing bounded NVD modification window")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"vulnerabilities": []any{
			map[string]any{"cve": map[string]any{
				"id": "CVE-2026-0001", "published": "2026-07-01T00:00:00.000Z", "lastModified": "2026-07-02T00:00:00.000Z",
				"descriptions": []any{map[string]string{"lang": "en", "value": "Example nginx issue"}},
				"metrics":      map[string]any{"cvssMetricV31": []any{map[string]any{"cvssData": map[string]any{"baseScore": 9.8, "baseSeverity": "CRITICAL"}}}},
				"references":   []any{map[string]string{"url": "https://example.test/advisory"}},
			}},
		}})
	}))
	defer server.Close()

	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	service := NewCVEMonitorService()
	service.BaseURL = server.URL
	service.Now = func() time.Time { return now }
	records, err := service.Search(context.Background(), "nginx,grafana", now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if queryCount != 2 || len(records) != 1 {
		t.Fatalf("query count=%d records=%d, want two queries and one deduplicated record", queryCount, len(records))
	}
	if records[0].Severity != "critical" || records[0].BaseScore != 9.8 || !strings.Contains(records[0].Summary, "nginx") {
		t.Fatalf("normalized CVE = %#v", records[0])
	}
}

func TestDiffCVERecordsReportsNewAndModified(t *testing.T) {
	oldTime := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	newTime := oldTime.Add(time.Hour)
	previous := []CVERecord{{ID: "CVE-2026-0001", LastModified: oldTime}}
	current := []CVERecord{{ID: "CVE-2026-0001", LastModified: newTime}, {ID: "CVE-2026-0002", LastModified: oldTime}}
	changes := DiffCVERecords(previous, current)
	if len(changes) != 2 || changes[0].Kind != "modified" || changes[1].Kind != "new" {
		t.Fatalf("changes = %#v", changes)
	}
}

func TestMergeCVERecordsKeepsHistoryAndLatestRevision(t *testing.T) {
	oldTime := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	newTime := oldTime.Add(time.Hour)
	merged := MergeCVERecords(
		[]CVERecord{{ID: "CVE-2026-0001", Summary: "old", LastModified: oldTime}, {ID: "CVE-2026-0002", LastModified: oldTime}},
		[]CVERecord{{ID: "CVE-2026-0001", Summary: "new", LastModified: newTime}},
	)
	if len(merged) != 2 || merged[0].Summary != "new" || merged[1].ID != "CVE-2026-0002" {
		t.Fatalf("merged = %#v", merged)
	}
}
