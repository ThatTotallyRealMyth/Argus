package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

func TestTaskWorkbenchCSVExports(t *testing.T) {
	exporter := NewExporter(t.TempDir())
	tests := []struct {
		name   string
		export func() (string, error)
		header string
	}{
		{name: "ips", export: func() (string, error) {
			return exporter.ExportIPsToCSV([]models.IP{{IPAddress: "203.0.113.7"}}, "task")
		}, header: "IPAddress,Associate domain name,Source,Operating system,Location,CDN,Created"},
		{name: "urls", export: func() (string, error) {
			return exporter.ExportURLsToCSV([]models.CrawlerResult{{URL: "https://example.com"}}, "task")
		}, header: "URL,Methodology,Status Code,Content-Type,Response Length,Source,Created"},
		{name: "http", export: func() (string, error) {
			return exporter.ExportHTTPTransactionsToCSV([]models.HTTPTransaction{{URL: "https://example.com"}}, "task")
		}, header: "URL,Methodology,Status Code,Content-Type,Response Length,Response time-consuming(ms),Source,Created"},
		{name: "vulnerabilities", export: func() (string, error) {
			verifiedAt := time.Date(2026, time.July, 21, 9, 30, 0, 0, time.UTC)
			return exporter.ExportVulnerabilitiesToCSV([]models.Vulnerability{{
				URL: "https://example.com/admin", Type: "poc_validation", Severity: "high", Status: models.VulnerabilityStatusRegressed,
				Title: "Access control bypass", Source: "poc-verification", LastVerificationResult: "safe", LastVerifiedAt: &verifiedAt,
				Payload: "role=user", Proof: "HTTP 200", TriageNote: "retest after deployment",
			}}, "task")
		}, header: "URL,Type,Severity,Status,Title,Source,Latest retest result,Latest retest time,Description,Payload,Proof,Triage notes,Solutions"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filename, err := test.export()
			if err != nil {
				t.Fatalf("export CSV: %v", err)
			}
			content, err := os.ReadFile(filename)
			if err != nil {
				t.Fatalf("read CSV: %v", err)
			}
			if !bytes.HasPrefix(content, []byte{0xEF, 0xBB, 0xBF}) || !bytes.Contains(content, []byte(test.header)) {
				t.Fatalf("unexpected CSV content: %q", content)
			}
		})
	}
}

func TestCSVExportsSanitizeSpreadsheetFormulas(t *testing.T) {
	exporter := NewExporter(t.TempDir())
	filename, err := exporter.ExportSitesToCSV([]models.Site{{
		URL:    "https://example.com",
		Title:  `=HYPERLINK("https://attacker.invalid/","open")`,
		Server: " @SUM(1,1)",
	}}, "task")
	if err != nil {
		t.Fatalf("export sites CSV: %v", err)
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read sites CSV: %v", err)
	}
	reader := csv.NewReader(strings.NewReader(string(bytes.TrimPrefix(content, []byte{0xEF, 0xBB, 0xBF}))))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("parse sites CSV: %v", err)
	}
	if len(records) != 2 || records[1][1][0] != '\'' || records[1][3][0] != '\'' {
		t.Fatalf("spreadsheet formulas were not neutralized: %#v", records)
	}
}

func TestJSONExportIncludesTaskLogs(t *testing.T) {
	exporter := NewExporter(t.TempDir())
	filename, err := exporter.ExportToJSON(&ExportData{
		Task:     &models.Task{ID: "task"},
		TaskLogs: []models.TaskLog{{TaskID: "task", Sequence: 1, Message: "Mission begins."}},
	})
	if err != nil {
		t.Fatalf("export JSON: %v", err)
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read JSON: %v", err)
	}
	var decoded ExportData
	if err := json.Unmarshal(content, &decoded); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if len(decoded.TaskLogs) != 1 || decoded.TaskLogs[0].Message != "Mission begins." {
		t.Fatalf("task logs missing from JSON: %#v", decoded.TaskLogs)
	}
}

func TestHTMLReportEscapesUntrustedReconEvidence(t *testing.T) {
	report, err := generateHTMLReport(&ExportData{
		Task: &models.Task{
			ID:        "task-report",
			Name:      `</title><script data-test="task">alert(1)</script>`,
			Target:    `<img src=x onerror="alert(2)">`,
			CreatedAt: time.Date(2026, time.July, 20, 10, 30, 0, 0, time.UTC),
		},
		Sites: []models.Site{{
			URL:    `javascript:alert(3)`,
			Title:  `<svg onload="alert(4)">`,
			Server: `</td><script>alert(5)</script>`,
		}},
		Vulnerabilities: []models.Vulnerability{{
			Severity:    `critical' onclick='alert(6)`,
			Status:      models.VulnerabilityStatusRegressed,
			Title:       `<script>alert(7)</script>`,
			URL:         `https://example.com/?q=<script>alert(8)</script>`,
			Description: `<img src=x onerror="alert(9)">`,
			Payload:     `"><script>alert(10)</script>`,
			Proof:       `<b>confirmed</b>`,
			TriageNote:  `<script>alert(12)</script>`,
			Solution:    `escape < and >`,
			Reference:   `javascript:alert(11)`,
		}},
		ExportTime: time.Date(2026, time.July, 20, 11, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("render report: %v", err)
	}
	for _, unsafe := range []string{"<script", "<img", "<svg", `href="javascript:`} {
		if strings.Contains(strings.ToLower(report), unsafe) {
			t.Fatalf("unsafe report markup %q survived: %s", unsafe, report)
		}
	}
	for _, marker := range []string{
		"Argus security research report",
		"Content-Security-Policy",
		"&lt;script&gt;alert(7)&lt;/script&gt;",
		"&lt;b&gt;confirmed&lt;/b&gt;",
		`class="severity-info"`,
		"Plugging evidence and sentencing",
		"Relapsing",
	} {
		if !strings.Contains(report, marker) {
			t.Fatalf("secure report missing %q", marker)
		}
	}
}

func TestGenerateReportUsesPrivatePermissions(t *testing.T) {
	exporter := NewExporter(t.TempDir())
	filename, err := exporter.GenerateReport(&ExportData{Task: &models.Task{ID: "task"}, ExportTime: time.Now()})
	if err != nil {
		t.Fatalf("generate report: %v", err)
	}
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatalf("stat report: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("report permissions = %o, want 600", got)
	}
}

func TestTruncateStringPreservesUTF8(t *testing.T) {
	if got := truncateString("Plugging evidence.", 2); got != "Leaks..." || strings.ToValidUTF8(got, "") != got {
		t.Fatalf("unicode truncation = %q", got)
	}
}
