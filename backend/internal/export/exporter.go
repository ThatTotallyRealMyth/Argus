package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/logger"
	"github.com/reconmaster/backend/internal/models"
)

// Exporter Data Exporter
type Exporter struct {
	outputDir string
}

// NewExporter Create Exporter
func NewExporter(outputDir string) *Exporter {
	if outputDir == "" {
		outputDir = "./exports"
	}
	os.MkdirAll(outputDir, 0755)
	return &Exporter{
		outputDir: outputDir,
	}
}

// ExportData Export Data Structure
type ExportData struct {
	Task             *models.Task             `json:"task"`
	Domains          []models.Domain          `json:"domains"`
	IPs              []models.IP              `json:"ips"`
	Ports            []models.Port            `json:"ports"`
	Sites            []models.Site            `json:"sites"`
	URLs             []models.CrawlerResult   `json:"urls"`
	HTTPTransactions []models.HTTPTransaction `json:"http_transactions"`
	Vulnerabilities  []models.Vulnerability   `json:"vulnerabilities"`
	TaskLogs         []models.TaskLog         `json:"task_logs"`
	ExportTime       time.Time                `json:"export_time"`
}

func writeCSVRecord(writer *csv.Writer, record []string) error {
	safe := make([]string, len(record))
	for index, value := range record {
		safe[index] = spreadsheetSafeCSV(value)
	}
	return writer.Write(safe)
}

func spreadsheetSafeCSV(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if value != "" && (value[0] == '\t' || value[0] == '\r') {
		return "'" + value
	}
	if trimmed == "" {
		return value
	}
	switch trimmed[0] {
	case '=', '+', '-', '@':
		return "'" + value
	default:
		return value
	}
}

func flushCSV(writer *csv.Writer) error {
	writer.Flush()
	return writer.Error()
}

// ExportIPsToCSV exports task IP assets.
func (e *Exporter) ExportIPsToCSV(ips []models.IP, taskID string) (string, error) {
	filename := fmt.Sprintf("%s/ips_%s_%s.csv", e.outputDir, taskID, time.Now().Format("20060102_150405"))
	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	file.Write([]byte{0xEF, 0xBB, 0xBF})
	writer := csv.NewWriter(file)
	if err := writeCSVRecord(writer, []string{"IPAddress", "Associate domain name", "Source", "Operating system", "Location", "CDN", "Created"}); err != nil {
		return "", err
	}
	for _, item := range ips {
		if err := writeCSVRecord(writer, []string{item.IPAddress, item.Domain, item.Source, item.OS, item.Location, fmt.Sprintf("%t", item.CDN), item.CreatedAt.Format("2006-01-02 15:04:05")}); err != nil {
			return "", err
		}
	}
	if err := flushCSV(writer); err != nil {
		return "", err
	}
	return filename, nil
}

// ExportToJSON Export AsJSON
func (e *Exporter) ExportToJSON(data *ExportData) (string, error) {
	filename := fmt.Sprintf("%s/task_%s_%s.json",
		e.outputDir,
		data.Task.ID,
		time.Now().Format("20060102_150405"))

	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(data); err != nil {
		return "", err
	}

	return filename, nil
}

// ExportDomainsToCSV Export domain nameCSV
func (e *Exporter) ExportDomainsToCSV(domains []models.Domain, taskID string) (string, error) {
	filename := fmt.Sprintf("%s/domains_%s_%s.csv",
		e.outputDir,
		taskID,
		time.Now().Format("20060102_150405"))

	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 🆕 WriteUTF-8 BOM, Jean.ExcelCorrect recognition in Chinese
	file.Write([]byte{0xEF, 0xBB, 0xBF})

	writer := csv.NewWriter(file)

	// Write to table header
	headers := []string{"Domain name", "IPAddress", "Source", "CDN", "Created"}
	if err := writeCSVRecord(writer, headers); err != nil {
		return "", err
	}

	// Writing Data
	for _, domain := range domains {
		record := []string{
			domain.Domain,
			domain.IPAddress,
			domain.Source,
			fmt.Sprintf("%t", domain.CDN),
			domain.CreatedAt.Format("2006-01-02 15:04:05"),
		}
		if err := writeCSVRecord(writer, record); err != nil {
			return "", err
		}
	}
	if err := flushCSV(writer); err != nil {
		return "", err
	}

	return filename, nil
}

// ExportPortsToCSV Export Port AsCSV
func (e *Exporter) ExportPortsToCSV(ports []models.Port, taskID string) (string, error) {
	filename := fmt.Sprintf("%s/ports_%s_%s.csv",
		e.outputDir,
		taskID,
		time.Now().Format("20060102_150405"))

	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 🆕 WriteUTF-8 BOM
	file.Write([]byte{0xEF, 0xBB, 0xBF})

	writer := csv.NewWriter(file)

	// Write to table header
	headers := []string{"IPAddress", "Port", "Agreement", "Services", "Version", "Banner"}
	if err := writeCSVRecord(writer, headers); err != nil {
		return "", err
	}

	// Writing Data
	for _, port := range ports {
		record := []string{
			port.IPAddress,
			fmt.Sprintf("%d", port.Port),
			port.Protocol,
			port.Service,
			port.Version,
			truncateString(port.Banner, 100),
		}
		if err := writeCSVRecord(writer, record); err != nil {
			return "", err
		}
	}
	if err := flushCSV(writer); err != nil {
		return "", err
	}

	return filename, nil
}

// ExportSitesToCSV Export Site AsCSV
func (e *Exporter) ExportSitesToCSV(sites []models.Site, taskID string) (string, error) {
	filename := fmt.Sprintf("%s/sites_%s_%s.csv",
		e.outputDir,
		taskID,
		time.Now().Format("20060102_150405"))

	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 🆕 WriteUTF-8 BOM
	file.Write([]byte{0xEF, 0xBB, 0xBF})

	writer := csv.NewWriter(file)

	// Write to table header
	headers := []string{"URL", "Title", "Status Code", "Server", "Fingerprints", "Screenshot"}
	if err := writeCSVRecord(writer, headers); err != nil {
		return "", err
	}

	// Writing Data
	for _, site := range sites {
		fingerprints := ""
		if len(site.Fingerprints) > 0 {
			fingerprintsBytes, _ := json.Marshal(site.Fingerprints)
			fingerprints = string(fingerprintsBytes)
		}

		record := []string{
			site.URL,
			site.Title,
			fmt.Sprintf("%d", site.StatusCode),
			site.Server,
			fingerprints,
			site.Screenshot,
		}
		if err := writeCSVRecord(writer, record); err != nil {
			return "", err
		}
	}
	if err := flushCSV(writer); err != nil {
		return "", err
	}

	return filename, nil
}

// ExportVulnerabilitiesToCSV Export bugs asCSV
func (e *Exporter) ExportVulnerabilitiesToCSV(vulns []models.Vulnerability, taskID string) (string, error) {
	filename := fmt.Sprintf("%s/vulnerabilities_%s_%s.csv",
		e.outputDir,
		taskID,
		time.Now().Format("20060102_150405"))

	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 🆕 WriteUTF-8 BOM
	file.Write([]byte{0xEF, 0xBB, 0xBF})

	writer := csv.NewWriter(file)

	// Write to table header
	headers := []string{"URL", "Type", "Severity", "Status", "Title", "Source", "Latest retest result", "Latest retest time", "Description", "Payload", "Proof", "Triage notes", "Solutions"}
	if err := writeCSVRecord(writer, headers); err != nil {
		return "", err
	}

	// Writing Data
	for _, vuln := range vulns {
		record := []string{
			vuln.URL,
			vuln.Type,
			vuln.Severity,
			findingStatusLabel(vuln.Status),
			vuln.Title,
			vuln.Source,
			verificationResultLabel(vuln.LastVerificationResult),
			formatOptionalTime(vuln.LastVerifiedAt),
			truncateString(vuln.Description, 200),
			vuln.Payload,
			vuln.Proof,
			vuln.TriageNote,
			truncateString(vuln.Solution, 200),
		}
		if err := writeCSVRecord(writer, record); err != nil {
			return "", err
		}
	}
	if err := flushCSV(writer); err != nil {
		return "", err
	}

	return filename, nil
}

// ExportURLsToCSV exports crawler results with the fields used by the task workbench.
func (e *Exporter) ExportURLsToCSV(urls []models.CrawlerResult, taskID string) (string, error) {
	filename := fmt.Sprintf("%s/urls_%s_%s.csv", e.outputDir, taskID, time.Now().Format("20060102_150405"))
	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	file.Write([]byte{0xEF, 0xBB, 0xBF})
	writer := csv.NewWriter(file)
	if err := writeCSVRecord(writer, []string{"URL", "Methodology", "Status Code", "Content-Type", "Response Length", "Source", "Created"}); err != nil {
		return "", err
	}
	for _, item := range urls {
		if err := writeCSVRecord(writer, []string{item.URL, item.Method, fmt.Sprintf("%d", item.StatusCode), item.ContentType, fmt.Sprintf("%d", item.ContentLength), item.Source, item.CreatedAt.Format("2006-01-02 15:04:05")}); err != nil {
			return "", err
		}
	}
	if err := flushCSV(writer); err != nil {
		return "", err
	}
	return filename, nil
}

// ExportHTTPTransactionsToCSV exports captured request/response metadata.
func (e *Exporter) ExportHTTPTransactionsToCSV(items []models.HTTPTransaction, taskID string) (string, error) {
	filename := fmt.Sprintf("%s/http_%s_%s.csv", e.outputDir, taskID, time.Now().Format("20060102_150405"))
	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	file.Write([]byte{0xEF, 0xBB, 0xBF})
	writer := csv.NewWriter(file)
	if err := writeCSVRecord(writer, []string{"URL", "Methodology", "Status Code", "Content-Type", "Response Length", "Response time-consuming(ms)", "Source", "Created"}); err != nil {
		return "", err
	}
	for _, item := range items {
		if err := writeCSVRecord(writer, []string{item.URL, item.Method, fmt.Sprintf("%d", item.ResponseStatusCode), item.ResponseContentType, fmt.Sprintf("%d", item.ResponseContentLength), fmt.Sprintf("%d", item.ResponseTimeMs), item.Source, item.CreatedAt.Format("2006-01-02 15:04:05")}); err != nil {
			return "", err
		}
	}
	if err := flushCSV(writer); err != nil {
		return "", err
	}
	return filename, nil
}

// ExportAll Export All Data
func (e *Exporter) ExportAll(data *ExportData) (map[string]string, error) {
	results := make(map[string]string)

	// JSON
	jsonFile, err := e.ExportToJSON(data)
	if err == nil {
		results["json"] = jsonFile
	}

	// Domain nameCSV
	if len(data.Domains) > 0 {
		csvFile, err := e.ExportDomainsToCSV(data.Domains, data.Task.ID)
		if err == nil {
			results["domains_csv"] = csvFile
		}
	}
	if len(data.IPs) > 0 {
		csvFile, err := e.ExportIPsToCSV(data.IPs, data.Task.ID)
		if err == nil {
			results["ips_csv"] = csvFile
		}
	}

	// PortCSV
	if len(data.Ports) > 0 {
		csvFile, err := e.ExportPortsToCSV(data.Ports, data.Task.ID)
		if err == nil {
			results["ports_csv"] = csvFile
		}
	}

	// SiteCSV
	if len(data.Sites) > 0 {
		csvFile, err := e.ExportSitesToCSV(data.Sites, data.Task.ID)
		if err == nil {
			results["sites_csv"] = csvFile
		}
	}
	if len(data.URLs) > 0 {
		csvFile, err := e.ExportURLsToCSV(data.URLs, data.Task.ID)
		if err == nil {
			results["urls_csv"] = csvFile
		}
	}
	if len(data.HTTPTransactions) > 0 {
		csvFile, err := e.ExportHTTPTransactionsToCSV(data.HTTPTransactions, data.Task.ID)
		if err == nil {
			results["http_csv"] = csvFile
		}
	}

	// LeaksCSV
	if len(data.Vulnerabilities) > 0 {
		csvFile, err := e.ExportVulnerabilitiesToCSV(data.Vulnerabilities, data.Task.ID)
		if err == nil {
			results["vulns_csv"] = csvFile
		}
	}

	return results, nil
}

// truncateString Cut String
func truncateString(s string, maxLen int) string {
	if maxLen < 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}

// GenerateReport Generate Report
func (e *Exporter) GenerateReport(data *ExportData) (string, error) {
	if data == nil || data.Task == nil {
		return "", fmt.Errorf("report task is required")
	}
	filename := filepath.Join(e.outputDir, fmt.Sprintf("report_%s_%s.html",
		data.Task.ID,
		time.Now().Format("20060102_150405")))

	html, err := generateHTMLReport(data)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filename, []byte(html), 0600); err != nil {
		return "", err
	}

	return filename, nil
}

var reportTemplate = template.Must(template.New("eclipse-report").Funcs(template.FuncMap{
	"safeURL":            safeReportURL,
	"severityClass":      reportSeverityClass,
	"findingStatus":      findingStatusLabel,
	"verificationResult": verificationResultLabel,
	"optionalTime":       formatOptionalTime,
	"activeFindingCount": activeFindingCount,
}).Parse(`<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="referrer" content="no-referrer">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'">
    <title>Eclipse Recon Reconnaissance report - {{.Task.ID}}</title>
    <style>
        :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
        * { box-sizing: border-box; }
        body { margin: 0; color: #e7edf0; background: #090b10; line-height: 1.55; }
        a { color: #53dfc0; overflow-wrap: anywhere; }
        .container { width: min(1180px, calc(100% - 40px)); margin: 0 auto; padding: 36px 0 64px; }
        header { display: flex; justify-content: space-between; gap: 24px; align-items: end; padding-bottom: 24px; border-bottom: 1px solid #29313b; }
        .eyebrow { margin: 0 0 8px; color: #53dfc0; font: 700 12px/1.2 ui-monospace, SFMono-Regular, Menlo, monospace; text-transform: uppercase; }
        h1 { margin: 0; font-size: 32px; letter-spacing: 0; }
        h2 { margin: 34px 0 12px; font-size: 18px; }
        .report-id { color: #8b99a5; font: 12px ui-monospace, SFMono-Regular, Menlo, monospace; }
        .info { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1px; margin: 24px 0; border: 1px solid #29313b; background: #29313b; }
        .info div { min-width: 0; padding: 14px 16px; background: #11151b; }
        .info span, .stat-card span { display: block; color: #8b99a5; font-size: 11px; }
        .info strong { display: block; margin-top: 4px; overflow-wrap: anywhere; }
        .stats { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 10px; }
        .stat-card { padding: 14px 16px; border: 1px solid #29313b; background: #11151b; }
        .stat-card strong { display: block; margin-top: 5px; color: #53dfc0; font: 700 24px ui-monospace, SFMono-Regular, Menlo, monospace; }
        .table-wrap { overflow-x: auto; border: 1px solid #29313b; }
        table { width: 100%; min-width: 720px; border-collapse: collapse; background: #11151b; }
        th, td { padding: 11px 12px; text-align: left; vertical-align: top; border-bottom: 1px solid #29313b; overflow-wrap: anywhere; }
        th { color: #8b99a5; background: #0d1015; font-size: 11px; }
        tr:last-child td { border-bottom: 0; }
        .severity-critical, .severity-high { color: #ff6b7a; font-weight: 700; }
        .severity-medium { color: #f0be5d; font-weight: 700; }
        .severity-low, .severity-info { color: #53dfc0; }
        details { margin-top: 9px; }
        summary { width: fit-content; color: #53dfc0; cursor: pointer; font-size: 12px; }
        .evidence { display: grid; gap: 8px; margin-top: 10px; }
        .evidence section { border-left: 2px solid #29313b; padding-left: 10px; }
        .evidence span { display: block; color: #8b99a5; font-size: 10px; text-transform: uppercase; }
        pre { margin: 4px 0 0; white-space: pre-wrap; overflow-wrap: anywhere; color: #d7e0e5; font: 11px/1.55 ui-monospace, SFMono-Regular, Menlo, monospace; }
        .empty { margin: 0; padding: 18px; color: #8b99a5; border: 1px solid #29313b; background: #11151b; }
        footer { margin-top: 28px; color: #697681; font-size: 11px; }
        @media (max-width: 760px) { .container { width: min(100% - 24px, 1180px); padding-top: 24px; } header { align-items: start; flex-direction: column; } .info { grid-template-columns: 1fr; } .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
    </style>
</head>
<body>
    <div class="container">
        <header><div><p class="eyebrow">Eclipse Recon / Authorized Reconnaissance</p><h1>Asset detection reports</h1></div><div class="report-id">TASK {{.Task.ID}}</div></header>
        <div class="info">
            <div><span>Task Name</span><strong>{{.Task.Name}}</strong></div>
            <div><span>Mandated objectives</span><strong>{{.Task.Target}}</strong></div>
            <div><span>Created</span><strong>{{.Task.CreatedAt.Format "2006-01-02 15:04:05"}}</strong></div>
            <div><span>Export Time</span><strong>{{.ExportTime.Format "2006-01-02 15:04:05"}}</strong></div>
        </div>

        <h2>Asset statistics</h2>
        <div class="stats">
            <div class="stat-card"><span>Domain name</span><strong>{{len .Domains}}</strong></div>
            <div class="stat-card"><span>IP</span><strong>{{len .IPs}}</strong></div>
            <div class="stat-card"><span>Open Port</span><strong>{{len .Ports}}</strong></div>
            <div class="stat-card"><span>Site</span><strong>{{len .Sites}}</strong></div>
            <div class="stat-card"><span>Effective risk</span><strong>{{activeFindingCount .Vulnerabilities}}</strong></div>
        </div>

        <h2>Plugging evidence and sentencing</h2>
        {{if .Vulnerabilities}}<div class="table-wrap"><table><thead><tr><th>Level</th><th>Status / Latest retest result</th><th>Title and evidence</th><th>Objective</th><th>Type / Source</th></tr></thead><tbody>{{range .Vulnerabilities}}<tr><td class="severity-{{severityClass .Severity}}">{{.Severity}}</td><td><strong>{{findingStatus .Status}}</strong><br>{{verificationResult .LastVerificationResult}}{{with .LastVerifiedAt}}<br>{{optionalTime .}}{{end}}</td><td><strong>{{.Title}}</strong>{{if or .Description .Payload .Proof .TriageNote .Solution .Reference}}<details><summary>View complete evidence</summary><div class="evidence">{{with .Description}}<section><span>Description</span><pre>{{.}}</pre></section>{{end}}{{with .Payload}}<section><span>Payload</span><pre>{{.}}</pre></section>{{end}}{{with .Proof}}<section><span>Proof</span><pre>{{.}}</pre></section>{{end}}{{with .TriageNote}}<section><span>Triage notes</span><pre>{{.}}</pre></section>{{end}}{{with .Solution}}<section><span>Remediation guidance</span><pre>{{.}}</pre></section>{{end}}{{with .Reference}}<section><span>References</span><pre>{{.}}</pre></section>{{end}}</div></details>{{end}}</td><td>{{.URL}}</td><td>{{.Type}}{{with .Source}} / {{.}}{{end}}</td></tr>{{end}}</tbody></table></div>{{else}}<p class="empty">No findings were recorded.</p>{{end}}

        <h2>Domain name</h2>
        {{if .Domains}}<div class="table-wrap"><table><thead><tr><th>Domain name</th><th>IP Address</th><th>Source</th></tr></thead><tbody>{{range .Domains}}<tr><td>{{.Domain}}</td><td>{{.IPAddress}}</td><td>{{.Source}}</td></tr>{{end}}</tbody></table></div>{{else}}<p class="empty">No domain name found</p>{{end}}

        <h2>Site</h2>
        {{if .Sites}}<div class="table-wrap"><table><thead><tr><th>URL</th><th>Title</th><th>Status Code</th><th>Server</th></tr></thead><tbody>{{range .Sites}}{{$site := .}}<tr><td>{{with safeURL .URL}}<a href="{{.}}" target="_blank" rel="noopener noreferrer">{{$site.URL}}</a>{{else}}{{$site.URL}}{{end}}</td><td>{{.Title}}</td><td>{{.StatusCode}}</td><td>{{.Server}}</td></tr>{{end}}</tbody></table></div>{{else}}<p class="empty">No site found</p>{{end}}
        <footer>Summary of the report Eclipse Recon Generate.The report was based on scanned evidence within the scope of the mandate, Please review manually before submitting.</footer>
    </div>
</body>
</html>`))

// generateHTMLReport renders untrusted reconnaissance output through
// html/template so evidence can never become executable report markup.
func generateHTMLReport(data *ExportData) (string, error) {
	if data == nil || data.Task == nil {
		return "", fmt.Errorf("report task is required")
	}
	var output bytes.Buffer
	if err := reportTemplate.Execute(&output, data); err != nil {
		return "", err
	}
	return output.String(), nil
}

func safeReportURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" || parsed.User != nil {
		return ""
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		return parsed.String()
	default:
		return ""
	}
}

func reportSeverityClass(value string) string {
	switch severity := strings.ToLower(strings.TrimSpace(value)); severity {
	case "critical", "high", "medium", "low", "info":
		return severity
	default:
		return "info"
	}
}

func findingStatusLabel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case models.VulnerabilityStatusValidated:
		return "Verifyed"
	case models.VulnerabilityStatusSubmitted:
		return "Submitted"
	case models.VulnerabilityStatusResolved:
		return "Resolved"
	case models.VulnerabilityStatusFalsePositive:
		return "Misreporting"
	case models.VulnerabilityStatusRegressed:
		return "Relapsing"
	default:
		return "New Discovery"
	}
}

func verificationResultLabel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "vulnerable":
		return "Recently hit."
	case "safe":
		return "Not recently recreated"
	case "error":
		return "Reaction Failed"
	default:
		return "Not yet recovered"
	}
}

func formatOptionalTime(value *time.Time) string {
	if value == nil || value.IsZero() {
		return ""
	}
	return value.UTC().Format("2006-01-02 15:04:05 UTC")
}

func activeFindingCount(findings []models.Vulnerability) int {
	count := 0
	for _, finding := range findings {
		status := strings.ToLower(strings.TrimSpace(finding.Status))
		if status != models.VulnerabilityStatusResolved && status != models.VulnerabilityStatusFalsePositive {
			count++
		}
	}
	return count
}

// CleanupOldExports Clean out export files that exceed the specified length
func (e *Exporter) CleanupOldExports(maxAge time.Duration) (int, error) {
	var deleted int
	err := filepath.Walk(e.outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if time.Since(info.ModTime()) > maxAge {
			if err := os.Remove(path); err == nil {
				deleted++
			}
		}
		return nil
	})
	return deleted, err
}

// StartPeriodicCleanup Start of regular clean-up missions
func (e *Exporter) StartPeriodicCleanup(interval, maxAge time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			deleted, err := e.CleanupOldExports(maxAge)
			if err != nil {
				logger.Error("Export cleanup error: %v", err)
			} else if deleted > 0 {
				logger.Info("Export cleanup: deleted %d old files", deleted)
			}
		}
	}()
}
