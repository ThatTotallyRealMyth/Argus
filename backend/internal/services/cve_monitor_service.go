package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/proxypool"
)

const (
	defaultNVDBaseURL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	maxCVEKeywords      = 5
	maxCVEResults       = 500
	maxCVERecords       = 500
	maxCVEResponseBytes = 8 << 20
)

// CVERecord is the bounded, notification-safe subset of an NVD CVE record.
type CVERecord struct {
	ID           string    `json:"id"`
	Summary      string    `json:"summary"`
	Severity     string    `json:"severity,omitempty"`
	BaseScore    float64   `json:"base_score,omitempty"`
	Published    time.Time `json:"published"`
	LastModified time.Time `json:"last_modified"`
	References   []string  `json:"references,omitempty"`
}

type CVEChange struct {
	Kind string    `json:"kind"` // new or modified
	CVE  CVERecord `json:"cve"`
}

type cveNVDResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				V31 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				V30 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
				V2 []struct {
					CVSSData struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type CVEMonitorService struct {
	Client  *http.Client
	BaseURL string
	Now     func() time.Time
}

func NewCVEMonitorService() *CVEMonitorService {
	return &CVEMonitorService{
		Client:  &http.Client{Timeout: 20 * time.Second, Transport: proxypool.ConfigureTransport(&http.Transport{})},
		BaseURL: defaultNVDBaseURL,
		Now:     time.Now,
	}
}

func ParseCVEKeywords(raw string) []string {
	seen := make(map[string]struct{})
	keywords := make([]string, 0, maxCVEKeywords)
	for _, value := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if len(value) > 120 {
			value = value[:120]
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keywords = append(keywords, value)
		if len(keywords) == maxCVEKeywords {
			break
		}
	}
	return keywords
}

func (s *CVEMonitorService) Search(ctx context.Context, target string, since time.Time) ([]CVERecord, error) {
	keywords := ParseCVEKeywords(target)
	if len(keywords) == 0 {
		return nil, fmt.Errorf("at least one CVE product keyword is required")
	}
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}
	baseURL := strings.TrimSpace(s.BaseURL)
	if baseURL == "" {
		baseURL = defaultNVDBaseURL
	}
	if since.IsZero() {
		since = s.now().Add(-7 * 24 * time.Hour)
	}
	until := s.now().UTC()
	if since.After(until) {
		since = until.Add(-5 * time.Minute)
	}
	resultByID := make(map[string]CVERecord)
	queryErrors := make([]string, 0)
	successfulQueries := 0
	for _, keyword := range keywords {
		parsed, err := url.Parse(baseURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return nil, fmt.Errorf("invalid NVD base URL")
		}
		query := parsed.Query()
		query.Set("keywordSearch", keyword)
		query.Set("lastModStartDate", since.UTC().Format("2006-01-02T15:04:05.000Z"))
		query.Set("lastModEndDate", until.Format("2006-01-02T15:04:05.000Z"))
		query.Set("resultsPerPage", fmt.Sprintf("%d", maxCVEResults))
		parsed.RawQuery = query.Encode()
		records, err := s.fetch(ctx, client, parsed.String())
		if err != nil {
			queryErrors = append(queryErrors, fmt.Sprintf("%s: %v", keyword, err))
			continue
		}
		successfulQueries++
		for _, record := range records {
			if record.ID == "" {
				continue
			}
			resultByID[record.ID] = record
		}
	}
	if successfulQueries == 0 && len(queryErrors) > 0 {
		return nil, fmt.Errorf("all CVE queries failed: %s", strings.Join(queryErrors, "; "))
	}
	results := make([]CVERecord, 0, len(resultByID))
	for _, record := range resultByID {
		results = append(results, record)
	}
	sort.Slice(results, func(i, j int) bool {
		if !results[i].LastModified.Equal(results[j].LastModified) {
			return results[i].LastModified.After(results[j].LastModified)
		}
		return results[i].ID < results[j].ID
	})
	if len(results) > maxCVERecords {
		results = results[:maxCVERecords]
	}
	return results, nil
}

func (s *CVEMonitorService) fetch(ctx context.Context, client *http.Client, endpoint string) ([]CVERecord, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "Eclipse-Recon-CVE-Monitor/1.0")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxCVEResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxCVEResponseBytes {
		return nil, fmt.Errorf("NVD response exceeded %d bytes", maxCVEResponseBytes)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("NVD returned HTTP %d", response.StatusCode)
	}
	var payload cveNVDResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	return normalizeCVERecords(payload), nil
}

func normalizeCVERecords(payload cveNVDResponse) []CVERecord {
	results := make([]CVERecord, 0, len(payload.Vulnerabilities))
	for _, item := range payload.Vulnerabilities {
		cve := item.CVE
		record := CVERecord{ID: strings.TrimSpace(cve.ID)}
		for _, description := range cve.Descriptions {
			if description.Lang == "en" || record.Summary == "" {
				record.Summary = truncateCVEText(description.Value, 4000)
			}
		}
		record.Published, _ = time.Parse(time.RFC3339, cve.Published)
		record.LastModified, _ = time.Parse(time.RFC3339, cve.LastModified)
		for _, reference := range cve.References {
			if value := strings.TrimSpace(reference.URL); value != "" {
				record.References = append(record.References, value)
			}
		}
		record.References = normalizedStrings(record.References)
		if len(record.References) > 10 {
			record.References = record.References[:10]
		}
		if len(cve.Metrics.V31) > 0 {
			record.BaseScore = cve.Metrics.V31[0].CVSSData.BaseScore
			record.Severity = strings.ToLower(cve.Metrics.V31[0].CVSSData.BaseSeverity)
		} else if len(cve.Metrics.V30) > 0 {
			record.BaseScore = cve.Metrics.V30[0].CVSSData.BaseScore
			record.Severity = strings.ToLower(cve.Metrics.V30[0].CVSSData.BaseSeverity)
		} else if len(cve.Metrics.V2) > 0 {
			record.BaseScore = cve.Metrics.V2[0].CVSSData.BaseScore
		}
		results = append(results, record)
	}
	return results
}

func truncateCVEText(value string, limit int) string {
	runes := []rune(strings.TrimSpace(value))
	if len(runes) > limit {
		runes = runes[:limit]
	}
	return string(runes)
}

func DiffCVERecords(previous, current []CVERecord) []CVEChange {
	previousByID := make(map[string]CVERecord, len(previous))
	for _, record := range previous {
		previousByID[record.ID] = record
	}
	changes := make([]CVEChange, 0)
	for _, record := range current {
		old, ok := previousByID[record.ID]
		if !ok {
			changes = append(changes, CVEChange{Kind: "new", CVE: record})
		} else if record.LastModified.After(old.LastModified) {
			changes = append(changes, CVEChange{Kind: "modified", CVE: record})
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].CVE.LastModified != changes[j].CVE.LastModified {
			return changes[i].CVE.LastModified.After(changes[j].CVE.LastModified)
		}
		return changes[i].CVE.ID < changes[j].CVE.ID
	})
	return changes
}

func MergeCVERecords(previous, current []CVERecord) []CVERecord {
	byID := make(map[string]CVERecord, len(previous)+len(current))
	for _, record := range previous {
		if record.ID != "" {
			byID[record.ID] = record
		}
	}
	for _, record := range current {
		if record.ID == "" {
			continue
		}
		old, ok := byID[record.ID]
		if !ok || record.LastModified.After(old.LastModified) {
			byID[record.ID] = record
		}
	}
	merged := make([]CVERecord, 0, len(byID))
	for _, record := range byID {
		merged = append(merged, record)
	}
	sort.Slice(merged, func(i, j int) bool {
		if !merged[i].LastModified.Equal(merged[j].LastModified) {
			return merged[i].LastModified.After(merged[j].LastModified)
		}
		return merged[i].ID < merged[j].ID
	})
	if len(merged) > maxCVERecords {
		merged = merged[:maxCVERecords]
	}
	return merged
}

func (s *CVEMonitorService) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
