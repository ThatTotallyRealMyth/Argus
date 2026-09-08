package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

// WebInfoHunter Scanner
type WebInfoHunter struct {
	binPath string
}

// NewWebInfoHunter CreateWIHScanner
func NewWebInfoHunter(binPath string) *WebInfoHunter {
	if binPath == "" {
		binPath = "webinfohunter" // Supposed to bePATHMedium
	}
	return &WebInfoHunter{
		binPath: binPath,
	}
}

// WIHResult WIHScan Results
type WIHResult struct {
	URL               string   `json:"url"`
	Domains           []string `json:"domains"`
	Subdomains        []string `json:"subdomains"`
	AccessKeys        []string `json:"access_keys"`
	SecretKeys        []string `json:"secret_keys"`
	APIKeys           []string `json:"api_keys"`
	Tokens            []string `json:"tokens"`
	InternalIPs       []string `json:"internal_ips"`
	Emails            []string `json:"emails"`
	PhoneNumbers      []string `json:"phone_numbers"`
	APIEndpoints      []string `json:"api_endpoints"`
	SuspiciousStrings []string `json:"suspicious_strings"`
}

// Scan ImplementationWIHScan
func (wih *WebInfoHunter) Scan(ctx *ScanContext, urls []string) ([]*WIHResult, error) {
	return wih.ScanWithURLValidator(ctx, urls, nil)
}

func (wih *WebInfoHunter) ScanWithURLValidator(ctx *ScanContext, urls []string, validateURL func(string) error) ([]*WIHResult, error) {
	if len(urls) == 0 {
		return nil, nil
	}

	ctx.Logger.Printf("Running WebInfoHunter on %d URLs", len(urls))

	var results []*WIHResult

	// BecauseWIHIt may not exist., We use crawler to extract.JSInformation as an alternative
	crawler := NewCrawlerWithConfig(CrawlerConfig{MaxDepth: 3, MaxPages: 100, Timeout: 10 * time.Second, ValidateURL: validateURL})

	for _, targetURL := range urls {
		if validateURL != nil {
			if err := validateURL(targetURL); err != nil {
				return nil, err
			}
		}
		result := &WIHResult{
			URL:          targetURL,
			Domains:      []string{},
			Subdomains:   []string{},
			AccessKeys:   []string{},
			SecretKeys:   []string{},
			APIKeys:      []string{},
			Tokens:       []string{},
			InternalIPs:  []string{},
			Emails:       []string{},
			PhoneNumbers: []string{},
			APIEndpoints: []string{},
		}

		// Fetching Page Contents
		resp, err := crawler.client.Get(targetURL)
		if err != nil {
			ctx.Logger.Printf("Failed to fetch %s: %v", targetURL, err)
			if validateURL != nil {
				return nil, err
			}
			continue
		}

		body, err := readResponseBody(resp)
		resp.Body.Close()
		if err != nil {
			continue
		}

		// ExtractJSDocumentation
		jsFiles := crawler.ExtractJSFiles(string(body), targetURL)
		ctx.Logger.Printf("Found %d JS files in %s", len(jsFiles), targetURL)

		// Analyse eachJSDocumentation
		for _, jsURL := range jsFiles {
			if validateURL != nil {
				if err := validateURL(jsURL); err != nil {
					return nil, err
				}
			}
			jsResp, err := crawler.client.Get(jsURL)
			if err != nil {
				if validateURL != nil {
					return nil, err
				}
				continue
			}

			jsBody, err := readResponseBody(jsResp)
			jsResp.Body.Close()
			if err != nil {
				continue
			}

			jsContent := string(jsBody)

			// Can not open message
			subdomains := crawler.ExtractSubdomains(jsContent)
			result.Subdomains = append(result.Subdomains, subdomains...)

			apis := crawler.ExtractAPIs(jsContent)
			result.APIEndpoints = append(result.APIEndpoints, apis...)

			sensitive := crawler.ExtractSensitiveInfo(jsContent)
			if keys, ok := sensitive["access_key"]; ok {
				result.AccessKeys = append(result.AccessKeys, keys...)
			}
			if keys, ok := sensitive["secret_key"]; ok {
				result.SecretKeys = append(result.SecretKeys, keys...)
			}
			if keys, ok := sensitive["api_key"]; ok {
				result.APIKeys = append(result.APIKeys, keys...)
			}
			if tokens, ok := sensitive["token"]; ok {
				result.Tokens = append(result.Tokens, tokens...)
			}
			if ips, ok := sensitive["internal_ip"]; ok {
				result.InternalIPs = append(result.InternalIPs, ips...)
			}

			// Mailbox Rip
			emails := extractEmails(jsContent)
			result.Emails = append(result.Emails, emails...)
		}

		// - Go heavy.
		result.Subdomains = uniqueStrings(result.Subdomains)
		result.APIEndpoints = uniqueStrings(result.APIEndpoints)
		result.AccessKeys = uniqueStrings(result.AccessKeys)
		result.SecretKeys = uniqueStrings(result.SecretKeys)
		result.APIKeys = uniqueStrings(result.APIKeys)
		result.Tokens = uniqueStrings(result.Tokens)
		result.InternalIPs = uniqueStrings(result.InternalIPs)
		result.Emails = uniqueStrings(result.Emails)

		if len(result.Subdomains) > 0 || len(result.AccessKeys) > 0 || len(result.APIEndpoints) > 0 {
			results = append(results, result)
		}
	}

	return results, nil
}

// ScanWithBinary Scan with binary files
func (wih *WebInfoHunter) ScanWithBinary(urls []string) ([]*WIHResult, error) {
	if !checkWIHInstalled(wih.binPath) {
		return nil, fmt.Errorf("WebInfoHunter not installed")
	}

	var results []*WIHResult

	for _, url := range urls {
		cmd := exec.Command(wih.binPath, "-u", url, "-j")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			continue
		}

		if err := cmd.Start(); err != nil {
			continue
		}

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			var result WIHResult
			if err := json.Unmarshal([]byte(line), &result); err == nil {
				results = append(results, &result)
			}
		}

		cmd.Wait()
	}

	return results, nil
}

// SaveResults SaveWIHOutcome
func (wih *WebInfoHunter) SaveResults(ctx *ScanContext, results []*WIHResult) error {
	// Get the destination domain name list
	targets := ctx.TargetList()
	domainScanner := NewDomainScanner()

	for _, result := range results {
		// Save discovered subdomain names (Require authentication)
		for _, subdomain := range result.Subdomains {
			subdomain = strings.ToLower(strings.TrimSpace(subdomain))
			if subdomain == "" {
				continue
			}

			// Verify whether domain names belong to any of the target domain names
			isValidDomain := false
			for _, target := range targets {
				if domainScanner.isSubdomainOf(subdomain, target) {
					isValidDomain = true
					break
				}
			}

			if isValidDomain {
				domain := &models.Domain{
					TaskID: ctx.Task.ID,
					Domain: subdomain,
					Source: "webinfohunter",
				}
				ctx.DB.Where("task_id = ? AND domain = ?", ctx.Task.ID, subdomain).FirstOrCreate(domain)
			}
		}

		// SaveAPIEnd
		for _, api := range result.APIEndpoints {
			url := &models.URL{
				TaskID: ctx.Task.ID,
				URL:    result.URL + api,
				Source: "webinfohunter",
			}
			ctx.DB.Create(url)
		}

		// If you find sensitive information,, Create a bug record
		if len(result.AccessKeys) > 0 || len(result.SecretKeys) > 0 || len(result.APIKeys) > 0 {
			description := ""
			if len(result.AccessKeys) > 0 {
				description += fmt.Sprintf("Access Keys: %d\n", len(result.AccessKeys))
			}
			if len(result.SecretKeys) > 0 {
				description += fmt.Sprintf("Secret Keys: %d\n", len(result.SecretKeys))
			}
			if len(result.APIKeys) > 0 {
				description += fmt.Sprintf("API Keys: %d\n", len(result.APIKeys))
			}
			if len(result.Tokens) > 0 {
				description += fmt.Sprintf("Tokens: %d\n", len(result.Tokens))
			}

			vuln := &models.Vulnerability{
				TaskID:      ctx.Task.ID,
				URL:         result.URL,
				Type:        "sensitive_info",
				Severity:    "high",
				Title:       "JSDiscreet information found in",
				Description: description,
				Solution:    "RemoveJavaScriptSensitive information in the, Manage using environment variables or secure configurations",
			}
			ctx.DB.Create(vuln)
		}

		// IntranetIPLeak
		if len(result.InternalIPs) > 0 {
			vuln := &models.Vulnerability{
				TaskID:      ctx.Task.ID,
				URL:         result.URL,
				Type:        "info_leak",
				Severity:    "low",
				Title:       "IntranetIPLeak",
				Description: fmt.Sprintf("Found %d I'm an insider.IPAddress: %s", len(result.InternalIPs), strings.Join(result.InternalIPs, ", ")),
				Solution:    "RemoveJavaScriptInner Networks in the MiddleIPAddress",
			}
			ctx.DB.Create(vuln)
		}
	}

	return nil
}

// checkWIHInstalled InspectionWIHWhether installed
func checkWIHInstalled(binPath string) bool {
	cmd := exec.Command(binPath, "-h")
	err := cmd.Run()
	return err == nil
}

// extractEmails Mailbox Address Extracting
func extractEmails(content string) []string {
	// Simple Mailbox Regular
	emails := []string{}
	seen := make(map[string]bool)

	// Find Mailbox Format
	words := strings.Fields(content)
	for _, word := range words {
		if strings.Contains(word, "@") && strings.Contains(word, ".") {
			// Simple Authentication
			parts := strings.Split(word, "@")
			if len(parts) == 2 && len(parts[0]) > 0 && len(parts[1]) > 0 {
				email := strings.ToLower(strings.Trim(word, "\"',;()[]{}"))
				if !seen[email] && isValidEmail(email) {
					seen[email] = true
					emails = append(emails, email)
				}
			}
		}
	}

	return emails
}

// isValidEmail Simple Mailbox Authentication
func isValidEmail(email string) bool {
	if len(email) < 5 || len(email) > 254 {
		return false
	}
	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return false
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	return true
}

// readResponseBody Read Responsebody
func readResponseBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
