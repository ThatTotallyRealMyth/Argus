package scanner

import (
	"fmt"
	"strings"
	"sync"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
)

// SmartPoCScanner SmartPoCScanner - It's based on a fingerprint smart match.PoC
// Duties: - I'm gonna coordinate the fingerprint matching and--PoCImplementation process, Do not directly process matching and execute logic
type SmartPoCScanner struct {
	pocMatcher    *PoCMatcher
	executor      *PoCExecutor
	maxConcurrent int // Maximum number of simultaneouss
}

// NewSmartPoCScanner Create SmartPoCScanner
func NewSmartPoCScanner() *SmartPoCScanner {
	return &SmartPoCScanner{
		pocMatcher:    NewPoCMatcher(),
		executor:      NewPoCExecutor(),
		maxConcurrent: 10, // Default10It's a couple.
	}
}

// ScanWithFingerprints Use fingerprints to be smart.PoCScan
// Process: 1. Get Sites → 2. Fingerprints. → 3. MatchPoC → 4. And then it's going to be implemented. → 5. Save Results
func (sps *SmartPoCScanner) ScanWithFingerprints(ctx *ScanContext) error {
	ctx.Logger.Printf("=== Smart PoC Scanner Started ===")

	// 1. Get All Sites
	var sites []models.Site
	if err := database.DB.Where("task_id = ?", ctx.Task.ID).Find(&sites).Error; err != nil {
		return fmt.Errorf("failed to get sites: %w", err)
	}

	if len(sites) == 0 {
		ctx.Logger.Printf("No sites found for PoC scanning")
		return nil
	}

	ctx.Logger.Printf("Found %d sites for PoC scanning", len(sites))

	// 2. And send out a scan of all sites.
	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, sps.maxConcurrent)
	totalVulnerabilities := 0
	scannedTargets := make(map[string]bool)

	for _, site := range sites {
		// Check if the task has been cancelled
		select {
		case <-ctx.Ctx.Done():
			ctx.Logger.Printf("PoC scan cancelled by user")
			wg.Wait()
			return ctx.Ctx.Err()
		default:
		}

		// - Go heavy.: Skipped ScannedURL
		mu.Lock()
		if scannedTargets[site.URL] {
			mu.Unlock()
			continue
		}
		scannedTargets[site.URL] = true
		mu.Unlock()

		wg.Add(1)
		go func(s models.Site) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Scan individual sites
			vulns := sps.scanSingleSite(ctx, s)

			// Save bugs to database
			if len(vulns) > 0 {
				mu.Lock()
				for _, vuln := range vulns {
					if err := database.DB.Create(vuln).Error; err != nil {
						ctx.Logger.Printf("Failed to save vulnerability: %v", err)
					}
				}
				totalVulnerabilities += len(vulns)
				ctx.Logger.Printf("[!] Found %d vulnerabilities on %s", len(vulns), s.URL)
				mu.Unlock()
			}
		}(site)
	}

	wg.Wait()

	ctx.Logger.Printf("=== PoC Scan Complete ===")
	ctx.Logger.Printf("Scanned %d sites, found %d vulnerabilities", len(sites), totalVulnerabilities)

	return nil
}

// scanSingleSite Scan individual sites (Extract as standalone method, Easy to test and maintain)
func (sps *SmartPoCScanner) scanSingleSite(ctx *ScanContext, site models.Site) []*models.Vulnerability {
	if err := ctx.ValidateNetworkTarget(site.URL); err != nil {
		ctx.Logger.Printf("PoC target blocked by scan scope: %s", site.URL)
		return nil
	}
	// 1. Take the site fingerprints.
	fingerprints := extractFingerprints(site)
	if len(fingerprints) == 0 {
		ctx.Logger.Printf("No fingerprints for %s, skipping", site.URL)
		return nil
	}

	ctx.Logger.Printf("Site %s fingerprints: %v", site.URL, fingerprints)

	// 2. It's a fingerprint match.PoC
	matchedPoCs, err := sps.pocMatcher.MatchPoCsByFingerprints(fingerprints)
	if err != nil {
		ctx.Logger.Printf("Failed to match PoCs for %s: %v", site.URL, err)
		return nil
	}

	if len(matchedPoCs) == 0 {
		ctx.Logger.Printf("No matching PoCs for %s", site.URL)
		return nil
	}

	ctx.Logger.Printf("Matched %d PoCs for %s", len(matchedPoCs), site.URL)

	// 3. Execute MatchesPoC
	return sps.executeMatchedPoCs(ctx, site.URL, matchedPoCs)
}

// executeMatchedPoCs Execute MatchesPoCList
func (sps *SmartPoCScanner) executeMatchedPoCs(ctx *ScanContext, target string, pocs []models.PoC) []*models.Vulnerability {
	var vulnerabilities []*models.Vulnerability

	ctx.Logger.Printf("Executing %d PoCs against %s", len(pocs), target)

	for _, poc := range pocs {
		// Check Cancel
		select {
		case <-ctx.Ctx.Done():
			return vulnerabilities
		default:
		}

		// Skip UnablePoC
		if !poc.IsEnabled {
			continue
		}
		if ctx.ValidateTarget != nil && strings.ToLower(strings.TrimSpace(poc.PoCType)) != "custom" {
			ctx.Logger.Printf("Skipping PoC %s: scope-enforced tasks only run same-origin custom PoCs", poc.Name)
			continue
		}

		ctx.Logger.Printf("Testing PoC: %s on %s", poc.Name, target)

		// ImplementationPoC (Use sharedexecutorExample)
		result, err := sps.executor.Execute(&poc, target)
		if err != nil {
			ctx.Logger.Printf("Failed to execute PoC %s: %v", poc.Name, err)
			continue
		}

		// We've got a leak.
		if result.Vulnerable {
			vuln := &models.Vulnerability{
				TaskID:      ctx.Task.ID,
				URL:         target,
				Type:        "poc",
				VulnType:    poc.Category,
				Severity:    poc.Severity,
				Title:       poc.Name,
				Description: fmt.Sprintf("%s\n\nDetails: %s", poc.Description, result.Details),
				Reference:   poc.Reference,
				Source:      "smart_poc",
			}
			vulnerabilities = append(vulnerabilities, vuln)
			ctx.Logger.Printf("[VULN] %s - %s: %s", target, poc.Name, result.Message)
		}
	}

	ctx.Logger.Printf("Completed PoC scan for %s, found %d vulnerabilities", target, len(vulnerabilities))
	return vulnerabilities
}

// extractFingerprints Take the site fingerprints. (Independent Functions, Not dependent scanner Example)
func extractFingerprints(site models.Site) []string {
	var fingerprints []string
	seen := make(map[string]bool)

	// Fingerprints from multiple fields
	sources := []string{
		site.Fingerprint,
		site.Server,
	}

	for _, source := range sources {
		if source == "" {
			continue
		}

		// Multiple fingerprints supported by comma separated
		parts := splitAndTrim(source)
		for _, part := range parts {
			if part != "" && !seen[part] {
				fingerprints = append(fingerprints, part)
				seen[part] = true
			}
		}
	}

	// FromFingerprintsPlural Field Extract
	for _, fp := range site.Fingerprints {
		if fp != "" && !seen[fp] {
			fingerprints = append(fingerprints, fp)
			seen[fp] = true
		}
	}

	// FromTitleExtracting a specific keyword
	if site.Title != "" {
		keywords := []string{"Tomcat", "WebLogic", "JBoss", "WordPress", "Joomla", "Drupal", "phpMyAdmin", "Jenkins"}
		titleLower := strings.ToLower(site.Title)
		for _, keyword := range keywords {
			if strings.Contains(titleLower, strings.ToLower(keyword)) && !seen[keyword] {
				fingerprints = append(fingerprints, keyword)
				seen[keyword] = true
			}
		}
	}

	return fingerprints
}

// splitAndTrim Split and clean strings (Tool Functions)
func splitAndTrim(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// GetMatchingPoCsForSite Get site matchesPoC (ForAPIPreview)
func (sps *SmartPoCScanner) GetMatchingPoCsForSite(siteID string) ([]models.PoC, error) {
	var site models.Site
	if err := database.DB.First(&site, "id = ?", siteID).Error; err != nil {
		return nil, err
	}

	fingerprints := extractFingerprints(site)
	return sps.pocMatcher.MatchPoCsByFingerprints(fingerprints)
}
