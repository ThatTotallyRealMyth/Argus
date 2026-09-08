package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/proxypool"
)

// SiteScanner Site Scanner
type SiteScanner struct {
	client      *http.Client
	crawler     *Crawler
	fingerprint bool
}

// NewSiteScanner Create Site Scanner
func NewSiteScanner() *SiteScanner {
	// Initialization of fingerprint library
	InitFingerprints()

	return &SiteScanner{
		client: &http.Client{
			Timeout: 5 * time.Second, // Optimize: LowerHTTPTimeout's up.5sec
			Transport: proxypool.ConfigureTransport(&http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:        100,              // Optimize: Increase connection pool
				MaxIdleConnsPerHost: 10,               // Optimize: Add eachhostNumber of connections
				IdleConnTimeout:     30 * time.Second, // Optimize: Connection Reuse
			}),
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		crawler:     NewCrawler(),
		fingerprint: true,
	}
}

// Detect Identification of sites
func (ss *SiteScanner) Detect(ctx *ScanContext) error {
	// 🆕 Load Scanner Configuration
	scannerConfig := LoadScannerConfig(ctx)
	ss.client.Timeout = scannerConfig.SiteTimeout
	ss.client.CheckRedirect = scopedRedirectPolicy(ctx.ValidateTarget)

	// 🆕 Recreate crawler using configuration
	ss.crawler = NewCrawlerWithConfig(CrawlerConfig{
		MaxDepth:    scannerConfig.CrawlerMaxDepth,
		MaxPages:    scannerConfig.CrawlerMaxPages,
		Timeout:     scannerConfig.SiteTimeout,
		ValidateURL: ctx.ValidateTarget,
	})

	var ports []models.Port
	ctx.DB.Where("task_id = ? AND (protocol = ? OR protocol = ?)", ctx.Task.ID, "tcp", "").Find(&ports)

	ctx.Logger.Printf("Detecting sites for %d ports", len(ports))

	// 🆕 Use configured co-mingled numbers
	concurrency := scannerConfig.SiteConcurrency
	if len(ports) < concurrency {
		concurrency = len(ports)
	}
	ctx.Logger.Printf("[Config] Site scanner: concurrency=%d, timeout=%v, crawler_depth=%d, crawler_pages=%d",
		concurrency, ss.client.Timeout, scannerConfig.CrawlerMaxDepth, scannerConfig.CrawlerMaxPages)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency)

	for _, port := range ports {
		// Check if the task has been cancelled
		select {
		case <-ctx.Ctx.Done():
			ctx.Logger.Printf("Site detection cancelled by user")
			wg.Wait()
			return ctx.Ctx.Err()
		default:
		}

		wg.Add(1)
		go func(p models.Port) {
			defer wg.Done()
			select {
			case semaphore <- struct{}{}:
			case <-ctx.Ctx.Done():
				return
			}
			defer func() { <-semaphore }()

			// Check for de-status
			select {
			case <-ctx.Ctx.Done():
				return
			default:
			}

			ss.detectSiteForPort(ctx, p)
		}(port)
	}

	wg.Wait()
	ctx.Logger.Printf("Site detection completed")
	return nil
}

// detectSiteForPort Checking for a single port
func (ss *SiteScanner) detectSiteForPort(ctx *ScanContext, port models.Port) {
	schemes := siteProbeSchemes(port)

	// Find thisIPThe corresponding domain name
	var domains []models.Domain
	ctx.DB.Where("task_id = ? AND ip_address = ?", ctx.Task.ID, port.IPAddress).Find(&domains)

	// Priority use of domain names, Use if no domain name existsIP
	hosts := make([]string, 0)
	for _, domain := range domains {
		hosts = append(hosts, domain.Domain)
	}
	if len(hosts) == 0 {
		hosts = append(hosts, port.IPAddress)
	}

	for _, host := range hosts {
		for _, scheme := range schemes {
			url := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, strconv.Itoa(port.Port)))

			if siteInfo := ss.probeSite(ctx, url); siteInfo != nil {
				siteInfo.TaskID = ctx.Task.ID
				ctx.DB.Create(siteInfo)
				ctx.Logger.Printf("Site detected: %s - %s", url, siteInfo.Title)

				// If the crawler are activated,
				if ctx.Task.Options.EnableCrawler {
					ss.crawlSite(ctx, url)
				}

				break // And when it works, no more agreements.
			}
		}
	}
}

func siteProbeSchemes(port models.Port) []string {
	service := strings.ToLower(port.Service)
	if strings.Contains(service, "https") || strings.Contains(service, "ssl") || strings.Contains(service, "tls") {
		return []string{"https", "http"}
	}
	if port.Port == 443 || port.Port == 8443 || port.Port == 9443 || port.Port == 10443 {
		return []string{"https", "http"}
	}
	return []string{"http", "https"}
}

// probeSite Stations
func (ss *SiteScanner) probeSite(ctx *ScanContext, url string) *models.Site {
	if err := ctx.ValidateNetworkTarget(url); err != nil {
		ctx.Logger.Printf("Site target blocked by scan scope: %s", url)
		return nil
	}
	scanContext := ctx.Ctx
	if scanContext == nil {
		scanContext = context.Background()
	}
	req, err := http.NewRequestWithContext(scanContext, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}

	// SettingsUser-Agent
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := ss.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Limited readbodyFor fingerprinting., Avoid individual site responses that exhaust the scanning process memory.
	body, _, err := readHTTPBody(resp, maxCrawlerCaptureBytes)
	if err != nil {
		return nil
	}
	bodyStr := string(body)

	// Extract Title
	title := ExtractTitle(bodyStr)

	// Get Allheaders
	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	// Fingerprint recognition.
	fingerprints := MatchFingerprints(headers, bodyStr, title)

	// Merge fingerprints as strings
	fingerprintStr := ""
	if len(fingerprints) > 0 {
		fingerprintStr = fingerprints[0]
		for i := 1; i < len(fingerprints) && i < 5; i++ { // Show at most5One.
			fingerprintStr += ", " + fingerprints[i]
		}
	}

	// CDNTest
	isCDN := IsCDN(headers, "")

	// FromURLDrawIP
	ip := ExtractIPFromURL(url)

	site := &models.Site{
		URL:          url,
		StatusCode:   resp.StatusCode,
		IP:           ip, // AddIP
		ContentType:  resp.Header.Get("Content-Type"),
		Server:       resp.Header.Get("Server"),
		Title:        title,
		Fingerprint:  fingerprintStr, // Add a single fingerprint string
		Fingerprints: fingerprints,   // Keep arrays
	}

	// RecordsCDNMessage toServerFields
	if isCDN {
		site.Server += " [CDN]"
	}

	return site
}

// crawlSite Climbing site
func (ss *SiteScanner) crawlSite(ctx *ScanContext, url string) {
	ctx.Logger.Printf("Starting crawler for site: %s", url)

	// Configure crawler with task options
	config := CrawlerConfig{
		MaxDepth:    3,
		MaxPages:    100,
		Timeout:     10 * time.Second,
		ValidateURL: ctx.ValidateTarget,
	}

	// If the task option contains a crawler configuration, Use them.
	if ctx.Task.Options.CrawlerDepth > 0 {
		config.MaxDepth = ctx.Task.Options.CrawlerDepth
	}
	if ctx.Task.Options.CrawlerPages > 0 {
		config.MaxPages = ctx.Task.Options.CrawlerPages
	}

	crawler := NewCrawlerWithConfig(config)
	err := crawler.Crawl(ctx, url)
	if err != nil {
		ctx.Logger.Printf("[Crawler] Failed for %s: %v", url, err)
		return
	}

	ctx.Logger.Printf("[Crawler] Completed for %s", url)
}

// TakeScreenshots Site Screenshot
func (ss *SiteScanner) TakeScreenshots(ctx *ScanContext) error {
	var sites []models.Site
	if err := ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&sites).Error; err != nil {
		return fmt.Errorf("failed to fetch sites: %w", err)
	}

	if len(sites) == 0 {
		ctx.Logger.Printf("No sites to screenshot")
		return nil
	}

	ctx.Logger.Printf("Taking screenshots for %d sites", len(sites))

	// Create a screenshot scanner
	screenshotDir := "./data/screenshots"
	screenshotScanner := NewScreenshotScannerWithValidator(screenshotDir, ctx.ValidateTarget)

	// And send a screenshot. (Limit Simultaneous Numbers To3, Avoid overexploitation of resources)
	concurrency := 3
	semaphore := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	successCount := 0
	failCount := 0
	var mu sync.Mutex

	for _, site := range sites {
		wg.Add(1)
		go func(s models.Site) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			ctx.Logger.Printf("Taking screenshot: %s", s.URL)

			// Use visual area screenshot (Faster.)
			screenshotPath, err := screenshotScanner.ScreenshotViewport(s.URL)
			if err != nil {
				ctx.Logger.Printf("Screenshot failed for %s: %v", s.URL, err)
				mu.Lock()
				failCount++
				mu.Unlock()
				return
			}

			// Save only filenames, Do not save full path
			filename := filepath.Base(screenshotPath)

			// Update the screenshot path in the database
			if err := ctx.DB.Model(&models.Site{}).
				Where("id = ?", s.ID).
				Update("screenshot", filename).Error; err != nil {
				ctx.Logger.Printf("Failed to update screenshot path for %s: %v", s.URL, err)
				mu.Lock()
				failCount++
				mu.Unlock()
				return
			}

			ctx.Logger.Printf("Screenshot saved: %s -> %s", s.URL, filename)
			mu.Lock()
			successCount++
			mu.Unlock()
		}(site)
	}

	wg.Wait()

	ctx.Logger.Printf("Screenshot completed: %d success, %d failed", successCount, failCount)
	return nil
}

func scopedRedirectPolicy(validate func(string) error) func(*http.Request, []*http.Request) error {
	return func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		if validate != nil {
			return validate(request.URL.String())
		}
		return nil
	}
}

// checkFileLeaksLegacy Keep old realization for compatibility tests; New Tasks Using Dictionary-Driving.
func (ss *SiteScanner) checkFileLeaksLegacy(ctx *ScanContext) error {
	var sites []models.Site
	ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&sites)

	ctx.Logger.Printf("Checking file leaks for %d sites", len(sites))

	// Path to sensitive files
	leakPaths := []struct {
		path     string
		severity string
		desc     string
	}{
		{"/.git/config", "high", "GitProfile leak"},
		{"/.git/HEAD", "high", "GitRepository leak"},
		{"/.env", "critical", "Environmental variable file leak"},
		{"/.env.local", "high", "Local environment configuration leak"},
		{"/.env.production", "high", "Production environment configuration exposure"},
		{"/web.config", "medium", "IISProfile leak"},
		{"/.DS_Store", "low", "MacSystem File Disconnect"},
		{"/backup.zip", "high", "Backup File Disclosing"},
		{"/backup.tar.gz", "high", "Backup File Disclosing"},
		{"/backup.sql", "critical", "Database backup leak"},
		{"/db.sql", "critical", "Database File Disconnect"},
		{"/database.sql", "critical", "Database File Disconnect"},
		{"/.svn/entries", "high", "SVNInformation leaks"},
		{"/phpinfo.php", "medium", "PHPInformation leaks"},
		{"/info.php", "medium", "PHPInformation leaks"},
		{"/test.php", "low", "Test file leak"},
		{"/config.php", "high", "Profile leak"},
		{"/config.json", "high", "Profile leak"},
		{"/config.yml", "high", "Profile leak"},
		{"/config.yaml", "high", "Profile leak"},
		{"/settings.py", "high", "DjangoConfigure leaks"},
		{"/application.properties", "high", "SpringConfigure leaks"},
		{"/application.yml", "high", "SpringConfigure leaks"},
		{"/.htaccess", "medium", "ApacheConfigure leaks"},
		{"/robots.txt", "info", "RobotsDocumentation"},
		{"/sitemap.xml", "info", "Site Map"},
		{"/README.md", "low", "READMEFile leaks"},
		{"/CHANGELOG.md", "low", "Change log leak"},
	}

	for _, site := range sites {
		for _, leak := range leakPaths {
			url := site.URL + leak.path

			statusCode, contentType, size := ss.checkURLDetailed(url)
			if statusCode == 200 && size > 0 {
				vuln := &models.Vulnerability{
					TaskID:      ctx.Task.ID,
					URL:         url,
					Type:        "file_leak",
					Severity:    leak.severity,
					Title:       leak.desc,
					Description: fmt.Sprintf("Discover sensitive files: %s (Size: %d bytes, Type: %s)", url, size, contentType),
					Solution:    "Delete or limit access to sensitive documents",
				}
				ctx.DB.Create(vuln)
				ctx.Logger.Printf("File leak found: %s [%s]", url, leak.severity)
			}
		}
	}

	return nil
}

// checkURLDetailed Detailed checkURL
func (ss *SiteScanner) checkURLDetailed(url string) (int, string, int64) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, "", 0
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := ss.client.Do(req)
	if err != nil {
		return 0, "", 0
	}
	defer resp.Body.Close()

	// ReadbodyFetch Size
	body, _ := io.ReadAll(resp.Body)

	return resp.StatusCode, resp.Header.Get("Content-Type"), int64(len(body))
}

// RunNuclei Abandoned - Use SmartPoCTesting substitution
func (ss *SiteScanner) RunNuclei(ctx *ScanContext) error {
	ctx.Logger.Printf("RunNuclei is deprecated, use smart PoC detection instead")
	return nil
}
