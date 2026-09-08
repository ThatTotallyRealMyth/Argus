package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/proxypool"
)

// Crawler Crawlers.
type Crawler struct {
	client      *http.Client
	validateURL func(string) error
	visited     map[string]bool
	visitedLock sync.Mutex
	maxDepth    int
	maxPages    int
	jsWorkers   int
	timeout     time.Duration
	userAgent   string
}

// CrawlerConfig Retrieve Configuration
type CrawlerConfig struct {
	MaxDepth    int
	MaxPages    int
	Timeout     time.Duration
	JSWorkers   int
	ValidateURL func(string) error
}

const defaultCrawlerJSWorkers = 4

// NewCrawler Create a crawler
func NewCrawler() *Crawler {
	return NewCrawlerWithConfig(CrawlerConfig{
		MaxDepth: 3,
		MaxPages: 100,
		Timeout:  10 * time.Second,
	})
}

// NewCrawlerWithConfig Create crawler using configuration
func NewCrawlerWithConfig(config CrawlerConfig) *Crawler {
	if config.MaxPages <= 0 {
		config.MaxPages = 100
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}
	if config.JSWorkers <= 0 {
		config.JSWorkers = defaultCrawlerJSWorkers
	}
	crawler := &Crawler{
		client: &http.Client{
			Timeout: config.Timeout,
			Transport: proxypool.ConfigureTransport(&http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			}),
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				if config.ValidateURL != nil {
					return config.ValidateURL(req.URL.String())
				}
				return nil
			},
		},
		validateURL: config.ValidateURL,
		visited:     make(map[string]bool),
		maxDepth:    config.MaxDepth,
		maxPages:    config.MaxPages,
		jsWorkers:   config.JSWorkers,
		timeout:     config.Timeout,
		userAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	}
	return crawler
}

// Crawl ClimbURL
func (c *Crawler) Crawl(ctx *ScanContext, baseURL string) error {
	if ctx == nil || ctx.Task == nil || ctx.DB == nil {
		return fmt.Errorf("scan context, task, and database are required")
	}
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("invalid base URL: %v", err)
	}
	if (parsedBase.Scheme != "http" && parsedBase.Scheme != "https") || parsedBase.Host == "" {
		return fmt.Errorf("invalid base URL: absolute HTTP(S) URL required")
	}
	scanContext := ctx.Ctx
	if scanContext == nil {
		scanContext = context.Background()
	}
	crawlContext, cancel := context.WithCancel(scanContext)
	defer cancel()
	workerScanContext := *ctx
	workerScanContext.Ctx = crawlContext
	db := ctx.DB.WithContext(crawlContext)
	c.resetVisited()
	budget := newCrawlerBudget(c.maxPages)

	ctx.Logger.Printf("Starting crawler for: %s (maxDepth: %d, maxPages: %d)", baseURL, c.maxDepth, c.maxPages)

	// Climb Queue
	queue := []crawlItem{{url: baseURL, depth: 0}}
	queued := map[string]bool{baseURL: true}
	workerCount := c.jsWorkers
	if workerCount > c.maxPages {
		workerCount = c.maxPages
	}
	jsJobs := make(chan string, workerCount)
	workerErrors := make(chan error, 1)
	var jsWorkers sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		jsWorkers.Add(1)
		go func() {
			defer jsWorkers.Done()
			for {
				select {
				case <-crawlContext.Done():
					return
				case jsURL, ok := <-jsJobs:
					if !ok {
						return
					}
					if err := c.analyzeJSFile(&workerScanContext, jsURL, parsedBase.Hostname(), budget); err != nil {
						select {
						case workerErrors <- err:
						default:
						}
						cancel()
						return
					}
				}
			}
		}()
	}

	var crawlErr error
crawlLoop:
	for len(queue) > 0 && budget.hasCapacity() {
		select {
		case <-crawlContext.Done():
			break crawlLoop
		default:
		}
		// Remove the first
		item := queue[0]
		queue = queue[1:]

		// Check whether visits have been made
		if !c.claimURL(item.url) {
			continue
		}

		// Check depth
		if item.depth > c.maxDepth {
			continue
		}

		ctx.Logger.Printf("[Crawler] Visiting: %s (depth: %d)", item.url, item.depth)
		if c.validateURL != nil {
			if err := c.validateURL(item.url); err != nil {
				ctx.Logger.Printf("[Crawler] URL blocked: %s: %v", item.url, err)
				continue
			}
		}

		// Create Request
		req, err := http.NewRequestWithContext(crawlContext, http.MethodGet, item.url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", c.userAgent)

		// Get Page
		startedAt := time.Now()
		resp, err := c.client.Do(req)
		if err != nil {
			if crawlContext.Err() != nil {
				break crawlLoop
			}
			ctx.Logger.Printf("[Crawler] Error fetching %s: %v", item.url, err)
			continue
		}

		// Get status code
		statusCode := resp.StatusCode
		contentType := resp.Header.Get("Content-Type")

		// SaveURLRecords
		urlRecord := &models.CrawlerResult{
			TaskID:         ctx.Task.ID,
			URL:            item.url,
			StatusCode:     statusCode,
			ContentType:    contentType,
			Method:         "GET",
			Source:         "crawler",
			ContentLength:  resp.ContentLength,
			ResponseTimeMs: time.Since(startedAt).Milliseconds(),
		}

		// ParsingURLParameters
		parsedURL, _ := url.Parse(item.url)
		if parsedURL.RawQuery != "" {
			urlRecord.HasParams = true
		}

		// Save to Database
		if !budget.reserve() {
			resp.Body.Close()
			break
		}
		if err := db.Create(urlRecord).Error; err != nil {
			budget.release()
			resp.Body.Close()
			crawlErr = fmt.Errorf("save crawler result for %s: %w", item.url, err)
			cancel()
			break
		}

		// Read a limited-sized response, For HTTP Look back and see HTML/JS Extract.
		body, truncated, err := readHTTPBody(resp, maxCrawlerCaptureBytes)
		resp.Body.Close()
		if err != nil {
			if crawlContext.Err() != nil {
				break crawlLoop
			}
			ctx.Logger.Printf("[Crawler] Error reading %s: %v", item.url, err)
			continue
		}
		if err := saveHTTPTransaction(&workerScanContext, req, resp, urlRecord.ID, body, truncated, startedAt); err != nil {
			crawlErr = fmt.Errorf("save crawler transaction for %s: %w", item.url, err)
			cancel()
			break
		}

		bodyStr := string(body)
		if urlRecord.ContentLength < 0 {
			urlRecord.ContentLength = int64(len(body))
			if truncated {
				urlRecord.ContentLength++
			}
			if err := db.Model(urlRecord).Update("content_length", urlRecord.ContentLength).Error; err != nil {
				crawlErr = fmt.Errorf("update crawler content length for %s: %w", item.url, err)
				cancel()
				break
			}
		}

		// Only handleHTMLContents
		if !strings.Contains(strings.ToLower(contentType), "text/html") {
			continue
		}

		// Extract Link
		links := c.extractLinks(bodyStr, item.url, parsedBase)
		for _, link := range links {
			if len(queue) >= c.maxPages {
				break
			}
			if queued[link] {
				continue
			}
			queued[link] = true
			queue = append(queue, crawlItem{url: link, depth: item.depth + 1})
		}

		// Rip and SaveJSDocumentation
		jsFiles := c.ExtractJSFiles(bodyStr, item.url)
		for _, jsURL := range jsFiles {
			select {
			case <-crawlContext.Done():
				break crawlLoop
			default:
			}
			if !c.claimURL(jsURL) {
				continue
			}
			if !budget.reserve() {
				break crawlLoop
			}
			// SaveJSDocumentationURL
			jsRecord := &models.CrawlerResult{
				TaskID:      ctx.Task.ID,
				URL:         jsURL,
				ContentType: "application/javascript",
				Method:      "GET",
				Source:      "crawler_js",
			}
			if err := db.Create(jsRecord).Error; err != nil {
				budget.release()
				crawlErr = fmt.Errorf("save JavaScript crawler result for %s: %w", jsURL, err)
				cancel()
				break crawlLoop
			}

			// Download and analyzeJSDocumentation
			select {
			case jsJobs <- jsURL:
			case <-crawlContext.Done():
				break crawlLoop
			}
		}
	}
	close(jsJobs)
	jsWorkers.Wait()

	select {
	case err := <-workerErrors:
		return err
	default:
	}
	if crawlErr != nil {
		return crawlErr
	}
	if scanContext.Err() != nil {
		return scanContext.Err()
	}
	ctx.Logger.Printf("[Crawler] Finished: collected %d URLs", budget.usedCount())
	return nil
}

// crawlItem Crawling Entry
type crawlItem struct {
	url   string
	depth int
}

type crawlerBudget struct {
	mu    sync.Mutex
	limit int
	used  int
}

func newCrawlerBudget(limit int) *crawlerBudget {
	return &crawlerBudget{limit: limit}
}

func (b *crawlerBudget) reserve() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used >= b.limit {
		return false
	}
	b.used++
	return true
}

func (b *crawlerBudget) release() {
	b.mu.Lock()
	if b.used > 0 {
		b.used--
	}
	b.mu.Unlock()
}

func (b *crawlerBudget) hasCapacity() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used < b.limit
}

func (b *crawlerBudget) usedCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

func (c *Crawler) resetVisited() {
	c.visitedLock.Lock()
	c.visited = make(map[string]bool)
	c.visitedLock.Unlock()
}

func (c *Crawler) claimURL(target string) bool {
	c.visitedLock.Lock()
	defer c.visitedLock.Unlock()
	if c.visited[target] {
		return false
	}
	c.visited[target] = true
	return true
}

// extractLinks Extract Link
func (c *Crawler) extractLinks(body, currentURL string, baseURL *url.URL) []string {
	var links []string
	seen := make(map[string]bool)

	// Reciprocalhref
	hrefRegex := regexp.MustCompile(`href=["']([^"']+)["']`)
	matches := hrefRegex.FindAllStringSubmatch(body, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		link := match[1]

		// Skip Special Links
		if strings.HasPrefix(link, "javascript:") ||
			strings.HasPrefix(link, "mailto:") ||
			strings.HasPrefix(link, "#") ||
			link == "" {
			continue
		}

		// ParsingURL
		parsedLink, err := url.Parse(link)
		if err != nil {
			continue
		}

		// Convert to AbsoluteURL
		if !parsedLink.IsAbs() {
			parsedCurrent, _ := url.Parse(currentURL)
			parsedLink = parsedCurrent.ResolveReference(parsedLink)
		}

		// Only crawl to links with the same domain name
		if parsedLink.Host != baseURL.Host {
			continue
		}

		// NormativeURL
		normalizedURL := parsedLink.Scheme + "://" + parsedLink.Host + parsedLink.Path
		if parsedLink.RawQuery != "" {
			normalizedURL += "?" + parsedLink.RawQuery
		}

		// - Go heavy.
		if !seen[normalizedURL] {
			seen[normalizedURL] = true
			links = append(links, normalizedURL)
		}
	}

	return links
}

// ExtractJSFiles ExtractJSDocumentation
func (c *Crawler) ExtractJSFiles(body, baseURL string) []string {
	var jsFiles []string
	seen := make(map[string]bool)

	// Extractscript src
	scriptRegex := regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	matches := scriptRegex.FindAllStringSubmatch(body, -1)

	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return jsFiles
	}

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		src := match[1]
		parsedSrc, err := url.Parse(src)
		if err != nil {
			continue
		}

		// Convert to AbsoluteURL
		if !parsedSrc.IsAbs() {
			parsedSrc = parsedBase.ResolveReference(parsedSrc)
		}

		jsURL := parsedSrc.String()
		if !seen[jsURL] && strings.HasSuffix(strings.ToLower(parsedSrc.Path), ".js") {
			seen[jsURL] = true
			jsFiles = append(jsFiles, jsURL)
		}
	}

	return jsFiles
}

// ExtractAPIs FromJSDrawAPIEnd
func (c *Crawler) ExtractAPIs(jsContent string) []string {
	var apis []string
	seen := make(map[string]bool)

	// APIPath Mode
	patterns := []string{
		`/api/[a-zA-Z0-9/_-]+`,
		`/v\d+/[a-zA-Z0-9/_-]+`,
		`['"](/[a-zA-Z0-9/_-]+)['":]`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(jsContent, -1)

		for _, match := range matches {
			// Clear quotes
			match = strings.Trim(match, `"':`)
			if !seen[match] && strings.HasPrefix(match, "/") {
				seen[match] = true
				apis = append(apis, match)
			}
		}
	}

	return apis
}

// ExtractSubdomains FromJSNeuro-Pill Subdomain Name
func (c *Crawler) ExtractSubdomains(jsContent string) []string {
	var subdomains []string
	seen := make(map[string]bool)

	// Domain name mode
	domainRegex := regexp.MustCompile(`[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+`)
	matches := domainRegex.FindAllString(jsContent, -1)

	for _, match := range matches {
		match = strings.ToLower(match)
		// Filter common non-domain names
		if !strings.Contains(match, ".") ||
			strings.HasSuffix(match, ".js") ||
			strings.HasSuffix(match, ".css") ||
			strings.HasSuffix(match, ".jpg") ||
			strings.HasSuffix(match, ".png") {
			continue
		}

		if !seen[match] {
			seen[match] = true
			subdomains = append(subdomains, match)
		}
	}

	return subdomains
}

// analyzeJSFile AnalysisJSDocumentation
func (c *Crawler) analyzeJSFile(ctx *ScanContext, jsURL string, baseDomain string, budget *crawlerBudget) error {
	if c.validateURL != nil {
		if err := c.validateURL(jsURL); err != nil {
			ctx.Logger.Printf("[Crawler] JS URL blocked: %s: %v", jsURL, err)
			return nil
		}
	}
	scanContext := ctx.Ctx
	if scanContext == nil {
		scanContext = context.Background()
	}
	db := ctx.DB.WithContext(scanContext)
	// DownloadJSDocumentation
	req, err := http.NewRequestWithContext(scanContext, http.MethodGet, jsURL, nil)
	if err != nil {
		ctx.Logger.Printf("[Crawler] Invalid JavaScript URL %s: %v", jsURL, err)
		return nil
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		if scanContext.Err() != nil {
			return scanContext.Err()
		}
		ctx.Logger.Printf("[Crawler] Error fetching JavaScript %s: %v", jsURL, err)
		return nil
	}
	defer resp.Body.Close()

	body, _, err := readHTTPBody(resp, maxCrawlerCaptureBytes)
	if err != nil {
		if scanContext.Err() != nil {
			return scanContext.Err()
		}
		ctx.Logger.Printf("[Crawler] Error reading JavaScript %s: %v", jsURL, err)
		return nil
	}

	jsContent := string(body)

	// ExtractAPIEnd
	apis := c.ExtractAPIs(jsContent)
	for _, api := range apis {
		if err := scanContext.Err(); err != nil {
			return err
		}
		// Build FullURL
		fullURL := jsURL
		if strings.HasPrefix(api, "/") {
			parsedJS, _ := url.Parse(jsURL)
			fullURL = parsedJS.Scheme + "://" + parsedJS.Host + api
		}

		apiRecord := &models.CrawlerResult{
			TaskID:      ctx.Task.ID,
			URL:         fullURL,
			Method:      "GET",
			Source:      "js_analysis",
			HasParams:   strings.Contains(api, "{") || strings.Contains(api, ":"),
			ContentType: "application/json",
		}
		if !budget.reserve() {
			break
		}
		result := db.Where("task_id = ? AND url = ?", ctx.Task.ID, fullURL).FirstOrCreate(apiRecord)
		if result.Error != nil {
			budget.release()
			return fmt.Errorf("save JavaScript API result %s: %w", fullURL, result.Error)
		}
		if result.RowsAffected == 0 {
			budget.release()
		}
	}

	// Extract subdomain names
	subdomains := c.ExtractSubdomains(jsContent)
	domainScanner := NewDomainScanner()
	for _, subdomain := range subdomains {
		if err := scanContext.Err(); err != nil {
			return err
		}
		// Verify whether to be a target domain name
		if domainScanner.isSubdomainOf(subdomain, baseDomain) {
			// Save discovered subdomain names
			domain := &models.Domain{
				TaskID: ctx.Task.ID,
				Domain: subdomain,
				Source: "js_analysis",
			}
			if err := db.Where("task_id = ? AND domain = ?", ctx.Task.ID, subdomain).FirstOrCreate(domain).Error; err != nil {
				return fmt.Errorf("save JavaScript subdomain %s: %w", subdomain, err)
			}
		}
	}

	// Extract sensitive information
	sensitiveInfo := c.ExtractSensitiveInfo(jsContent)
	if len(sensitiveInfo) > 0 {
		// Create a bug record
		description := ""
		for key, values := range sensitiveInfo {
			if len(values) > 0 {
				description += fmt.Sprintf("%s: %d found\n", key, len(values))
			}
		}

		vuln := &models.Vulnerability{
			TaskID:      ctx.Task.ID,
			URL:         jsURL,
			Type:        "sensitive_info_leak",
			Severity:    "high",
			Title:       "JSSensitive information found in the document",
			Description: description,
			Solution:    "RemoveJavaScriptSensitive information in the, Manage using environment variables or secure configurations",
		}
		if err := db.Create(vuln).Error; err != nil {
			return fmt.Errorf("save JavaScript sensitive information finding for %s: %w", jsURL, err)
		}
	}
	return nil
}

// ExtractSensitiveInfo Extract sensitive information
func (c *Crawler) ExtractSensitiveInfo(content string) map[string][]string {
	result := make(map[string][]string)

	// AccessKey
	accessKeyRegex := regexp.MustCompile(`(?i)(access[_-]?key|accesskey|access[_-]?id)\s*[:=]\s*['"]([a-zA-Z0-9]{16,})['"]`)
	matches := accessKeyRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 2 {
			result["access_key"] = append(result["access_key"], match[2])
		}
	}

	// SecretKey
	secretKeyRegex := regexp.MustCompile(`(?i)(secret[_-]?key|secretkey)\s*[:=]\s*['"]([a-zA-Z0-9+/]{20,})['"]`)
	matches = secretKeyRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 2 {
			result["secret_key"] = append(result["secret_key"], match[2])
		}
	}

	// API Key
	apiKeyRegex := regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]([a-zA-Z0-9]{16,})['"]`)
	matches = apiKeyRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 2 {
			result["api_key"] = append(result["api_key"], match[2])
		}
	}

	// Token
	tokenRegex := regexp.MustCompile(`(?i)(token|auth[_-]?token)\s*[:=]\s*['"]([a-zA-Z0-9._-]{20,})['"]`)
	matches = tokenRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 2 {
			result["token"] = append(result["token"], match[2])
		}
	}

	// IntranetIP
	internalIPRegex := regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`)
	internalIPs := internalIPRegex.FindAllString(content, -1)
	if len(internalIPs) > 0 {
		result["internal_ip"] = internalIPs
	}

	// - Go heavy.
	for key, values := range result {
		result[key] = uniqueStrings(values)
	}

	return result
}
