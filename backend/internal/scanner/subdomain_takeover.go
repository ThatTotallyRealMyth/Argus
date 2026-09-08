package scanner

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/proxypool"
)

// SubdomainTakeoverScanner Subdomain name takes over the detector
type SubdomainTakeoverScanner struct {
	client       *http.Client
	dnsTimeout   time.Duration
	httpTimeout  time.Duration
	fingerprints []TakeoverFingerprint
}

// TakeoverFingerprint describes a service-specific takeover signature.
type TakeoverFingerprint struct {
	Service      string   // Service name (Like: GitHub Pages, AWS S3, Heroku)
	CNAMEPattern []string // CNAME Match Mode
	ResponseCode []int    // HTTP Status Code
	BodyKeywords []string // Response Keywords
	Description  string   // Synchronising folder
	Severity     string   // Extent: high, medium, low
}

// TakeoverResult records the outcome of a subdomain-takeover check.
type TakeoverResult struct {
	Domain      string
	Vulnerable  bool
	Service     string
	CNAME       string
	Evidence    string
	Severity    string
	Description string
}

// NewSubdomainTakeoverScanner Create sub-domain name to take over the detector
func NewSubdomainTakeoverScanner() *SubdomainTakeoverScanner {
	return &SubdomainTakeoverScanner{
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: proxypool.ConfigureTransport(&http.Transport{}),
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Do not follow redirection
			},
		},
		dnsTimeout:   5 * time.Second,
		httpTimeout:  10 * time.Second,
		fingerprints: initTakeoverFingerprints(),
	}
}

// initTakeoverFingerprints Initialization of the fingerprint collection.
func initTakeoverFingerprints() []TakeoverFingerprint {
	return []TakeoverFingerprint{
		// GitHub Pages
		{
			Service:      "GitHub Pages",
			CNAMEPattern: []string{"github.io", "github.com"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"There isn't a GitHub Pages site here",
				"For root URLs (like http://example.com/) you must provide an index.html file",
			},
			Description: "Subdomain NameCNAMEPointGitHub PagesBut the page does not exist",
			Severity:    "high",
		},
		// AWS S3
		{
			Service:      "AWS S3",
			CNAMEPattern: []string{"s3.amazonaws.com", "s3-website"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"NoSuchBucket",
				"The specified bucket does not exist",
			},
			Description: "S3Storage drums have been deleted or do not exist",
			Severity:    "high",
		},
		// Heroku
		{
			Service:      "Heroku",
			CNAMEPattern: []string{"herokuapp.com", "herokussl.com"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"No such app",
				"There's nothing here, yet",
			},
			Description: "HerokuApplication does not exist",
			Severity:    "high",
		},
		// Azure
		{
			Service:      "Azure",
			CNAMEPattern: []string{"azurewebsites.net", "cloudapp.azure.com", "azure.com"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"404 Web Site not found",
				"Error 404",
			},
			Description: "AzureService does not exist",
			Severity:    "high",
		},
		// Shopify
		{
			Service:      "Shopify",
			CNAMEPattern: []string{"myshopify.com"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"Sorry, this shop is currently unavailable",
				"Only one step left!",
			},
			Description: "ShopifyThe store doesn't exist.",
			Severity:    "medium",
		},
		// Fastly
		{
			Service:      "Fastly",
			CNAMEPattern: []string{"fastly.net"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"Fastly error: unknown domain",
			},
			Description: "Fastly CDNConfiguration error",
			Severity:    "medium",
		},
		// Ghost
		{
			Service:      "Ghost",
			CNAMEPattern: []string{"ghost.io"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"The thing you were looking for is no longer here",
			},
			Description: "GhostBlog does not exist",
			Severity:    "medium",
		},
		// Pantheon
		{
			Service:      "Pantheon",
			CNAMEPattern: []string{"pantheonsite.io"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"404 error unknown site!",
			},
			Description: "PantheonSite does not exist",
			Severity:    "high",
		},
		// Tumblr
		{
			Service:      "Tumblr",
			CNAMEPattern: []string{"tumblr.com"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"Whatever you were looking for doesn't currently exist at this address",
				"There's nothing here.",
			},
			Description: "TumblrBlog does not exist",
			Severity:    "low",
		},
		// WordPress.com
		{
			Service:      "WordPress.com",
			CNAMEPattern: []string{"wordpress.com"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"Do you want to register",
			},
			Description: "WordPressSite does not exist",
			Severity:    "low",
		},
		// Bitbucket
		{
			Service:      "Bitbucket",
			CNAMEPattern: []string{"bitbucket.io"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"Repository not found",
			},
			Description: "Bitbucketrepository does not exist",
			Severity:    "medium",
		},
		// Cargo
		{
			Service:      "Cargo",
			CNAMEPattern: []string{"cargocollective.com"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"404 Not Found",
			},
			Description: "CargoSite does not exist",
			Severity:    "low",
		},
		// Feedpress
		{
			Service:      "Feedpress",
			CNAMEPattern: []string{"redirect.feedpress.me"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"The feed has not been found",
			},
			Description: "FeedpressSynchronising folder failed: %s: %s",
			Severity:    "low",
		},
		// StatusPage
		{
			Service:      "StatusPage",
			CNAMEPattern: []string{"statuspage.io"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"You are being",
				"redirected",
			},
			Description: "StatusPagePage does not exist",
			Severity:    "medium",
		},
		// Unbounce
		{
			Service:      "Unbounce",
			CNAMEPattern: []string{"unbouncepages.com"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"The requested URL was not found on this server",
			},
			Description: "UnbouncePage does not exist",
			Severity:    "medium",
		},
		// Surge.sh
		{
			Service:      "Surge.sh",
			CNAMEPattern: []string{"surge.sh"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"project not found",
			},
			Description: "SurgeProject does not exist",
			Severity:    "high",
		},
		// Vercel
		{
			Service:      "Vercel",
			CNAMEPattern: []string{"vercel.app", "now.sh"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"The deployment could not be found on Vercel",
				"DEPLOYMENT_NOT_FOUND",
			},
			Description: "VercelDeployment does not exist",
			Severity:    "high",
		},
		// Netlify
		{
			Service:      "Netlify",
			CNAMEPattern: []string{"netlify.app", "netlify.com"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"Not Found - Request ID:",
			},
			Description: "NetlifySite does not exist",
			Severity:    "high",
		},
	}
}

// Scan Execute subdomain name takeover detection
func (s *SubdomainTakeoverScanner) Scan(ctx *ScanContext) error {
	// 🆕 Load Scanner Configuration
	scannerConfig := LoadScannerConfig(ctx)

	var domains []models.Domain
	ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&domains)

	ctx.Logger.Printf("=== Subdomain Takeover Scan Started ===")
	ctx.Logger.Printf("Checking %d domains for potential takeover vulnerabilities", len(domains))

	// 🆕 Use configured co-mingled numbers
	concurrency := scannerConfig.SubdomainTakeoverConcurrency
	ctx.Logger.Printf("[Config] Subdomain takeover scanner: concurrency=%d", concurrency)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency)
	resultChan := make(chan *TakeoverResult, len(domains))

	for _, domain := range domains {
		if err := ctx.ValidateNetworkTarget(domain.Domain); err != nil {
			ctx.Logger.Printf("Subdomain takeover target blocked by scan scope: %s", domain.Domain)
			continue
		}
		wg.Add(1)
		go func(d models.Domain) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := s.checkDomain(d.Domain)
			if result != nil {
				resultChan <- result
			}
		}(domain)
	}

	// Waiting for all tests to be completed
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Save Results
	vulnerableCount := 0
	for result := range resultChan {
		if result.Vulnerable {
			s.saveResult(ctx, result)
			vulnerableCount++
			ctx.Logger.Printf("⚠️  VULNERABLE: %s -> %s (%s)", result.Domain, result.Service, result.Severity)
		}
	}

	ctx.Logger.Printf("Subdomain takeover scan completed: %d vulnerable domains found", vulnerableCount)
	return nil
}

// checkDomain Check if there is a takeover risk for a single domain name
func (s *SubdomainTakeoverScanner) checkDomain(domain string) *TakeoverResult {
	// 1. InspectionCNAMERecords
	cname, err := s.getCNAME(domain)
	if err != nil || cname == "" {
		return nil // Nothing.CNAME, Skip
	}

	// 2. Matching fingerprints.
	for _, fp := range s.fingerprints {
		if s.matchCNAME(cname, fp.CNAMEPattern) {
			// 3. HTTPRequest Authentication
			if s.verifyTakeover(domain, &fp) {
				return &TakeoverResult{
					Domain:      domain,
					Vulnerable:  true,
					Service:     fp.Service,
					CNAME:       cname,
					Evidence:    fmt.Sprintf("CNAME: %s", cname),
					Severity:    fp.Severity,
					Description: fp.Description,
				}
			}
		}
	}

	return nil
}

// getCNAME returns the CNAME records for a domain.
func (s *SubdomainTakeoverScanner) getCNAME(domain string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.dnsTimeout)
	defer cancel()

	cname, err := net.DefaultResolver.LookupCNAME(ctx, domain)
	if err != nil {
		return "", err
	}

	// Remove the end point.
	cname = strings.TrimSuffix(cname, ".")

	// IfCNAMESame as domain name, No, it's not.CNAMERecords
	if cname == domain {
		return "", nil
	}

	return cname, nil
}

// matchCNAME InspectionCNAMEMatching fingerprint mode
func (s *SubdomainTakeoverScanner) matchCNAME(cname string, patterns []string) bool {
	cnameLower := strings.ToLower(cname)
	for _, pattern := range patterns {
		if strings.Contains(cnameLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// verifyTakeover ThroughHTTPRequest for verification of taking over risk
func (s *SubdomainTakeoverScanner) verifyTakeover(domain string, fp *TakeoverFingerprint) bool {
	// TryHTTPandHTTPS
	schemes := []string{"https", "http"}

	for _, scheme := range schemes {
		url := fmt.Sprintf("%s://%s", scheme, domain)

		resp, err := s.client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Check the status code
		codeMatch := false
		for _, code := range fp.ResponseCode {
			if resp.StatusCode == code {
				codeMatch = true
				break
			}
		}

		if !codeMatch {
			continue
		}

		// Check for response keywords
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		bodyStr := string(body)
		for _, keyword := range fp.BodyKeywords {
			if strings.Contains(bodyStr, keyword) {
				return true
			}
		}
	}

	return false
}

// saveResult Save detection results to database
func (s *SubdomainTakeoverScanner) saveResult(ctx *ScanContext, result *TakeoverResult) {
	// Update domain name records, Add the takeover mark
	ctx.DB.Model(&models.Domain{}).
		Where("task_id = ? AND domain = ?", ctx.Task.ID, result.Domain).
		Updates(map[string]interface{}{
			"takeover_vulnerable": true,
			"takeover_service":    result.Service,
			"takeover_cname":      result.CNAME,
			"takeover_severity":   result.Severity,
		})

	// Optional: Create a separate bug log
	// vulnerability := &models.Vulnerability{
	// 	TaskID:      ctx.Task.ID,
	// 	Type:        "subdomain_takeover",
	// 	Target:      result.Domain,
	// 	Service:     result.Service,
	// 	Severity:    result.Severity,
	// 	Description: result.Description,
	// 	Evidence:    result.Evidence,
	// }
	// ctx.DB.Create(vulnerability)
}
