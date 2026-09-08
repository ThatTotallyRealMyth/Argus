package scanner

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/reconmaster/backend/internal/models"
	"golang.org/x/net/publicsuffix"
)

// AssetMapper Asset Surveyor
type AssetMapper struct {
	mu sync.RWMutex
}

// AssetProfile Asset portrait
type AssetProfile struct {
	TaskID string `json:"task_id"`
	Target string `json:"target"`

	// Domain name assets
	TotalDomains     int            `json:"total_domains"`
	RootDomains      []string       `json:"root_domains"`
	SubdomainSources map[string]int `json:"subdomain_sources"` // Source statistics

	// IPAssets
	TotalIPs    int            `json:"total_ips"`
	IPLocations map[string]int `json:"ip_locations"` // Geographical distribution
	CDNIPs      int            `json:"cdn_ips"`      // CDN IPNumber
	UniqueIPs   []string       `json:"unique_ips"`

	// Port assets
	TotalPorts       int            `json:"total_ports"`
	OpenPorts        map[int]int    `json:"open_ports"`        // Port number:Number
	PortDistribution map[string]int `json:"port_distribution"` // Port range distribution

	// Service assets
	TotalServices int                 `json:"total_services"`
	ServiceTypes  map[string]int      `json:"service_types"` // Statistics on service types
	Versions      map[string][]string `json:"versions"`      // Service version information

	// WebAssets
	TotalSites      int            `json:"total_sites"`
	WebTechnologies map[string]int `json:"web_technologies"`  // Web technology statistics
	HTTPStatusCodes map[int]int    `json:"http_status_codes"` // Status Code Distribution
	TitleKeywords   map[string]int `json:"title_keywords"`    // Title keywords

	// Security risk
	TakeoverVulnerable int `json:"takeover_vulnerable"` // Subdomain name takeover risk
	FileLeaks          int `json:"file_leaks"`          // File leaks
	SensitiveInfo      int `json:"sensitive_info"`      // Sensitive information

	// Certificate assets
	SSLCertificates int            `json:"ssl_certificates"`
	CertIssuers     map[string]int `json:"cert_issuers"`
	ExpiredCerts    int            `json:"expired_certs"`

	// crawler
	TotalURLs int            `json:"total_urls"`
	URLPaths  map[string]int `json:"url_paths"`  // URLPath statistics
	FormCount int            `json:"form_count"` // Number of forms

	// Time stamp
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// NewAssetMapper Create an asset mapr
func NewAssetMapper() *AssetMapper {
	return &AssetMapper{}
}

// MapAssets Implementation of asset mapping
func (am *AssetMapper) MapAssets(ctx *ScanContext) error {
	ctx.Logger.Printf("=== Asset Mapping Started ===")

	profile := &AssetProfile{
		TaskID:           ctx.Task.ID,
		Target:           ctx.Task.Target,
		SubdomainSources: make(map[string]int),
		IPLocations:      make(map[string]int),
		UniqueIPs:        []string{},
		OpenPorts:        make(map[int]int),
		PortDistribution: make(map[string]int),
		ServiceTypes:     make(map[string]int),
		Versions:         make(map[string][]string),
		WebTechnologies:  make(map[string]int),
		HTTPStatusCodes:  make(map[int]int),
		TitleKeywords:    make(map[string]int),
		CertIssuers:      make(map[string]int),
		URLPaths:         make(map[string]int),
	}

	// And then you can run a list of assets.
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		am.mapDomains(ctx, profile)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		am.mapIPs(ctx, profile)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		am.mapPorts(ctx, profile)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		am.mapServices(ctx, profile)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		am.mapSites(ctx, profile)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		am.mapSecurity(ctx, profile)
	}()

	wg.Wait()

	// Save asset portraits
	am.saveProfile(ctx, profile)

	// Print statistical summary
	am.printSummary(ctx, profile)

	ctx.Logger.Printf("Asset mapping completed")
	return nil
}

// mapDomains Statistical domain name assets
func (am *AssetMapper) mapDomains(ctx *ScanContext, profile *AssetProfile) {
	am.mu.Lock()
	defer am.mu.Unlock()

	var domains []models.Domain
	ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&domains)

	profile.TotalDomains = len(domains)
	rootDomainsMap := make(map[string]bool)

	for _, domain := range domains {
		// Statistical sources
		source := domain.Source
		if source == "" {
			source = "unknown"
		}
		profile.SubdomainSources[source]++

		// Rip Root Domain Name
		rootDomain := extractRootDomain(domain.Domain)
		rootDomainsMap[rootDomain] = true
	}

	for root := range rootDomainsMap {
		profile.RootDomains = append(profile.RootDomains, root)
	}
}

// mapIPs StatisticsIPAssets
func (am *AssetMapper) mapIPs(ctx *ScanContext, profile *AssetProfile) {
	am.mu.Lock()
	defer am.mu.Unlock()

	var ips []models.IP
	ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&ips)

	profile.TotalIPs = len(ips)
	uniqueIPMap := make(map[string]bool)

	for _, ip := range ips {
		uniqueIPMap[ip.IPAddress] = true

		// Statistical geographic location
		if ip.Location != "" {
			profile.IPLocations[ip.Location]++
		}

		// StatisticsCDN
		if ip.CDN {
			profile.CDNIPs++
		}
	}

	for ipAddr := range uniqueIPMap {
		profile.UniqueIPs = append(profile.UniqueIPs, ipAddr)
	}
}

// mapPorts Statistical Port Assets
func (am *AssetMapper) mapPorts(ctx *ScanContext, profile *AssetProfile) {
	am.mu.Lock()
	defer am.mu.Unlock()

	var ports []models.Port
	ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&ports)

	profile.TotalPorts = len(ports)

	for _, port := range ports {
		// Statistical port number
		profile.OpenPorts[port.Port]++

		// Port range distribution
		portRange := getPortRange(port.Port)
		profile.PortDistribution[portRange]++
	}
}

// mapServices Statistical services assets
func (am *AssetMapper) mapServices(ctx *ScanContext, profile *AssetProfile) {
	am.mu.Lock()
	defer am.mu.Unlock()

	var ports []models.Port
	ctx.DB.Where("task_id = ? AND service IS NOT NULL AND service != ''", ctx.Task.ID).Find(&ports)

	profile.TotalServices = len(ports)

	for _, port := range ports {
		// Type of statistical services
		service := port.Service
		if service != "" {
			profile.ServiceTypes[service]++

			// Collect Version Information
			if port.Version != "" {
				versionKey := fmt.Sprintf("%s/%s", service, port.Version)
				if !containsString(profile.Versions[service], port.Version) {
					profile.Versions[service] = append(profile.Versions[service], port.Version)
				}
				_ = versionKey
			}
		}
	}
}

// mapSites StatisticsWebAssets
func (am *AssetMapper) mapSites(ctx *ScanContext, profile *AssetProfile) {
	am.mu.Lock()
	defer am.mu.Unlock()

	var sites []models.Site
	ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&sites)

	profile.TotalSites = len(sites)

	for _, site := range sites {
		// StatisticsHTTPStatus Code
		profile.HTTPStatusCodes[site.StatusCode]++

		// Statistical title keywords (Draw meaningful words)
		if site.Title != "" {
			keywords := extractKeywords(site.Title)
			for _, keyword := range keywords {
				profile.TitleKeywords[keyword]++
			}
		}

		// Statistical Technical Repository (FromfingerprintField Parsing)
		if site.Fingerprint != "" {
			techs := parseFingerprint(site.Fingerprint)
			for _, tech := range techs {
				profile.WebTechnologies[tech]++
			}
		}
	}

	// StatisticsURL
	var crawlerResults []models.CrawlerResult
	ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&crawlerResults)
	profile.TotalURLs = len(crawlerResults)

	for _, result := range crawlerResults {
		// ExtractURLPath
		path := extractURLPath(result.URL)
		profile.URLPaths[path]++

		// Statistical forms
		if result.HasForm {
			profile.FormCount++
		}
	}
}

// mapSecurity Statistical security assets
func (am *AssetMapper) mapSecurity(ctx *ScanContext, profile *AssetProfile) {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Subdomain name takeover risk
	var takeoverCount int64
	ctx.DB.Model(&models.Domain{}).
		Where("task_id = ? AND takeover_vulnerable = ?", ctx.Task.ID, true).
		Count(&takeoverCount)
	profile.TakeoverVulnerable = int(takeoverCount)

	// Document leakage and sensitive information statistics from leaking results, Maintains the same risk list.
	var fileLeakCount int64
	ctx.DB.Model(&models.Vulnerability{}).
		Where("task_id = ? AND type = ?", ctx.Task.ID, "file_leak").
		Count(&fileLeakCount)
	profile.FileLeaks = int(fileLeakCount)

	var sensitiveInfoCount int64
	ctx.DB.Model(&models.Vulnerability{}).
		Where("task_id = ? AND type = ?", ctx.Task.ID, "sensitive_info").
		Count(&sensitiveInfoCount)
	profile.SensitiveInfo = int(sensitiveInfoCount)

	// SSLCertificate
	var ports []models.Port
	ctx.DB.Where("task_id = ? AND ssl_cert IS NOT NULL AND ssl_cert != ''", ctx.Task.ID).Find(&ports)
	profile.SSLCertificates = len(ports)

	// Certificate issuer statistics
	for _, port := range ports {
		if port.SSLCert != "" {
			issuer := extractCertIssuer(port.SSLCert)
			if issuer != "" {
				profile.CertIssuers[issuer]++
			}
		}
	}
}

// saveProfile Keep asset drawings to database
func (am *AssetMapper) saveProfile(ctx *ScanContext, profile *AssetProfile) {
	profileJSON, err := json.Marshal(profile)
	if err != nil {
		ctx.Logger.Printf("Failed to marshal asset profile: %v", err)
		return
	}

	// Save to Tasks Metadata Fields or Separateasset_profileTable
	ctx.DB.Model(&models.Task{}).
		Where("id = ?", ctx.Task.ID).
		Update("asset_profile", string(profileJSON))
}

// printSummary Print summary of asset mapping
func (am *AssetMapper) printSummary(ctx *ScanContext, profile *AssetProfile) {
	ctx.Logger.Printf("=== Asset Mapping Summary ===")
	ctx.Logger.Printf("📊 Domains: %d (Root: %d)", profile.TotalDomains, len(profile.RootDomains))
	ctx.Logger.Printf("🌐 IPs: %d (CDN: %d)", profile.TotalIPs, profile.CDNIPs)
	ctx.Logger.Printf("🔌 Ports: %d", profile.TotalPorts)
	ctx.Logger.Printf("⚙️  Services: %d types", len(profile.ServiceTypes))
	ctx.Logger.Printf("🌍 Sites: %d", profile.TotalSites)
	ctx.Logger.Printf("🔗 URLs: %d", profile.TotalURLs)
	ctx.Logger.Printf("🔒 SSL Certs: %d", profile.SSLCertificates)

	if profile.TakeoverVulnerable > 0 {
		ctx.Logger.Printf("⚠️  Takeover Vulnerable: %d domains", profile.TakeoverVulnerable)
	}

	// PrintTopServices
	ctx.Logger.Printf("\n🔝 Top Services:")
	for service, count := range profile.ServiceTypes {
		if count > 0 {
			ctx.Logger.Printf("  - %s: %d", service, count)
		}
	}

	// PrintTopPort
	ctx.Logger.Printf("\n🔝 Top Open Ports:")
	for port, count := range profile.OpenPorts {
		if count > 2 { // Show only more than2Subport
			ctx.Logger.Printf("  - Port %d: %d instances", port, count)
		}
	}
}

// Auxiliary Functions

func extractRootDomain(domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	root, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return domain
	}
	return strings.ToLower(root)
}

func getPortRange(port int) string {
	switch {
	case port < 1024:
		return "well-known (0-1023)"
	case port < 49152:
		return "registered (1024-49151)"
	default:
		return "dynamic (49152-65535)"
	}
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func extractKeywords(title string) []string {
	// Simple keyword extraction (It's more sophisticated.NLPMethodology)
	keywords := []string{}
	words := strings.Fields(title)
	for _, word := range words {
		word = strings.TrimSpace(word)
		if len(word) > 2 { // Filter too short a word
			keywords = append(keywords, strings.ToLower(word))
		}
	}
	return keywords
}

func parseFingerprint(fingerprint string) []string {
	// Parsingfingerprint JSONString, Extracting Technical Repository Name
	techs := []string{}
	// Simple realization: AssumptionsfingerprintIt's a comma-separated string
	if fingerprint != "" {
		parts := strings.Split(fingerprint, ",")
		for _, part := range parts {
			tech := strings.TrimSpace(part)
			if tech != "" {
				techs = append(techs, tech)
			}
		}
	}
	return techs
}

func extractURLPath(url string) string {
	// ExtractURLPath part of the
	parts := strings.SplitN(url, "://", 2)
	if len(parts) == 2 {
		pathParts := strings.SplitN(parts[1], "/", 2)
		if len(pathParts) == 2 {
			return "/" + pathParts[1]
		}
	}
	return "/"
}

func extractCertIssuer(certInfo string) string {
	// Extract the issuer from the certificate information
	// Simple realization: Find"Issuer:"Okay.
	lines := strings.Split(certInfo, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Issuer:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				issuer := strings.TrimSpace(parts[1])
				// Extract organisation name (O=)
				if idx := strings.Index(issuer, "O="); idx >= 0 {
					orgPart := issuer[idx+2:]
					if endIdx := strings.Index(orgPart, ","); endIdx >= 0 {
						return orgPart[:endIdx]
					}
					return orgPart
				}
				return issuer
			}
		}
	}
	return "Unknown"
}
