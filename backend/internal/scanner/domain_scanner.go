package scanner

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/reconmaster/backend/internal/config"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/proxypool"
)

// DomainScanner Domain name scanner
type DomainScanner struct {
	dictionaries map[string][]string
	dnsResolvers []string
	timeout      time.Duration
	retryCount   int
	concurrency  int // Domain name explosion and launch (Load from Configuration)
}

// DomainStats Domain name scanning statistics
type DomainStats struct {
	TotalAttempts   int64
	ResolvedDomains int64
	FailedAttempts  int64
	StartTime       time.Time
}

// NewDomainScanner Create domain name scanner
func NewDomainScanner() *DomainScanner {
	ds := &DomainScanner{
		dictionaries: make(map[string][]string),
		dnsResolvers: []string{
			"8.8.8.8:53",         // Google DNS
			"8.8.4.4:53",         // Google DNS Secondary
			"1.1.1.1:53",         // Cloudflare DNS
			"1.0.0.1:53",         // Cloudflare DNS Secondary
			"223.5.5.5:53",       // Ali.DNS
			"223.6.6.6:53",       // Ali.DNS Secondary
			"114.114.114.114:53", // 114DNS
			"114.114.115.115:53", // 114DNS Secondary
		},
		timeout:    5 * time.Second,
		retryCount: 2,
	}

	// Load Dictionary
	ds.loadDictionaries()

	return ds
}

// loadDictionaries Load Dictionary Files
func (ds *DomainScanner) loadDictionaries() {
	// Internal Test Dictionary - Extension
	ds.dictionaries["test"] = []string{
		"www", "mail", "ftp", "admin", "test", "dev", "api", "app",
		"m", "wap", "mobile", "blog", "forum", "bbs", "shop", "store",
		"vpn", "oa", "crm", "erp", "cdn", "img", "image", "static",
		"video", "live", "stream", "download", "upload", "cloud",
	}

	// Try loading large dictionary from file
	bigDictPath := "./configs/dicts/domain/big.txt"
	if dict, err := ds.loadDictFromFile(bigDictPath); err == nil {
		ds.dictionaries["big"] = dict
	} else {
		// If the file does not exist, Use generated large dictionary
		ds.dictionaries["big"] = generateBigDict()
	}
}

// loadDictFromFile Load Dictionary from File
func (ds *DomainScanner) loadDictFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var dict []string
	scanner := bufio.NewScanner(file)
	// Increase the buffer zone to handle the movement
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Filter empty lines and comments
		if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "//") {
			// Authenticate subdomain name formats
			if ds.isValidSubdomain(line) {
				dict = append(dict, line)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return dict, nil
}

// loadDictFromDatabase Load Dictionary From Database
func (ds *DomainScanner) loadDictFromDatabase(ctx *ScanContext, dictName string) ([]string, error) {
	// Query database to get dictionary information
	var dictionary models.Dictionary
	if err := ctx.DB.Where("name = ? AND type = ?", dictName, "domain").First(&dictionary).Error; err != nil {
		return nil, fmt.Errorf("dictionary not found: %s", dictName)
	}

	// Load dictionary contents from file path
	return ds.loadDictFromFile(dictionary.FilePath)
}

// Scan Execute domain scan
func (ds *DomainScanner) Scan(ctx *ScanContext) error {
	// 🆕 Load Scanner Configuration
	scannerConfig := LoadScannerConfig(ctx)
	ds.timeout = scannerConfig.DomainTimeout
	ds.retryCount = scannerConfig.DomainRetry
	ds.concurrency = scannerConfig.DomainConcurrency
	ctx.Logger.Printf("[Config] Domain scanner: concurrency=%d, timeout=%v, retry=%d",
		ds.concurrency, ds.timeout, ds.retryCount)

	targets := ctx.TargetList()

	for _, target := range targets {
		if target == "" {
			continue
		}

		if domain, ok := domainTarget(target); ok {
			resolvedIPs, resolveErr := ds.resolveWithRetry(domain)
			primaryIP := ""
			if resolveErr != nil {
				ctx.Logger.Printf("Root domain resolution failed for %s: %v", domain, resolveErr)
			} else {
				for _, ip := range resolvedIPs {
					if primaryIP == "" {
						primaryIP = ip
					}
					ds.saveIP(ctx, ip, domain)
				}
				ctx.Logger.Printf("Root domain resolved: %s -> %v", domain, resolvedIPs)
			}
			ds.saveDomain(ctx, domain, "target", primaryIP)

			if ctx.Task.Options.EnableDomainBrute {
				if err := ds.bruteForceDomain(ctx, domain); err != nil {
					ctx.Logger.Printf("Domain brute force failed: %v", err)
				}
			}

			// Query domain names using plugins
			if ctx.Task.Options.EnableDomainPlugins {
				if err := ds.queryDomainPlugins(ctx, domain); err != nil {
					ctx.Logger.Printf("Domain plugins query failed: %v", err)
				}
			}
		}
	}

	// After scan is complete, Batch UpdatesIPGeographical location
	ctx.Logger.Printf("Updating IP locations in batch...")
	ds.updateIPLocationsInBatch(ctx)

	return nil
}

// bruteForceDomain Domain Blast (Optimizing)
func (ds *DomainScanner) bruteForceDomain(ctx *ScanContext, domain string) error {
	dictType := ctx.Task.Options.DomainBruteType
	if dictType == "" {
		dictType = "big" // Default usebigDictionary
	}

	// Try loading it from the memory dictionary first
	dict, exists := ds.dictionaries[dictType]

	// If there is no memory, Try loading from database
	if !exists {
		ctx.Logger.Printf("Dictionary '%s' not in memory, trying to load from database...", dictType)
		loadedDict, err := ds.loadDictFromDatabase(ctx, dictType)
		if err != nil {
			ctx.Logger.Printf("Failed to load dictionary from database: %v, using test dict", err)
			dict = ds.dictionaries["test"]
		} else {
			dict = loadedDict
			ds.dictionaries[dictType] = loadedDict // Cache to Memory
			ctx.Logger.Printf("Loaded dictionary '%s' from database: %d entries", dictType, len(dict))
		}
	}

	if len(dict) == 0 {
		return fmt.Errorf("empty dictionary: %s", dictType)
	}

	ctx.Logger.Printf("=== Domain Brute Force Started ===")
	ctx.Logger.Printf("Target Domain: %s", domain)
	ctx.Logger.Printf("Dictionary: %s (%d entries)", dictType, len(dict))

	// Smart Dictionary Generation
	if ctx.Task.Options.SmartDictGen {
		smartDict := ds.generateSmartDict(ctx, domain)
		if len(smartDict) > 0 {
			ctx.Logger.Printf("Generated %d smart dictionary entries", len(smartDict))
			dict = append(dict, smartDict...)
		}
	}

	// To re-instate and verify
	uniqueDict := ds.deduplicateAndValidate(dict)
	ctx.Logger.Printf("Final dictionary size: %d entries (after deduplication)", len(uniqueDict))

	// Initialization of statistics
	stats := &DomainStats{
		TotalAttempts: int64(len(uniqueDict)),
		StartTime:     time.Now(),
	}

	// Adjusted and distributed according to dictionary size dynamics
	concurrency := ds.calculateConcurrency(len(uniqueDict))
	ctx.Logger.Printf("Concurrency: %d", concurrency)
	ctx.Logger.Printf("DNS Servers: %d", len(ds.dnsResolvers))
	ctx.Logger.Printf("Retry Count: %d", ds.retryCount)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency)

	// Use a buffer result channel
	results := make(chan *DomainResult, 100)

	// UsecontextSupport for Cancel
	scanCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start result processinggoroutine
	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		ds.processResults(scanCtx, results, ctx, stats)
	}()

	// Progress reportgoroutine
	go ds.reportProgress(scanCtx, stats, ctx)

	// Execute Blast
	for _, subdomain := range uniqueDict {
		select {
		case <-scanCtx.Done():
			break
		case <-ctx.Ctx.Done():
			ctx.Logger.Printf("Domain brute force cancelled by user")
			cancel()
			break
		default:
		}

		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			fullDomain := sub + "." + domain
			if err := ctx.ValidateNetworkTarget(fullDomain); err != nil {
				atomic.AddInt64(&stats.FailedAttempts, 1)
				return
			}

			// Resolve domain names (Bring a retry)
			ips, err := ds.resolveWithRetry(fullDomain)
			if err == nil && len(ips) > 0 {
				// Send Results
				select {
				case results <- &DomainResult{
					Domain: fullDomain,
					IPs:    ips,
					Source: "brute",
				}:
				case <-scanCtx.Done():
				}
			} else {
				atomic.AddInt64(&stats.FailedAttempts, 1)
			}
		}(subdomain)
	}

	// Waiting for all scans to be finished
	wg.Wait()
	close(results)

	// Pending outcome processing
	resultWg.Wait()

	// Final statistics
	elapsed := time.Since(stats.StartTime)
	ctx.Logger.Printf("=== Domain Brute Force Completed ===")
	ctx.Logger.Printf("Resolved: %d", stats.ResolvedDomains)
	ctx.Logger.Printf("Failed: %d", stats.FailedAttempts)
	ctx.Logger.Printf("Total Attempts: %d", stats.TotalAttempts)
	ctx.Logger.Printf("Time Elapsed: %v", elapsed)
	ctx.Logger.Printf("Resolution Rate: %.2f domains/sec", float64(stats.TotalAttempts)/elapsed.Seconds())

	return nil
}

// DomainResult Domain name resolution result
type DomainResult struct {
	Domain string
	IPs    []string
	Source string
}

// processResults Process parsing results
func (ds *DomainScanner) processResults(ctx context.Context, results chan *DomainResult, scanCtx *ScanContext, stats *DomainStats) {
	for {
		select {
		case <-ctx.Done():
			return
		case result, ok := <-results:
			if !ok {
				return
			}

			// Validate domain names
			if ds.validateDomain(result.Domain, result.IPs) {
				atomic.AddInt64(&stats.ResolvedDomains, 1)
				scanCtx.Logger.Printf("[FOUND] %s -> %s", result.Domain, result.IPs[0])
				ds.saveDomain(scanCtx, result.Domain, result.Source, result.IPs[0])

				// Save all parsedIP
				for _, ip := range result.IPs {
					ds.saveIP(scanCtx, ip, result.Domain)
				}
			}
		}
	}
}

// resolveWithRetry With a retry.DNSParsing
func (ds *DomainScanner) resolveWithRetry(domain string) ([]string, error) {
	var lastErr error

	for i := 0; i <= ds.retryCount; i++ {
		// Use differentDNSServer rotation
		dnsServer := ds.dnsResolvers[i%len(ds.dnsResolvers)]

		ips, err := ds.resolveWithDNS(domain, dnsServer)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}

		lastErr = err

		// Short delay before retry
		if i < ds.retryCount {
			time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
		}
	}

	return nil, lastErr
}

// resolveWithDNS Use AssignedDNSServer Parsing
func (ds *DomainScanner) resolveWithDNS(domain string, dnsServer string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ds.timeout)
	defer cancel()

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: ds.timeout,
			}
			return d.DialContext(ctx, "udp", dnsServer)
		},
	}

	ips, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		return nil, err
	}

	// Filter and weigh.IP
	return ds.filterIPs(ips), nil
}

// filterIPs Filter and weigh.IPAddress
func (ds *DomainScanner) filterIPs(ips []string) []string {
	seen := make(map[string]bool)
	var filtered []string

	for _, ip := range ips {
		// Skip local and invalid addresses
		if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "0.") {
			continue
		}

		// SkipIPv6Address (Optional)
		if strings.Contains(ip, ":") {
			continue
		}

		if !seen[ip] {
			seen[ip] = true
			filtered = append(filtered, ip)
		}
	}

	return filtered
}

// validateDomain Validate domain names
func (ds *DomainScanner) validateDomain(domain string, ips []string) bool {
	// Basic Authentication
	if len(ips) == 0 {
		return false
	}

	// Filter Pan-Parse (Simple Test)
	// If you parse a common pan-synthesisIP, Could need to filter.
	wildcardIPs := map[string]bool{
		"127.0.0.1": true,
		"0.0.0.0":   true,
	}

	for _, ip := range ips {
		if wildcardIPs[ip] {
			return false
		}
	}

	return true
}

// deduplicateAndValidate To re-establish and verify the dictionary
func (ds *DomainScanner) deduplicateAndValidate(dict []string) []string {
	seen := make(map[string]bool)
	var unique []string

	for _, entry := range dict {
		entry = strings.TrimSpace(strings.ToLower(entry))
		if entry == "" || seen[entry] {
			continue
		}

		// Authenticate subdomain name formats
		if ds.isValidSubdomain(entry) {
			seen[entry] = true
			unique = append(unique, entry)
		}
	}

	return unique
}

// isValidSubdomain Authenticate subdomain name formats
func (ds *DomainScanner) isValidSubdomain(subdomain string) bool {
	// Length Check
	if len(subdomain) == 0 || len(subdomain) > 63 {
		return false
	}

	// Character Check: Only Letters allowed, Numbers, Hyphenation, Can not start or end with hyphen
	if strings.HasPrefix(subdomain, "-") || strings.HasSuffix(subdomain, "-") {
		return false
	}

	// Simple Regular Validation
	for _, c := range subdomain {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}

	return true
}

// calculateConcurrency Calculate reasonable co-mingling
func (ds *DomainScanner) calculateConcurrency(dictSize int) int {
	// 🆕 Prefer to the number of co-mingled releases of the configuration
	if ds.concurrency > 0 {
		return ds.concurrency
	}

	// Back to Dynamic Calculate Based on Dictionary Size
	// Small Dictionary
	if dictSize < 100 {
		return 20
	}
	// Chinese dictionary
	if dictSize < 1000 {
		return 50
	}
	// Big Dictionary
	if dictSize < 10000 {
		return 100
	}
	// Super Dictionary
	return 200
}

// reportProgress Periodic reporting on progress
func (ds *DomainScanner) reportProgress(ctx context.Context, stats *DomainStats, scanCtx *ScanContext) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			resolved := atomic.LoadInt64(&stats.ResolvedDomains)
			failed := atomic.LoadInt64(&stats.FailedAttempts)
			total := stats.TotalAttempts
			attempted := resolved + failed

			if total > 0 {
				progress := float64(attempted) / float64(total) * 100
				elapsed := time.Since(stats.StartTime)
				rate := float64(attempted) / elapsed.Seconds()

				// Estimated remaining time
				remaining := time.Duration(0)
				if rate > 0 {
					remaining = time.Duration(float64(total-attempted)/rate) * time.Second
				}

				scanCtx.Logger.Printf("[Progress] %.1f%% (%d/%d) | Resolved: %d | Failed: %d | Rate: %.0f/s | ETA: %v",
					progress, attempted, total, resolved, failed, rate, remaining.Round(time.Second))
			}
		}
	}
}

// generateSmartDict Smart Generate Dictionary
func (ds *DomainScanner) generateSmartDict(ctx *ScanContext, domain string) []string {
	var dict []string

	// Extract keywords from found subdomain names
	var existingDomains []models.Domain
	ctx.DB.Where("task_id = ? AND domain LIKE ?", ctx.Task.ID, "%."+domain).Limit(100).Find(&existingDomains)

	if len(existingDomains) == 0 {
		return dict
	}

	keywords := make(map[string]bool)
	for _, d := range existingDomains {
		// Extract subdomain name prefix
		subdomain := strings.TrimSuffix(d.Domain, "."+domain)
		parts := strings.Split(subdomain, ".")

		for _, part := range parts {
			// Keyword before extracting numbers
			base := strings.TrimRight(part, "0123456789-_")
			if base != "" && len(base) > 1 {
				keywords[base] = true
			}
		}
	}

	if len(keywords) == 0 {
		return dict
	}

	// Generate variants based on keywords
	variations := []string{
		"", "1", "2", "3", "4", "5",
		"01", "02", "03",
		"-1", "-2", "-test", "-dev", "-prod", "-staging",
		"test", "dev", "prod", "uat", "pre",
	}

	for keyword := range keywords {
		for _, suffix := range variations {
			candidate := keyword + suffix
			if ds.isValidSubdomain(candidate) {
				dict = append(dict, candidate)
			}
		}
	}

	// Add Common Group
	prefixes := []string{"dev", "test", "staging", "prod", "uat", "pre", "demo", "beta", "alpha", "new", "old"}
	for keyword := range keywords {
		for _, prefix := range prefixes {
			candidate1 := prefix + "-" + keyword
			candidate2 := keyword + "-" + prefix
			candidate3 := prefix + keyword

			if ds.isValidSubdomain(candidate1) {
				dict = append(dict, candidate1)
			}
			if ds.isValidSubdomain(candidate2) {
				dict = append(dict, candidate2)
			}
			if ds.isValidSubdomain(candidate3) {
				dict = append(dict, candidate3)
			}
		}
	}

	return dict
}

// queryDomainPlugins Query domain name plugin
func (ds *DomainScanner) queryDomainPlugins(ctx *ScanContext, domain string) error {
	pluginNames := ctx.Task.Options.DomainPlugins
	if len(pluginNames) == 0 {
		// Use some free plugins by default
		pluginNames = []string{"crtsh", "hackertarget"}
		ctx.Logger.Printf("⚠️ No plugins specified in task options, using default: %v", pluginNames)
	}

	ctx.Logger.Printf("=== Domain Plugins Query Started ===")
	ctx.Logger.Printf("Target Domain: %s", domain)
	ctx.Logger.Printf("Selected Plugins: %v (%d)", pluginNames, len(pluginNames))

	// Retrieve from database API Keys
	apiKeys := ds.loadAPIKeys(ctx)
	ctx.Logger.Printf("Loaded API Keys: %d", len(apiKeys))
	for key := range apiKeys {
		if strings.Contains(key, "fofa") || strings.Contains(key, "hunter") {
			ctx.Logger.Printf("  - %s: %s", key, maskKey(apiKeys[key]))
		}
	}

	// Get All Available Plugins
	allPlugins := GetAvailablePlugins(apiKeys)
	ctx.Logger.Printf("Available Plugins: %d", len(allPlugins))
	pluginMap := make(map[string]DomainPlugin)
	for _, p := range allPlugins {
		pluginMap[p.Name()] = p
		ctx.Logger.Printf("  - %s", p.Name())
	}

	// For weight-decomposition
	foundDomains := make(map[string]bool)

	// Execute Plugin Query
	for _, pluginName := range pluginNames {
		plugin, exists := pluginMap[pluginName]
		if !exists {
			ctx.Logger.Printf("Plugin not found: %s", pluginName)
			continue
		}

		ctx.Logger.Printf("Running plugin: %s", pluginName)
		domains, err := plugin.Query(domain)
		if err != nil {
			ctx.Logger.Printf("Plugin %s failed: %v", pluginName, err)
			continue
		}

		ctx.Logger.Printf("Plugin %s found %d domains (before filtering)", pluginName, len(domains))

		// Collect domain names to process
		var validDomains []string
		for _, d := range domains {
			// Important: Verify whether domain names belong to the target domain name
			if !ds.isSubdomainOf(d, domain) {
				continue
			}
			if err := ctx.ValidateNetworkTarget(d); err != nil {
				ctx.Logger.Printf("Plugin target blocked by scan scope: %s", d)
				continue
			}

			if !foundDomains[d] {
				foundDomains[d] = true
				validDomains = append(validDomains, d)
			}
		}

		// Sending and processing domain names for resolution and saving
		ctx.Logger.Printf("Plugin %s: processing %d valid domains concurrently", pluginName, len(validDomains))
		validCount := ds.processDomainsInParallel(ctx, validDomains, "plugin:"+pluginName)
		ctx.Logger.Printf("Plugin %s: %d valid subdomains saved", pluginName, validCount)
	}

	ctx.Logger.Printf("Total unique domains from plugins: %d", len(foundDomains))
	return nil
}

// processDomainsInParallel Sending and processing domain names for resolution and saving
func (ds *DomainScanner) processDomainsInParallel(ctx *ScanContext, domains []string, source string) int {
	if len(domains) == 0 {
		return 0
	}

	// Use and send hand-out, Efficiency gains
	workers := 50 // Number of co-existes
	if len(domains) < workers {
		workers = len(domains)
	}

	domainChan := make(chan string, len(domains))
	successChan := make(chan int, workers)

	var wg sync.WaitGroup

	// Startworker
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localSuccess := 0
			for d := range domainChan {
				// ParsingIP
				ips, err := ds.resolveWithRetry(d)
				if err == nil && len(ips) > 0 {
					ds.saveDomain(ctx, d, source, ips[0])

					// SaveIP
					for _, ip := range ips {
						ds.saveIPOptimized(ctx, ip, d)
					}
					localSuccess++
				}
			}
			successChan <- localSuccess
		}()
	}

	// _Other Organiser
	for _, d := range domains {
		domainChan <- d
	}
	close(domainChan)

	// Waiting for completion
	wg.Wait()
	close(successChan)

	// Number of successful statistics
	totalSuccess := 0
	for count := range successChan {
		totalSuccess += count
	}

	return totalSuccess
}

// saveDomain Save Domain Name Information
func (ds *DomainScanner) saveDomain(ctx *ScanContext, domain, source, ip string) {
	d := &models.Domain{
		TaskID: ctx.Task.ID,
		Domain: domain,
		Source: source,
	}

	if ip != "" {
		d.IPAddress = ip
	}

	// UseFirstOrCreateAvoidance of duplication
	ctx.DB.Where("task_id = ? AND domain = ?", ctx.Task.ID, domain).FirstOrCreate(d)
}

// saveIP SaveIPInformation
func (ds *DomainScanner) saveIP(ctx *ScanContext, ip, domain string) {
	ipModel := &models.IP{
		TaskID:    ctx.Task.ID,
		IPAddress: ip,
		Domain:    domain,
	}

	// QueryIPGeographical location
	if location := getIPLocation(ip); location != "" {
		ipModel.Location = location
	}

	// UseFirstOrCreateAvoidance of duplication
	ctx.DB.Where("task_id = ? AND ip_address = ?", ctx.Task.ID, ip).FirstOrCreate(ipModel)
}

// saveIPOptimized OptimizingIPSave (Used for batch processing, Delaying query location)
func (ds *DomainScanner) saveIPOptimized(ctx *ScanContext, ip, domain string) {
	ipModel := &models.IP{
		TaskID:    ctx.Task.ID,
		IPAddress: ip,
		Domain:    domain,
	}

	// No geometry first., AvoidAPIStream Limit
	// Geographic location allows subsequent batch updates

	// UseFirstOrCreateAvoidance of duplication
	ctx.DB.Where("task_id = ? AND ip_address = ?", ctx.Task.ID, ip).FirstOrCreate(ipModel)
}

// updateIPLocationsInBatch Batch UpdatesIPGeolocation information
func (ds *DomainScanner) updateIPLocationsInBatch(ctx *ScanContext) {
	// Queries all ungeographically locatedIP
	var ips []models.IP
	ctx.DB.Where("task_id = ? AND (location IS NULL OR location = '')", ctx.Task.ID).Find(&ips)

	if len(ips) == 0 {
		ctx.Logger.Printf("No IPs need location update")
		return
	}

	ctx.Logger.Printf("Updating location for %d IPs (rate limited to avoid API throttling)", len(ips))

	// Stream Limit: Up to one minute.45One request. (ip-api.comFree restrictions)
	ticker := time.NewTicker(1350 * time.Millisecond) // NYO44One request./min
	defer ticker.Stop()

	updatedCount := 0
	for i, ip := range ips {
		// Waiting for the limit stream
		if i > 0 {
			<-ticker.C
		}

		// Query Geographic Location
		location := getIPLocation(ip.IPAddress)
		if location != "" {
			ctx.DB.Model(&ip).Update("location", location)
			updatedCount++
		}

		// Every50One.IPRecord progress once
		if (i+1)%50 == 0 {
			ctx.Logger.Printf("IP location update progress: %d/%d", i+1, len(ips))
		}
	}

	ctx.Logger.Printf("IP location update completed: %d/%d", updatedCount, len(ips))
}

// isDomain Determine whether to use domain names
func domainTarget(target string) (string, bool) {
	candidate := strings.TrimSpace(target)
	if candidate == "" {
		return "", false
	}
	if _, _, err := net.ParseCIDR(candidate); err == nil {
		return "", false
	}
	parseValue := candidate
	if !strings.Contains(parseValue, "://") {
		parseValue = "//" + parseValue
	}
	parsed, err := url.Parse(parseValue)
	if err != nil {
		return "", false
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "" || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return "", false
	}
	return host, true
}

// isSubdomainOf Judgement subdomain Is it? domain subdomain name or equal to domain
func (ds *DomainScanner) isSubdomainOf(subdomain, domain string) bool {
	subdomain = strings.ToLower(strings.TrimSpace(subdomain))
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Perfect match.
	if subdomain == domain {
		return true
	}

	// Subdomain name must .domain End
	suffix := "." + domain
	if strings.HasSuffix(subdomain, suffix) {
		return true
	}

	return false
}

// loadAPIKeys Load from Database API Keys
func (ds *DomainScanner) loadAPIKeys(ctx *ScanContext) map[string]string {
	apiKeys := make(map[string]string)

	// Query All API Category Settings
	var settings []models.Setting
	ctx.DB.Where("category = ?", "api").Find(&settings)

	for _, setting := range settings {
		// If it's encrypted,, Decrypt required
		value := setting.Value
		if setting.IsEncrypted && value != "" {
			decrypted, err := decryptValue(value)
			if err != nil {
				ctx.Logger.Printf("Failed to decrypt %s: %v", setting.Key, err)
				continue
			}
			value = decrypted
		}

		// Only non-empty values add to apiKeys
		if value != "" {
			apiKeys[setting.Key] = value
		}
	}

	return apiKeys
}

// maskKey Hide Key Display
func maskKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "****" + key[len(key)-4:]
}

// decryptValue Decrypt Encryption Values
func decryptValue(ciphertext string) (string, error) {
	// Get Encryption Keys, Remarkable configuration
	if config.GlobalConfig == nil {
		return "", fmt.Errorf("encryption configuration is unavailable")
	}
	key := config.GlobalConfig.Encryption.Key
	if key == "" {
		return "", fmt.Errorf("encryption.key is not configured")
	}

	encryptionKey := []byte(key)

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, cipherData := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// generateBigDict Generate built-in large dictionary
func generateBigDict() []string {
	// Common Prefix
	prefixes := []string{
		"www", "mail", "ftp", "webmail", "smtp", "pop", "pop3", "imap", "admin",
		"test", "dev", "stage", "staging", "prod", "production", "demo", "beta", "alpha",
		"api", "app", "mobile", "m", "wap", "web", "www2", "www3",
		"blog", "forum", "bbs", "support", "help", "docs", "doc", "wiki",
		"shop", "store", "cart", "order", "pay", "payment",
		"user", "member", "account", "login", "register", "auth",
		"static", "img", "image", "images", "pic", "pics", "photo", "photos",
		"css", "js", "assets", "cdn", "static", "resource", "resources",
		"video", "videos", "media", "stream", "live",
		"download", "downloads", "upload", "uploads", "file", "files",
		"news", "article", "post", "content",
		"search", "find", "query",
		"data", "db", "database", "mysql", "oracle", "mssql", "redis", "mongodb",
		"cache", "memcache", "memcached",
		"service", "services", "svc",
		"vpn", "proxy", "gateway", "gw",
		"monitor", "monitoring", "dashboard", "console", "panel", "cp", "admin",
		"backup", "bak", "temp", "tmp", "old", "new",
		"log", "logs", "logger", "logging",
		"git", "svn", "hg", "repo", "code",
		"ci", "cd", "jenkins", "travis", "gitlab", "github",
		"docker", "k8s", "kube", "kubernetes",
		"cloud", "public", "private", "internal", "external",
		"oa", "crm", "erp", "hr", "finance",
	}

	// Add a digital variable
	var dict []string
	for _, prefix := range prefixes {
		dict = append(dict, prefix)
		// Add a common number suffix
		for i := 1; i <= 10; i++ {
			dict = append(dict, fmt.Sprintf("%s%d", prefix, i))
			dict = append(dict, fmt.Sprintf("%s-%d", prefix, i))
			dict = append(dict, fmt.Sprintf("%s%02d", prefix, i))
		}
	}

	return dict
}

// getIPLocation QueryIPGeographical location (Free useAPI)
func getIPLocation(ip string) string {
	// Skip PrivateIP
	if isPrivateIP(ip) {
		return "IntranetIP"
	}

	// Use ip-api.com Free.API (No key required, Limits45Number of times/min)
	url := fmt.Sprintf("http://ip-api.com/json/%s?lang=zh-CN&fields=status,country,regionName,city,isp", ip)

	client := &http.Client{Timeout: 5 * time.Second, Transport: proxypool.ConfigureTransport(&http.Transport{})}
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	var result struct {
		Status     string `json:"status"`
		Country    string `json:"country"`
		RegionName string `json:"regionName"`
		City       string `json:"city"`
		ISP        string `json:"isp"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return ""
	}

	if result.Status != "success" {
		return ""
	}

	// Group geolocation information
	location := result.Country
	if result.RegionName != "" && result.RegionName != result.Country {
		location += " " + result.RegionName
	}
	if result.City != "" && result.City != result.RegionName {
		location += " " + result.City
	}
	if result.ISP != "" {
		location += " (" + result.ISP + ")"
	}

	return location
}

// isPrivateIP To judge whether it's private or not.IP
func isPrivateIP(ip string) bool {
	privateIPBlocks := []string{
		"10.",
		"172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
		"172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
		"192.168.",
		"127.",
		"169.254.",
		"::1",
		"fc00:",
		"fe80:",
	}

	for _, block := range privateIPBlocks {
		if strings.HasPrefix(ip, block) {
			return true
		}
	}

	return false
}
