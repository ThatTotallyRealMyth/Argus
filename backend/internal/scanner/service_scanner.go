package scanner

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

// ServiceScanner Service scanner
type ServiceScanner struct {
	serviceMap   map[int]string
	timeout      time.Duration // Load from Configuration
	bannerMaxLen int           // Load from Configuration
}

// NewServiceScanner Create Service Scanner
func NewServiceScanner() *ServiceScanner {
	return &ServiceScanner{
		serviceMap: map[int]string{
			21:    "ftp",
			22:    "ssh",
			23:    "telnet",
			25:    "smtp",
			53:    "dns",
			80:    "http",
			110:   "pop3",
			143:   "imap",
			443:   "https",
			445:   "smb",
			3306:  "mysql",
			3389:  "rdp",
			5432:  "postgresql",
			5900:  "vnc",
			6379:  "redis",
			8080:  "http-proxy",
			8443:  "https-alt",
			9200:  "elasticsearch",
			27017: "mongodb",
		},
	}
}

// Detect Identification services
func (ss *ServiceScanner) Detect(ctx *ScanContext) error {
	// 🆕 Load Scanner Configuration
	scannerConfig := LoadScannerConfig(ctx)
	ss.timeout = scannerConfig.ServiceTimeout
	ss.bannerMaxLen = scannerConfig.BannerMaxLength
	ctx.Logger.Printf("[Config] Service scanner: timeout=%v, banner_max_len=%d", ss.timeout, ss.bannerMaxLen)

	var ports []models.Port
	ctx.DB.Where("task_id = ? AND (service IS NULL OR service = '')", ctx.Task.ID).Find(&ports)

	ctx.Logger.Printf("Detecting services for %d ports", len(ports))

	// SSLScanner
	sslScanner := NewSSLScanner()

	for _, port := range ports {
		if err := ctx.ValidateNetworkTarget(port.IPAddress); err != nil {
			ctx.Logger.Printf("Service target blocked by scan scope: %s", port.IPAddress)
			continue
		}
		service := ss.detectService(port.IPAddress, port.Port)
		banner := ss.grabBanner(port.IPAddress, port.Port)

		updates := make(map[string]interface{})

		if service != "" {
			updates["service"] = service
		}

		if banner != "" {
			updates["banner"] = banner

			// FrombannerTest Version
			version := ss.extractVersion(banner)
			if version != "" {
				updates["version"] = version
			}
		}

		// If enabledSSLCertificate Acquisition
		if ctx.Task.Options.EnableSSLCert {
			if port.Port == 443 || port.Port == 8443 || service == "https" {
				certInfo, err := sslScanner.GetCertificate(port.IPAddress, port.Port)
				if err == nil {
					updates["ssl_cert"] = sslScanner.FormatCertInfo(certInfo)
					ctx.Logger.Printf("SSL cert obtained: %s:%d", port.IPAddress, port.Port)

					// Extract domain name from certificate (Require verification of target domain name)
					if len(certInfo.DNSNames) > 0 {
						// Get the destination domain name list
						targets := ctx.TargetList()
						for _, domain := range certInfo.DNSNames {
							if !strings.HasPrefix(domain, "*") {
								// Verify whether domain names belong to any of the target domain names
								isValidDomain := false
								for _, target := range targets {
									if ss.isSubdomainOf(domain, target) {
										isValidDomain = true
										break
									}
								}

								if isValidDomain {
									// Save found domain name
									d := &models.Domain{
										TaskID:    ctx.Task.ID,
										Domain:    domain,
										Source:    "ssl_cert",
										IPAddress: port.IPAddress,
									}
									ctx.DB.Create(d)
								}
							}
						}
					}
				}
			}
		}

		if len(updates) > 0 {
			ctx.DB.Model(&port).Updates(updates)
			ctx.Logger.Printf("Service detected: %s:%d -> %s", port.IPAddress, port.Port, service)
		}
	}

	return nil
}

// extractVersion FrombannerExtract Version Information
func (ss *ServiceScanner) extractVersion(banner string) string {
	// Simple version extraction logic
	// Matches a common version format: Numbers.Numbers.Numbers
	re := regexp.MustCompile(`\d+\.\d+\.?\d*`)
	match := re.FindString(banner)
	return match
}

// detectService Testing services (Optimize: Reduce misreporting)
func (ss *ServiceScanner) detectService(ip string, port int) string {
	// First try to get it from known port maps
	if service, exists := ss.serviceMap[port]; exists {
		// Optimize: For Standard Ports, Verify first.bannerBack
		banner := ss.grabBanner(ip, port)
		if banner != "" {
			// AuthenticationbannerMatching expected services
			if ss.verifyService(service, banner) {
				return service
			}
			// If not matched, Try frombannerIdentification of real services
			if realService := ss.identifyFromBanner(banner); realService != "" {
				return realService
			}
		}
		// Even if not.banner, Standard ports also return to the intended service.
		return service
	}

	// For non-standard ports, TrybannerGrab
	banner := ss.grabBanner(ip, port)
	if banner != "" {
		// FrombannerIdentification services
		if service := ss.identifyFromBanner(banner); service != "" {
			return service
		}
		return "unknown"
	}

	return ""
}

// verifyService Whether the certification service is in coordination withbannerMatch (Reduce misreporting)
func (ss *ServiceScanner) verifyService(expectedService, banner string) bool {
	banner = strings.ToLower(banner)

	// Define service feature keywords
	serviceKeywords := map[string][]string{
		"ssh":           {"ssh", "openssh"},
		"http":          {"http", "server:", "nginx", "apache"},
		"https":         {"http", "server:", "nginx", "apache"},
		"ftp":           {"ftp", "220"},
		"smtp":          {"smtp", "220"},
		"mysql":         {"mysql", "mariadb"},
		"redis":         {"redis"},
		"mongodb":       {"mongodb"},
		"postgresql":    {"postgresql"},
		"elasticsearch": {"elasticsearch"},
	}

	keywords, exists := serviceKeywords[expectedService]
	if !exists {
		return true // Service without feature keywords, Default Trust
	}

	// Check whether any keywords are contained
	for _, keyword := range keywords {
		if strings.Contains(banner, keyword) {
			return true
		}
	}

	return false
}

// identifyFromBanner FrombannerIdentification of service type
func (ss *ServiceScanner) identifyFromBanner(banner string) string {
	banner = strings.ToLower(banner)

	// Definition of Service Identification Rules
	identifyRules := map[string][]string{
		"ssh":           {"ssh-", "openssh"},
		"http":          {"http/1", "server:"},
		"ftp":           {"220", "ftp"},
		"smtp":          {"220", "smtp", "esmtp"},
		"mysql":         {"mysql", "mariadb"},
		"redis":         {"-err", "redis"},
		"mongodb":       {"mongodb"},
		"postgresql":    {"postgresql"},
		"elasticsearch": {"elasticsearch"},
		"nginx":         {"nginx"},
		"apache":        {"apache"},
	}

	for service, keywords := range identifyRules {
		for _, keyword := range keywords {
			if strings.Contains(banner, keyword) {
				return service
			}
		}
	}

	return ""
}

// isSubdomainOf Check if it's a subdomain name
func (ss *ServiceScanner) isSubdomainOf(subdomain, domain string) bool {
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

// grabBanner Grabbanner
func (ss *ServiceScanner) grabBanner(ip string, port int) string {
	// 🆕 Use configured timeout
	timeout := ss.timeout
	if timeout == 0 {
		timeout = 3 * time.Second // Default3sec
	}

	// 🆕 Use configuredbannerMaximum length
	bannerLen := ss.bannerMaxLen
	if bannerLen == 0 {
		bannerLen = 2048 // Default2048Bytes
	}

	address := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Set the timeout for reading
	conn.SetReadDeadline(time.Now().Add(timeout))

	buffer := make([]byte, bannerLen)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	return string(buffer[:n])
}
