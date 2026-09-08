package scanner

import (
	"fmt"
	"time"

	"github.com/lcvvvv/gonmap"
)

// ServiceDetector Service identifier (Basedgonmap)
type ServiceDetector struct {
	timeout time.Duration
}

// NewServiceDetector Create Service Identification
func NewServiceDetector() *ServiceDetector {
	return &ServiceDetector{
		timeout: 5 * time.Second,
	}
}

// DetectService Services to identify individual ports
func (sd *ServiceDetector) DetectService(ip string, port int) (service, version, product string) {
	// UsegonmapService detection
	scanner := gonmap.New()

	// Set Timeout
	scanner.SetTimeout(sd.timeout)

	// Scan individual ports
	status, response := scanner.ScanTimeout(ip, port, sd.timeout)

	if status == gonmap.Matched && response != nil && response.FingerPrint != nil {
		// We've got a service print match.
		fp := response.FingerPrint
		service = fp.Service
		version = fp.Version
		product = fp.ProductName

		// Can not open message, Try fromInfoField Fetch
		if version == "" && fp.Info != "" {
			version = fp.Info
		}

		return service, version, product
	}

	// No fingerprints match., Returns Basic Information
	if status == gonmap.Open {
		// Port open but not identifiable service
		service = guessServiceByPort(port)
		return service, "", ""
	}

	// Default return unknown
	return "unknown", "", ""
}

// DetectServices Batch recognition services for multiple ports
func (sd *ServiceDetector) DetectServices(results []*PortScanResult) []*PortScanResult {
	fmt.Printf("🔍 Starting service detection for %d ports...\n", len(results))

	for i, result := range results {
		service, version, product := sd.DetectService(result.IP, result.Port)

		// Update Service Information
		result.Service = service
		if version != "" {
			result.Version = version
		}
		if product != "" {
			result.Product = product
		}

		// Print Progress
		if (i+1)%10 == 0 || i == len(results)-1 {
			fmt.Printf("  ✓ Detected %d/%d services\n", i+1, len(results))
		}
	}

	fmt.Printf("✓ Service detection complete\n")
	return results
}

// guessServiceByPort Guess the service type by port number (fallback)
func guessServiceByPort(port int) string {
	commonPorts := map[int]string{
		20:    "ftp-data",
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "domain",
		80:    "http",
		110:   "pop3",
		143:   "imap",
		443:   "https",
		445:   "microsoft-ds",
		3306:  "mysql",
		3389:  "ms-wbt-server",
		5432:  "postgresql",
		6379:  "redis",
		8080:  "http-proxy",
		8443:  "https-alt",
		9200:  "elasticsearch",
		27017: "mongodb",
		5000:  "upnp",
		8888:  "http-alt",
	}

	if service, exists := commonPorts[port]; exists {
		return service
	}

	return "unknown"
}
