package scanner

import (
	"strconv"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

// ScannerConfig Scanner Configuration
type ScannerConfig struct {
	// Domain name scanning configuration
	DomainConcurrency            int
	DomainTimeout                time.Duration
	DomainRetry                  int
	SubdomainTakeoverConcurrency int

	// Port Scan Configuration
	PortConcurrencySmall  int
	PortConcurrencyMedium int
	PortConcurrencyLarge  int
	PortTimeout           time.Duration

	// Site Scan Configuration
	SiteConcurrency int
	SiteTimeout     time.Duration
	CrawlerMaxDepth int
	CrawlerMaxPages int

	// Service Recognition Configuration
	ServiceTimeout  time.Duration
	BannerMaxLength int

	// IPGeographical location configuration
	IPLocationRateLimit int
	IPLocationBatchSize int

	// Directory and Sensitive File Enumeration Configuration
	FileLeakConcurrency int
	FileLeakRateLimit   int
}

// LoadScannerConfig Load scanner configuration from database
func LoadScannerConfig(ctx *ScanContext) *ScannerConfig {
	config := &ScannerConfig{
		// Default value - Domain Scanning
		DomainConcurrency:            50,
		DomainTimeout:                3 * time.Second,
		DomainRetry:                  2,
		SubdomainTakeoverConcurrency: 20,

		// Default value - Port Scan
		PortConcurrencySmall:  100,
		PortConcurrencyMedium: 300,
		PortConcurrencyLarge:  500,
		PortTimeout:           1500 * time.Millisecond, // 1.5sec

		// Default value - Site Scan
		SiteConcurrency: 30,
		SiteTimeout:     5 * time.Second,
		CrawlerMaxDepth: 3,
		CrawlerMaxPages: 500,

		// Default value - Service recognition
		ServiceTimeout:  3 * time.Second,
		BannerMaxLength: 2048,

		// Default value - IPGeographical location
		IPLocationRateLimit: 10,
		IPLocationBatchSize: 20,

		// Default value - Directory and sensitive document listings
		FileLeakConcurrency: 20,
		FileLeakRateLimit:   0,
	}

	// Load Configuration From Database
	var settings []models.Setting
	ctx.DB.Where("category = ?", "scanner").Find(&settings)

	for _, setting := range settings {
		normalized, err := NormalizeScannerSettingValue(setting.Key, setting.Value)
		if err != nil {
			continue
		}
		setting.Value = normalized
		switch setting.Key {
		// Domain name scanning configuration
		case "domain_concurrency":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.DomainConcurrency = val
			}
		case "domain_timeout":
			if val, err := strconv.ParseFloat(setting.Value, 64); err == nil && val > 0 {
				config.DomainTimeout = time.Duration(val * float64(time.Second))
			}
		case "domain_retry":
			if val, err := strconv.Atoi(setting.Value); err == nil && val >= 0 {
				config.DomainRetry = val
			}
		case "subdomain_takeover_concurrency":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.SubdomainTakeoverConcurrency = val
			}

		// Port Scan Configuration
		case "port_concurrency_small":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.PortConcurrencySmall = val
			}
		case "port_concurrency_medium":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.PortConcurrencyMedium = val
			}
		case "port_concurrency_large":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.PortConcurrencyLarge = val
			}
		case "port_timeout":
			if val, err := strconv.ParseFloat(setting.Value, 64); err == nil && val > 0 {
				config.PortTimeout = time.Duration(val * float64(time.Second))
			}

		// Site Scan Configuration
		case "site_concurrency":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.SiteConcurrency = val
			}
		case "site_timeout":
			if val, err := strconv.ParseFloat(setting.Value, 64); err == nil && val > 0 {
				config.SiteTimeout = time.Duration(val * float64(time.Second))
			}
		case "crawler_max_depth":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.CrawlerMaxDepth = val
			}
		case "crawler_max_pages":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.CrawlerMaxPages = val
			}

		// Service Recognition Configuration
		case "service_timeout":
			if val, err := strconv.ParseFloat(setting.Value, 64); err == nil && val > 0 {
				config.ServiceTimeout = time.Duration(val * float64(time.Second))
			}
		case "banner_max_length":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.BannerMaxLength = val
			}

		// IPGeographical location configuration
		case "ip_location_rate_limit":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.IPLocationRateLimit = val
			}
		case "ip_location_batch_size":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.IPLocationBatchSize = val
			}

		case "file_leak_concurrency":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.FileLeakConcurrency = val
			}
		case "file_leak_rate_limit":
			if val, err := strconv.Atoi(setting.Value); err == nil && val >= 0 {
				config.FileLeakRateLimit = val
			}
		}
	}

	return config
}
