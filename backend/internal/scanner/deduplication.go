package scanner

import (
	"crypto/md5"
	"fmt"
	"sync"
)

// DeduplicationCache To re-cached.
type DeduplicationCache struct {
	cache map[string]bool
	mu    sync.RWMutex
}

// NewDeduplicationCache Create to Recache
func NewDeduplicationCache() *DeduplicationCache {
	return &DeduplicationCache{
		cache: make(map[string]bool),
	}
}

// Add records a value and returns true when it was newly added.
func (dc *DeduplicationCache) Add(key string) bool {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	if dc.cache[key] {
		return false // Existing
	}

	dc.cache[key] = true
	return true // New records
}

// Exists Check if there is a problem.
func (dc *DeduplicationCache) Exists(key string) bool {
	dc.mu.RLock()
	defer dc.mu.RUnlock()

	return dc.cache[key]
}

// Clear Clear Cache
func (dc *DeduplicationCache) Clear() {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	dc.cache = make(map[string]bool)
}

// Size Fetch Cache Size
func (dc *DeduplicationCache) Size() int {
	dc.mu.RLock()
	defer dc.mu.RUnlock()

	return len(dc.cache)
}

// GenerateDomainKey Generate domain name to hard key
func GenerateDomainKey(taskID, domain string) string {
	return fmt.Sprintf("%s:%s", taskID, domain)
}

// GenerateIPKey GenerateIPGo to the hard key.
func GenerateIPKey(taskID, ip string) string {
	return fmt.Sprintf("%s:%s", taskID, ip)
}

// GeneratePortKey Generate port to heavy key
func GeneratePortKey(taskID, ip string, port int) string {
	return fmt.Sprintf("%s:%s:%d", taskID, ip, port)
}

// GenerateSiteKey Generate site to hard key (BasedURL)
func GenerateSiteKey(taskID, url string) string {
	return fmt.Sprintf("%s:%s", taskID, url)
}

// GenerateContentHash Generate content Hash (To re-read similar content)
func GenerateContentHash(content string) string {
	hash := md5.Sum([]byte(content))
	return fmt.Sprintf("%x", hash)
}

// ValidateDomain Authenticate domain name format
func ValidateDomain(domain string) bool {
	if domain == "" {
		return false
	}

	// Basic length check
	if len(domain) > 253 {
		return false
	}

	// Check whether illegal characters are included
	for _, char := range domain {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '.' || char == '-') {
			return false
		}
	}

	return true
}

// ValidateIP AuthenticationIPFormat (Simple Check)
func ValidateIP(ip string) bool {
	if ip == "" {
		return false
	}

	// Simple Authentication: Length and Characters
	if len(ip) < 7 || len(ip) > 15 {
		return false
	}

	parts := 0
	for _, char := range ip {
		if char == '.' {
			parts++
		} else if !(char >= '0' && char <= '9') {
			return false
		}
	}

	return parts == 3
}

// ValidatePort Validate port range
func ValidatePort(port int) bool {
	return port > 0 && port <= 65535
}

// ValidateURL AuthenticationURLFormat (Simple Check)
func ValidateURL(url string) bool {
	if url == "" {
		return false
	}

	// Check whether to usehttp://orhttps://Start
	if len(url) < 10 {
		return false
	}

	if url[:7] != "http://" && url[:8] != "https://" {
		return false
	}

	return true
}
