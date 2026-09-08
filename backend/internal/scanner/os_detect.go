package scanner

import (
	"fmt"
	"net"
	"time"
)

// OSDetector Operating system detector
type OSDetector struct {
	timeout time.Duration
}

// NewOSDetector CreateOSDetection
func NewOSDetector() *OSDetector {
	return &OSDetector{
		timeout: 5 * time.Second,
	}
}

// Detect Test operating system
func (od *OSDetector) Detect(ip string, openPorts []int) string {
	// Inference of operating systems based on open ports and service characteristics

	// WindowsCharacteristics
	windowsScore := 0
	// LinuxCharacteristics
	linuxScore := 0
	// Other characteristics
	otherScore := 0

	for _, port := range openPorts {
		switch port {
		case 135, 139, 445, 3389: // WindowsCommon Port
			windowsScore += 2
		case 22, 111, 2049: // LinuxCommon Port
			linuxScore += 2
		case 80, 443, 8080: // Universal Port
			// No point.
		}
	}

	// TryTTLTest
	ttl := od.detectTTL(ip)
	if ttl > 0 {
		if ttl <= 64 {
			linuxScore += 3 // Linux/Unix TTLUsually.64
		} else if ttl <= 128 {
			windowsScore += 3 // Windows TTLUsually.128
		}
	}

	// Based on the scores,
	if windowsScore > linuxScore && windowsScore > otherScore {
		return "Windows"
	} else if linuxScore > windowsScore && linuxScore > otherScore {
		return "Linux/Unix"
	}

	return "Unknown"
}

// detectTTL TestTTLValue
func (od *OSDetector) detectTTL(ip string) int {
	// TrypingTo getTTL
	// Simplified here, Actual requirementsraw socketor call systempingCommand

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", ip), od.timeout)
	if err != nil {
		return 0
	}
	defer conn.Close()

	// Could not close temporary folder: %sTTL, Back here.0
	// Actual realization needs to be usedsyscallor parsingpingOutput
	return 0
}

// DetectByBanner ThroughBannerTestOS
func (od *OSDetector) DetectByBanner(banner, service string) string {
	bannerLower := toLower(banner)

	// WindowsCharacteristics
	if contains(bannerLower, "microsoft") ||
		contains(bannerLower, "windows") ||
		contains(bannerLower, "win32") ||
		contains(bannerLower, "iis") {
		return "Windows"
	}

	// LinuxCharacteristics
	if contains(bannerLower, "linux") ||
		contains(bannerLower, "ubuntu") ||
		contains(bannerLower, "debian") ||
		contains(bannerLower, "centos") ||
		contains(bannerLower, "red hat") ||
		contains(bannerLower, "fedora") {
		return "Linux"
	}

	// UnixCharacteristics
	if contains(bannerLower, "unix") ||
		contains(bannerLower, "bsd") ||
		contains(bannerLower, "freebsd") ||
		contains(bannerLower, "openbsd") ||
		contains(bannerLower, "netbsd") {
		return "Unix"
	}

	// MacCharacteristics
	if contains(bannerLower, "darwin") ||
		contains(bannerLower, "mac os") ||
		contains(bannerLower, "macos") {
		return "macOS"
	}

	return ""
}

// contains String contains detection (Ignore case)
func contains(s, substr string) bool {
	return indexOf(s, substr) >= 0
}

// indexOf Find substring position
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// toLower Lowercase
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			result[i] = c + 32
		} else {
			result[i] = c
		}
	}
	return string(result)
}
