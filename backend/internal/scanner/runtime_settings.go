package scanner

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// ScannerSettingSpec describes one runtime setting that can be managed by the
// HTTP API and MCP without exposing arbitrary database keys.
type ScannerSettingSpec struct {
	Key         string  `json:"key"`
	Description string  `json:"description"`
	Type        string  `json:"type"`
	Default     string  `json:"default"`
	Min         float64 `json:"min,omitempty"`
	Max         float64 `json:"max,omitempty"`
}

var scannerSettingSpecs = []ScannerSettingSpec{
	{Key: "domain_concurrency", Description: "Scanning and distributing domain names", Type: "integer", Default: "50", Min: 1, Max: 1000},
	{Key: "domain_timeout", Description: "Domain scan timed out (sec)", Type: "number", Default: "3", Min: 0.1, Max: 120},
	{Key: "domain_retry", Description: "Domain name scans retry", Type: "integer", Default: "2", Min: 0, Max: 10},
	{Key: "subdomain_takeover_concurrency", Description: "Concurrent subdomain-takeover checks", Type: "integer", Default: "20", Min: 1, Max: 500},
	{Key: "port_concurrency_small", Description: "Small Port Collection and Distribution", Type: "integer", Default: "100", Min: 1, Max: 5000},
	{Key: "port_concurrency_medium", Description: "Medium Port Collection and Distribution", Type: "integer", Default: "300", Min: 1, Max: 5000},
	{Key: "port_concurrency_large", Description: "Full port scan and send", Type: "integer", Default: "500", Min: 1, Max: 5000},
	{Key: "port_timeout", Description: "Port scan timed out (sec)", Type: "number", Default: "1.5", Min: 0.1, Max: 60},
	{Key: "site_concurrency", Description: "Site detection and distribution", Type: "integer", Default: "30", Min: 1, Max: 1000},
	{Key: "site_timeout", Description: "Site detection timed out (sec)", Type: "number", Default: "5", Min: 0.1, Max: 120},
	{Key: "crawler_max_depth", Description: "Maximum crawler depth", Type: "integer", Default: "3", Min: 1, Max: 20},
	{Key: "crawler_max_pages", Description: "Maximum crawler pages", Type: "integer", Default: "500", Min: 1, Max: 100000},
	{Key: "service_timeout", Description: "Service recognition timed out (sec)", Type: "number", Default: "3", Min: 0.1, Max: 60},
	{Key: "banner_max_length", Description: "Banner Maximum length", Type: "integer", Default: "2048", Min: 128, Max: 1048576},
	{Key: "ip_location_rate_limit", Description: "IP Geolocation query rate", Type: "integer", Default: "10", Min: 1, Max: 1000},
	{Key: "ip_location_batch_size", Description: "IP Geographic Bulk Size", Type: "integer", Default: "20", Min: 1, Max: 1000},
	{Key: "file_leak_concurrency", Description: "List of contents with sensitive documents", Type: "integer", Default: "20", Min: 1, Max: 200},
	{Key: "file_leak_rate_limit", Description: "Maximum request per second for directory and sensitive document listings, 0 It means no speed limit.", Type: "integer", Default: "0", Min: 0, Max: 1000},
	{Key: "proxy_auto_check_enabled", Description: "Proxy automatic health check-ups", Type: "boolean", Default: "true"},
	{Key: "proxy_check_interval_seconds", Description: "Proxy Check Interval (sec)", Type: "integer", Default: "30", Min: 10, Max: 86400},
	{Key: "proxy_rotation_enabled", Description: "Proxy Auto Rotation", Type: "boolean", Default: "true"},
	{Key: "proxy_rotation_interval_seconds", Description: "Proxy Rotation (sec)", Type: "integer", Default: "30", Min: 10, Max: 86400},
}

// ScannerSettingSpecs returns a copy so callers cannot mutate the whitelist.
func ScannerSettingSpecs() []ScannerSettingSpec {
	result := make([]ScannerSettingSpec, len(scannerSettingSpecs))
	copy(result, scannerSettingSpecs)
	return result
}

func ScannerSettingDefinition(key string) (ScannerSettingSpec, bool) {
	for _, spec := range scannerSettingSpecs {
		if spec.Key == key {
			return spec, true
		}
	}
	return ScannerSettingSpec{}, false
}

// NormalizeScannerSettingValue validates a value and returns its canonical
// database representation.
func NormalizeScannerSettingValue(key, raw string) (string, error) {
	spec, ok := ScannerSettingDefinition(strings.TrimSpace(key))
	if !ok {
		return "", fmt.Errorf("unsupported scanner setting: %s", key)
	}
	value := strings.TrimSpace(raw)
	switch spec.Type {
	case "boolean":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return "", fmt.Errorf("%s must be true or false", key)
		}
		return strconv.FormatBool(parsed), nil
	case "integer":
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil || float64(parsed) < spec.Min || float64(parsed) > spec.Max {
			return "", fmt.Errorf("%s must be an integer between %s and %s", key, formatSettingBound(spec.Min), formatSettingBound(spec.Max))
		}
		return strconv.FormatInt(parsed, 10), nil
	case "number":
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) || parsed < spec.Min || parsed > spec.Max {
			return "", fmt.Errorf("%s must be a number between %s and %s", key, formatSettingBound(spec.Min), formatSettingBound(spec.Max))
		}
		return strconv.FormatFloat(parsed, 'f', -1, 64), nil
	default:
		return "", fmt.Errorf("unsupported scanner setting type: %s", spec.Type)
	}
}

func formatSettingBound(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}
