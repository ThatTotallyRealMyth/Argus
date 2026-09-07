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
	{Key: "domain_concurrency", Description: "域名扫描并发", Type: "integer", Default: "50", Min: 1, Max: 1000},
	{Key: "domain_timeout", Description: "域名扫描超时（秒）", Type: "number", Default: "3", Min: 0.1, Max: 120},
	{Key: "domain_retry", Description: "域名扫描重试次数", Type: "integer", Default: "2", Min: 0, Max: 10},
	{Key: "subdomain_takeover_concurrency", Description: "子域接管检测并发", Type: "integer", Default: "20", Min: 1, Max: 500},
	{Key: "port_concurrency_small", Description: "小端口集并发", Type: "integer", Default: "100", Min: 1, Max: 5000},
	{Key: "port_concurrency_medium", Description: "中端口集并发", Type: "integer", Default: "300", Min: 1, Max: 5000},
	{Key: "port_concurrency_large", Description: "全端口扫描并发", Type: "integer", Default: "500", Min: 1, Max: 5000},
	{Key: "port_timeout", Description: "端口扫描超时（秒）", Type: "number", Default: "1.5", Min: 0.1, Max: 60},
	{Key: "site_concurrency", Description: "站点探测并发", Type: "integer", Default: "30", Min: 1, Max: 1000},
	{Key: "site_timeout", Description: "站点探测超时（秒）", Type: "number", Default: "5", Min: 0.1, Max: 120},
	{Key: "crawler_max_depth", Description: "爬虫最大深度", Type: "integer", Default: "3", Min: 1, Max: 20},
	{Key: "crawler_max_pages", Description: "爬虫最大页面数", Type: "integer", Default: "500", Min: 1, Max: 100000},
	{Key: "service_timeout", Description: "服务识别超时（秒）", Type: "number", Default: "3", Min: 0.1, Max: 60},
	{Key: "banner_max_length", Description: "Banner 最大长度", Type: "integer", Default: "2048", Min: 128, Max: 1048576},
	{Key: "ip_location_rate_limit", Description: "IP 地理位置查询速率", Type: "integer", Default: "10", Min: 1, Max: 1000},
	{Key: "ip_location_batch_size", Description: "IP 地理位置批量大小", Type: "integer", Default: "20", Min: 1, Max: 1000},
	{Key: "file_leak_concurrency", Description: "目录与敏感文件枚举并发", Type: "integer", Default: "20", Min: 1, Max: 200},
	{Key: "file_leak_rate_limit", Description: "目录与敏感文件枚举每秒请求上限，0 表示不限速", Type: "integer", Default: "0", Min: 0, Max: 1000},
	{Key: "proxy_auto_check_enabled", Description: "代理自动健康检查", Type: "boolean", Default: "true"},
	{Key: "proxy_check_interval_seconds", Description: "代理检查间隔（秒）", Type: "integer", Default: "30", Min: 10, Max: 86400},
	{Key: "proxy_rotation_enabled", Description: "代理自动轮换", Type: "boolean", Default: "true"},
	{Key: "proxy_rotation_interval_seconds", Description: "代理轮换间隔（秒）", Type: "integer", Default: "30", Min: 10, Max: 86400},
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
