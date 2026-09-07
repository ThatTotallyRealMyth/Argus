package scanner

import "testing"

func TestNormalizeScannerSettingValue(t *testing.T) {
	tests := []struct {
		key, input, expected string
	}{
		{"file_leak_concurrency", " 40 ", "40"},
		{"file_leak_rate_limit", "0", "0"},
		{"port_timeout", "1.50", "1.5"},
		{"proxy_rotation_enabled", "TRUE", "true"},
	}
	for _, test := range tests {
		actual, err := NormalizeScannerSettingValue(test.key, test.input)
		if err != nil {
			t.Fatalf("normalize %s: %v", test.key, err)
		}
		if actual != test.expected {
			t.Fatalf("normalize %s: got %q, want %q", test.key, actual, test.expected)
		}
	}
}

func TestNormalizeScannerSettingValueRejectsUnsafeValues(t *testing.T) {
	for key, value := range map[string]string{
		"file_leak_concurrency":        "201",
		"file_leak_rate_limit":         "-1",
		"port_timeout":                 "NaN",
		"site_timeout":                 "+Inf",
		"proxy_check_interval_seconds": "9",
		"unknown":                      "1",
	} {
		if _, err := NormalizeScannerSettingValue(key, value); err == nil {
			t.Fatalf("accepted invalid scanner setting %s=%s", key, value)
		}
	}
}
