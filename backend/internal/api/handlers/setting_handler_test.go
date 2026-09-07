package handlers

import (
	"testing"

	"github.com/reconmaster/backend/internal/models"
)

func TestValidateEnterpriseSettingValue(t *testing.T) {
	tests := []struct {
		key     string
		value   string
		wantErr bool
	}{
		{"enterprise_icp_api_url", "http://127.0.0.1:8765", false},
		{"enterprise_icp_api_url", "https://icp.example.com/base", false},
		{"enterprise_icp_api_url", "https://user:pass@icp.example.com/base", true},
		{"custom_space_api_url", "https://search.example.com?q={domain}", false},
		{"enterprise_icp_api_url", "file:///etc/passwd", true},
		{"enterprise_icp_api_url", "not-a-url", true},
		{"enterprise_icp_api_headers", `{"Authorization":"Bearer test"}`, false},
		{"enterprise_icp_api_headers", `{}`, false},
		{"enterprise_icp_api_headers", `{"X-Retry":3}`, true},
		{"enterprise_icp_api_headers", `null`, true},
		{"enterprise_icp_api_headers", "", false},
	}
	for _, test := range tests {
		err := validateSettingValue(test.key, test.value)
		if (err != nil) != test.wantErr {
			t.Errorf("validateSettingValue(%q, %q) error = %v, wantErr %v", test.key, test.value, err, test.wantErr)
		}
	}
}

func TestEncryptedSettingResponseNeverReturnsStoredValue(t *testing.T) {
	setting := settingForResponse(models.Setting{Key: models.SettingKeyGitHubToken, Value: "encrypted-or-plain-secret", IsEncrypted: true})
	if setting.Value != "" || !setting.Configured {
		t.Fatalf("redacted setting = %#v", setting)
	}
	empty := settingForResponse(models.Setting{Key: models.SettingKeyGitHubToken, IsEncrypted: true})
	if empty.Configured {
		t.Fatalf("empty encrypted setting reported configured: %#v", empty)
	}
	legacy := settingForResponse(models.Setting{Key: models.SettingKeyCustomSpaceAPIURL, Value: "https://token.example/query"})
	if legacy.Value != "" || !legacy.Configured || !legacy.IsEncrypted {
		t.Fatalf("legacy sensitive setting was exposed: %#v", legacy)
	}
}

func TestSensitiveSettingKeysForceEncryption(t *testing.T) {
	for _, key := range []string{models.SettingKeyGitHubToken, models.SettingKeyZoomEyeKey, models.SettingKeyCustomSpaceAPIURL, models.SettingKeyEnterpriseICPURL, models.SettingKeyWebhookURL, models.SettingKeyEmailPassword} {
		if !sensitiveSettingKey(key) {
			t.Fatalf("sensitive key %q is not enforced", key)
		}
	}
	if sensitiveSettingKey(models.SettingKeyFOFAEmail) {
		t.Fatal("FOFA email should remain readable")
	}
}
