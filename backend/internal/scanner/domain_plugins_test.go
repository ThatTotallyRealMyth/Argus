package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCustomSpaceAPIPluginBuildsURLAndParsesDomains(t *testing.T) {
	var requestedPath string
	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.String()
		authHeader = r.Header.Get("X-Token")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"results": [
				{"host": "api.example.com:443"},
				{"url": "https://admin.example.com/login"}
			],
			"extra": "dev.example.com other.test"
		}`))
	}))
	defer server.Close()

	plugin := NewCustomSpaceAPIPlugin(server.URL+"/search?q={domain}", map[string]string{"X-Token": "secret"})
	domains, err := plugin.Query("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if requestedPath != "/search?q=example.com" {
		t.Fatalf("unexpected requested path: %s", requestedPath)
	}
	if authHeader != "secret" {
		t.Fatalf("custom header was not sent: %q", authHeader)
	}
	for _, want := range []string{"api.example.com", "admin.example.com", "dev.example.com"} {
		if !containsDomainString(domains, want) {
			t.Fatalf("expected %s in %#v", want, domains)
		}
	}
}

func TestGetAvailablePluginsAcceptsHunterKeyAliasesAndCustomAPI(t *testing.T) {
	plugins := GetAvailablePlugins(map[string]string{
		"hunter_api_key":       "hunter-secret",
		"custom_space_api_url": "https://example.test/search?domain={domain}",
	})
	names := make(map[string]bool)
	for _, plugin := range plugins {
		names[plugin.Name()] = true
	}
	for _, want := range []string{"hunter", "custom_space_api"} {
		if !names[want] {
			t.Fatalf("expected plugin %s in %#v", want, names)
		}
	}
}

func TestGetAvailablePluginsSkipsDisabledProviders(t *testing.T) {
	plugins := GetAvailablePlugins(map[string]string{
		"virustotal_api_key":       "virustotal-secret",
		"virustotal_enabled":       "false",
		"fofa_email":               "user@example.com",
		"fofa_key":                 "fofa-secret",
		"fofa_enabled":             "0",
		"hunter_api_key":           "hunter-secret",
		"hunter_enabled":           "off",
		"quake_api_key":            "quake-secret",
		"quake_enabled":            "disabled",
		"zoomeye_api_key":          "zoomeye-secret",
		"zoomeye_enabled":          "no",
		"custom_space_api_url":     "https://example.test/search?domain={domain}",
		"custom_space_api_enabled": "false",
	})
	names := make(map[string]bool)
	for _, plugin := range plugins {
		names[plugin.Name()] = true
	}
	for _, disabled := range []string{"virustotal", "fofa", "hunter", "quake", "zoomeye", "custom_space_api"} {
		if names[disabled] {
			t.Fatalf("disabled plugin %s was loaded: %#v", disabled, names)
		}
	}
	for _, free := range []string{"crtsh", "certspotter", "alienvault", "hackertarget", "threatcrowd"} {
		if !names[free] {
			t.Fatalf("free plugin %s was not loaded: %#v", free, names)
		}
	}
}

func TestAPIProviderEnabledDefaultsToEnabled(t *testing.T) {
	if !apiProviderEnabled(nil, "fofa") {
		t.Fatal("providers without a stored flag must remain enabled")
	}
	if !apiProviderEnabled(map[string]string{"fofa_enabled": "true"}, "fofa") {
		t.Fatal("explicitly enabled provider was disabled")
	}
	if apiProviderEnabled(map[string]string{"fofa_enabled": "false"}, "fofa") {
		t.Fatal("explicitly disabled provider was enabled")
	}
}

func TestParseCustomSpaceAPIHeaders(t *testing.T) {
	headers := parseCustomSpaceAPIHeaders("Authorization: Bearer token\nX-Source: moon")
	if headers["Authorization"] != "Bearer token" || headers["X-Source"] != "moon" {
		t.Fatalf("unexpected headers: %#v", headers)
	}
	jsonHeaders := parseCustomSpaceAPIHeaders(`{"X-Token":"secret"}`)
	if jsonHeaders["X-Token"] != "secret" {
		t.Fatalf("unexpected json headers: %#v", jsonHeaders)
	}
}

func containsDomainString(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}
