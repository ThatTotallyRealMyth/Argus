package config

import (
	"strings"
	"testing"
)

func validProductionConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Environment: "production", ReadHeaderTimeout: 10, ReadTimeout: 30,
			WriteTimeout: 120, IdleTimeout: 60, ShutdownTimeout: 20,
		},
		JWT:        JWTConfig{Secret: strings.Repeat("j", 32)},
		Encryption: EncryptionConfig{Key: strings.Repeat("e", 32)},
		Database:   DatabaseConfig{Host: "db", Password: strings.Repeat("d", 16)},
		Redis:      RedisConfig{Password: strings.Repeat("r", 16)},
		Security:   SecurityConfig{AllowedOrigins: []string{"http://console.example.test"}},
	}
}

func TestProductionConfigAcceptsExplicitStrongSettings(t *testing.T) {
	if missing := validProductionConfig().IsMissingRequiredConfig(); len(missing) != 0 {
		t.Fatalf("valid production configuration rejected: %v", missing)
	}
}

func TestProductionConfigRejectsUnsafeSettings(t *testing.T) {
	value := validProductionConfig()
	value.Database.Password = "short"
	value.Redis.Password = ""
	value.Security.AllowRegistration = true
	value.Security.AllowedOrigins = []string{"*"}
	value.MCP.Enabled = true
	value.MCP.APIKey = "short"
	missing := strings.Join(value.IsMissingRequiredConfig(), "\n")
	for _, expected := range []string{"database.password", "redis.password", "allow_registration", "wildcard", "mcp.api_key"} {
		if !strings.Contains(missing, expected) {
			t.Errorf("missing production validation for %s: %s", expected, missing)
		}
	}
}

func TestProductionConfigRejectsLongPlaceholderSecrets(t *testing.T) {
	value := validProductionConfig()
	value.Database.Password = "replace-with-a-long-database-password"
	value.Redis.Password = "change-me-to-a-long-redis-password"
	missing := strings.Join(value.IsMissingRequiredConfig(), "\n")
	if !strings.Contains(missing, "database.password") || !strings.Contains(missing, "redis.password") {
		t.Fatalf("placeholder secrets were accepted: %s", missing)
	}
}

func TestConfigStringEnvironmentOverride(t *testing.T) {
	t.Setenv("CORS_ALLOWED_ORIGINS", " http://one.test, http://two.test,http://one.test ")
	values := getEnvOrConfigStrings("CORS_ALLOWED_ORIGINS", []string{"http://fallback.test"})
	if len(values) != 2 || values[0] != "http://one.test" || values[1] != "http://two.test" {
		t.Fatalf("unexpected normalized values: %#v", values)
	}
}
