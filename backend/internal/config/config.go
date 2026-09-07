package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

// Config 全局配置
type Config struct {
	Server     ServerConfig
	JWT        JWTConfig
	Encryption EncryptionConfig
	Database   DatabaseConfig
	Redis      RedisConfig
	Scanner    ScannerConfig
	MCP        MCPConfig
	Security   SecurityConfig
	Logging    LoggingConfig
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Host              string
	Port              string
	Mode              string
	Environment       string
	ReadHeaderTimeout int
	ReadTimeout       int
	WriteTimeout      int
	IdleTimeout       int
	ShutdownTimeout   int
	TrustedProxies    []string
}

// JWTConfig JWT配置
type JWTConfig struct {
	Secret string
}

// EncryptionConfig 加密配置
type EncryptionConfig struct {
	Key string
}

// DatabaseConfig 数据库配置
type DatabaseConfig struct {
	Host         string
	Port         int
	User         string
	Password     string
	DBName       string
	SSLMode      string
	MaxIdleConns int
	MaxOpenConns int
}

// RedisConfig Redis配置
type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
}

// ScannerConfig 扫描器配置
type ScannerConfig struct {
	MaxConcurrentTasks int
	Timeout            int
	MaxRetries         int
	PortScanTimeout    int
	PortScanThreads    int
	DomainBruteThreads int
	DomainDictPath     string
	ScreenshotTimeout  int
	ScreenshotDir      string
	ResultsDir         string
}

// MCPConfig MCP 服务配置
type MCPConfig struct {
	Enabled bool   // 是否启用 MCP HTTP 端点
	Path    string // MCP 端点路径
	APIKey  string // 管理级 API 密钥；为空或长度不足时 MCP 不挂载
}

type SecurityConfig struct {
	AllowRegistration bool
	AllowedOrigins    []string
}

// LoggingConfig 日志配置
type LoggingConfig struct {
	Level      string
	File       string
	MaxSize    int
	MaxBackups int
	MaxAge     int
}

var GlobalConfig *Config

// LoadConfig 加载配置
func LoadConfig() error {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath(".")
	setDefaults()

	// 读取环境变量
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		log.Printf("Warning: Failed to read config file: %v", err)
	}

	GlobalConfig = &Config{
		Server: ServerConfig{
			Host:              getEnvOrConfig("SERVER_HOST", viper.GetString("server.host")),
			Port:              getEnvOrConfig("SERVER_PORT", viper.GetString("server.port")),
			Mode:              getEnvOrConfig("GIN_MODE", viper.GetString("server.mode")),
			Environment:       getEnvOrConfig("APP_ENV", viper.GetString("server.environment")),
			ReadHeaderTimeout: getEnvOrConfigInt("SERVER_READ_HEADER_TIMEOUT", viper.GetInt("server.read_header_timeout")),
			ReadTimeout:       getEnvOrConfigInt("SERVER_READ_TIMEOUT", viper.GetInt("server.read_timeout")),
			WriteTimeout:      getEnvOrConfigInt("SERVER_WRITE_TIMEOUT", viper.GetInt("server.write_timeout")),
			IdleTimeout:       getEnvOrConfigInt("SERVER_IDLE_TIMEOUT", viper.GetInt("server.idle_timeout")),
			ShutdownTimeout:   getEnvOrConfigInt("SERVER_SHUTDOWN_TIMEOUT", viper.GetInt("server.shutdown_timeout")),
			TrustedProxies:    getEnvOrConfigStrings("TRUSTED_PROXIES", viper.GetStringSlice("server.trusted_proxies")),
		},
		JWT: JWTConfig{
			Secret: getEnvOrConfig("JWT_SECRET", viper.GetString("jwt.secret")),
		},
		Encryption: EncryptionConfig{
			Key: getEnvOrConfig("ENCRYPTION_KEY", viper.GetString("encryption.key")),
		},
		Database: DatabaseConfig{
			Host:         getEnvOrConfig("DB_HOST", viper.GetString("database.host")),
			Port:         getEnvOrConfigInt("DB_PORT", viper.GetInt("database.port")),
			User:         firstNonEmptyString(getEnvOrConfig("DB_USER", viper.GetString("database.user")), "admin"),
			Password:     getEnvOrConfig("DB_PASSWORD", viper.GetString("database.password")),
			DBName:       firstNonEmptyString(getEnvOrConfig("DB_NAME", viper.GetString("database.dbname")), viper.GetString("database.db_name"), viper.GetString("database.name"), "arl_vp3"),
			SSLMode:      getEnvOrConfig("DB_SSLMODE", viper.GetString("database.sslmode")),
			MaxIdleConns: viper.GetInt("database.max_idle_conns"),
			MaxOpenConns: viper.GetInt("database.max_open_conns"),
		},
		Redis: RedisConfig{
			Host:     getEnvOrConfig("REDIS_HOST", viper.GetString("redis.host")),
			Port:     getEnvOrConfigInt("REDIS_PORT", viper.GetInt("redis.port")),
			Password: getEnvOrConfig("REDIS_PASSWORD", viper.GetString("redis.password")),
			DB:       viper.GetInt("redis.db"),
		},
		Scanner: ScannerConfig{
			MaxConcurrentTasks: viper.GetInt("scanner.max_concurrent_tasks"),
			Timeout:            viper.GetInt("scanner.timeout"),
			MaxRetries:         viper.GetInt("scanner.max_retries"),
			PortScanTimeout:    viper.GetInt("scanner.port_scan_timeout"),
			PortScanThreads:    viper.GetInt("scanner.port_scan_threads"),
			DomainBruteThreads: viper.GetInt("scanner.domain_brute_threads"),
			DomainDictPath:     viper.GetString("scanner.domain_dict_path"),
			ScreenshotTimeout:  viper.GetInt("scanner.screenshot_timeout"),
			ScreenshotDir:      viper.GetString("scanner.screenshot_dir"),
			ResultsDir:         viper.GetString("scanner.results_dir"),
		},
		MCP: MCPConfig{
			Enabled: getEnvOrConfigBool("MCP_ENABLED", viper.GetBool("mcp.enabled")),
			Path:    viper.GetString("mcp.path"),
			APIKey:  getEnvOrConfig("MCP_API_KEY", viper.GetString("mcp.api_key")),
		},
		Security: SecurityConfig{
			AllowRegistration: getEnvOrConfigBool("ALLOW_REGISTRATION", viper.GetBool("security.allow_registration")),
			AllowedOrigins:    getEnvOrConfigStrings("CORS_ALLOWED_ORIGINS", viper.GetStringSlice("security.allowed_origins")),
		},
		Logging: LoggingConfig{
			Level:      viper.GetString("logging.level"),
			File:       viper.GetString("logging.file"),
			MaxSize:    viper.GetInt("logging.max_size"),
			MaxBackups: viper.GetInt("logging.max_backups"),
			MaxAge:     viper.GetInt("logging.max_age"),
		},
	}

	if GlobalConfig.JWT.Secret == "" {
		secret, err := loadOrCreateHexSecret("JWT_SECRET_FILE", "./data/.jwt-secret", 32)
		if err != nil {
			return fmt.Errorf("initialize JWT secret: %w", err)
		}
		GlobalConfig.JWT.Secret = secret
	}
	if GlobalConfig.Encryption.Key == "" {
		secret, err := loadOrCreateHexSecret("ENCRYPTION_KEY_FILE", "./data/.encryption-key", 16)
		if err != nil {
			return fmt.Errorf("initialize encryption key: %w", err)
		}
		GlobalConfig.Encryption.Key = secret
	}

	return nil
}

// IsMissingRequiredConfig 检查是否缺失必要配置
func (c *Config) IsMissingRequiredConfig() []string {
	var missing []string
	if len(c.JWT.Secret) < 32 || c.JWT.Secret == "change-me-in-production" {
		missing = append(missing, "jwt.secret (must be at least 32 characters and non-default)")
	}
	if len(c.Encryption.Key) != 32 || strings.Contains(c.Encryption.Key, "change-in-prod") || strings.Contains(c.Encryption.Key, "change-me") {
		missing = append(missing, "encryption.key (must be exactly 32 non-default characters)")
	}
	if c.Database.Host == "" {
		missing = append(missing, "database.host")
	}
	for name, value := range map[string]int{
		"server.read_header_timeout": c.Server.ReadHeaderTimeout,
		"server.read_timeout":        c.Server.ReadTimeout,
		"server.write_timeout":       c.Server.WriteTimeout,
		"server.idle_timeout":        c.Server.IdleTimeout,
		"server.shutdown_timeout":    c.Server.ShutdownTimeout,
	} {
		if value <= 0 {
			missing = append(missing, name+" (must be greater than zero)")
		}
	}
	if strings.EqualFold(strings.TrimSpace(c.Server.Environment), "production") {
		if len(c.Database.Password) < 16 || isPlaceholderSecret(c.Database.Password) {
			missing = append(missing, "database.password (production requires at least 16 characters)")
		}
		if len(c.Redis.Password) < 16 || isPlaceholderSecret(c.Redis.Password) {
			missing = append(missing, "redis.password (production requires at least 16 characters)")
		}
		if c.Security.AllowRegistration {
			missing = append(missing, "security.allow_registration (must be false in production)")
		}
		for _, origin := range c.Security.AllowedOrigins {
			if strings.TrimSpace(origin) == "*" {
				missing = append(missing, "security.allowed_origins (wildcard is forbidden in production)")
				break
			}
		}
		if c.MCP.Enabled && (len(c.MCP.APIKey) < 32 || isPlaceholderSecret(c.MCP.APIKey)) {
			missing = append(missing, "mcp.api_key (enabled production MCP requires at least 32 characters)")
		}
	}
	return missing
}

// setDefaults 设置默认配置
func setDefaults() {
	viper.SetDefault("server.host", "127.0.0.1")
	viper.SetDefault("server.port", "8080")
	viper.SetDefault("server.mode", "release")
	viper.SetDefault("server.environment", "development")
	viper.SetDefault("server.read_header_timeout", 10)
	viper.SetDefault("server.read_timeout", 30)
	viper.SetDefault("server.write_timeout", 120)
	viper.SetDefault("server.idle_timeout", 60)
	viper.SetDefault("server.shutdown_timeout", 20)
	viper.SetDefault("server.trusted_proxies", []string{})
	// JWT密钥必须在配置文件中显式设置，不使用默认值
	// encryption.key 必须显式设置，不使用默认值
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.user", "admin")
	viper.SetDefault("database.dbname", "arl_vp3")
	viper.SetDefault("database.sslmode", "disable")
	viper.SetDefault("database.max_idle_conns", 10)
	viper.SetDefault("database.max_open_conns", 100)
	viper.SetDefault("redis.host", "localhost")
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("scanner.max_concurrent_tasks", 10)
	viper.SetDefault("scanner.timeout", 3600)
	viper.SetDefault("scanner.max_retries", 3)
	viper.SetDefault("scanner.port_scan_timeout", 300)
	viper.SetDefault("scanner.port_scan_threads", 100)
	viper.SetDefault("scanner.domain_brute_threads", 50)
	viper.SetDefault("mcp.enabled", false)
	viper.SetDefault("mcp.path", "/mcp")
	viper.SetDefault("security.allow_registration", false)
	viper.SetDefault("security.allowed_origins", []string{"http://localhost:5173", "http://127.0.0.1:5173"})
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.max_size", 100)
	viper.SetDefault("logging.max_backups", 10)
	viper.SetDefault("logging.max_age", 30)
}

// getEnvOrConfig 从环境变量或配置文件获取值
func getEnvOrConfig(envKey, configValue string) string {
	if value := os.Getenv(envKey); value != "" {
		return value
	}
	return configValue
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// getEnvOrConfigInt 从环境变量或配置文件获取整数值
func getEnvOrConfigInt(envKey string, configValue int) int {
	if value := os.Getenv(envKey); value != "" {
		// 尝试将环境变量转换为整数
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
		// 如果转换失败，使用配置文件的值
		log.Printf("Warning: Failed to parse env var %s as int, using config value", envKey)
	}
	return configValue
}

func getEnvOrConfigBool(envKey string, configValue bool) bool {
	if value := os.Getenv(envKey); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err == nil {
			return parsed
		}
		log.Printf("Warning: Failed to parse env var %s as bool, using config value", envKey)
	}
	return configValue
}

func getEnvOrConfigStrings(envKey string, configValue []string) []string {
	if value, exists := os.LookupEnv(envKey); exists {
		if strings.TrimSpace(value) == "" {
			return nil
		}
		configValue = strings.Split(value, ",")
	}
	result := make([]string, 0, len(configValue))
	seen := make(map[string]struct{}, len(configValue))
	for _, value := range configValue {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func isPlaceholderSecret(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.Contains(value, "replace-with") || strings.Contains(value, "change-me") || strings.Contains(value, "changeme")
}
