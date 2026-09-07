package models

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ProxyEndpoint struct {
	ID            string         `gorm:"type:varchar(36);primaryKey" json:"id"`
	Name          string         `gorm:"type:varchar(100);not null" json:"name"`
	Scheme        string         `gorm:"type:varchar(10);not null;index" json:"scheme"`
	Host          string         `gorm:"type:varchar(255);not null;uniqueIndex:idx_proxy_address" json:"host"`
	Port          int            `gorm:"not null;uniqueIndex:idx_proxy_address" json:"port"`
	Username      string         `gorm:"type:varchar(255)" json:"username"`
	Password      string         `gorm:"type:varchar(1000)" json:"-"`
	IsEnabled     bool           `gorm:"default:true;index" json:"is_enabled"`
	Status        string         `gorm:"type:varchar(20);default:'unknown';index" json:"status"`
	LatencyMS     int64          `json:"latency_ms"`
	SuccessCount  int64          `json:"success_count"`
	FailureCount  int64          `json:"failure_count"`
	LastError     string         `gorm:"type:varchar(500)" json:"last_error"`
	LastCheckedAt *time.Time     `json:"last_checked_at"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

func (ProxyEndpoint) TableName() string { return "proxy_endpoints" }

func (p *ProxyEndpoint) BeforeCreate(tx *gorm.DB) error {
	if p.ID == "" {
		p.ID = uuid.New().String()
	}
	return nil
}

// Validate applies the shared proxy constraints used by HTTP and MCP writes.
func (p ProxyEndpoint) Validate() error {
	if strings.TrimSpace(p.Name) == "" || len(p.Name) > 100 {
		return fmt.Errorf("proxy name must be between 1 and 100 characters")
	}
	scheme := strings.ToLower(strings.TrimSpace(p.Scheme))
	if scheme != "http" && scheme != "https" && scheme != "socks5" {
		return fmt.Errorf("supported schemes: http, https, socks5")
	}
	host := strings.TrimSpace(p.Host)
	if host == "" || strings.ContainsAny(host, "/@") {
		return fmt.Errorf("invalid proxy host")
	}
	if p.Port < 1 || p.Port > 65535 {
		return fmt.Errorf("invalid proxy port")
	}
	if p.Username == "" && p.Password != "" {
		return fmt.Errorf("username is required when password is set")
	}
	return nil
}

func (p ProxyEndpoint) ProxyURL() (*url.URL, error) {
	value := &url.URL{Scheme: p.Scheme, Host: net.JoinHostPort(p.Host, strconv.Itoa(p.Port))}
	if p.Username != "" {
		value.User = url.UserPassword(p.Username, p.Password)
	}
	if value.Scheme == "" || value.Hostname() == "" {
		return nil, fmt.Errorf("invalid proxy endpoint")
	}
	return value, nil
}
