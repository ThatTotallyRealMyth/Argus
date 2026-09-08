package models

import (
	"time"
)

// AssetProfile Asset portrait
type AssetProfile struct {
	// Basic information
	AssetType string    `json:"asset_type"` // domain, ip, site, port
	AssetID   string    `json:"asset_id"`
	AssetName string    `json:"asset_name"` // Asset name (Domain name/IP/URL)
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Label
	Tags []AssetTag `json:"tags,omitempty"`

	// Associated assets statistics
	RelatedDomains int `json:"related_domains"` // Associate domain names
	RelatedIPs     int `json:"related_ips"`     // AssociationIPCount
	RelatedPorts   int `json:"related_ports"`   // Associated ports
	RelatedSites   int `json:"related_sites"`   // Associated sites

	// Gap statistics
	VulnStats VulnerabilityStats `json:"vuln_stats"`

	// Risk rating (0-100)
	RiskScore    int    `json:"risk_score"`
	RiskLevel    string `json:"risk_level"`    // low, medium, high, critical
	RiskReasons  []string `json:"risk_reasons"` // List of causes of risk

	// Asset characteristics
	Features AssetFeatures `json:"features,omitempty"`

	// Recent activities
	LastScanTime   *time.Time `json:"last_scan_time,omitempty"`
	LastUpdateTime *time.Time `json:"last_update_time,omitempty"`
}

// VulnerabilityStats Gap statistics
type VulnerabilityStats struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// AssetFeatures Asset characteristics
type AssetFeatures struct {
	// Domain name characteristics
	IsCDN              bool     `json:"is_cdn,omitempty"`
	SubdomainCount     int      `json:"subdomain_count,omitempty"`
	TakeoverVulnerable bool     `json:"takeover_vulnerable,omitempty"`
	
	// IPCharacteristics
	Location  string   `json:"location,omitempty"`
	OS        string   `json:"os,omitempty"`
	OpenPorts []int    `json:"open_ports,omitempty"`
	
	// Site Character
	Title        string   `json:"title,omitempty"`
	StatusCode   int      `json:"status_code,omitempty"`
	Fingerprints []string `json:"fingerprints,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
	HasScreenshot bool    `json:"has_screenshot,omitempty"`
	
	// Port characteristics
	Service string `json:"service,omitempty"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

// AssetRelation Asset relations
type AssetRelation struct {
	SourceType string      `json:"source_type"` // domain, ip, site, port
	SourceID   string      `json:"source_id"`
	SourceName string      `json:"source_name"`
	TargetType string      `json:"target_type"`
	TargetID   string      `json:"target_id"`
	TargetName string      `json:"target_name"`
	Relation   string      `json:"relation"` // resolves_to, hosted_on, runs_on, related_to
	CreatedAt  time.Time   `json:"created_at"`
}

// AssetGraphNode Asset Profile Node
type AssetGraphNode struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"`
	Name     string            `json:"name"`
	Label    string            `json:"label"`
	Data     map[string]interface{} `json:"data,omitempty"`
	RiskLevel string           `json:"risk_level,omitempty"`
	Tags     []string          `json:"tags,omitempty"`
}

// AssetGraphEdge Asset Map Edge
type AssetGraphEdge struct {
	ID       string `json:"id"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	Relation string `json:"relation"`
	Label    string `json:"label"`
}

// AssetGraph Asset relationship profile
type AssetGraph struct {
	Nodes []AssetGraphNode `json:"nodes"`
	Edges []AssetGraphEdge `json:"edges"`
}

// CSegmentAnalysis CParagraph analysis
type CSegmentAnalysis struct {
	CSegment     string   `json:"c_segment"`     // For example...: 192.168.1.0/24
	TotalIPs     int      `json:"total_ips"`     // The...CTotal paragraphIPCount
	ActiveIPs    []string `json:"active_ips"`    // ActiveIPList
	TotalPorts   int      `json:"total_ports"`   // Total ports
	TotalSites   int      `json:"total_sites"`   // Total sites
	CommonPorts  []int    `json:"common_ports"`  // Common Open Port
	RiskLevel    string   `json:"risk_level"`    // Risk level
}

// AssetTimeline Asset time line
type AssetTimeline struct {
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"` // created, updated, scanned, vuln_found, tag_added
	Description string    `json:"description"`
	Details     string    `json:"details,omitempty"`
}
