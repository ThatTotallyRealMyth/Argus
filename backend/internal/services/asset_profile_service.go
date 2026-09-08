package services

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"golang.org/x/net/publicsuffix"
)

// AssetProfileService Asset portrait services
type AssetProfileService struct{}

const (
	maxProfilePorts = 1000
	maxRelations    = 250
	maxGraphNodes   = 500
	maxGraphEdges   = 1000
)

// NewAssetProfileService Create an asset image service
func NewAssetProfileService() *AssetProfileService {
	return &AssetProfileService{}
}

// GetAssetProfile Acquisition of asset portraits
func (s *AssetProfileService) GetAssetProfile(assetType, assetID string) (*models.AssetProfile, error) {
	// Obtain different drawings by asset type
	switch assetType {
	case "domain":
		return s.getDomainProfile(assetID)
	case "ip":
		return s.getIPProfile(assetID)
	case "site":
		return s.getSiteProfile(assetID)
	case "port":
		return s.getPortProfile(assetID)
	default:
		return nil, fmt.Errorf("unsupported asset type: %s", assetType)
	}
}

// getDomainProfile Get domain name drawings
func (s *AssetProfileService) getDomainProfile(domainID string) (*models.AssetProfile, error) {
	var domain models.Domain
	if err := database.DB.First(&domain, "id = ?", domainID).Error; err != nil {
		return nil, err
	}

	profile := &models.AssetProfile{
		AssetType: "domain",
		AssetID:   domainID,
		AssetName: domain.Domain,
		CreatedAt: domain.CreatedAt,
		UpdatedAt: domain.UpdatedAt,
	}

	// Get Tabs
	var err error
	profile.Tags, err = s.getAssetTags("domain", domainID)
	if err != nil {
		return nil, err
	}

	// Statistically associated assets
	if err := s.countRelatedAssets(profile, "domain", domainID); err != nil {
		return nil, err
	}

	// Statistical gaps
	profile.VulnStats, err = s.getVulnStats(domain.TaskID, "domain", domain.Domain)
	if err != nil {
		return nil, err
	}

	// Domain name characteristics
	profile.Features.IsCDN = domain.CDN
	profile.Features.TakeoverVulnerable = domain.TakeoverVulnerable

	// Number of statistical subdomain names
	rootDomain := registrableDomain(domain.Domain)
	var taskDomains []models.Domain
	if err := database.DB.Select("domain").Where("task_id = ?", domain.TaskID).Find(&taskDomains).Error; err != nil {
		return nil, err
	}
	for _, candidate := range taskDomains {
		candidateDomain := canonicalDomain(candidate.Domain)
		if candidateDomain != rootDomain && strings.HasSuffix(candidateDomain, "."+rootDomain) {
			profile.Features.SubdomainCount++
		}
	}

	// Calculate risk rating
	profile.RiskScore, profile.RiskLevel, profile.RiskReasons = s.calculateDomainRisk(domain, profile)

	return profile, nil
}

// getIPProfile FetchIPPainting
func (s *AssetProfileService) getIPProfile(ipID string) (*models.AssetProfile, error) {
	var ip models.IP
	if err := database.DB.First(&ip, "id = ?", ipID).Error; err != nil {
		return nil, err
	}

	profile := &models.AssetProfile{
		AssetType: "ip",
		AssetID:   ipID,
		AssetName: ip.IPAddress,
		CreatedAt: ip.CreatedAt,
		UpdatedAt: ip.UpdatedAt,
	}

	// Get Tabs
	var err error
	profile.Tags, err = s.getAssetTags("ip", ipID)
	if err != nil {
		return nil, err
	}

	// Statistically associated assets
	if err := s.countRelatedAssets(profile, "ip", ipID); err != nil {
		return nil, err
	}

	// Statistical gaps
	profile.VulnStats, err = s.getVulnStats(ip.TaskID, "ip", ip.IPAddress)
	if err != nil {
		return nil, err
	}

	// IPCharacteristics
	profile.Features.Location = ip.Location
	profile.Features.OS = ip.OS

	// Get Open Port
	var ports []models.Port
	if err := database.DB.Where("task_id = ? AND ip_address = ?", ip.TaskID, ip.IPAddress).Limit(maxProfilePorts).Find(&ports).Error; err != nil {
		return nil, err
	}
	openPorts := make([]int, len(ports))
	for i, p := range ports {
		openPorts[i] = p.Port
	}
	profile.Features.OpenPorts = openPorts

	// Calculate risk rating
	profile.RiskScore, profile.RiskLevel, profile.RiskReasons = s.calculateIPRisk(ip, profile)

	return profile, nil
}

// getSiteProfile Get Site Graphics
func (s *AssetProfileService) getSiteProfile(siteID string) (*models.AssetProfile, error) {
	var site models.Site
	if err := database.DB.First(&site, "id = ?", siteID).Error; err != nil {
		return nil, err
	}

	profile := &models.AssetProfile{
		AssetType: "site",
		AssetID:   siteID,
		AssetName: site.URL,
		CreatedAt: site.CreatedAt,
		UpdatedAt: site.UpdatedAt,
	}

	// Get Tabs
	var err error
	profile.Tags, err = s.getAssetTags("site", siteID)
	if err != nil {
		return nil, err
	}

	// Statistically associated assets
	if err := s.countRelatedAssets(profile, "site", siteID); err != nil {
		return nil, err
	}

	// Statistical gaps
	profile.VulnStats, err = s.getVulnStats(site.TaskID, "site", site.URL)
	if err != nil {
		return nil, err
	}

	// Site Character
	profile.Features.Title = site.Title
	profile.Features.StatusCode = site.StatusCode
	profile.Features.Fingerprints = site.Fingerprints
	profile.Features.HasScreenshot = site.Screenshot != ""

	// Calculate risk rating
	profile.RiskScore, profile.RiskLevel, profile.RiskReasons = s.calculateSiteRisk(site, profile)

	return profile, nil
}

// getPortProfile Get Port Images
func (s *AssetProfileService) getPortProfile(portID string) (*models.AssetProfile, error) {
	var port models.Port
	if err := database.DB.First(&port, "id = ?", portID).Error; err != nil {
		return nil, err
	}

	profile := &models.AssetProfile{
		AssetType: "port",
		AssetID:   portID,
		AssetName: fmt.Sprintf("%s:%d", port.IPAddress, port.Port),
		CreatedAt: port.CreatedAt,
		UpdatedAt: port.UpdatedAt,
	}

	// Get Tabs
	var err error
	profile.Tags, err = s.getAssetTags("port", portID)
	if err != nil {
		return nil, err
	}

	// Statistically associated assets
	if err := s.countRelatedAssets(profile, "port", portID); err != nil {
		return nil, err
	}

	// Statistical gaps
	profile.VulnStats, err = s.getVulnStats(port.TaskID, "port", net.JoinHostPort(port.IPAddress, strconv.Itoa(port.Port))+"/tcp")
	if err != nil {
		return nil, err
	}

	// Port characteristics
	profile.Features.Service = port.Service
	profile.Features.Version = port.Version
	profile.Features.Banner = port.Banner

	// Calculate risk rating
	profile.RiskScore, profile.RiskLevel, profile.RiskReasons = s.calculatePortRisk(port, profile)

	return profile, nil
}

// getAssetTags Obtain asset labels
func (s *AssetProfileService) getAssetTags(assetType, assetID string) ([]models.AssetTag, error) {
	var relations []models.AssetTagRelation
	if err := database.DB.Where("asset_type = ? AND asset_id = ?", assetType, assetID).Find(&relations).Error; err != nil {
		return nil, err
	}

	if len(relations) == 0 {
		return []models.AssetTag{}, nil
	}

	tagIDs := make([]string, len(relations))
	for i, rel := range relations {
		tagIDs[i] = rel.TagID
	}

	var tags []models.AssetTag
	if err := database.DB.Where("id IN ?", tagIDs).Find(&tags).Error; err != nil {
		return nil, err
	}

	return tags, nil
}

// countRelatedAssets Statistics of associated assets within the same mandate.
func (s *AssetProfileService) countRelatedAssets(profile *models.AssetProfile, assetType, assetID string) error {
	switch assetType {
	case "domain":
		var domain models.Domain
		if err := database.DB.First(&domain, "id = ?", assetID).Error; err != nil {
			return err
		}

		if domain.IPAddress != "" {
			var ipCount int64
			if err := database.DB.Model(&models.IP{}).Where("task_id = ? AND ip_address = ?", domain.TaskID, domain.IPAddress).Count(&ipCount).Error; err != nil {
				return err
			}
			profile.RelatedIPs = int(ipCount)
			var portCount int64
			if err := database.DB.Model(&models.Port{}).Where("task_id = ? AND ip_address = ?", domain.TaskID, domain.IPAddress).Count(&portCount).Error; err != nil {
				return err
			}
			profile.RelatedPorts = int(portCount)
		}
		siteCount, err := countTaskSitesByHostname(domain.TaskID, domain.Domain)
		if err != nil {
			return err
		}
		profile.RelatedSites = siteCount

	case "ip":
		var ip models.IP
		if err := database.DB.First(&ip, "id = ?", assetID).Error; err != nil {
			return err
		}

		var domainCount int64
		if err := database.DB.Model(&models.Domain{}).Where("task_id = ? AND ip_address = ?", ip.TaskID, ip.IPAddress).Count(&domainCount).Error; err != nil {
			return err
		}
		profile.RelatedDomains = int(domainCount)
		var portCount int64
		if err := database.DB.Model(&models.Port{}).Where("task_id = ? AND ip_address = ?", ip.TaskID, ip.IPAddress).Count(&portCount).Error; err != nil {
			return err
		}
		profile.RelatedPorts = int(portCount)
		var siteCount int64
		if err := database.DB.Model(&models.Site{}).Where("task_id = ? AND ip = ?", ip.TaskID, ip.IPAddress).Count(&siteCount).Error; err != nil {
			return err
		}
		profile.RelatedSites = int(siteCount)

	case "site":
		var site models.Site
		if err := database.DB.First(&site, "id = ?", assetID).Error; err != nil {
			return err
		}

		domain := extractHostname(site.URL)
		if domain != "" {
			var domainCount int64
			if err := database.DB.Model(&models.Domain{}).Where("task_id = ? AND LOWER(domain) = ?", site.TaskID, canonicalDomain(domain)).Count(&domainCount).Error; err != nil {
				return err
			}
			profile.RelatedDomains = int(domainCount)
		}

		if site.IP != "" {
			var ipCount int64
			if err := database.DB.Model(&models.IP{}).Where("task_id = ? AND ip_address = ?", site.TaskID, site.IP).Count(&ipCount).Error; err != nil {
				return err
			}
			profile.RelatedIPs = int(ipCount)

			var portCount int64
			if port := siteURLPort(site.URL); port > 0 {
				if err := database.DB.Model(&models.Port{}).Where("task_id = ? AND ip_address = ? AND port = ?", site.TaskID, site.IP, port).Count(&portCount).Error; err != nil {
					return err
				}
			} else if err := database.DB.Model(&models.Port{}).Where("task_id = ? AND ip_address = ?", site.TaskID, site.IP).Count(&portCount).Error; err != nil {
				return err
			}
			profile.RelatedPorts = int(portCount)
		}

	case "port":
		var port models.Port
		if err := database.DB.First(&port, "id = ?", assetID).Error; err != nil {
			return err
		}
		var ipCount int64
		if err := database.DB.Model(&models.IP{}).Where("task_id = ? AND ip_address = ?", port.TaskID, port.IPAddress).Count(&ipCount).Error; err != nil {
			return err
		}
		profile.RelatedIPs = int(ipCount)
		var sites []models.Site
		if err := database.DB.Select("url").Where("task_id = ? AND ip = ?", port.TaskID, port.IPAddress).Find(&sites).Error; err != nil {
			return err
		}
		for _, site := range sites {
			if siteURLPort(site.URL) == port.Port {
				profile.RelatedSites++
			}
		}
	}
	return nil
}

func countTaskSitesByHostname(taskID, hostname string) (int, error) {
	var sites []models.Site
	if err := database.DB.Select("url").Where("task_id = ?", taskID).Find(&sites).Error; err != nil {
		return 0, err
	}
	hostname = canonicalDomain(hostname)
	count := 0
	for _, site := range sites {
		if canonicalDomain(extractHostname(site.URL)) == hostname {
			count++
		}
	}
	return count, nil
}

// getVulnStats Use with canonical The leaks are linked to the same structured target rules.
func (s *AssetProfileService) getVulnStats(taskID, assetType, assetValue string) (models.VulnerabilityStats, error) {
	var stats models.VulnerabilityStats
	var vulnerabilities []models.Vulnerability
	if err := database.DB.Where("task_id = ?", taskID).Find(&vulnerabilities).Error; err != nil {
		return stats, err
	}
	for _, vulnerability := range vulnerabilities {
		if !vulnerabilityMatchesProfile(vulnerability.URL, assetType, assetValue) {
			continue
		}
		stats.Total++
		switch strings.ToLower(strings.TrimSpace(vulnerability.Severity)) {
		case "critical":
			stats.Critical++
		case "high":
			stats.High++
		case "medium":
			stats.Medium++
		case "low":
			stats.Low++
		case "info":
			stats.Info++
		}
	}
	return stats, nil
}

func vulnerabilityMatchesProfile(rawTarget, assetType, assetValue string) bool {
	target := parseVulnerabilityTarget(rawTarget)
	switch assetType {
	case "domain":
		return target.domain != "" && target.domain == canonicalDomain(assetValue)
	case "ip":
		return target.ip != "" && target.ip == canonicalIP(assetValue)
	case "site":
		assetSite := canonicalSite(assetValue)
		assetOrigin := canonicalSiteOrigin(assetValue)
		return target.siteKey == assetSite || (assetOrigin != "" && target.origin == assetOrigin)
	case "port":
		return target.portKey != "" && target.portKey == assetValue
	default:
		return false
	}
}

// calculateDomainRisk Calculate domain name risk rating
func (s *AssetProfileService) calculateDomainRisk(domain models.Domain, profile *models.AssetProfile) (int, string, []string) {
	score := 0
	reasons := []string{}

	// Subdomain name takes over +40
	if domain.TakeoverVulnerable {
		score += 40
		reasons = append(reasons, "There is a risk of subdomain names taking over")
	}

	// Number of gaps
	if profile.VulnStats.Critical > 0 {
		score += 30
		reasons = append(reasons, fmt.Sprintf("Existence %d A serious breach.", profile.VulnStats.Critical))
	}
	if profile.VulnStats.High > 0 {
		score += 20
		reasons = append(reasons, fmt.Sprintf("Existence %d A high-risk breach.", profile.VulnStats.High))
	}
	if profile.VulnStats.Medium > 0 {
		score += 10
		reasons = append(reasons, fmt.Sprintf("Existence %d A breach.", profile.VulnStats.Medium))
	}

	// CDNProtection -5
	if domain.CDN {
		score -= 5
	}

	level := getRiskLevel(score)
	return score, level, reasons
}

// calculateIPRisk CalculateIPRisk rating
func (s *AssetProfileService) calculateIPRisk(ip models.IP, profile *models.AssetProfile) (int, string, []string) {
	score := 0
	reasons := []string{}

	// Open Port Number
	openPortCount := len(profile.Features.OpenPorts)
	if openPortCount > 20 {
		score += 20
		reasons = append(reasons, fmt.Sprintf("Open Port Too Too Many (%dOne.)", openPortCount))
	} else if openPortCount > 10 {
		score += 10
		reasons = append(reasons, fmt.Sprintf("More open ports (%dOne.)", openPortCount))
	}

	// Number of gaps
	if profile.VulnStats.Critical > 0 {
		score += 30
		reasons = append(reasons, fmt.Sprintf("Existence %d A serious breach.", profile.VulnStats.Critical))
	}
	if profile.VulnStats.High > 0 {
		score += 20
		reasons = append(reasons, fmt.Sprintf("Existence %d A high-risk breach.", profile.VulnStats.High))
	}

	// Dangerous port
	dangerousPorts := []int{21, 22, 23, 3389, 445, 135, 1433, 3306, 5432, 6379, 27017}
	for _, port := range profile.Features.OpenPorts {
		for _, dangerPort := range dangerousPorts {
			if port == dangerPort {
				score += 5
				reasons = append(reasons, fmt.Sprintf("Open the dangerous port. %d", port))
				break
			}
		}
	}

	level := getRiskLevel(score)
	return score, level, reasons
}

// calculateSiteRisk Calculate site risk rating
func (s *AssetProfileService) calculateSiteRisk(site models.Site, profile *models.AssetProfile) (int, string, []string) {
	score := 0
	reasons := []string{}

	// Number of gaps
	if profile.VulnStats.Critical > 0 {
		score += 30
		reasons = append(reasons, fmt.Sprintf("Existence %d A serious breach.", profile.VulnStats.Critical))
	}
	if profile.VulnStats.High > 0 {
		score += 20
		reasons = append(reasons, fmt.Sprintf("Existence %d A high-risk breach.", profile.VulnStats.High))
	}
	if profile.VulnStats.Medium > 0 {
		score += 10
		reasons = append(reasons, fmt.Sprintf("Existence %d A breach.", profile.VulnStats.Medium))
	}

	// Number of fingerprints (Possible exposure)
	if len(profile.Features.Fingerprints) > 5 {
		score += 5
		reasons = append(reasons, "Over-exposed fingerprint information.")
	}

	// HTTPStatus Code
	if site.StatusCode == 403 || site.StatusCode == 401 {
		score += 5
		reasons = append(reasons, "Observed in an authorized scan or trusted data source")
	}

	level := getRiskLevel(score)
	return score, level, reasons
}

// calculatePortRisk Calculate port risk rating
func (s *AssetProfileService) calculatePortRisk(port models.Port, profile *models.AssetProfile) (int, string, []string) {
	score := 0
	reasons := []string{}

	// Dangerous port
	dangerousPorts := map[int]string{
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		3389:  "RDP",
		445:   "SMB",
		135:   "RPC",
		1433:  "MSSQL",
		3306:  "MySQL",
		5432:  "PostgreSQL",
		6379:  "Redis",
		27017: "MongoDB",
	}

	if serviceName, isDangerous := dangerousPorts[port.Port]; isDangerous {
		score += 15
		reasons = append(reasons, fmt.Sprintf("Dangerous services %s (%d)", serviceName, port.Port))
	}

	// Number of gaps
	if profile.VulnStats.Critical > 0 {
		score += 30
		reasons = append(reasons, fmt.Sprintf("Existence %d A serious breach.", profile.VulnStats.Critical))
	}
	if profile.VulnStats.High > 0 {
		score += 20
		reasons = append(reasons, fmt.Sprintf("Existence %d A high-risk breach.", profile.VulnStats.High))
	}

	// BannerInformation leaks
	if port.Banner != "" && len(port.Banner) > 50 {
		score += 5
		reasons = append(reasons, "BannerOverexposure of information")
	}

	level := getRiskLevel(score)
	return score, level, reasons
}

// getRiskLevel Get risk level based on scores
func getRiskLevel(score int) string {
	if score >= 50 {
		return "critical"
	} else if score >= 30 {
		return "high"
	} else if score >= 15 {
		return "medium"
	}
	return "low"
}

func registrableDomain(domain string) string {
	domain = canonicalDomain(domain)
	root, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return domain
	}
	return canonicalDomain(root)
}

func extractHostname(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	if parsed.Hostname() == "" && !strings.Contains(raw, "://") {
		parsed, err = url.Parse("//" + strings.TrimSpace(raw))
		if err != nil {
			return ""
		}
	}
	return canonicalDomain(parsed.Hostname())
}

func siteURLPort(raw string) int {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" {
		return 0
	}
	if parsed.Port() != "" {
		port, err := strconv.Atoi(parsed.Port())
		if err == nil && port >= 1 && port <= 65535 {
			return port
		}
		return 0
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http":
		return 80
	case "https":
		return 443
	default:
		return 0
	}
}

// GetAssetRelations Acquisition of assets relationship
func (s *AssetProfileService) GetAssetRelations(assetType, assetID string) ([]models.AssetRelation, error) {
	relations := []models.AssetRelation{}
	add := func(sourceType, sourceID, sourceName, targetType, targetID, targetName, relation string, createdAt time.Time) {
		if targetID == "" || len(relations) >= maxRelations {
			return
		}
		relations = append(relations, models.AssetRelation{
			SourceType: sourceType, SourceID: sourceID, SourceName: sourceName,
			TargetType: targetType, TargetID: targetID, TargetName: targetName,
			Relation: relation, CreatedAt: createdAt,
		})
	}

	switch assetType {
	case "domain":
		var domain models.Domain
		if err := database.DB.First(&domain, "id = ?", assetID).Error; err != nil {
			return nil, err
		}
		if domain.IPAddress != "" {
			var ips []models.IP
			if err := database.DB.Where("task_id = ? AND ip_address = ?", domain.TaskID, domain.IPAddress).Limit(maxRelations).Find(&ips).Error; err != nil {
				return nil, err
			}
			for _, ip := range ips {
				add("domain", domain.ID, domain.Domain, "ip", ip.ID, ip.IPAddress, "resolves_to", ip.CreatedAt)
			}
		}
		var sites []models.Site
		if err := database.DB.Where("task_id = ?", domain.TaskID).Limit(maxRelations).Find(&sites).Error; err != nil {
			return nil, err
		}
		for _, site := range sites {
			if canonicalDomain(extractHostname(site.URL)) == canonicalDomain(domain.Domain) {
				add("domain", domain.ID, domain.Domain, "site", site.ID, site.URL, "serves", site.CreatedAt)
			}
		}

	case "ip":
		var ip models.IP
		if err := database.DB.First(&ip, "id = ?", assetID).Error; err != nil {
			return nil, err
		}
		var domains []models.Domain
		if err := database.DB.Where("task_id = ? AND ip_address = ?", ip.TaskID, ip.IPAddress).Limit(maxRelations).Find(&domains).Error; err != nil {
			return nil, err
		}
		for _, domain := range domains {
			add("ip", ip.ID, ip.IPAddress, "domain", domain.ID, domain.Domain, "resolved_from", domain.CreatedAt)
		}
		var ports []models.Port
		if err := database.DB.Where("task_id = ? AND ip_address = ?", ip.TaskID, ip.IPAddress).Limit(maxRelations).Find(&ports).Error; err != nil {
			return nil, err
		}
		for _, port := range ports {
			protocol := fallbackText(port.Protocol, "tcp")
			add("ip", ip.ID, ip.IPAddress, "port", port.ID, fmt.Sprintf("%d/%s", port.Port, protocol), "exposes", port.CreatedAt)
		}
		var sites []models.Site
		if err := database.DB.Where("task_id = ? AND ip = ?", ip.TaskID, ip.IPAddress).Limit(maxRelations).Find(&sites).Error; err != nil {
			return nil, err
		}
		for _, site := range sites {
			add("ip", ip.ID, ip.IPAddress, "site", site.ID, site.URL, "hosts", site.CreatedAt)
		}

	case "port":
		var port models.Port
		if err := database.DB.First(&port, "id = ?", assetID).Error; err != nil {
			return nil, err
		}
		sourceName := net.JoinHostPort(port.IPAddress, strconv.Itoa(port.Port)) + "/" + fallbackText(port.Protocol, "tcp")
		var ips []models.IP
		if err := database.DB.Where("task_id = ? AND ip_address = ?", port.TaskID, port.IPAddress).Limit(maxRelations).Find(&ips).Error; err != nil {
			return nil, err
		}
		for _, ip := range ips {
			add("port", port.ID, sourceName, "ip", ip.ID, ip.IPAddress, "exposed_by", ip.CreatedAt)
		}
		var sites []models.Site
		if err := database.DB.Where("task_id = ? AND ip = ?", port.TaskID, port.IPAddress).Limit(maxRelations).Find(&sites).Error; err != nil {
			return nil, err
		}
		for _, site := range sites {
			if siteURLPort(site.URL) == port.Port {
				add("port", port.ID, sourceName, "site", site.ID, site.URL, "serves", site.CreatedAt)
			}
		}

	case "site":
		var site models.Site
		if err := database.DB.First(&site, "id = ?", assetID).Error; err != nil {
			return nil, err
		}
		if site.IP != "" {
			var ips []models.IP
			if err := database.DB.Where("task_id = ? AND ip_address = ?", site.TaskID, site.IP).Limit(maxRelations).Find(&ips).Error; err != nil {
				return nil, err
			}
			for _, ip := range ips {
				add("site", site.ID, site.URL, "ip", ip.ID, ip.IPAddress, "hosted_on", ip.CreatedAt)
			}
			if portNumber := siteURLPort(site.URL); portNumber > 0 {
				var ports []models.Port
				if err := database.DB.Where("task_id = ? AND ip_address = ? AND port = ?", site.TaskID, site.IP, portNumber).Limit(maxRelations).Find(&ports).Error; err != nil {
					return nil, err
				}
				for _, port := range ports {
					protocol := fallbackText(port.Protocol, "tcp")
					add("site", site.ID, site.URL, "port", port.ID, fmt.Sprintf("%d/%s", port.Port, protocol), "served_by", port.CreatedAt)
				}
			}
		}
		if hostname := extractHostname(site.URL); hostname != "" && net.ParseIP(hostname) == nil {
			var domains []models.Domain
			if err := database.DB.Where("task_id = ? AND LOWER(domain) = ?", site.TaskID, canonicalDomain(hostname)).Limit(maxRelations).Find(&domains).Error; err != nil {
				return nil, err
			}
			for _, domain := range domains {
				add("site", site.ID, site.URL, "domain", domain.ID, domain.Domain, "belongs_to", domain.CreatedAt)
			}
		}

	default:
		return nil, fmt.Errorf("unsupported asset type: %s", assetType)
	}

	return relations, nil
}

// GetAssetGraph Access to asset relationship maps
func (s *AssetProfileService) GetAssetGraph(assetType, assetID string, depth int) (*models.AssetGraph, error) {
	if depth < 0 {
		return nil, fmt.Errorf("graph depth cannot be negative")
	}
	graph := &models.AssetGraph{
		Nodes: []models.AssetGraphNode{},
		Edges: []models.AssetGraphEdge{},
	}
	nodeSeen := make(map[string]bool)
	expandedDepth := make(map[string]int)
	edgeSeen := make(map[string]bool)
	if err := s.buildGraph(graph, assetType, assetID, depth, nodeSeen, expandedDepth, edgeSeen); err != nil {
		return nil, err
	}
	return graph, nil
}

// buildGraph Recursively build relationship maps
func (s *AssetProfileService) buildGraph(graph *models.AssetGraph, assetType, assetID string, depth int, nodeSeen map[string]bool, expandedDepth map[string]int, edgeSeen map[string]bool) error {
	key := assetType + ":" + assetID
	if !nodeSeen[key] {
		if len(graph.Nodes) >= maxGraphNodes {
			return nil
		}
		node, err := s.createGraphNode(assetType, assetID)
		if err != nil {
			return err
		}
		graph.Nodes = append(graph.Nodes, *node)
		nodeSeen[key] = true
	}
	if depth <= 0 {
		return nil
	}
	if previousDepth, expanded := expandedDepth[key]; expanded && previousDepth >= depth {
		return nil
	}
	expandedDepth[key] = depth
	relations, err := s.GetAssetRelations(assetType, assetID)
	if err != nil {
		return err
	}
	for _, rel := range relations {
		if len(graph.Edges) >= maxGraphEdges {
			break
		}
		targetKey := rel.TargetType + ":" + rel.TargetID
		if !nodeSeen[targetKey] {
			if len(graph.Nodes) >= maxGraphNodes {
				break
			}
			targetNode, err := s.createGraphNode(rel.TargetType, rel.TargetID)
			if err != nil {
				return err
			}
			graph.Nodes = append(graph.Nodes, *targetNode)
			nodeSeen[targetKey] = true
		}
		edgeKey := rel.SourceID + "\x00" + rel.Relation + "\x00" + rel.TargetID
		if !edgeSeen[edgeKey] {
			graph.Edges = append(graph.Edges, models.AssetGraphEdge{
				ID:     rel.SourceID + ":" + rel.Relation + ":" + rel.TargetID,
				Source: rel.SourceID, Target: rel.TargetID, Relation: rel.Relation, Label: rel.Relation,
			})
			edgeSeen[edgeKey] = true
		}
		if err := s.buildGraph(graph, rel.TargetType, rel.TargetID, depth-1, nodeSeen, expandedDepth, edgeSeen); err != nil {
			return err
		}
	}
	return nil
}

// createGraphNode Create a Spectrum Node
func (s *AssetProfileService) createGraphNode(assetType, assetID string) (*models.AssetGraphNode, error) {
	node := &models.AssetGraphNode{
		ID:   assetID,
		Type: assetType,
	}

	switch assetType {
	case "domain":
		var domain models.Domain
		if err := database.DB.First(&domain, "id = ?", assetID).Error; err != nil {
			return nil, err
		}
		node.Name = domain.Domain
		node.Label = domain.Domain
	case "ip":
		var ip models.IP
		if err := database.DB.First(&ip, "id = ?", assetID).Error; err != nil {
			return nil, err
		}
		node.Name = ip.IPAddress
		node.Label = ip.IPAddress
	case "site":
		var site models.Site
		if err := database.DB.First(&site, "id = ?", assetID).Error; err != nil {
			return nil, err
		}
		node.Name = site.URL
		node.Label = site.Title
		if node.Label == "" {
			node.Label = site.URL
		}
	case "port":
		var port models.Port
		if err := database.DB.First(&port, "id = ?", assetID).Error; err != nil {
			return nil, err
		}
		node.Name = net.JoinHostPort(port.IPAddress, strconv.Itoa(port.Port))
		node.Label = fmt.Sprintf("%d/%s", port.Port, fallbackText(port.Service, fallbackText(port.Protocol, "tcp")))
	default:
		return nil, fmt.Errorf("unsupported asset type: %s", assetType)
	}
	return node, nil
}

// AnalyzeCSegment Analysis of collected within individual missions C Assets in Sector.
func (s *AssetProfileService) AnalyzeCSegment(taskID, ipAddress string) (*models.CSegmentAnalysis, error) {
	if strings.TrimSpace(taskID) == "" {
		return nil, fmt.Errorf("task_id is required")
	}

	// ExtractCParagraph
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address")
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("only IPv4 supported")
	}

	// CParagraph: x.x.x.0/24
	cSegment := fmt.Sprintf("%d.%d.%d.0/24", ipv4[0], ipv4[1], ipv4[2])
	cSegmentPrefix := fmt.Sprintf("%d.%d.%d.", ipv4[0], ipv4[1], ipv4[2])

	analysis := &models.CSegmentAnalysis{
		CSegment: cSegment,
	}

	// Query thisCAll of the paragraphsIP
	var ips []models.IP
	if err := database.DB.Where("task_id = ? AND ip_address LIKE ?", taskID, cSegmentPrefix+"%").Limit(512).Find(&ips).Error; err != nil {
		return nil, err
	}

	analysis.TotalIPs = len(ips)
	analysis.ActiveIPs = make([]string, len(ips))
	for i, ip := range ips {
		analysis.ActiveIPs[i] = ip.IPAddress
	}

	// Statistical Port
	var totalPorts int64
	if err := database.DB.Model(&models.Port{}).
		Where("task_id = ? AND ip_address LIKE ?", taskID, cSegmentPrefix+"%").
		Count(&totalPorts).Error; err != nil {
		return nil, err
	}
	analysis.TotalPorts = int(totalPorts)

	// Statistical sites
	var totalSites int64
	if err := database.DB.Model(&models.Site{}).
		Where("task_id = ? AND ip LIKE ?", taskID, cSegmentPrefix+"%").
		Count(&totalSites).Error; err != nil {
		return nil, err
	}
	analysis.TotalSites = int(totalSites)

	// Statistics common ports
	type PortCount struct {
		Port  int
		Count int
	}
	var portCounts []PortCount
	if err := database.DB.Model(&models.Port{}).
		Select("port, COUNT(*) as count").
		Where("task_id = ? AND ip_address LIKE ?", taskID, cSegmentPrefix+"%").
		Group("port").
		Order("count DESC").
		Limit(10).
		Scan(&portCounts).Error; err != nil {
		return nil, err
	}

	analysis.CommonPorts = make([]int, len(portCounts))
	for i, pc := range portCounts {
		analysis.CommonPorts[i] = pc.Port
	}

	// Simple risk assessment
	if analysis.TotalPorts > 100 {
		analysis.RiskLevel = "high"
	} else if analysis.TotalPorts > 50 {
		analysis.RiskLevel = "medium"
	} else {
		analysis.RiskLevel = "low"
	}

	return analysis, nil
}
