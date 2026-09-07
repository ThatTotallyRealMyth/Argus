package scanner

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/reconmaster/backend/internal/models"
	"golang.org/x/net/publicsuffix"
)

// AssetMapper 资产测绘器
type AssetMapper struct {
	mu sync.RWMutex
}

// AssetProfile 资产画像
type AssetProfile struct {
	TaskID string `json:"task_id"`
	Target string `json:"target"`

	// 域名资产
	TotalDomains     int            `json:"total_domains"`
	RootDomains      []string       `json:"root_domains"`
	SubdomainSources map[string]int `json:"subdomain_sources"` // 来源统计

	// IP资产
	TotalIPs    int            `json:"total_ips"`
	IPLocations map[string]int `json:"ip_locations"` // 地理位置分布
	CDNIPs      int            `json:"cdn_ips"`      // CDN IP数量
	UniqueIPs   []string       `json:"unique_ips"`

	// 端口资产
	TotalPorts       int            `json:"total_ports"`
	OpenPorts        map[int]int    `json:"open_ports"`        // 端口号:数量
	PortDistribution map[string]int `json:"port_distribution"` // 端口范围分布

	// 服务资产
	TotalServices int                 `json:"total_services"`
	ServiceTypes  map[string]int      `json:"service_types"` // 服务类型统计
	Versions      map[string][]string `json:"versions"`      // 服务版本信息

	// Web资产
	TotalSites      int            `json:"total_sites"`
	WebTechnologies map[string]int `json:"web_technologies"`  // 技术栈统计
	HTTPStatusCodes map[int]int    `json:"http_status_codes"` // 状态码分布
	TitleKeywords   map[string]int `json:"title_keywords"`    // 标题关键词

	// 安全风险
	TakeoverVulnerable int `json:"takeover_vulnerable"` // 子域名接管风险
	FileLeaks          int `json:"file_leaks"`          // 文件泄露
	SensitiveInfo      int `json:"sensitive_info"`      // 敏感信息

	// 证书资产
	SSLCertificates int            `json:"ssl_certificates"`
	CertIssuers     map[string]int `json:"cert_issuers"`
	ExpiredCerts    int            `json:"expired_certs"`

	// 爬虫资产
	TotalURLs int            `json:"total_urls"`
	URLPaths  map[string]int `json:"url_paths"`  // URL路径统计
	FormCount int            `json:"form_count"` // 表单数量

	// 时间戳
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// NewAssetMapper 创建资产测绘器
func NewAssetMapper() *AssetMapper {
	return &AssetMapper{}
}

// MapAssets 执行资产测绘
func (am *AssetMapper) MapAssets(ctx *ScanContext) error {
	ctx.Logger.Printf("=== Asset Mapping Started ===")

	profile := &AssetProfile{
		TaskID:           ctx.Task.ID,
		Target:           ctx.Task.Target,
		SubdomainSources: make(map[string]int),
		IPLocations:      make(map[string]int),
		UniqueIPs:        []string{},
		OpenPorts:        make(map[int]int),
		PortDistribution: make(map[string]int),
		ServiceTypes:     make(map[string]int),
		Versions:         make(map[string][]string),
		WebTechnologies:  make(map[string]int),
		HTTPStatusCodes:  make(map[int]int),
		TitleKeywords:    make(map[string]int),
		CertIssuers:      make(map[string]int),
		URLPaths:         make(map[string]int),
	}

	// 并发统计各类资产
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		am.mapDomains(ctx, profile)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		am.mapIPs(ctx, profile)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		am.mapPorts(ctx, profile)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		am.mapServices(ctx, profile)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		am.mapSites(ctx, profile)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		am.mapSecurity(ctx, profile)
	}()

	wg.Wait()

	// 保存资产画像
	am.saveProfile(ctx, profile)

	// 打印统计摘要
	am.printSummary(ctx, profile)

	ctx.Logger.Printf("Asset mapping completed")
	return nil
}

// mapDomains 统计域名资产
func (am *AssetMapper) mapDomains(ctx *ScanContext, profile *AssetProfile) {
	am.mu.Lock()
	defer am.mu.Unlock()

	var domains []models.Domain
	ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&domains)

	profile.TotalDomains = len(domains)
	rootDomainsMap := make(map[string]bool)

	for _, domain := range domains {
		// 统计来源
		source := domain.Source
		if source == "" {
			source = "unknown"
		}
		profile.SubdomainSources[source]++

		// 提取根域名
		rootDomain := extractRootDomain(domain.Domain)
		rootDomainsMap[rootDomain] = true
	}

	for root := range rootDomainsMap {
		profile.RootDomains = append(profile.RootDomains, root)
	}
}

// mapIPs 统计IP资产
func (am *AssetMapper) mapIPs(ctx *ScanContext, profile *AssetProfile) {
	am.mu.Lock()
	defer am.mu.Unlock()

	var ips []models.IP
	ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&ips)

	profile.TotalIPs = len(ips)
	uniqueIPMap := make(map[string]bool)

	for _, ip := range ips {
		uniqueIPMap[ip.IPAddress] = true

		// 统计地理位置
		if ip.Location != "" {
			profile.IPLocations[ip.Location]++
		}

		// 统计CDN
		if ip.CDN {
			profile.CDNIPs++
		}
	}

	for ipAddr := range uniqueIPMap {
		profile.UniqueIPs = append(profile.UniqueIPs, ipAddr)
	}
}

// mapPorts 统计端口资产
func (am *AssetMapper) mapPorts(ctx *ScanContext, profile *AssetProfile) {
	am.mu.Lock()
	defer am.mu.Unlock()

	var ports []models.Port
	ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&ports)

	profile.TotalPorts = len(ports)

	for _, port := range ports {
		// 统计端口号
		profile.OpenPorts[port.Port]++

		// 端口范围分布
		portRange := getPortRange(port.Port)
		profile.PortDistribution[portRange]++
	}
}

// mapServices 统计服务资产
func (am *AssetMapper) mapServices(ctx *ScanContext, profile *AssetProfile) {
	am.mu.Lock()
	defer am.mu.Unlock()

	var ports []models.Port
	ctx.DB.Where("task_id = ? AND service IS NOT NULL AND service != ''", ctx.Task.ID).Find(&ports)

	profile.TotalServices = len(ports)

	for _, port := range ports {
		// 统计服务类型
		service := port.Service
		if service != "" {
			profile.ServiceTypes[service]++

			// 收集版本信息
			if port.Version != "" {
				versionKey := fmt.Sprintf("%s/%s", service, port.Version)
				if !containsString(profile.Versions[service], port.Version) {
					profile.Versions[service] = append(profile.Versions[service], port.Version)
				}
				_ = versionKey
			}
		}
	}
}

// mapSites 统计Web资产
func (am *AssetMapper) mapSites(ctx *ScanContext, profile *AssetProfile) {
	am.mu.Lock()
	defer am.mu.Unlock()

	var sites []models.Site
	ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&sites)

	profile.TotalSites = len(sites)

	for _, site := range sites {
		// 统计HTTP状态码
		profile.HTTPStatusCodes[site.StatusCode]++

		// 统计标题关键词（提取有意义的词）
		if site.Title != "" {
			keywords := extractKeywords(site.Title)
			for _, keyword := range keywords {
				profile.TitleKeywords[keyword]++
			}
		}

		// 统计技术栈（从fingerprint字段解析）
		if site.Fingerprint != "" {
			techs := parseFingerprint(site.Fingerprint)
			for _, tech := range techs {
				profile.WebTechnologies[tech]++
			}
		}
	}

	// 统计URL
	var crawlerResults []models.CrawlerResult
	ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&crawlerResults)
	profile.TotalURLs = len(crawlerResults)

	for _, result := range crawlerResults {
		// 提取URL路径
		path := extractURLPath(result.URL)
		profile.URLPaths[path]++

		// 统计表单
		if result.HasForm {
			profile.FormCount++
		}
	}
}

// mapSecurity 统计安全资产
func (am *AssetMapper) mapSecurity(ctx *ScanContext, profile *AssetProfile) {
	am.mu.Lock()
	defer am.mu.Unlock()

	// 子域名接管风险
	var takeoverCount int64
	ctx.DB.Model(&models.Domain{}).
		Where("task_id = ? AND takeover_vulnerable = ?", ctx.Task.ID, true).
		Count(&takeoverCount)
	profile.TakeoverVulnerable = int(takeoverCount)

	// 文件泄露与敏感信息统计来自漏洞结果，保持和风险列表一致。
	var fileLeakCount int64
	ctx.DB.Model(&models.Vulnerability{}).
		Where("task_id = ? AND type = ?", ctx.Task.ID, "file_leak").
		Count(&fileLeakCount)
	profile.FileLeaks = int(fileLeakCount)

	var sensitiveInfoCount int64
	ctx.DB.Model(&models.Vulnerability{}).
		Where("task_id = ? AND type = ?", ctx.Task.ID, "sensitive_info").
		Count(&sensitiveInfoCount)
	profile.SensitiveInfo = int(sensitiveInfoCount)

	// SSL证书
	var ports []models.Port
	ctx.DB.Where("task_id = ? AND ssl_cert IS NOT NULL AND ssl_cert != ''", ctx.Task.ID).Find(&ports)
	profile.SSLCertificates = len(ports)

	// 证书颁发者统计
	for _, port := range ports {
		if port.SSLCert != "" {
			issuer := extractCertIssuer(port.SSLCert)
			if issuer != "" {
				profile.CertIssuers[issuer]++
			}
		}
	}
}

// saveProfile 保存资产画像到数据库
func (am *AssetMapper) saveProfile(ctx *ScanContext, profile *AssetProfile) {
	profileJSON, err := json.Marshal(profile)
	if err != nil {
		ctx.Logger.Printf("Failed to marshal asset profile: %v", err)
		return
	}

	// 保存到任务的元数据字段或单独的asset_profile表
	ctx.DB.Model(&models.Task{}).
		Where("id = ?", ctx.Task.ID).
		Update("asset_profile", string(profileJSON))
}

// printSummary 打印资产测绘摘要
func (am *AssetMapper) printSummary(ctx *ScanContext, profile *AssetProfile) {
	ctx.Logger.Printf("=== Asset Mapping Summary ===")
	ctx.Logger.Printf("📊 Domains: %d (Root: %d)", profile.TotalDomains, len(profile.RootDomains))
	ctx.Logger.Printf("🌐 IPs: %d (CDN: %d)", profile.TotalIPs, profile.CDNIPs)
	ctx.Logger.Printf("🔌 Ports: %d", profile.TotalPorts)
	ctx.Logger.Printf("⚙️  Services: %d types", len(profile.ServiceTypes))
	ctx.Logger.Printf("🌍 Sites: %d", profile.TotalSites)
	ctx.Logger.Printf("🔗 URLs: %d", profile.TotalURLs)
	ctx.Logger.Printf("🔒 SSL Certs: %d", profile.SSLCertificates)

	if profile.TakeoverVulnerable > 0 {
		ctx.Logger.Printf("⚠️  Takeover Vulnerable: %d domains", profile.TakeoverVulnerable)
	}

	// 打印Top服务
	ctx.Logger.Printf("\n🔝 Top Services:")
	for service, count := range profile.ServiceTypes {
		if count > 0 {
			ctx.Logger.Printf("  - %s: %d", service, count)
		}
	}

	// 打印Top端口
	ctx.Logger.Printf("\n🔝 Top Open Ports:")
	for port, count := range profile.OpenPorts {
		if count > 2 { // 只显示出现超过2次的端口
			ctx.Logger.Printf("  - Port %d: %d instances", port, count)
		}
	}
}

// 辅助函数

func extractRootDomain(domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	root, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return domain
	}
	return strings.ToLower(root)
}

func getPortRange(port int) string {
	switch {
	case port < 1024:
		return "well-known (0-1023)"
	case port < 49152:
		return "registered (1024-49151)"
	default:
		return "dynamic (49152-65535)"
	}
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func extractKeywords(title string) []string {
	// 简单的关键词提取（可以使用更复杂的NLP方法）
	keywords := []string{}
	words := strings.Fields(title)
	for _, word := range words {
		word = strings.TrimSpace(word)
		if len(word) > 2 { // 过滤太短的词
			keywords = append(keywords, strings.ToLower(word))
		}
	}
	return keywords
}

func parseFingerprint(fingerprint string) []string {
	// 解析fingerprint JSON字符串，提取技术栈名称
	techs := []string{}
	// 简单实现：假设fingerprint是逗号分隔的字符串
	if fingerprint != "" {
		parts := strings.Split(fingerprint, ",")
		for _, part := range parts {
			tech := strings.TrimSpace(part)
			if tech != "" {
				techs = append(techs, tech)
			}
		}
	}
	return techs
}

func extractURLPath(url string) string {
	// 提取URL的路径部分
	parts := strings.SplitN(url, "://", 2)
	if len(parts) == 2 {
		pathParts := strings.SplitN(parts[1], "/", 2)
		if len(pathParts) == 2 {
			return "/" + pathParts[1]
		}
	}
	return "/"
}

func extractCertIssuer(certInfo string) string {
	// 从证书信息中提取颁发者
	// 简单实现：查找"Issuer:"行
	lines := strings.Split(certInfo, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Issuer:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				issuer := strings.TrimSpace(parts[1])
				// 提取组织名称 (O=)
				if idx := strings.Index(issuer, "O="); idx >= 0 {
					orgPart := issuer[idx+2:]
					if endIdx := strings.Index(orgPart, ","); endIdx >= 0 {
						return orgPart[:endIdx]
					}
					return orgPart
				}
				return issuer
			}
		}
	}
	return "Unknown"
}
