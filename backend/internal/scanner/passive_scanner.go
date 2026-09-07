package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/proxypool"
)

// PassiveScanner 被动扫描器
type PassiveScanner struct {
	client *http.Client
}

// NewPassiveScanner 创建被动扫描器
func NewPassiveScanner() *PassiveScanner {
	return &PassiveScanner{
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: proxypool.ConfigureTransport(&http.Transport{}),
		},
	}
}

// Scan 执行被动扫描
func (ps *PassiveScanner) Scan(ctx *ScanContext) error {
	targets := ctx.TargetList()

	for _, rawTarget := range targets {
		target, err := normalizeDNSName(rawTarget)
		if err != nil {
			ctx.Logger.Printf("Skipping invalid passive target %q: %v", rawTarget, err)
			continue
		}
		if target == "" {
			ctx.Logger.Printf("Skipping non-domain passive target: %s", rawTarget)
			continue
		}

		ctx.Logger.Printf("Starting passive scan for: %s", target)

		// 1. 使用各种数据源进行被动收集
		var wg sync.WaitGroup

		// crt.sh 证书透明度
		wg.Add(1)
		go func() {
			defer wg.Done()
			if domains, err := ps.queryCrtSh(target); err == nil {
				ctx.Logger.Printf("crt.sh found %d domains", len(domains))
				ps.saveDomains(ctx, domains, "crt.sh", target)
			} else {
				ctx.Logger.Printf("crt.sh query failed: %v", err)
			}
		}()

		// DNS解析
		wg.Add(1)
		go func() {
			defer wg.Done()
			if records, err := ps.queryDNSRecords(target); err == nil {
				ctx.Logger.Printf("DNS records found: %d", len(records))
				ps.processDNSRecords(ctx, records, target)
			} else {
				ctx.Logger.Printf("DNS query failed: %v", err)
			}
		}()

		// VirusTotal (如果有API key)
		if apiKey := ps.getAPIKey(ctx, "virustotal"); apiKey != "" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if domains, err := ps.queryVirusTotal(target, apiKey); err == nil {
					ctx.Logger.Printf("VirusTotal found %d domains", len(domains))
					ps.saveDomains(ctx, domains, "virustotal", target)
				} else {
					ctx.Logger.Printf("VirusTotal query failed: %v", err)
				}
			}()
		}

		// Shodan (如果有API key)
		if apiKey := ps.getAPIKey(ctx, "shodan"); apiKey != "" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if results, err := ps.queryShodan(target, apiKey); err == nil {
					ctx.Logger.Printf("Shodan found %d results", len(results))
					ps.processShodanResults(ctx, results, target)
				} else {
					ctx.Logger.Printf("Shodan query failed: %v", err)
				}
			}()
		}

		wg.Wait()
		ctx.Logger.Printf("Passive scan completed for: %s", target)
	}

	return nil
}

// queryCrtSh 查询证书透明度日志
func (ps *PassiveScanner) queryCrtSh(domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	resp, err := ps.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var results []struct {
		NameValue string `json:"name_value"`
	}

	if err := json.Unmarshal(body, &results); err != nil {
		return nil, err
	}

	// 去重
	domainMap := make(map[string]bool)
	for _, r := range results {
		names := strings.Split(r.NameValue, "\n")
		for _, name := range names {
			name = strings.ToLower(strings.TrimSpace(name))
			if name != "" && !strings.HasPrefix(name, "*") {
				domainMap[name] = true
			}
		}
	}

	domains := make([]string, 0, len(domainMap))
	for d := range domainMap {
		domains = append(domains, d)
	}

	return domains, nil
}

// queryDNSRecords 查询DNS记录
func (ps *PassiveScanner) queryDNSRecords(domain string) (map[string][]string, error) {
	name, err := normalizeDNSName(domain)
	if err != nil {
		return nil, err
	}
	if name == "" {
		return map[string][]string{}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resolver := net.DefaultResolver
	records := make(map[string][]string)
	var queryErrors []string

	addresses, lookupErr := resolver.LookupIPAddr(ctx, name)
	if lookupErr != nil {
		queryErrors = append(queryErrors, "A/AAAA: "+lookupErr.Error())
	} else {
		for _, address := range addresses {
			if address.IP.To4() != nil {
				records["A"] = append(records["A"], address.IP.String())
			} else {
				records["AAAA"] = append(records["AAAA"], address.IP.String())
			}
		}
	}

	if mx, lookupErr := resolver.LookupMX(ctx, name); lookupErr != nil {
		queryErrors = append(queryErrors, "MX: "+lookupErr.Error())
	} else {
		for _, record := range mx {
			records["MX"] = append(records["MX"], strings.TrimSuffix(strings.ToLower(record.Host), "."))
		}
	}

	if ns, lookupErr := resolver.LookupNS(ctx, name); lookupErr != nil {
		queryErrors = append(queryErrors, "NS: "+lookupErr.Error())
	} else {
		for _, record := range ns {
			records["NS"] = append(records["NS"], strings.TrimSuffix(strings.ToLower(record.Host), "."))
		}
	}

	if txt, lookupErr := resolver.LookupTXT(ctx, name); lookupErr != nil {
		queryErrors = append(queryErrors, "TXT: "+lookupErr.Error())
	} else {
		records["TXT"] = append(records["TXT"], txt...)
	}

	if cname, lookupErr := resolver.LookupCNAME(ctx, name); lookupErr == nil {
		cname = strings.TrimSuffix(strings.ToLower(cname), ".")
		if cname != name {
			records["CNAME"] = []string{cname}
		}
	} else {
		queryErrors = append(queryErrors, "CNAME: "+lookupErr.Error())
	}

	for recordType, values := range records {
		records[recordType] = sortedUnique(values)
	}
	if len(records) == 0 && len(queryErrors) > 0 {
		return nil, fmt.Errorf("DNS lookup for %s failed: %s", name, strings.Join(queryErrors, "; "))
	}
	return records, nil
}

func normalizeDNSName(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", nil
	}
	if strings.Contains(target, "://") {
		parsed, err := url.Parse(target)
		if err != nil || parsed.Hostname() == "" {
			return "", fmt.Errorf("invalid DNS target %q", target)
		}
		target = parsed.Hostname()
	}
	if net.ParseIP(target) != nil || strings.Contains(target, "/") {
		return "", nil
	}
	return strings.TrimSuffix(strings.ToLower(target), "."), nil
}

func sortedUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// queryVirusTotal 查询VirusTotal
func (ps *PassiveScanner) queryVirusTotal(domain, apiKey string) ([]string, error) {
	url := fmt.Sprintf("https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s", apiKey, domain)

	resp, err := ps.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Subdomains []string `json:"subdomains"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return result.Subdomains, nil
}

// queryShodan 查询Shodan
func (ps *PassiveScanner) queryShodan(domain, apiKey string) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", domain, apiKey)

	resp, err := ps.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Data []map[string]interface{} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return result.Data, nil
}

// saveDomains 保存发现的域名
func (ps *PassiveScanner) saveDomains(ctx *ScanContext, domains []string, source, target string) {
	domainScanner := NewDomainScanner()

	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			continue
		}

		// 验证域名是否属于目标
		if !domainScanner.isSubdomainOf(domain, target) {
			continue
		}

		// 解析IP
		ips, err := domainScanner.resolveWithRetry(domain)
		if err == nil && len(ips) > 0 {
			domainScanner.saveDomain(ctx, domain, source, ips[0])

			// 保存IP
			for _, ip := range ips {
				domainScanner.saveIPOptimized(ctx, ip, domain)
			}
		} else {
			// 即使无法解析，也保存域名
			domainScanner.saveDomain(ctx, domain, source, "")
		}
	}
}

// processDNSRecords 处理DNS记录
func (ps *PassiveScanner) processDNSRecords(ctx *ScanContext, records map[string][]string, target string) {
	dnsTarget, _ := normalizeDNSName(target)
	if dnsTarget == "" {
		dnsTarget = target
	}
	// 处理各种DNS记录类型
	for recordType, values := range records {
		ctx.Logger.Printf("Processing %s records: %d", recordType, len(values))

		switch recordType {
		case "A", "AAAA":
			// IP地址记录
			for _, ip := range values {
				ipModel := &models.IP{
					TaskID:    ctx.Task.ID,
					IPAddress: ip,
					Domain:    dnsTarget,
				}
				ctx.DB.Where("task_id = ? AND ip_address = ?", ctx.Task.ID, ip).FirstOrCreate(ipModel)
			}
		case "MX":
			// 邮件服务器记录
			for _, mx := range values {
				ctx.Logger.Printf("MX record for %s: %s", dnsTarget, mx)
			}
		case "NS", "CNAME":
			for _, name := range values {
				ctx.Logger.Printf("%s record for %s: %s", recordType, dnsTarget, name)
			}
		case "TXT":
			// TXT记录可能包含SPF、DKIM等信息
			for _, txt := range values {
				ctx.Logger.Printf("TXT record: %s", txt)
			}
		}
	}
}

// processShodanResults 处理Shodan结果
func (ps *PassiveScanner) processShodanResults(ctx *ScanContext, results []map[string]interface{}, target string) {
	for _, result := range results {
		// 提取IP地址
		if ip, ok := result["ip_str"].(string); ok {
			ipModel := &models.IP{
				TaskID:    ctx.Task.ID,
				IPAddress: ip,
				Domain:    target,
			}

			// 提取位置信息
			if location, ok := result["location"].(map[string]interface{}); ok {
				if country, ok := location["country_name"].(string); ok {
					if city, ok := location["city"].(string); ok {
						ipModel.Location = fmt.Sprintf("%s, %s", country, city)
					} else {
						ipModel.Location = country
					}
				}
			}

			ctx.DB.Where("task_id = ? AND ip_address = ?", ctx.Task.ID, ip).FirstOrCreate(ipModel)

			// 提取端口信息
			if port, ok := result["port"].(float64); ok {
				portModel := &models.Port{
					TaskID:    ctx.Task.ID,
					IPAddress: ip,
					Port:      int(port),
					Protocol:  "tcp",
				}

				// 提取服务信息
				if service, ok := result["product"].(string); ok {
					portModel.Service = service
				}

				// 提取版本信息
				if version, ok := result["version"].(string); ok {
					portModel.Version = version
				}

				ctx.DB.Where("task_id = ? AND ip_address = ? AND port = ?",
					ctx.Task.ID, ip, int(port)).FirstOrCreate(portModel)
			}
		}
	}
}

// getAPIKey 从数据库获取API密钥
func (ps *PassiveScanner) getAPIKey(ctx *ScanContext, keyName string) string {
	var enabledSetting models.Setting
	if err := ctx.DB.Where("category = ? AND key = ?", "api", keyName+"_enabled").First(&enabledSetting).Error; err == nil {
		if !apiProviderEnabled(map[string]string{enabledSetting.Key: enabledSetting.Value}, keyName) {
			return ""
		}
	}

	keys := []string{keyName}
	if keyName == "virustotal" {
		keys = append(keys, "virustotal_api_key")
	}
	if keyName == "shodan" {
		keys = append(keys, "shodan_api_key")
	}
	var setting models.Setting
	if err := ctx.DB.Where("category = ? AND key IN ?", "api", keys).First(&setting).Error; err != nil {
		return ""
	}

	if setting.IsEncrypted && setting.Value != "" {
		value, err := decryptValue(setting.Value)
		if err != nil {
			return ""
		}
		return value
	}

	return setting.Value
}
