package scanner

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/proxypool"
)

type QuakePlugin struct {
	client *http.Client
	apiKey string
}

func NewQuakePlugin(apiKey string) *QuakePlugin {
	return &QuakePlugin{client: createHTTPClient(30*time.Second, false), apiKey: apiKey}
}
func (p *QuakePlugin) Name() string { return "quake" }
func (p *QuakePlugin) Query(domain string) ([]string, error) {
	body := []byte(fmt.Sprintf(`{"query":"domain:\"%s\"","start":0,"size":100}`, strings.ReplaceAll(domain, `"`, "")))
	req, err := http.NewRequest(http.MethodPost, "https://quake.360.net/api/v3/quake_service", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-QuakeToken", p.apiKey)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("quake status code: %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}
	return extractDomainsFromCustomSpaceAPIResponse(data), nil
}

type ZoomEyePlugin struct {
	client *http.Client
	apiKey string
}

func NewZoomEyePlugin(apiKey string) *ZoomEyePlugin {
	return &ZoomEyePlugin{client: createHTTPClient(30*time.Second, false), apiKey: apiKey}
}
func (p *ZoomEyePlugin) Name() string { return "zoomeye" }
func (p *ZoomEyePlugin) Query(domain string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, "https://api.zoomeye.org/host/search?query=hostname:%22"+url.QueryEscape(domain)+"%22&page=1", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("API-KEY", p.apiKey)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("zoomeye status code: %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}
	return extractDomainsFromCustomSpaceAPIResponse(data), nil
}

// DomainPlugin 域名查询插件接口
type DomainPlugin interface {
	Name() string
	Query(domain string) ([]string, error)
}

// createHTTPClient 创建HTTP客户端
func createHTTPClient(timeout time.Duration, skipTLS bool) *http.Client {
	transport := proxypool.ConfigureTransport(&http.Transport{})
	if skipTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

// CrtshPlugin Certificate Transparency日志查询
type CrtshPlugin struct {
	client *http.Client
}

func NewCrtshPlugin() *CrtshPlugin {
	return &CrtshPlugin{
		client: createHTTPClient(60*time.Second, false), // 增加超时到60秒
	}
}

func (p *CrtshPlugin) Name() string {
	return "crtsh"
}

func (p *CrtshPlugin) Query(domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	// 重试机制
	var resp *http.Response
	var err error
	for i := 0; i < 3; i++ {
		resp, err = p.client.Get(url)
		if err == nil {
			break
		}
		time.Sleep(time.Duration(i+1) * time.Second)
	}

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

	domains := make(map[string]bool)
	for _, r := range results {
		// name_value可能包含多个域名，用\n分隔
		names := strings.Split(r.NameValue, "\n")
		for _, name := range names {
			name = strings.ToLower(strings.TrimSpace(name))
			if name != "" && !strings.HasPrefix(name, "*") {
				domains[name] = true
			}
		}
	}

	result := make([]string, 0, len(domains))
	for d := range domains {
		result = append(result, d)
	}

	return result, nil
}

// CertSpotterPlugin CertSpotter API
type CertSpotterPlugin struct {
	client *http.Client
}

func NewCertSpotterPlugin() *CertSpotterPlugin {
	return &CertSpotterPlugin{
		client: createHTTPClient(30*time.Second, false),
	}
}

func (p *CertSpotterPlugin) Name() string {
	return "certspotter"
}

func (p *CertSpotterPlugin) Query(domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)

	resp, err := p.client.Get(url)
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
		DNSNames []string `json:"dns_names"`
	}

	if err := json.Unmarshal(body, &results); err != nil {
		return nil, err
	}

	domains := make(map[string]bool)
	for _, r := range results {
		for _, name := range r.DNSNames {
			name = strings.ToLower(strings.TrimSpace(name))
			if name != "" && !strings.HasPrefix(name, "*") {
				domains[name] = true
			}
		}
	}

	result := make([]string, 0, len(domains))
	for d := range domains {
		result = append(result, d)
	}

	return result, nil
}

// AlienVaultPlugin AlienVault OTX
type AlienVaultPlugin struct {
	client *http.Client
}

func NewAlienVaultPlugin() *AlienVaultPlugin {
	return &AlienVaultPlugin{
		client: createHTTPClient(30*time.Second, false),
	}
}

func (p *AlienVaultPlugin) Name() string {
	return "alienvault"
}

func (p *AlienVaultPlugin) Query(domain string) ([]string, error) {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)

	resp, err := p.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 处理速率限制
	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("rate limited (429), please wait and retry later")
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	domains := make(map[string]bool)
	for _, record := range result.PassiveDNS {
		name := strings.ToLower(strings.TrimSpace(record.Hostname))
		if name != "" && !strings.HasPrefix(name, "*") {
			domains[name] = true
		}
	}

	domainList := make([]string, 0, len(domains))
	for d := range domains {
		domainList = append(domainList, d)
	}

	return domainList, nil
}

// HackerTargetPlugin HackerTarget API
type HackerTargetPlugin struct {
	client *http.Client
}

func NewHackerTargetPlugin() *HackerTargetPlugin {
	return &HackerTargetPlugin{
		client: createHTTPClient(30*time.Second, false),
	}
}

func (p *HackerTargetPlugin) Name() string {
	return "hackertarget"
}

func (p *HackerTargetPlugin) Query(domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)

	resp, err := p.client.Get(url)
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

	lines := strings.Split(string(body), "\n")
	domains := make([]string, 0)

	for _, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) >= 1 {
			domain := strings.TrimSpace(parts[0])
			if domain != "" && !strings.HasPrefix(domain, "error") {
				domains = append(domains, domain)
			}
		}
	}

	return domains, nil
}

// ThreatCrowdPlugin ThreatCrowd API (跳过TLS验证因为证书问题)
type ThreatCrowdPlugin struct {
	client *http.Client
}

func NewThreatCrowdPlugin() *ThreatCrowdPlugin {
	return &ThreatCrowdPlugin{
		client: createHTTPClient(30*time.Second, true), // 跳过TLS验证
	}
}

func (p *ThreatCrowdPlugin) Name() string {
	return "threatcrowd"
}

func (p *ThreatCrowdPlugin) Query(domain string) ([]string, error) {
	url := fmt.Sprintf("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", domain)

	resp, err := p.client.Get(url)
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

// VirusTotalPlugin VirusTotal API (需要API Key)
type VirusTotalPlugin struct {
	client *http.Client
	apiKey string
}

func NewVirusTotalPlugin(apiKey string) *VirusTotalPlugin {
	return &VirusTotalPlugin{
		client: createHTTPClient(30*time.Second, false),
		apiKey: apiKey,
	}
}

func (p *VirusTotalPlugin) Name() string {
	return "virustotal"
}

func (p *VirusTotalPlugin) Query(domain string) ([]string, error) {
	if p.apiKey == "" {
		return nil, fmt.Errorf("API key required")
	}

	url := fmt.Sprintf("https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s", p.apiKey, domain)

	resp, err := p.client.Get(url)
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

// FOFAPlugin FOFA搜索引擎
type FOFAPlugin struct {
	client *http.Client
	email  string
	key    string
}

func NewFOFAPlugin(email, key string) *FOFAPlugin {
	return &FOFAPlugin{
		client: createHTTPClient(30*time.Second, false),
		email:  email,
		key:    key,
	}
}

func (p *FOFAPlugin) Name() string {
	return "fofa"
}

func (p *FOFAPlugin) Query(domain string) ([]string, error) {
	if p.email == "" || p.key == "" {
		return nil, fmt.Errorf("FOFA API key required")
	}

	// FOFA查询语法：查询子域名
	query := fmt.Sprintf("domain=\"%s\"", domain)

	// Base64编码查询语句
	qbase64 := base64.StdEncoding.EncodeToString([]byte(query))

	// 构建API URL
	apiURL := fmt.Sprintf("https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&fields=host&size=10000",
		p.email, p.key, qbase64)

	resp, err := p.client.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// FOFA API 响应格式
	var result struct {
		Error   bool     `json:"error"`
		ErrMsg  string   `json:"errmsg"`
		Size    int      `json:"size"`
		Results []string `json:"results"` // FOFA返回的是字符串数组，不是二维数组
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v, body: %s", err, string(body))
	}

	if result.Error {
		return nil, fmt.Errorf("FOFA API error: %s", result.ErrMsg)
	}

	// 提取域名并去重
	domainSet := make(map[string]bool)
	for _, host := range result.Results {
		host = strings.TrimSpace(host)
		// 移除协议和端口，只保留域名
		host = strings.TrimPrefix(host, "http://")
		host = strings.TrimPrefix(host, "https://")
		if idx := strings.Index(host, ":"); idx != -1 {
			host = host[:idx]
		}
		if idx := strings.Index(host, "/"); idx != -1 {
			host = host[:idx]
		}
		if host != "" && !domainSet[host] {
			domainSet[host] = true
		}
	}

	domains := make([]string, 0, len(domainSet))
	for d := range domainSet {
		domains = append(domains, d)
	}

	return domains, nil
}

// HunterPlugin 鹰图平台（Hunter）
type HunterPlugin struct {
	client *http.Client
	apiKey string
}

func NewHunterPlugin(apiKey string) *HunterPlugin {
	return &HunterPlugin{
		client: createHTTPClient(30*time.Second, false),
		apiKey: apiKey,
	}
}

func (p *HunterPlugin) Name() string {
	return "hunter"
}

func (p *HunterPlugin) Query(domain string) ([]string, error) {
	if p.apiKey == "" {
		return nil, fmt.Errorf("Hunter API key required")
	}

	// Hunter API 查询语法
	// 使用 domain 字段搜索子域名
	query := fmt.Sprintf("domain=\"%s\"", domain)
	encodedQuery := url.QueryEscape(query)

	// Hunter API 端点
	apiURL := fmt.Sprintf("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=1&page_size=100&is_web=1",
		p.apiKey, encodedQuery)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	// 设置 User-Agent
	req.Header.Set("User-Agent", "ReconMaster/1.0")

	resp, err := p.client.Do(req)
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
		Code int `json:"code"`
		Data struct {
			AccountType string `json:"account_type"`
			Total       int    `json:"total"`
			Arr         []struct {
				Domain string `json:"domain"`
				URL    string `json:"url"`
			} `json:"arr"`
		} `json:"data"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if result.Code != 200 {
		return nil, fmt.Errorf("Hunter API error: %s", result.Message)
	}

	// 提取域名并去重
	domainSet := make(map[string]bool)
	for _, item := range result.Data.Arr {
		if item.Domain != "" {
			domain := strings.ToLower(strings.TrimSpace(item.Domain))
			domainSet[domain] = true
		}
	}

	domains := make([]string, 0, len(domainSet))
	for d := range domainSet {
		domains = append(domains, d)
	}

	return domains, nil
}

// CustomSpaceAPIPlugin calls a user supplied cyberspace/search API URL.
// The URL template may contain {domain}; otherwise the domain is appended as
// a query parameter named domain.
type CustomSpaceAPIPlugin struct {
	client      *http.Client
	urlTemplate string
	headers     map[string]string
}

func NewCustomSpaceAPIPlugin(urlTemplate string, headers map[string]string) *CustomSpaceAPIPlugin {
	return &CustomSpaceAPIPlugin{
		client:      createHTTPClient(30*time.Second, false),
		urlTemplate: strings.TrimSpace(urlTemplate),
		headers:     headers,
	}
}

func (p *CustomSpaceAPIPlugin) Name() string {
	return "custom_space_api"
}

func (p *CustomSpaceAPIPlugin) Query(domain string) ([]string, error) {
	if p.urlTemplate == "" {
		return nil, fmt.Errorf("custom_space_api_url is required")
	}

	apiURL := p.urlTemplate
	if strings.Contains(apiURL, "{domain}") {
		apiURL = strings.ReplaceAll(apiURL, "{domain}", url.QueryEscape(domain))
	} else {
		separator := "?"
		if strings.Contains(apiURL, "?") {
			separator = "&"
		}
		apiURL = apiURL + separator + "domain=" + url.QueryEscape(domain)
	}

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ReconMaster/1.0")
	for key, value := range p.headers {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			req.Header.Set(key, value)
		}
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}
	return extractDomainsFromCustomSpaceAPIResponse(body), nil
}

func extractDomainsFromCustomSpaceAPIResponse(body []byte) []string {
	domainSet := make(map[string]bool)
	add := func(value string) {
		value = strings.ToLower(strings.TrimSpace(value))
		value = strings.TrimPrefix(value, "http://")
		value = strings.TrimPrefix(value, "https://")
		if idx := strings.IndexAny(value, ":/"); idx >= 0 {
			value = value[:idx]
		}
		value = strings.Trim(value, " \t\r\n\"'")
		if value != "" && strings.Contains(value, ".") && !strings.HasPrefix(value, "*") {
			domainSet[value] = true
		}
	}

	var decoded any
	if err := json.Unmarshal(body, &decoded); err == nil {
		walkCustomSpaceAPIJSON(decoded, add)
	}

	domainRegex := regexp.MustCompile(`(?i)\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b`)
	for _, match := range domainRegex.FindAllString(string(body), -1) {
		add(match)
	}

	domains := make([]string, 0, len(domainSet))
	for domain := range domainSet {
		domains = append(domains, domain)
	}
	return domains
}

func walkCustomSpaceAPIJSON(value any, add func(string)) {
	switch typed := value.(type) {
	case string:
		add(typed)
	case []any:
		for _, item := range typed {
			walkCustomSpaceAPIJSON(item, add)
		}
	case map[string]any:
		for key, item := range typed {
			switch strings.ToLower(key) {
			case "domain", "host", "hostname", "subdomain", "url":
				if text, ok := item.(string); ok {
					add(text)
					continue
				}
			}
			walkCustomSpaceAPIJSON(item, add)
		}
	}
}

// GetAvailablePlugins 获取可用的插件列表
func GetAvailablePlugins(apiKeys map[string]string) []DomainPlugin {
	plugins := []DomainPlugin{
		NewCrtshPlugin(),
		NewCertSpotterPlugin(),
		NewAlienVaultPlugin(),
		NewHackerTargetPlugin(),
		NewThreatCrowdPlugin(),
	}

	// 添加需要API Key的插件
	if apiProviderEnabled(apiKeys, "virustotal") {
		if key := firstNonEmpty(apiKeys, "virustotal", "virustotal_api_key"); key != "" {
			plugins = append(plugins, NewVirusTotalPlugin(key))
		}
	}

	if apiProviderEnabled(apiKeys, "fofa") && apiKeys["fofa_email"] != "" && apiKeys["fofa_key"] != "" {
		plugins = append(plugins, NewFOFAPlugin(apiKeys["fofa_email"], apiKeys["fofa_key"]))
	}

	if apiProviderEnabled(apiKeys, "hunter") {
		if hunterKey := firstNonEmpty(apiKeys, "hunter", "hunter_key", "hunter_api_key"); hunterKey != "" {
			plugins = append(plugins, NewHunterPlugin(hunterKey))
		}
	}
	if apiProviderEnabled(apiKeys, "quake") {
		if key := firstNonEmpty(apiKeys, "quake", "quake_api_key"); key != "" {
			plugins = append(plugins, NewQuakePlugin(key))
		}
	}
	if apiProviderEnabled(apiKeys, "zoomeye") {
		if key := firstNonEmpty(apiKeys, "zoomeye", "zoomeye_api_key"); key != "" {
			plugins = append(plugins, NewZoomEyePlugin(key))
		}
	}

	if apiProviderEnabled(apiKeys, "custom_space_api") {
		if customURL := firstNonEmpty(apiKeys, "custom_space_api_url", "custom_api_url"); customURL != "" {
			plugins = append(plugins, NewCustomSpaceAPIPlugin(customURL, parseCustomSpaceAPIHeaders(apiKeys["custom_space_api_headers"])))
		}
	}

	return plugins
}

func apiProviderEnabled(values map[string]string, provider string) bool {
	value, exists := values[provider+"_enabled"]
	if !exists {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "false", "0", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func firstNonEmpty(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value
		}
	}
	return ""
}

func parseCustomSpaceAPIHeaders(raw string) map[string]string {
	headers := make(map[string]string)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return headers
	}
	if err := json.Unmarshal([]byte(raw), &headers); err == nil {
		return headers
	}
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			headers[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return headers
}
