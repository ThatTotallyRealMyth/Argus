package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/proxypool"
	"gorm.io/gorm"
)

var (
	ErrGithubTokenNotConfigured  = errors.New("GitHub token is not configured")
	ErrGithubIntegrationDisabled = errors.New("GitHub integration is disabled")
)

// GithubMonitor Github监控器
type GithubMonitor struct {
	client  *http.Client
	token   string
	baseURL string
}

// NewGithubMonitor 创建Github监控器
func NewGithubMonitor(token string) *GithubMonitor {
	return &GithubMonitor{
		client: &http.Client{
			Timeout:   15 * time.Second,
			Transport: proxypool.ConfigureTransport(&http.Transport{}),
		},
		token:   token,
		baseURL: "https://api.github.com",
	}
}

// NewGithubMonitorFromSettings loads the encrypted GitHub token and honors the
// provider switch used by the settings page.
func NewGithubMonitorFromSettings(db *gorm.DB) (*GithubMonitor, error) {
	if db == nil {
		return nil, ErrGithubTokenNotConfigured
	}
	var settings []models.Setting
	if err := db.Where("category = ? AND key IN ?", models.SettingCategoryAPI, []string{models.SettingKeyGitHubToken, models.SettingKeyGitHubEnabled}).Find(&settings).Error; err != nil {
		return nil, fmt.Errorf("load GitHub token: %w", err)
	}
	values := make(map[string]string, len(settings))
	for _, setting := range settings {
		value := strings.TrimSpace(setting.Value)
		if setting.IsEncrypted && value != "" {
			decrypted, err := decryptValue(value)
			if err != nil {
				return nil, fmt.Errorf("decrypt GitHub token: %w", err)
			}
			value = strings.TrimSpace(decrypted)
		}
		values[setting.Key] = value
	}
	if !apiProviderEnabled(values, "github") {
		return nil, ErrGithubIntegrationDisabled
	}
	token := values[models.SettingKeyGitHubToken]
	if token == "" {
		return nil, ErrGithubTokenNotConfigured
	}
	return NewGithubMonitor(token), nil
}

// GithubSearchResult Github搜索结果
type GithubSearchResult struct {
	TotalCount int                `json:"total_count"`
	Items      []GithubSearchItem `json:"items"`
}

type GithubSearchItem struct {
	Name       string           `json:"name"`
	Path       string           `json:"path"`
	HTMLURL    string           `json:"html_url"`
	Repository GithubRepository `json:"repository"`
	Score      float64          `json:"score"`
}

type GithubRepository struct {
	FullName    string `json:"full_name"`
	Description string `json:"description"`
	HTMLURL     string `json:"html_url"`
}

type GithubInspectedItem struct {
	Item  GithubSearchItem
	Leaks map[string][]string
	Err   error
}

// SearchKeyword 搜索关键字
func (gm *GithubMonitor) SearchKeyword(keyword string, maxResults int) (*GithubSearchResult, error) {
	if maxResults <= 0 {
		maxResults = 30
	}
	if maxResults > 100 {
		maxResults = 100
	}

	// 构建搜索URL
	query := url.QueryEscape(keyword)
	apiURL := fmt.Sprintf("%s/search/code?q=%s&per_page=%d&sort=indexed&order=desc", strings.TrimRight(gm.baseURL, "/"), query, maxResults)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	// 设置认证头
	if gm.token != "" {
		req.Header.Set("Authorization", "Bearer "+gm.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "Eclipse-Recon")

	resp, err := gm.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		return nil, fmt.Errorf("API rate limit exceeded or authentication required")
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result GithubSearchResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// SearchMultipleKeywords 搜索多个关键字
func (gm *GithubMonitor) SearchMultipleKeywords(keywords []string) (map[string]*GithubSearchResult, error) {
	results := make(map[string]*GithubSearchResult)
	var searchErrors []string

	for _, keyword := range keywords {
		result, err := gm.SearchKeyword(keyword, 30)
		if err != nil {
			searchErrors = append(searchErrors, fmt.Sprintf("%s: %v", keyword, err))
			continue
		}
		results[keyword] = result

		// 避免触发rate limit
		time.Sleep(2 * time.Second)
	}

	if len(results) == 0 && len(searchErrors) > 0 {
		return nil, fmt.Errorf("all GitHub keyword searches failed: %s", strings.Join(searchErrors, "; "))
	}
	return results, nil
}

// SearchSensitiveInfo 搜索敏感信息
func (gm *GithubMonitor) SearchSensitiveInfo(domain string) (*GithubSearchResult, error) {
	// 构建敏感信息搜索查询
	queries := []string{
		fmt.Sprintf("%s password", domain),
		fmt.Sprintf("%s api_key", domain),
		fmt.Sprintf("%s secret", domain),
		fmt.Sprintf("%s token", domain),
		fmt.Sprintf("%s aws_access_key", domain),
	}

	var allItems []GithubSearchItem
	seen := make(map[string]struct{})

	for _, query := range queries {
		result, err := gm.SearchKeyword(query, 10)
		if err != nil {
			continue
		}
		for _, item := range result.Items {
			key := item.HTMLURL
			if key == "" {
				key = item.Repository.FullName + ":" + item.Path
			}
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			allItems = append(allItems, item)
		}
		time.Sleep(2 * time.Second)
	}

	return &GithubSearchResult{
		TotalCount: len(allItems),
		Items:      allItems,
	}, nil
}

// MonitorKeywords 监控关键字
func (gm *GithubMonitor) MonitorKeywords(ctx *ScanContext, keywords []string) error {
	ctx.Logger.Printf("Monitoring %d keywords on Github", len(keywords))

	results, err := gm.SearchMultipleKeywords(keywords)
	if err != nil {
		return err
	}

	// 保存结果
	for keyword, result := range results {
		ctx.Logger.Printf("Keyword '%s' found %d results", keyword, result.TotalCount)

		for _, item := range result.Items {
			leaks, err := gm.InspectSearchItem(item)
			if err != nil {
				ctx.Logger.Printf("GitHub content inspection failed for %s: %v", item.HTMLURL, err)
				continue
			}
			if len(leaks) == 0 {
				continue
			}

			severity := githubLeakSeverity(leaks)
			title := fmt.Sprintf("Github确认敏感信息泄露: %s", keyword)
			description := fmt.Sprintf("Repository: %s\nFile: %s\nURL: %s\nEvidence: %s",
				item.Repository.FullName, item.Path, item.HTMLURL, GithubLeakSummary(leaks))

			vuln := &models.Vulnerability{
				TaskID:      ctx.Task.ID,
				URL:         item.HTMLURL,
				Type:        "github_leak",
				Severity:    severity,
				Title:       title,
				Description: description,
				Reference:   item.Repository.HTMLURL,
				Solution:    "检查Github仓库中的敏感信息泄露，及时删除或修改凭据",
			}
			ctx.DB.Create(vuln)
		}
	}

	return nil
}

func githubLeakSeverity(leaks map[string][]string) string {
	if len(leaks["private_key"]) > 0 || len(leaks["aws_secret_key"]) > 0 {
		return "critical"
	}
	if len(leaks["aws_access_key"]) > 0 || len(leaks["jwt_token"]) > 0 || len(leaks["api_key"]) > 0 {
		return "high"
	}
	return "medium"
}

// GetFileContent 获取文件内容
func (gm *GithubMonitor) GetFileContent(repo, path, ref string) (string, error) {
	base, err := url.Parse(strings.TrimRight(gm.baseURL, "/"))
	if err != nil {
		return "", err
	}
	rawPathParts := []string{"repos"}
	escapedPathParts := []string{"repos"}
	for _, part := range strings.Split(repo, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("invalid GitHub repository path")
		}
		rawPathParts = append(rawPathParts, part)
		escapedPathParts = append(escapedPathParts, url.PathEscape(part))
	}
	rawPathParts = append(rawPathParts, "contents")
	escapedPathParts = append(escapedPathParts, "contents")
	for _, part := range strings.Split(strings.Trim(path, "/"), "/") {
		if part == ".." {
			return "", fmt.Errorf("invalid GitHub file path")
		}
		if part != "" && part != "." {
			rawPathParts = append(rawPathParts, part)
			escapedPathParts = append(escapedPathParts, url.PathEscape(part))
		}
	}
	basePathPrefix := strings.TrimRight(base.Path, "/")
	base.Path = basePathPrefix + "/" + strings.Join(rawPathParts, "/")
	base.RawPath = basePathPrefix + "/" + strings.Join(escapedPathParts, "/")
	query := base.Query()
	if strings.TrimSpace(ref) != "" {
		query.Set("ref", ref)
	}
	base.RawQuery = query.Encode()

	req, err := http.NewRequest("GET", base.String(), nil)
	if err != nil {
		return "", err
	}

	if gm.token != "" {
		req.Header.Set("Authorization", "Bearer "+gm.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3.raw")
	req.Header.Set("User-Agent", "Eclipse-Recon")

	resp, err := gm.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20+1))
	if err != nil {
		return "", err
	}
	if len(body) > 5<<20 {
		return "", fmt.Errorf("GitHub file exceeds 5 MiB inspection limit")
	}

	return string(body), nil
}

// InspectSearchItem downloads a public search result and extracts only a
// redacted category/count summary. Raw credentials are never persisted.
func (gm *GithubMonitor) InspectSearchItem(item GithubSearchItem) (map[string][]string, error) {
	if strings.TrimSpace(item.Repository.FullName) == "" || strings.TrimSpace(item.Path) == "" {
		return nil, fmt.Errorf("GitHub search item is missing repository or path")
	}
	content, err := gm.GetFileContent(item.Repository.FullName, item.Path, "")
	if err != nil {
		return nil, err
	}
	return gm.CheckLeakedCredentials(content), nil
}

func (gm *GithubMonitor) InspectSearchItems(items []GithubSearchItem, concurrency int) []GithubInspectedItem {
	if len(items) == 0 {
		return nil
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > len(items) {
		concurrency = len(items)
	}
	jobs := make(chan GithubSearchItem)
	results := make(chan GithubInspectedItem, len(items))
	var workers sync.WaitGroup
	workers.Add(concurrency)
	for index := 0; index < concurrency; index++ {
		go func() {
			defer workers.Done()
			for item := range jobs {
				leaks, err := gm.InspectSearchItem(item)
				results <- GithubInspectedItem{Item: item, Leaks: leaks, Err: err}
			}
		}()
	}
	go func() {
		for _, item := range items {
			jobs <- item
		}
		close(jobs)
		workers.Wait()
		close(results)
	}()
	inspected := make([]GithubInspectedItem, 0, len(items))
	for result := range results {
		inspected = append(inspected, result)
	}
	sort.Slice(inspected, func(i, j int) bool {
		left, right := inspected[i].Item, inspected[j].Item
		leftKey := left.Repository.FullName + "\x00" + left.Path + "\x00" + left.HTMLURL
		rightKey := right.Repository.FullName + "\x00" + right.Path + "\x00" + right.HTMLURL
		return leftKey < rightKey
	})
	return inspected
}

// GithubLeakSummary returns a deterministic redacted result safe for storage.
func GithubLeakSummary(leaks map[string][]string) string {
	if len(leaks) == 0 {
		return "content_checked:no_confirmed_credentials"
	}
	keys := make([]string, 0, len(leaks))
	for key := range leaks {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", key, len(leaks[key])))
	}
	return "confirmed:" + strings.Join(parts, ",")
}

func GithubLeakSeverity(leaks map[string][]string) string {
	return githubLeakSeverity(leaks)
}

// CheckLeakedCredentials 检查泄露的凭据
func (gm *GithubMonitor) CheckLeakedCredentials(content string) map[string][]string {
	leaks := make(map[string][]string)

	// AWS Access Key
	if keys := extractPattern(content, `\bAKIA[0-9A-Z]{16}\b`); len(keys) > 0 {
		leaks["aws_access_key"] = keys
	}

	// AWS Secret Key requires an assignment label to avoid treating arbitrary
	// 40-character hashes as credentials.
	if keys := extractCapturedPattern(content, `(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[:=]\s*["']?([0-9a-zA-Z/+]{40})`); len(keys) > 0 {
		leaks["aws_secret_key"] = keys
	}

	// Generic credentials also require a credential-like assignment label.
	if keys := extractCapturedPattern(content, `(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|secret[_-]?key|auth[_-]?token|token)\s*[:=]\s*["']?([a-zA-Z0-9_./+=-]{20,})`); len(keys) > 0 {
		leaks["api_key"] = keys
	}

	// JWT Token
	if keys := extractPattern(content, `\beyJ[a-zA-Z0-9_-]{4,}\.eyJ[a-zA-Z0-9_-]{4,}\.[a-zA-Z0-9_-]{4,}\b`); len(keys) > 0 {
		leaks["jwt_token"] = keys
	}

	// 私钥
	if strings.Contains(content, "BEGIN RSA PRIVATE KEY") ||
		strings.Contains(content, "BEGIN PRIVATE KEY") ||
		strings.Contains(content, "BEGIN EC PRIVATE KEY") ||
		strings.Contains(content, "BEGIN OPENSSH PRIVATE KEY") {
		leaks["private_key"] = []string{"Found private key"}
	}

	return leaks
}

func extractCapturedPattern(content, pattern string) []string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	matches := re.FindAllStringSubmatch(content, -1)
	results := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		if len(match) < 2 || match[1] == "" {
			continue
		}
		if _, exists := seen[match[1]]; exists {
			continue
		}
		seen[match[1]] = struct{}{}
		results = append(results, match[1])
	}
	return results
}

// extractPattern 提取模式匹配
func extractPattern(content, pattern string) []string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	matches := re.FindAllString(content, -1)
	if len(matches) == 0 {
		return nil
	}
	results := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		if _, exists := seen[match]; exists {
			continue
		}
		seen[match] = struct{}{}
		results = append(results, match)
	}
	return results
}
