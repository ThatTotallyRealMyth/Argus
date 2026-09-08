package scanner

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/reconmaster/backend/internal/models"
	"gorm.io/gorm"
)

const (
	maxFileLeakDictionaryEntries = 200000
	maxFileLeakProbeBytes        = 10 << 20
)

type fileLeakPath struct {
	Path     string
	Severity string
	Title    string
	Known    bool
}

type fileLeakProbeResult struct {
	StatusCode     int
	ContentType    string
	ContentLength  int64
	ResponseTime   time.Duration
	Truncated      bool
	BodyStored     bool
	Body           []byte
	BodySHA256     string
	RequestHeader  string
	ResponseHeader string
}

// CheckFileLeaks probes paths from the selected/default file_leak dictionary.
func (ss *SiteScanner) CheckFileLeaks(ctx *ScanContext) error {
	ss.client.CheckRedirect = scopedRedirectPolicy(ctx.ValidateTarget)
	var sites []models.Site
	if err := ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&sites).Error; err != nil {
		return err
	}
	if len(sites) == 0 {
		return nil
	}

	paths, source, err := ss.loadFileLeakPaths(ctx)
	if err != nil {
		return err
	}
	config := LoadScannerConfig(ctx)
	ctx.Logger.Printf("Checking %d paths on %d sites using %s (concurrency=%d, rate_limit=%d req/s)", len(paths), len(sites), source, config.FileLeakConcurrency, config.FileLeakRateLimit)

	type probeJob struct {
		site models.Site
		path fileLeakPath
	}
	jobs := make(chan probeJob)
	var wg sync.WaitGroup
	var throttle <-chan time.Time
	var throttleTicker *time.Ticker
	if config.FileLeakRateLimit > 0 {
		throttleTicker = time.NewTicker(time.Second / time.Duration(config.FileLeakRateLimit))
		defer throttleTicker.Stop()
		throttle = throttleTicker.C
	}
	for i := 0; i < config.FileLeakConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if throttle != nil {
					select {
					case <-ctx.Ctx.Done():
						return
					case <-throttle:
					}
				}
				select {
				case <-ctx.Ctx.Done():
					return
				default:
					ss.probeFileLeakPath(ctx, job.site, job.path)
				}
			}
		}()
	}

	cancelled := false
	for _, site := range sites {
		for _, path := range paths {
			select {
			case <-ctx.Ctx.Done():
				cancelled = true
			case jobs <- probeJob{site: site, path: path}:
			}
			if cancelled {
				break
			}
		}
		if cancelled {
			break
		}
	}
	close(jobs)
	wg.Wait()
	if cancelled {
		return ctx.Ctx.Err()
	}
	return nil
}

func (ss *SiteScanner) probeFileLeakPath(ctx *ScanContext, site models.Site, path fileLeakPath) {
	targetURL := strings.TrimRight(site.URL, "/") + path.Path
	result, err := ss.probeFileLeakURL(ctx, targetURL)
	if err != nil {
		return
	}

	record := &models.CrawlerResult{
		TaskID:         ctx.Task.ID,
		URL:            targetURL,
		Method:         http.MethodGet,
		StatusCode:     result.StatusCode,
		ContentType:    result.ContentType,
		ContentLength:  result.ContentLength,
		ResponseTimeMs: result.ResponseTime.Milliseconds(),
		Source:         "file_leak",
	}
	ctx.DB.Where("task_id = ? AND url = ? AND source = ?", record.TaskID, record.URL, record.Source).FirstOrCreate(record)
	transaction := &models.HTTPTransaction{
		TaskID:                ctx.Task.ID,
		CrawlerResultID:       record.ID,
		URL:                   targetURL,
		Method:                http.MethodGet,
		Source:                "file_leak",
		RequestHeaders:        result.RequestHeader,
		ResponseStatusCode:    result.StatusCode,
		ResponseHeaders:       result.ResponseHeader,
		ResponseContentType:   result.ContentType,
		ResponseContentLength: result.ContentLength,
		ResponseTimeMs:        result.ResponseTime.Milliseconds(),
		ResponseBodyStored:    result.BodyStored,
		ResponseBodyTruncated: result.Truncated,
		ResponseBodySHA256:    result.BodySHA256,
	}
	if result.BodyStored {
		transaction.ResponseBody = string(result.Body)
	}
	var existing models.HTTPTransaction
	err = ctx.DB.Where("task_id = ? AND url = ? AND method = ? AND source = ?", transaction.TaskID, transaction.URL, transaction.Method, transaction.Source).
		First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		ctx.DB.Create(transaction)
	} else if err == nil {
		ctx.DB.Model(&existing).Updates(map[string]any{
			"crawler_result_id":       transaction.CrawlerResultID,
			"request_headers":         transaction.RequestHeaders,
			"request_body":            transaction.RequestBody,
			"request_body_truncated":  transaction.RequestBodyTruncated,
			"response_status_code":    transaction.ResponseStatusCode,
			"response_headers":        transaction.ResponseHeaders,
			"response_content_type":   transaction.ResponseContentType,
			"response_content_length": transaction.ResponseContentLength,
			"response_body":           transaction.ResponseBody,
			"response_body_stored":    transaction.ResponseBodyStored,
			"response_body_truncated": transaction.ResponseBodyTruncated,
			"response_body_sha256":    transaction.ResponseBodySHA256,
			"response_time_ms":        transaction.ResponseTimeMs,
		})
	}

	// Custom dictionary paths are discovery results. Known built-in paths retain
	// the existing vulnerability output until response-content rules are added.
	if !path.Known || result.StatusCode != http.StatusOK || result.ContentLength == 0 {
		return
	}
	description := fmt.Sprintf("Discover sensitive files: %s (Size: %d bytes, Type: %s)", targetURL, result.ContentLength, result.ContentType)
	if result.Truncated {
		description += ", Response exceeds the maximum detection reading limit"
	}
	vulnerability := &models.Vulnerability{
		TaskID:      ctx.Task.ID,
		URL:         targetURL,
		Type:        "file_leak",
		Severity:    path.Severity,
		Title:       path.Title,
		Description: description,
		Solution:    "Delete or limit access to sensitive documents",
	}
	ctx.DB.Where("task_id = ? AND url = ? AND type = ?", vulnerability.TaskID, vulnerability.URL, vulnerability.Type).FirstOrCreate(vulnerability)
}

func (ss *SiteScanner) loadFileLeakPaths(ctx *ScanContext) ([]fileLeakPath, string, error) {
	query := ctx.DB.Where("type = ?", "file_leak")
	var dictionary models.Dictionary
	if name := strings.TrimSpace(ctx.Task.Options.FileLeakDict); name != "" {
		if err := query.Where("name = ?", name).First(&dictionary).Error; err != nil {
			return nil, "", fmt.Errorf("file leak dictionary %q: %w", name, err)
		}
	} else {
		err := query.Where("is_default = ?", true).Order("created_at DESC").First(&dictionary).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return defaultFileLeakPaths(), "built-in dictionary", nil
		}
		if err != nil {
			return nil, "", err
		}
	}

	file, err := os.Open(dictionary.FilePath)
	if err != nil {
		return nil, "", fmt.Errorf("open file leak dictionary: %w", err)
	}
	defer file.Close()
	paths, err := parseFileLeakDictionary(file)
	if err != nil {
		return nil, "", err
	}
	return paths, "dictionary " + dictionary.Name, nil
}

func parseFileLeakDictionary(reader io.Reader) ([]fileLeakPath, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	seen := make(map[string]bool)
	paths := make([]fileLeakPath, 0)
	for scanner.Scan() {
		value := strings.TrimSpace(scanner.Text())
		if value == "" || strings.HasPrefix(value, "#") || strings.HasPrefix(value, "//") {
			continue
		}
		if strings.ContainsAny(value, "\r\n") || strings.Contains(value, "://") {
			return nil, fmt.Errorf("invalid dictionary path: %q", value)
		}
		if !strings.HasPrefix(value, "/") {
			value = "/" + value
		}
		if !seen[value] {
			seen[value] = true
			paths = append(paths, fileLeakPath{Path: value})
			if len(paths) > maxFileLeakDictionaryEntries {
				return nil, fmt.Errorf("file leak dictionary exceeds %d entries", maxFileLeakDictionaryEntries)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("file leak dictionary is empty")
	}
	return paths, nil
}

// ValidateFileLeakDictionary validates the exact format consumed by the scanner.
func ValidateFileLeakDictionary(reader io.Reader) (int, error) {
	paths, err := parseFileLeakDictionary(reader)
	if err != nil {
		return 0, err
	}
	return len(paths), nil
}

func (ss *SiteScanner) probeFileLeakURL(ctx *ScanContext, targetURL string) (fileLeakProbeResult, error) {
	var result fileLeakProbeResult
	if err := ctx.ValidateNetworkTarget(targetURL); err != nil {
		return result, err
	}
	req, err := http.NewRequestWithContext(ctx.Ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return result, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	result.RequestHeader = headerJSON(req.Header)

	startedAt := time.Now()
	resp, err := ss.client.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()
	result.StatusCode = resp.StatusCode
	result.ContentType = resp.Header.Get("Content-Type")
	result.ContentLength = resp.ContentLength
	result.ResponseTime = time.Since(startedAt)
	result.ResponseHeader = headerJSON(resp.Header)
	result.Truncated = result.ContentLength > maxStoredHTTPBodyBytes

	limit := int64(maxStoredHTTPBodyBytes)
	if shouldStoreHTTPBody(result.ContentType) {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return result, readErr
		}
		result.Truncated = result.Truncated || readErr == io.ErrUnexpectedEOF || int64(len(body)) > limit
		if int64(len(body)) > limit {
			body = body[:limit]
		}
		result.Body = body
		result.BodyStored = true
		result.BodySHA256 = bodySHA256(body)
		if result.ContentLength < 0 {
			result.ContentLength = int64(len(body))
			if result.Truncated {
				result.ContentLength = limit + 1
			}
		}
		return result, nil
	}

	if result.ContentLength > limit {
		result.Truncated = true
	}
	if result.ContentLength < 0 {
		read, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, limit+1))
		if readErr != nil {
			return result, readErr
		}
		result.ContentLength = read
		result.Truncated = read > limit
	}
	return result, nil
}

func defaultFileLeakPaths() []fileLeakPath {
	return []fileLeakPath{
		{Path: "/.git/config", Severity: "high", Title: "GitProfile leak", Known: true},
		{Path: "/.git/HEAD", Severity: "high", Title: "GitRepository leak", Known: true},
		{Path: "/.env", Severity: "critical", Title: "Environmental variable file leak", Known: true},
		{Path: "/.env.local", Severity: "high", Title: "Local environment configuration leak", Known: true},
		{Path: "/.env.production", Severity: "high", Title: "Production environment configuration exposure", Known: true},
		{Path: "/web.config", Severity: "medium", Title: "IISProfile leak", Known: true},
		{Path: "/.DS_Store", Severity: "low", Title: "MacSystem File Disconnect", Known: true},
		{Path: "/backup.zip", Severity: "high", Title: "Backup File Disclosing", Known: true},
		{Path: "/backup.tar.gz", Severity: "high", Title: "Backup File Disclosing", Known: true},
		{Path: "/backup.sql", Severity: "critical", Title: "Database backup leak", Known: true},
		{Path: "/db.sql", Severity: "critical", Title: "Database File Disconnect", Known: true},
		{Path: "/database.sql", Severity: "critical", Title: "Database File Disconnect", Known: true},
		{Path: "/.svn/entries", Severity: "high", Title: "SVNInformation leaks", Known: true},
		{Path: "/phpinfo.php", Severity: "medium", Title: "PHPInformation leaks", Known: true},
		{Path: "/info.php", Severity: "medium", Title: "PHPInformation leaks", Known: true},
		{Path: "/test.php", Severity: "low", Title: "Test file leak", Known: true},
		{Path: "/config.php", Severity: "high", Title: "Profile leak", Known: true},
		{Path: "/config.json", Severity: "high", Title: "Profile leak", Known: true},
		{Path: "/config.yml", Severity: "high", Title: "Profile leak", Known: true},
		{Path: "/config.yaml", Severity: "high", Title: "Profile leak", Known: true},
		{Path: "/settings.py", Severity: "high", Title: "DjangoConfigure leaks", Known: true},
		{Path: "/application.properties", Severity: "high", Title: "SpringConfigure leaks", Known: true},
		{Path: "/application.yml", Severity: "high", Title: "SpringConfigure leaks", Known: true},
		{Path: "/.htaccess", Severity: "medium", Title: "ApacheConfigure leaks", Known: true},
		{Path: "/robots.txt", Severity: "info", Title: "RobotsDocumentation", Known: true},
		{Path: "/sitemap.xml", Severity: "info", Title: "Site Map", Known: true},
		{Path: "/README.md", Severity: "low", Title: "READMEFile leaks", Known: true},
		{Path: "/CHANGELOG.md", Severity: "low", Title: "Change log leak", Known: true},
	}
}
