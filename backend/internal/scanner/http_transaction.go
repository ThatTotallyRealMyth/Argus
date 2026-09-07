package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

const maxStoredHTTPBodyBytes = 10 << 20
const maxCrawlerCaptureBytes = 2 << 20

func headerJSON(header http.Header) string {
	values := make(map[string][]string, len(header))
	for key, value := range header {
		copied := make([]string, len(value))
		copy(copied, value)
		values[key] = copied
	}
	data, err := json.Marshal(values)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func shouldStoreHTTPBody(contentType string) bool {
	contentType = strings.ToLower(contentType)
	if contentType == "" {
		return true
	}
	textual := []string{
		"text/",
		"application/json",
		"application/xml",
		"application/javascript",
		"application/x-javascript",
		"application/xhtml+xml",
		"application/x-www-form-urlencoded",
		"application/graphql",
	}
	for _, prefix := range textual {
		if strings.HasPrefix(contentType, prefix) {
			return true
		}
	}
	return strings.Contains(contentType, "+json") || strings.Contains(contentType, "+xml")
}

func bodySHA256(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func readHTTPBody(resp *http.Response, limit int64) ([]byte, bool, error) {
	if limit <= 0 {
		limit = maxCrawlerCaptureBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, false, err
	}
	truncated := int64(len(body)) > limit
	if truncated {
		body = body[:limit]
	}
	return body, truncated, nil
}

func saveHTTPTransaction(ctx *ScanContext, request *http.Request, response *http.Response, crawlerResultID string, body []byte, truncated bool, startedAt time.Time) error {
	if ctx == nil || ctx.Task == nil || ctx.DB == nil || request == nil || response == nil {
		return fmt.Errorf("scan context, task, database, request, and response are required")
	}
	contentLength := response.ContentLength
	if contentLength < 0 {
		contentLength = int64(len(body))
		if truncated {
			contentLength++
		}
	}
	transaction := &models.HTTPTransaction{
		TaskID:                ctx.Task.ID,
		CrawlerResultID:       crawlerResultID,
		URL:                   request.URL.String(),
		Method:                request.Method,
		Source:                "crawler",
		RequestHeaders:        headerJSON(request.Header),
		ResponseStatusCode:    response.StatusCode,
		ResponseHeaders:       headerJSON(response.Header),
		ResponseContentType:   response.Header.Get("Content-Type"),
		ResponseContentLength: contentLength,
		ResponseTimeMs:        time.Since(startedAt).Milliseconds(),
		ResponseBodySHA256:    bodySHA256(body),
		ResponseBodyTruncated: truncated,
	}
	if shouldStoreHTTPBody(response.Header.Get("Content-Type")) {
		transaction.ResponseBody = string(body)
		transaction.ResponseBodyStored = true
	}
	db := ctx.DB
	if ctx.Ctx != nil {
		db = db.WithContext(ctx.Ctx)
	}
	if err := db.Create(transaction).Error; err != nil {
		return fmt.Errorf("save HTTP transaction: %w", err)
	}
	return nil
}
