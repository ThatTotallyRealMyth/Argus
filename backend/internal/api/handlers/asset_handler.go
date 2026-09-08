package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/services"
)

// AssetHandler Asset processor
type AssetHandler struct{}

// NewAssetHandler Create an asset processor
func NewAssetHandler() *AssetHandler {
	return &AssetHandler{}
}

// ListDomains List domain names assets
func (h *AssetHandler) ListDomains(c *gin.Context) {
	taskID := c.Query("task_id")
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "50")
	search := c.Query("search")

	var pageInt, pageSizeInt int
	fmt.Sscanf(page, "%d", &pageInt)
	fmt.Sscanf(pageSize, "%d", &pageSizeInt)
	if pageInt < 1 {
		pageInt = 1
	}
	if pageSizeInt < 1 {
		pageSizeInt = 50
	}
	if pageSizeInt > 200 {
		pageSizeInt = 200
	}

	query := database.DB.Model(&models.Domain{})

	if taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}

	if search != "" {
		query = query.Where("domain LIKE ?", "%"+search+"%")
	}
	var ok bool
	query, ok = applyAdvancedSearch(c, query,
		map[string]string{"domain": "domain", "ip": "ip_address", "source": "source", "takeover": "takeover_service"},
		[]string{"domain", "ip_address", "source", "takeover_service"})
	if !ok {
		return
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count domains"})
		return
	}

	var domains []models.Domain
	offset := (pageInt - 1) * pageSizeInt
	if err := query.Order("created_at DESC").
		Limit(pageSizeInt).
		Offset(offset).
		Find(&domains).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch domains"})
		return
	}

	totalPages := int((total + int64(pageSizeInt) - 1) / int64(pageSizeInt))

	c.JSON(http.StatusOK, gin.H{
		"domains":     domains,
		"total":       total,
		"page":        pageInt,
		"page_size":   pageSizeInt,
		"total_pages": totalPages,
	})
}

// ListIPs ListIPAssets
func (h *AssetHandler) ListIPs(c *gin.Context) {
	taskID := c.Query("task_id")
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "50")

	var pageInt, pageSizeInt int
	fmt.Sscanf(page, "%d", &pageInt)
	fmt.Sscanf(pageSize, "%d", &pageSizeInt)
	if pageInt < 1 {
		pageInt = 1
	}
	if pageSizeInt < 1 {
		pageSizeInt = 50
	}
	if pageSizeInt > 200 {
		pageSizeInt = 200
	}

	query := database.DB.Model(&models.IP{})

	if taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}
	var ok bool
	query, ok = applyAdvancedSearch(c, query,
		map[string]string{"ip": "ip_address", "domain": "domain", "source": "source", "os": "os", "location": "location"},
		[]string{"ip_address", "domain", "source", "os", "location"})
	if !ok {
		return
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count IPs"})
		return
	}

	var ips []models.IP
	offset := (pageInt - 1) * pageSizeInt
	if err := query.Order("created_at DESC").
		Limit(pageSizeInt).
		Offset(offset).
		Find(&ips).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch IPs"})
		return
	}

	totalPages := int((total + int64(pageSizeInt) - 1) / int64(pageSizeInt))

	c.JSON(http.StatusOK, gin.H{
		"ips":         ips,
		"total":       total,
		"page":        pageInt,
		"page_size":   pageSizeInt,
		"total_pages": totalPages,
	})
}

// ListPorts List Port Assets
func (h *AssetHandler) ListPorts(c *gin.Context) {
	taskID := c.Query("task_id")
	ipAddress := c.Query("ip")
	portStr := c.Query("port")
	service := c.Query("service")
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "50")

	var pageInt, pageSizeInt int
	fmt.Sscanf(page, "%d", &pageInt)
	fmt.Sscanf(pageSize, "%d", &pageSizeInt)
	if pageInt < 1 {
		pageInt = 1
	}
	if pageSizeInt < 1 {
		pageSizeInt = 50
	}
	if pageSizeInt > 200 {
		pageSizeInt = 200
	}
	// Limit maximum number of single pages, Preventing excessive data searches from causing performance problems
	const maxPageSize = 200
	if pageSizeInt > maxPageSize {
		pageSizeInt = maxPageSize
	}

	query := database.DB.Model(&models.Port{})

	if taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}

	if ipAddress != "" {
		query = query.Where("ip_address = ?", ipAddress)
	}

	// Support port number filter
	if portStr != "" {
		var portInt int
		if _, err := fmt.Sscanf(portStr, "%d", &portInt); err == nil && portInt > 0 && portInt <= 65535 {
			query = query.Where("port = ?", portInt)
		}
	}

	// Support services filter
	if service != "" {
		query = query.Where("service LIKE ?", "%"+service+"%")
	}
	var ok bool
	query, ok = applyAdvancedSearch(c, query,
		map[string]string{"ip": "ip_address", "port": "port", "protocol": "protocol", "service": "service", "version": "version", "banner": "banner"},
		[]string{"ip_address", "port", "protocol", "service", "version", "banner"})
	if !ok {
		return
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count ports"})
		return
	}

	var ports []models.Port
	offset := (pageInt - 1) * pageSizeInt
	if err := query.Order("port ASC").
		Limit(pageSizeInt).
		Offset(offset).
		Find(&ports).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch ports"})
		return
	}

	totalPages := int((total + int64(pageSizeInt) - 1) / int64(pageSizeInt))

	c.JSON(http.StatusOK, gin.H{
		"ports":       ports,
		"total":       total,
		"page":        pageInt,
		"page_size":   pageSizeInt,
		"total_pages": totalPages,
	})
}

// ListSites List site assets
func (h *AssetHandler) ListSites(c *gin.Context) {
	taskID := c.Query("task_id")
	url := c.Query("url")
	domain := c.Query("domain")
	ip := c.Query("ip")
	port := c.Query("port")
	statusCode := c.Query("status_code")
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "50")

	var pageInt, pageSizeInt int
	fmt.Sscanf(page, "%d", &pageInt)
	fmt.Sscanf(pageSize, "%d", &pageSizeInt)
	if pageInt < 1 {
		pageInt = 1
	}
	if pageSizeInt < 1 {
		pageSizeInt = 50
	}
	if pageSizeInt > 200 {
		pageSizeInt = 200
	}

	query := database.DB.Model(&models.Site{})

	if taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}

	// URL Filter
	if url != "" {
		query = query.Where("url LIKE ?", "%"+url+"%")
	}

	// Domain Name Filter
	if domain != "" {
		query = query.Where("url LIKE ?", "%"+domain+"%")
	}

	// IP Filter
	if ip != "" {
		query = query.Where("ip = ? OR url LIKE ?", ip, "%"+ip+"%")
	}

	// Port Filter
	if port != "" {
		query = query.Where("url LIKE ?", "%:"+port+"%")
	}

	// Status Code Filter
	if statusCode != "" {
		var statusInt int
		if _, err := fmt.Sscanf(statusCode, "%d", &statusInt); err == nil {
			query = query.Where("status_code = ?", statusInt)
		}
	}
	var ok bool
	query, ok = applyAdvancedSearch(c, query,
		map[string]string{"url": "url", "title": "title", "status": "status_code", "ip": "ip", "type": "content_type", "server": "server", "fingerprint": "fingerprint"},
		[]string{"url", "title", "status_code", "ip", "content_type", "server", "fingerprint"})
	if !ok {
		return
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count sites"})
		return
	}

	var sites []models.Site
	offset := (pageInt - 1) * pageSizeInt
	if err := query.Order("created_at DESC").
		Limit(pageSizeInt).
		Offset(offset).
		Find(&sites).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch sites"})
		return
	}

	totalPages := int((total + int64(pageSizeInt) - 1) / int64(pageSizeInt))

	c.JSON(http.StatusOK, gin.H{
		"sites":       sites,
		"total":       total,
		"page":        pageInt,
		"page_size":   pageSizeInt,
		"total_pages": totalPages,
	})
}

// ListVulnerabilities Listing leak information
func (h *AssetHandler) ListVulnerabilities(c *gin.Context) {
	taskID := c.Query("task_id")
	severity := c.Query("severity")
	status := strings.ToLower(strings.TrimSpace(c.Query("status")))
	page, pageSize := parsePagination(c, 20, 100)

	query := database.DB.Model(&models.Vulnerability{})

	if taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}

	if severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if status != "" && status != "all" {
		if !services.ValidVulnerabilityStatus(status) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid vulnerability status"})
			return
		}
		query = query.Where("status = ?", status)
	}
	var ok bool
	query, ok = applyAdvancedSearch(c, query,
		map[string]string{"severity": "severity", "status": "status", "title": "title", "url": "url", "type": "type", "source": "source", "description": "description"},
		[]string{"severity", "status", "title", "url", "type", "source", "description", "triage_note"})
	if !ok {
		return
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count vulnerabilities"})
		return
	}

	var vulns []models.Vulnerability
	offset := (page - 1) * pageSize
	if err := query.Order("created_at DESC").Limit(pageSize).Offset(offset).Find(&vulns).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch vulnerabilities"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"vulnerabilities": vulns,
		"total":           total,
		"page":            page,
		"page_size":       pageSize,
		"total_pages":     int((total + int64(pageSize) - 1) / int64(pageSize)),
	})
}

func parsePagination(c *gin.Context, defaultSize, maxSize int) (int, int) {
	page := 1
	pageSize := defaultSize
	if value, err := strconv.Atoi(c.Query("page")); err == nil && value > 0 {
		page = value
	}
	if value, err := strconv.Atoi(c.Query("page_size")); err == nil && value > 0 {
		pageSize = value
	}
	if pageSize > maxSize {
		pageSize = maxSize
	}
	return page, pageSize
}

// GetAssetStats Access to asset statistics
func (h *AssetHandler) GetAssetStats(c *gin.Context) {
	taskID := c.Query("task_id")

	var stats struct {
		Domains          int64 `json:"domains"`
		IPs              int64 `json:"ips"`
		Ports            int64 `json:"ports"`
		Sites            int64 `json:"sites"`
		URLs             int64 `json:"urls"`
		HTTPTransactions int64 `json:"http_transactions"`
		Vulnerabilities  int64 `json:"vulnerabilities"`
		ActiveFindings   int64 `json:"active_vulnerabilities"`
	}

	filter := ""
	args := make([]any, 0, 1)
	if taskID != "" {
		filter = " WHERE task_id = ?"
		args = append(args, taskID)
	}
	query := fmt.Sprintf(`
		SELECT 'domains' AS kind, COUNT(*) AS count FROM domains%s
		UNION ALL SELECT 'ips', COUNT(*) FROM ips%s
		UNION ALL SELECT 'ports', COUNT(*) FROM ports%s
		UNION ALL SELECT 'sites', COUNT(*) FROM sites%s
		UNION ALL SELECT 'urls', COUNT(*) FROM crawler_results%s
		UNION ALL SELECT 'http_transactions', COUNT(*) FROM http_transactions%s
		UNION ALL SELECT 'vulnerabilities', COUNT(*) FROM vulnerabilities%s
		UNION ALL SELECT 'active_vulnerabilities', COUNT(*) FROM vulnerabilities%s`, filter, filter, filter, filter, filter, filter, filter, filter)
	if taskID == "" {
		query += " WHERE status NOT IN ('resolved', 'false_positive')"
	} else {
		query += " AND status NOT IN ('resolved', 'false_positive')"
	}
	// PostgreSQL reuses the same placeholder position only when the argument is
	// repeated, so build the argument list once per filtered table.
	if taskID != "" {
		args = []any{taskID, taskID, taskID, taskID, taskID, taskID, taskID, taskID}
	}
	var rows []struct {
		Kind  string
		Count int64
	}
	if err := database.DB.Raw(query, args...).Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to calculate asset statistics"})
		return
	}
	for _, row := range rows {
		switch row.Kind {
		case "domains":
			stats.Domains = row.Count
		case "ips":
			stats.IPs = row.Count
		case "ports":
			stats.Ports = row.Count
		case "sites":
			stats.Sites = row.Count
		case "urls":
			stats.URLs = row.Count
		case "http_transactions":
			stats.HTTPTransactions = row.Count
		case "vulnerabilities":
			stats.Vulnerabilities = row.Count
		case "active_vulnerabilities":
			stats.ActiveFindings = row.Count
		}
	}

	c.JSON(http.StatusOK, stats)
}

// ListURLs FetchURLList
func (h *AssetHandler) ListURLs(c *gin.Context) {
	taskID := c.Query("task_id")
	url := c.Query("url")
	source := c.Query("source")
	statusCode := c.Query("status_code")
	contentType := c.Query("content_type")
	minLength := c.Query("min_length")
	maxLength := c.Query("max_length")
	sortBy := c.DefaultQuery("sort_by", "created_at")
	sortOrder := strings.ToLower(c.DefaultQuery("sort_order", "desc"))

	page := 1
	pageSize := 20

	if p := c.Query("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	if ps := c.Query("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	var urls []models.CrawlerResult
	query := database.DB.Model(&models.CrawlerResult{})

	// Filter Conditions
	if taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}
	if url != "" {
		query = query.Where("url LIKE ?", "%"+url+"%")
	}
	if source != "" {
		query = query.Where("source = ?", source)
	}
	if statusCode != "" {
		if code, err := strconv.Atoi(statusCode); err == nil {
			query = query.Where("status_code = ?", code)
		}
	}
	if contentType != "" {
		query = query.Where("content_type LIKE ?", "%"+contentType+"%")
	}
	if value, err := strconv.ParseInt(minLength, 10, 64); err == nil && value >= 0 {
		query = query.Where("content_length >= ?", value)
	}
	if value, err := strconv.ParseInt(maxLength, 10, 64); err == nil && value >= 0 {
		query = query.Where("content_length <= ?", value)
	}
	var ok bool
	query, ok = applyAdvancedSearch(c, query,
		map[string]string{"url": "url", "method": "method", "status": "status_code", "type": "content_type", "source": "source"},
		[]string{"url", "method", "status_code", "content_type", "source"})
	if !ok {
		return
	}

	// Calculate total
	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count URLs"})
		return
	}

	// Page Break Query
	offset := (page - 1) * pageSize
	allowedSort := map[string]bool{"created_at": true, "url": true, "status_code": true, "content_length": true, "response_time_ms": true}
	if !allowedSort[sortBy] {
		sortBy = "created_at"
	}
	if sortOrder != "asc" {
		sortOrder = "desc"
	}
	if err := query.Order(sortBy + " " + sortOrder).Limit(pageSize).Offset(offset).Find(&urls).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch URLs"})
		return
	}

	// Calculate total number of pages
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	c.JSON(http.StatusOK, gin.H{
		"urls":        urls,
		"total":       total,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": totalPages,
	})
}

// ListHTTPTransactions returns captured HTTP exchanges without body fields.
func (h *AssetHandler) ListHTTPTransactions(c *gin.Context) {
	taskID := c.Query("task_id")
	urlValue := c.Query("url")
	source := c.Query("source")
	statusCode := c.Query("status_code")
	contentType := c.Query("content_type")
	bodySearch := c.Query("body_search")
	bodyStored := c.Query("body_stored")
	bodyTruncated := c.Query("body_truncated")
	minLength := c.Query("min_length")
	maxLength := c.Query("max_length")
	sortBy := c.DefaultQuery("sort_by", "created_at")
	sortOrder := strings.ToLower(c.DefaultQuery("sort_order", "desc"))
	page, pageSize := parsePagination(c, 20, 100)

	query := database.DB.Model(&models.HTTPTransaction{})

	if taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}
	if urlValue != "" {
		query = query.Where("url LIKE ?", "%"+urlValue+"%")
	}
	if source != "" {
		query = query.Where("source = ?", source)
	}
	if code, err := strconv.Atoi(statusCode); err == nil {
		query = query.Where("response_status_code = ?", code)
	}
	if contentType != "" {
		query = query.Where("response_content_type LIKE ?", "%"+contentType+"%")
	}
	if bodySearch != "" {
		query = query.Where("response_body LIKE ?", "%"+bodySearch+"%")
	}
	if stored, ok := parseBoolQuery(bodyStored); ok {
		query = query.Where("response_body_stored = ?", stored)
	}
	if truncated, ok := parseBoolQuery(bodyTruncated); ok {
		query = query.Where("response_body_truncated = ?", truncated)
	}
	if value, err := strconv.ParseInt(minLength, 10, 64); err == nil && value >= 0 {
		query = query.Where("response_content_length >= ?", value)
	}
	if value, err := strconv.ParseInt(maxLength, 10, 64); err == nil && value >= 0 {
		query = query.Where("response_content_length <= ?", value)
	}
	var ok bool
	query, ok = applyAdvancedSearch(c, query,
		map[string]string{"url": "url", "method": "method", "status": "response_status_code", "type": "response_content_type", "source": "source", "body": "response_body", "request": "request_body"},
		[]string{"url", "method", "response_status_code", "response_content_type", "source", "response_body", "request_body"})
	if !ok {
		return
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count HTTP transactions"})
		return
	}

	allowedSort := map[string]bool{"created_at": true, "url": true, "response_status_code": true, "response_content_length": true, "response_time_ms": true}
	if !allowedSort[sortBy] {
		sortBy = "created_at"
	}
	if sortOrder != "asc" {
		sortOrder = "desc"
	}

	var items []models.HTTPTransaction
	if err := query.Select("id", "task_id", "crawler_result_id", "url", "method", "source", "response_status_code", "response_content_type", "response_content_length", "response_body_stored", "response_body_truncated", "response_body_sha256", "response_time_ms", "created_at").
		Order(sortBy + " " + sortOrder).
		Limit(pageSize).
		Offset((page - 1) * pageSize).
		Find(&items).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch HTTP transactions"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"items":       items,
		"total":       total,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": int((total + int64(pageSize) - 1) / int64(pageSize)),
	})
}

// GetHTTPTransaction returns one captured HTTP exchange including stored bodies.
func (h *AssetHandler) GetHTTPTransaction(c *gin.Context) {
	var item models.HTTPTransaction
	if err := database.DB.First(&item, "id = ?", c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "HTTP transaction not found"})
		return
	}
	c.JSON(http.StatusOK, item)
}

func parseBoolQuery(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes":
		return true, true
	case "false", "0", "no":
		return false, true
	default:
		return false, false
	}
}
