package handlers

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/logger"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/scanner"
	"github.com/reconmaster/backend/internal/services"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

// PoCHandler PoCProcessor
type PoCHandler struct{}

// NewPoCHandler CreatePoCProcessor
func NewPoCHandler() *PoCHandler {
	return &PoCHandler{}
}

// CreatePoCRequest CreatePoCRequest (SupportYAML)
type CreatePoCRequest struct {
	Name             string `json:"name" yaml:"name" binding:"required"`
	Category         string `json:"category" yaml:"category" binding:"required"`
	Severity         string `json:"severity" yaml:"severity" binding:"required"`
	CVE              string `json:"cve" yaml:"cve"`
	Product          string `json:"product" yaml:"product"`
	AffectedVersions string `json:"affected_versions" yaml:"affected_versions"`
	Author           string `json:"author" yaml:"author"`
	Description      string `json:"description" yaml:"description"`
	Reference        string `json:"reference" yaml:"reference"`
	PoCType          string `json:"poc_type" yaml:"poc_type" binding:"required"`
	PoCContent       string `json:"poc_content" yaml:"poc_content" binding:"required"`
	Tags             string `json:"tags" yaml:"tags"`
	Fingerprints     string `json:"fingerprints" yaml:"fingerprints"`
	AppNames         string `json:"app_names" yaml:"app_names"`
	MatchMode        string `json:"match_mode" yaml:"match_mode"`
}

// ListPoCs List allPoC
func (h *PoCHandler) ListPoCs(c *gin.Context) {
	category := c.Query("category")
	severity := c.Query("severity")
	pocType := c.Query("poc_type")
	name := c.Query("name")
	cve := c.Query("cve")
	product := c.Query("product")
	tags := c.Query("tags")

	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "20")

	var pageInt, pageSizeInt int
	if _, err := fmt.Sscanf(page, "%d", &pageInt); err != nil || pageInt < 1 {
		pageInt = 1
	}
	if _, err := fmt.Sscanf(pageSize, "%d", &pageSizeInt); err != nil || pageSizeInt < 1 {
		pageSizeInt = 20
	}
	// Limit maximum number of single pages, Preventing excessive data searches from causing performance problems
	const maxPageSize = 100
	if pageSizeInt > maxPageSize {
		pageSizeInt = maxPageSize
	}

	query := database.DB.Model(&models.PoC{})

	if category != "" {
		query = query.Where("category = ?", category)
	}
	if severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if pocType != "" {
		query = query.Where("po_c_type = ?", pocType)
	}
	if name != "" {
		query = query.Where("name LIKE ?", "%"+name+"%")
	}
	if cve != "" {
		query = query.Where("cve LIKE ?", "%"+cve+"%")
	}
	if product != "" {
		query = query.Where("product LIKE ?", "%"+product+"%")
	}
	if tags != "" {
		query = query.Where("tags LIKE ?", "%"+tags+"%")
	}
	var ok bool
	query, ok = applyAdvancedSearch(c, query,
		map[string]string{"name": "name", "category": "category", "severity": "severity", "type": "po_c_type", "cve": "cve", "product": "product", "tags": "tags", "description": "description"},
		[]string{"name", "category", "severity", "po_c_type", "cve", "product", "tags", "description"})
	if !ok {
		return
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count PoCs"})
		return
	}

	var pocs []models.PoC
	offset := (pageInt - 1) * pageSizeInt
	if err := query.Order("created_at DESC").
		Limit(pageSizeInt).
		Offset(offset).
		Find(&pocs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch PoCs"})
		return
	}

	totalPages := int((total + int64(pageSizeInt) - 1) / int64(pageSizeInt))

	c.JSON(http.StatusOK, gin.H{
		"pocs":        pocs,
		"total":       total,
		"page":        pageInt,
		"page_size":   pageSizeInt,
		"total_pages": totalPages,
	})
}

// GetPoC Fetching individualPoC
func (h *PoCHandler) GetPoC(c *gin.Context) {
	id := c.Param("id")

	var poc models.PoC
	if err := database.DB.First(&poc, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "PoC not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get PoC"})
		return
	}

	c.JSON(http.StatusOK, poc)
}

// CreatePoC CreatePoC
func (h *PoCHandler) CreatePoC(c *gin.Context) {
	var req CreatePoCRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Authenticate Serious Level
	validSeverities := map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true, "info": true,
	}
	if !validSeverities[req.Severity] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid severity"})
		return
	}

	// AuthenticationPoCType
	validPoCTypes := map[string]bool{
		"nuclei": true, "custom": true,
	}
	if !validPoCTypes[req.PoCType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid poc_type"})
		return
	}
	if err := scanner.ValidatePoCContent(req.PoCType, req.PoCContent); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.GetString("user_id")

	poc := &models.PoC{
		Name:             req.Name,
		Category:         req.Category,
		Severity:         req.Severity,
		CVE:              req.CVE,
		Product:          req.Product,
		AffectedVersions: req.AffectedVersions,
		Author:           req.Author,
		Description:      req.Description,
		Reference:        req.Reference,
		PoCType:          req.PoCType,
		PoCContent:       req.PoCContent,
		Tags:             req.Tags,
		Fingerprints:     req.Fingerprints,
		AppNames:         req.AppNames,
		MatchMode:        req.MatchMode,
		IsEnabled:        true,
		CreatedBy:        userID,
	}

	if err := database.DB.Create(poc).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create PoC"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "PoC created successfully",
		"poc":     poc,
	})
}

// UpdatePoC UpdatePoC
func (h *PoCHandler) UpdatePoC(c *gin.Context) {
	id := c.Param("id")

	var poc models.PoC
	if err := database.DB.First(&poc, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "PoC not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get PoC"})
		return
	}

	var req CreatePoCRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Authenticate Serious Level
	validSeverities := map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true, "info": true,
	}
	if !validSeverities[req.Severity] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid severity"})
		return
	}

	// AuthenticationPoCType
	validPoCTypes := map[string]bool{
		"nuclei": true, "custom": true,
	}
	if !validPoCTypes[req.PoCType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid poc_type"})
		return
	}
	if err := scanner.ValidatePoCContent(req.PoCType, req.PoCContent); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update Fields
	poc.Name = req.Name
	poc.Category = req.Category
	poc.Severity = req.Severity
	poc.CVE = req.CVE
	poc.Product = req.Product
	poc.AffectedVersions = req.AffectedVersions
	poc.Author = req.Author
	poc.Description = req.Description
	poc.Reference = req.Reference
	poc.PoCType = req.PoCType
	poc.PoCContent = req.PoCContent
	poc.Tags = req.Tags
	poc.Fingerprints = req.Fingerprints
	poc.AppNames = req.AppNames
	poc.MatchMode = req.MatchMode

	if err := database.DB.Save(&poc).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update PoC"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "PoC updated successfully",
		"poc":     poc,
	})
}

// DeletePoC DeletePoC
func (h *PoCHandler) DeletePoC(c *gin.Context) {
	id := c.Param("id")

	if err := database.DB.Delete(&models.PoC{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete PoC"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "PoC deleted successfully"})
}

// TogglePoCStatus TogglePoCEnable Status
func (h *PoCHandler) TogglePoCStatus(c *gin.Context) {
	id := c.Param("id")

	var poc models.PoC
	if err := database.DB.First(&poc, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "PoC not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get PoC"})
		return
	}

	poc.IsEnabled = !poc.IsEnabled
	if err := database.DB.Save(&poc).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update PoC status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "PoC status updated successfully",
		"is_enabled": poc.IsEnabled,
	})
}

// BatchImportPoCs Batch ImportPoC (Support onlyYAMLFormat)
func (h *PoCHandler) BatchImportPoCs(c *gin.Context) {
	// Read raw data
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 10<<20)
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body: " + err.Error()})
		return
	}

	// Check whether to YAML Format
	contentType := c.GetHeader("Content-Type")
	isYAML := strings.Contains(contentType, "yaml") || strings.Contains(contentType, "yml")

	// If Content-Type Not clear, Try to judge by content
	if !isYAML && len(body) > 0 {
		bodyStr := strings.TrimSpace(string(body))
		// YAML Not usually. "[" or "{" Start
		if !strings.HasPrefix(bodyStr, "[") && !strings.HasPrefix(bodyStr, "{") {
			isYAML = true
		}
	}

	var pocs []CreatePoCRequest

	if !isYAML {
		// Not supported JSON Format
		c.JSON(http.StatusBadRequest, gin.H{"error": "Only YAML format is supported. JSON format is no longer supported."})
		return
	}

	fmt.Println("Detected YAML Format, Start parsing...")

	// First attempt to solve the number group format (Batch Import)
	if err := yaml.Unmarshal(body, &pocs); err != nil {
		fmt.Printf("Failed to attempt to parsing as array: %v, Try asNucleiTemplate Parsing...\n", err)

		// Try to parse into multiple documentsYAML (Use --- Separator)
		bodyStr := string(body)
		documents := strings.Split(bodyStr, "\n---\n")

		fmt.Printf("Detected %d One.YAMLDocument\n", len(documents))

		for i, doc := range documents {
			doc = strings.TrimSpace(doc)
			if doc == "" || doc == "---" {
				continue
			}

			fmt.Printf("Parsing %d Documents (Front100Character): %s...\n", i+1, doc[:min(100, len(doc))])

			// Try to parse asNucleiTemplate Format (Single Object)
			var nucleiTemplate map[string]interface{}
			if err := yaml.Unmarshal([]byte(doc), &nucleiTemplate); err != nil {
				fmt.Printf("⚠️ Document %d YAMLParsing error: %v\n", i+1, err)
				continue
			}

			// ConvertNucleiTemplate AsCreatePoCRequest
			poc, err := convertNucleiTemplate(nucleiTemplate)
			if err != nil {
				fmt.Printf("⚠️ Document %d NucleiTemplate conversion error: %v\n", i+1, err)
				continue
			}

			pocs = append(pocs, poc)
			fmt.Printf("✅ Document %d Parsing successful: Name=%s, Category=%s, Severity=%s\n", i+1, poc.Name, poc.Category, poc.Severity)
		}

		if len(pocs) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No valid PoC templates found in the uploaded file"})
			return
		}
	}

	fmt.Printf("Received %d Article PoC Data\n", len(pocs))

	// Limit the number of single imports, Prevent over-data from leading to time-consuming or over-spills in memory
	const maxBatchSize = 1000
	if len(pocs) > maxBatchSize {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   fmt.Sprintf("Too many PoCs in one batch. Maximum allowed: %d, received: %d", maxBatchSize, len(pocs)),
			"message": fmt.Sprintf("Please.PoCbatch upload, Most times per person %d Article", maxBatchSize),
		})
		return
	}

	userID := c.GetString("user_id")
	var created []models.PoC
	var failed int
	var skipped int
	var updated int

	for i, req := range pocs {
		fmt.Printf("Deal with the %d Article: Name=%s, Category=%s, Severity=%s\n",
			i+1, req.Name, req.Category, req.Severity)

		// Authentication of required fields
		if req.Name == "" || req.Category == "" || req.Severity == "" || req.PoCType == "" || req.PoCContent == "" {
			fmt.Printf("  -> ❌ Skip: Missing required fields (Name=%q, Category=%q, Severity=%q, PoCType=%q, ContentLen=%d)\n",
				req.Name, req.Category, req.Severity, req.PoCType, len(req.PoCContent))
			failed++
			continue
		}
		if err := scanner.ValidatePoCContent(req.PoCType, req.PoCContent); err != nil {
			fmt.Printf("  -> ❌ Skip: %v\n", err)
			failed++
			continue
		}

		poc := models.PoC{
			Name:             req.Name,
			Category:         req.Category,
			Severity:         req.Severity,
			CVE:              req.CVE,
			Product:          req.Product,
			AffectedVersions: req.AffectedVersions,
			Author:           req.Author,
			Description:      req.Description,
			Reference:        req.Reference,
			PoCType:          req.PoCType,
			PoCContent:       req.PoCContent,
			Tags:             req.Tags,
			Fingerprints:     req.Fingerprints,
			AppNames:         req.AppNames,
			MatchMode:        req.MatchMode,
			IsEnabled:        true,
			CreatedBy:        userID,
		}
		if poc.MatchMode == "" {
			poc.MatchMode = "fuzzy"
		}

		var existingPoC models.PoC
		err := database.DB.Where(
			"name = ? AND cve = ? AND product = ? AND affected_versions = ?",
			poc.Name, poc.CVE, poc.Product, poc.AffectedVersions,
		).First(&existingPoC).Error
		if err == nil {
			poc.ID = existingPoC.ID
			poc.CreatedAt = existingPoC.CreatedAt
			if err := database.DB.Save(&poc).Error; err != nil {
				failed++
				continue
			}
			updated++
			fmt.Printf("  -> Overwrite Already PoC: %s\n", req.Name)
			continue
		}
		if err != gorm.ErrRecordNotFound {
			failed++
			continue
		}
		created = append(created, poc)
		fmt.Printf("  -> Create successfully PoC: %s\n", poc.Name)
	}

	// Batch Insert - Batch Processing, Maximum per batch100Article
	if len(created) > 0 {
		batchSize := 100
		for i := 0; i < len(created); i += batchSize {
			end := i + batchSize
			if end > len(created) {
				end = len(created)
			}
			batch := created[i:end]

			if err := database.DB.Create(&batch).Error; err != nil {
				fmt.Printf("❌ Batch Insert Failed (batch %d-%d): %v\n", i, end, err)
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":          "Failed to import PoCs: " + err.Error(),
					"imported_count": i,
					"skipped_count":  skipped,
					"failed_count":   failed + (len(created) - i),
					"total":          len(pocs),
				})
				return
			}
			fmt.Printf("✅ Batch Inserted Successfully (batch %d-%d)\n", i, end)
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":        "PoCs imported successfully",
		"imported_count": len(created),
		"updated_count":  updated,
		"skipped_count":  skipped,
		"failed_count":   failed,
		"total":          len(pocs),
	})
}

// GetPoCCategories Get All Categories
func (h *PoCHandler) GetPoCCategories(c *gin.Context) {
	var categories []string
	if err := database.DB.Model(&models.PoC{}).
		Distinct("category").
		Pluck("category", &categories).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch PoC categories"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"categories": categories})
}

// GetPoCStats FetchPoCStatistical information
func (h *PoCHandler) GetPoCStats(c *gin.Context) {
	var total int64
	if err := database.DB.Model(&models.PoC{}).Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count PoCs"})
		return
	}

	var severityStats []struct {
		Severity string
		Count    int64
	}
	if err := database.DB.Model(&models.PoC{}).
		Select("severity, COUNT(*) as count").
		Group("severity").
		Scan(&severityStats).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load PoC severity statistics"})
		return
	}

	var categoryStats []struct {
		Category string
		Count    int64
	}
	if err := database.DB.Model(&models.PoC{}).
		Select("category, COUNT(*) as count").
		Group("category").
		Order("count DESC").
		Limit(10).
		Scan(&categoryStats).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load PoC category statistics"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"total":          total,
		"severity_stats": severityStats,
		"category_stats": categoryStats,
	})
}

// ExecutePoC ImplementationPoC
func (h *PoCHandler) ExecutePoC(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Target  string `json:"target" binding:"required"`
		ScopeID string `json:"scope_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var poc models.PoC
	if err := database.DB.First(&poc, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "PoC not found"})
		return
	}

	// Inspection PoC Whether to enable
	if !poc.IsEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "PoC is disabled"})
		return
	}
	validation, err := services.NewScanScopeService().Validate(req.ScopeID, req.Target)
	if err == nil {
		err = services.ScanScopeBlockedError(validation)
	}
	if err != nil {
		if services.IsScanScopeInputError(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		logger.Error("PoC scope validation failed poc_id=%q error=%v", poc.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "PoC authorization failed"})
		return
	}
	if validation.Enforced && strings.ToLower(strings.TrimSpace(poc.PoCType)) != "custom" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scope-enforced execution supports only same-origin custom PoCs"})
		return
	}
	req.Target = validation.NormalizedTarget

	// Use newPoCExecutor
	executor := scanner.NewPoCExecutor()
	execResult, err := executor.Execute(&poc, req.Target)

	// Record executable logs
	logResult := "safe"
	details := ""

	if err != nil {
		logResult = "error"
		details = "Execution failed"
		logger.Error("PoC execution failed poc_id=%q target=%q error=%v", poc.ID, req.Target, err)
	} else if execResult.Vulnerable {
		logResult = "vulnerable"
		details = execResult.Details
	} else {
		details = execResult.Message
	}

	log := &models.PoCExecutionLog{
		PoCID: poc.ID, ScopeID: validation.ScopeID, InvocationSource: "web", ActorID: c.GetString("user_id"),
		Target: req.Target, Result: logResult, Details: details,
	}
	if logErr := database.DB.Create(log).Error; logErr != nil {
		logger.Error("PoC audit log failed poc_id=%q target=%q error=%v", poc.ID, req.Target, logErr)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "PoC execution completed but the audit record could not be saved", "result": logResult, "details": details,
		})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":  "PoC execution failed",
			"result": logResult,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":       "PoC executed successfully",
		"result":        logResult,
		"details":       details,
		"execution_log": log,
	})
}

// min Returns the smaller of two integer values
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ImportPoCsFromZip FromzipDocument batch importPoC
func (h *PoCHandler) ImportPoCsFromZip(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 25<<20)
	// Fetch UploadedzipDocumentation
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to get uploaded file: " + err.Error()})
		return
	}

	// Check file extension
	if !strings.HasSuffix(strings.ToLower(file.Filename), ".zip") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Only .zip files are supported"})
		return
	}

	// The compressor itself and the post-pressure limits separately.
	const maxFileSize = 20 * 1024 * 1024
	if file.Size > maxFileSize {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("File too large. Maximum size: %dMB, uploaded: %.2fMB",
				maxFileSize/(1024*1024), float64(file.Size)/(1024*1024)),
		})
		return
	}

	// Use a separate directory for each request, Avoid simultaneous import overlaying.
	tempDir, err := os.MkdirTemp("", "poc_import_*")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create temp directory"})
		return
	}
	defer os.RemoveAll(tempDir)

	// Save UploadedzipDocumentation
	zipPath := filepath.Join(tempDir, file.Filename)
	if err := c.SaveUploadedFile(file, zipPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save uploaded file"})
		return
	}

	// Unpressure.zipDocumentation
	extractDir := filepath.Join(tempDir, "extracted")
	if err := unzipFile(zipPath, extractDir); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to extract zip file: " + err.Error()})
		return
	}

	// Recursively search for allyamlDocumentation
	var yamlFiles []string
	err = filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".yaml" || ext == ".yml" {
				yamlFiles = append(yamlFiles, path)
			}
		}
		return nil
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan yaml files: " + err.Error()})
		return
	}

	if len(yamlFiles) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No YAML files found in the zip archive"})
		return
	}

	fmt.Printf("📦 Found it. %d One.YAMLDocumentation, Start batch import...\n", len(yamlFiles))

	// Batch ImportPoC
	userID := c.GetString("user_id")
	var created []models.PoC
	var skipped int
	var failed int
	var updated int
	var failedFiles []string

	for _, yamlPath := range yamlFiles {
		relPath, _ := filepath.Rel(extractDir, yamlPath)
		fmt.Printf("📄 Processing of documents: %s\n", relPath)

		// ReadyamlContents
		content, err := os.ReadFile(yamlPath)
		if err != nil {
			fmt.Printf("  ❌ Reading Failed: %v\n", err)
			failed++
			failedFiles = append(failedFiles, relPath)
			continue
		}

		// Try to parse asNucleiTemplates
		var template map[string]interface{}
		if err := yaml.Unmarshal(content, &template); err != nil {
			fmt.Printf("  ❌ YAMLParsing failed: %v\n", err)
			failed++
			failedFiles = append(failedFiles, relPath)
			continue
		}

		// Convert toCreatePoCRequest
		poc, err := convertNucleiTemplate(template)
		if err != nil {
			fmt.Printf("  ❌ Template conversion failed: %v\n", err)
			failed++
			failedFiles = append(failedFiles, relPath)
			continue
		}

		// Authentication of required fields
		if poc.Name == "" || poc.Category == "" || poc.Severity == "" || poc.PoCType == "" || poc.PoCContent == "" {
			fmt.Printf("  ⏭️ Skip: Missing required fields\n")
			failed++
			failedFiles = append(failedFiles, relPath)
			continue
		}
		if err := scanner.ValidatePoCContent(poc.PoCType, poc.PoCContent); err != nil {
			fmt.Printf("  ⏭️ Skip: %v\n", err)
			failed++
			failedFiles = append(failedFiles, relPath)
			continue
		}

		// Add to to to create list
		pocModel := models.PoC{
			Name:             poc.Name,
			Category:         poc.Category,
			Severity:         poc.Severity,
			CVE:              poc.CVE,
			Product:          poc.Product,
			AffectedVersions: poc.AffectedVersions,
			Author:           poc.Author,
			Description:      poc.Description,
			Reference:        poc.Reference,
			PoCType:          poc.PoCType,
			PoCContent:       poc.PoCContent,
			Tags:             poc.Tags,
			Fingerprints:     poc.Fingerprints,
			AppNames:         poc.AppNames,
			MatchMode:        poc.MatchMode,
			IsEnabled:        true,
			CreatedBy:        userID,
		}
		if pocModel.MatchMode == "" {
			pocModel.MatchMode = "fuzzy"
		}

		var existingPoC models.PoC
		err = database.DB.Where(
			"name = ? AND cve = ? AND product = ? AND affected_versions = ?",
			pocModel.Name, pocModel.CVE, pocModel.Product, pocModel.AffectedVersions,
		).First(&existingPoC).Error
		if err == nil {
			pocModel.ID = existingPoC.ID
			pocModel.CreatedAt = existingPoC.CreatedAt
			if err := database.DB.Save(&pocModel).Error; err != nil {
				failed++
				failedFiles = append(failedFiles, relPath)
				continue
			}
			updated++
			fmt.Printf("  ✅ Overwrite Already PoC: %s\n", poc.Name)
			continue
		}
		if err != gorm.ErrRecordNotFound {
			failed++
			failedFiles = append(failedFiles, relPath)
			continue
		}
		created = append(created, pocModel)
		fmt.Printf("  ✅ Ready for import: %s\n", poc.Name)
	}

	// Batch Insert to Database (Batch Processing, Each batch100Article)
	if len(created) > 0 {
		batchSize := 100
		for i := 0; i < len(created); i += batchSize {
			end := i + batchSize
			if end > len(created) {
				end = len(created)
			}
			batch := created[i:end]

			if err := database.DB.Create(&batch).Error; err != nil {
				fmt.Printf("❌ Batch Insert Failed (batch %d-%d): %v\n", i, end, err)
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":          "Failed to import PoCs: " + err.Error(),
					"imported_count": i,
					"skipped_count":  skipped,
					"failed_count":   failed + (len(created) - i),
					"failed_files":   failedFiles,
					"total_files":    len(yamlFiles),
				})
				return
			}
			fmt.Printf("✅ Batch Inserted Successfully (batch %d-%d)\n", i, end)
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":        "PoCs imported from zip successfully",
		"imported_count": len(created),
		"updated_count":  updated,
		"skipped_count":  skipped,
		"failed_count":   failed,
		"failed_files":   failedFiles,
		"total_files":    len(yamlFiles),
	})
}

// unzipFile Unpressure.zipFile to specified directory
func unzipFile(zipPath, destDir string) error {
	const (
		maxArchiveFiles = 5000
		maxEntrySize    = 2 << 20
		maxTotalSize    = 200 << 20
	)
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	if len(r.File) > maxArchiveFiles {
		return fmt.Errorf("archive contains too many files")
	}
	var totalSize uint64
	for _, f := range r.File {
		if f.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("archive symlinks are not allowed: %s", f.Name)
		}
		if !f.FileInfo().IsDir() {
			if f.UncompressedSize64 > maxEntrySize {
				return fmt.Errorf("archive entry is too large: %s", f.Name)
			}
			totalSize += f.UncompressedSize64
			if totalSize > maxTotalSize {
				return fmt.Errorf("archive expands beyond the allowed size")
			}
		}
		// Prevent the path from going through the attack.
		fpath := filepath.Join(destDir, filepath.Clean(f.Name))
		if !strings.HasPrefix(fpath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, 0755); err != nil {
				return err
			}
			continue
		}

		// Create Parent Directory
		if err := os.MkdirAll(filepath.Dir(fpath), 0755); err != nil {
			return err
		}

		// Unpress File
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		written, copyErr := io.Copy(outFile, io.LimitReader(rc, maxEntrySize+1))
		outFile.Close()
		rc.Close()
		if copyErr != nil {
			return copyErr
		}
		if written > maxEntrySize {
			return fmt.Errorf("archive entry exceeded size limit: %s", f.Name)
		}
	}

	return nil
}

// convertNucleiTemplate ConvertNucleiTemplate AsCreatePoCRequest
func convertNucleiTemplate(template map[string]interface{}) (CreatePoCRequest, error) {
	var req CreatePoCRequest

	// ExtractIDAsCVENumbering
	if id, ok := template["id"].(string); ok {
		req.CVE = id
	}

	// ExtractinfoPart
	info, ok := template["info"].(map[string]interface{})
	if !ok {
		return req, fmt.Errorf("missing 'info' section")
	}

	// Extractname (Required)
	if name, ok := info["name"].(string); ok {
		req.Name = name
	} else {
		// If not,name, Try usingIDAsname
		if req.CVE != "" {
			req.Name = req.CVE
		} else {
			return req, fmt.Errorf("missing 'name' in info section and no ID available")
		}
	}

	// Extractauthor
	if author, ok := info["author"].(string); ok {
		req.Author = author
	}

	// Extractseverity
	if severity, ok := info["severity"].(string); ok {
		req.Severity = severity
	} else {
		req.Severity = "medium" // Default value
	}

	// Extractdescription
	if desc, ok := info["description"].(string); ok {
		req.Description = strings.TrimSpace(desc)
	}

	// Extractreference (Could be a array or string)
	if ref, ok := info["reference"]; ok {
		switch v := ref.(type) {
		case []interface{}:
			refs := make([]string, 0, len(v))
			for _, r := range v {
				if refStr, ok := r.(string); ok {
					refs = append(refs, refStr)
				}
			}
			req.Reference = strings.Join(refs, "\n")
		case string:
			req.Reference = v
		}
	}

	// Extracttags
	if tags, ok := info["tags"].(string); ok {
		req.Tags = tags
	}

	// ExtractCVE ID (FromclassificationOr directly frominfo)
	if classification, ok := info["classification"].(map[string]interface{}); ok {
		if cveID, ok := classification["cve-id"].(string); ok {
			req.CVE = cveID
		}
	}

	// Settingscategory (FromtagsDraw)
	if req.Tags != "" {
		tagList := strings.Split(req.Tags, ",")
		if len(tagList) > 0 {
			req.Category = strings.TrimSpace(tagList[0])
		}
	}
	if req.Category == "" {
		req.Category = "Other" // Default Category
	}

	// Use the entire template asPoCContents (Turn backYAML)
	templateBytes, err := yaml.Marshal(template)
	if err != nil {
		return req, fmt.Errorf("failed to marshal template: %w", err)
	}
	req.PoCContent = string(templateBytes)
	req.PoCType = "nuclei" // SettingsPoCTypenuclei

	return req, nil
}
