package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

// FingerprintHandler Fingerprint processor
type FingerprintHandler struct{}

// NewFingerprintHandler Create fingerprint processor
func NewFingerprintHandler() *FingerprintHandler {
	return &FingerprintHandler{}
}

// CreateFingerprintRequest Create fingerprint request
type CreateFingerprintRequest struct {
	Name        string   `json:"name" binding:"required"`
	Category    string   `json:"category" binding:"required"`
	DSL         []string `json:"dsl" binding:"required"`
	Description string   `json:"description"`
}

// ListFingerprints List all fingerprints.
func (h *FingerprintHandler) ListFingerprints(c *gin.Context) {
	category := c.Query("category")
	name := c.Query("name")

	// Page Break Parameters
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "20")

	var pageInt, pageSizeInt int
	fmt.Sscanf(page, "%d", &pageInt)
	fmt.Sscanf(pageSize, "%d", &pageSizeInt)
	if pageInt < 1 {
		pageInt = 1
	}
	if pageSizeInt < 1 {
		pageSizeInt = 20
	}
	if pageSizeInt > 200 {
		pageSizeInt = 200
	}

	query := database.DB.Model(&models.Fingerprint{})

	if category != "" {
		query = query.Where("category = ?", category)
	}
	if name != "" {
		query = query.Where("name LIKE ?", "%"+name+"%")
	}
	var ok bool
	query, ok = applyAdvancedSearch(c, query,
		map[string]string{"name": "name", "category": "category", "status": "is_enabled", "description": "description", "dsl": "dsl"},
		[]string{"name", "category", "description", "dsl"})
	if !ok {
		return
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count fingerprints"})
		return
	}

	var fingerprints []models.Fingerprint
	offset := (pageInt - 1) * pageSizeInt
	if err := query.Order("category ASC, name ASC").
		Limit(pageSizeInt).
		Offset(offset).
		Find(&fingerprints).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch fingerprints"})
		return
	}

	totalPages := int((total + int64(pageSizeInt) - 1) / int64(pageSizeInt))

	c.JSON(http.StatusOK, gin.H{
		"fingerprints": fingerprints,
		"total":        total,
		"page":         pageInt,
		"page_size":    pageSizeInt,
		"total_pages":  totalPages,
	})
}

// GetFingerprint Get a single fingerprint.
func (h *FingerprintHandler) GetFingerprint(c *gin.Context) {
	id := c.Param("id")

	var fingerprint models.Fingerprint
	if err := database.DB.First(&fingerprint, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Fingerprint not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get fingerprint"})
		return
	}

	c.JSON(http.StatusOK, fingerprint)
}

// CreateFingerprint Create Fingerprints
func (h *FingerprintHandler) CreateFingerprint(c *gin.Context) {
	var req CreateFingerprintRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Authentication DSL Rules
	if len(req.DSL) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "DSL rules cannot be empty"})
		return
	}

	fingerprint := &models.Fingerprint{
		Name:        req.Name,
		Category:    req.Category,
		DSL:         req.DSL,
		Description: req.Description,
		IsEnabled:   true,
	}

	if err := database.DB.Create(fingerprint).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create fingerprint"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":     "Fingerprint created successfully",
		"fingerprint": fingerprint,
	})
}

// UpdateFingerprint Update Fingerprints
func (h *FingerprintHandler) UpdateFingerprint(c *gin.Context) {
	id := c.Param("id")

	var fingerprint models.Fingerprint
	if err := database.DB.First(&fingerprint, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Fingerprint not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get fingerprint"})
		return
	}

	var req CreateFingerprintRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Authentication DSL Rules
	if len(req.DSL) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "DSL rules cannot be empty"})
		return
	}

	// Update Fields
	fingerprint.Name = req.Name
	fingerprint.Category = req.Category
	fingerprint.DSL = req.DSL
	fingerprint.Description = req.Description

	if err := database.DB.Save(&fingerprint).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update fingerprint"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "Fingerprint updated successfully",
		"fingerprint": fingerprint,
	})
}

// DeleteFingerprint Remove Fingerprints
func (h *FingerprintHandler) DeleteFingerprint(c *gin.Context) {
	id := c.Param("id")

	if err := database.DB.Delete(&models.Fingerprint{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete fingerprint"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Fingerprint deleted successfully"})
}

// BatchCreateFingerprints Batch Create Fingerprints
func (h *FingerprintHandler) BatchCreateFingerprints(c *gin.Context) {
	var fingerprints []CreateFingerprintRequest
	if err := c.ShouldBindJSON(&fingerprints); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var created []models.Fingerprint
	for _, req := range fingerprints {
		fp := models.Fingerprint{
			Name:        req.Name,
			Category:    req.Category,
			DSL:         req.DSL,
			Description: req.Description,
			IsEnabled:   true,
		}
		created = append(created, fp)
	}

	if err := database.DB.Create(&created).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create fingerprints"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Fingerprints created successfully",
		"count":   len(created),
	})
}

// GetCategories Get All Categories
func (h *FingerprintHandler) GetCategories(c *gin.Context) {
	var categories []string
	database.DB.Model(&models.Fingerprint{}).
		Distinct("category").
		Pluck("category", &categories)

	c.JSON(http.StatusOK, gin.H{"categories": categories})
}

// FingerprintImportItem Fingerprint Import Item Format (SupportJSONandYAML)
type FingerprintImportItem struct {
	CMS      string   `json:"cms" yaml:"cms"`
	Method   string   `json:"method" yaml:"method"`
	Location string   `json:"location" yaml:"location"`
	Keyword  []string `json:"keyword" yaml:"keyword"`
}

// UniversalFingerprintFormat Generic fingerprint format (Auto-settling multiple formats)
type UniversalFingerprintFormat struct {
	// Common fields
	Name        string      `yaml:"name" json:"name"`
	ID          string      `yaml:"id" json:"id"`
	CMS         string      `yaml:"cms" json:"cms"`
	Category    string      `yaml:"category" json:"category"`
	Tags        interface{} `yaml:"tags" json:"tags"` // Could be a string or array
	Description string      `yaml:"description" json:"description"`

	// NucleiStyle
	Info     map[string]interface{}   `yaml:"info" json:"info"`
	Matchers []map[string]interface{} `yaml:"matchers" json:"matchers"`

	// EHole/Simplified style
	Method   string   `yaml:"method" json:"method"`
	Location string   `yaml:"location" json:"location"`
	Keyword  []string `yaml:"keyword" json:"keyword"`

	// CustompatternsFormat
	Patterns map[string]interface{} `yaml:"patterns" json:"patterns"`

	// ObserverWardStyle
	Priority   int                      `yaml:"priority" json:"priority"`
	MatchRules []map[string]interface{} `yaml:"match_rules" json:"match_rules"`

	// WappalyzerStyle (Key-to-Format)
	Cats    interface{}            `yaml:"cats" json:"cats"`
	HTML    interface{}            `yaml:"html" json:"html"`
	Headers map[string]interface{} `yaml:"headers" json:"headers"`
	Implies interface{}            `yaml:"implies" json:"implies"`

	// Raw data (For processing unknown format)
	Raw map[string]interface{} `yaml:",inline" json:"-"`
}

// ImportFingerprints Import Fingerprints (Multiple supportYAML/JSONFormat - Smart Recognition)
func (h *FingerprintHandler) ImportFingerprints(c *gin.Context) {
	// Call for a common import interface
	h.ImportFingerprintsUniversal(c)
}

// ImportFingerprintsLegacy Import Fingerprints (Old version format - For backward compatibility only)
func (h *FingerprintHandler) ImportFingerprintsLegacy(c *gin.Context) {
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
		// YAML Organisation ":" As Key Separator, And first line is not. "[" or "{"
		bodyStr := strings.TrimSpace(string(body))
		if !strings.HasPrefix(bodyStr, "[") && !strings.HasPrefix(bodyStr, "{") {
			isYAML = true
		}
	}

	var items []FingerprintImportItem

	if isYAML {
		fmt.Println("Detected YAML Format, Start parsing...")
		if err := yaml.Unmarshal(body, &items); err != nil {
			fmt.Printf("YAMLParsing error: %v\n", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid YAML format: " + err.Error()})
			return
		}
	} else {
		fmt.Println("Detected JSON Format, Start parsing...")
		if err := json.Unmarshal(body, &items); err != nil {
			fmt.Printf("JSONParsing error: %v\n", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format: " + err.Error()})
			return
		}
	}

	fmt.Printf("Received %d Fingerprint data. (Format: %s)\n", len(items), map[bool]string{true: "YAML", false: "JSON"}[isYAML])

	var created []models.Fingerprint
	var failed int
	var skipped int
	var failedReasons []string

	for i, item := range items {
		fmt.Printf("Deal with the %d Article: CMS=%s, Method=%s, Location=%s, Keywords=%v\n",
			i+1, item.CMS, item.Method, item.Location, item.Keyword)

		// Authentication of required fields
		if item.CMS == "" || item.Method == "" || item.Location == "" || len(item.Keyword) == 0 {
			reason := fmt.Sprintf("Article%dArticle: Missing required fields (cms=%s, method=%s, location=%s, keywords=%dOne.)",
				i+1, item.CMS, item.Method, item.Location, len(item.Keyword))
			failedReasons = append(failedReasons, reason)
			fmt.Printf("  -> Skip: %s\n", reason)
			failed++
			continue
		}

		// Convert location Yes. rule_type
		ruleType := convertLocationToRuleType(item.Location)
		if ruleType == "" {
			reason := fmt.Sprintf("Article%dArticle: UnsupportedlocationType '%s'", i+1, item.Location)
			failedReasons = append(failedReasons, reason)
			fmt.Printf("  -> Skip: %s\n", reason)
			failed++
			continue
		}

		// Convert keywords to DSL Rules
		dslRules := []string{}
		for _, keyword := range item.Keyword {
			// According to the different location Create corresponding DSL Rules
			var target string
			switch item.Location {
			case "body":
				target = "body"
			case "title":
				target = "title"
			case "header", "server", "banner":
				target = "header"
			default:
				target = "body"
			}
			// Create contains Rules
			dslRule := fmt.Sprintf("contains(%s, '%s')", target, strings.ReplaceAll(keyword, "'", "\\'"))
			dslRules = append(dslRules, dslRule)
		}

		if len(dslRules) == 0 {
			reason := fmt.Sprintf("Article%dArticle: DSLThe rule is empty.", i+1)
			failedReasons = append(failedReasons, reason)
			fmt.Printf("  -> Skip: %s\n", reason)
			failed++
			continue
		}

		// Check if the same fingerprints exist. (Weight by name)
		var existingFingerprint models.Fingerprint
		if err := database.DB.Where("name = ?", item.CMS).First(&existingFingerprint).Error; err == nil {
			// Existing, Skip
			fmt.Printf("  -> Skip (Existing): %s\n", item.CMS)
			skipped++
			continue
		}

		fingerprint := models.Fingerprint{
			Name:        item.CMS,
			Category:    "Web", // Default Category
			DSL:         dslRules,
			Description: fmt.Sprintf("Imported from JSON - Method: %s, Location: %s", item.Method, item.Location),
			IsEnabled:   true,
		}

		fmt.Printf("  -> Successfully created fingerprint: %s (DSLNumber of rules: %d)\n", fingerprint.Name, len(fingerprint.DSL))
		created = append(created, fingerprint)
	}

	// Batch Insert, UseFirstOrCreateAvoidance of errors
	successCount := 0
	duplicateCount := 0

	if len(created) > 0 {
		for i, fingerprint := range created {
			// UseFirstOrCreateTo avoid duplication (By name)
			var existing models.Fingerprint
			result := database.DB.Where("name = ?", fingerprint.Name).
				FirstOrCreate(&existing, &fingerprint)

			if result.Error != nil {
				fmt.Printf("Article %d Scratch failed: %v\n", i+1, result.Error)
				failed++
				continue
			}

			if result.RowsAffected > 0 {
				// Newly created records
				successCount++
				if (i+1)%100 == 0 {
					fmt.Printf("Progress: %d/%d (Success: %d, Repeat: %d)\n", i+1, len(created), successCount, duplicateCount)
				}
			} else {
				// Existing records
				duplicateCount++
			}
		}

		fmt.Printf("All completed: Add %d Article, Skip Repeat %d Article\n", successCount, duplicateCount)
	}

	response := gin.H{
		"message":        "Fingerprints imported successfully",
		"imported_count": successCount,
		"skipped_count":  skipped + duplicateCount,
		"failed_count":   failed,
		"total":          len(items),
	}

	if len(failedReasons) > 0 {
		response["failed_reasons"] = failedReasons
	}

	c.JSON(http.StatusCreated, response)
}

// convertLocationToRuleType WilllocationConvert torule_type
func convertLocationToRuleType(location string) string {
	location = strings.ToLower(location)
	switch location {
	case "body":
		return "body"
	case "header":
		return "header"
	case "title":
		return "title"
	case "favicon":
		return "favicon"
	case "url":
		return "url"
	default:
		return ""
	}
}

// parseUniversalFingerprint Smart parsing generic fingerprint formats
func parseUniversalFingerprint(item *UniversalFingerprintFormat, index int) (*models.Fingerprint, error) {
	var name, category, description string
	var dslRules []string

	// 1. Extract Name (Priority: name > id > cms)
	if item.Name != "" {
		name = item.Name
	} else if item.ID != "" {
		name = item.ID
	} else if item.CMS != "" {
		name = item.CMS
	}

	if name == "" {
		return nil, fmt.Errorf("Fingerprint missing name field")
	}

	// 2. Extract Classification
	category = "Web" // Default Category
	if item.Category != "" {
		category = item.Category
	} else if item.Info != nil {
		if cat, ok := item.Info["category"].(string); ok {
			category = cat
		} else if tags, ok := item.Info["tags"].(string); ok {
			category = tags
		}
	} else if item.Tags != nil {
		if tagStr, ok := item.Tags.(string); ok {
			category = tagStr
		} else if tagArr, ok := item.Tags.([]interface{}); ok && len(tagArr) > 0 {
			if firstTag, ok := tagArr[0].(string); ok {
				category = firstTag
			}
		}
	}

	// 3. Extract description
	description = item.Description
	if description == "" && item.Info != nil {
		if desc, ok := item.Info["description"].(string); ok {
			description = desc
		}
	}

	// 4. Extracting matching rules according to different formats

	// Format1: NucleiStyle (matchers)
	if len(item.Matchers) > 0 {
		fmt.Printf("  [Format Recognition] NucleiStyle\n")
		for _, matcher := range item.Matchers {
			matcherType, _ := matcher["type"].(string)
			part, _ := matcher["part"].(string)
			if part == "" {
				part = "body"
			}

			// Extract keywords
			var words []string
			if wordList, ok := matcher["words"].([]interface{}); ok {
				for _, w := range wordList {
					if ws, ok := w.(string); ok {
						words = append(words, ws)
					}
				}
			} else if word, ok := matcher["word"].(string); ok {
				words = append(words, word)
			}

			// GenerateDSLRules
			for _, word := range words {
				dsl := generateDSLRule(part, matcherType, word)
				if dsl != "" {
					dslRules = append(dslRules, dsl)
				}
			}
		}
	}

	// Format2: EHoleStyle (method + location + keyword)
	if len(dslRules) == 0 && len(item.Keyword) > 0 {
		fmt.Printf("  [Format Recognition] EHoleStyle\n")
		location := item.Location
		if location == "" {
			location = "body"
		}
		for _, keyword := range item.Keyword {
			dsl := generateDSLRule(location, "keyword", keyword)
			if dsl != "" {
				dslRules = append(dslRules, dsl)
			}
		}
	}

	// Format3: CustompatternsFormat
	if len(dslRules) == 0 && item.Patterns != nil {
		fmt.Printf("  [Format Recognition] PatternsStyle\n")
		for location, patterns := range item.Patterns {
			if patternList, ok := patterns.([]interface{}); ok {
				for _, p := range patternList {
					if pattern, ok := p.(string); ok {
						dsl := generateDSLRule(location, "keyword", pattern)
						if dsl != "" {
							dslRules = append(dslRules, dsl)
						}
					}
				}
			} else if patternStr, ok := patterns.(string); ok {
				dsl := generateDSLRule(location, "keyword", patternStr)
				if dsl != "" {
					dslRules = append(dslRules, dsl)
				}
			}
		}
	}

	// Format4: ObserverWardStyle (match_rules)
	if len(dslRules) == 0 && len(item.MatchRules) > 0 {
		fmt.Printf("  [Format Recognition] ObserverWardStyle\n")
		for _, rule := range item.MatchRules {
			// url_path
			if urlPath, ok := rule["url_path"].(string); ok {
				dsl := fmt.Sprintf("contains(url, '%s')", strings.ReplaceAll(urlPath, "'", "\\'"))
				dslRules = append(dslRules, dsl)
			}
			// response_body
			if respBody, ok := rule["response_body"].(string); ok {
				dsl := fmt.Sprintf("contains(body, '%s')", strings.ReplaceAll(respBody, "'", "\\'"))
				dslRules = append(dslRules, dsl)
			}
			// response_header
			if respHeader, ok := rule["response_header"].(string); ok {
				dsl := fmt.Sprintf("contains(header, '%s')", strings.ReplaceAll(respHeader, "'", "\\'"))
				dslRules = append(dslRules, dsl)
			}
			// status_code
			if statusCode, ok := rule["status_code"].(int); ok {
				dsl := fmt.Sprintf("status_code == %d", statusCode)
				dslRules = append(dslRules, dsl)
			}
		}
	}

	// Format5: WappalyzerStyle (html, headers)
	if len(dslRules) == 0 && (item.HTML != nil || item.Headers != nil) {
		fmt.Printf("  [Format Recognition] WappalyzerStyle\n")
		// ProcessingHTMLMode
		if item.HTML != nil {
			if htmlList, ok := item.HTML.([]interface{}); ok {
				for _, h := range htmlList {
					if htmlStr, ok := h.(string); ok {
						dsl := generateDSLRule("body", "keyword", htmlStr)
						if dsl != "" {
							dslRules = append(dslRules, dsl)
						}
					}
				}
			} else if htmlStr, ok := item.HTML.(string); ok {
				dsl := generateDSLRule("body", "keyword", htmlStr)
				if dsl != "" {
					dslRules = append(dslRules, dsl)
				}
			}
		}
		// ProcessingHeaders
		if item.Headers != nil {
			for headerName, headerValue := range item.Headers {
				if hvStr, ok := headerValue.(string); ok {
					dsl := fmt.Sprintf("contains(header, '%s: %s')", headerName, strings.ReplaceAll(hvStr, "'", "\\'"))
					dslRules = append(dslRules, dsl)
				}
			}
		}
	}

	// If no rule is extracted
	if len(dslRules) == 0 {
		return nil, fmt.Errorf("Could not extract matching rules from fingerprints")
	}

	// Generate description
	if description == "" {
		description = fmt.Sprintf("Automaticly imported fingerprints - Number of rules: %d", len(dslRules))
	}

	fingerprint := &models.Fingerprint{
		Name:        name,
		Category:    category,
		DSL:         dslRules,
		Description: description,
		IsEnabled:   true,
	}

	return fingerprint, nil
}

// generateDSLRule GenerateDSLRules
func generateDSLRule(location, matchType, pattern string) string {
	location = strings.ToLower(location)

	// ConvertlocationYes.DSLObjective
	var target string
	switch location {
	case "body", "response_body", "html":
		target = "body"
	case "header", "headers", "response_header", "banner", "server":
		target = "header"
	case "title":
		target = "title"
	case "url", "path", "url_path":
		target = "url"
	case "favicon", "icon":
		target = "favicon"
	default:
		target = "body"
	}

	// Transliterate single quotation marks
	escapedPattern := strings.ReplaceAll(pattern, "'", "\\'")

	// Generate rules by matching type
	switch strings.ToLower(matchType) {
	case "word", "keyword", "contains":
		return fmt.Sprintf("contains(%s, '%s')", target, escapedPattern)
	case "regex", "regexp":
		return fmt.Sprintf("regex(%s, '%s')", target, escapedPattern)
	case "exact", "equals":
		return fmt.Sprintf("%s == '%s'", target, escapedPattern)
	default:
		// Default usecontains
		return fmt.Sprintf("contains(%s, '%s')", target, escapedPattern)
	}
}

// ImportFingerprintsUniversal Universal fingerprint import interface (Smart recognition in multiple formats)
func (h *FingerprintHandler) ImportFingerprintsUniversal(c *gin.Context) {
	// Read raw data
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 10<<20)
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body: " + err.Error()})
		return
	}

	// Check whether toYAMLFormat
	contentType := c.GetHeader("Content-Type")
	isYAML := strings.Contains(contentType, "yaml") || strings.Contains(contentType, "yml")

	if !isYAML && len(body) > 0 {
		bodyStr := strings.TrimSpace(string(body))
		if !strings.HasPrefix(bodyStr, "[") && !strings.HasPrefix(bodyStr, "{") {
			isYAML = true
		}
	}

	fmt.Printf("📦 Start importing fingerprints (Format: %s)\n", map[bool]string{true: "YAML", false: "JSON"}[isYAML])

	// Try to interpret into a generic format array
	var items []UniversalFingerprintFormat

	if isYAML {
		// Try to parsing as a array first
		if err := yaml.Unmarshal(body, &items); err != nil {
			// If you fail, Try parsing as a single object
			var singleItem UniversalFingerprintFormat
			if err := yaml.Unmarshal(body, &singleItem); err != nil {
				// If it still fails,, Try asmap[string]UniversalFingerprintFormatParsing (WappalyzerStyle)
				var itemsMap map[string]UniversalFingerprintFormat
				if err := yaml.Unmarshal(body, &itemsMap); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid YAML format: " + err.Error()})
					return
				}
				// ConvertmapGroup of countries
				for name, item := range itemsMap {
					if item.Name == "" {
						item.Name = name
					}
					items = append(items, item)
				}
			} else {
				items = append(items, singleItem)
			}
		}
	} else {
		// JSONParsing
		if err := json.Unmarshal(body, &items); err != nil {
			// Try Single Object
			var singleItem UniversalFingerprintFormat
			if err := json.Unmarshal(body, &singleItem); err != nil {
				// TrymapFormat
				var itemsMap map[string]UniversalFingerprintFormat
				if err := json.Unmarshal(body, &itemsMap); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format: " + err.Error()})
					return
				}
				for name, item := range itemsMap {
					if item.Name == "" {
						item.Name = name
					}
					items = append(items, item)
				}
			} else {
				items = append(items, singleItem)
			}
		}
	}

	fmt.Printf("✅ Parsing successful, Total %d A fingerprint.\n", len(items))

	var created []models.Fingerprint
	var skipped int
	var failed int
	var failedReasons []string

	for i, item := range items {
		fmt.Printf("\n[%d/%d] Handle fingerprints....\n", i+1, len(items))

		// Smart Parsing
		fingerprint, err := parseUniversalFingerprint(&item, i)
		if err != nil {
			reason := fmt.Sprintf("Article%dArticle: %s", i+1, err.Error())
			failedReasons = append(failedReasons, reason)
			fmt.Printf("  ❌ %s\n", reason)
			failed++
			continue
		}

		// Check if it exists
		var existing models.Fingerprint
		if err := database.DB.Where("name = ?", fingerprint.Name).First(&existing).Error; err == nil {
			fmt.Printf("  ⏭️ Skip (Existing): %s\n", fingerprint.Name)
			skipped++
			continue
		}

		fmt.Printf("  ✅ %s (Classification: %s, Number of rules: %d)\n", fingerprint.Name, fingerprint.Category, len(fingerprint.DSL))
		created = append(created, *fingerprint)
	}

	// Batch Insert
	successCount := 0
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
				failed += len(batch)
			} else {
				successCount += len(batch)
				fmt.Printf("✅ Batch Inserted Successfully (batch %d-%d)\n", i, end)
			}
		}
	}

	response := gin.H{
		"message":        "Fingerprints imported successfully",
		"imported_count": successCount,
		"skipped_count":  skipped,
		"failed_count":   failed,
		"total":          len(items),
	}

	if len(failedReasons) > 0 && len(failedReasons) <= 10 {
		response["failed_reasons"] = failedReasons
	} else if len(failedReasons) > 10 {
		response["failed_reasons"] = append(failedReasons[:10], fmt.Sprintf("... And... %d A failure.", len(failedReasons)-10))
	}

	c.JSON(http.StatusCreated, response)
}
