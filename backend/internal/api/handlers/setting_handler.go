package handlers

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/config"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/logger"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/proxypool"
	"github.com/reconmaster/backend/internal/scanner"
	"github.com/reconmaster/backend/internal/services"
	"gorm.io/gorm"
)

// SettingHandler Set Processor
type SettingHandler struct {
	encryptionKey []byte
}

// TestNotification sends a test event through one configured notification channel.
func (h *SettingHandler) TestNotification(c *gin.Context) {
	channel := strings.ToLower(strings.TrimSpace(c.Param("channel")))
	selection := services.NotificationSelection{}
	switch channel {
	case "webhook":
		selection.Webhook = true
	case "dingtalk":
		selection.DingTalk = true
	case "feishu":
		selection.Feishu = true
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported notification channel", "allowed": []string{"webhook", "dingtalk", "feishu"}})
		return
	}
	notifier, err := services.LoadNotificationService(database.DB)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load notification settings"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 12*time.Second)
	defer cancel()
	results := notifier.Send(ctx, services.NotificationEvent{
		Type: "notification_test", Title: "Argus Notification Test", Message: "Notification channel connection test succeeded.", Severity: "info", OccurredAt: time.Now(),
	}, selection)
	for _, result := range results {
		if !result.Success {
			c.JSON(http.StatusBadGateway, gin.H{"error": "notification delivery failed", "results": results})
			return
		}
	}
	if len(results) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "notification channel is not enabled or configured"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "notification sent", "results": results})
}

// NewSettingHandler Create Settings Processor
func NewSettingHandler() *SettingHandler {
	// Fetch encryption keys from configuration, Remarkable configuration
	key := config.GlobalConfig.Encryption.Key
	if key == "" {
		panic("encryption.key is not configured. Set encryption.key in config.yaml. " +
			"Existing encrypted data requires the original key to decrypt.")
	}
	return &SettingHandler{
		encryptionKey: []byte(key),
	}
}

// GetSettings Get All Settings
func (h *SettingHandler) GetSettings(c *gin.Context) {
	category := c.Query("category")

	var settings []models.Setting
	query := database.DB
	if category != "" {
		query = query.Where("category = ?", category)
	}

	if err := query.Order("category ASC, key ASC").Limit(200).Find(&settings).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get settings"})
		return
	}

	for i := range settings {
		settings[i] = settingForResponse(settings[i])
	}

	c.JSON(http.StatusOK, gin.H{"settings": settings})
}

// GetSetting Get individual settings
func (h *SettingHandler) GetSetting(c *gin.Context) {
	key := c.Param("key")

	var setting models.Setting
	if err := database.DB.Where("key = ?", key).First(&setting).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Setting not found"})
		return
	}

	c.JSON(http.StatusOK, settingForResponse(setting))
}

// UpdateSetting Update Settings
func (h *SettingHandler) UpdateSetting(c *gin.Context) {
	var input struct {
		Category    string `json:"category" binding:"required"`
		Key         string `json:"key" binding:"required"`
		Value       string `json:"value"`
		Description string `json:"description"`
		IsEncrypted bool   `json:"is_encrypted"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := validateSettingValue(input.Key, input.Value); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var setting models.Setting
	result := database.DB.Where("key = ?", input.Key).First(&setting)
	if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		logger.Error("Setting lookup failed key=%q error=%v", input.Key, result.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update setting"})
		return
	}

	value := input.Value
	shouldEncrypt := input.IsEncrypted || sensitiveSettingKey(input.Key) || (result.Error == nil && setting.IsEncrypted)
	if shouldEncrypt && value == "" && result.Error == nil {
		c.JSON(http.StatusOK, gin.H{"message": "Setting unchanged", "setting": settingForResponse(setting)})
		return
	}
	// If encryption is required
	if shouldEncrypt && value != "" {
		encrypted, err := h.encrypt(value)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt value"})
			return
		}
		value = encrypted
	}

	if result.Error != nil {
		// Create New Settings
		setting = models.Setting{
			Category:    input.Category,
			Key:         input.Key,
			Value:       value,
			Description: input.Description,
			IsEncrypted: shouldEncrypt,
		}
		if err := database.DB.Create(&setting).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create setting"})
			return
		}
	} else {
		// Update existing settings
		setting.Category = input.Category
		setting.Value = value
		setting.Description = input.Description
		setting.IsEncrypted = shouldEncrypt
		if err := database.DB.Save(&setting).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update setting"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Setting updated successfully", "setting": settingForResponse(setting)})
}

// BatchUpdateSettings Batch Update Settings
func (h *SettingHandler) BatchUpdateSettings(c *gin.Context) {
	var input struct {
		Settings []struct {
			Category    string `json:"category" binding:"required"`
			Key         string `json:"key" binding:"required"`
			Value       string `json:"value"`
			Description string `json:"description"`
			IsEncrypted bool   `json:"is_encrypted"`
			ClearEmpty  bool   `json:"clear_empty"`
		} `json:"settings" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	for _, setting := range input.Settings {
		if err := validateSettingValue(setting.Key, setting.Value); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "key": setting.Key})
			return
		}
	}

	if err := database.DB.Transaction(func(tx *gorm.DB) error {
		for _, s := range input.Settings {
			var setting models.Setting
			result := tx.Where("key = ?", s.Key).First(&setting)
			if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return result.Error
			}
			exists := result.Error == nil
			shouldEncrypt := s.IsEncrypted || sensitiveSettingKey(s.Key) || (exists && setting.IsEncrypted)
			value := s.Value
			if shouldEncrypt && value == "" && !s.ClearEmpty {
				continue
			}
			if shouldEncrypt && value != "" {
				encrypted, err := h.encrypt(value)
				if err != nil {
					return err
				}
				value = encrypted
			}
			if !exists {
				setting = models.Setting{Category: s.Category, Key: s.Key, Value: value, Description: s.Description, IsEncrypted: shouldEncrypt}
				if err := tx.Create(&setting).Error; err != nil {
					return err
				}
				continue
			}
			setting.Category = s.Category
			setting.Value = value
			setting.Description = s.Description
			setting.IsEncrypted = shouldEncrypt
			if err := tx.Save(&setting).Error; err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		logger.Error("Batch settings update failed user_id=%q error=%v", c.GetString("user_id"), err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update settings"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Settings updated successfully"})
}

func settingForResponse(setting models.Setting) models.Setting {
	if setting.IsEncrypted || sensitiveSettingKey(setting.Key) {
		setting.Configured = strings.TrimSpace(setting.Value) != ""
		setting.Value = ""
		setting.IsEncrypted = true
	}
	return setting
}

func sensitiveSettingKey(key string) bool {
	switch key {
	case models.SettingKeyFOFAKey, models.SettingKeyHunterKey, models.SettingKeyQuakeKey,
		models.SettingKeyZoomEyeKey, models.SettingKeyGitHubToken, models.SettingKeyShodanKey,
		models.SettingKeyVirusTotalKey, models.SettingKeyCustomSpaceAPIURL,
		models.SettingKeyCustomSpaceAPIHeaders, models.SettingKeyEnterpriseICPURL,
		models.SettingKeyEnterpriseICPHeaders, models.SettingKeyWebhookURL,
		models.SettingKeyWebhookSecret, models.SettingKeyDingDingWebhook,
		models.SettingKeyDingDingSecret, models.SettingKeyFeishuWebhook,
		models.SettingKeyFeishuSecret, models.SettingKeyEmailPassword:
		return true
	default:
		return false
	}
}

func validateSettingValue(key, value string) error {
	if _, ok := scanner.ScannerSettingDefinition(key); ok {
		_, err := scanner.NormalizeScannerSettingValue(key, value)
		return err
	}
	value = strings.TrimSpace(value)
	switch key {
	case models.SettingKeyEnterpriseICPURL, models.SettingKeyCustomSpaceAPIURL:
		if value == "" {
			return nil
		}
		parsed, err := url.Parse(strings.ReplaceAll(value, "{domain}", "example.com"))
		if err != nil || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return fmt.Errorf("provider URL must use http or https and must not contain credentials")
		}
	case models.SettingKeyEnterpriseICPHeaders:
		if value == "" {
			return nil
		}
		var headers map[string]string
		if err := json.Unmarshal([]byte(value), &headers); err != nil || headers == nil {
			return fmt.Errorf("enterprise ICP headers must be a JSON object with string values")
		}
	}
	return nil
}

// DeleteSetting Remove Settings
func (h *SettingHandler) DeleteSetting(c *gin.Context) {
	key := c.Param("key")

	if err := database.DB.Where("key = ?", key).Delete(&models.Setting{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete setting"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Setting deleted successfully"})
}

func (h *SettingHandler) ValidateProvider(c *gin.Context) {
	provider := strings.ToLower(c.Param("provider"))
	var input struct {
		Credentials map[string]string `json:"credentials"`
		UseSaved    bool              `json:"use_saved"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "example": gin.H{"credentials": gin.H{"api_key": "your-key"}}})
		return
	}
	if input.UseSaved {
		input.Credentials = nil
	}
	client := &http.Client{Timeout: 12 * time.Second, Transport: proxypool.ConfigureTransport(&http.Transport{})}
	var req *http.Request
	var err error
	require := func(key string) (string, bool) {
		value := strings.TrimSpace(input.Credentials[key])
		if value != "" {
			return value, true
		}
		stored, storedErr := h.storedSettingValue(key)
		if storedErr != nil {
			logger.Error("Provider credential load failed provider=%q key=%q error=%v", provider, key, storedErr)
			return "", false
		}
		return stored, stored != ""
	}
	switch provider {
	case "fofa":
		email, okEmail := require("email")
		key, okKey := require("api_key")
		if !okEmail || !okKey {
			c.JSON(400, gin.H{"error": "FOFA requires email and api_key"})
			return
		}
		req, err = http.NewRequest(http.MethodGet, "https://fofa.info/api/v1/info/my?email="+url.QueryEscape(email)+"&key="+url.QueryEscape(key), nil)
	case "hunter":
		key, ok := require("api_key")
		if !ok {
			c.JSON(400, gin.H{"error": "Hunter requires api_key"})
			return
		}
		req, err = http.NewRequest(http.MethodGet, "https://hunter.qianxin.com/openApi/userInfo?api-key="+url.QueryEscape(key), nil)
	case "quake":
		key, ok := require("api_key")
		if !ok {
			c.JSON(400, gin.H{"error": "Quake requires api_key"})
			return
		}
		req, err = http.NewRequest(http.MethodGet, "https://quake.360.net/api/v3/user/info", nil)
		if err == nil {
			req.Header.Set("X-QuakeToken", key)
		}
	case "zoomeye":
		key, ok := require("api_key")
		if !ok {
			c.JSON(400, gin.H{"error": "ZoomEye requires api_key"})
			return
		}
		req, err = http.NewRequest(http.MethodGet, "https://api.zoomeye.org/resources-info", nil)
		if err == nil {
			req.Header.Set("API-KEY", key)
		}
	case "shodan":
		key, ok := require("api_key")
		if !ok {
			c.JSON(400, gin.H{"error": "Shodan requires api_key"})
			return
		}
		req, err = http.NewRequest(http.MethodGet, "https://api.shodan.io/api-info?key="+url.QueryEscape(key), nil)
	case "virustotal":
		key, ok := require("api_key")
		if !ok {
			c.JSON(400, gin.H{"error": "VirusTotal requires api_key"})
			return
		}
		req, err = http.NewRequest(http.MethodGet, "https://www.virustotal.com/api/v3/users/current", nil)
		if err == nil {
			req.Header.Set("x-apikey", key)
		}
	case "github":
		key, ok := require("api_key")
		if !ok {
			c.JSON(400, gin.H{"error": "GitHub requires api_key"})
			return
		}
		req, err = http.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+key)
			req.Header.Set("Accept", "application/vnd.github+json")
			req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
			req.Header.Set("User-Agent", "Eclipse-Recon")
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported provider", "supported": []string{"fofa", "hunter", "quake", "zoomeye", "shodan", "virustotal", "github"}})
		return
	}
	if err != nil {
		logger.Error("Provider validation request build failed provider=%q error=%v", provider, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "provider validation request failed"})
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Provider validation request failed provider=%q error=%v", provider, err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "provider request failed"})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "credential validation failed", "provider": provider, "status": resp.StatusCode})
		return
	}
	c.JSON(http.StatusOK, gin.H{"valid": true, "provider": provider, "status": resp.StatusCode})
}

func (h *SettingHandler) storedSettingValue(key string) (string, error) {
	var setting models.Setting
	if err := database.DB.Where("key = ?", key).First(&setting).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", nil
		}
		return "", err
	}
	value := strings.TrimSpace(setting.Value)
	if setting.IsEncrypted && value != "" {
		decrypted, err := h.decrypt(value)
		if err != nil {
			return "", err
		}
		value = strings.TrimSpace(decrypted)
	}
	return value, nil
}

// ListDictionaries List all dictionarys
func (h *SettingHandler) ListDictionaries(c *gin.Context) {
	dictType := c.Query("type")

	var dictionaries []models.Dictionary
	query := database.DB
	if dictType != "" {
		query = query.Where("type = ?", dictType)
	}

	if err := query.Order("is_default DESC, created_at DESC").Limit(200).Find(&dictionaries).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get dictionaries"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"dictionaries": dictionaries})
}

// UploadDictionary Upload Dictionary
func (h *SettingHandler) UploadDictionary(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 26<<20)
	userID := c.GetString("user_id")

	name := c.PostForm("name")
	dictType := c.PostForm("type")
	description := c.PostForm("description")

	if name == "" || dictType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Name and type are required"})
		return
	}
	if len(name) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Name is too long"})
		return
	}
	validTypes := map[string]bool{"domain": true, "port": true, "file": true, "file_leak": true}
	if !validTypes[dictType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid dictionary type"})
		return
	}

	// Fetch Uploaded Files
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File is required"})
		return
	}
	if file.Size <= 0 || file.Size > 25<<20 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Dictionary file must be between 1 byte and 25 MiB"})
		return
	}

	// Prevent the passage of the path.
	if containsPathTraversal(dictType) || containsPathTraversal(file.Filename) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid type or filename"})
		return
	}

	// Create Dictionary Directory
	dictDir := filepath.Join("./configs/dicts", dictType)
	os.MkdirAll(dictDir, 0755)

	// Save File
	filename := fmt.Sprintf("%d_%s", time.Now().Unix(), file.Filename)
	filePath := filepath.Join(dictDir, filename)

	if err := c.SaveUploadedFile(file, filePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
		return
	}
	if dictType == "file_leak" {
		dictionaryFile, openErr := os.Open(filePath)
		if openErr != nil {
			_ = os.Remove(filePath)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to validate dictionary"})
			return
		}
		validatedCount, validateErr := scanner.ValidateFileLeakDictionary(dictionaryFile)
		dictionaryFile.Close()
		if validateErr != nil {
			_ = os.Remove(filePath)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file leak dictionary: " + validateErr.Error()})
			return
		}
		if validatedCount == 0 {
			_ = os.Remove(filePath)
			c.JSON(http.StatusBadRequest, gin.H{"error": "File leak dictionary is empty"})
			return
		}
	}

	// Number of statistical lines
	lineCount, err := h.countLines(filePath)
	if err != nil {
		lineCount = 0
	}

	// Create Dictionary Records
	dict := models.Dictionary{
		Name:        name,
		Type:        dictType,
		FilePath:    filePath,
		Size:        file.Size,
		LineCount:   lineCount,
		Description: description,
		CreatedBy:   userID,
	}

	if err := database.DB.Create(&dict).Error; err != nil {
		os.Remove(filePath) // Delete File
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create dictionary record"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Dictionary uploaded successfully", "dictionary": dict})
}

// DeleteDictionary Remove Dictionary
func (h *SettingHandler) DeleteDictionary(c *gin.Context) {
	id := c.Param("id")

	var dict models.Dictionary
	if err := database.DB.Where("id = ?", id).First(&dict).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Dictionary not found"})
		return
	}

	if dict.IsDefault {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete default dictionary"})
		return
	}

	// Delete the record first.; Failed file deletion only leaves isolated files that can be cleaned up, It won't destroy the database..
	if err := database.DB.Delete(&dict).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete dictionary"})
		return
	}
	if dict.FilePath != "" {
		_ = os.Remove(dict.FilePath)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Dictionary deleted successfully"})
}

// SetDefaultDictionary Set Default Dictionary
func (h *SettingHandler) SetDefaultDictionary(c *gin.Context) {
	id := c.Param("id")

	var dict models.Dictionary
	if err := database.DB.Where("id = ?", id).First(&dict).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Dictionary not found"})
		return
	}

	tx := database.DB.Begin()
	if tx.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start transaction"})
		return
	}
	if err := tx.Model(&models.Dictionary{}).Where("type = ? AND is_default = ?", dict.Type, true).Update("is_default", false).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to clear previous default"})
		return
	}
	if err := tx.Model(&dict).Update("is_default", true).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set default dictionary"})
		return
	}
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit default dictionary"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Default dictionary set successfully"})
}

// encrypt Encryption Strings
func (h *SettingHandler) encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(h.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt Decrypt String
func (h *SettingHandler) decrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(h.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// countLines Number of statistical documents
func (h *SettingHandler) countLines(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lineCount++
		}
	}

	return lineCount, scanner.Err()
}
