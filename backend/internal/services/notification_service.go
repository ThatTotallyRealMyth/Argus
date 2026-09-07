package services

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/reconmaster/backend/internal/config"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/proxypool"
	"gorm.io/gorm"
)

const maxNotificationResponseBytes = 64 << 10

type NotificationEvent struct {
	Type       string         `json:"type"`
	Title      string         `json:"title"`
	Message    string         `json:"message"`
	Severity   string         `json:"severity"`
	Target     string         `json:"target,omitempty"`
	SourceID   string         `json:"source_id,omitempty"`
	OccurredAt time.Time      `json:"occurred_at"`
	Data       map[string]any `json:"data,omitempty"`
}

type NotificationSelection struct {
	Webhook  bool `json:"enable_webhook"`
	DingTalk bool `json:"enable_dingding"`
	Feishu   bool `json:"enable_feishu"`
}

type NotificationChannelConfig struct {
	WebhookEnabled  bool
	WebhookURL      string
	WebhookSecret   string
	DingTalkEnabled bool
	DingTalkWebhook string
	DingTalkSecret  string
	FeishuEnabled   bool
	FeishuWebhook   string
	FeishuSecret    string
}

type NotificationDeliveryResult struct {
	Channel string `json:"channel"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type NotificationService struct {
	config NotificationChannelConfig
	client *http.Client
}

func NewNotificationService(channelConfig NotificationChannelConfig) *NotificationService {
	return &NotificationService{
		config: channelConfig,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: proxypool.ConfigureTransport(&http.Transport{
				MaxIdleConns:        20,
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     60 * time.Second,
			}),
		},
	}
}

func LoadNotificationService(db *gorm.DB) (*NotificationService, error) {
	var settings []models.Setting
	if err := db.Where("category = ?", models.SettingCategoryNotification).Limit(100).Find(&settings).Error; err != nil {
		return nil, err
	}
	values := make(map[string]string, len(settings))
	for _, setting := range settings {
		value := setting.Value
		if setting.IsEncrypted && value != "" {
			decrypted, err := decryptNotificationSetting(value)
			if err != nil {
				return nil, fmt.Errorf("decrypt notification setting %s: %w", setting.Key, err)
			}
			value = decrypted
		}
		values[setting.Key] = strings.TrimSpace(value)
	}
	return NewNotificationService(NotificationChannelConfig{
		WebhookEnabled:  notificationBool(values[models.SettingKeyWebhookEnabled]),
		WebhookURL:      values[models.SettingKeyWebhookURL],
		WebhookSecret:   values[models.SettingKeyWebhookSecret],
		DingTalkEnabled: notificationBool(values[models.SettingKeyDingDingEnabled]),
		DingTalkWebhook: values[models.SettingKeyDingDingWebhook],
		DingTalkSecret:  values[models.SettingKeyDingDingSecret],
		FeishuEnabled:   notificationBool(values[models.SettingKeyFeishuEnabled]),
		FeishuWebhook:   values[models.SettingKeyFeishuWebhook],
		FeishuSecret:    values[models.SettingKeyFeishuSecret],
	}), nil
}

func AllNotificationChannels() NotificationSelection {
	return NotificationSelection{Webhook: true, DingTalk: true, Feishu: true}
}

func (service *NotificationService) Send(ctx context.Context, event NotificationEvent, selection NotificationSelection) []NotificationDeliveryResult {
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now()
	}
	type delivery struct {
		name    string
		enabled bool
		send    func(context.Context, NotificationEvent) error
	}
	deliveries := []delivery{
		{name: "webhook", enabled: selection.Webhook && service.config.WebhookEnabled && service.config.WebhookURL != "", send: service.sendWebhook},
		{name: "dingtalk", enabled: selection.DingTalk && service.config.DingTalkEnabled && service.config.DingTalkWebhook != "", send: service.sendDingTalk},
		{name: "feishu", enabled: selection.Feishu && service.config.FeishuEnabled && service.config.FeishuWebhook != "", send: service.sendFeishu},
	}
	results := make([]NotificationDeliveryResult, 0, len(deliveries))
	var mutex sync.Mutex
	var wait sync.WaitGroup
	for _, item := range deliveries {
		if !item.enabled {
			continue
		}
		item := item
		wait.Add(1)
		go func() {
			defer wait.Done()
			result := NotificationDeliveryResult{Channel: item.name, Success: true}
			if err := item.send(ctx, event); err != nil {
				result.Success = false
				result.Error = err.Error()
			}
			mutex.Lock()
			results = append(results, result)
			mutex.Unlock()
		}()
	}
	wait.Wait()
	return results
}

func (service *NotificationService) sendWebhook(ctx context.Context, event NotificationEvent) error {
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	headers := map[string]string{"X-Eclipse-Event": event.Type}
	if service.config.WebhookSecret != "" {
		headers["X-Eclipse-Signature"] = "sha256=" + hmacHex(service.config.WebhookSecret, body)
	}
	return service.sendJSON(ctx, service.config.WebhookURL, body, headers)
}

func (service *NotificationService) sendDingTalk(ctx context.Context, event NotificationEvent) error {
	webhook, err := url.Parse(service.config.DingTalkWebhook)
	if err != nil {
		return err
	}
	if service.config.DingTalkSecret != "" {
		timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
		signature := hmacBase64(service.config.DingTalkSecret, []byte(timestamp+"\n"+service.config.DingTalkSecret))
		query := webhook.Query()
		query.Set("timestamp", timestamp)
		query.Set("sign", signature)
		webhook.RawQuery = query.Encode()
	}
	payload := map[string]any{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": event.Title,
			"text":  notificationMarkdown(event),
		},
	}
	body, _ := json.Marshal(payload)
	responseBody, err := service.sendJSONResponse(ctx, webhook.String(), body, nil)
	if err != nil {
		return err
	}
	var result struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if json.Unmarshal(responseBody, &result) == nil && result.ErrCode != 0 {
		return fmt.Errorf("dingtalk returned errcode %d: %s", result.ErrCode, result.ErrMsg)
	}
	return nil
}

func (service *NotificationService) sendFeishu(ctx context.Context, event NotificationEvent) error {
	payload := map[string]any{
		"msg_type": "text",
		"content":  map[string]string{"text": notificationPlainText(event)},
	}
	if service.config.FeishuSecret != "" {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		mac := hmac.New(sha256.New, []byte(service.config.FeishuSecret))
		_, _ = mac.Write([]byte(timestamp + "\n" + service.config.FeishuSecret))
		payload["timestamp"] = timestamp
		payload["sign"] = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	}
	body, _ := json.Marshal(payload)
	responseBody, err := service.sendJSONResponse(ctx, service.config.FeishuWebhook, body, nil)
	if err != nil {
		return err
	}
	var result struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if json.Unmarshal(responseBody, &result) == nil && result.Code != 0 {
		return fmt.Errorf("feishu returned code %d: %s", result.Code, result.Msg)
	}
	return nil
}

func (service *NotificationService) sendJSON(ctx context.Context, endpoint string, body []byte, headers map[string]string) error {
	_, err := service.sendJSONResponse(ctx, endpoint, body, headers)
	return err
}

func (service *NotificationService) sendJSONResponse(ctx context.Context, endpoint string, body []byte, headers map[string]string) ([]byte, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
		return nil, errors.New("notification webhook must be a valid HTTP or HTTPS URL")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "Eclipse-Recon-Notifier/1.0")
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := service.client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		return nil, err
	}
	defer response.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(response.Body, maxNotificationResponseBytes))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return responseBody, fmt.Errorf("notification endpoint returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	return responseBody, nil
}

func notificationPlainText(event NotificationEvent) string {
	parts := []string{event.Title, event.Message, "级别: " + event.Severity}
	if event.Target != "" {
		parts = append(parts, "目标: "+event.Target)
	}
	parts = append(parts, "时间: "+event.OccurredAt.Format("2006-01-02 15:04:05"))
	return strings.Join(parts, "\n")
}

func notificationMarkdown(event NotificationEvent) string {
	return "### " + event.Title + "\n\n" + strings.ReplaceAll(notificationPlainText(event), "\n", "  \n")
}

func notificationBool(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "true" || value == "1" || value == "yes" || value == "on"
}

func hmacHex(secret string, content []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(content)
	return hex.EncodeToString(mac.Sum(nil))
}

func hmacBase64(secret string, content []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(content)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func decryptNotificationSetting(ciphertext string) (string, error) {
	if config.GlobalConfig == nil || len(config.GlobalConfig.Encryption.Key) != 32 {
		return "", errors.New("encryption key is unavailable")
	}
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(config.GlobalConfig.Encryption.Key))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	plaintext, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
