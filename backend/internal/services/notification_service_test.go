package services

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNotificationServiceDeliversWebhookWithSignature(t *testing.T) {
	var received NotificationEvent
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body := make([]byte, request.ContentLength)
		request.Body.Read(body)
		mac := hmac.New(sha256.New, []byte("secret"))
		mac.Write(body)
		expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if request.Header.Get("X-Eclipse-Signature") != expected {
			t.Fatalf("invalid signature: %q", request.Header.Get("X-Eclipse-Signature"))
		}
		if err := json.Unmarshal(body, &received); err != nil {
			t.Fatal(err)
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	service := NewNotificationService(NotificationChannelConfig{WebhookEnabled: true, WebhookURL: server.URL, WebhookSecret: "secret"})
	results := service.Send(context.Background(), NotificationEvent{Type: "monitor_change", Title: "资产变化", Message: "端口发生变化", Severity: "high", OccurredAt: time.Now()}, NotificationSelection{Webhook: true})
	if len(results) != 1 || !results[0].Success || received.Type != "monitor_change" {
		t.Fatalf("unexpected delivery: results=%#v event=%#v", results, received)
	}
}

func TestNotificationServiceDeliversSelectedRobotChannels(t *testing.T) {
	var mutex sync.Mutex
	requests := make(map[string]map[string]any)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		mutex.Lock()
		requests[strings.TrimPrefix(request.URL.Path, "/")] = payload
		mutex.Unlock()
		response.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	service := NewNotificationService(NotificationChannelConfig{
		DingTalkEnabled: true, DingTalkWebhook: server.URL + "/dingtalk", DingTalkSecret: "ding-secret",
		FeishuEnabled: true, FeishuWebhook: server.URL + "/feishu", FeishuSecret: "fei-secret",
	})
	results := service.Send(context.Background(), NotificationEvent{Type: "monitor_error", Title: "监控失败", Message: "timeout", Severity: "high"}, NotificationSelection{DingTalk: true, Feishu: true})
	if len(results) != 2 {
		t.Fatalf("unexpected deliveries: %#v", results)
	}
	for _, result := range results {
		if !result.Success {
			t.Fatalf("delivery failed: %#v", result)
		}
	}
	mutex.Lock()
	defer mutex.Unlock()
	if requests["dingtalk"]["msgtype"] != "markdown" || requests["feishu"]["msg_type"] != "text" || requests["feishu"]["sign"] == "" {
		t.Fatalf("unexpected robot payloads: %#v", requests)
	}
}

func TestNotificationServiceUsesFeishuSignatureFormula(t *testing.T) {
	const secret = "fei-secret"
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var payload struct {
			Timestamp string `json:"timestamp"`
			Sign      string `json:"sign"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(payload.Timestamp + "\n" + secret))
		expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		if payload.Sign != expected {
			t.Fatalf("invalid Feishu signature: got=%q want=%q", payload.Sign, expected)
		}
		response.Write([]byte(`{"code":0,"msg":"ok"}`))
	}))
	defer server.Close()

	service := NewNotificationService(NotificationChannelConfig{
		FeishuEnabled: true, FeishuWebhook: server.URL, FeishuSecret: secret,
	})
	results := service.Send(context.Background(), NotificationEvent{Title: "test"}, NotificationSelection{Feishu: true})
	if len(results) != 1 || !results[0].Success {
		t.Fatalf("unexpected delivery result: %#v", results)
	}
}

func TestNotificationServiceSkipsDisabledChannels(t *testing.T) {
	service := NewNotificationService(NotificationChannelConfig{})
	if results := service.Send(context.Background(), NotificationEvent{Title: "test"}, AllNotificationChannels()); len(results) != 0 {
		t.Fatalf("disabled channels produced deliveries: %#v", results)
	}
}

func TestNotificationServiceRejectsRobotBusinessErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/dingtalk" {
			response.Write([]byte(`{"errcode":310000,"errmsg":"invalid token"}`))
			return
		}
		response.Write([]byte(`{"code":19021,"msg":"sign match fail"}`))
	}))
	defer server.Close()

	service := NewNotificationService(NotificationChannelConfig{
		DingTalkEnabled: true, DingTalkWebhook: server.URL + "/dingtalk",
		FeishuEnabled: true, FeishuWebhook: server.URL + "/feishu",
	})
	results := service.Send(context.Background(), NotificationEvent{Title: "test"}, NotificationSelection{DingTalk: true, Feishu: true})
	if len(results) != 2 {
		t.Fatalf("unexpected deliveries: %#v", results)
	}
	for _, result := range results {
		if result.Success || result.Error == "" {
			t.Fatalf("business error reported as success: %#v", result)
		}
	}
}
