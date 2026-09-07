package mcpserver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/services"
)

const testMCPAPIKey = "01234567890123456789012345678901"

type bearerTransport struct {
	key string
}

type fakeMCPMonitorRunner struct{ id string }

func (runner *fakeMCPMonitorRunner) RunMonitorNow(id string) error {
	runner.id = id
	return nil
}

type fakeMCPScheduledTaskManager struct {
	action string
	id     string
}

func (manager *fakeMCPScheduledTaskManager) Create(services.ScheduledTaskDefinition, string) (*models.ScheduledTask, error) {
	manager.action = "create"
	return &models.ScheduledTask{ID: "schedule-1", IsEnabled: true}, nil
}

func (manager *fakeMCPScheduledTaskManager) Update(id string, _ services.ScheduledTaskDefinition) (*models.ScheduledTask, error) {
	manager.action, manager.id = "update", id
	return &models.ScheduledTask{ID: id, IsEnabled: true}, nil
}

func (manager *fakeMCPScheduledTaskManager) SetEnabled(id string, enabled bool) (*models.ScheduledTask, error) {
	manager.action, manager.id = "disable", id
	return &models.ScheduledTask{ID: id, IsEnabled: enabled}, nil
}

func (manager *fakeMCPScheduledTaskManager) RunNow(id string) (*models.Task, error) {
	manager.action, manager.id = "run", id
	return &models.Task{ID: "task-1"}, nil
}

func (manager *fakeMCPScheduledTaskManager) Delete(id string) error {
	manager.action, manager.id = "delete", id
	return nil
}

func (transport bearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header.Set("Authorization", "Bearer "+transport.key)
	return http.DefaultTransport.RoundTrip(clone)
}

func TestMCPProtocolListsHunterToolsAndCallsCapabilities(t *testing.T) {
	monitorRunner := &fakeMCPMonitorRunner{}
	scheduledTaskManager := &fakeMCPScheduledTaskManager{}
	enterpriseService := services.NewEnterpriseService(nil)
	defer enterpriseService.Close()
	httpServer := httptest.NewServer(NewHandler(&Deps{EnterpriseService: enterpriseService, MonitorRunner: monitorRunner, ScheduledTasks: scheduledTaskManager}, testMCPAPIKey))
	defer httpServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "eclipse-recon-test", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   httpServer.URL,
		HTTPClient: &http.Client{Transport: bearerTransport{key: testMCPAPIKey}},
	}, nil)
	if err != nil {
		t.Fatalf("connect authenticated MCP client: %v", err)
	}
	defer session.Close()

	listed, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list MCP tools: %v", err)
	}
	wanted := map[string]bool{
		"create_scan_task":          false,
		"start_task":                false,
		"list_canonical_assets":     false,
		"get_canonical_asset":       false,
		"list_hunting_leads":        false,
		"update_lead_triage":        false,
		"update_finding_triage":     false,
		"list_asset_changes":        false,
		"get_attack_evidence":       false,
		"execute_lead_poc":          false,
		"get_asset_graph":           false,
		"list_scan_scopes":          false,
		"validate_scan_scope":       false,
		"retry_task":                false,
		"list_enterprise_providers": false,
		"create_enterprise_query":   false,
		"list_enterprise_queries":   false,
		"list_enterprise_assets":    false,
		"sync_enterprise_assets":    false,
		"launch_enterprise_scan":    false,
		"manage_scheduled_scan":     false,
		"manage_dictionary":         false,
		"manage_scanner_settings":   false,
		"manage_proxy_pool":         false,
		"manage_scan_scope":         false,
	}
	for _, tool := range listed.Tools {
		if _, ok := wanted[tool.Name]; ok {
			wanted[tool.Name] = true
		}
		if tool.Name == "list_canonical_assets" {
			if len(tool.InputSchema.Required) != 0 {
				t.Errorf("list_canonical_assets unexpectedly requires optional filters: %#v", tool.InputSchema.Required)
			}
		}
		if tool.Name == "create_scan_task" || tool.Name == "start_task" || tool.Name == "retry_task" {
			if !containsString(tool.InputSchema.Required, "confirm") {
				t.Errorf("%s schema does not require explicit confirmation: %#v", tool.Name, tool.InputSchema.Required)
			}
		}
		if tool.Name == "create_enterprise_query" || tool.Name == "manage_platform_record" {
			if !containsString(tool.InputSchema.Required, "confirm") {
				t.Errorf("%s schema does not require explicit confirmation: %#v", tool.Name, tool.InputSchema.Required)
			}
		}
		if tool.Name == "validate_scan_scope" || tool.Name == "list_scan_scopes" || tool.Name == "get_asset_graph" {
			if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
				t.Errorf("%s annotations do not describe a local read-only operation: %#v", tool.Name, tool.Annotations)
			}
		}
		if tool.Name == "execute_lead_poc" {
			if tool.Annotations == nil || tool.Annotations.DestructiveHint == nil || !*tool.Annotations.DestructiveHint || tool.Annotations.OpenWorldHint == nil || !*tool.Annotations.OpenWorldHint {
				t.Errorf("execute_lead_poc annotations do not disclose external side effects: %#v", tool.Annotations)
			}
		}
		if tool.Name == "retry_task" {
			if tool.Annotations == nil || tool.Annotations.DestructiveHint == nil || *tool.Annotations.DestructiveHint || tool.Annotations.OpenWorldHint == nil || !*tool.Annotations.OpenWorldHint {
				t.Errorf("retry_task annotations do not disclose external network activity: %#v", tool.Annotations)
			}
		}
		if tool.Name == "manage_scheduled_scan" {
			if tool.Annotations == nil || tool.Annotations.DestructiveHint == nil || !*tool.Annotations.DestructiveHint || tool.Annotations.OpenWorldHint == nil || !*tool.Annotations.OpenWorldHint {
				t.Errorf("manage_scheduled_scan annotations do not disclose future network side effects: %#v", tool.Annotations)
			}
		}
		if tool.Name == "manage_dictionary" {
			if tool.Annotations == nil || tool.Annotations.DestructiveHint == nil || !*tool.Annotations.DestructiveHint || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
				t.Errorf("manage_dictionary annotations do not describe local destructive operations: %#v", tool.Annotations)
			}
		}
		if tool.Name == "manage_scan_scope" {
			if !containsString(tool.InputSchema.Required, "confirm") {
				t.Errorf("manage_scan_scope schema does not require explicit confirmation: %#v", tool.InputSchema.Required)
			}
			if tool.Annotations == nil || tool.Annotations.DestructiveHint == nil || !*tool.Annotations.DestructiveHint || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
				t.Errorf("manage_scan_scope annotations do not describe a local authorization-boundary change: %#v", tool.Annotations)
			}
		}
		if tool.Name == "manage_scanner_settings" {
			if tool.Annotations == nil || tool.Annotations.DestructiveHint == nil || *tool.Annotations.DestructiveHint || !tool.Annotations.IdempotentHint || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
				t.Errorf("manage_scanner_settings annotations do not describe idempotent local updates: %#v", tool.Annotations)
			}
		}
		if tool.Name == "manage_proxy_pool" {
			if tool.Annotations == nil || tool.Annotations.DestructiveHint == nil || !*tool.Annotations.DestructiveHint || tool.Annotations.OpenWorldHint == nil || !*tool.Annotations.OpenWorldHint {
				t.Errorf("manage_proxy_pool annotations do not disclose destructive and external operations: %#v", tool.Annotations)
			}
		}
		if tool.Name == "update_finding_triage" {
			if tool.Annotations == nil || tool.Annotations.DestructiveHint == nil || *tool.Annotations.DestructiveHint || !tool.Annotations.IdempotentHint || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
				t.Errorf("update_finding_triage annotations do not describe an idempotent local update: %#v", tool.Annotations)
			}
		}
	}
	for name, found := range wanted {
		if !found {
			t.Errorf("missing hunter MCP tool %q", name)
		}
	}

	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "platform_capabilities", Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("call platform_capabilities: %v", err)
	}
	if result.IsError || len(result.Content) == 0 {
		t.Fatalf("unexpected capability result: %#v", result)
	}
	graphResult, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "get_asset_graph", Arguments: map[string]any{"task_id": ""}})
	if err != nil {
		t.Fatalf("call scoped asset graph: %v", err)
	}
	if !graphResult.IsError {
		t.Fatalf("asset graph accepted a missing task scope: %#v", graphResult)
	}
	previewResult, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "validate_scan_scope", Arguments: map[string]any{
		"name": "preview", "allow_rules": []string{"*.example.test"}, "deny_rules": []string{"admin.example.test"}, "target": "api.example.test",
	}})
	if err != nil || previewResult.IsError {
		t.Fatalf("temporary scan scope preview failed: result=%#v err=%v", previewResult, err)
	}
	unsafeCreate, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "create_scan_task", Arguments: map[string]any{"target": "example.test"}})
	if err == nil && (unsafeCreate == nil || !unsafeCreate.IsError) {
		t.Fatalf("scan creation did not require confirmation: result=%#v err=%v", unsafeCreate, err)
	}
	unsafeStart, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "start_task", Arguments: map[string]any{"task_id": "task-1"}})
	if err == nil && (unsafeStart == nil || !unsafeStart.IsError) {
		t.Fatalf("task start did not require confirmation: result=%#v err=%v", unsafeStart, err)
	}
	findingResult, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "update_finding_triage", Arguments: map[string]any{
		"vulnerability_id": "missing", "status": "invalid",
	}})
	if err != nil {
		t.Fatalf("call finding triage tool: %v", err)
	}
	if !findingResult.IsError {
		t.Fatalf("finding triage accepted an invalid lifecycle state: %#v", findingResult)
	}
	unsafeMonitor, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "manage_platform_record", Arguments: map[string]any{"resource": "monitors", "action": "run", "id": "monitor-1", "confirm": false}})
	if err != nil || !unsafeMonitor.IsError || monitorRunner.id != "" {
		t.Fatalf("monitor run did not require confirmation: result=%#v id=%q err=%v", unsafeMonitor, monitorRunner.id, err)
	}
	runResult, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "manage_platform_record", Arguments: map[string]any{"resource": "monitors", "action": "run", "id": "monitor-1", "confirm": true}})
	if err != nil || runResult.IsError || monitorRunner.id != "monitor-1" {
		t.Fatalf("run monitor via MCP: result=%#v id=%q err=%v", runResult, monitorRunner.id, err)
	}
	unsafeMonitorCreate, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "manage_platform_record", Arguments: map[string]any{"resource": "monitors", "action": "create", "confirm": false, "data": map[string]any{"name": "watch", "target": "example.test", "type": "domain", "status": "active", "interval": 3600}}})
	if err != nil || !unsafeMonitorCreate.IsError {
		t.Fatalf("monitor creation did not require confirmation: result=%#v err=%v", unsafeMonitorCreate, err)
	}
	unsafeEnterpriseQuery, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "create_enterprise_query", Arguments: map[string]any{"keyword": "example", "confirm": false}})
	if err != nil || !unsafeEnterpriseQuery.IsError {
		t.Fatalf("enterprise query did not require confirmation: result=%#v err=%v", unsafeEnterpriseQuery, err)
	}
	unsafeSchedule, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "manage_scheduled_scan", Arguments: map[string]any{"action": "run", "id": "schedule-1"}})
	if err != nil || !unsafeSchedule.IsError || scheduledTaskManager.action != "" {
		t.Fatalf("scheduled run did not require confirmation: result=%#v action=%q err=%v", unsafeSchedule, scheduledTaskManager.action, err)
	}
	unsafeRetry, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "retry_task", Arguments: map[string]any{"task_id": "task-1"}})
	if err == nil && (unsafeRetry == nil || !unsafeRetry.IsError) {
		t.Fatalf("task retry did not require confirmation: result=%#v err=%v", unsafeRetry, err)
	}
	unsafeDictionary, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "manage_dictionary", Arguments: map[string]any{"action": "upload", "name": "test", "type": "domain", "content": "www"}})
	if err != nil || !unsafeDictionary.IsError {
		t.Fatalf("dictionary upload did not require confirmation: result=%#v err=%v", unsafeDictionary, err)
	}
	unsafeScope, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "manage_scan_scope", Arguments: map[string]any{"action": "create", "name": "test", "allow_rules": []string{"example.test"}}})
	if err == nil && (unsafeScope == nil || !unsafeScope.IsError) {
		t.Fatalf("scan scope creation did not require confirmation: result=%#v err=%v", unsafeScope, err)
	}
	unsafeSettings, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "manage_scanner_settings", Arguments: map[string]any{"action": "update", "settings": map[string]any{"file_leak_concurrency": "10"}}})
	if err != nil || !unsafeSettings.IsError {
		t.Fatalf("scanner settings update did not require confirmation: result=%#v err=%v", unsafeSettings, err)
	}
	unsafeProxy, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "manage_proxy_pool", Arguments: map[string]any{"action": "test", "id": "proxy-1"}})
	if err != nil || !unsafeProxy.IsError {
		t.Fatalf("proxy test did not require confirmation: result=%#v err=%v", unsafeProxy, err)
	}
	disableSchedule, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "manage_scheduled_scan", Arguments: map[string]any{"action": "disable", "id": "schedule-1"}})
	if err != nil || disableSchedule.IsError || scheduledTaskManager.action != "disable" || scheduledTaskManager.id != "schedule-1" {
		t.Fatalf("disable scheduled scan via MCP: result=%#v action=%q id=%q err=%v", disableSchedule, scheduledTaskManager.action, scheduledTaskManager.id, err)
	}
}

func TestMCPProtocolRejectsUnauthenticatedClient(t *testing.T) {
	httpServer := httptest.NewServer(NewHandler(&Deps{}, testMCPAPIKey))
	defer httpServer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "unauthenticated-test", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: httpServer.URL}, nil)
	if session != nil {
		session.Close()
	}
	if err == nil {
		t.Fatal("expected unauthenticated MCP initialization to fail")
	}
}

func TestNewHandlerFailsClosedWithoutAPIKey(t *testing.T) {
	handler := NewHandler(&Deps{}, "")
	request := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", response.Code)
	}
}

func TestCheckAPIKey(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	request.Header.Set("Authorization", "Bearer "+testMCPAPIKey)
	if !checkAPIKey(request, testMCPAPIKey) {
		t.Fatal("valid key rejected")
	}
	if checkAPIKey(request, "01234567890123456789012345678902") {
		t.Fatal("invalid key accepted")
	}
}

func TestNormalizePage(t *testing.T) {
	page, size := normalizePage(0, 1000)
	if page != 1 || size != 100 {
		t.Fatalf("unexpected normalized pagination: page=%d size=%d", page, size)
	}
}

func TestMCPRateLimiterCleansExpiredClientsAtCapacity(t *testing.T) {
	limiter := &mcpRateLimiter{clients: make(map[string]rateWindow, 10000)}
	expired := time.Now().Add(-2 * time.Minute)
	for index := 0; index < 10000; index++ {
		limiter.clients[fmt.Sprintf("192.0.2.%d", index)] = rateWindow{start: expired, count: 1}
	}
	handler := limiter.middleware(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	request.RemoteAddr = "198.51.100.5:4000"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("expired rate limiter capacity was not reclaimed: %d", response.Code)
	}
}

func TestMCPRateLimiterRejectsNewClientsAtActiveCapacity(t *testing.T) {
	limiter := &mcpRateLimiter{clients: make(map[string]rateWindow, 10000)}
	active := time.Now()
	for index := 0; index < 10000; index++ {
		limiter.clients[fmt.Sprintf("192.0.2.%d", index)] = rateWindow{start: active, count: 1}
	}
	handler := limiter.middleware(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	request.RemoteAddr = "198.51.100.5:4000"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || len(limiter.clients) != 10000 {
		t.Fatalf("active limiter capacity was not bounded: status=%d clients=%d", response.Code, len(limiter.clients))
	}
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
