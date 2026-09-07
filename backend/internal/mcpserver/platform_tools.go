package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/scanner"
	"github.com/reconmaster/backend/internal/services"
	"gorm.io/gorm"
)

type PlatformListInput struct {
	Resource string `json:"resource" jsonschema:"required,资源类型: monitors, monitor_results, github_monitors, github_results, scheduled_tasks, scheduled_logs, policies, pocs, fingerprints, sensitive_rules, sensitive_matches, tags, dictionaries, settings"`
	ParentID string `json:"parent_id" jsonschema:"父级 ID，例如监控 ID 或计划任务 ID"`
	TaskID   string `json:"task_id" jsonschema:"任务 ID 过滤"`
	Search   string `json:"search" jsonschema:"名称、目标或内容搜索"`
	Page     int    `json:"page" jsonschema:"页码，默认1"`
	PageSize int    `json:"page_size" jsonschema:"每页数量，默认20，最大100"`
}

type AssetProfileInput struct {
	AssetType string `json:"asset_type" jsonschema:"required,资产类型: domain, ip, site, port"`
	AssetID   string `json:"asset_id" jsonschema:"required,资产 ID"`
	Depth     int    `json:"depth" jsonschema:"关系图深度，默认2，最大3"`
}

type CSegmentInput struct {
	TaskID string `json:"task_id" jsonschema:"required,任务 ID"`
	IP     string `json:"ip" jsonschema:"required,IPv4 地址"`
}

type ManageRecordInput struct {
	Resource string         `json:"resource" jsonschema:"required,资源类型: policies, monitors, github_monitors, pocs, fingerprints, sensitive_rules, tags"`
	Action   string         `json:"action" jsonschema:"required,操作: create, update, delete, toggle, run"`
	ID       string         `json:"id,omitempty" jsonschema:"update/delete/toggle/run 时必填"`
	Data     map[string]any `json:"data,omitempty" jsonschema:"create/update 的字段对象"`
	Confirm  bool           `json:"confirm" jsonschema:"required,监控变更/运行和所有删除操作必须明确设为 true"`
}

type ManageScheduledScanInput struct {
	Action      string             `json:"action" jsonschema:"required,操作: create, update, enable, disable, run, delete"`
	ID          string             `json:"id,omitempty" jsonschema:"update/enable/disable/run/delete 时必填"`
	Name        string             `json:"name,omitempty" jsonschema:"计划任务名称；create/update 时必填"`
	Description string             `json:"description,omitempty" jsonschema:"计划任务说明"`
	Target      string             `json:"target,omitempty" jsonschema:"扫描目标；create/update 时必填"`
	CronType    string             `json:"cron_type,omitempty" jsonschema:"运行周期: once, daily, weekly, monthly, custom"`
	CronExpr    string             `json:"cron_expr,omitempty" jsonschema:"custom 使用六段 Cron: 秒 分 时 日 月 周；最短周期一分钟"`
	PolicyID    string             `json:"policy_id,omitempty" jsonschema:"可选扫描策略 ID"`
	ScopeID     string             `json:"scope_id,omitempty" jsonschema:"可选授权扫描范围 ID；空值使用默认范围"`
	Options     models.TaskOptions `json:"options,omitempty" jsonschema:"扫描选项；端口扫描始终开启"`
	Confirm     bool               `json:"confirm,omitempty" jsonschema:"create/update/enable/run/delete 必须明确设为 true"`
}

type HTTPTransactionListInput struct {
	TaskID        string `json:"task_id" jsonschema:"任务 ID 过滤"`
	URL           string `json:"url" jsonschema:"URL 关键词过滤"`
	Source        string `json:"source" jsonschema:"来源过滤，例如 crawler,file_leak"`
	StatusCode    int    `json:"status_code" jsonschema:"响应状态码过滤"`
	ContentType   string `json:"content_type" jsonschema:"响应 Content-Type 过滤"`
	BodySearch    string `json:"body_search" jsonschema:"响应正文关键词过滤；只匹配已存储文本正文"`
	BodyStored    string `json:"body_stored" jsonschema:"true/false，是否存储了响应正文"`
	BodyTruncated string `json:"body_truncated" jsonschema:"true/false，响应正文是否被截断"`
	MinLength     int64  `json:"min_length" jsonschema:"最小响应长度"`
	MaxLength     int64  `json:"max_length" jsonschema:"最大响应长度，0表示不限制"`
	SortBy        string `json:"sort_by" jsonschema:"排序字段: created_at,url,response_status_code,response_content_length,response_time_ms"`
	SortOrder     string `json:"sort_order" jsonschema:"排序方向: asc或desc"`
	Page          int    `json:"page" jsonschema:"页码，默认1"`
	PageSize      int    `json:"page_size" jsonschema:"每页数量，默认20，最大100"`
}

type HTTPTransactionIDInput struct {
	ID string `json:"id" jsonschema:"required,HTTP 记录 ID"`
}

func RegisterPlatformTools(server *mcp.Server, deps *Deps) {
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: boolPtr(false)}
	RegisterLibraryTools(server)
	RegisterHunterTools(server)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "platform_capabilities",
		Description: "返回 Eclipse Recon MCP 已覆盖的猎人工作流、功能域、资源名称和操作约束。需要规划操作时先调用此工具。",
		Annotations: readOnly,
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		result := map[string]any{
			"task_operations":            []string{"list_scan_scopes", "validate_scan_scope", "create_and_start", "list", "get", "start", "retry", "cancel"},
			"scan_scope_operations":      []string{"list", "preview", "create", "update", "set_default", "delete"},
			"scheduled_scan_operations":  []string{"list", "create", "update", "enable", "disable", "run", "delete"},
			"enterprise_operations":      []string{"providers", "create_query", "list_queries", "list_assets", "sync_catalog", "launch_scan"},
			"monitor_operations":         []string{"create", "update", "pause", "resume", "run", "results", "delete"},
			"dictionary_operations":      []string{"list", "upload", "set_default", "delete"},
			"scanner_setting_operations": []string{"get", "update"},
			"proxy_pool_operations":      []string{"list", "create", "batch_create", "update", "toggle", "delete", "test", "test_all"},
			"hunter_workflow":            []string{"list_canonical_assets", "list_hunting_leads", "get_attack_evidence", "update_lead_triage", "execute_lead_poc"},
			"asset_operations":           []string{"canonical_inventory", "canonical_workbench", "changes", "hunting_leads", "triage", "evidence", "poc_validation", "legacy_list_paginated", "stats", "profile", "relations", "graph", "c_segment", "http_transaction_list", "http_transaction_detail"},
			"readable_resources":         []string{"monitors", "monitor_results", "github_monitors", "github_results", "scheduled_tasks", "scheduled_logs", "policies", "pocs", "fingerprints", "sensitive_rules", "sensitive_matches", "tags", "dictionaries", "settings", "http_transactions"},
			"manageable_resources":       []string{"policies", "monitors", "github_monitors", "pocs", "fingerprints", "sensitive_rules", "tags"},
			"domain_plugins":             []string{"crtsh", "certspotter", "alienvault", "hackertarget", "threatcrowd", "virustotal", "fofa", "hunter", "quake", "zoomeye", "custom_space_api"},
			"api_setting_keys":           []string{"fofa_email", "fofa_key", "fofa_enabled", "hunter_api_key", "hunter_key", "hunter_enabled", "quake_api_key", "quake_enabled", "zoomeye_api_key", "zoomeye_enabled", "shodan_api_key", "shodan_enabled", "virustotal_api_key", "virustotal_enabled", "github_token", "github_enabled", "custom_space_api_url", "custom_space_api_headers", "custom_space_api_enabled", "enterprise_icp_api_url", "enterprise_icp_api_headers", "enterprise_icp_enabled"},
			"custom_space_api":           map[string]any{"url_template_key": "custom_space_api_url", "headers_key": "custom_space_api_headers", "placeholder": "{domain}", "response_parsing": "extract domains from JSON fields, arrays, or plain text"},
			"enterprise_discovery":       map[string]any{"provider": "icp_query", "query_types": []string{"web", "app", "mapp", "kapp"}, "scan_limit": 2000, "scan_requires_confirmation": true},
			"limits":                     map[string]any{"default_page_size": 20, "max_page_size": 100, "lead_candidate_assets": hunterLeadCandidateLimit, "graph_nodes": 500, "graph_edges": 1000},
			"invariants":                 []string{"default or explicit scan scopes are revalidated before queueing, monitor network I/O, redirects, scheduled scan enablement, and execution", "deny scope rules override allow rules", "scan scope mutations require confirm=true because they change the authorization boundary", "scheduled scan create/update/enable/run/delete require confirm=true", "custom schedules run no more frequently than once per minute", "GitHub leak monitors persist only redacted confirmed evidence", "canonical assets are deduplicated across tasks and enterprise queries", "enterprise catalog sync is idempotent and preserves origin_type provenance", "lead triage updates all supplied cluster references", "PoC execution requires confirm=true and writes an execution log", "monitor creation, mutation, and runs require confirm=true", "port scanning is mandatory", "dictionary, scanner setting, and proxy mutations require confirm=true", "proxy tests disclose external network activity and require confirmation", "proxy passwords and encrypted setting values are never returned", "all destructive actions require confirm=true"},
			"write_schemas": map[string]any{
				"pocs": map[string]any{
					"required": []string{"name", "category", "severity", "poc_type", "poc_content"},
					"enums":    map[string][]string{"severity": {"critical", "high", "medium", "low", "info"}, "poc_type": {"nuclei", "custom"}, "match_mode": {"exact", "fuzzy", "keyword"}},
					"example":  map[string]any{"name": "Example CVE check", "category": "web", "severity": "high", "poc_type": "nuclei", "poc_content": "id: example\ninfo:\n  name: Example check\n  severity: high", "match_mode": "fuzzy"},
				},
				"fingerprints": map[string]any{
					"required": []string{"name", "category", "dsl"},
					"example":  map[string]any{"name": "Example product", "category": "web", "dsl": []string{"contains(body, 'example')"}},
				},
				"monitors": map[string]any{
					"required": []string{"name", "type", "status", "interval"},
					"enums":    map[string][]string{"type": {"domain", "ip", "site", "github", "wih", "cve"}, "status": {"active", "paused", "stopped"}},
					"example":  map[string]any{"name": "Daily domain monitor", "target": "example.com", "scope_id": "optional-scan-scope-uuid", "type": "domain", "status": "active", "interval": 3600},
				},
				"github_monitors": map[string]any{
					"required": []string{"name", "keywords", "search_type", "interval"},
					"enums":    map[string][]string{"search_type": {"code", "repository", "issue"}},
				},
				"sensitive_rules": map[string]any{
					"required": []string{"name", "type", "severity", "pattern"},
					"enums":    map[string][]string{"type": {"regex", "keyword"}, "severity": {"high", "medium", "low"}},
				},
				"tags": map[string]any{"required": []string{"name"}, "format": map[string]string{"color": "#RRGGBB"}, "example": map[string]any{"name": "critical", "color": "#FF5C7A"}},
			},
		}
		return jsonResult(result)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_platform_data",
		Description: "分页读取平台管理数据，包括监控、计划任务、PoC、指纹、敏感规则、标签、字典和设置。",
		Annotations: readOnly,
	}, func(ctx context.Context, req *mcp.CallToolRequest, input PlatformListInput) (*mcp.CallToolResult, any, error) {
		result, err := listPlatformData(input)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(result)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_asset_profile",
		Description: "获取单个域名、IP、端口或站点的风险画像和关联统计。",
		Annotations: readOnly,
	}, func(ctx context.Context, req *mcp.CallToolRequest, input AssetProfileInput) (*mcp.CallToolResult, any, error) {
		profile, err := services.NewAssetProfileService().GetAssetProfile(input.AssetType, input.AssetID)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(profile)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_asset_relations",
		Description: "获取单个资产的直接关系，结果有硬上限以保护客户端。",
		Annotations: readOnly,
	}, func(ctx context.Context, req *mcp.CallToolRequest, input AssetProfileInput) (*mcp.CallToolResult, any, error) {
		relations, err := services.NewAssetProfileService().GetAssetRelations(input.AssetType, input.AssetID)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(map[string]any{"items": relations, "count": len(relations)})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_asset_profile_graph",
		Description: "获取指定资产出发的有限深度关系图，最多500节点和1000条边。",
		Annotations: readOnly,
	}, func(ctx context.Context, req *mcp.CallToolRequest, input AssetProfileInput) (*mcp.CallToolResult, any, error) {
		depth := input.Depth
		if depth < 1 {
			depth = 2
		}
		if depth > 3 {
			depth = 3
		}
		graph, err := services.NewAssetProfileService().GetAssetGraph(input.AssetType, input.AssetID, depth)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(graph)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "analyze_c_segment",
		Description: "按任务分析 IPv4 所在 C 段的已有资产、端口和站点分布。",
		Annotations: readOnly,
	}, func(ctx context.Context, req *mcp.CallToolRequest, input CSegmentInput) (*mcp.CallToolResult, any, error) {
		if strings.TrimSpace(input.TaskID) == "" {
			return errResult(fmt.Errorf("task_id is required for scoped C segment analysis")), nil, nil
		}
		result, err := services.NewAssetProfileService().AnalyzeCSegment(input.TaskID, input.IP)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(result)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "manage_platform_record",
		Description: "创建、更新、切换、删除平台记录，或立即运行监控。监控变更、监控运行和所有删除操作必须 confirm=true。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(true)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ManageRecordInput) (*mcp.CallToolResult, any, error) {
		log.Printf("[MCP audit] resource=%s action=%s id=%s", input.Resource, input.Action, input.ID)
		if input.Action == "run" {
			if input.Resource != "monitors" || strings.TrimSpace(input.ID) == "" {
				return errResult(fmt.Errorf("run requires resource=monitors and id")), nil, nil
			}
			if deps == nil || deps.MonitorRunner == nil {
				return errResult(fmt.Errorf("monitor runner is unavailable")), nil, nil
			}
			if !input.Confirm {
				return errResult(fmt.Errorf("monitor run requires confirm=true")), nil, nil
			}
			if err := deps.MonitorRunner.RunMonitorNow(input.ID); err != nil {
				return errResult(err), nil, nil
			}
			return jsonResult(map[string]any{"action": "queued", "resource": "monitors", "id": input.ID})
		}
		if (input.Resource == "monitors" || input.Resource == "github_monitors") && !input.Confirm {
			return errResult(fmt.Errorf("monitor mutation requires confirm=true")), nil, nil
		}
		result, err := managePlatformRecord(input)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(result)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "manage_scheduled_scan",
		Description: "创建、修改、启停、立即运行或删除自动扫描计划。所有会创建或扩大外部网络访问的操作都要求 confirm=true，并在执行前重新校验授权范围。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(true)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ManageScheduledScanInput) (*mcp.CallToolResult, any, error) {
		manager := scheduledTaskManager(deps)
		if manager == nil {
			return errResult(fmt.Errorf("scheduled task manager is unavailable")), nil, nil
		}
		action := strings.ToLower(strings.TrimSpace(input.Action))
		id := strings.TrimSpace(input.ID)
		log.Printf("[MCP audit] resource=scheduled_tasks action=%s id=%s", action, id)
		if action != "disable" && !input.Confirm {
			return errResult(fmt.Errorf("%s requires confirm=true", action)), nil, nil
		}
		if action != "create" && id == "" {
			return errResult(fmt.Errorf("%s requires id", action)), nil, nil
		}
		definition := services.ScheduledTaskDefinition{
			Name: input.Name, Description: input.Description, CronType: input.CronType,
			CronExpr: input.CronExpr, PolicyID: input.PolicyID, ScopeID: input.ScopeID,
			TaskOptions: input.Options,
		}
		definition.TaskOptions.Target = input.Target
		switch action {
		case "create":
			task, err := manager.Create(definition, "mcp")
			if err != nil {
				return errResult(publicScheduledTaskError(err)), nil, nil
			}
			return jsonResult(map[string]any{"action": "created", "scheduled_task": task})
		case "update":
			task, err := manager.Update(id, definition)
			if err != nil {
				return errResult(publicScheduledTaskError(err)), nil, nil
			}
			return jsonResult(map[string]any{"action": "updated", "scheduled_task": task})
		case "enable", "disable":
			task, err := manager.SetEnabled(id, action == "enable")
			if err != nil {
				return errResult(publicScheduledTaskError(err)), nil, nil
			}
			return jsonResult(map[string]any{"action": action + "d", "scheduled_task": task})
		case "run":
			task, err := manager.RunNow(id)
			if err != nil {
				return errResult(publicScheduledTaskError(err)), nil, nil
			}
			return jsonResult(map[string]any{"action": "queued", "scheduled_task_id": id, "task": task})
		case "delete":
			if err := manager.Delete(id); err != nil {
				return errResult(publicScheduledTaskError(err)), nil, nil
			}
			return jsonResult(map[string]any{"action": "deleted", "scheduled_task_id": id})
		default:
			return errResult(fmt.Errorf("unsupported scheduled scan action: %s", action)), nil, nil
		}
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_http_transactions",
		Description: "分页筛选扫描保存的 HTTP 请求/响应记录；列表只返回摘要，不返回正文，避免大结果卡死客户端。",
		Annotations: readOnly,
	}, func(ctx context.Context, req *mcp.CallToolRequest, input HTTPTransactionListInput) (*mcp.CallToolResult, any, error) {
		result, err := listHTTPTransactions(input)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(result)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_http_transaction",
		Description: "按 ID 读取单条 HTTP 请求/响应详情，包含已保存的响应正文。",
		Annotations: readOnly,
	}, func(ctx context.Context, req *mcp.CallToolRequest, input HTTPTransactionIDInput) (*mcp.CallToolResult, any, error) {
		var item models.HTTPTransaction
		if err := database.DB.First(&item, "id = ?", input.ID).Error; err != nil {
			return errResult(fmt.Errorf("HTTP transaction not found: %s", input.ID)), nil, nil
		}
		return jsonResult(item)
	})
}

func scheduledTaskManager(deps *Deps) ScheduledTaskManager {
	if deps == nil {
		return nil
	}
	if deps.ScheduledTasks != nil {
		return deps.ScheduledTasks
	}
	if deps.TaskService == nil {
		return nil
	}
	return services.NewScheduledTaskService(deps.TaskService)
}

func publicScheduledTaskError(err error) error {
	if services.IsScheduledTaskInputError(err) {
		return err
	}
	return fmt.Errorf("scheduled task operation failed")
}

func listPlatformData(input PlatformListInput) (map[string]any, error) {
	page, pageSize := normalizePage(input.Page, input.PageSize)
	query := database.DB
	var items any
	var err error

	switch input.Resource {
	case "monitors":
		q := searchLike(query.Model(&models.Monitor{}), input.Search, "name", "target")
		items, err = queryPage[models.Monitor](q, page, pageSize)
	case "monitor_results":
		q := query.Model(&models.MonitorResult{})
		if input.ParentID != "" {
			q = q.Where("monitor_id = ?", input.ParentID)
		}
		items, err = queryPage[models.MonitorResult](q, page, pageSize)
	case "github_monitors":
		q := searchLike(query.Model(&models.GitHubMonitor{}), input.Search, "name", "keywords", "repository")
		items, err = queryPage[models.GitHubMonitor](q, page, pageSize)
	case "github_results":
		q := query.Model(&models.GitHubMonitorResult{})
		if input.ParentID != "" {
			q = q.Where("monitor_id = ?", input.ParentID)
		}
		items, err = queryPage[models.GitHubMonitorResult](q, page, pageSize)
	case "scheduled_tasks":
		q := searchLike(query.Model(&models.ScheduledTask{}), input.Search, "name", "description")
		items, err = queryPage[models.ScheduledTask](q, page, pageSize)
	case "scheduled_logs":
		q := query.Model(&models.ScheduledTaskLog{})
		if input.ParentID != "" {
			q = q.Where("scheduled_task_id = ?", input.ParentID)
		}
		items, err = queryPage[models.ScheduledTaskLog](q, page, pageSize)
	case "policies":
		items, err = queryPage[models.Policy](searchLike(query.Model(&models.Policy{}), input.Search, "name", "description"), page, pageSize)
	case "pocs":
		items, err = queryPage[models.PoC](searchLike(query.Model(&models.PoC{}), input.Search, "name", "cve", "product", "affected_versions", "tags"), page, pageSize)
	case "fingerprints":
		items, err = queryPage[models.Fingerprint](searchLike(query.Model(&models.Fingerprint{}), input.Search, "name", "category"), page, pageSize)
	case "sensitive_rules":
		items, err = queryPage[models.SensitiveRule](searchLike(query.Model(&models.SensitiveRule{}), input.Search, "name", "category"), page, pageSize)
	case "sensitive_matches":
		q := query.Model(&models.SensitiveMatch{})
		if input.TaskID != "" {
			q = q.Where("task_id = ?", input.TaskID)
		}
		items, err = queryPage[models.SensitiveMatch](q, page, pageSize)
	case "http_transactions":
		items, err = queryHTTPTransactionPage(HTTPTransactionListInput{
			TaskID: input.TaskID, URL: input.Search, Page: page, PageSize: pageSize,
		})
	case "tags":
		items, err = queryPage[models.AssetTag](searchLike(query.Model(&models.AssetTag{}), input.Search, "name", "category"), page, pageSize)
	case "dictionaries":
		items, err = queryPage[models.Dictionary](searchLike(query.Model(&models.Dictionary{}), input.Search, "name", "type"), page, pageSize)
	case "settings":
		var settings []models.Setting
		result, queryErr := queryPage[models.Setting](searchLike(query.Model(&models.Setting{}), input.Search, "key", "category"), page, pageSize)
		if queryErr != nil {
			err = queryErr
			break
		}
		settings = result.Items
		for i := range settings {
			settings[i].Value = "***"
		}
		result.Items = settings
		items = result
	default:
		return nil, fmt.Errorf("unsupported resource: %s", input.Resource)
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"resource": input.Resource, "page": page, "page_size": pageSize, "result": items}, nil
}

type pageResult[T any] struct {
	Items []T   `json:"items"`
	Total int64 `json:"total"`
}

func queryPage[T any](query *gorm.DB, page, pageSize int) (pageResult[T], error) {
	var result pageResult[T]
	if err := query.Count(&result.Total).Error; err != nil {
		return result, err
	}
	if err := query.Order("created_at DESC").Limit(pageSize).Offset((page - 1) * pageSize).Find(&result.Items).Error; err != nil {
		return result, err
	}
	return result, nil
}

func listHTTPTransactions(input HTTPTransactionListInput) (map[string]any, error) {
	page, pageSize := normalizePage(input.Page, input.PageSize)
	result, err := queryHTTPTransactionPage(HTTPTransactionListInput{
		TaskID:        input.TaskID,
		URL:           input.URL,
		Source:        input.Source,
		StatusCode:    input.StatusCode,
		ContentType:   input.ContentType,
		BodySearch:    input.BodySearch,
		BodyStored:    input.BodyStored,
		BodyTruncated: input.BodyTruncated,
		MinLength:     input.MinLength,
		MaxLength:     input.MaxLength,
		SortBy:        input.SortBy,
		SortOrder:     input.SortOrder,
		Page:          page,
		PageSize:      pageSize,
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"resource": "http_transactions", "page": page, "page_size": pageSize, "result": result}, nil
}

func queryHTTPTransactionPage(input HTTPTransactionListInput) (pageResult[models.HTTPTransaction], error) {
	page, pageSize := normalizePage(input.Page, input.PageSize)
	query := database.DB.Model(&models.HTTPTransaction{})
	if input.TaskID != "" {
		query = query.Where("task_id = ?", input.TaskID)
	}
	if input.URL != "" {
		query = query.Where("url LIKE ?", "%"+input.URL+"%")
	}
	if input.Source != "" {
		query = query.Where("source = ?", input.Source)
	}
	if input.StatusCode > 0 {
		query = query.Where("response_status_code = ?", input.StatusCode)
	}
	if input.ContentType != "" {
		query = query.Where("response_content_type LIKE ?", "%"+input.ContentType+"%")
	}
	if input.BodySearch != "" {
		query = query.Where("response_body LIKE ?", "%"+input.BodySearch+"%")
	}
	if value, ok := parseOptionalBool(input.BodyStored); ok {
		query = query.Where("response_body_stored = ?", value)
	}
	if value, ok := parseOptionalBool(input.BodyTruncated); ok {
		query = query.Where("response_body_truncated = ?", value)
	}
	if input.MinLength > 0 {
		query = query.Where("response_content_length >= ?", input.MinLength)
	}
	if input.MaxLength > 0 {
		query = query.Where("response_content_length <= ?", input.MaxLength)
	}

	var result pageResult[models.HTTPTransaction]
	if err := query.Count(&result.Total).Error; err != nil {
		return result, err
	}
	sortBy := input.SortBy
	allowed := map[string]bool{"created_at": true, "url": true, "response_status_code": true, "response_content_length": true, "response_time_ms": true}
	if !allowed[sortBy] {
		sortBy = "created_at"
	}
	sortOrder := strings.ToLower(input.SortOrder)
	if sortOrder != "asc" {
		sortOrder = "desc"
	}
	err := query.Select("id", "task_id", "crawler_result_id", "url", "method", "source", "response_status_code", "response_content_type", "response_content_length", "response_body_stored", "response_body_truncated", "response_body_sha256", "response_time_ms", "created_at").
		Order(sortBy + " " + sortOrder).
		Limit(pageSize).
		Offset((page - 1) * pageSize).
		Find(&result.Items).Error
	return result, err
}

func parseOptionalBool(value string) (bool, bool) {
	if value == "" {
		return false, false
	}
	parsed, err := strconv.ParseBool(value)
	if err == nil {
		return parsed, true
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes", "1":
		return true, true
	case "no", "0":
		return false, true
	default:
		return false, false
	}
}

func searchLike(query *gorm.DB, search string, fields ...string) *gorm.DB {
	search = strings.TrimSpace(search)
	if search == "" || len(fields) == 0 {
		return query
	}
	clause := make([]string, len(fields))
	args := make([]any, len(fields))
	for i, field := range fields {
		clause[i] = field + " LIKE ?"
		args[i] = "%" + search + "%"
	}
	return query.Where("("+strings.Join(clause, " OR ")+")", args...)
}

func managePlatformRecord(input ManageRecordInput) (map[string]any, error) {
	switch input.Action {
	case "create":
		return createPlatformRecord(input.Resource, input.Data)
	case "update":
		if input.ID == "" {
			return nil, fmt.Errorf("id is required")
		}
		return updatePlatformRecord(input.Resource, input.ID, input.Data)
	case "toggle":
		if input.ID == "" {
			return nil, fmt.Errorf("id is required")
		}
		return togglePlatformRecord(input.Resource, input.ID)
	case "delete":
		if input.ID == "" {
			return nil, fmt.Errorf("delete requires id")
		}
		if !input.Confirm {
			return nil, fmt.Errorf("delete requires confirm=true")
		}
		return deletePlatformRecord(input.Resource, input.ID)
	default:
		return nil, fmt.Errorf("unsupported action: %s", input.Action)
	}
}

func createPlatformRecord(resource string, data map[string]any) (map[string]any, error) {
	var record any
	switch resource {
	case "policies":
		var value models.Policy
		if err := decodeMap(data, &value); err != nil {
			return nil, err
		}
		value.ID = ""
		value.Config.EnablePortScan = true
		record = &value
	case "monitors":
		var value models.Monitor
		if err := decodeMap(data, &value); err != nil {
			return nil, err
		}
		value.ID = ""
		if value.Status == "" {
			value.Status = models.MonitorStatusActive
		}
		if value.Interval < 60 {
			return nil, fmt.Errorf("monitor interval must be at least 60 seconds")
		}
		record = &value
	case "github_monitors":
		var value models.GitHubMonitor
		if err := decodeMap(data, &value); err != nil {
			return nil, err
		}
		value.ID = ""
		value.IsEnabled = true
		if value.Interval < 600 {
			return nil, fmt.Errorf("GitHub monitor interval must be at least 600 seconds")
		}
		next := time.Now().Add(time.Duration(value.Interval) * time.Second)
		value.NextRunAt = &next
		record = &value
	case "pocs":
		var value models.PoC
		if err := decodeMap(data, &value); err != nil {
			return nil, err
		}
		value.ID = ""
		value.IsEnabled = true
		record = &value
	case "fingerprints":
		var value models.Fingerprint
		if err := decodeMap(data, &value); err != nil {
			return nil, err
		}
		value.ID = ""
		value.IsEnabled = true
		record = &value
	case "sensitive_rules":
		var value models.SensitiveRule
		if err := decodeMap(data, &value); err != nil {
			return nil, err
		}
		value.ID = ""
		value.IsEnabled = true
		if value.Type == models.SensitiveRuleTypeRegex {
			if _, err := regexp.Compile(value.Pattern); err != nil {
				return nil, fmt.Errorf("invalid regex: %w", err)
			}
		}
		record = &value
	case "tags":
		var value models.AssetTag
		if err := decodeMap(data, &value); err != nil {
			return nil, err
		}
		value.ID = ""
		if value.Color == "" {
			value.Color = "#3B82F6"
		}
		record = &value
	default:
		return nil, fmt.Errorf("resource is not manageable: %s", resource)
	}
	if err := validatePlatformRecord(record); err != nil {
		return nil, err
	}
	if monitor, ok := record.(*models.Monitor); ok {
		if err := services.SaveMonitor(database.DB, monitor); err != nil {
			return nil, err
		}
	} else if err := database.DB.Create(record).Error; err != nil {
		return nil, err
	}
	return map[string]any{"action": "created", "resource": resource, "record": record}, nil
}

func updatePlatformRecord(resource, id string, data map[string]any) (map[string]any, error) {
	_, allowed, err := manageableModel(resource)
	if err != nil {
		return nil, err
	}
	updates := whitelist(data, allowed)
	if len(updates) == 0 {
		return nil, fmt.Errorf("no supported fields to update")
	}
	if resource == "monitors" {
		for _, field := range []string{"options", "notification_config"} {
			if value, ok := updates[field]; ok {
				if _, isString := value.(string); !isString {
					bytes, _ := json.Marshal(value)
					updates[field] = string(bytes)
				}
			}
		}
	}

	var record any
	switch resource {
	case "policies":
		record = &models.Policy{}
	case "monitors":
		record = &models.Monitor{}
	case "github_monitors":
		record = &models.GitHubMonitor{}
	case "pocs":
		record = &models.PoC{}
	case "fingerprints":
		record = &models.Fingerprint{}
	case "sensitive_rules":
		record = &models.SensitiveRule{}
	case "tags":
		record = &models.AssetTag{}
	}
	if err := database.DB.First(record, "id = ?", id).Error; err != nil {
		return nil, err
	}
	if rule, ok := record.(*models.SensitiveRule); ok && rule.IsBuiltIn {
		return nil, fmt.Errorf("built-in sensitive rules cannot be modified")
	}
	if err := decodeMap(updates, record); err != nil {
		return nil, err
	}
	if policy, ok := record.(*models.Policy); ok {
		policy.Config.EnablePortScan = true
	}
	if err := validatePlatformRecord(record); err != nil {
		return nil, err
	}
	if monitor, ok := record.(*models.Monitor); ok {
		if err := services.SaveMonitor(database.DB, monitor); err != nil {
			return nil, err
		}
	} else if err := database.DB.Save(record).Error; err != nil {
		return nil, err
	}
	return map[string]any{"action": "updated", "resource": resource, "id": id, "record": record}, nil
}

func togglePlatformRecord(resource, id string) (map[string]any, error) {
	model, field, err := toggleModel(resource)
	if err != nil {
		return nil, err
	}
	result := database.DB.Model(model).Where("id = ?", id).UpdateColumn(field, gorm.Expr("NOT "+field))
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, fmt.Errorf("record not found: %s", id)
	}
	var current bool
	if err := database.DB.Model(model).Select(field).Where("id = ?", id).Scan(&current).Error; err != nil {
		return nil, err
	}
	return map[string]any{"action": "toggled", "resource": resource, "id": id, field: current}, nil
}

func deletePlatformRecord(resource, id string) (map[string]any, error) {
	model, _, err := manageableModel(resource)
	if err != nil {
		return nil, err
	}
	if resource == "sensitive_rules" {
		var rule models.SensitiveRule
		if err := database.DB.First(&rule, "id = ?", id).Error; err != nil {
			return nil, err
		}
		if rule.IsBuiltIn {
			return nil, fmt.Errorf("built-in sensitive rules cannot be deleted")
		}
	}
	if resource == "policies" {
		var policy models.Policy
		if err := database.DB.First(&policy, "id = ?", id).Error; err != nil {
			return nil, err
		}
		if policy.IsDefault {
			return nil, fmt.Errorf("default policy cannot be deleted")
		}
	}
	tx := database.DB.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	switch resource {
	case "monitors":
		if err := tx.Where("monitor_id = ?", id).Delete(&models.MonitorResult{}).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	case "github_monitors":
		if err := tx.Where("monitor_id = ?", id).Delete(&models.GitHubMonitorResult{}).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	case "tags":
		if err := tx.Where("tag_id = ?", id).Delete(&models.AssetTagRelation{}).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	case "pocs":
		if err := tx.Where("poc_id = ?", id).Delete(&models.PoCExecutionLog{}).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}
	result := tx.Delete(model, "id = ?", id)
	if result.Error != nil {
		tx.Rollback()
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		tx.Rollback()
		return nil, fmt.Errorf("record not found: %s", id)
	}
	if err := tx.Commit().Error; err != nil {
		return nil, err
	}
	return map[string]any{"action": "deleted", "resource": resource, "id": id}, nil
}

func validatePlatformRecord(record any) error {
	required := func(name, value string) error {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
		if len(value) > 255 {
			return fmt.Errorf("%s is too long", name)
		}
		return nil
	}
	valid := func(value string, choices ...string) bool {
		for _, choice := range choices {
			if value == choice {
				return true
			}
		}
		return false
	}

	switch value := record.(type) {
	case *models.Policy:
		if err := required("name", value.Name); err != nil {
			return err
		}
		value.Config.EnablePortScan = true
		if value.Config.PortScanType == "" {
			value.Config.PortScanType = "top100"
		}
		if !valid(value.Config.PortScanType, "test", "top100", "top1000", "all") {
			return fmt.Errorf("invalid field config.port_scan_type=%q; allowed: test, top100, top1000, all; example: top100", value.Config.PortScanType)
		}
	case *models.Monitor:
		if err := required("name", value.Name); err != nil {
			return err
		}
		if !valid(string(value.Type), "domain", "ip", "site", "github", "wih", "cve") {
			return fmt.Errorf("invalid field type=%q; allowed: domain, ip, site, github, wih, cve; example: domain", value.Type)
		}
		if !valid(string(value.Status), "active", "paused", "stopped") {
			return fmt.Errorf("invalid field status=%q; allowed: active, paused, stopped; example: active", value.Status)
		}
		if value.Interval < 60 {
			return fmt.Errorf("monitor interval must be at least 60 seconds")
		}
		if len(value.Options) > 65536 || len(value.NotificationConfig) > 65536 {
			return fmt.Errorf("monitor configuration is too large")
		}
	case *models.GitHubMonitor:
		if err := required("name", value.Name); err != nil {
			return err
		}
		if err := required("keywords", value.Keywords); err != nil {
			return err
		}
		if !valid(value.SearchType, "code", "repository", "issue") {
			return fmt.Errorf("invalid field search_type=%q; allowed: code, repository, issue; example: code", value.SearchType)
		}
		if value.Interval < 600 {
			return fmt.Errorf("GitHub monitor interval must be at least 600 seconds")
		}
	case *models.PoC:
		if err := required("name", value.Name); err != nil {
			return err
		}
		if err := required("category", value.Category); err != nil {
			return err
		}
		if !valid(value.Severity, "critical", "high", "medium", "low", "info") {
			return fmt.Errorf("invalid field severity=%q; allowed: critical, high, medium, low, info; example: high", value.Severity)
		}
		if !valid(value.PoCType, "nuclei", "custom") {
			return fmt.Errorf("invalid field poc_type=%q; allowed: nuclei, custom; example: nuclei", value.PoCType)
		}
		if err := scanner.ValidatePoCContent(value.PoCType, value.PoCContent); err != nil {
			return err
		}
		if len(value.Product) > 255 {
			return fmt.Errorf("product is too long")
		}
		if len(value.AffectedVersions) > 1000 {
			return fmt.Errorf("affected_versions is too long")
		}
		if value.MatchMode == "" {
			value.MatchMode = "fuzzy"
		}
		if !valid(value.MatchMode, "exact", "fuzzy", "keyword") {
			return fmt.Errorf("invalid field match_mode=%q; allowed: exact, fuzzy, keyword; example: fuzzy", value.MatchMode)
		}
	case *models.Fingerprint:
		if err := required("name", value.Name); err != nil {
			return err
		}
		if err := required("category", value.Category); err != nil {
			return err
		}
		if len(value.DSL) == 0 {
			return fmt.Errorf("dsl rules cannot be empty")
		}
		if len(value.DSL) > 100 {
			return fmt.Errorf("too many dsl rules")
		}
		for _, rule := range value.DSL {
			if len(rule) > 4096 {
				return fmt.Errorf("dsl rule is too large")
			}
		}
	case *models.SensitiveRule:
		if err := required("name", value.Name); err != nil {
			return err
		}
		if !valid(string(value.Type), "regex", "keyword") {
			return fmt.Errorf("invalid field type=%q; allowed: regex, keyword; example: regex", value.Type)
		}
		if !valid(string(value.Severity), "high", "medium", "low") {
			return fmt.Errorf("invalid field severity=%q; allowed: high, medium, low; example: high", value.Severity)
		}
		if strings.TrimSpace(value.Pattern) == "" {
			return fmt.Errorf("pattern is required")
		}
		if len(value.Pattern) > 16384 {
			return fmt.Errorf("pattern is too large")
		}
		if value.Type == models.SensitiveRuleTypeRegex {
			if _, err := regexp.Compile(value.Pattern); err != nil {
				return fmt.Errorf("invalid regex: %w", err)
			}
		}
	case *models.AssetTag:
		if err := required("name", value.Name); err != nil {
			return err
		}
		if value.Color == "" {
			value.Color = "#3B82F6"
		}
		if matched, _ := regexp.MatchString(`^#[0-9A-Fa-f]{6}$`, value.Color); !matched {
			return fmt.Errorf("invalid field color=%q; expected #RRGGBB; example: #3B82F6", value.Color)
		}
	default:
		return fmt.Errorf("unsupported record type")
	}
	return nil
}

func manageableModel(resource string) (any, []string, error) {
	switch resource {
	case "policies":
		return &models.Policy{}, []string{"name", "description", "config", "is_default"}, nil
	case "monitors":
		return &models.Monitor{}, []string{"name", "type", "target", "status", "interval", "options", "notification_config", "asset_group_id", "scope_id"}, nil
	case "github_monitors":
		return &models.GitHubMonitor{}, []string{"name", "keywords", "search_type", "language", "user", "repository", "extension", "interval", "is_enabled"}, nil
	case "pocs":
		return &models.PoC{}, []string{"name", "category", "severity", "cve", "product", "affected_versions", "author", "description", "reference", "poc_type", "poc_content", "tags", "fingerprints", "app_names", "match_mode", "is_enabled"}, nil
	case "fingerprints":
		return &models.Fingerprint{}, []string{"name", "category", "dsl", "description", "is_enabled"}, nil
	case "sensitive_rules":
		return &models.SensitiveRule{}, []string{"name", "type", "pattern", "description", "severity", "is_enabled", "category", "example"}, nil
	case "tags":
		return &models.AssetTag{}, []string{"name", "color", "description", "category"}, nil
	default:
		return nil, nil, fmt.Errorf("resource is not manageable: %s", resource)
	}
}

func toggleModel(resource string) (any, string, error) {
	switch resource {
	case "github_monitors":
		return &models.GitHubMonitor{}, "is_enabled", nil
	case "pocs":
		return &models.PoC{}, "is_enabled", nil
	case "fingerprints":
		return &models.Fingerprint{}, "is_enabled", nil
	case "sensitive_rules":
		return &models.SensitiveRule{}, "is_enabled", nil
	default:
		return nil, "", fmt.Errorf("resource does not support toggle: %s", resource)
	}
}

func whitelist(data map[string]any, allowed []string) map[string]any {
	result := make(map[string]any)
	set := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		set[key] = true
	}
	for key, value := range data {
		if set[key] {
			result[key] = value
		}
	}
	return result
}

func decodeMap(data map[string]any, destination any) error {
	bytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(bytes, destination)
}

func jsonResult(value any) (*mcp.CallToolResult, any, error) {
	bytes, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return errResult(err), nil, nil
	}
	return textResult(string(bytes)), value, nil
}

func boolPtr(value bool) *bool { return &value }
