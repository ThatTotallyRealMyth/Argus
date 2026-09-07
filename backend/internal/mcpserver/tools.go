package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/reconmaster/backend/internal/database"
	platformexport "github.com/reconmaster/backend/internal/export"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/services"
	"gorm.io/gorm"
)

// Deps MCP 工具依赖的内部服务
type Deps struct {
	TaskService       *services.TaskService
	EnterpriseService *services.EnterpriseService
	MonitorRunner     interface{ RunMonitorNow(string) error }
	ScheduledTasks    ScheduledTaskManager
}

type ScheduledTaskManager interface {
	Create(services.ScheduledTaskDefinition, string) (*models.ScheduledTask, error)
	Update(string, services.ScheduledTaskDefinition) (*models.ScheduledTask, error)
	SetEnabled(string, bool) (*models.ScheduledTask, error)
	RunNow(string) (*models.Task, error)
	Delete(string) error
}

// --- 工具输入/输出类型 ---

type CreateTaskInput struct {
	Target            string             `json:"target" jsonschema:"required,扫描目标，支持域名/IP/CIDR/URL，多个用逗号分隔"`
	Name              string             `json:"name" jsonschema:"任务名称"`
	PolicyID          string             `json:"policy_id" jsonschema:"可选扫描策略 ID"`
	ScopeID           string             `json:"scope_id" jsonschema:"可选授权扫描范围 ID；空值使用默认范围"`
	Options           models.TaskOptions `json:"options" jsonschema:"完整扫描选项；端口扫描始终开启"`
	EnablePortScan    bool               `json:"enable_port_scan" jsonschema:"兼容旧客户端；端口扫描始终开启"`
	PortScanType      string             `json:"port_scan_type" jsonschema:"端口扫描类型: test, top100, top1000, all"`
	EnableDomainBrute bool               `json:"enable_domain_brute" jsonschema:"是否启用域名爆破"`
	EnablePassiveScan bool               `json:"enable_passive_scan" jsonschema:"是否启用被动扫描(第三方API)"`
	EnablePoCDetect   bool               `json:"enable_poc_detect" jsonschema:"是否启用PoC漏洞检测"`
	EnableScreenshot  bool               `json:"enable_screenshot" jsonschema:"是否对站点截图"`
	Confirm           bool               `json:"confirm" jsonschema:"required,发起外部网络扫描，必须明确设为 true"`
}

type TaskIDInput struct {
	TaskID string `json:"task_id" jsonschema:"required,任务 ID"`
}

type StartTaskInput struct {
	TaskID  string `json:"task_id" jsonschema:"required,任务 ID"`
	Confirm bool   `json:"confirm" jsonschema:"required,发起外部网络扫描，必须明确设为 true"`
}

type ValidateScanScopeInput struct {
	ScopeID    string   `json:"scope_id,omitempty" jsonschema:"授权扫描范围 ID；空值使用默认范围"`
	Name       string   `json:"name,omitempty" jsonschema:"临时规则预检名称"`
	AllowRules []string `json:"allow_rules,omitempty" jsonschema:"临时允许规则；不能与 scope_id 同时使用"`
	DenyRules  []string `json:"deny_rules,omitempty" jsonschema:"临时排除规则；不能与 scope_id 同时使用"`
	Target     string   `json:"target" jsonschema:"required,待预检的域名、IP、CIDR或URL，多个用逗号分隔"`
}

type DeleteTaskInput struct {
	TaskID  string `json:"task_id" jsonschema:"required,任务 ID"`
	Confirm bool   `json:"confirm" jsonschema:"required,必须明确设为 true"`
}

type RetryTaskInput struct {
	TaskID  string `json:"task_id" jsonschema:"required,已完成、失败或已取消的任务 ID"`
	Confirm bool   `json:"confirm" jsonschema:"required,重新发起网络扫描，必须明确设为 true"`
}

type ListAssetsInput struct {
	AssetType   string `json:"asset_type" jsonschema:"required,资产类型: domains, ips, ports, sites, urls, vulnerabilities"`
	TaskID      string `json:"task_id" jsonschema:"按任务 ID 过滤"`
	Limit       int    `json:"limit" jsonschema:"返回数量上限，默认50"`
	Page        int    `json:"page" jsonschema:"页码，默认1"`
	Search      string `json:"search" jsonschema:"按资产关键字段模糊搜索"`
	StatusCode  int    `json:"status_code" jsonschema:"URL响应状态码过滤"`
	ContentType string `json:"content_type" jsonschema:"URL响应Content-Type过滤"`
	MinLength   int64  `json:"min_length" jsonschema:"URL最小响应长度"`
	MaxLength   int64  `json:"max_length" jsonschema:"URL最大响应长度，0表示不限制"`
	SortBy      string `json:"sort_by" jsonschema:"URL排序字段: created_at,status_code,content_length,response_time_ms,url"`
	SortOrder   string `json:"sort_order" jsonschema:"排序方向: asc或desc"`
}

type ListTasksInput struct {
	Page     int    `json:"page" jsonschema:"页码，默认1"`
	PageSize int    `json:"page_size" jsonschema:"每页数量，默认20，最大100"`
	Status   string `json:"status" jsonschema:"状态过滤: pending, queued, running, completed, failed, cancelled"`
}

type ExportInput struct {
	TaskID string `json:"task_id" jsonschema:"required,任务 ID"`
	Format string `json:"format" jsonschema:"导出格式: json, csv, html, all"`
}

// RegisterTools 注册 MCP 工具到 server，使用内部服务
func RegisterTools(server *mcp.Server, deps *Deps) {
	// 1. 服务器状态
	mcp.AddTool(server, &mcp.Tool{
		Name:        "server_status",
		Description: "检查望月塔资产侦察平台服务器状态",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		var count int64
		if err := database.DB.Model(&models.Task{}).Count(&count).Error; err != nil {
			return errResult(fmt.Errorf("load server status failed: %w", err)), nil, nil
		}
		return textResult(fmt.Sprintf("服务器在线，共 %d 个任务", count)), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_scan_scopes",
		Description: "列出授权扫描范围；排除规则优先，默认范围会自动用于未指定 scope_id 的任务",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: boolPtr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		var scopes []models.ScanScope
		if err := database.DB.Order("is_default DESC, updated_at DESC").Find(&scopes).Error; err != nil {
			return errResult(fmt.Errorf("list scan scopes failed")), nil, nil
		}
		return jsonResult(map[string]any{"scopes": scopes, "total": len(scopes)})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "validate_scan_scope",
		Description: "在创建扫描前预检目标是否位于指定或默认授权范围内；不会发起网络请求",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: boolPtr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ValidateScanScopeInput) (*mcp.CallToolResult, any, error) {
		if strings.TrimSpace(input.ScopeID) != "" && (len(input.AllowRules) > 0 || len(input.DenyRules) > 0) {
			return errResult(fmt.Errorf("scope_id cannot be combined with temporary rules")), nil, nil
		}
		var validation *services.ScanScopeValidation
		var err error
		if len(input.AllowRules) > 0 || len(input.DenyRules) > 0 {
			validation, err = services.ValidateScanScopePreview(models.ScanScope{Name: input.Name, AllowRules: input.AllowRules, DenyRules: input.DenyRules}, input.Target)
		} else {
			validation, err = deps.TaskService.ValidateScopeTarget(input.ScopeID, input.Target)
		}
		if err != nil {
			if services.IsScanScopeInputError(err) {
				return errResult(err), nil, nil
			}
			return errResult(fmt.Errorf("scan scope validation failed")), nil, nil
		}
		return jsonResult(validation)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "delete_task", Description: "删除任务及其全部关联资产；必须 confirm=true",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input DeleteTaskInput) (*mcp.CallToolResult, any, error) {
		if !input.Confirm {
			return errResult(fmt.Errorf("delete requires confirm=true")), nil, nil
		}
		if err := deps.TaskService.DeleteTask(input.TaskID); err != nil {
			return errResult(err), nil, nil
		}
		return textResult(fmt.Sprintf("任务 %s 及关联数据已删除", input.TaskID)), nil, nil
	})

	// 2. 创建扫描任务
	mcp.AddTool(server, &mcp.Tool{
		Name: "create_scan_task",
		Description: "创建一个新的资产侦察扫描任务并立即启动，必须 confirm=true。" +
			"支持子域名爆破、端口扫描、服务识别、PoC漏洞检测、站点截图等。" +
			"目标可以是域名、IP、CIDR网段或URL，多个用逗号分隔。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input CreateTaskInput) (*mcp.CallToolResult, any, error) {
		if !input.Confirm {
			return errResult(fmt.Errorf("create scan requires confirm=true")), nil, nil
		}
		options := input.Options
		options.EnablePortScan = true
		if options.PortScanType == "" {
			options.PortScanType = orDefault(input.PortScanType, "top100")
		}
		options.EnableDomainBrute = options.EnableDomainBrute || input.EnableDomainBrute
		options.EnablePassiveScan = options.EnablePassiveScan || input.EnablePassiveScan
		options.EnablePoCDetection = options.EnablePoCDetection || input.EnablePoCDetect
		options.EnableScreenshot = options.EnableScreenshot || input.EnableScreenshot

		task, err := deps.TaskService.CreateQueuedTaskInScopeWithOrigin(orDefault(input.Name, "MCP-"+input.Target), input.Target, input.PolicyID, input.ScopeID, options, models.TaskOrigin{Source: models.TaskTriggerMCP})
		if err != nil {
			if services.IsTaskInputError(err) {
				return errResult(fmt.Errorf("创建任务失败: %w", err)), nil, nil
			}
			return errResult(fmt.Errorf("创建任务失败")), nil, nil
		}

		result := map[string]any{
			"task_id": task.ID,
			"name":    task.Name,
			"target":  task.Target,
			"status":  "queued",
			"message": fmt.Sprintf("任务已创建并进入队列: %s", task.ID),
		}
		jsonBytes, _ := json.MarshalIndent(result, "", "  ")
		return textResult(string(jsonBytes)), result, nil
	})

	// 3. 列出任务
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_tasks",
		Description: "列出最近的扫描任务及其状态",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ListTasksInput) (*mcp.CallToolResult, any, error) {
		page, pageSize := normalizePage(input.Page, input.PageSize)
		query := database.DB.Model(&models.Task{})
		if input.Status != "" && input.Status != "all" {
			query = query.Where("status = ?", input.Status)
		}
		var total int64
		if err := query.Count(&total).Error; err != nil {
			return errResult(err), nil, nil
		}
		var tasks []models.Task
		if err := query.Order("created_at DESC").Limit(pageSize).Offset((page - 1) * pageSize).Find(&tasks).Error; err != nil {
			return errResult(err), nil, nil
		}

		type Summary struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Target   string `json:"target"`
			ScopeID  string `json:"scope_id,omitempty"`
			Status   string `json:"status"`
			Progress int    `json:"progress"`
		}
		var list []Summary
		for _, t := range tasks {
			list = append(list, Summary{ID: t.ID, Name: t.Name, Target: t.Target, ScopeID: t.ScopeID, Status: string(t.Status), Progress: t.Progress})
		}

		result := map[string]any{"items": list, "total": total, "page": page, "page_size": pageSize}
		jsonBytes, _ := json.MarshalIndent(result, "", "  ")
		return textResult(string(jsonBytes)), result, nil
	})

	// 4. 获取任务详情
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_task",
		Description: "获取指定任务的详细信息",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input TaskIDInput) (*mcp.CallToolResult, any, error) {
		var task models.Task
		if err := database.DB.First(&task, "id = ?", input.TaskID).Error; err != nil {
			return errResult(fmt.Errorf("任务不存在: %s", input.TaskID)), nil, nil
		}

		result := map[string]any{
			"task_id":   task.ID,
			"name":      task.Name,
			"target":    task.Target,
			"status":    task.Status,
			"progress":  task.Progress,
			"error_msg": task.ErrorMsg,
			"created":   task.CreatedAt.Format(time.RFC3339),
			"started":   fmtTime(task.StartedAt),
			"ended":     fmtTime(task.EndedAt),
			"policy_id": task.PolicyID,
			"scope_id":  task.ScopeID,
			"options":   task.Options,
		}
		jsonBytes, _ := json.MarshalIndent(result, "", "  ")
		return textResult(string(jsonBytes)), result, nil
	})

	// 5b. 启动待执行任务
	mcp.AddTool(server, &mcp.Tool{
		Name:        "start_task",
		Description: "将一个 pending 状态的扫描任务加入执行队列，必须 confirm=true",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input StartTaskInput) (*mcp.CallToolResult, any, error) {
		if !input.Confirm {
			return errResult(fmt.Errorf("start requires confirm=true")), nil, nil
		}
		if err := deps.TaskService.StartTask(input.TaskID); err != nil {
			if services.IsTaskInputError(err) {
				return errResult(err), nil, nil
			}
			return errResult(fmt.Errorf("启动任务失败")), nil, nil
		}
		return textResult(fmt.Sprintf("任务 %s 已进入执行队列", input.TaskID)), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "retry_task",
		Description: "按终态任务的目标与配置创建一个全新的扫描任务并加入队列；保留原任务及其资产，必须 confirm=true",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input RetryTaskInput) (*mcp.CallToolResult, any, error) {
		if !input.Confirm {
			return errResult(fmt.Errorf("retry requires confirm=true")), nil, nil
		}
		if deps == nil || deps.TaskService == nil {
			return errResult(fmt.Errorf("task service is unavailable")), nil, nil
		}
		task, err := deps.TaskService.RetryTask(input.TaskID)
		if err != nil {
			if services.IsTaskInputError(err) {
				return errResult(err), nil, nil
			}
			return errResult(fmt.Errorf("重新运行任务失败")), nil, nil
		}
		return jsonResult(map[string]any{"action": "queued", "source_task_id": input.TaskID, "task": task})
	})

	// 5. 取消任务
	mcp.AddTool(server, &mcp.Tool{
		Name:        "cancel_task",
		Description: "取消一个正在运行的扫描任务",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input TaskIDInput) (*mcp.CallToolResult, any, error) {
		if err := deps.TaskService.CancelTask(input.TaskID); err != nil {
			return errResult(err), nil, nil
		}
		return textResult(fmt.Sprintf("任务 %s 已取消", input.TaskID)), nil, nil
	})

	// 6. 列出资产
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_assets",
		Description: "列出已发现资产。asset_type: domains(域名), ips(IP), ports(端口), sites(站点), urls(URL), vulnerabilities(漏洞)",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ListAssetsInput) (*mcp.CallToolResult, any, error) {
		if input.Limit <= 0 {
			input.Limit = 50
		}
		if input.Limit > 100 {
			input.Limit = 100
		}
		if input.Page <= 0 {
			input.Page = 1
		}

		db := database.DB
		if input.TaskID != "" {
			db = db.Where("task_id = ?", input.TaskID)
		}

		var (
			result map[string]any
			err    error
		)
		offset := (input.Page - 1) * input.Limit
		switch input.AssetType {
		case "domains":
			var data []models.Domain
			query := db.Model(&models.Domain{})
			if input.Search != "" {
				query = query.Where("domain LIKE ?", "%"+input.Search+"%")
			}
			result, err = pagedAssetResult(query, &data, input.Page, input.Limit, offset, "domains")
		case "ips":
			var data []models.IP
			query := db.Model(&models.IP{})
			if input.Search != "" {
				query = query.Where("ip_address LIKE ?", "%"+input.Search+"%")
			}
			result, err = pagedAssetResult(query, &data, input.Page, input.Limit, offset, "ips")
		case "ports":
			var data []models.Port
			query := db.Model(&models.Port{})
			if input.Search != "" {
				query = query.Where("ip_address LIKE ? OR service LIKE ?", "%"+input.Search+"%", "%"+input.Search+"%")
			}
			result, err = pagedAssetResult(query, &data, input.Page, input.Limit, offset, "ports")
		case "sites":
			var data []models.Site
			query := db.Model(&models.Site{})
			if input.Search != "" {
				query = query.Where("url LIKE ? OR title LIKE ?", "%"+input.Search+"%", "%"+input.Search+"%")
			}
			result, err = pagedAssetResult(query, &data, input.Page, input.Limit, offset, "sites")
		case "urls":
			var data []models.CrawlerResult
			query := db.Model(&models.CrawlerResult{})
			if input.Search != "" {
				query = query.Where("url LIKE ?", "%"+input.Search+"%")
			}
			if input.StatusCode > 0 {
				query = query.Where("status_code = ?", input.StatusCode)
			}
			if input.ContentType != "" {
				query = query.Where("content_type LIKE ?", "%"+input.ContentType+"%")
			}
			if input.MinLength > 0 {
				query = query.Where("content_length >= ?", input.MinLength)
			}
			if input.MaxLength > 0 {
				query = query.Where("content_length <= ?", input.MaxLength)
			}
			result, err = pagedURLResult(query, &data, input.Page, input.Limit, offset, input.SortBy, input.SortOrder)
		case "vulnerabilities":
			var data []models.Vulnerability
			query := db.Model(&models.Vulnerability{})
			if input.Search != "" {
				query = query.Where("url LIKE ? OR title LIKE ?", "%"+input.Search+"%", "%"+input.Search+"%")
			}
			result, err = pagedAssetResult(query, &data, input.Page, input.Limit, offset, "vulnerabilities")
		default:
			return errResult(fmt.Errorf("不支持的资产类型: %s (可选: domains, ips, ports, sites, urls, vulnerabilities)", input.AssetType)), nil, nil
		}
		if err != nil {
			return errResult(fmt.Errorf("list %s failed: %w", input.AssetType, err)), nil, nil
		}

		jsonBytes, _ := json.MarshalIndent(result, "", "  ")
		return textResult(string(jsonBytes)), result, nil
	})

	// 7. 资产统计
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_asset_stats",
		Description: "获取资产统计概览：各类型数量及漏洞分布",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		var domains, ips, ports, sites, urls, vulns int64
		counts := []struct {
			name  string
			model any
			value *int64
		}{
			{name: "domains", model: &models.Domain{}, value: &domains},
			{name: "ips", model: &models.IP{}, value: &ips},
			{name: "ports", model: &models.Port{}, value: &ports},
			{name: "sites", model: &models.Site{}, value: &sites},
			{name: "urls", model: &models.CrawlerResult{}, value: &urls},
			{name: "vulnerabilities", model: &models.Vulnerability{}, value: &vulns},
		}
		for _, count := range counts {
			if err := database.DB.Model(count.model).Count(count.value).Error; err != nil {
				return errResult(fmt.Errorf("count %s failed: %w", count.name, err)), nil, nil
			}
		}

		result := map[string]any{
			"domains":         domains,
			"ips":             ips,
			"ports":           ports,
			"sites":           sites,
			"urls":            urls,
			"vulnerabilities": vulns,
		}
		jsonBytes, _ := json.MarshalIndent(result, "", "  ")
		return textResult(string(jsonBytes)), result, nil
	})

	// 8. 资产关系图
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_asset_graph",
		Description: "按任务获取资产节点-边关系图：域名→IP→端口→站点链路",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: boolPtr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input TaskIDInput) (*mcp.CallToolResult, any, error) {
		if strings.TrimSpace(input.TaskID) == "" {
			return errResult(fmt.Errorf("task_id is required for a scoped asset graph")), nil, nil
		}
		db := database.DB
		db = db.Where("task_id = ?", input.TaskID)

		var domains []models.Domain
		if err := db.Limit(500).Find(&domains).Error; err != nil {
			return errResult(fmt.Errorf("load task domains failed: %w", err)), nil, nil
		}

		type Node struct {
			ID    string `json:"id"`
			Label string `json:"label"`
			Type  string `json:"type"`
		}
		type Edge struct {
			Source string `json:"source"`
			Target string `json:"target"`
		}

		var nodes []Node
		var edges []Edge
		seen := map[string]bool{}
		edgeSeen := map[string]bool{}
		addNode := func(id, label, nodeType string) bool {
			if id == "" {
				return false
			}
			if seen[id] {
				return true
			}
			if len(nodes) >= 500 {
				return false
			}
			nodes = append(nodes, Node{ID: id, Label: label, Type: nodeType})
			seen[id] = true
			return true
		}
		addEdge := func(source, target string) {
			key := source + "\x00" + target
			if !seen[source] || !seen[target] || edgeSeen[key] || len(edges) >= 1000 {
				return
			}
			edges = append(edges, Edge{Source: source, Target: target})
			edgeSeen[key] = true
		}

		for _, d := range domains {
			addNode(d.Domain, d.Domain, "domain")
			if d.IPAddress != "" {
				addNode(d.IPAddress, d.IPAddress, "ip")
				addEdge(d.Domain, d.IPAddress)
			}
		}

		var sites []models.Site
		var ports []models.Port
		if err := db.Limit(500).Find(&ports).Error; err != nil {
			return errResult(fmt.Errorf("load task ports failed: %w", err)), nil, nil
		}
		for _, port := range ports {
			portID := fmt.Sprintf("%s:%d/%s", port.IPAddress, port.Port, orDefault(port.Protocol, "tcp"))
			addNode(port.IPAddress, port.IPAddress, "ip")
			addNode(portID, fmt.Sprintf("%d/%s", port.Port, orDefault(port.Service, orDefault(port.Protocol, "tcp"))), "port")
			addEdge(port.IPAddress, portID)
		}
		if err := db.Limit(500).Find(&sites).Error; err != nil {
			return errResult(fmt.Errorf("load task sites failed: %w", err)), nil, nil
		}
		for _, s := range sites {
			addNode(s.IP, s.IP, "ip")
			addNode(s.URL, s.URL, "site")
			addEdge(s.IP, s.URL)
		}

		graph := map[string]any{"nodes": nodes, "edges": edges}
		jsonBytes, _ := json.MarshalIndent(graph, "", "  ")
		return textResult(string(jsonBytes)), graph, nil
	})

	// 9. 导出结果
	mcp.AddTool(server, &mcp.Tool{
		Name:        "export_results",
		Description: "导出扫描任务结果。format: json(完整JSON), csv(CSV), html(HTML报告), all(全部格式)",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ExportInput) (*mcp.CallToolResult, any, error) {
		var task models.Task
		if err := database.DB.First(&task, "id = ?", input.TaskID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errResult(fmt.Errorf("任务不存在: %s", input.TaskID)), nil, nil
			}
			return errResult(fmt.Errorf("load export task failed: %w", err)), nil, nil
		}

		var domains []models.Domain
		var ips []models.IP
		var ports []models.Port
		var sites []models.Site
		var urls []models.CrawlerResult
		var vulns []models.Vulnerability

		const exportLimit = 10000
		exportQueries := []struct {
			name        string
			destination any
		}{
			{name: "domains", destination: &domains},
			{name: "ips", destination: &ips},
			{name: "ports", destination: &ports},
			{name: "sites", destination: &sites},
			{name: "urls", destination: &urls},
			{name: "vulnerabilities", destination: &vulns},
		}
		for _, query := range exportQueries {
			if err := database.DB.Where("task_id = ?", input.TaskID).Limit(exportLimit).Find(query.destination).Error; err != nil {
				return errResult(fmt.Errorf("load export %s failed: %w", query.name, err)), nil, nil
			}
		}

		exportData := &platformexport.ExportData{
			Task: &task, Domains: domains, IPs: ips, Ports: ports, Sites: sites,
			URLs: urls, Vulnerabilities: vulns, ExportTime: time.Now(),
		}
		result := map[string]any{
			"task":            task,
			"domains":         len(domains),
			"ips":             len(ips),
			"ports":           len(ports),
			"sites":           len(sites),
			"urls":            len(urls),
			"vulnerabilities": len(vulns),
		}
		result["truncated"] = len(domains) == exportLimit || len(ips) == exportLimit || len(ports) == exportLimit || len(sites) == exportLimit || len(urls) == exportLimit || len(vulns) == exportLimit

		format := orDefault(input.Format, "json")
		exporter := platformexport.NewExporter("./exports")
		switch format {
		case "json":
			filename, err := exporter.ExportToJSON(exportData)
			if err != nil {
				return errResult(err), nil, nil
			}
			result["files"] = map[string]string{"json": filename}
		case "csv":
			files, err := exporter.ExportAll(exportData)
			if err != nil {
				return errResult(err), nil, nil
			}
			delete(files, "json")
			result["files"] = files
		case "html":
			filename, err := exporter.GenerateReport(exportData)
			if err != nil {
				return errResult(err), nil, nil
			}
			result["files"] = map[string]string{"html": filename}
		case "all":
			files, err := exporter.ExportAll(exportData)
			if err != nil {
				return errResult(err), nil, nil
			}
			html, err := exporter.GenerateReport(exportData)
			if err != nil {
				return errResult(err), nil, nil
			}
			files["html"] = html
			result["files"] = files
		default:
			return errResult(fmt.Errorf("不支持的导出格式: %s", format)), nil, nil
		}

		jsonBytes, _ := json.MarshalIndent(result, "", "  ")
		return textResult(string(jsonBytes)), result, nil
	})

	// 10. 扫描策略列表
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_policies",
		Description: "列出可用的扫描策略配置",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		var policies []models.Policy
		if err := database.DB.Order("created_at DESC").Limit(100).Find(&policies).Error; err != nil {
			return errResult(fmt.Errorf("list policies failed: %w", err)), nil, nil
		}
		jsonBytes, _ := json.MarshalIndent(policies, "", "  ")
		return textResult(string(jsonBytes)), policies, nil
	})

	RegisterPlatformTools(server, deps)
	RegisterEnterpriseTools(server, deps)
	RegisterRuntimeTools(server)
}

// --- 辅助 ---

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}

func errResult(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error: %v", err)}},
	}
}

func orDefault(val, def string) string {
	if val == "" {
		return def
	}
	return val
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

func normalizePage(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return page, pageSize
}

func pagedAssetResult(db *gorm.DB, destination any, page, pageSize, offset int, assetType string) (map[string]any, error) {
	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, err
	}
	if err := db.Order("created_at DESC").Limit(pageSize).Offset(offset).Find(destination).Error; err != nil {
		return nil, err
	}
	return map[string]any{"type": assetType, "items": destination, "total": total, "page": page, "page_size": pageSize}, nil
}

func pagedURLResult(db *gorm.DB, destination any, page, pageSize, offset int, sortBy, sortOrder string) (map[string]any, error) {
	allowed := map[string]bool{"created_at": true, "url": true, "status_code": true, "content_length": true, "response_time_ms": true}
	if !allowed[sortBy] {
		sortBy = "created_at"
	}
	sortOrder = strings.ToLower(sortOrder)
	if sortOrder != "asc" {
		sortOrder = "desc"
	}
	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, err
	}
	if err := db.Order(sortBy + " " + sortOrder).Limit(pageSize).Offset(offset).Find(destination).Error; err != nil {
		return nil, err
	}
	return map[string]any{"type": "urls", "items": destination, "total": total, "page": page, "page_size": pageSize}, nil
}
