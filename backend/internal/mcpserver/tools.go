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

// Deps MCP Internal services on which the tools depend
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

// --- Tool Input/Output Type ---

type CreateTaskInput struct {
	Target            string             `json:"target" jsonschema:"required,Scan target, Support domain names/IP/CIDR/URL, Multiple Comma Separated"`
	Name              string             `json:"name" jsonschema:"Task Name"`
	PolicyID          string             `json:"policy_id" jsonschema:"Optional Scan Policy ID"`
	ScopeID           string             `json:"scope_id" jsonschema:"Optional authorized scan range ID; Empty values use default range"`
	Options           models.TaskOptions `json:"options" jsonschema:"Full Scan Options; Port scans are open at all times."`
	EnablePortScan    bool               `json:"enable_port_scan" jsonschema:"Compatible with Old Client; Port scans are open at all times."`
	PortScanType      string             `json:"port_scan_type" jsonschema:"Port Scan Type: test, top100, top1000, all"`
	EnableDomainBrute bool               `json:"enable_domain_brute" jsonschema:"Whether subdomain brute force is enabled"`
	EnablePassiveScan bool               `json:"enable_passive_scan" jsonschema:"Whether passive scans are enabled(Third partiesAPI)"`
	EnablePoCDetect   bool               `json:"enable_poc_detect" jsonschema:"Whether to enable PoC-based finding validation"`
	EnableScreenshot  bool               `json:"enable_screenshot" jsonschema:"Whether to screenshot of site"`
	Confirm           bool               `json:"confirm" jsonschema:"required,Launch external network scan, It must be clearly defined. true"`
}

type TaskIDInput struct {
	TaskID string `json:"task_id" jsonschema:"required,Tasks ID"`
}

type StartTaskInput struct {
	TaskID  string `json:"task_id" jsonschema:"required,Tasks ID"`
	Confirm bool   `json:"confirm" jsonschema:"required,Launch external network scan, It must be clearly defined. true"`
}

type ValidateScanScopeInput struct {
	ScopeID    string   `json:"scope_id,omitempty" jsonschema:"Authorized scan range ID; Empty values use default range"`
	Name       string   `json:"name,omitempty" jsonschema:"Provisional rule pre-screen name"`
	AllowRules []string `json:"allow_rules,omitempty" jsonschema:"Provisional rules on permission; Can't be with scope_id Use simultaneously"`
	DenyRules  []string `json:"deny_rules,omitempty" jsonschema:"Provisional exclusion rules; Can't be with scope_id Use simultaneously"`
	Target     string   `json:"target" jsonschema:"required,Domain name, IP, CIDR, or URL to validate; separate multiple targets with commas"`
}

type DeleteTaskInput struct {
	TaskID  string `json:"task_id" jsonschema:"required,Tasks ID"`
	Confirm bool   `json:"confirm" jsonschema:"required,It must be clearly defined. true"`
}

type RetryTaskInput struct {
	TaskID  string `json:"task_id" jsonschema:"required,Completed, Failed or cancelled tasks ID"`
	Confirm bool   `json:"confirm" jsonschema:"required,Relaunch Network Scan, It must be clearly defined. true"`
}

type ListAssetsInput struct {
	AssetType   string `json:"asset_type" jsonschema:"required,Asset type: domains, ips, ports, sites, urls, vulnerabilities"`
	TaskID      string `json:"task_id" jsonschema:"By Task ID Filter"`
	Limit       int    `json:"limit" jsonschema:"Returns the maximum quantity, Default50"`
	Page        int    `json:"page" jsonschema:"Page Number, Default1"`
	Search      string `json:"search" jsonschema:"Search with asset key fields"`
	StatusCode  int    `json:"status_code" jsonschema:"URLResponse State Code Filter"`
	ContentType string `json:"content_type" jsonschema:"URLResponseContent-TypeFilter"`
	MinLength   int64  `json:"min_length" jsonschema:"URLMinimum Response Length"`
	MaxLength   int64  `json:"max_length" jsonschema:"URLMaximum Response Length, 0Expressing unlimited"`
	SortBy      string `json:"sort_by" jsonschema:"URLSort Fields: created_at,status_code,content_length,response_time_ms,url"`
	SortOrder   string `json:"sort_order" jsonschema:"Sort Direction: ascordesc"`
}

type ListTasksInput struct {
	Page     int    `json:"page" jsonschema:"Page Number, Default1"`
	PageSize int    `json:"page_size" jsonschema:"Number of pages per page, Default20, Max100"`
	Status   string `json:"status" jsonschema:"Status Filter: pending, queued, running, completed, failed, cancelled"`
}

type ExportInput struct {
	TaskID string `json:"task_id" jsonschema:"required,Tasks ID"`
	Format string `json:"format" jsonschema:"Export Format: json, csv, html, all"`
}

// RegisterTools Registration MCP Tools to server, Use of internal services
func RegisterTools(server *mcp.Server, deps *Deps) {
	// 1. Server status
	mcp.AddTool(server, &mcp.Tool{
		Name:        "server_status",
		Description: "Check the status of the platform server for the observation tower asset reconnaissance",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		var count int64
		if err := database.DB.Model(&models.Task{}).Count(&count).Error; err != nil {
			return errResult(fmt.Errorf("load server status failed: %w", err)), nil, nil
		}
		return textResult(fmt.Sprintf("Server online, Total %d One task", count)), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_scan_scopes",
		Description: "List authorized scan range; Exclusion rule first, Default range will automatically be used without a specification scope_id Tasks",
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
		Description: "Precheck if the target is within the specified or default authorization before creating the scan; No network requests launched",
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
		Name: "delete_task", Description: "Remove Tasks and All Associated Assets; Yes. confirm=true",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input DeleteTaskInput) (*mcp.CallToolResult, any, error) {
		if !input.Confirm {
			return errResult(fmt.Errorf("delete requires confirm=true")), nil, nil
		}
		if err := deps.TaskService.DeleteTask(input.TaskID); err != nil {
			return errResult(err), nil, nil
		}
		return textResult(fmt.Sprintf("Tasks %s & Associated Data Deleted", input.TaskID)), nil, nil
	})

	// 2. Create Scan Task
	mcp.AddTool(server, &mcp.Tool{
		Name: "create_scan_task",
		Description: "Create a new asset reconnaissance scan and start immediately., Yes. confirm=true." +
			"Supports subdomain discovery, port scanning, service detection, PoC-based validation, and site screenshots. " +
			"The target could be a domain name., IP, CIDRNetwork segment orURL, Multiple Comma Separated.",
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
				return errResult(fmt.Errorf("invalid task input: %w", err)), nil, nil
			}
			return errResult(fmt.Errorf("could not create task: %w", err)), nil, nil
		}

		result := map[string]any{
			"task_id": task.ID,
			"name":    task.Name,
			"target":  task.Target,
			"status":  "queued",
			"message": fmt.Sprintf("Task created and in Queue: %s", task.ID),
		}
		jsonBytes, _ := json.MarshalIndent(result, "", "  ")
		return textResult(string(jsonBytes)), result, nil
	})

	// 3. List Tasks
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_tasks",
		Description: "List the most recent scans and their status",
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

	// 4. Get Task Details
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_task",
		Description: "Get details of the given task",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input TaskIDInput) (*mcp.CallToolResult, any, error) {
		var task models.Task
		if err := database.DB.First(&task, "id = ?", input.TaskID).Error; err != nil {
			return errResult(fmt.Errorf("Mission does not exist: %s", input.TaskID)), nil, nil
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

	// 5b. Start of pending tasks
	mcp.AddTool(server, &mcp.Tool{
		Name:        "start_task",
		Description: "♪ Will one ♪ pending Scan Tasks in Status Add to Implementation Queue, Yes. confirm=true",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input StartTaskInput) (*mcp.CallToolResult, any, error) {
		if !input.Confirm {
			return errResult(fmt.Errorf("start requires confirm=true")), nil, nil
		}
		if err := deps.TaskService.StartTask(input.TaskID); err != nil {
			if services.IsTaskInputError(err) {
				return errResult(err), nil, nil
			}
			return errResult(fmt.Errorf("Failed to start task")), nil, nil
		}
		return textResult(fmt.Sprintf("Tasks %s Entered the execution queue", input.TaskID)), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "retry_task",
		Description: "Create a new scan task and join the queue by the destination and configuration of the terminal task; Retain original tasks and their assets, Yes. confirm=true",
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
			return errResult(fmt.Errorf("Rerun failed")), nil, nil
		}
		return jsonResult(map[string]any{"action": "queued", "source_task_id": input.TaskID, "task": task})
	})

	// 5. Cancel Task
	mcp.AddTool(server, &mcp.Tool{
		Name:        "cancel_task",
		Description: "Cancel a running scan task",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input TaskIDInput) (*mcp.CallToolResult, any, error) {
		if err := deps.TaskService.CancelTask(input.TaskID); err != nil {
			return errResult(err), nil, nil
		}
		return textResult(fmt.Sprintf("Tasks %s Cancelled", input.TaskID)), nil, nil
	})

	// 6. List assets
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_assets",
		Description: "List of assets found.asset_type: domains(Domain name), ips(IP), ports(Port), sites(Site), urls(URL), vulnerabilities(Leaks)",
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
			return errResult(fmt.Errorf("Types of assets not supported: %s (Optional: domains, ips, ports, sites, urls, vulnerabilities)", input.AssetType)), nil, nil
		}
		if err != nil {
			return errResult(fmt.Errorf("list %s failed: %w", input.AssetType, err)), nil, nil
		}

		jsonBytes, _ := json.MarshalIndent(result, "", "  ")
		return textResult(string(jsonBytes)), result, nil
	})

	// 7. Asset statistics
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_asset_stats",
		Description: "Overview of acquisition statistics: Number of types and distribution of gaps",
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

	// 8. Asset relationship chart
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_asset_graph",
		Description: "Get asset nodes by task-Border Relationship Map: Domain name→IP→Port→Site Link",
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

	// 9. Export Results
	mcp.AddTool(server, &mcp.Tool{
		Name:        "export_results",
		Description: "Export Scan Results.format: json(CompleteJSON), csv(CSV), html(HTMLReport), all(All Format)",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ExportInput) (*mcp.CallToolResult, any, error) {
		var task models.Task
		if err := database.DB.First(&task, "id = ?", input.TaskID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errResult(fmt.Errorf("Mission does not exist: %s", input.TaskID)), nil, nil
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
			return errResult(fmt.Errorf("Unsupported Export Format: %s", format)), nil, nil
		}

		jsonBytes, _ := json.MarshalIndent(result, "", "  ")
		return textResult(string(jsonBytes)), result, nil
	})

	// 10. Scan Policy List
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_policies",
		Description: "List available scan policy configurations",
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

// --- Auxiliary ---

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
