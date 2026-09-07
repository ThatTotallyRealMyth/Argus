package mcpserver

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/services"
)

type EnterpriseQueryCreateInput struct {
	Keyword    string   `json:"keyword" jsonschema:"required,企业名称或关键词"`
	Name       string   `json:"name,omitempty" jsonschema:"查询任务名称，默认使用关键词"`
	Provider   string   `json:"provider,omitempty" jsonschema:"提供者，当前支持 icp_query"`
	QueryTypes []string `json:"query_types,omitempty" jsonschema:"查询类型数组: web, app, mapp, kapp；默认 web"`
	Confirm    bool     `json:"confirm" jsonschema:"required,查询会访问外部企业数据源，必须明确设为 true"`
}

type EnterpriseListInput struct {
	QueryID  string `json:"query_id,omitempty" jsonschema:"企业查询 ID，仅资产列表使用"`
	Status   string `json:"status,omitempty" jsonschema:"任务状态过滤: queued, running, completed, failed"`
	Kind     string `json:"kind,omitempty" jsonschema:"资产类型过滤: web, app, miniapp, quickapp"`
	Search   string `json:"search,omitempty" jsonschema:"企业、名称、域名或备案号关键词"`
	Page     int    `json:"page,omitempty" jsonschema:"页码，默认1"`
	PageSize int    `json:"page_size,omitempty" jsonschema:"每页数量，默认20，最大100"`
}

type EnterpriseScanInput struct {
	AssetIDs []string           `json:"asset_ids" jsonschema:"required,要下发扫描的企业资产 ID 数组，最多2000条"`
	Name     string             `json:"name,omitempty" jsonschema:"扫描任务名称"`
	PolicyID string             `json:"policy_id,omitempty" jsonschema:"可选扫描策略 ID"`
	ScopeID  string             `json:"scope_id,omitempty" jsonschema:"可选授权扫描范围 ID；空值使用默认范围"`
	Options  models.TaskOptions `json:"options,omitempty" jsonschema:"扫描选项；端口扫描始终开启"`
	Start    bool               `json:"start,omitempty" jsonschema:"是否创建后立即加入扫描队列"`
	Confirm  bool               `json:"confirm" jsonschema:"required,确认目标已获授权并明确设为 true"`
}

type EnterpriseSyncInput struct {
	AssetIDs     []string `json:"asset_ids" jsonschema:"required,要同步到全局资产清单的企业资产 ID，最多2000条"`
	GroupID      string   `json:"group_id,omitempty" jsonschema:"可选已有资产分组 ID"`
	NewGroupName string   `json:"new_group_name,omitempty" jsonschema:"可选新资产分组名称；不能与 group_id 同时设置"`
}

func RegisterEnterpriseTools(server *mcp.Server, deps *Deps) {
	if deps.EnterpriseService == nil {
		return
	}
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: boolPtr(false)}
	mcp.AddTool(server, &mcp.Tool{Name: "list_enterprise_providers", Description: "列出企业资产发现提供者的配置和启用状态", Annotations: readOnly},
		func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			providers, err := deps.EnterpriseService.ProviderStatus()
			if err != nil {
				return errResult(err), nil, nil
			}
			return jsonResult(map[string]any{"providers": providers})
		})

	mcp.AddTool(server, &mcp.Tool{Name: "create_enterprise_query", Description: "通过已配置提供者查询企业域名、应用、小程序和快应用资产", Annotations: &mcp.ToolAnnotations{OpenWorldHint: boolPtr(true)}},
		func(ctx context.Context, req *mcp.CallToolRequest, input EnterpriseQueryCreateInput) (*mcp.CallToolResult, any, error) {
			if !input.Confirm {
				return errResult(fmt.Errorf("enterprise query requires confirm=true")), nil, nil
			}
			query, err := deps.EnterpriseService.CreateQuery(input.Name, input.Keyword, input.Provider, input.QueryTypes, "mcp")
			if err != nil {
				return errResult(err), nil, nil
			}
			return jsonResult(map[string]any{"query": query})
		})

	mcp.AddTool(server, &mcp.Tool{Name: "list_enterprise_queries", Description: "分页列出企业资产查询任务及分类统计", Annotations: readOnly},
		func(ctx context.Context, req *mcp.CallToolRequest, input EnterpriseListInput) (*mcp.CallToolResult, any, error) {
			page, pageSize := normalizePage(input.Page, input.PageSize)
			query := database.DB.Model(&models.EnterpriseQuery{})
			if input.Status != "" && input.Status != "all" {
				query = query.Where("status = ?", input.Status)
			}
			if search := strings.TrimSpace(input.Search); search != "" {
				like := "%" + search + "%"
				query = query.Where("name ILIKE ? OR keyword ILIKE ? OR provider ILIKE ?", like, like, like)
			}
			var total int64
			if err := query.Count(&total).Error; err != nil {
				return errResult(err), nil, nil
			}
			var rows []models.EnterpriseQuery
			if err := query.Order("created_at DESC").Limit(pageSize).Offset((page - 1) * pageSize).Find(&rows).Error; err != nil {
				return errResult(err), nil, nil
			}
			return jsonResult(map[string]any{"queries": rows, "total": total, "page": page, "page_size": pageSize})
		})

	mcp.AddTool(server, &mcp.Tool{Name: "list_enterprise_assets", Description: "分页列出企业发现资产，可按查询、类型和关键词过滤", Annotations: readOnly},
		func(ctx context.Context, req *mcp.CallToolRequest, input EnterpriseListInput) (*mcp.CallToolResult, any, error) {
			page, pageSize := normalizePage(input.Page, input.PageSize)
			query := database.DB.Model(&models.EnterpriseAsset{})
			if input.QueryID != "" {
				query = query.Where("query_id = ?", input.QueryID)
			}
			if input.Kind != "" && input.Kind != "all" {
				query = query.Where("kind = ?", input.Kind)
			}
			if search := strings.TrimSpace(input.Search); search != "" {
				like := "%" + search + "%"
				query = query.Where("company_name ILIKE ? OR name ILIKE ? OR domain ILIKE ? OR license ILIKE ?", like, like, like, like)
			}
			var total int64
			if err := query.Count(&total).Error; err != nil {
				return errResult(err), nil, nil
			}
			var rows []models.EnterpriseAsset
			if err := query.Order("created_at DESC").Limit(pageSize).Offset((page - 1) * pageSize).Find(&rows).Error; err != nil {
				return errResult(err), nil, nil
			}
			return jsonResult(map[string]any{"assets": rows, "total": total, "page": page, "page_size": pageSize})
		})

	mcp.AddTool(server, &mcp.Tool{Name: "sync_enterprise_assets", Description: "将选中的企业域名同步到跨任务去重的全局资产清单，并可加入已有或新建资产分组", Annotations: &mcp.ToolAnnotations{IdempotentHint: true, OpenWorldHint: boolPtr(false)}},
		func(ctx context.Context, req *mcp.CallToolRequest, input EnterpriseSyncInput) (*mcp.CallToolResult, any, error) {
			result, err := deps.EnterpriseService.SyncAssets(input.AssetIDs, input.GroupID, input.NewGroupName)
			if err != nil {
				if !services.IsEnterpriseSyncInputError(err) {
					log.Printf("[MCP audit] enterprise action=sync result=failed error=%v", err)
					return errResult(fmt.Errorf("enterprise catalog sync failed")), nil, nil
				}
				return errResult(err), nil, nil
			}
			log.Printf("[MCP audit] enterprise action=sync requested=%d synced=%d group_id=%q", result.RequestedCount, result.SyncedCount, result.GroupID)
			return jsonResult(result)
		})

	mcp.AddTool(server, &mcp.Tool{Name: "launch_enterprise_scan", Description: "将选中的企业域名资产下发为原生扫描任务；必须 confirm=true", Annotations: &mcp.ToolAnnotations{OpenWorldHint: boolPtr(true)}},
		func(ctx context.Context, req *mcp.CallToolRequest, input EnterpriseScanInput) (*mcp.CallToolResult, any, error) {
			if !input.Confirm {
				return errResult(fmt.Errorf("launch requires confirm=true")), nil, nil
			}
			task, targets, err := deps.EnterpriseService.LaunchScan(input.AssetIDs, input.Name, input.PolicyID, input.ScopeID, input.Options, input.Start, "")
			if err != nil {
				if services.IsEnterpriseScanInputError(err) {
					return errResult(err), nil, nil
				}
				log.Printf("[MCP audit] enterprise action=launch_scan result=failed error=%v", err)
				return errResult(fmt.Errorf("enterprise scan handoff failed")), nil, nil
			}
			return jsonResult(map[string]any{"task": task, "targets": targets, "target_count": len(targets)})
		})
}
