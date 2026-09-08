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
	Keyword    string   `json:"keyword" jsonschema:"required,Name or keyword of enterprise"`
	Name       string   `json:"name,omitempty" jsonschema:"Query job name, Default use of keywords"`
	Provider   string   `json:"provider,omitempty" jsonschema:"Providers, Current support icp_query"`
	QueryTypes []string `json:"query_types,omitempty" jsonschema:"Query type arrays: web, app, mapp, kapp; Default web"`
	Confirm    bool     `json:"confirm" jsonschema:"required,Query visits external enterprise data sources, It must be clearly defined. true"`
}

type EnterpriseListInput struct {
	QueryID  string `json:"query_id,omitempty" jsonschema:"Enterprise queries ID, Use only for asset lists"`
	Status   string `json:"status,omitempty" jsonschema:"Task Status Filter: queued, running, completed, failed"`
	Kind     string `json:"kind,omitempty" jsonschema:"Asset type filter: web, app, miniapp, quickapp"`
	Search   string `json:"search,omitempty" jsonschema:"Enterprise, Name, Domain name or filing number keyword"`
	Page     int    `json:"page,omitempty" jsonschema:"Page Number, Default1"`
	PageSize int    `json:"page_size,omitempty" jsonschema:"Number of pages per page, Default20, Max100"`
}

type EnterpriseScanInput struct {
	AssetIDs []string           `json:"asset_ids" jsonschema:"required,Business assets to be scanned ID Array, Up to2000Article"`
	Name     string             `json:"name,omitempty" jsonschema:"Scan Task Name"`
	PolicyID string             `json:"policy_id,omitempty" jsonschema:"Optional Scan Policy ID"`
	ScopeID  string             `json:"scope_id,omitempty" jsonschema:"Optional authorized scan range ID; Empty values use default range"`
	Options  models.TaskOptions `json:"options,omitempty" jsonschema:"Scan Options; Port scans are open at all times."`
	Start    bool               `json:"start,omitempty" jsonschema:"Whether to add scan queues as soon as they are created"`
	Confirm  bool               `json:"confirm" jsonschema:"required,The objectives are identified as mandated and clearly identified true"`
}

type EnterpriseSyncInput struct {
	AssetIDs     []string `json:"asset_ids" jsonschema:"required,Business assets to synchronize to global asset lists ID, Up to2000Article"`
	GroupID      string   `json:"group_id,omitempty" jsonschema:"Selectable grouping of existing assets ID"`
	NewGroupName string   `json:"new_group_name,omitempty" jsonschema:"New asset group name for possible; Can't be with group_id Setup simultaneously"`
}

func RegisterEnterpriseTools(server *mcp.Server, deps *Deps) {
	if deps.EnterpriseService == nil {
		return
	}
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: boolPtr(false)}
	mcp.AddTool(server, &mcp.Tool{Name: "list_enterprise_providers", Description: "Listing configuration and enable status of enterprise asset discovery provider", Annotations: readOnly},
		func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			providers, err := deps.EnterpriseService.ProviderStatus()
			if err != nil {
				return errResult(err), nil, nil
			}
			return jsonResult(map[string]any{"providers": providers})
		})

	mcp.AddTool(server, &mcp.Tool{Name: "create_enterprise_query", Description: "Query enterprise domain names through configured provider, Apply, Small programs and fast-applying assets", Annotations: &mcp.ToolAnnotations{OpenWorldHint: boolPtr(true)}},
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

	mcp.AddTool(server, &mcp.Tool{Name: "list_enterprise_queries", Description: "Paged breakdown of enterprise asset search tasks and classification statistics", Annotations: readOnly},
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

	mcp.AddTool(server, &mcp.Tool{Name: "list_enterprise_assets", Description: "Page-by-page listing of assets found by an enterprise, Available on Query, Type and keyword filter", Annotations: readOnly},
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

	mcp.AddTool(server, &mcp.Tool{Name: "sync_enterprise_assets", Description: "Synchronize selected enterprise domain names to cross-tasked global asset lists, and can add existing or new asset groups", Annotations: &mcp.ToolAnnotations{IdempotentHint: true, OpenWorldHint: boolPtr(false)}},
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

	mcp.AddTool(server, &mcp.Tool{Name: "launch_enterprise_scan", Description: "Issuance of selected enterprise domain name assets as original scan missions; Yes. confirm=true", Annotations: &mcp.ToolAnnotations{OpenWorldHint: boolPtr(true)}},
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
