package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/services"
)

const hunterLeadCandidateLimit = 1000

type CanonicalAssetListInput struct {
	Kind     string `json:"kind,omitempty" jsonschema:"资产类型: domain, ip, port, site；默认全部"`
	Status   string `json:"status,omitempty" jsonschema:"资产状态过滤"`
	Search   string `json:"search,omitempty" jsonschema:"按资产值或 canonical key 搜索"`
	MinRisk  int    `json:"min_risk,omitempty" jsonschema:"最低风险分，默认0"`
	Page     int    `json:"page,omitempty" jsonschema:"页码，默认1"`
	PageSize int    `json:"page_size,omitempty" jsonschema:"每页数量，默认20，最大100"`
}

type CanonicalAssetIDInput struct {
	AssetID string `json:"asset_id" jsonschema:"required,canonical asset ID"`
}

type HuntingLeadListInput struct {
	Status   string `json:"status,omitempty" jsonschema:"状态: all, open, new, investigating, validated, ignored"`
	Severity string `json:"severity,omitempty" jsonschema:"严重性: critical, high, medium, low, info"`
	Type     string `json:"type,omitempty" jsonschema:"线索类型过滤"`
	Search   string `json:"search,omitempty" jsonschema:"按资产、标题、原因、动作或备注搜索"`
	Page     int    `json:"page,omitempty" jsonschema:"页码，默认1"`
	PageSize int    `json:"page_size,omitempty" jsonschema:"每页数量，默认20，最大100"`
}

type UpdateLeadTriageInput struct {
	AssetID      string                              `json:"asset_id" jsonschema:"required,主线索 canonical asset ID"`
	LeadID       string                              `json:"lead_id" jsonschema:"required,主线索 ID"`
	Status       string                              `json:"status" jsonschema:"required,状态: new, investigating, validated, ignored"`
	Note         string                              `json:"note,omitempty" jsonschema:"研判备注，最大5000字符"`
	RelatedLeads []services.AssetLeadTriageReference `json:"related_leads,omitempty" jsonschema:"聚类线索中需要同步更新的资产与线索引用，最多99条"`
}

type AssetChangeListInput struct {
	AssetID   string `json:"asset_id,omitempty" jsonschema:"canonical asset ID；为空时查看全局变化"`
	EventType string `json:"event_type,omitempty" jsonschema:"事件类型过滤，例如 modified"`
	Page      int    `json:"page,omitempty" jsonschema:"页码，默认1"`
	PageSize  int    `json:"page_size,omitempty" jsonschema:"每页数量，默认20，最大100"`
}

type AttackEvidenceInput struct {
	AssetID string `json:"asset_id" jsonschema:"required,canonical asset ID"`
	LeadID  string `json:"lead_id" jsonschema:"required,该资产上的线索 ID"`
}

type ExecuteLeadPoCInput struct {
	AssetID string `json:"asset_id" jsonschema:"required,canonical asset ID"`
	LeadID  string `json:"lead_id" jsonschema:"required,必须是带 PoC 的线索 ID"`
	Confirm bool   `json:"confirm" jsonschema:"required,确认目标已获授权并执行外部 PoC 请求"`
}

type UpdateFindingTriageInput struct {
	VulnerabilityID string `json:"vulnerability_id" jsonschema:"required,漏洞证据 ID"`
	Status          string `json:"status" jsonschema:"required,状态: new, validated, submitted, resolved, false_positive, regressed"`
	Note            string `json:"note,omitempty" jsonschema:"人工研判备注，最大5000字符"`
}

type hunterRelationView struct {
	ID           string             `json:"id"`
	Direction    string             `json:"direction"`
	RelationType string             `json:"relation_type"`
	Asset        models.AssetEntity `json:"asset"`
	LastTaskID   string             `json:"last_task_id,omitempty"`
	FirstSeenAt  time.Time          `json:"first_seen_at"`
	LastSeenAt   time.Time          `json:"last_seen_at"`
}

type hunterFindingView struct {
	ID                     string     `json:"id"`
	VulnerabilityID        string     `json:"vulnerability_id"`
	TaskID                 string     `json:"task_id"`
	Severity               string     `json:"severity"`
	Title                  string     `json:"title"`
	URL                    string     `json:"url"`
	Type                   string     `json:"type"`
	Source                 string     `json:"source"`
	MatchType              string     `json:"match_type"`
	Description            string     `json:"description,omitempty"`
	Payload                string     `json:"payload,omitempty"`
	Proof                  string     `json:"proof,omitempty"`
	Status                 string     `json:"status"`
	TriageNote             string     `json:"triage_note,omitempty"`
	TriageUpdatedAt        *time.Time `json:"triage_updated_at,omitempty"`
	LastVerifiedAt         *time.Time `json:"last_verified_at,omitempty"`
	LastVerificationResult string     `json:"last_verification_result,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`
}

func RegisterHunterTools(server *mcp.Server) {
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: boolPtr(false)}

	mcp.AddTool(server, &mcp.Tool{
		Name: "list_canonical_assets", Description: "分页查询跨任务去重后的全局资产清单，并按类型、状态、风险和关键词筛选。", Annotations: readOnly,
	}, func(ctx context.Context, req *mcp.CallToolRequest, input CanonicalAssetListInput) (*mcp.CallToolResult, any, error) {
		page, pageSize := normalizePage(input.Page, input.PageSize)
		query := database.DB.Model(&models.AssetEntity{}).Where("scope_id = ?", models.DefaultAssetScope)
		if kind := strings.ToLower(strings.TrimSpace(input.Kind)); kind != "" && kind != "all" {
			query = query.Where("kind = ?", kind)
		}
		if status := strings.ToLower(strings.TrimSpace(input.Status)); status != "" && status != "all" {
			query = query.Where("status = ?", status)
		}
		if search := strings.TrimSpace(input.Search); search != "" {
			query = query.Where("display_value ILIKE ? OR canonical_key ILIKE ?", "%"+search+"%", "%"+search+"%")
		}
		if input.MinRisk > 0 {
			query = query.Where("risk_score >= ?", input.MinRisk)
		}
		var total int64
		if err := query.Count(&total).Error; err != nil {
			return errResult(err), nil, nil
		}
		var assets []models.AssetEntity
		if err := query.Order("risk_score DESC, last_seen_at DESC, display_value ASC").Limit(pageSize).Offset((page - 1) * pageSize).Find(&assets).Error; err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(map[string]any{"assets": assets, "total": total, "page": page, "page_size": pageSize, "total_pages": (total + int64(pageSize) - 1) / int64(pageSize)})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "get_canonical_asset", Description: "打开 canonical asset 工作台，返回当前快照、观测、关系、变化、漏洞证据和派生攻击线索。", Annotations: readOnly,
	}, func(ctx context.Context, req *mcp.CallToolRequest, input CanonicalAssetIDInput) (*mcp.CallToolResult, any, error) {
		result, err := loadCanonicalAssetWorkbench(strings.TrimSpace(input.AssetID))
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(result)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "list_hunting_leads", Description: "返回全局聚类、排序并叠加研判状态的攻击线索队列，适合挑选下一步验证目标。", Annotations: readOnly,
	}, func(ctx context.Context, req *mcp.CallToolRequest, input HuntingLeadListInput) (*mcp.CallToolResult, any, error) {
		page, pageSize := normalizePage(input.Page, input.PageSize)
		var candidateTotal int64
		assetQuery := database.DB.Model(&models.AssetEntity{}).Where("scope_id = ?", models.DefaultAssetScope)
		if err := assetQuery.Count(&candidateTotal).Error; err != nil {
			return errResult(err), nil, nil
		}
		var assets []models.AssetEntity
		if err := assetQuery.Order("risk_score DESC, last_seen_at DESC, display_value ASC").Limit(hunterLeadCandidateLimit).Find(&assets).Error; err != nil {
			return errResult(err), nil, nil
		}
		leads, err := services.BuildAssetLeadQueue(database.DB, assets)
		if err != nil {
			return errResult(err), nil, nil
		}
		triages, err := services.LoadAssetLeadTriages(database.DB, services.AssetIDs(assets))
		if err != nil {
			return errResult(err), nil, nil
		}
		services.ApplyAssetLeadTriages(leads, triages)
		leads = services.CollapseDuplicateAssetAttackLeads(leads)
		stats := services.SummarizeAssetAttackLeads(leads)
		filtered := services.FilterAndSortAssetAttackLeads(leads, services.AssetLeadQueueFilter{
			Status: input.Status, Severity: input.Severity, Type: input.Type, Query: input.Search,
		})
		total := len(filtered)
		start := (page - 1) * pageSize
		if start > total {
			start = total
		}
		end := start + pageSize
		if end > total {
			end = total
		}
		return jsonResult(map[string]any{
			"leads": filtered[start:end], "stats": stats, "total": total, "page": page, "page_size": pageSize,
			"total_pages": (total + pageSize - 1) / pageSize, "candidate_assets": len(assets), "truncated": candidateTotal > int64(len(assets)),
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "update_lead_triage", Description: "更新一条或一个聚类内多条攻击线索的研判状态和备注。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(false), IdempotentHint: true, OpenWorldHint: boolPtr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input UpdateLeadTriageInput) (*mcp.CallToolResult, any, error) {
		saved, updatedCount, err := services.UpdateAssetLeadTriages(database.DB, services.AssetLeadTriageUpdate{
			AssetID: input.AssetID, LeadID: input.LeadID, Status: input.Status, Note: input.Note, RelatedLeads: input.RelatedLeads,
		})
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(map[string]any{"triage": saved, "updated_count": updatedCount})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "update_finding_triage", Description: "更新漏洞证据的人工状态和备注；已解决或误报会从资产风险分中排除。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(false), IdempotentHint: true, OpenWorldHint: boolPtr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input UpdateFindingTriageInput) (*mcp.CallToolResult, any, error) {
		finding, assetIDs, err := services.UpdateFindingTriage(database.DB, services.FindingTriageInput{
			VulnerabilityID: input.VulnerabilityID, Status: input.Status, Note: input.Note, ActorID: "mcp",
		})
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(map[string]any{"finding": finding, "asset_ids": assetIDs})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "list_asset_changes", Description: "分页查看 canonical asset 的新增与字段变化时间线，可限定单个资产。", Annotations: readOnly,
	}, func(ctx context.Context, req *mcp.CallToolRequest, input AssetChangeListInput) (*mcp.CallToolResult, any, error) {
		page, pageSize := normalizePage(input.Page, input.PageSize)
		query := database.DB.Model(&models.AssetChange{})
		if assetID := strings.TrimSpace(input.AssetID); assetID != "" {
			query = query.Where("asset_id = ?", assetID)
		}
		if eventType := strings.TrimSpace(input.EventType); eventType != "" && eventType != "all" {
			query = query.Where("event_type = ?", eventType)
		}
		var total int64
		if err := query.Count(&total).Error; err != nil {
			return errResult(err), nil, nil
		}
		var changes []models.AssetChange
		if err := query.Order("observed_at DESC").Limit(pageSize).Offset((page - 1) * pageSize).Find(&changes).Error; err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(map[string]any{"changes": changes, "total": total, "page": page, "page_size": pageSize, "total_pages": (total + int64(pageSize) - 1) / int64(pageSize)})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "get_attack_evidence", Description: "返回指定资产线索的完整可复核证据，包括资产快照、漏洞证明、PoC 验证日志、变化记录和线索上下文。", Annotations: readOnly,
	}, func(ctx context.Context, req *mcp.CallToolRequest, input AttackEvidenceInput) (*mcp.CallToolResult, any, error) {
		asset, lead, err := loadAssetLead(strings.TrimSpace(input.AssetID), strings.TrimSpace(input.LeadID))
		if err != nil {
			return errResult(err), nil, nil
		}
		var changes []models.AssetChange
		if err := database.DB.Where("asset_id = ?", asset.ID).Order("observed_at DESC").Limit(100).Find(&changes).Error; err != nil {
			return errResult(err), nil, nil
		}
		var findings []hunterFindingView
		if err := loadHunterFindings(asset.ID, &findings); err != nil {
			return errResult(err), nil, nil
		}
		executions, err := services.LoadAssetLeadPoCExecutions(database.DB, asset.ID)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(map[string]any{"asset": asset, "lead": lead, "changes": changes, "findings": findings, "executions": executions})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "execute_lead_poc", Description: "对带有已匹配 PoC 的攻击线索执行一次实际验证并写入执行日志；必须 confirm=true。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(true)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ExecuteLeadPoCInput) (*mcp.CallToolResult, any, error) {
		if !input.Confirm {
			return errResult(errors.New("PoC execution requires confirm=true")), nil, nil
		}
		result, execErr := services.ExecuteAssetLeadPoC(database.DB, nil, services.AssetLeadPoCExecutionInput{
			AssetID: input.AssetID, LeadID: input.LeadID, InvocationSource: "mcp",
		})
		if result == nil {
			return errResult(execErr), nil, nil
		}
		payload := map[string]any{"result": result.Result, "details": result.Details, "lead": result.Lead, "audit_saved": !errors.Is(execErr, services.ErrAssetLeadPoCAudit)}
		if result.Finding != nil && !errors.Is(execErr, services.ErrAssetLeadPoCAudit) {
			payload["finding"] = result.Finding
			payload["finding_link"] = result.FindingLink
			payload["finding_created"] = result.FindingNew
		}
		if !errors.Is(execErr, services.ErrAssetLeadPoCAudit) {
			payload["execution_log"] = result.ExecutionLog
		}
		if execErr != nil {
			return errResult(execErr), payload, nil
		}
		return jsonResult(payload)
	})
}

func loadCanonicalAssetWorkbench(assetID string) (map[string]any, error) {
	if assetID == "" {
		return nil, errors.New("asset_id is required")
	}
	var asset models.AssetEntity
	if err := database.DB.Where("id = ? AND scope_id = ?", assetID, models.DefaultAssetScope).First(&asset).Error; err != nil {
		return nil, fmt.Errorf("canonical asset not found: %w", err)
	}
	var observations []models.AssetObservation
	if err := database.DB.Where("asset_id = ?", assetID).Order("observed_at DESC").Limit(100).Find(&observations).Error; err != nil {
		return nil, err
	}
	var primaryObservation models.AssetObservation
	primaryResult := database.DB.Where("asset_id = ? AND source_type = ?", assetID, asset.Kind).Order("observed_at DESC, id DESC").Limit(1).Find(&primaryObservation)
	if primaryResult.Error != nil {
		return nil, primaryResult.Error
	}
	if primaryResult.RowsAffected == 1 {
		asset.CurrentData = primaryObservation.Payload
	}
	var changes []models.AssetChange
	if err := database.DB.Where("asset_id = ?", assetID).Order("observed_at DESC").Limit(100).Find(&changes).Error; err != nil {
		return nil, err
	}
	executions, err := services.LoadAssetLeadPoCExecutions(database.DB, assetID)
	if err != nil {
		return nil, err
	}
	relations, err := loadHunterRelations(assetID)
	if err != nil {
		return nil, err
	}
	var findings []hunterFindingView
	if err := loadHunterFindings(assetID, &findings); err != nil {
		return nil, err
	}
	leads, err := services.BuildAssetLeadQueue(database.DB, []models.AssetEntity{asset})
	if err != nil {
		return nil, err
	}
	triages, err := services.LoadAssetLeadTriages(database.DB, []string{asset.ID})
	if err != nil {
		return nil, err
	}
	services.ApplyAssetLeadTriages(leads, triages)
	return map[string]any{"asset": asset, "observations": observations, "relations": relations, "findings": findings, "changes": changes, "executions": executions, "leads": leads}, nil
}

func loadAssetLead(assetID, leadID string) (models.AssetEntity, services.AssetAttackLead, error) {
	return services.LoadAssetAttackLead(database.DB, assetID, leadID)
}

func loadHunterRelations(assetID string) ([]hunterRelationView, error) {
	var relations []models.CanonicalAssetRelation
	if err := database.DB.Where("from_asset_id = ? OR to_asset_id = ?", assetID, assetID).Order("last_seen_at DESC").Limit(100).Find(&relations).Error; err != nil {
		return nil, err
	}
	relatedIDs := make([]string, 0, len(relations))
	for _, relation := range relations {
		if relation.FromAssetID == assetID {
			relatedIDs = append(relatedIDs, relation.ToAssetID)
		} else {
			relatedIDs = append(relatedIDs, relation.FromAssetID)
		}
	}
	assetMap := make(map[string]models.AssetEntity, len(relatedIDs))
	if len(relatedIDs) > 0 {
		var relatedAssets []models.AssetEntity
		if err := database.DB.Where("id IN ?", relatedIDs).Find(&relatedAssets).Error; err != nil {
			return nil, err
		}
		for _, asset := range relatedAssets {
			assetMap[asset.ID] = asset
		}
	}
	views := make([]hunterRelationView, 0, len(relations))
	for _, relation := range relations {
		direction, relatedID := "outgoing", relation.ToAssetID
		if relation.ToAssetID == assetID {
			direction, relatedID = "incoming", relation.FromAssetID
		}
		views = append(views, hunterRelationView{ID: relation.ID, Direction: direction, RelationType: relation.RelationType, Asset: assetMap[relatedID], LastTaskID: relation.LastTaskID, FirstSeenAt: relation.FirstSeenAt, LastSeenAt: relation.LastSeenAt})
	}
	return views, nil
}

func loadHunterFindings(assetID string, destination *[]hunterFindingView) error {
	return database.DB.Table("asset_vulnerability_links AS links").
		Select("links.id, links.vulnerability_id, links.task_id, links.severity, links.match_type, vulnerabilities.status, vulnerabilities.title, vulnerabilities.url, vulnerabilities.type, vulnerabilities.source, vulnerabilities.description, vulnerabilities.payload, vulnerabilities.proof, vulnerabilities.triage_note, vulnerabilities.triage_updated_at, vulnerabilities.last_verified_at, vulnerabilities.last_verification_result, vulnerabilities.created_at").
		Joins("JOIN vulnerabilities ON vulnerabilities.id = links.vulnerability_id").Where("links.asset_id = ?", assetID).
		Order("CASE links.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, vulnerabilities.created_at DESC").Limit(100).Scan(destination).Error
}
