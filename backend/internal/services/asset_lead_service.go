package services

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

// AssetLeadFinding is the confirmed vulnerability evidence used to derive a lead.
type AssetLeadFinding struct {
	ID              string
	VulnerabilityID string
	TaskID          string
	Severity        string
	Status          string
	Title           string
	URL             string
	Type            string
	Source          string
	MatchType       string
	CreatedAt       time.Time
}

// AssetLeadRelation is the related canonical asset context used to derive a lead.
type AssetLeadRelation struct {
	RelationType string
	Asset        models.AssetEntity
	LastTaskID   string
	LastSeenAt   time.Time
}

type AssetLeadPoC struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Product  string `json:"product,omitempty"`
	PoCType  string `json:"poc_type"`
}

type AssetLeadEvidence struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type AssetLeadRelatedAsset struct {
	AssetID string `json:"asset_id"`
	LeadID  string `json:"lead_id"`
	Kind    string `json:"kind"`
	Value   string `json:"value"`
}

// AssetAttackLead is an explainable, ranked next step for a bounty hunter.
type AssetAttackLead struct {
	ID              string                  `json:"id"`
	AssetID         string                  `json:"asset_id,omitempty"`
	AssetKind       string                  `json:"asset_kind,omitempty"`
	AssetValue      string                  `json:"asset_value,omitempty"`
	Type            string                  `json:"type"`
	Priority        int                     `json:"priority"`
	Severity        string                  `json:"severity"`
	Confidence      int                     `json:"confidence"`
	Title           string                  `json:"title"`
	Reason          string                  `json:"reason"`
	Target          string                  `json:"target"`
	SuggestedAction string                  `json:"suggested_action"`
	Evidence        []AssetLeadEvidence     `json:"evidence"`
	TaskID          string                  `json:"task_id,omitempty"`
	ObservedAt      time.Time               `json:"observed_at"`
	PoC             *AssetLeadPoC           `json:"poc,omitempty"`
	TriageStatus    string                  `json:"triage_status"`
	TriageNote      string                  `json:"triage_note,omitempty"`
	TriageUpdatedAt *time.Time              `json:"triage_updated_at,omitempty"`
	AffectedAssets  int                     `json:"affected_assets,omitempty"`
	RelatedAssets   []AssetLeadRelatedAsset `json:"related_assets,omitempty"`
	DedupeKey       string                  `json:"-"`
}

var sensitivePortProfiles = map[int]struct {
	Name     string
	Severity string
	Priority int
}{
	21:    {Name: "FTP", Severity: "high", Priority: 78},
	22:    {Name: "SSH", Severity: "medium", Priority: 68},
	23:    {Name: "Telnet", Severity: "high", Priority: 86},
	135:   {Name: "RPC", Severity: "medium", Priority: 70},
	445:   {Name: "SMB", Severity: "high", Priority: 84},
	1433:  {Name: "MSSQL", Severity: "high", Priority: 82},
	3306:  {Name: "MySQL", Severity: "high", Priority: 80},
	3389:  {Name: "RDP", Severity: "high", Priority: 84},
	5432:  {Name: "PostgreSQL", Severity: "high", Priority: 80},
	6379:  {Name: "Redis", Severity: "critical", Priority: 90},
	27017: {Name: "MongoDB", Severity: "high", Priority: 82},
}

// AssetLeadFingerprints returns normalized technology signals suitable for PoC matching.
func AssetLeadFingerprints(asset models.AssetEntity) []string {
	data := assetLeadData(asset.CurrentData)
	values := make([]string, 0, 8)
	for _, key := range []string{"fingerprint", "server", "service", "version"} {
		if value := leadString(data[key]); value != "" {
			values = append(values, value)
		}
	}
	if fingerprints, ok := data["fingerprints"].([]any); ok {
		for _, value := range fingerprints {
			if text := leadString(value); text != "" {
				values = append(values, text)
			}
		}
	}
	return normalizedStrings(values)
}

// BuildAssetAttackLeads turns canonical asset evidence into ranked, explainable leads.
func BuildAssetAttackLeads(asset models.AssetEntity, changes []models.AssetChange, findings []AssetLeadFinding, relations []AssetLeadRelation, matchedPoCs []models.PoC) []AssetAttackLead {
	data := assetLeadData(asset.CurrentData)
	leads := make([]AssetAttackLead, 0, len(findings)+len(changes)+len(matchedPoCs)+4)
	seen := make(map[string]struct{})
	add := func(key string, lead AssetAttackLead) {
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		if lead.Target == "" {
			lead.Target = asset.DisplayValue
		}
		lead.AssetID = asset.ID
		lead.AssetKind = asset.Kind
		lead.AssetValue = asset.DisplayValue
		if lead.TriageStatus == "" {
			lead.TriageStatus = models.AssetLeadStatusNew
		}
		if lead.DedupeKey == "" {
			lead.DedupeKey = asset.ID + ":" + lead.ID
		}
		if lead.ObservedAt.IsZero() {
			lead.ObservedAt = asset.LastSeenAt
		}
		leads = append(leads, lead)
	}

	for _, finding := range findings {
		if !VulnerabilityStatusAffectsRisk(finding.Status) {
			continue
		}
		severity := normalizedLeadSeverity(finding.Severity)
		add("finding:"+finding.ID, AssetAttackLead{
			ID: "finding:" + finding.ID, Type: "confirmed_vulnerability", Priority: findingPriority(severity),
			Severity: severity, Confidence: 100, Title: fallbackText(finding.Title, "已确认漏洞"),
			Reason: fmt.Sprintf("%s 已产出可复核的漏洞证据", fallbackText(finding.Source, finding.Type)),
			Target: fallbackText(finding.URL, asset.DisplayValue), SuggestedAction: "复核证明与影响范围，整理可提交证据链",
			Evidence: []AssetLeadEvidence{{Label: "匹配方式", Value: fallbackText(finding.MatchType, "关联")}, {Label: "来源", Value: fallbackText(finding.Source, finding.Type)}},
			TaskID:   finding.TaskID, ObservedAt: finding.CreatedAt,
			DedupeKey: "vulnerability:" + fallbackText(finding.VulnerabilityID, finding.ID),
		})
	}

	if leadBool(data["takeover_vulnerable"]) {
		severity := normalizedLeadSeverity(fallbackText(leadString(data["takeover_severity"]), "critical"))
		service := fallbackText(leadString(data["takeover_service"]), "未知托管服务")
		cname := fallbackText(leadString(data["takeover_cname"]), "未记录 CNAME")
		add("takeover", AssetAttackLead{
			ID: "takeover", Type: "subdomain_takeover", Priority: 98, Severity: severity, Confidence: 96,
			Title: "子域名接管候选", Reason: fmt.Sprintf("DNS 指纹命中 %s 的悬空绑定", service),
			SuggestedAction: "验证资源是否可注册，并保留 DNS 与服务端回显证据",
			Evidence:        []AssetLeadEvidence{{Label: "服务", Value: service}, {Label: "CNAME", Value: cname}},
			TaskID:          asset.LastTaskID, ObservedAt: asset.LastSeenAt,
		})
	}

	if port, ok := canonicalPortNumber(asset.CanonicalKey); asset.Kind == "port" && ok {
		addSensitivePortLead(add, asset, port, asset.DisplayValue, asset.LastTaskID, asset.LastSeenAt)
	}
	if asset.Kind == "ip" {
		for _, relation := range relations {
			if relation.RelationType != "exposes" || relation.Asset.Kind != "port" {
				continue
			}
			if port, ok := canonicalPortNumber(relation.Asset.CanonicalKey); ok {
				addSensitivePortLead(add, relation.Asset, port, relation.Asset.DisplayValue, relation.LastTaskID, relation.LastSeenAt)
			}
		}
	}

	if asset.Kind == "site" || asset.Kind == "url" {
		if keyword, label := managementSurfaceSignal(asset, data); keyword != "" {
			add("management:"+keyword, AssetAttackLead{
				ID: "management:" + keyword, Type: "management_surface", Priority: 72, Severity: "medium", Confidence: 72,
				Title: "管理或认证入口暴露", Reason: fmt.Sprintf("站点特征包含 %s 信号（%s）", label, keyword),
				SuggestedAction: "核查未授权访问、默认凭据、弱口令与登录后越权边界",
				Evidence:        []AssetLeadEvidence{{Label: "命中特征", Value: keyword}, {Label: "页面标题", Value: fallbackText(leadString(data["title"]), "未记录")}},
				TaskID:          asset.LastTaskID, ObservedAt: asset.LastSeenAt,
			})
		}
	}

	fingerprints := AssetLeadFingerprints(asset)
	rankedPoCs := append([]models.PoC{}, matchedPoCs...)
	sort.SliceStable(rankedPoCs, func(i, j int) bool {
		left, right := pocPriority(normalizedLeadSeverity(rankedPoCs[i].Severity)), pocPriority(normalizedLeadSeverity(rankedPoCs[j].Severity))
		if left != right {
			return left > right
		}
		return rankedPoCs[i].Name < rankedPoCs[j].Name
	})
	for index, poc := range rankedPoCs {
		if index >= 8 {
			break
		}
		severity := normalizedLeadSeverity(poc.Severity)
		pocView := &AssetLeadPoC{ID: poc.ID, Name: poc.Name, Severity: severity, Product: poc.Product, PoCType: poc.PoCType}
		add("poc:"+poc.ID, AssetAttackLead{
			ID: "poc:" + poc.ID, Type: "poc_opportunity", Priority: pocPriority(severity), Severity: severity, Confidence: 84,
			Title: "指纹命中可用 PoC", Reason: fmt.Sprintf("%s 与当前技术指纹匹配", poc.Name),
			Target:          assetPoCTarget(asset, data),
			SuggestedAction: "确认授权范围后直接验证，并保存请求与响应证据",
			Evidence:        []AssetLeadEvidence{{Label: "产品", Value: fallbackText(poc.Product, "未标注")}, {Label: "资产指纹", Value: fallbackText(strings.Join(fingerprints, ", "), "未记录")}},
			TaskID:          asset.LastTaskID, ObservedAt: asset.LastSeenAt, PoC: pocView,
		})
	}

	changeLimit := 0
	for _, change := range changes {
		if change.EventType != "modified" || changeLimit >= 5 {
			continue
		}
		changeLimit++
		title, severity, priority, action := changeLeadProfile(change.ChangedFields)
		fields := strings.Join(change.ChangedFields, "、")
		add("change:"+change.ID, AssetAttackLead{
			ID: "change:" + change.ID, Type: "surface_change", Priority: priority, Severity: severity, Confidence: 100,
			Title: title, Reason: fmt.Sprintf("与上一次观测相比，%s 发生变化", fallbackText(fields, "资产状态")),
			SuggestedAction: action, Evidence: []AssetLeadEvidence{{Label: "变化字段", Value: fallbackText(fields, "state")}},
			TaskID: change.TaskID, ObservedAt: change.ObservedAt,
		})
	}

	if (asset.Kind == "port" || asset.Kind == "site") && !asset.FirstSeenAt.IsZero() && time.Since(asset.FirstSeenAt) >= 0 && time.Since(asset.FirstSeenAt) <= 72*time.Hour {
		add("recent-exposure", AssetAttackLead{
			ID: "recent-exposure", Type: "recent_exposure", Priority: 58, Severity: "low", Confidence: 100,
			Title: "最近出现的攻击面", Reason: "该资产在最近 72 小时内首次进入全局资产库",
			SuggestedAction: "优先确认是否为新部署、临时环境或未纳入预期范围的服务",
			Evidence:        []AssetLeadEvidence{{Label: "首次发现", Value: asset.FirstSeenAt.Format(time.RFC3339)}},
			TaskID:          asset.LastTaskID, ObservedAt: asset.FirstSeenAt,
		})
	}

	sort.SliceStable(leads, func(i, j int) bool {
		if leads[i].Priority != leads[j].Priority {
			return leads[i].Priority > leads[j].Priority
		}
		if !leads[i].ObservedAt.Equal(leads[j].ObservedAt) {
			return leads[i].ObservedAt.After(leads[j].ObservedAt)
		}
		return leads[i].ID < leads[j].ID
	})
	return leads
}

func assetPoCTarget(asset models.AssetEntity, data map[string]any) string {
	if asset.Kind != "port" {
		return asset.DisplayValue
	}
	endpoint := strings.TrimSuffix(strings.TrimSuffix(asset.CanonicalKey, "/tcp"), "/udp")
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return asset.DisplayValue
	}
	scheme := "http"
	service := strings.ToLower(leadString(data["service"]))
	if strings.Contains(service, "https") || port == "443" || port == "8443" || port == "9443" {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

func addSensitivePortLead(add func(string, AssetAttackLead), asset models.AssetEntity, port int, target, taskID string, observedAt time.Time) {
	profile, ok := sensitivePortProfiles[port]
	if !ok {
		return
	}
	service := leadString(assetLeadData(asset.CurrentData)["service"])
	reason := fmt.Sprintf("%s 服务直接暴露在 %d 端口", profile.Name, port)
	if service != "" && !strings.EqualFold(service, profile.Name) {
		reason += "，扫描识别为 " + service
	}
	add("port:"+strconv.Itoa(port)+":"+target, AssetAttackLead{
		ID: "port:" + strconv.Itoa(port) + ":" + target, Type: "sensitive_service", Priority: profile.Priority,
		Severity: profile.Severity, Confidence: 92, Title: "敏感服务暴露", Reason: reason, Target: target,
		SuggestedAction: "检查未授权访问、弱口令、默认配置和已知版本漏洞",
		Evidence:        []AssetLeadEvidence{{Label: "端口", Value: strconv.Itoa(port)}, {Label: "服务", Value: fallbackText(service, profile.Name)}},
		TaskID:          taskID, ObservedAt: observedAt, DedupeKey: "sensitive-service:" + target,
	})
}

func assetLeadData(raw string) map[string]any {
	data := make(map[string]any)
	_ = json.Unmarshal([]byte(raw), &data)
	return data
}

func managementSurfaceSignal(asset models.AssetEntity, data map[string]any) (string, string) {
	values := []string{asset.DisplayValue, leadString(data["url"]), leadString(data["title"]), leadString(data["server"])}
	values = append(values, AssetLeadFingerprints(asset)...)
	haystack := strings.ToLower(strings.Join(values, " "))
	keywords := []struct{ value, label string }{
		{"phpmyadmin", "数据库管理"}, {"grafana", "监控后台"}, {"jenkins", "持续集成"}, {"kibana", "日志后台"},
		{"nacos", "配置中心"}, {"swagger", "接口文档"}, {"gitlab", "代码托管"}, {"dashboard", "控制面板"},
		{"admin", "管理后台"}, {"console", "控制台"}, {"management", "管理入口"}, {"login", "认证入口"},
	}
	for _, keyword := range keywords {
		if strings.Contains(haystack, keyword.value) {
			return keyword.value, keyword.label
		}
	}
	return "", ""
}

func changeLeadProfile(fields []string) (string, string, int, string) {
	joined := "\x00" + strings.Join(fields, "\x00") + "\x00"
	has := func(field string) bool { return strings.Contains(joined, "\x00"+field+"\x00") }
	switch {
	case has("takeover_vulnerable") || has("takeover_cname") || has("takeover_service"):
		return "接管状态发生变化", "high", 82, "重新验证 DNS 解析与第三方资源归属"
	case has("status_code") || has("title") || has("server") || has("fingerprints"):
		return "站点关键特征变化", "medium", 70, "对比新旧响应，检查新入口、技术栈和权限边界"
	case has("service") || has("version") || has("banner_sha256") || has("ssl_cert_sha256"):
		return "服务暴露发生变化", "medium", 72, "重新识别服务版本并匹配对应漏洞与 PoC"
	default:
		return "资产状态发生变化", "low", 60, "对比变化前后证据，确认是否产生新的攻击入口"
	}
}

func findingPriority(severity string) int {
	return map[string]int{"critical": 100, "high": 92, "medium": 76, "low": 58, "info": 45}[severity]
}

func pocPriority(severity string) int {
	return map[string]int{"critical": 90, "high": 82, "medium": 70, "low": 58, "info": 48}[severity]
}

func normalizedLeadSeverity(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if _, ok := map[string]struct{}{"critical": {}, "high": {}, "medium": {}, "low": {}, "info": {}}[value]; ok {
		return value
	}
	return "info"
}

func fallbackText(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func leadString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return ""
	}
}

func leadBool(value any) bool {
	result, _ := value.(bool)
	return result
}
