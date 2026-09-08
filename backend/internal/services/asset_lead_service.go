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
			Severity: severity, Confidence: 100, Title: fallbackText(finding.Title, "Gap identified"),
			Reason: fmt.Sprintf("%s Producing and re-readable gaps of evidence", fallbackText(finding.Source, finding.Type)),
			Target: fallbackText(finding.URL, asset.DisplayValue), SuggestedAction: "Review of proof of review and scope of impact, Collating the chain of evidence available for submission",
			Evidence: []AssetLeadEvidence{{Label: "Match", Value: fallbackText(finding.MatchType, "Association")}, {Label: "Source", Value: fallbackText(finding.Source, finding.Type)}},
			TaskID:   finding.TaskID, ObservedAt: finding.CreatedAt,
			DedupeKey: "vulnerability:" + fallbackText(finding.VulnerabilityID, finding.ID),
		})
	}

	if leadBool(data["takeover_vulnerable"]) {
		severity := normalizedLeadSeverity(fallbackText(leadString(data["takeover_severity"]), "critical"))
		service := fallbackText(leadString(data["takeover_service"]), "Unknown hosting services")
		cname := fallbackText(leadString(data["takeover_cname"]), "Unrecorded CNAME")
		add("takeover", AssetAttackLead{
			ID: "takeover", Type: "subdomain_takeover", Priority: 98, Severity: severity, Confidence: 96,
			Title: "Subdomain name takes over the candidate", Reason: fmt.Sprintf("DNS Fingerprint hit. %s The suspended air is tied.", service),
			SuggestedAction: "Verifying the registration of resources, And keep it. DNS Reveal evidence with the server",
			Evidence:        []AssetLeadEvidence{{Label: "Services", Value: service}, {Label: "CNAME", Value: cname}},
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
				Title: "Manage or authenticate entrance exposure", Reason: fmt.Sprintf("Site Character Contains %s Signal (%s)", label, keyword),
				SuggestedAction: "Verification of unauthorized visits, Default evidence, Weak password and access to the border overstepping authority",
				Evidence:        []AssetLeadEvidence{{Label: "Hit Character", Value: keyword}, {Label: "Page Title", Value: fallbackText(leadString(data["title"]), "Unrecorded")}},
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
			Title: "Fingerprint hits are available. PoC", Reason: fmt.Sprintf("%s Matching current technical fingerprints", poc.Name),
			Target:          assetPoCTarget(asset, data),
			SuggestedAction: "Direct verification after confirmation of authorized range, And keep the request and respond to the evidence.",
			Evidence:        []AssetLeadEvidence{{Label: "Products", Value: fallbackText(poc.Product, "Unmarked")}, {Label: "Asset fingerprint.", Value: fallbackText(strings.Join(fingerprints, ", "), "Unrecorded")}},
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
		fields := strings.Join(change.ChangedFields, ", ")
		add("change:"+change.ID, AssetAttackLead{
			ID: "change:" + change.ID, Type: "surface_change", Priority: priority, Severity: severity, Confidence: 100,
			Title: title, Reason: fmt.Sprintf("Compared to previous observations, %s Change", fallbackText(fields, "Asset status")),
			SuggestedAction: action, Evidence: []AssetLeadEvidence{{Label: "Change Fields", Value: fallbackText(fields, "state")}},
			TaskID: change.TaskID, ObservedAt: change.ObservedAt,
		})
	}

	if (asset.Kind == "port" || asset.Kind == "site") && !asset.FirstSeenAt.IsZero() && time.Since(asset.FirstSeenAt) >= 0 && time.Since(asset.FirstSeenAt) <= 72*time.Hour {
		add("recent-exposure", AssetAttackLead{
			ID: "recent-exposure", Type: "recent_exposure", Priority: 58, Severity: "low", Confidence: 100,
			Title: "Recent attacks", Reason: "The asset is in the nearest position. 72 First access to global asset pool within hours",
			SuggestedAction: "Priority is given to identifying new deployments, Temporary environment or services not included in the expected range",
			Evidence:        []AssetLeadEvidence{{Label: "First Discovery", Value: asset.FirstSeenAt.Format(time.RFC3339)}},
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
	reason := fmt.Sprintf("%s The service is exposed directly to %d Port", profile.Name, port)
	if service != "" && !strings.EqualFold(service, profile.Name) {
		reason += ", Scan As " + service
	}
	add("port:"+strconv.Itoa(port)+":"+target, AssetAttackLead{
		ID: "port:" + strconv.Itoa(port) + ":" + target, Type: "sensitive_service", Priority: profile.Priority,
		Severity: profile.Severity, Confidence: 92, Title: "Exposure to sensitive services", Reason: reason, Target: target,
		SuggestedAction: "Check for unauthorized access, Weak password., Default Configuration and Known Version Broker",
		Evidence:        []AssetLeadEvidence{{Label: "Port", Value: strconv.Itoa(port)}, {Label: "Services", Value: fallbackText(service, profile.Name)}},
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
		{"phpmyadmin", "Database management"}, {"grafana", "Monitor the backstage."}, {"jenkins", "Continuous Integration"}, {"kibana", "Log Back"},
		{"nacos", "Configure Centre"}, {"swagger", "Interface Document"}, {"gitlab", "Code Host"}, {"dashboard", "Control Panel"},
		{"admin", "Manage backstage"}, {"console", "Console"}, {"management", "Manage the entrances"}, {"login", "Authentication entrance"},
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
		return "The state of the takeover has changed.", "high", 82, "Revalidate DNS Resolve third party resource attribution"
	case has("status_code") || has("title") || has("server") || has("fingerprints"):
		return "Site fingerprint changed", "medium", 70, "Compare the previous and current responses for new entry points, technology changes, and trust-boundary changes"
	case has("service") || has("version") || has("banner_sha256") || has("ssl_cert_sha256"):
		return "Change in service exposure", "medium", 72, "Re-identify service version and match the matching bugs and PoC"
	default:
		return "Change in asset status", "low", 60, "Evidence before and after the comparison of changes, Confirm if a new attack entrance is created."
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
