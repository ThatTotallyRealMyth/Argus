package services

import (
	"sort"
	"strings"

	"github.com/reconmaster/backend/internal/models"
)

type AssetLeadQueueFilter struct {
	Status   string
	Severity string
	Type     string
	Query    string
}

type AssetLeadQueueStats struct {
	Total         int `json:"total"`
	New           int `json:"new"`
	Investigating int `json:"investigating"`
	Validated     int `json:"validated"`
	Ignored       int `json:"ignored"`
	CriticalHigh  int `json:"critical_high"`
	Assets        int `json:"assets"`
}

func AssetLeadTriageKey(assetID, leadID string) string { return assetID + "\x00" + leadID }

func ApplyAssetLeadTriages(leads []AssetAttackLead, triages map[string]models.AssetLeadTriage) {
	for index := range leads {
		triage, ok := triages[AssetLeadTriageKey(leads[index].AssetID, leads[index].ID)]
		if !ok {
			leads[index].TriageStatus = models.AssetLeadStatusNew
			continue
		}
		leads[index].TriageStatus = triage.Status
		leads[index].TriageNote = triage.Note
		updatedAt := triage.UpdatedAt
		leads[index].TriageUpdatedAt = &updatedAt
	}
}

// CollapseDuplicateAssetAttackLeads reduces cross-asset noise while retaining every affected asset.
func CollapseDuplicateAssetAttackLeads(leads []AssetAttackLead) []AssetAttackLead {
	collapsed := make([]AssetAttackLead, 0, len(leads))
	groupIndex := make(map[string]int)
	for _, lead := range leads {
		key := lead.DedupeKey
		if key == "" {
			key = lead.AssetID + ":" + lead.ID
		}
		index, exists := groupIndex[key]
		if !exists {
			lead.RelatedAssets = []AssetLeadRelatedAsset{{AssetID: lead.AssetID, LeadID: lead.ID, Kind: lead.AssetKind, Value: lead.AssetValue}}
			lead.AffectedAssets = 1
			groupIndex[key] = len(collapsed)
			collapsed = append(collapsed, lead)
			continue
		}
		current := &collapsed[index]
		related := appendUniqueLeadAsset(current.RelatedAssets, AssetLeadRelatedAsset{AssetID: lead.AssetID, LeadID: lead.ID, Kind: lead.AssetKind, Value: lead.AssetValue})
		if preferAttackLeadRepresentative(lead, *current) {
			lead.RelatedAssets = related
			lead.AffectedAssets = len(related)
			*current = lead
		} else {
			current.RelatedAssets = related
			current.AffectedAssets = len(related)
		}
	}
	return collapsed
}

func appendUniqueLeadAsset(assets []AssetLeadRelatedAsset, asset AssetLeadRelatedAsset) []AssetLeadRelatedAsset {
	for _, current := range assets {
		if current.AssetID == asset.AssetID && current.LeadID == asset.LeadID {
			return assets
		}
	}
	return append(assets, asset)
}

func preferAttackLeadRepresentative(candidate, current AssetAttackLead) bool {
	statusRank := func(status string) int {
		switch status {
		case models.AssetLeadStatusValidated:
			return 4
		case models.AssetLeadStatusInvestigating:
			return 3
		case models.AssetLeadStatusIgnored:
			return 2
		case models.AssetLeadStatusNew, "":
			return 1
		default:
			return 0
		}
	}
	if statusRank(candidate.TriageStatus) != statusRank(current.TriageStatus) {
		return statusRank(candidate.TriageStatus) > statusRank(current.TriageStatus)
	}
	kindRank := map[string]int{"site": 4, "domain": 3, "port": 2, "ip": 1}
	if kindRank[candidate.AssetKind] != kindRank[current.AssetKind] {
		return kindRank[candidate.AssetKind] > kindRank[current.AssetKind]
	}
	if candidate.Priority != current.Priority {
		return candidate.Priority > current.Priority
	}
	if !candidate.ObservedAt.Equal(current.ObservedAt) {
		return candidate.ObservedAt.After(current.ObservedAt)
	}
	return candidate.AssetValue < current.AssetValue
}

func SummarizeAssetAttackLeads(leads []AssetAttackLead) AssetLeadQueueStats {
	stats := AssetLeadQueueStats{}
	assets := make(map[string]struct{})
	for _, lead := range leads {
		stats.Total++
		if len(lead.RelatedAssets) > 0 {
			for _, asset := range lead.RelatedAssets {
				assets[asset.AssetID] = struct{}{}
			}
		} else {
			assets[lead.AssetID] = struct{}{}
		}
		switch lead.TriageStatus {
		case models.AssetLeadStatusInvestigating:
			stats.Investigating++
		case models.AssetLeadStatusValidated:
			stats.Validated++
		case models.AssetLeadStatusIgnored:
			stats.Ignored++
		default:
			stats.New++
		}
		if lead.Severity == "critical" || lead.Severity == "high" {
			stats.CriticalHigh++
		}
	}
	stats.Assets = len(assets)
	return stats
}

func FilterAndSortAssetAttackLeads(leads []AssetAttackLead, filter AssetLeadQueueFilter) []AssetAttackLead {
	status := strings.ToLower(strings.TrimSpace(filter.Status))
	severity := strings.ToLower(strings.TrimSpace(filter.Severity))
	leadType := strings.ToLower(strings.TrimSpace(filter.Type))
	query := strings.ToLower(strings.TrimSpace(filter.Query))
	filtered := make([]AssetAttackLead, 0, len(leads))
	for _, lead := range leads {
		leadStatus := lead.TriageStatus
		if leadStatus == "" {
			leadStatus = models.AssetLeadStatusNew
		}
		if status != "" && status != "all" {
			if status == "open" {
				if leadStatus != models.AssetLeadStatusNew && leadStatus != models.AssetLeadStatusInvestigating {
					continue
				}
			} else if leadStatus != status {
				continue
			}
		}
		if severity != "" && severity != "all" && lead.Severity != severity {
			continue
		}
		if leadType != "" && leadType != "all" && lead.Type != leadType {
			continue
		}
		if query != "" {
			values := []string{lead.AssetValue, lead.Target, lead.Title, lead.Reason, lead.SuggestedAction, lead.TriageNote}
			for _, asset := range lead.RelatedAssets {
				values = append(values, asset.Value)
			}
			haystack := strings.ToLower(strings.Join(values, " "))
			if !strings.Contains(haystack, query) {
				continue
			}
		}
		filtered = append(filtered, lead)
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		if filtered[i].Priority != filtered[j].Priority {
			return filtered[i].Priority > filtered[j].Priority
		}
		if !filtered[i].ObservedAt.Equal(filtered[j].ObservedAt) {
			return filtered[i].ObservedAt.After(filtered[j].ObservedAt)
		}
		if filtered[i].AssetValue != filtered[j].AssetValue {
			return filtered[i].AssetValue < filtered[j].AssetValue
		}
		return filtered[i].ID < filtered[j].ID
	})
	return filtered
}
