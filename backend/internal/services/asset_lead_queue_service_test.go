package services

import (
	"testing"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

func TestAssetLeadQueueAppliesTriageAndFiltersOpen(t *testing.T) {
	now := time.Now().UTC()
	leads := []AssetAttackLead{
		{ID: "lead-new", AssetID: "asset-1", AssetValue: "a.example", Severity: "high", Type: "management_surface", Priority: 80, ObservedAt: now, TriageStatus: models.AssetLeadStatusNew},
		{ID: "lead-investigating", AssetID: "asset-2", AssetValue: "b.example", Severity: "medium", Type: "surface_change", Priority: 70, ObservedAt: now.Add(-time.Minute), TriageStatus: models.AssetLeadStatusNew},
		{ID: "lead-ignored", AssetID: "asset-3", AssetValue: "c.example", Severity: "critical", Type: "sensitive_service", Priority: 95, ObservedAt: now.Add(-time.Hour), TriageStatus: models.AssetLeadStatusNew},
	}
	triages := map[string]models.AssetLeadTriage{
		AssetLeadTriageKey("asset-2", "lead-investigating"): {Status: models.AssetLeadStatusInvestigating, Note: "check auth"},
		AssetLeadTriageKey("asset-3", "lead-ignored"):       {Status: models.AssetLeadStatusIgnored},
	}
	ApplyAssetLeadTriages(leads, triages)
	filtered := FilterAndSortAssetAttackLeads(leads, AssetLeadQueueFilter{Status: "open"})
	if len(filtered) != 2 || filtered[0].ID != "lead-new" || filtered[1].TriageNote != "check auth" {
		t.Fatalf("unexpected open queue: %#v", filtered)
	}
	stats := SummarizeAssetAttackLeads(leads)
	if stats.Total != 3 || stats.New != 1 || stats.Investigating != 1 || stats.Ignored != 1 || stats.CriticalHigh != 2 || stats.Assets != 3 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
}

func TestAssetLeadQueueSearchesNotesAndKeepsPriorityOrder(t *testing.T) {
	now := time.Now().UTC()
	leads := []AssetAttackLead{
		{ID: "lower", AssetID: "asset-1", AssetValue: "app.example", Severity: "medium", Type: "surface_change", Priority: 60, ObservedAt: now, TriageStatus: models.AssetLeadStatusInvestigating, TriageNote: "authorization boundary"},
		{ID: "higher", AssetID: "asset-2", AssetValue: "admin.example", Severity: "high", Type: "management_surface", Priority: 90, ObservedAt: now.Add(-time.Hour), TriageStatus: models.AssetLeadStatusInvestigating, TriageNote: "authorization bypass"},
	}
	filtered := FilterAndSortAssetAttackLeads(leads, AssetLeadQueueFilter{Status: "investigating", Query: "authorization"})
	if len(filtered) != 2 || filtered[0].ID != "higher" {
		t.Fatalf("unexpected filtered order: %#v", filtered)
	}
}

func TestCollapseDuplicateAssetAttackLeadsKeepsAffectedAssets(t *testing.T) {
	now := time.Now().UTC()
	leads := []AssetAttackLead{
		{ID: "finding:domain-link", DedupeKey: "vulnerability:vuln-1", AssetID: "domain-1", AssetKind: "domain", AssetValue: "admin.example.com", Title: "same finding", Priority: 92, TriageStatus: models.AssetLeadStatusNew, ObservedAt: now},
		{ID: "finding:site-link", DedupeKey: "vulnerability:vuln-1", AssetID: "site-1", AssetKind: "site", AssetValue: "https://admin.example.com/login", Title: "same finding", Priority: 92, TriageStatus: models.AssetLeadStatusNew, ObservedAt: now},
		{ID: "management:admin", DedupeKey: "site-1:management:admin", AssetID: "site-1", AssetKind: "site", AssetValue: "https://admin.example.com/login", Title: "management", Priority: 72, TriageStatus: models.AssetLeadStatusInvestigating, ObservedAt: now},
	}
	collapsed := CollapseDuplicateAssetAttackLeads(leads)
	if len(collapsed) != 2 {
		t.Fatalf("collapsed count = %d, want 2: %#v", len(collapsed), collapsed)
	}
	if collapsed[0].AssetID != "site-1" || collapsed[0].AffectedAssets != 2 || len(collapsed[0].RelatedAssets) != 2 {
		t.Fatalf("unexpected vulnerability cluster: %#v", collapsed[0])
	}
	if collapsed[0].RelatedAssets[0].LeadID != "finding:domain-link" || collapsed[0].RelatedAssets[1].LeadID != "finding:site-link" {
		t.Fatalf("cluster did not retain member lead IDs: %#v", collapsed[0].RelatedAssets)
	}
	stats := SummarizeAssetAttackLeads(collapsed)
	if stats.Total != 2 || stats.Assets != 2 {
		t.Fatalf("unexpected collapsed stats: %#v", stats)
	}
}

func TestCollapseDuplicateAssetAttackLeadsPreservesIgnoredClusterState(t *testing.T) {
	now := time.Now().UTC()
	leads := []AssetAttackLead{
		{ID: "finding:domain-link", DedupeKey: "vulnerability:vuln-1", AssetID: "domain-1", AssetKind: "domain", AssetValue: "admin.example.com", TriageStatus: models.AssetLeadStatusNew, ObservedAt: now},
		{ID: "finding:site-link", DedupeKey: "vulnerability:vuln-1", AssetID: "site-1", AssetKind: "site", AssetValue: "https://admin.example.com/login", TriageStatus: models.AssetLeadStatusIgnored, TriageNote: "duplicate reviewed", ObservedAt: now},
	}
	collapsed := CollapseDuplicateAssetAttackLeads(leads)
	if len(collapsed) != 1 || collapsed[0].TriageStatus != models.AssetLeadStatusIgnored || collapsed[0].TriageNote != "duplicate reviewed" {
		t.Fatalf("ignored cluster state was lost: %#v", collapsed)
	}
}
