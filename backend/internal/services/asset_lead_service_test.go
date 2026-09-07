package services

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/scanner"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type recordingLeadPoCExecutor struct {
	calls      int
	target     string
	vulnerable bool
	message    string
	details    string
}

func (executor *recordingLeadPoCExecutor) Execute(_ *models.PoC, target string) (*scanner.ExecuteResult, error) {
	executor.calls++
	executor.target = target
	message := executor.message
	if message == "" {
		message = "not matched"
	}
	details := executor.details
	if details == "" {
		details = "Status: 200\nMatched: status"
	}
	return &scanner.ExecuteResult{Vulnerable: executor.vulnerable, Message: message, Details: details}, nil
}

func TestBuildAssetAttackLeadsRanksConfirmedSignals(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	payload, _ := json.Marshal(map[string]any{
		"domain": "docs.example.com", "takeover_vulnerable": true, "takeover_service": "GitHub Pages",
		"takeover_cname": "orphan.github.io", "takeover_severity": "critical",
	})
	asset := models.AssetEntity{
		ID: "asset-domain", Kind: "domain", DisplayValue: "docs.example.com", CanonicalKey: "docs.example.com",
		CurrentData: string(payload), LastTaskID: "task-current", FirstSeenAt: now.Add(-24 * time.Hour), LastSeenAt: now,
	}
	findings := []AssetLeadFinding{{
		ID: "finding-1", TaskID: "task-finding", Severity: "high", Title: "Confirmed access control bypass",
		URL: "https://docs.example.com/admin", Source: "nuclei", MatchType: "hostname", CreatedAt: now.Add(-time.Minute),
	}}

	leads := BuildAssetAttackLeads(asset, nil, findings, nil, nil)
	if len(leads) != 2 {
		t.Fatalf("lead count = %d, want 2: %#v", len(leads), leads)
	}
	if leads[0].Type != "subdomain_takeover" || leads[0].Priority != 98 {
		t.Fatalf("first lead = %#v, want takeover priority 98", leads[0])
	}
	if leads[1].Type != "confirmed_vulnerability" || leads[1].Confidence != 100 {
		t.Fatalf("second lead = %#v, want confirmed vulnerability", leads[1])
	}
}

func TestBuildAssetAttackLeadsUsesRelatedSensitivePorts(t *testing.T) {
	now := time.Now().UTC().Add(-7 * 24 * time.Hour)
	asset := models.AssetEntity{ID: "asset-ip", Kind: "ip", DisplayValue: "203.0.113.9", CanonicalKey: "203.0.113.9", LastSeenAt: now}
	portPayload, _ := json.Marshal(map[string]any{"service": "redis", "version": "7.2"})
	relations := []AssetLeadRelation{{
		RelationType: "exposes", LastTaskID: "task-port", LastSeenAt: now,
		Asset: models.AssetEntity{ID: "asset-port", Kind: "port", DisplayValue: "203.0.113.9:6379/tcp", CanonicalKey: "203.0.113.9:6379/tcp", CurrentData: string(portPayload)},
	}}

	leads := BuildAssetAttackLeads(asset, nil, nil, relations, nil)
	if len(leads) != 1 {
		t.Fatalf("lead count = %d, want 1: %#v", len(leads), leads)
	}
	lead := leads[0]
	if lead.Type != "sensitive_service" || lead.Severity != "critical" || lead.Target != "203.0.113.9:6379/tcp" {
		t.Fatalf("sensitive port lead = %#v", lead)
	}
	if lead.TaskID != "task-port" {
		t.Fatalf("task id = %q, want task-port", lead.TaskID)
	}
}

func TestBuildAssetAttackLeadsIncludesManagementPoCAndChange(t *testing.T) {
	now := time.Now().UTC().Add(-8 * 24 * time.Hour)
	payload, _ := json.Marshal(map[string]any{
		"url": "https://ops.example.com/admin", "title": "Grafana Login", "server": "nginx",
		"fingerprints": []string{"Grafana", "nginx"},
	})
	asset := models.AssetEntity{
		ID: "asset-site", Kind: "site", DisplayValue: "https://ops.example.com/admin", CanonicalKey: "https://ops.example.com/admin",
		CurrentData: string(payload), LastTaskID: "task-site", FirstSeenAt: now, LastSeenAt: now,
	}
	changes := []models.AssetChange{{
		ID: "change-1", EventType: "modified", ChangedFields: []string{"server", "fingerprints"}, TaskID: "task-change", ObservedAt: now,
	}}
	pocs := []models.PoC{{ID: "poc-1", Name: "Grafana CVE check", Severity: "high", Product: "Grafana", PoCType: "nuclei"}}

	leads := BuildAssetAttackLeads(asset, changes, nil, nil, pocs)
	if len(leads) != 3 {
		t.Fatalf("lead count = %d, want 3: %#v", len(leads), leads)
	}
	if leads[0].Type != "poc_opportunity" || leads[0].PoC == nil || leads[0].PoC.ID != "poc-1" {
		t.Fatalf("first lead = %#v, want PoC opportunity", leads[0])
	}
	found := map[string]bool{}
	for _, lead := range leads {
		found[lead.Type] = true
	}
	if !found["management_surface"] || !found["surface_change"] {
		t.Fatalf("missing management or change lead: %#v", found)
	}
	fingerprints := AssetLeadFingerprints(asset)
	if len(fingerprints) != 2 || fingerprints[0] != "Grafana" || fingerprints[1] != "nginx" {
		t.Fatalf("fingerprints = %#v, want normalized technology signals", fingerprints)
	}
}

func TestBuildAssetAttackLeadsRecognizesManagementURLAssets(t *testing.T) {
	asset := models.AssetEntity{
		ID: "asset-url", Kind: "url", DisplayValue: "https://example.com/admin/login",
		CanonicalKey: "https://example.com/admin/login", CurrentData: `{"url":"https://example.com/admin/login","status_code":200}`,
	}
	leads := BuildAssetAttackLeads(asset, nil, nil, nil, nil)
	if len(leads) != 1 || leads[0].Type != "management_surface" {
		t.Fatalf("URL management lead = %#v", leads)
	}
}

func TestBuildAssetAttackLeadsCapsPoCNoise(t *testing.T) {
	now := time.Now().UTC().Add(-8 * 24 * time.Hour)
	asset := models.AssetEntity{ID: "asset-site", Kind: "site", DisplayValue: "https://example.com", CanonicalKey: "https://example.com", CurrentData: `{"fingerprints":["Example"]}`, FirstSeenAt: now, LastSeenAt: now}
	pocs := make([]models.PoC, 12)
	for index := range pocs {
		pocs[index] = models.PoC{ID: string(rune('a' + index)), Name: "matched", Severity: "medium", PoCType: "nuclei"}
	}
	pocs[11].Name = "critical-last"
	pocs[11].Severity = "critical"
	leads := BuildAssetAttackLeads(asset, nil, nil, nil, pocs)
	if len(leads) != 8 {
		t.Fatalf("lead count = %d, want capped 8", len(leads))
	}
	if leads[0].PoC == nil || leads[0].PoC.Name != "critical-last" {
		t.Fatalf("highest severity PoC was dropped or misranked: %#v", leads[0])
	}
}

func TestBuildAssetAttackLeadsUsesExecutablePortTarget(t *testing.T) {
	now := time.Now().UTC()
	for _, test := range []struct {
		name  string
		asset models.AssetEntity
		want  string
	}{
		{name: "HTTP IPv4", asset: models.AssetEntity{ID: "port-http", Kind: "port", CanonicalKey: "203.0.113.9:8080/tcp", DisplayValue: "203.0.113.9:8080/tcp", CurrentData: `{"service":"http"}`, LastTaskID: "task", LastSeenAt: now}, want: "http://203.0.113.9:8080"},
		{name: "HTTPS IPv6", asset: models.AssetEntity{ID: "port-https", Kind: "port", CanonicalKey: "[2001:db8::10]:443/tcp", DisplayValue: "[2001:db8::10]:443/tcp", CurrentData: `{"service":"https"}`, LastTaskID: "task", LastSeenAt: now}, want: "https://[2001:db8::10]:443"},
	} {
		t.Run(test.name, func(t *testing.T) {
			leads := BuildAssetAttackLeads(test.asset, nil, nil, nil, []models.PoC{{ID: "poc", Name: "matched", Severity: "high", PoCType: "custom"}})
			if len(leads) != 1 || leads[0].Target != test.want {
				t.Fatalf("PoC lead target = %#v, want %q", leads, test.want)
			}
		})
	}
}

func TestTruncateAssetLeadTextPreservesUnicodeBoundary(t *testing.T) {
	value := truncateAssetLeadText(strings.Repeat("验", 300), 255)
	if len([]rune(value)) != 255 || !utf8.ValidString(value) {
		t.Fatalf("truncated text is invalid: runes=%d valid=%t", len([]rune(value)), utf8.ValidString(value))
	}
}

func TestExecuteAssetLeadPoCEnforcesSourceTaskScopePostgres(t *testing.T) {
	dsn := os.Getenv("ASSET_CATALOG_INTEGRATION_DSN")
	if dsn == "" {
		t.Skip("set ASSET_CATALOG_INTEGRATION_DSN to run lead PoC authorization coverage")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open integration database: %v", err)
	}
	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("begin integration transaction: %v", tx.Error)
	}
	t.Cleanup(func() { tx.Rollback() })
	if err := tx.AutoMigrate(
		&models.AssetEntity{}, &models.AssetObservation{}, &models.AssetChange{}, &models.AssetVulnerabilityLink{}, &models.Vulnerability{},
		&models.CanonicalAssetRelation{}, &models.AssetLeadTriage{}, &models.PoC{}, &models.PoCExecutionLog{},
		&models.ScanScope{}, &models.Task{},
	); err != nil {
		t.Fatalf("migrate lead PoC integration schema: %v", err)
	}

	suffix := uuid.NewString()
	scope := models.ScanScope{Name: "lead-poc-" + suffix, AllowRules: []string{"allowed.example.com"}}
	if err := tx.Create(&scope).Error; err != nil {
		t.Fatalf("create scan scope: %v", err)
	}
	task := models.Task{Name: "lead-poc", Target: "https://allowed.example.com/admin", ScopeID: scope.ID, Status: models.TaskStatusCompleted}
	if err := tx.Create(&task).Error; err != nil {
		t.Fatalf("create source task: %v", err)
	}
	now := time.Now().UTC()
	allowedAsset := models.AssetEntity{
		Kind: "site", CanonicalKey: "https://allowed.example.com/admin/" + suffix, DisplayValue: "https://allowed.example.com/admin",
		CurrentData: `{"fingerprints":["ScopedTest"]}`, LastTaskID: task.ID, FirstSeenAt: now, LastSeenAt: now,
	}
	blockedAsset := models.AssetEntity{
		Kind: "site", CanonicalKey: "https://outside.example.net/admin/" + suffix, DisplayValue: "https://outside.example.net/admin",
		CurrentData: `{"fingerprints":["ScopedTest"]}`, LastTaskID: task.ID, FirstSeenAt: now, LastSeenAt: now,
	}
	safeAsset := models.AssetEntity{
		Kind: "site", CanonicalKey: "https://allowed.example.com/safe/" + suffix, DisplayValue: "https://allowed.example.com/safe",
		CurrentData: `{"fingerprints":["ScopedTest"]}`, LastTaskID: task.ID, FirstSeenAt: now, LastSeenAt: now,
	}
	assets := []models.AssetEntity{allowedAsset, blockedAsset, safeAsset}
	if err := tx.Create(&assets).Error; err != nil {
		t.Fatalf("create canonical assets: %v", err)
	}
	allowedAsset, blockedAsset, safeAsset = assets[0], assets[1], assets[2]
	observations := []models.AssetObservation{
		{AssetID: allowedAsset.ID, TaskID: task.ID, SourceType: "site", SourceRef: "allowed", Payload: allowedAsset.CurrentData, PayloadHash: "allowed", StateData: allowedAsset.CurrentData, StateHash: "allowed", ObservedAt: now},
		{AssetID: safeAsset.ID, TaskID: task.ID, SourceType: "site", SourceRef: "safe", Payload: safeAsset.CurrentData, PayloadHash: "safe", StateData: safeAsset.CurrentData, StateHash: "safe", ObservedAt: now},
	}
	if err := tx.Create(&observations).Error; err != nil {
		t.Fatalf("create canonical observations: %v", err)
	}
	poc := models.PoC{
		Name: "Scoped custom " + suffix, Category: "integration", Severity: "high", PoCType: "custom", IsEnabled: true,
		Fingerprints: "ScopedTest", MatchMode: "exact", PoCContent: "requests:\n  - path: /\n    matchers:\n      - type: status\n        status: [200]\n",
	}
	if err := tx.Create(&poc).Error; err != nil {
		t.Fatalf("create matched PoC: %v", err)
	}

	executor := &recordingLeadPoCExecutor{vulnerable: true}
	result, err := ExecuteAssetLeadPoC(tx, executor, AssetLeadPoCExecutionInput{
		AssetID: allowedAsset.ID, LeadID: "poc:" + poc.ID, InvocationSource: "web", ActorID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("execute authorized lead PoC: %v", err)
	}
	if executor.calls != 1 || executor.target != "https://allowed.example.com/admin" {
		t.Fatalf("executor calls/target = %d/%q", executor.calls, executor.target)
	}
	if result.ExecutionLog.AssetID != allowedAsset.ID || result.ExecutionLog.LeadID != "poc:"+poc.ID || result.ExecutionLog.TaskID != task.ID || result.ExecutionLog.ScopeID != scope.ID || result.ExecutionLog.InvocationSource != "web" {
		t.Fatalf("incomplete execution audit record: %#v", result.ExecutionLog)
	}
	if result.Finding == nil || result.FindingLink == nil || !result.FindingNew || result.ExecutionLog.VulnerabilityID != result.Finding.ID {
		t.Fatalf("PoC hit was not promoted into linked evidence: %#v", result)
	}
	if result.Finding.TaskID != task.ID || result.Finding.URL != "https://allowed.example.com/admin" || result.Finding.Source != "poc-verification" || result.FindingLink.AssetID != allowedAsset.ID || result.FindingLink.MatchType != "poc_validated" {
		t.Fatalf("promoted evidence is incomplete: finding=%#v link=%#v", result.Finding, result.FindingLink)
	}
	var persisted models.PoCExecutionLog
	if err := tx.First(&persisted, "id = ?", result.ExecutionLog.ID).Error; err != nil {
		t.Fatalf("load execution audit record: %v", err)
	}
	var persistedTriage models.AssetLeadTriage
	if err := tx.First(&persistedTriage, "asset_id = ? AND lead_id = ?", allowedAsset.ID, "poc:"+poc.ID).Error; err != nil || persistedTriage.Status != models.AssetLeadStatusValidated {
		t.Fatalf("PoC lead was not marked validated: %#v / %v", persistedTriage, err)
	}
	var refreshedAsset models.AssetEntity
	if err := tx.First(&refreshedAsset, "id = ?", allowedAsset.ID).Error; err != nil || refreshedAsset.VulnerabilityCount != 1 || refreshedAsset.RiskScore < 70 {
		t.Fatalf("asset risk was not recomputed: %#v / %v", refreshedAsset, err)
	}

	executor.details = "Status: 201\nMatched: refreshed-proof"
	repeated, err := ExecuteAssetLeadPoC(tx, executor, AssetLeadPoCExecutionInput{AssetID: allowedAsset.ID, LeadID: "poc:" + poc.ID, InvocationSource: "mcp"})
	if err != nil {
		t.Fatalf("repeat authorized lead PoC: %v", err)
	}
	if repeated.Finding == nil || repeated.Finding.ID != result.Finding.ID || repeated.FindingNew {
		t.Fatalf("repeat PoC hit was not deduplicated: first=%#v repeat=%#v", result.Finding, repeated.Finding)
	}
	if repeated.Finding.Proof != executor.details || repeated.Finding.LastExecutionLogID != repeated.ExecutionLog.ID || repeated.Finding.LastVerificationResult != "vulnerable" {
		t.Fatalf("repeat PoC hit did not refresh evidence: %#v", repeated.Finding)
	}
	var findingCount int64
	if err := tx.Model(&models.Vulnerability{}).Where("id = ?", result.Finding.ID).Count(&findingCount).Error; err != nil || findingCount != 1 {
		t.Fatalf("deduplicated finding count = %d / %v", findingCount, err)
	}
	resolved, _, err := UpdateFindingTriage(tx, FindingTriageInput{
		VulnerabilityID: result.Finding.ID, Status: models.VulnerabilityStatusResolved, Note: "fixed in deployment", ActorID: uuid.NewString(),
	})
	if err != nil || resolved.Status != models.VulnerabilityStatusResolved || resolved.TriageNote != "fixed in deployment" {
		t.Fatalf("resolve finding lifecycle: %#v / %v", resolved, err)
	}
	if err := tx.First(&refreshedAsset, "id = ?", allowedAsset.ID).Error; err != nil || refreshedAsset.VulnerabilityCount != 0 || refreshedAsset.RiskScore != 0 {
		t.Fatalf("resolved finding still affects risk: %#v / %v", refreshedAsset, err)
	}
	executor.details = "Status: 200\nMatched: regression"
	regressed, err := ExecuteAssetLeadPoC(tx, executor, AssetLeadPoCExecutionInput{AssetID: allowedAsset.ID, LeadID: "poc:" + poc.ID, InvocationSource: "mcp"})
	if err != nil || regressed.Finding == nil || regressed.Finding.Status != models.VulnerabilityStatusRegressed || regressed.Finding.Proof != executor.details || regressed.Finding.TriageUpdatedBy != "poc-verification" {
		t.Fatalf("resolved finding was not reopened as regressed: %#v / %v", regressed, err)
	}
	if err := tx.First(&refreshedAsset, "id = ?", allowedAsset.ID).Error; err != nil || refreshedAsset.VulnerabilityCount != 1 || refreshedAsset.RiskScore < 70 {
		t.Fatalf("regressed finding did not restore risk: %#v / %v", refreshedAsset, err)
	}
	executor.vulnerable = false
	executor.message = "not reproduced after retest"
	retested, err := ExecuteAssetLeadPoC(tx, executor, AssetLeadPoCExecutionInput{AssetID: allowedAsset.ID, LeadID: "poc:" + poc.ID, InvocationSource: "web"})
	if err != nil || retested.Finding == nil || retested.Finding.Status != models.VulnerabilityStatusRegressed || retested.Finding.LastVerificationResult != "safe" || retested.Finding.LastExecutionLogID != retested.ExecutionLog.ID {
		t.Fatalf("safe retest incorrectly changed analyst lifecycle: %#v / %v", retested, err)
	}
	if err := tx.First(&refreshedAsset, "id = ?", allowedAsset.ID).Error; err != nil || refreshedAsset.VulnerabilityCount != 1 || refreshedAsset.RiskScore < 70 {
		t.Fatalf("single safe retest incorrectly reduced risk: %#v / %v", refreshedAsset, err)
	}
	falsePositive, _, err := UpdateFindingTriage(tx, FindingTriageInput{
		VulnerabilityID: result.Finding.ID, Status: models.VulnerabilityStatusFalsePositive, Note: "environment-specific false positive", ActorID: uuid.NewString(),
	})
	if err != nil || falsePositive.Status != models.VulnerabilityStatusFalsePositive {
		t.Fatalf("mark finding false positive: %#v / %v", falsePositive, err)
	}
	if err := tx.First(&refreshedAsset, "id = ?", allowedAsset.ID).Error; err != nil || refreshedAsset.VulnerabilityCount != 0 || refreshedAsset.RiskScore != 0 {
		t.Fatalf("false-positive finding still affects risk: %#v / %v", refreshedAsset, err)
	}

	executor.vulnerable = false
	safeResult, err := ExecuteAssetLeadPoC(tx, executor, AssetLeadPoCExecutionInput{AssetID: safeAsset.ID, LeadID: "poc:" + poc.ID, InvocationSource: "web"})
	if err != nil || safeResult.Finding != nil || safeResult.ExecutionLog.VulnerabilityID != "" {
		t.Fatalf("safe result created finding evidence: result=%#v err=%v", safeResult, err)
	}
	var safeLinkCount int64
	if err := tx.Model(&models.AssetVulnerabilityLink{}).Where("asset_id = ?", safeAsset.ID).Count(&safeLinkCount).Error; err != nil || safeLinkCount != 0 {
		t.Fatalf("safe result link count = %d / %v", safeLinkCount, err)
	}
	safeTriage := models.AssetLeadTriage{AssetID: safeAsset.ID, LeadID: "poc:" + poc.ID, Status: models.AssetLeadStatusValidated, Note: "manual validation"}
	if err := tx.Create(&safeTriage).Error; err != nil {
		t.Fatalf("create manual safe triage: %v", err)
	}
	if err := (&AssetCatalogService{}).syncTaskVulnerabilities(tx, task.ID); err != nil {
		t.Fatalf("rebuild task vulnerability links: %v", err)
	}
	var rebuiltLinks []models.AssetVulnerabilityLink
	if err := tx.Where("vulnerability_id = ?", result.Finding.ID).Find(&rebuiltLinks).Error; err != nil || len(rebuiltLinks) != 1 || rebuiltLinks[0].AssetID != allowedAsset.ID || rebuiltLinks[0].MatchType != "poc_validated" {
		t.Fatalf("PoC evidence mapping changed during rebuild: %#v / %v", rebuiltLinks, err)
	}

	callsBeforeBlocked := executor.calls
	_, err = ExecuteAssetLeadPoC(tx, executor, AssetLeadPoCExecutionInput{AssetID: blockedAsset.ID, LeadID: "poc:" + poc.ID, InvocationSource: "mcp"})
	if err == nil || !IsScanScopeInputError(err) {
		t.Fatalf("out-of-scope lead was not blocked: %v", err)
	}
	if executor.calls != callsBeforeBlocked {
		t.Fatalf("executor was called for blocked target: %d", executor.calls)
	}

	nuclei := models.PoC{Name: "Scoped nuclei " + suffix, Category: "integration", Severity: "high", PoCType: "nuclei", IsEnabled: true, Fingerprints: "ScopedTest", MatchMode: "exact", PoCContent: "id: scoped-test\ninfo:\n  name: scoped-test\n  severity: high\n"}
	if err := tx.Create(&nuclei).Error; err != nil {
		t.Fatalf("create Nuclei PoC: %v", err)
	}
	_, err = ExecuteAssetLeadPoC(tx, executor, AssetLeadPoCExecutionInput{AssetID: allowedAsset.ID, LeadID: "poc:" + nuclei.ID, InvocationSource: "mcp"})
	if err == nil || !errors.Is(err, ErrAssetLeadPoCBlocked) {
		t.Fatalf("scope-enforced Nuclei PoC was not blocked: %v", err)
	}
	if executor.calls != callsBeforeBlocked {
		t.Fatalf("executor was called for non-custom scoped PoC: %d", executor.calls)
	}
	if err := tx.Model(&models.AssetLeadTriage{}).Where("asset_id = ? AND lead_id = ?", allowedAsset.ID, "poc:"+poc.ID).Update("note", "keep analyst note").Error; err != nil {
		t.Fatalf("set analyst note: %v", err)
	}
	references, err := promotedTaskLeadReferences(tx, task.ID)
	if err != nil || len(references) != 1 || references[0].AssetID != allowedAsset.ID || references[0].LeadID != "poc:"+poc.ID {
		t.Fatalf("promoted task lead references include non-hits: %#v / %v", references, err)
	}
	if err := tx.Where("task_id = ?", task.ID).Delete(&models.PoCExecutionLog{}).Error; err != nil {
		t.Fatalf("delete source task execution logs: %v", err)
	}
	if err := resetDeletedTaskLeadTriages(tx, references); err != nil {
		t.Fatalf("reset deleted task triage: %v", err)
	}
	if err := tx.First(&persistedTriage, "asset_id = ? AND lead_id = ?", allowedAsset.ID, "poc:"+poc.ID).Error; err != nil || persistedTriage.Status != models.AssetLeadStatusNew || persistedTriage.Note != "keep analyst note" {
		t.Fatalf("deleted task triage lifecycle is incorrect: %#v / %v", persistedTriage, err)
	}
	if err := tx.First(&safeTriage, "asset_id = ? AND lead_id = ?", safeAsset.ID, "poc:"+poc.ID).Error; err != nil || safeTriage.Status != models.AssetLeadStatusValidated || safeTriage.Note != "manual validation" {
		t.Fatalf("non-promoted triage was changed by task deletion: %#v / %v", safeTriage, err)
	}
}
