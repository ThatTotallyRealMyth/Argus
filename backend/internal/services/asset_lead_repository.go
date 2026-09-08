package services

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/scanner"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type AssetLeadPoCExecutionInput struct {
	AssetID          string
	LeadID           string
	InvocationSource string
	ActorID          string
}

type AssetLeadPoCExecutionResult struct {
	Lead         AssetAttackLead
	ExecutionLog models.PoCExecutionLog
	Finding      *models.Vulnerability
	FindingLink  *models.AssetVulnerabilityLink
	FindingNew   bool
	Result       string
	Details      string
}

var (
	ErrInvalidAssetLeadTriage = errors.New("invalid asset lead triage payload")
	ErrInvalidAssetLeadRef    = errors.New("invalid asset lead reference")
	ErrAssetLeadNotFound      = errors.New("asset lead not found")
	ErrCanonicalAssetNotFound = errors.New("canonical asset not found")
	ErrAssetLeadPoCBlocked    = errors.New("asset lead PoC execution blocked")
	ErrAssetLeadPoCAudit      = errors.New("asset lead PoC audit failed")
)

type AssetLeadTriageReference struct {
	AssetID string `json:"asset_id"`
	LeadID  string `json:"lead_id"`
}

type AssetLeadTriageUpdate struct {
	AssetID      string                     `json:"asset_id"`
	LeadID       string                     `json:"lead_id"`
	Status       string                     `json:"status"`
	Note         string                     `json:"note"`
	RelatedLeads []AssetLeadTriageReference `json:"related_leads"`
}

func AssetIDs(assets []models.AssetEntity) []string {
	ids := make([]string, 0, len(assets))
	for _, asset := range assets {
		ids = append(ids, asset.ID)
	}
	return ids
}

func LoadAssetLeadTriages(db *gorm.DB, ids []string) (map[string]models.AssetLeadTriage, error) {
	result := make(map[string]models.AssetLeadTriage)
	if len(ids) == 0 {
		return result, nil
	}
	var triages []models.AssetLeadTriage
	if err := db.Where("asset_id IN ?", ids).Find(&triages).Error; err != nil {
		return nil, err
	}
	for _, triage := range triages {
		result[AssetLeadTriageKey(triage.AssetID, triage.LeadID)] = triage
	}
	return result, nil
}

func BuildAssetLeadQueue(db *gorm.DB, assets []models.AssetEntity) ([]AssetAttackLead, error) {
	ids := AssetIDs(assets)
	if len(ids) == 0 {
		return []AssetAttackLead{}, nil
	}
	assetSet := make(map[string]struct{}, len(ids))
	assetMap := make(map[string]models.AssetEntity, len(ids))
	for _, asset := range assets {
		assetSet[asset.ID] = struct{}{}
		assetMap[asset.ID] = asset
	}

	var changes []models.AssetChange
	if err := db.Where("asset_id IN ? AND event_type = ?", ids, "modified").Order("observed_at DESC").Find(&changes).Error; err != nil {
		return nil, err
	}
	changesByAsset := make(map[string][]models.AssetChange)
	for _, change := range changes {
		if len(changesByAsset[change.AssetID]) < 5 {
			changesByAsset[change.AssetID] = append(changesByAsset[change.AssetID], change)
		}
	}

	var findingRows []struct {
		AssetID         string
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
	if err := db.Table("asset_vulnerability_links AS links").
		Select("links.asset_id, links.id, links.vulnerability_id, links.task_id, links.severity, links.match_type, vulnerabilities.status, vulnerabilities.title, vulnerabilities.url, vulnerabilities.type, vulnerabilities.source, vulnerabilities.created_at").
		Joins("JOIN vulnerabilities ON vulnerabilities.id = links.vulnerability_id").
		Where("links.asset_id IN ?", ids).
		Order("vulnerabilities.created_at DESC").Scan(&findingRows).Error; err != nil {
		return nil, err
	}
	findingsByAsset := make(map[string][]AssetLeadFinding)
	for _, finding := range findingRows {
		findingsByAsset[finding.AssetID] = append(findingsByAsset[finding.AssetID], AssetLeadFinding{
			ID: finding.ID, VulnerabilityID: finding.VulnerabilityID, TaskID: finding.TaskID, Severity: finding.Severity, Status: finding.Status,
			Title: finding.Title, URL: finding.URL, Type: finding.Type, Source: finding.Source,
			MatchType: finding.MatchType, CreatedAt: finding.CreatedAt,
		})
	}

	var relations []models.CanonicalAssetRelation
	if err := db.Where("from_asset_id IN ? OR to_asset_id IN ?", ids, ids).Order("last_seen_at DESC").Find(&relations).Error; err != nil {
		return nil, err
	}
	relatedIDs := make([]string, 0, len(relations)*2)
	for _, relation := range relations {
		relatedIDs = append(relatedIDs, relation.FromAssetID, relation.ToAssetID)
	}
	if len(relatedIDs) > 0 {
		var relatedAssets []models.AssetEntity
		if err := db.Where("id IN ?", relatedIDs).Find(&relatedAssets).Error; err != nil {
			return nil, err
		}
		for _, asset := range relatedAssets {
			assetMap[asset.ID] = asset
		}
	}
	relationsByAsset := make(map[string][]AssetLeadRelation)
	for _, relation := range relations {
		if _, ok := assetSet[relation.FromAssetID]; ok && len(relationsByAsset[relation.FromAssetID]) < 100 {
			relationsByAsset[relation.FromAssetID] = append(relationsByAsset[relation.FromAssetID], AssetLeadRelation{
				RelationType: relation.RelationType, Asset: assetMap[relation.ToAssetID], LastTaskID: relation.LastTaskID, LastSeenAt: relation.LastSeenAt,
			})
		}
		if _, ok := assetSet[relation.ToAssetID]; ok && len(relationsByAsset[relation.ToAssetID]) < 100 {
			relationsByAsset[relation.ToAssetID] = append(relationsByAsset[relation.ToAssetID], AssetLeadRelation{
				RelationType: relation.RelationType, Asset: assetMap[relation.FromAssetID], LastTaskID: relation.LastTaskID, LastSeenAt: relation.LastSeenAt,
			})
		}
	}

	var pocs []models.PoC
	if err := db.Where("is_enabled = ? AND po_c_type IN ?", true, []string{"nuclei", "custom"}).Find(&pocs).Error; err != nil {
		return nil, err
	}
	matcher := scanner.NewPoCMatcher()
	leads := make([]AssetAttackLead, 0)
	for _, asset := range assets {
		matchedPoCs := matcher.MatchPoCsFromCandidates(AssetLeadFingerprints(asset), pocs)
		leads = append(leads, BuildAssetAttackLeads(asset, changesByAsset[asset.ID], findingsByAsset[asset.ID], relationsByAsset[asset.ID], matchedPoCs)...)
	}
	return leads, nil
}

// LoadAssetAttackLead resolves a lead from canonical evidence instead of
// trusting a client-supplied target, task, or PoC ID.
func LoadAssetAttackLead(db *gorm.DB, assetID, leadID string) (models.AssetEntity, AssetAttackLead, error) {
	assetID = strings.TrimSpace(assetID)
	leadID = strings.TrimSpace(leadID)
	if assetID == "" || leadID == "" {
		return models.AssetEntity{}, AssetAttackLead{}, ErrInvalidAssetLeadRef
	}
	var asset models.AssetEntity
	if err := db.Where("id = ? AND scope_id = ?", assetID, models.DefaultAssetScope).First(&asset).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return models.AssetEntity{}, AssetAttackLead{}, fmt.Errorf("%w: canonical asset", ErrAssetLeadNotFound)
		}
		return models.AssetEntity{}, AssetAttackLead{}, fmt.Errorf("canonical asset not found: %w", err)
	}
	leads, err := BuildAssetLeadQueue(db, []models.AssetEntity{asset})
	if err != nil {
		return models.AssetEntity{}, AssetAttackLead{}, err
	}
	triages, err := LoadAssetLeadTriages(db, []string{asset.ID})
	if err != nil {
		return models.AssetEntity{}, AssetAttackLead{}, err
	}
	ApplyAssetLeadTriages(leads, triages)
	for _, lead := range leads {
		if lead.ID == leadID {
			return asset, lead, nil
		}
	}
	return models.AssetEntity{}, AssetAttackLead{}, ErrAssetLeadNotFound
}

type AssetLeadPoCExecutor interface {
	Execute(*models.PoC, string) (*scanner.ExecuteResult, error)
}

// ExecuteAssetLeadPoC is the single network-execution path for a canonical
// lead. It resolves the source task and scope from persisted evidence before
// invoking the executor, so callers cannot substitute a different target.
func ExecuteAssetLeadPoC(db *gorm.DB, executor AssetLeadPoCExecutor, input AssetLeadPoCExecutionInput) (*AssetLeadPoCExecutionResult, error) {
	asset, lead, err := LoadAssetAttackLead(db, input.AssetID, input.LeadID)
	if err != nil {
		return nil, err
	}
	if lead.PoC == nil || strings.TrimSpace(lead.PoC.ID) == "" {
		return nil, fmt.Errorf("%w: the selected lead has no executable PoC", ErrAssetLeadPoCBlocked)
	}
	var poc models.PoC
	if err := db.First(&poc, "id = ?", lead.PoC.ID).Error; err != nil {
		return nil, fmt.Errorf("PoC not found: %w", err)
	}
	if !poc.IsEnabled {
		return nil, fmt.Errorf("%w: PoC is disabled", ErrAssetLeadPoCBlocked)
	}
	if strings.TrimSpace(lead.TaskID) == "" {
		return nil, fmt.Errorf("%w: lead has no source task", ErrAssetLeadPoCBlocked)
	}
	var task models.Task
	if err := db.Select("id", "scope_id").First(&task, "id = ?", lead.TaskID).Error; err != nil {
		return nil, fmt.Errorf("source task for lead is unavailable: %w", err)
	}
	validation, err := (&ScanScopeService{}).validateWithDB(db, task.ScopeID, lead.Target)
	if err != nil {
		return nil, fmt.Errorf("PoC authorization failed: %w", err)
	}
	if err := ScanScopeBlockedError(validation); err != nil {
		return nil, err
	}
	if validation.Enforced && !strings.EqualFold(strings.TrimSpace(poc.PoCType), "custom") {
		return nil, fmt.Errorf("%w: scope-enforced execution supports only same-origin custom PoCs", ErrAssetLeadPoCBlocked)
	}
	if executor == nil {
		executor = scanner.NewPoCExecutor()
	}
	execResult, execErr := executor.Execute(&poc, validation.NormalizedTarget)
	logResult := "safe"
	details := ""
	if execErr != nil {
		logResult = "error"
		details = "Execution failed"
	} else if execResult == nil {
		execErr = errors.New("PoC executor returned no result")
		logResult = "error"
		details = "Execution failed"
	} else if execResult.Vulnerable {
		logResult = "vulnerable"
		details = execResult.Details
	} else {
		details = execResult.Message
	}
	logEntry := models.PoCExecutionLog{
		PoCID: poc.ID, AssetID: asset.ID, LeadID: lead.ID, TaskID: lead.TaskID,
		ScopeID: validation.ScopeID, InvocationSource: strings.TrimSpace(input.InvocationSource),
		ActorID: strings.TrimSpace(input.ActorID), Target: validation.NormalizedTarget,
		Result: logResult, Details: details,
	}
	result := &AssetLeadPoCExecutionResult{Lead: lead, ExecutionLog: logEntry, Result: logResult, Details: details}
	if err := persistAssetLeadPoCExecution(db, &logEntry, &asset, &lead, &poc, result); err != nil {
		return result, fmt.Errorf("%w: %v", ErrAssetLeadPoCAudit, err)
	}
	result.ExecutionLog = logEntry
	return result, execErr
}

func persistAssetLeadPoCExecution(db *gorm.DB, logEntry *models.PoCExecutionLog, asset *models.AssetEntity, lead *AssetAttackLead, poc *models.PoC, result *AssetLeadPoCExecutionResult) error {
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT pg_advisory_xact_lock(hashtext(?))", "asset-lead-poc:"+asset.ID+":"+lead.ID).Error; err != nil {
			return err
		}
		existing, hasExisting, err := loadAssetLeadPoCFinding(tx, asset.ID, lead.ID)
		if err != nil {
			return err
		}
		if err := tx.Create(logEntry).Error; err != nil {
			return err
		}
		if logEntry.Result == "vulnerable" {
			finding, link, created, err := promoteAssetLeadPoCFinding(tx, asset, lead, poc, logEntry, existing, hasExisting)
			if err != nil {
				return err
			}
			result.Finding, result.FindingLink, result.FindingNew = finding, link, created
			logEntry.VulnerabilityID = finding.ID
		} else if hasExisting {
			verifiedAt := logEntry.CreatedAt.UTC()
			if err := tx.Model(&existing).Updates(map[string]any{
				"last_verified_at": verifiedAt, "last_verification_result": logEntry.Result, "last_execution_log_id": logEntry.ID,
			}).Error; err != nil {
				return err
			}
			if err := tx.First(&existing, "id = ?", existing.ID).Error; err != nil {
				return err
			}
			result.Finding = &existing
			logEntry.VulnerabilityID = existing.ID
		}
		if logEntry.VulnerabilityID != "" {
			return tx.Model(logEntry).Update("vulnerability_id", logEntry.VulnerabilityID).Error
		}
		return nil
	})
}

func loadAssetLeadPoCFinding(db *gorm.DB, assetID, leadID string) (models.Vulnerability, bool, error) {
	var vulnerabilityID string
	lookup := db.Model(&models.PoCExecutionLog{}).
		Select("vulnerability_id").
		Where("asset_id = ? AND lead_id = ? AND vulnerability_id <> ''", assetID, leadID).
		Order("created_at ASC").Limit(1).Scan(&vulnerabilityID)
	if lookup.Error != nil {
		return models.Vulnerability{}, false, lookup.Error
	}
	if lookup.RowsAffected == 0 || strings.TrimSpace(vulnerabilityID) == "" {
		return models.Vulnerability{}, false, nil
	}
	var finding models.Vulnerability
	if err := db.Clauses(clause.Locking{Strength: "UPDATE"}).First(&finding, "id = ?", vulnerabilityID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return models.Vulnerability{}, false, nil
		}
		return models.Vulnerability{}, false, err
	}
	return finding, true, nil
}

func promoteAssetLeadPoCFinding(db *gorm.DB, asset *models.AssetEntity, lead *AssetAttackLead, poc *models.PoC, logEntry *models.PoCExecutionLog, finding models.Vulnerability, exists bool) (*models.Vulnerability, *models.AssetVulnerabilityLink, bool, error) {
	verifiedAt := logEntry.CreatedAt.UTC()
	created := !exists
	if !exists {
		finding = models.Vulnerability{
			TaskID: lead.TaskID, URL: logEntry.Target, Type: "poc_validation", VulnType: fallbackText(poc.Category, "PoC"),
			Severity: normalizedLeadSeverity(poc.Severity), Title: truncateAssetLeadText("PoC Verify hit: "+fallbackText(poc.Name, poc.ID), 255),
			Description: assetLeadPoCFindingDescription(poc, logEntry),
			Payload:     fmt.Sprintf("PoC ID: %s\nPoC type: %s", poc.ID, poc.PoCType),
			Proof:       logEntry.Details, Solution: "Review of practical implications and boundaries of competence, Revalidate after restoring the affected component or configuration.",
			Reference: poc.Reference, Source: "poc-verification",
			Status: models.VulnerabilityStatusValidated, LastVerifiedAt: &verifiedAt,
			LastVerificationResult: "vulnerable", LastExecutionLogID: logEntry.ID,
		}
		if err := db.Create(&finding).Error; err != nil {
			return nil, nil, false, err
		}
	} else {
		status := finding.Status
		updates := map[string]any{
			"task_id": lead.TaskID, "url": logEntry.Target, "severity": normalizedLeadSeverity(poc.Severity),
			"title":       truncateAssetLeadText("PoC Verify hit: "+fallbackText(poc.Name, poc.ID), 255),
			"description": assetLeadPoCFindingDescription(poc, logEntry), "proof": logEntry.Details,
			"reference": poc.Reference, "last_verified_at": verifiedAt,
			"last_verification_result": "vulnerable", "last_execution_log_id": logEntry.ID,
		}
		if status == "" || status == models.VulnerabilityStatusNew {
			status = models.VulnerabilityStatusValidated
		} else if status == models.VulnerabilityStatusResolved {
			status = models.VulnerabilityStatusRegressed
			updates["triage_updated_at"] = verifiedAt
			updates["triage_updated_by"] = "poc-verification"
		}
		updates["status"] = status
		if err := db.Model(&finding).Updates(updates).Error; err != nil {
			return nil, nil, false, err
		}
		if err := db.First(&finding, "id = ?", finding.ID).Error; err != nil {
			return nil, nil, false, err
		}
	}
	link := models.AssetVulnerabilityLink{
		AssetID: asset.ID, VulnerabilityID: finding.ID, TaskID: lead.TaskID,
		MatchType: "poc_validated", Severity: finding.Severity,
	}
	if err := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "asset_id"}, {Name: "vulnerability_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"task_id", "match_type", "severity", "updated_at"}),
	}, clause.Returning{Columns: []clause.Column{{Name: "id"}}}).Create(&link).Error; err != nil {
		return nil, nil, false, err
	}
	triage := models.AssetLeadTriage{AssetID: asset.ID, LeadID: lead.ID, Status: models.AssetLeadStatusValidated}
	if err := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "asset_id"}, {Name: "lead_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"status", "updated_at"}),
	}).Create(&triage).Error; err != nil {
		return nil, nil, false, err
	}
	if err := (&AssetCatalogService{}).recomputeAssetRisk(db, []string{asset.ID}); err != nil {
		return nil, nil, false, err
	}
	return &finding, &link, created, nil
}

func assetLeadPoCFindingDescription(poc *models.PoC, logEntry *models.PoCExecutionLog) string {
	parts := []string{fmt.Sprintf("Authentication in target %s Hit! PoC %s.", logEntry.Target, fallbackText(poc.Name, poc.ID))}
	if description := strings.TrimSpace(poc.Description); description != "" {
		parts = append(parts, description)
	}
	return strings.Join(parts, "\n\n")
}

func truncateAssetLeadText(value string, limit int) string {
	runes := []rune(strings.TrimSpace(value))
	if len(runes) > limit {
		runes = runes[:limit]
	}
	return string(runes)
}

func LoadAssetLeadPoCExecutions(db *gorm.DB, assetID string) ([]models.PoCExecutionLog, error) {
	logs := []models.PoCExecutionLog{}
	if err := db.Where("asset_id = ?", strings.TrimSpace(assetID)).Order("created_at DESC, id DESC").Limit(100).Find(&logs).Error; err != nil {
		return nil, err
	}
	return logs, nil
}

func UpdateAssetLeadTriages(db *gorm.DB, input AssetLeadTriageUpdate) (models.AssetLeadTriage, int, error) {
	input.AssetID = strings.TrimSpace(input.AssetID)
	input.LeadID = strings.TrimSpace(input.LeadID)
	input.Status = strings.ToLower(strings.TrimSpace(input.Status))
	input.Note = strings.TrimSpace(input.Note)
	if input.AssetID == "" || input.LeadID == "" || len(input.LeadID) > 512 || len(input.Note) > 5000 || !ValidAssetLeadStatus(input.Status) {
		return models.AssetLeadTriage{}, 0, ErrInvalidAssetLeadTriage
	}

	references := make([]AssetLeadTriageReference, 0, len(input.RelatedLeads)+1)
	seenReferences := make(map[string]struct{}, len(input.RelatedLeads)+1)
	assetSet := make(map[string]struct{}, len(input.RelatedLeads)+1)
	allReferences := append([]AssetLeadTriageReference{{AssetID: input.AssetID, LeadID: input.LeadID}}, input.RelatedLeads...)
	for _, reference := range allReferences {
		reference.AssetID = strings.TrimSpace(reference.AssetID)
		reference.LeadID = strings.TrimSpace(reference.LeadID)
		if reference.AssetID == "" || reference.LeadID == "" || len(reference.LeadID) > 512 {
			return models.AssetLeadTriage{}, 0, ErrInvalidAssetLeadTriage
		}
		key := AssetLeadTriageKey(reference.AssetID, reference.LeadID)
		if _, exists := seenReferences[key]; exists {
			continue
		}
		seenReferences[key] = struct{}{}
		assetSet[reference.AssetID] = struct{}{}
		references = append(references, reference)
	}
	if len(references) > 100 {
		return models.AssetLeadTriage{}, 0, ErrInvalidAssetLeadTriage
	}

	assetIDs := make([]string, 0, len(assetSet))
	for assetID := range assetSet {
		assetIDs = append(assetIDs, assetID)
	}
	var assetCount int64
	if err := db.Model(&models.AssetEntity{}).Where("id IN ? AND scope_id = ?", assetIDs, models.DefaultAssetScope).Count(&assetCount).Error; err != nil {
		return models.AssetLeadTriage{}, 0, err
	}
	if assetCount != int64(len(assetIDs)) {
		return models.AssetLeadTriage{}, 0, ErrCanonicalAssetNotFound
	}

	var saved models.AssetLeadTriage
	err := db.Transaction(func(tx *gorm.DB) error {
		for _, reference := range references {
			triage := models.AssetLeadTriage{AssetID: reference.AssetID, LeadID: reference.LeadID, Status: input.Status, Note: input.Note}
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "asset_id"}, {Name: "lead_id"}},
				DoUpdates: clause.AssignmentColumns([]string{"status", "note", "updated_at"}),
			}).Create(&triage).Error; err != nil {
				return err
			}
		}
		return tx.Where("asset_id = ? AND lead_id = ?", input.AssetID, input.LeadID).First(&saved).Error
	})
	return saved, len(references), err
}

func ValidAssetLeadStatus(status string) bool {
	switch status {
	case models.AssetLeadStatusNew, models.AssetLeadStatusInvestigating, models.AssetLeadStatusValidated, models.AssetLeadStatusIgnored:
		return true
	default:
		return false
	}
}
