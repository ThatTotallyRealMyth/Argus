package services

import (
	"errors"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	ErrInvalidFindingTriage = errors.New("invalid finding triage payload")
	ErrFindingNotFound      = errors.New("finding not found")
)

type FindingTriageInput struct {
	VulnerabilityID string
	Status          string
	Note            string
	ActorID         string
}

func ValidVulnerabilityStatus(status string) bool {
	switch status {
	case models.VulnerabilityStatusNew, models.VulnerabilityStatusValidated, models.VulnerabilityStatusSubmitted,
		models.VulnerabilityStatusResolved, models.VulnerabilityStatusFalsePositive, models.VulnerabilityStatusRegressed:
		return true
	default:
		return false
	}
}

func VulnerabilityStatusAffectsRisk(status string) bool {
	status = strings.ToLower(strings.TrimSpace(status))
	return status != models.VulnerabilityStatusResolved && status != models.VulnerabilityStatusFalsePositive
}

func UpdateFindingTriage(db *gorm.DB, input FindingTriageInput) (models.Vulnerability, []string, error) {
	input.VulnerabilityID = strings.TrimSpace(input.VulnerabilityID)
	input.Status = strings.ToLower(strings.TrimSpace(input.Status))
	input.Note = strings.TrimSpace(input.Note)
	input.ActorID = strings.TrimSpace(input.ActorID)
	if input.VulnerabilityID == "" || !ValidVulnerabilityStatus(input.Status) || len([]rune(input.Note)) > 5000 {
		return models.Vulnerability{}, nil, ErrInvalidFindingTriage
	}

	var finding models.Vulnerability
	assetIDs := []string{}
	err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(lockingClause()).First(&finding, "id = ?", input.VulnerabilityID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrFindingNotFound
			}
			return err
		}
		now := time.Now().UTC()
		if err := tx.Model(&finding).Updates(map[string]any{
			"status": input.Status, "triage_note": input.Note, "triage_updated_at": now, "triage_updated_by": input.ActorID,
		}).Error; err != nil {
			return err
		}
		if err := tx.Model(&models.AssetVulnerabilityLink{}).Where("vulnerability_id = ?", finding.ID).Distinct().Pluck("asset_id", &assetIDs).Error; err != nil {
			return err
		}
		if err := (&AssetCatalogService{}).recomputeAssetRisk(tx, assetIDs); err != nil {
			return err
		}
		return tx.First(&finding, "id = ?", finding.ID).Error
	})
	return finding, assetIDs, err
}

func lockingClause() clause.Locking {
	return clause.Locking{Strength: "UPDATE"}
}
