package scanner

import (
	"strings"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
)

// PoCMatcher PoCSmart Matching Service
type PoCMatcher struct{}

// NewPoCMatcher CreatePoCMatcher
func NewPoCMatcher() *PoCMatcher {
	return &PoCMatcher{}
}

// MatchPoCsByFingerprints It's a fingerprint match.PoC
// fingerprints: List of identified fingerprints
// Back MatchingPoCList
func (pm *PoCMatcher) MatchPoCsByFingerprints(fingerprints []string) ([]models.PoC, error) {
	if len(fingerprints) == 0 {
		return []models.PoC{}, nil
	}

	var allPoCs []models.PoC

	// Get all enabledPoC
	if err := database.DB.Where("is_enabled = ?", true).Find(&allPoCs).Error; err != nil {
		return nil, err
	}

	return pm.MatchPoCsFromCandidates(fingerprints, allPoCs), nil
}

// MatchPoCsFromCandidates matches fingerprints without querying the database.
func (pm *PoCMatcher) MatchPoCsFromCandidates(fingerprints []string, candidates []models.PoC) []models.PoC {
	matchedPoCs := make([]models.PoC, 0)
	for _, poc := range candidates {
		if poc.IsEnabled && executablePoCType(poc.PoCType) && pm.isPoCMatched(poc, fingerprints) {
			matchedPoCs = append(matchedPoCs, poc)
		}
	}
	return matchedPoCs
}

func executablePoCType(pocType string) bool {
	switch strings.ToLower(strings.TrimSpace(pocType)) {
	case "nuclei", "custom":
		return true
	default:
		return false
	}
}

// isPoCMatched JudgementPoCMatching fingerprints
func (pm *PoCMatcher) isPoCMatched(poc models.PoC, fingerprints []string) bool {
	// IfPoCNo fingerprint association and application name set, Default mismatch(Avoiding Undifferent Scan)
	if poc.Fingerprints == "" && poc.AppNames == "" {
		return false
	}

	matchMode := poc.MatchMode
	if matchMode == "" {
		matchMode = "fuzzy" // Default Fuzzy Matches
	}

	switch matchMode {
	case "exact":
		return pm.exactMatch(poc, fingerprints)
	case "fuzzy":
		return pm.fuzzyMatch(poc, fingerprints)
	case "keyword":
		return pm.keywordMatch(poc, fingerprints)
	default:
		return pm.fuzzyMatch(poc, fingerprints)
	}
}

// exactMatch Accurate Match - PoCFingerprints must match exactly.
func (pm *PoCMatcher) exactMatch(poc models.PoC, fingerprints []string) bool {
	if poc.Fingerprints == "" {
		return false
	}

	pocFingerprints := pm.splitAndTrim(poc.Fingerprints)
	fingerprintMap := make(map[string]bool)
	for _, fp := range fingerprints {
		fingerprintMap[strings.ToLower(fp)] = true
	}

	// AllPoCThe fingerprints must be in place.
	for _, pocFp := range pocFingerprints {
		if !fingerprintMap[strings.ToLower(pocFp)] {
			return false
		}
	}

	return len(pocFingerprints) > 0
}

// fuzzyMatch Fuzzy Match - Just one fingerprint match.
func (pm *PoCMatcher) fuzzyMatch(poc models.PoC, fingerprints []string) bool {
	// InspectionfingerprintsFields
	if poc.Fingerprints != "" {
		pocFingerprints := pm.splitAndTrim(poc.Fingerprints)
		for _, pocFp := range pocFingerprints {
			for _, fp := range fingerprints {
				if pm.fuzzyCompare(pocFp, fp) {
					return true
				}
			}
		}
	}

	// Inspectionapp_namesFields
	if poc.AppNames != "" {
		appNames := pm.splitAndTrim(poc.AppNames)
		for _, appName := range appNames {
			for _, fp := range fingerprints {
				if pm.fuzzyCompare(appName, fp) {
					return true
				}
			}
		}
	}

	return false
}

// keywordMatch Keywords Match - Include keywords to match
func (pm *PoCMatcher) keywordMatch(poc models.PoC, fingerprints []string) bool {
	// InspectionfingerprintsFields
	if poc.Fingerprints != "" {
		pocFingerprints := pm.splitAndTrim(poc.Fingerprints)
		for _, pocFp := range pocFingerprints {
			pocFpLower := strings.ToLower(pocFp)
			for _, fp := range fingerprints {
				fpLower := strings.ToLower(fp)
				if strings.Contains(fpLower, pocFpLower) || strings.Contains(pocFpLower, fpLower) {
					return true
				}
			}
		}
	}

	// Inspectionapp_namesFields
	if poc.AppNames != "" {
		appNames := pm.splitAndTrim(poc.AppNames)
		for _, appName := range appNames {
			appNameLower := strings.ToLower(appName)
			for _, fp := range fingerprints {
				fpLower := strings.ToLower(fp)
				if strings.Contains(fpLower, appNameLower) || strings.Contains(appNameLower, fpLower) {
					return true
				}
			}
		}
	}

	return false
}

// fuzzyCompare Blur Compares Two Strings
func (pm *PoCMatcher) fuzzyCompare(str1, str2 string) bool {
	s1 := strings.ToLower(strings.TrimSpace(str1))
	s2 := strings.ToLower(strings.TrimSpace(str2))

	// Exactly the same.
	if s1 == s2 {
		return true
	}

	// Organisation
	if strings.Contains(s1, s2) || strings.Contains(s2, s1) {
		return true
	}

	// Compare after removing common separator
	s1Clean := pm.cleanString(s1)
	s2Clean := pm.cleanString(s2)
	if s1Clean == s2Clean {
		return true
	}

	return false
}

// cleanString Clear String,Remove Common Separator
func (pm *PoCMatcher) cleanString(s string) string {
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, "_", "")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, ".", "")
	return s
}

// splitAndTrim Split and Remove Space
func (pm *PoCMatcher) splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	var result []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// GetMatchedPoCsByAppName Matches by applied namePoC
func (pm *PoCMatcher) GetMatchedPoCsByAppName(appName string) ([]models.PoC, error) {
	var pocs []models.PoC

	// UseLIKEQuery Fuzzy Matches
	query := database.DB.Where("is_enabled = ?", true)
	query = query.Where(
		"app_names LIKE ? OR fingerprints LIKE ? OR name LIKE ?",
		"%"+appName+"%",
		"%"+appName+"%",
		"%"+appName+"%",
	)

	if err := query.Find(&pocs).Error; err != nil {
		return nil, err
	}

	return pocs, nil
}

// GetPoCStats FetchPoCMatch Statistics
func (pm *PoCMatcher) GetPoCStats(fingerprints []string) map[string]interface{} {
	matchedPoCs, _ := pm.MatchPoCsByFingerprints(fingerprints)

	stats := make(map[string]interface{})
	stats["total_matched"] = len(matchedPoCs)
	stats["matched_fingerprints"] = fingerprints

	// Classification by Serious Level
	severityCount := make(map[string]int)
	for _, poc := range matchedPoCs {
		severityCount[poc.Severity]++
	}
	stats["severity_distribution"] = severityCount

	// By category
	categoryCount := make(map[string]int)
	for _, poc := range matchedPoCs {
		categoryCount[poc.Category]++
	}
	stats["category_distribution"] = categoryCount

	return stats
}
