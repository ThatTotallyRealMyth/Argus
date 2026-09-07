package scanner

import (
	"testing"

	"github.com/reconmaster/backend/internal/models"
)

func TestMatchPoCsFromCandidatesExcludesUnsupportedTypes(t *testing.T) {
	candidates := []models.PoC{
		{Name: "nuclei", PoCType: "nuclei", Fingerprints: "grafana", IsEnabled: true},
		{Name: "custom", PoCType: "custom", Fingerprints: "grafana", IsEnabled: true},
		{Name: "legacy xray", PoCType: "xray", Fingerprints: "grafana", IsEnabled: true},
		{Name: "disabled", PoCType: "custom", Fingerprints: "grafana", IsEnabled: false},
	}
	matched := NewPoCMatcher().MatchPoCsFromCandidates([]string{"Grafana"}, candidates)
	if len(matched) != 2 || matched[0].Name != "nuclei" || matched[1].Name != "custom" {
		t.Fatalf("unexpected executable matches: %#v", matched)
	}
}
