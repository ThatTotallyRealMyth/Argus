package scanner

import (
	"reflect"
	"testing"

	"github.com/reconmaster/backend/internal/models"
)

func TestSiteProbeSchemesUsesServiceEvidenceOnArbitraryPorts(t *testing.T) {
	tests := []struct {
		port models.Port
		want []string
	}{
		{port: models.Port{Port: 12345, Service: "https"}, want: []string{"https", "http"}},
		{port: models.Port{Port: 9443, Service: "unknown"}, want: []string{"https", "http"}},
		{port: models.Port{Port: 3000, Service: "http"}, want: []string{"http", "https"}},
		{port: models.Port{Port: 27017, Service: "mongodb"}, want: []string{"http", "https"}},
	}
	for _, test := range tests {
		if got := siteProbeSchemes(test.port); !reflect.DeepEqual(got, test.want) {
			t.Fatalf("siteProbeSchemes(%#v) = %v; want %v", test.port, got, test.want)
		}
	}
}
