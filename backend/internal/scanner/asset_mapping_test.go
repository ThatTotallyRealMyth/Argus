package scanner

import "testing"

func TestExtractRootDomainUsesPublicSuffixList(t *testing.T) {
	tests := map[string]string{
		"api.example.com":           "example.com",
		"shop.api.example.co.uk":    "example.co.uk",
		"SERVICE.INTERNAL.EXAMPLE.": "internal.example",
	}
	for input, want := range tests {
		if got := extractRootDomain(input); got != want {
			t.Fatalf("root domain for %q = %q, want %q", input, got, want)
		}
	}
}
