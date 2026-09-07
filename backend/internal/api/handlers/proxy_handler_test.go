package handlers

import (
	"fmt"
	"testing"
)

func TestNormalizeProxyIDs(t *testing.T) {
	t.Run("deduplicates and trims ids", func(t *testing.T) {
		ids, err := normalizeProxyIDs([]string{" proxy-1 ", "proxy-2", "proxy-1"})
		if err != nil {
			t.Fatalf("normalizeProxyIDs returned an error: %v", err)
		}
		if len(ids) != 2 || ids[0] != "proxy-1" || ids[1] != "proxy-2" {
			t.Fatalf("unexpected ids: %#v", ids)
		}
	})

	for name, ids := range map[string][]string{
		"empty batch": nil,
		"empty id":    {"proxy-1", " "},
		"too large":   makeProxyIDs(1001),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeProxyIDs(ids); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func makeProxyIDs(size int) []string {
	ids := make([]string, size)
	for i := range ids {
		ids[i] = fmt.Sprintf("proxy-%d", i)
	}
	return ids
}
