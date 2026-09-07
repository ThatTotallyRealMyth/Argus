package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reconmaster/backend/internal/models"
)

func TestParseFileLeakDictionary(t *testing.T) {
	paths, err := parseFileLeakDictionary(strings.NewReader("# comment\nadmin\n/admin\n.env\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0].Path != "/admin" || paths[1].Path != "/.env" {
		t.Fatalf("unexpected paths: %#v", paths)
	}
}

func TestParseFileLeakDictionaryRejectsRemoteURL(t *testing.T) {
	if _, err := parseFileLeakDictionary(strings.NewReader("https://example.com/admin\n")); err == nil {
		t.Fatal("remote URL was accepted as a dictionary path")
	}
}

func TestProbeFileLeakURLCapturesMetadataAndCapsLargeBodies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", fmt.Sprint(maxFileLeakProbeBytes+1))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	scanner := NewSiteScanner()
	result, err := scanner.probeFileLeakURL(&ScanContext{
		Task: &models.Task{},
		Ctx:  context.Background(),
	}, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != http.StatusOK || result.ContentType != "text/plain" {
		t.Fatalf("unexpected response metadata: %#v", result)
	}
	if !result.Truncated {
		t.Fatal("large response was not marked truncated")
	}
}
