package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reconmaster/backend/internal/models"
)

func TestCustomPoCExecutesAndReturnsEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/admin/check" {
			t.Fatalf("unexpected path: %s", request.URL.Path)
		}
		if request.Header.Get("X-PoC-Host") != request.Host {
			t.Fatalf("placeholder header not rendered: %q", request.Header.Get("X-PoC-Host"))
		}
		response.Header().Set("X-Product", "Example Admin")
		response.WriteHeader(http.StatusOK)
		response.Write([]byte("management-console build=2026"))
	}))
	defer server.Close()

	poc := &models.PoC{PoCType: "custom", PoCContent: `
requests:
  - method: GET
    path: /admin/check
    headers:
      X-PoC-Host: "{{Host}}"
    matchers_condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words: [management-console]
      - type: regex
        part: header
        regex: ['X-Product: Example Admin']
`}
	executor := &PoCExecutor{client: server.Client()}
	result, err := executor.Execute(poc, server.URL)
	if err != nil {
		t.Fatalf("execute custom PoC: %v", err)
	}
	if !result.Vulnerable {
		t.Fatalf("expected match, got %#v", result)
	}
	for _, expected := range []string{"GET " + server.URL + "/admin/check", "Status: 200", "management-console"} {
		if !strings.Contains(result.Details, expected) {
			t.Fatalf("missing evidence %q in %q", expected, result.Details)
		}
	}
}

func TestCustomPoCNoMatchIsSafe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusNotFound)
		response.Write([]byte("not found"))
	}))
	defer server.Close()
	poc := &models.PoC{PoCType: "custom", PoCContent: `
requests:
  - path: /
    matchers:
      - type: status
        status: [200]
`}
	result, err := (&PoCExecutor{client: server.Client()}).Execute(poc, server.URL)
	if err != nil {
		t.Fatalf("execute custom PoC: %v", err)
	}
	if result.Vulnerable || result.Message != "No vulnerability detected" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestCustomPoCRejectsCrossOriginRequest(t *testing.T) {
	poc := &models.PoC{PoCType: "custom", PoCContent: `
requests:
  - path: https://other.example.test/check
    matchers:
      - type: status
        status: [200]
`}
	_, err := (&PoCExecutor{client: http.DefaultClient}).Execute(poc, "https://target.example.test")
	if err == nil || !strings.Contains(err.Error(), "target origin") {
		t.Fatalf("expected cross-origin rejection, got %v", err)
	}
}

func TestValidateCustomPoCRejectsUnsafeOrInvalidTemplates(t *testing.T) {
	cases := []string{
		`requests: [{method: TRACE, path: /, matchers: [{type: status, status: [200]}]}]`,
		`requests: [{path: /, headers: {Host: other.example}, matchers: [{type: status, status: [200]}]}]`,
		`requests: [{path: /, matchers: [{type: regex, regex: ['[']}]}]`,
		`requests: [{path: /, unknown: true, matchers: [{type: status, status: [200]}]}]`,
	}
	for _, content := range cases {
		if err := ValidatePoCContent("custom", content); err == nil {
			t.Fatalf("invalid custom PoC accepted: %s", content)
		}
	}
}

func TestValidatePoCContentRejectsUnsupportedType(t *testing.T) {
	if err := ValidatePoCContent("xray", "name: test"); err == nil {
		t.Fatal("unsupported xray type accepted")
	}
}
