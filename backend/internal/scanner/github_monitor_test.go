package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckLeakedCredentialsExtractsAndDeduplicatesMatches(t *testing.T) {
	content := `
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_ACCESS_KEY_ID_COPY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
token=0123456789abcdef0123456789abcdef
jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature
-----BEGIN RSA PRIVATE KEY-----
`

	leaks := NewGithubMonitor("").CheckLeakedCredentials(content)
	if got := leaks["aws_access_key"]; len(got) != 1 || got[0] != "AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("unexpected AWS access key matches: %#v", got)
	}
	if got := leaks["api_key"]; len(got) != 1 || got[0] != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("unexpected API key matches: %#v", got)
	}
	if got := leaks["aws_secret_key"]; len(got) != 1 || got[0] != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
		t.Fatalf("unexpected AWS secret matches: %#v", got)
	}
	if got := leaks["jwt_token"]; len(got) != 1 || got[0] != "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature" {
		t.Fatalf("unexpected JWT matches: %#v", got)
	}
	if got := leaks["private_key"]; len(got) != 1 {
		t.Fatalf("private key marker missing: %#v", got)
	}
}

func TestCheckLeakedCredentialsIgnoresUnlabelledHashes(t *testing.T) {
	content := "sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	leaks := NewGithubMonitor("").CheckLeakedCredentials(content)
	if len(leaks) != 0 {
		t.Fatalf("unlabelled hash was treated as a credential: %#v", leaks)
	}
}

func TestInspectSearchItemUsesDefaultBranchAndRedactedSummary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/repos/acme/project/contents/config files/app.env" {
			t.Fatalf("unexpected content path: %s", request.URL.Path)
		}
		if request.URL.Query().Get("ref") != "" {
			t.Fatalf("default branch request unexpectedly forced a ref: %s", request.URL.RawQuery)
		}
		if request.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("unexpected authorization header: %q", request.Header.Get("Authorization"))
		}
		_, _ = response.Write([]byte("api_key=0123456789abcdef0123456789abcdef"))
	}))
	defer server.Close()

	monitor := NewGithubMonitor("test-token")
	monitor.baseURL = server.URL
	item := GithubSearchItem{Path: "config files/app.env", Repository: GithubRepository{FullName: "acme/project"}}
	leaks, err := monitor.InspectSearchItem(item)
	if err != nil {
		t.Fatal(err)
	}
	summary := GithubLeakSummary(leaks)
	if summary != "confirmed:api_key=1" || strings.Contains(summary, "0123456789abcdef") {
		t.Fatalf("unsafe or unexpected leak summary: %q", summary)
	}
}

func TestGithubLeakSummaryIsDeterministic(t *testing.T) {
	leaks := map[string][]string{"jwt_token": {"one"}, "api_key": {"one", "two"}}
	if got := GithubLeakSummary(leaks); got != "confirmed:api_key=2,jwt_token=1" {
		t.Fatalf("unexpected summary: %s", got)
	}
}

func TestInspectSearchItemsReturnsDeterministicRedactedResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "secret.env") {
			_, _ = response.Write([]byte("api_key=0123456789abcdef0123456789abcdef"))
			return
		}
		_, _ = response.Write([]byte("no credentials"))
	}))
	defer server.Close()
	monitor := NewGithubMonitor("")
	monitor.baseURL = server.URL
	items := []GithubSearchItem{
		{Path: "plain.txt", Repository: GithubRepository{FullName: "zeta/app"}},
		{Path: "secret.env", Repository: GithubRepository{FullName: "alpha/app"}},
	}
	inspected := monitor.InspectSearchItems(items, 2)
	if len(inspected) != 2 || inspected[0].Item.Repository.FullName != "alpha/app" {
		t.Fatalf("inspection order = %#v", inspected)
	}
	if summary := GithubLeakSummary(inspected[0].Leaks); summary != "confirmed:api_key=1" || strings.Contains(summary, "0123456789abcdef") {
		t.Fatalf("unsafe inspection summary: %q", summary)
	}
}

func TestGithubLeakSeverityPrioritizesPrivateMaterial(t *testing.T) {
	if got := githubLeakSeverity(map[string][]string{"api_key": {"one"}}); got != "high" {
		t.Fatalf("unexpected API key severity: %s", got)
	}
	if got := githubLeakSeverity(map[string][]string{"private_key": {"found"}, "api_key": {"one"}}); got != "critical" {
		t.Fatalf("unexpected private key severity: %s", got)
	}
}

func TestCheckLeakedCredentialsIgnoresInvalidPatterns(t *testing.T) {
	leaks := NewGithubMonitor("").CheckLeakedCredentials("no credentials here")
	if len(leaks) != 0 {
		t.Fatalf("unexpected leak matches: %#v", leaks)
	}
}
