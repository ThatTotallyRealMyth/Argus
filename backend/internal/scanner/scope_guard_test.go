package scanner

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/reconmaster/backend/internal/models"
)

func TestAuthorizedDerivedNetworkTargets(t *testing.T) {
	ctx := &ScanContext{ValidateTarget: func(target string) error {
		if target == "192.0.2.2" {
			return errors.New("blocked")
		}
		return nil
	}}
	targets, blocked := authorizedNetworkTargets(ctx, map[string]bool{"192.0.2.1": true, "192.0.2.2": true})
	if blocked != 1 || len(targets) != 1 || targets[0] != "192.0.2.1" {
		t.Fatalf("targets/blocked = %v/%d", targets, blocked)
	}
	ips := authorizedPortScanIPs(ctx, []models.IP{{IPAddress: "192.0.2.1"}, {IPAddress: "192.0.2.2"}})
	if len(ips) != 1 || ips[0].IPAddress != "192.0.2.1" {
		t.Fatalf("authorized port IPs = %#v", ips)
	}
}

func TestCrawlerBlocksRedirectBeforeOutOfScopeRequest(t *testing.T) {
	var blockedRequested atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/blocked" {
			blockedRequested.Store(true)
			writer.WriteHeader(http.StatusOK)
			return
		}
		redirectURL := strings.Replace(serverURL(request), "127.0.0.1", "localhost", 1) + "blocked"
		http.Redirect(writer, request, redirectURL, http.StatusFound)
	}))
	defer server.Close()

	validate := func(target string) error {
		parsed, err := url.Parse(target)
		if err != nil {
			return err
		}
		if parsed.Hostname() != "127.0.0.1" {
			return errors.New("outside scope")
		}
		return nil
	}
	crawler := NewCrawlerWithConfig(CrawlerConfig{MaxDepth: 1, MaxPages: 5, Timeout: time.Second, ValidateURL: validate})
	ctx := &ScanContext{Task: &models.Task{ID: "scope-test"}, DB: newScannerDryRunDB(t), Ctx: context.Background(), Logger: log.New(io.Discard, "", 0)}
	if err := crawler.Crawl(ctx, server.URL+"/"); err != nil {
		t.Fatal(err)
	}
	if blockedRequested.Load() {
		t.Fatal("crawler followed an out-of-scope redirect")
	}
}

func serverURL(request *http.Request) string {
	return "http://" + request.Host + "/"
}

func TestScreenshotRequestScopeValidation(t *testing.T) {
	validate := func(target string) error {
		parsed, err := url.Parse(target)
		if err != nil {
			return err
		}
		if parsed.Hostname() != "allowed.example" {
			return errors.New("outside scope")
		}
		return nil
	}
	for _, target := range []string{"https://allowed.example/app.js", "wss://allowed.example/socket", "data:text/plain,ok"} {
		if err := validateScreenshotRequest(validate, target); err != nil {
			t.Fatalf("allowed screenshot request %q: %v", target, err)
		}
	}
	if err := validateScreenshotRequest(validate, "https://outside.example/app.js"); err == nil {
		t.Fatal("out-of-scope screenshot request was allowed")
	}
	if !blockedScreenshotRequestIsFatal(network.ResourceTypeDocument) || blockedScreenshotRequestIsFatal(network.ResourceTypeScript) {
		t.Fatal("screenshot scope failure policy should fail documents but tolerate blocked subresources")
	}
}
