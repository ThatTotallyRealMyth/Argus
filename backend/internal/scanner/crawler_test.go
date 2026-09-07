package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reconmaster/backend/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newScannerDryRunDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  "host=localhost user=test dbname=test",
		PreferSimpleProtocol: true,
	}), &gorm.Config{
		DryRun:                 true,
		SkipDefaultTransaction: true,
		DisableAutomaticPing:   true,
		Logger:                 logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open dry-run scanner database: %v", err)
	}
	if !db.DryRun || !db.WithContext(context.Background()).DryRun {
		t.Fatal("scanner test database lost dry-run mode")
	}
	return db
}

func newCrawlerTestContext(db *gorm.DB, scanContext context.Context) *ScanContext {
	return &ScanContext{
		Task:   &models.Task{ID: "00000000-0000-0000-0000-000000000001"},
		DB:     db,
		Ctx:    scanContext,
		Logger: log.New(io.Discard, "", 0),
	}
}

func TestCrawlerCancellationStopsActiveRequest(t *testing.T) {
	requestStarted := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(requestStarted)
		<-request.Context().Done()
	}))
	defer server.Close()

	scanContext, cancel := context.WithCancel(context.Background())
	crawler := NewCrawlerWithConfig(CrawlerConfig{MaxDepth: 1, MaxPages: 5, Timeout: 5 * time.Second})
	db := newScannerDryRunDB(t)
	result := make(chan error, 1)
	go func() {
		result <- crawler.Crawl(newCrawlerTestContext(db, scanContext), server.URL)
	}()

	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("crawler request did not start")
	}
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("crawler cancellation error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("crawler did not stop promptly after cancellation")
	}
}

func TestCrawlerBoundsJavaScriptConcurrencyAndResultBudget(t *testing.T) {
	const scriptCount = 10
	var active atomic.Int32
	var peak atomic.Int32
	var scriptRequests atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/" {
			writer.Header().Set("Content-Type", "text/html")
			for index := 0; index < scriptCount; index++ {
				fmt.Fprintf(writer, `<script src="/static/%d.js?v=1"></script>`, index)
			}
			return
		}
		scriptRequests.Add(1)
		current := active.Add(1)
		for {
			previous := peak.Load()
			if current <= previous || peak.CompareAndSwap(previous, current) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		active.Add(-1)
		writer.Header().Set("Content-Type", "application/javascript")
		_, _ = writer.Write([]byte(`window.ready = true;`))
	}))
	defer server.Close()

	crawler := NewCrawlerWithConfig(CrawlerConfig{
		MaxDepth:  1,
		MaxPages:  5,
		Timeout:   time.Second,
		JSWorkers: 2,
	})
	if err := crawler.Crawl(newCrawlerTestContext(newScannerDryRunDB(t), context.Background()), server.URL); err != nil {
		t.Fatal(err)
	}
	if got := peak.Load(); got < 2 || got > 2 {
		t.Fatalf("peak JavaScript concurrency = %d, want 2", got)
	}
	if got := scriptRequests.Load(); got != 4 {
		t.Fatalf("JavaScript requests = %d, want 4 within shared maxPages budget", got)
	}
}

func TestCrawlerReturnsPersistenceErrors(t *testing.T) {
	wantErr := errors.New("forced persistence failure")
	db := newScannerDryRunDB(t)
	if err := db.Callback().Create().Before("gorm:create").Register("test:fail_create", func(tx *gorm.DB) {
		tx.AddError(wantErr)
	}); err != nil {
		t.Fatalf("register failing database callback: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte("ok"))
	}))
	defer server.Close()

	crawler := NewCrawlerWithConfig(CrawlerConfig{MaxPages: 1, Timeout: time.Second})
	err := crawler.Crawl(newCrawlerTestContext(db, context.Background()), server.URL)
	if !errors.Is(err, wantErr) {
		t.Fatalf("crawler persistence error = %v, want %v", err, wantErr)
	}
}

func TestExtractJSFilesSupportsQueryStrings(t *testing.T) {
	crawler := NewCrawler()
	files := crawler.ExtractJSFiles(strings.Join([]string{
		`<script src="/assets/app.js?v=123"></script>`,
		`<script src="/assets/not-js.css?v=123"></script>`,
	}, ""), "https://example.com/page")
	if len(files) != 1 || files[0] != "https://example.com/assets/app.js?v=123" {
		t.Fatalf("JavaScript files = %#v", files)
	}
}
