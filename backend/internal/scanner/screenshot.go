package scanner

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// ScreenshotScanner Screen scanner
type ScreenshotScanner struct {
	outputDir      string
	timeout        time.Duration
	validateTarget func(string) error
}

// NewScreenshotScanner Create a screenshot scanner
func NewScreenshotScanner(outputDir string) *ScreenshotScanner {
	return NewScreenshotScannerWithValidator(outputDir, nil)
}

func NewScreenshotScannerWithValidator(outputDir string, validateTarget func(string) error) *ScreenshotScanner {
	if outputDir == "" {
		outputDir = "./screenshots"
	}

	// Ensure directory exists
	os.MkdirAll(outputDir, 0755)

	return &ScreenshotScanner{
		outputDir:      outputDir,
		timeout:        30 * time.Second,
		validateTarget: validateTarget,
	}
}

// Screenshot Yeah.URLTake a screenshot.
func (s *ScreenshotScanner) Screenshot(url string) (string, error) {
	if err := s.validateBrowserTarget(url); err != nil {
		return "", err
	}
	// CreatechromeContext
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	// Set Timeout
	ctx, cancel = context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Generate Filename
	filename := s.generateFilename(url)
	filepath := filepath.Join(s.outputDir, filename)

	// Screenshot
	var buf []byte
	blocked := installScreenshotScopeGuard(ctx, s.validateTarget)
	err := chromedp.Run(ctx,
		fetch.Enable(),
		chromedp.EmulateViewport(1920, 1080),
		chromedp.Navigate(url),
		chromedp.Sleep(2*time.Second), // Waiting for page load
		chromedp.FullScreenshot(&buf, 90),
	)

	if err != nil {
		return "", fmt.Errorf("screenshot failed: %w", err)
	}
	if err := blocked(); err != nil {
		return "", err
	}

	// Save File
	if err := os.WriteFile(filepath, buf, 0644); err != nil {
		return "", fmt.Errorf("save screenshot failed: %w", err)
	}

	return filepath, nil
}

// ScreenshotWithHeadless Use header screenshot (Faster.)
func (s *ScreenshotScanner) ScreenshotWithHeadless(url string) (string, error) {
	if err := s.validateBrowserTarget(url); err != nil {
		return "", err
	}
	// ConfigurechromedpOptions
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.WindowSize(1920, 1080),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// Set Timeout
	ctx, cancel = context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Generate Filename
	filename := s.generateFilename(url)
	filepath := filepath.Join(s.outputDir, filename)

	// Screenshot
	var buf []byte
	blocked := installScreenshotScopeGuard(ctx, s.validateTarget)
	err := chromedp.Run(ctx,
		fetch.Enable(),
		chromedp.Navigate(url),
		chromedp.Sleep(2*time.Second),
		chromedp.FullScreenshot(&buf, 90),
	)

	if err != nil {
		return "", fmt.Errorf("screenshot failed: %w", err)
	}
	if err := blocked(); err != nil {
		return "", err
	}

	// Save File
	if err := os.WriteFile(filepath, buf, 0644); err != nil {
		return "", fmt.Errorf("save screenshot failed: %w", err)
	}

	return filepath, nil
}

// ScreenshotViewport Intercept visual areas
func (s *ScreenshotScanner) ScreenshotViewport(url string) (string, error) {
	if err := s.validateBrowserTarget(url); err != nil {
		return "", err
	}
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.WindowSize(1920, 1080),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filename := s.generateFilename(url)
	filepath := filepath.Join(s.outputDir, filename)

	var buf []byte
	blocked := installScreenshotScopeGuard(ctx, s.validateTarget)
	err := chromedp.Run(ctx,
		fetch.Enable(),
		chromedp.Navigate(url),
		chromedp.Sleep(2*time.Second),
		chromedp.CaptureScreenshot(&buf), // Only take visual areas
	)

	if err != nil {
		return "", fmt.Errorf("screenshot failed: %w", err)
	}
	if err := blocked(); err != nil {
		return "", err
	}

	if err := os.WriteFile(filepath, buf, 0644); err != nil {
		return "", fmt.Errorf("save screenshot failed: %w", err)
	}

	return filepath, nil
}

func (s *ScreenshotScanner) validateBrowserTarget(target string) error {
	if s.validateTarget == nil {
		return nil
	}
	return s.validateTarget(target)
}

func installScreenshotScopeGuard(ctx context.Context, validate func(string) error) func() error {
	var mu sync.Mutex
	var handlers sync.WaitGroup
	var blockedErr error
	chromedp.ListenTarget(ctx, func(event any) {
		paused, ok := event.(*fetch.EventRequestPaused)
		if !ok {
			return
		}
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			commandCtx := ctx
			if chromeContext := chromedp.FromContext(ctx); chromeContext != nil && chromeContext.Target != nil {
				commandCtx = cdp.WithExecutor(ctx, chromeContext.Target)
			}
			if validate != nil {
				if err := validateScreenshotRequest(validate, paused.Request.URL); err != nil {
					if blockedScreenshotRequestIsFatal(paused.ResourceType) {
						mu.Lock()
						if blockedErr == nil {
							blockedErr = err
						}
						mu.Unlock()
					}
					_ = fetch.FailRequest(paused.RequestID, network.ErrorReasonBlockedByClient).Do(commandCtx)
					return
				}
			}
			_ = fetch.ContinueRequest(paused.RequestID).Do(commandCtx)
		}()
	})
	return func() error {
		handlers.Wait()
		mu.Lock()
		defer mu.Unlock()
		if blockedErr != nil {
			return fmt.Errorf("screenshot request blocked by scan scope: %w", blockedErr)
		}
		return nil
	}
}

func blockedScreenshotRequestIsFatal(resourceType network.ResourceType) bool {
	return resourceType == network.ResourceTypeDocument
}

func validateScreenshotRequest(validate func(string) error, rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	switch parsed.Scheme {
	case "http", "https":
		return validate(rawURL)
	case "ws":
		parsed.Scheme = "http"
		return validate(parsed.String())
	case "wss":
		parsed.Scheme = "https"
		return validate(parsed.String())
	default:
		return nil
	}
}

// BatchScreenshot Bulk Screenshot
func (s *ScreenshotScanner) BatchScreenshot(urls []string, concurrency int) map[string]string {
	if concurrency <= 0 {
		concurrency = 5
	}

	results := make(map[string]string)
	semaphore := make(chan struct{}, concurrency)
	done := make(chan struct {
		url      string
		filepath string
	}, len(urls))

	// Startgoroutine
	for _, url := range urls {
		go func(u string) {
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			filepath, err := s.ScreenshotViewport(u)
			if err != nil {
				filepath = ""
			}
			done <- struct {
				url      string
				filepath string
			}{u, filepath}
		}(url)
	}

	// Collection of results
	for i := 0; i < len(urls); i++ {
		result := <-done
		results[result.url] = result.filepath
	}

	return results
}

// generateFilename Generate screenshot filenames
func (s *ScreenshotScanner) generateFilename(url string) string {
	// UseMD5Hash Generate Filename
	hash := md5Hash(url)
	timestamp := time.Now().Format("20060102_150405")
	return fmt.Sprintf("screenshot_%s_%s.png", hash[:16], timestamp)
}

// md5Hash CalculateMD5Hashi.
func md5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

// GetScreenshotPath Fetch Screenshot Save Path
func (s *ScreenshotScanner) GetScreenshotPath(filename string) string {
	return filepath.Join(s.outputDir, filename)
}

// CleanOldScreenshots Clear Old Screenshot
func (s *ScreenshotScanner) CleanOldScreenshots(days int) error {
	if days <= 0 {
		days = 7
	}

	cutoff := time.Now().AddDate(0, 0, -days)

	return filepath.Walk(s.outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && info.ModTime().Before(cutoff) {
			return os.Remove(path)
		}

		return nil
	})
}
