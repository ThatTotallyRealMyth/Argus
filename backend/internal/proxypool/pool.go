package proxypool

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
)

var state struct {
	sync.RWMutex
	urls                   []*url.URL
	loadedAt               time.Time
	rotationEnabled        bool
	rotationIntervalSecond int
	configLoadedAt         time.Time
}
var cursor uint64
var checkerStop chan struct{}
var checkerOnce sync.Once

func Refresh() {
	if database.DB == nil {
		return
	}
	var records []models.ProxyEndpoint
	if err := database.DB.Where("is_enabled = ? AND status = ?", true, "healthy").Order("created_at ASC").Find(&records).Error; err != nil {
		// Keep the last known-good pool during a transient database failure.
		return
	}
	parsed := make([]*url.URL, 0, len(records))
	for _, record := range records {
		if value, err := record.ProxyURL(); err == nil {
			parsed = append(parsed, value)
		}
	}
	rotationEnabled, rotationInterval, configErr := rotationConfig()
	now := time.Now()
	state.Lock()
	state.urls = parsed
	state.loadedAt = now
	if configErr == nil {
		state.rotationEnabled = rotationEnabled
		state.rotationIntervalSecond = rotationInterval
	}
	state.configLoadedAt = now
	state.Unlock()
}

func next(_ *http.Request) (*url.URL, error) {
	state.RLock()
	stale := time.Since(state.loadedAt) > 30*time.Second
	configStale := time.Since(state.configLoadedAt) > 30*time.Second
	state.RUnlock()
	if stale || configStale {
		Refresh()
	}
	state.RLock()
	defer state.RUnlock()
	if len(state.urls) == 0 {
		return nil, nil
	}
	sequence := atomic.AddUint64(&cursor, 1) - 1
	index := selectionIndex(sequence, len(state.urls), state.rotationEnabled, state.rotationIntervalSecond, time.Now())
	return state.urls[index], nil
}

func selectionIndex(sequence uint64, size int, rotationEnabled bool, intervalSecond int, now time.Time) int {
	if size <= 0 {
		return 0
	}
	if rotationEnabled && intervalSecond > 0 {
		// Keep request-level load balancing while rotating the starting node each window.
		sequence += uint64(now.Unix() / int64(intervalSecond))
	}
	return int(sequence % uint64(size))
}

func ConfigureTransport(transport *http.Transport) *http.Transport {
	if transport == nil {
		transport = &http.Transport{}
	}
	transport.Proxy = next
	return transport
}

func CheckOne(value *models.ProxyEndpoint) error {
	proxyURL, err := value.ProxyURL()
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 12 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	started := time.Now()
	resp, err := client.Get("https://api.ipify.org?format=json")
	now := time.Now()
	value.LastCheckedAt = &now
	if err == nil && resp.StatusCode >= 400 {
		err = fmt.Errorf("validation endpoint returned %s", resp.Status)
	}
	if resp != nil {
		resp.Body.Close()
	}
	if err != nil {
		value.Status = "dead"
		value.FailureCount++
		value.LastError = err.Error()
		return err
	}
	value.Status = "healthy"
	value.SuccessCount++
	value.LatencyMS = time.Since(started).Milliseconds()
	value.LastError = ""
	return nil
}

func CheckAll() (int, int, int, error) {
	if database.DB == nil {
		return 0, 0, 0, fmt.Errorf("proxy database is unavailable")
	}
	var values []models.ProxyEndpoint
	if err := database.DB.Where("is_enabled = ?", true).Find(&values).Error; err != nil {
		return 0, 0, 0, fmt.Errorf("load proxies: %w", err)
	}
	var wg sync.WaitGroup
	jobs := make(chan *models.ProxyEndpoint)
	var saveMu sync.Mutex
	var saveErr error
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for value := range jobs {
				_ = CheckOne(value)
				if err := database.DB.Save(value).Error; err != nil {
					saveMu.Lock()
					if saveErr == nil {
						saveErr = err
					}
					saveMu.Unlock()
				}
			}
		}()
	}
	for i := range values {
		jobs <- &values[i]
	}
	close(jobs)
	wg.Wait()
	if saveErr != nil {
		return len(values), 0, 0, fmt.Errorf("save proxy test result: %w", saveErr)
	}
	Refresh()
	healthy := 0
	for _, value := range values {
		if value.Status == "healthy" {
			healthy++
		}
	}
	return len(values), healthy, len(values) - healthy, nil
}

func StartAutoChecker() func() {
	checkerOnce.Do(func() {
		checkerStop = make(chan struct{})
		go func() {
			for {
				enabled, interval, err := checkConfig()
				if err != nil {
					log.Printf("Proxy health check configuration unavailable: %v", err)
					enabled = false
				}
				if enabled {
					if _, _, _, err := CheckAll(); err != nil {
						log.Printf("Proxy health check failed: %v", err)
					}
				}
				timer := time.NewTimer(interval)
				select {
				case <-timer.C:
				case <-checkerStop:
					timer.Stop()
					return
				}
			}
		}()
	})
	return func() {
		select {
		case <-checkerStop:
		default:
			close(checkerStop)
		}
	}
}

func checkConfig() (bool, time.Duration, error) {
	enabled, interval := true, 30
	if database.DB == nil {
		return false, time.Duration(interval) * time.Second, fmt.Errorf("proxy database is unavailable")
	}
	var settings []models.Setting
	if err := database.DB.Where("category = ? AND key IN ?", "scanner", []string{"proxy_auto_check_enabled", "proxy_check_interval_seconds"}).Find(&settings).Error; err != nil {
		return false, time.Duration(interval) * time.Second, fmt.Errorf("load proxy health check settings: %w", err)
	}
	for _, setting := range settings {
		if setting.Key == "proxy_auto_check_enabled" {
			enabled = setting.Value != "false" && setting.Value != "0"
		}
		if setting.Key == "proxy_check_interval_seconds" {
			var value int
			fmt.Sscanf(setting.Value, "%d", &value)
			if value >= 10 && value <= 86400 {
				interval = value
			}
		}
	}
	return enabled, time.Duration(interval) * time.Second, nil
}

func rotationConfig() (bool, int, error) {
	enabled, interval := true, 30
	if database.DB == nil {
		return false, interval, fmt.Errorf("proxy database is unavailable")
	}
	var settings []models.Setting
	if err := database.DB.Where("category = ? AND key IN ?", "scanner", []string{"proxy_rotation_enabled", "proxy_rotation_interval_seconds"}).Find(&settings).Error; err != nil {
		return false, interval, fmt.Errorf("load proxy rotation settings: %w", err)
	}
	for _, setting := range settings {
		switch setting.Key {
		case "proxy_rotation_enabled":
			enabled = setting.Value != "false" && setting.Value != "0"
		case "proxy_rotation_interval_seconds":
			var value int
			fmt.Sscanf(setting.Value, "%d", &value)
			if value >= 10 && value <= 86400 {
				interval = value
			}
		}
	}
	return enabled, interval, nil
}
