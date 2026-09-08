package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

// AdvancedPortScanner Advanced Port Scanner
// Use the port available to the platform to find the engine, and unified implementation service identification.
type AdvancedPortScanner struct {
	scanMode     string // normal, comprehensive
	progressChan chan *ScanProgress
	engine       PortScanEngine
}

// ScanProgress Scan Progress
type ScanProgress struct {
	TaskID      string    `json:"task_id"`
	Stage       string    `json:"stage"`        // port_scan
	Current     int       `json:"current"`      // Current completions
	Total       int       `json:"total"`        // Total
	Percentage  float64   `json:"percentage"`   // Percentage
	Speed       float64   `json:"speed"`        // Speed (ports/sec)
	OpenPorts   int       `json:"open_ports"`   // Open port found
	ElapsedTime int64     `json:"elapsed_time"` // Time used(sec)
	ETA         int64     `json:"eta"`          // Projected remainder of time(sec)
	Message     string    `json:"message"`      // Status Message
	Timestamp   time.Time `json:"timestamp"`
}

// NewAdvancedPortScanner Create an advanced port scanner
func NewAdvancedPortScanner() *AdvancedPortScanner {
	scanner := &AdvancedPortScanner{
		scanMode:     "normal",
		progressChan: make(chan *ScanProgress, 100),
		engine:       NewPortScanEngine(),
	}
	fmt.Printf("Port scanner ready: %s discovery + gonmap service detection\n", scanner.engine.Name())

	return scanner
}

// SetProgressChannel Set Progress Send Channel
func (aps *AdvancedPortScanner) SetProgressChannel(ch chan *ScanProgress) {
	aps.progressChan = ch
}

// SetScanMode Set Scan Mode
// normal: Naabu Self-adaptation rate + Nmap Standard Scan
// comprehensive: Naabu Self-adaptation rate + Nmap Deep Scan
func (aps *AdvancedPortScanner) SetScanMode(mode string) {
	aps.scanMode = mode
	// NaabuUse self-adaptation rate, No manual setting required
	// Rates are automatically adjusted to target numbers and port range
}

// ApplyConfig Apply scanner configuration (Compatibility Interface)
func (aps *AdvancedPortScanner) ApplyConfig(config *ScannerConfig, portCount int) {
	// NaabuUse self-adaptation rate, Keep the configuration interface here to fit the existing code
}

// ScanWithProgress Execute port scan and push progress
func (aps *AdvancedPortScanner) ScanWithProgress(ctx *ScanContext, ips []models.IP, ports []int) ([]*PortScanResult, error) {
	if aps == nil {
		return nil, fmt.Errorf("port scanner not initialized")
	}

	if aps.engine == nil {
		return nil, fmt.Errorf("port scan engine not initialized")
	}

	startTime := time.Now()
	totalScans := len(ips) * len(ports)

	ctx.Logger.Printf("=== Port Scanner Started (%s) ===", aps.engine.Name())
	ctx.Logger.Printf("Scan Mode: %s", aps.scanMode)
	ctx.Logger.Printf("Target IPs: %d", len(ips))
	ctx.Logger.Printf("Ports per IP: %d", len(ports))
	ctx.Logger.Printf("Total port checks: %d", totalScans)

	// Send Initial Progress
	aps.sendProgress(ctx, 0, totalScans, 0, 0, startTime, "Start port discovery...")

	results, err := aps.scanWithEngine(ctx, ips, ports, startTime, totalScans)
	if err != nil {
		return nil, err
	}

	elapsed := time.Since(startTime)
	ctx.Logger.Printf("=== Scan Complete ===")
	ctx.Logger.Printf("Open ports found: %d", len(results))
	ctx.Logger.Printf("Total time: %v", elapsed)
	if totalScans > 0 {
		ctx.Logger.Printf("Average speed: %.0f ports/sec", float64(totalScans)/elapsed.Seconds())
	}

	// Send Completion
	aps.sendProgress(ctx, totalScans, totalScans, len(results), 0, startTime, "Port scan complete.")

	return results, nil
}

func (aps *AdvancedPortScanner) scanWithEngine(ctx *ScanContext, ips []models.IP, ports []int, startTime time.Time, totalScans int) ([]*PortScanResult, error) {
	// ConvertIPList as String Array
	ipStrings := make([]string, len(ips))
	for i, ip := range ips {
		ipStrings[i] = ip.IPAddress
	}

	ctx.Logger.Printf("Stage 1/2: %s port discovery", aps.engine.Name())
	aps.sendProgress(ctx, 0, totalScans, 0, 0, startTime, "Open port being detected...")

	// Use Naabu Engine Scan
	results, err := aps.engine.ScanPorts(ctx.Ctx, ipStrings, ports)
	if err != nil {
		return nil, fmt.Errorf("%s scan failed: %w", aps.engine.Name(), err)
	}

	ctx.Logger.Printf("Stage 2/2: service detection completed")
	ctx.Logger.Printf("Found %d open ports total", len(results))

	// Save results to database in real time
	for _, result := range results {
		aps.savePortResult(ctx, result)
	}

	// Update Final Progress
	aps.sendProgress(ctx, totalScans, totalScans, len(results), 0, startTime, "Port and service scan complete.")

	return results, nil
}

// sendProgress Send Scan Progress
func (aps *AdvancedPortScanner) sendProgress(ctx *ScanContext, current, total, openPorts int, speed float64, startTime time.Time, message string) {
	if aps.progressChan == nil {
		return
	}

	elapsed := time.Since(startTime).Seconds()
	var eta int64
	if current > 0 && current < total {
		remainingScans := total - current
		eta = int64(float64(remainingScans) / speed)
	}

	percentage := 0.0
	if total > 0 {
		percentage = float64(current) / float64(total) * 100
	}
	progress := &ScanProgress{
		TaskID:      ctx.Task.ID,
		Stage:       "port_scan",
		Current:     current,
		Total:       total,
		Percentage:  percentage,
		Speed:       speed,
		OpenPorts:   openPorts,
		ElapsedTime: int64(elapsed),
		ETA:         eta,
		Message:     message,
		Timestamp:   time.Now(),
	}

	select {
	case aps.progressChan <- progress:
	default:
		// The tunnel's full., Skip this update
	}
}

// savePortResult Save the results of the port scan to the database in real time
func (aps *AdvancedPortScanner) savePortResult(ctx *ScanContext, result *PortScanResult) {
	if ctx.DB == nil || ctx.Task == nil {
		return
	}

	// CreatePortAsset records
	port := &models.Port{
		TaskID:    ctx.Task.ID,
		IPAddress: result.IP,
		Port:      result.Port,
		Protocol:  result.Protocol,
		Service:   result.Service,
		Banner:    result.Banner,
	}

	// Use WithContext Make sure you can cancel.
	dbCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := ctx.DB.WithContext(dbCtx).Create(port).Error; err != nil {
		// Ignore duplicate record error
		if !isDuplicateError(err) {
			ctx.Logger.Printf("WARNING: Failed to save port result: %v", err)
		}
	}
}

// isDuplicateError A double record error to judge
func isDuplicateError(err error) bool {
	if err == nil {
		return false
	}
	errMsg := err.Error()
	return containsStringIgnoreCase(errMsg, "duplicate") || containsStringIgnoreCase(errMsg, "UNIQUE")
}

// containsStringIgnoreCase String contains inspection (Case sensitive, Avoid renaming)
func containsStringIgnoreCase(str, substr string) bool {
	return strings.Contains(strings.ToLower(str), strings.ToLower(substr))
}
