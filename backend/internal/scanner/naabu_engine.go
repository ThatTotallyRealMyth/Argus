//go:build linux && cgo

package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// NaabuEngine NaabuPort Scan Engine
type NaabuEngine struct {
	rate        int
	timeout     time.Duration
	concurrency int
}

func (ne *NaabuEngine) Name() string { return "naabu" }

// NewNaabuEngine CreateNaabuScan engines
func NewNaabuEngine() *NaabuEngine {
	return &NaabuEngine{
		rate:        0, // 0This indicates self-adaptation rate
		timeout:     3 * time.Second,
		concurrency: 25, // Default25Together.
	}
}

// SetRate Set Scan Rate (Manually Assign)
func (ne *NaabuEngine) SetRate(rate int) {
	ne.rate = rate
}

// calculateAdaptiveRate Rate of self-adaptation based on scan size
func (ne *NaabuEngine) calculateAdaptiveRate(targetCount, portCount int) int {
	// If the speed is set manually, Direct use
	if ne.rate > 0 {
		return ne.rate
	}

	// Calculate total scans
	totalScans := targetCount * portCount

	var adaptiveRate int

	switch {
	case portCount <= 100:
		// Small-scale scan (TOP100Port): Superhigh.
		adaptiveRate = 10000

	case portCount <= 1000:
		// Medium-range scan (TOP1000Port): High speed
		adaptiveRate = 5000

	case portCount <= 10000:
		// Large scan (1-10000Port): Medium Speed
		if targetCount > 100 {
			// CParagraphs and above: Lower the speed to avoid cyber congestion
			adaptiveRate = 3000
		} else {
			adaptiveRate = 5000
		}

	default:
		// Full Port Scan (65535Port): Adjusted to target number
		if targetCount == 1 {
			// Single Target Full Port: High speed
			adaptiveRate = 8000
		} else if targetCount <= 10 {
			// Small Target Full Port: Medium Highway
			adaptiveRate = 5000
		} else if targetCount <= 100 {
			// CParagraph Full Port: Medium Speed
			adaptiveRate = 3000
		} else {
			// Mass Full Port: Conservative Rate
			adaptiveRate = 2000
		}
	}

	fmt.Printf("🎯 Adaptive Rate: %d pps (targets=%d, ports=%d, total=%d scans)\n",
		adaptiveRate, targetCount, portCount, totalScans)

	return adaptiveRate
}

// ScanPorts UseNaabuScan Port
func (ne *NaabuEngine) ScanPorts(ctx context.Context, targets []string, ports []int) ([]*PortScanResult, error) {
	// Calculate self-adaptation rate
	adaptiveRate := ne.calculateAdaptiveRate(len(targets), len(ports))

	fmt.Printf("=== Naabu Port Scanner ===\n")
	fmt.Printf("Targets: %d | Ports: %d | Rate: %d pps\n", len(targets), len(ports), adaptiveRate)

	// For collecting results
	var results []*PortScanResult
	var resultsMutex sync.Mutex

	// CreateNaabuOptions (Must createrunnerSet backs before)
	options := &runner.Options{
		Host:    targets,
		Ports:   formatPortsForNaabu(ports),
		Rate:    adaptiveRate,
		Timeout: ne.timeout,
		Retries: 1,
		Threads: ne.concurrency,
		Silent:  true,
		OnResult: func(hr *result.HostResult) {
			resultsMutex.Lock()
			defer resultsMutex.Unlock()

			fmt.Printf("✓ Found open ports on %s: %v\n", hr.Host, hr.Ports)

			for _, port := range hr.Ports {
				results = append(results, &PortScanResult{
					IP:       hr.Host,
					Port:     port.Port,
					Protocol: "tcp",
					Open:     true,
					Service:  "unknown", // NaabuDo not perform service recognition
				})
			}
		},
	}

	// CreateNaabu runner
	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		return nil, fmt.Errorf("failed to create naabu runner: %w", err)
	}
	defer naabuRunner.Close()

	// Execute Scan
	fmt.Println("Starting Naabu scan...")
	if err := naabuRunner.RunEnumeration(ctx); err != nil {
		return nil, fmt.Errorf("naabu scan failed: %w", err)
	}

	fmt.Printf("✓ Naabu scan complete: found %d open ports\n", len(results))

	// UsegonmapService identification (PureGoAchieved, No need.nmapBinary)
	if len(results) > 0 {
		fmt.Println("🔍 Performing service detection with gonmap...")
		detector := NewServiceDetector()
		results = detector.DetectServices(results)
	}

	return results, nil
}

// formatPortsForNaabu Format Port List AsNaabuAccepted Strings
func formatPortsForNaabu(ports []int) string {
	if len(ports) == 0 {
		return "1-65535"
	}

	// NaabuList of ports supporting comma-separated
	portStr := ""
	for i, port := range ports {
		if i > 0 {
			portStr += ","
		}
		portStr += fmt.Sprintf("%d", port)
	}
	return portStr
}
