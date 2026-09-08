package scanner

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

// CSegmentScanner CParagraph Scanner
type CSegmentScanner struct{}

// NewCSegmentScanner CreateCParagraph Scanner
func NewCSegmentScanner() *CSegmentScanner {
	return &CSegmentScanner{}
}

// Scan ScanCParagraphIP (With a survival test.)
func (cs *CSegmentScanner) Scan(ctx *ScanContext) error {
	if !ctx.Task.Options.EnableCSegment {
		return nil
	}

	// Fetch all parsedIP
	var ips []models.IP
	ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&ips)

	if len(ips) == 0 {
		ctx.Logger.Printf("No IPs found for C segment scanning")
		return nil
	}

	ctx.Logger.Printf("Starting C segment scanning for %d IPs", len(ips))

	// For weight-decomposition
	existingIPs := make(map[string]bool)
	for _, ip := range ips {
		existingIPs[ip.IPAddress] = true
	}

	// GenerateCParagraphIP
	cSegmentIPs := make(map[string]bool)
	for _, ip := range ips {
		// SkipCDN IP
		if ip.CDN {
			ctx.Logger.Printf("Skipping CDN IP for C segment: %s", ip.IPAddress)
			continue
		}

		// Generate theIPIt's...CParagraph
		segment := cs.generateCSegment(ip.IPAddress)
		for _, segmentIP := range segment {
			// Skip ExistingIP
			if !existingIPs[segmentIP] && !cSegmentIPs[segmentIP] {
				cSegmentIPs[segmentIP] = true
			}
		}
	}

	ctx.Logger.Printf("Generated %d C segment IPs, checking liveness...", len(cSegmentIPs))

	// Survival detection and preservation (Use fast port detection)
	count := 0
	aliveCount := 0

	// Convert to slice for commoprocessing
	ipList, blockedCount := authorizedNetworkTargets(ctx, cSegmentIPs)
	if blockedCount > 0 {
		ctx.Logger.Printf("C segment authorization blocked %d out-of-scope IPs", blockedCount)
	}

	// And we're gonna have to test and survive.IP
	aliveChan := make(chan string, len(ipList))
	semaphore := make(chan struct{}, 50) // Together.50One.

	for _, segmentIP := range ipList {
		semaphore <- struct{}{}
		go func(ip string) {
			defer func() { <-semaphore }()

			// Quick Test: Try connecting to common ports
			if cs.IsAlive(ip) {
				aliveChan <- ip
			}
		}(segmentIP)
	}

	// Waiting for all detections to be completed
	go func() {
		for i := 0; i < 50; i++ {
			semaphore <- struct{}{}
		}
		close(aliveChan)
	}()

	// Save the living.IP
	for aliveIP := range aliveChan {
		ipModel := &models.IP{
			TaskID:    ctx.Task.ID,
			IPAddress: aliveIP,
			Source:    "c_segment",
		}

		// UseFirstOrCreateAvoidance of duplication
		if err := ctx.DB.Where("task_id = ? AND ip_address = ?", ctx.Task.ID, aliveIP).
			FirstOrCreate(ipModel).Error; err != nil {
			ctx.Logger.Printf("Failed to save C segment IP %s: %v", aliveIP, err)
			continue
		}
		count++
		aliveCount++

		if aliveCount%10 == 0 {
			ctx.Logger.Printf("C segment: found %d alive IPs so far...", aliveCount)
		}
	}

	ctx.Logger.Printf("C segment scanning completed: scanned %d IPs, found %d alive, saved %d new IPs",
		len(ipList), aliveCount, count)
	return nil
}

func authorizedNetworkTargets(ctx *ScanContext, candidates map[string]bool) ([]string, int) {
	result := make([]string, 0, len(candidates))
	blocked := 0
	for target := range candidates {
		if err := ctx.ValidateNetworkTarget(target); err != nil {
			blocked++
			continue
		}
		result = append(result, target)
	}
	return result, blocked
}

// generateCSegment GenerateCParagraphIPList
func (cs *CSegmentScanner) generateCSegment(ipAddr string) []string {
	var result []string

	// ParsingIPAddress
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return result
	}

	// Only handleIPv4
	ip = ip.To4()
	if ip == nil {
		return result
	}

	// Extracting the first three paragraphs
	parts := strings.Split(ipAddr, ".")
	if len(parts) != 4 {
		return result
	}

	// GenerateCParagraph: xxx.xxx.xxx.1-254
	prefix := fmt.Sprintf("%s.%s.%s", parts[0], parts[1], parts[2])
	for i := 1; i <= 254; i++ {
		segmentIP := fmt.Sprintf("%s.%d", prefix, i)
		// Skip OriginalIP
		if segmentIP != ipAddr {
			result = append(result, segmentIP)
		}
	}

	return result
}

// IsAlive Quick TestIPAlive or not? (Detection of common ports)
func (cs *CSegmentScanner) IsAlive(ip string) bool {
	// List of common ports (Rapid detection)
	commonPorts := []int{80, 443, 22, 3389, 8080, 8443}

	timeout := 500 // 500msTimeout

	for _, port := range commonPorts {
		address := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", address, time.Duration(timeout)*time.Millisecond)
		if err == nil {
			conn.Close()
			return true // Any port open, Thinking of survival.
		}
	}

	return false
}
