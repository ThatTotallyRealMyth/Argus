package scanner

import (
	"fmt"
	"net"
	"strings"

	"github.com/reconmaster/backend/internal/models"
)

// CSegmentScanner CParagraph Scanner
type CSegmentScanner struct{}

// NewCSegmentScanner CreateCParagraph Scanner
func NewCSegmentScanner() *CSegmentScanner {
	return &CSegmentScanner{}
}

// Scan queues authorized neighboring addresses for the selected Nmap profile.
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

	ctx.Logger.Printf("Generated %d C segment IPs", len(cSegmentIPs))

	// Convert to slice for commoprocessing
	ipList, blockedCount := authorizedNetworkTargets(ctx, cSegmentIPs)
	if blockedCount > 0 {
		ctx.Logger.Printf("C segment authorization blocked %d out-of-scope IPs", blockedCount)
	}

	saved, err := saveIPTargets(ctx, ipList, "c_segment")
	if err != nil {
		return err
	}
	ctx.Logger.Printf("C segment preparation completed: queued %d authorized addresses (%d new) for Nmap", len(ipList), saved)
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
