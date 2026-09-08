package scanner

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/utils"
	"gorm.io/gorm"
)

// ScanContext Scan context
type ScanContext struct {
	Task           *models.Task
	DB             *gorm.DB
	Logger         *log.Logger
	Ctx            context.Context    // Scan lifecycle context.
	ProgressChan   chan *ScanProgress // WebSocket Progress Send Channel
	ValidateTarget func(string) error // Authorisation of active network target verification
}

// ValidateNetworkTarget applies the task authorization boundary. A nil
// callback preserves compatibility for scanner use outside task execution.
func (ctx *ScanContext) ValidateNetworkTarget(target string) error {
	if ctx == nil || ctx.ValidateTarget == nil {
		return nil
	}
	return ctx.ValidateTarget(target)
}

// TargetList Return to original task, Go to the blank target list.CIDR Not here to expand, Avoid
// Passive collection and domain name phases take each IP As a stand-alone Internet target..
func (ctx *ScanContext) TargetList() []string {
	if ctx == nil || ctx.Task == nil {
		return nil
	}
	rawTargets := strings.Split(ctx.Task.Target, ",")
	targets := make([]string, 0, len(rawTargets))
	seen := make(map[string]struct{}, len(rawTargets))
	for _, raw := range rawTargets {
		target := strings.TrimSpace(raw)
		if target == "" {
			continue
		}
		if _, exists := seen[target]; exists {
			continue
		}
		seen[target] = struct{}{}
		targets = append(targets, target)
	}
	return targets
}

// Engine Scan engines
type Engine struct {
	domainScanner      *DomainScanner
	portScanner        *PortScanner
	cSegmentScanner    *CSegmentScanner
	serviceScanner     *ServiceScanner
	siteScanner        *SiteScanner
	hostCollision      *HostCollisionScanner
	osDetector         *OSDetector
	customScriptRunner *CustomScriptRunner
	passiveScanner     *PassiveScanner
	takeoverScanner    *SubdomainTakeoverScanner
	assetMapper        *AssetMapper
	smartPoCScanner    *SmartPoCScanner // SmartPoCScanner(AlternativeNuclei/XPOC/Afrog)
}

// NewEngine Create Scan Engine
func NewEngine() *Engine {
	return &Engine{
		domainScanner:      NewDomainScanner(),
		portScanner:        NewPortScanner(),
		cSegmentScanner:    NewCSegmentScanner(),
		serviceScanner:     NewServiceScanner(),
		siteScanner:        NewSiteScanner(),
		hostCollision:      NewHostCollisionScanner(),
		osDetector:         NewOSDetector(),
		customScriptRunner: NewCustomScriptRunner(),
		passiveScanner:     NewPassiveScanner(),
		takeoverScanner:    NewSubdomainTakeoverScanner(),
		assetMapper:        NewAssetMapper(),
		smartPoCScanner:    NewSmartPoCScanner(), // SmartPoCScanner
	}
}

// DiscoverDomains Domain name found
func (e *Engine) DiscoverDomains(ctx *ScanContext) error {
	return e.domainScanner.Scan(ctx)
}

// ResolveIPs IPParsing (Scanning for domain names completed, Keep this method to keep compatibility)
func (e *Engine) ResolveIPs(ctx *ScanContext) error {
	// IPParsing already done automatically during domain name scan
	// This is where you process the direct input.IPorCIDRFormat

	if ctx == nil || ctx.Task == nil {
		return fmt.Errorf("scan context and task are required")
	}
	scanContext := ctx.Ctx
	if scanContext == nil {
		scanContext = context.Background()
	}

	// Get Target List; CIDR By Unable to Undo Parser.
	targets := ctx.TargetList()

	for _, target := range targets {
		select {
		case <-scanContext.Done():
			return scanContext.Err()
		default:
		}

		// Only IP The slash target is the prefix. CIDR; URL The path slash cannot be entered IP Detection.
		if isIPCIDRTarget(target) {
			ctx.Logger.Printf("Parsing CIDR target: %s", target)
			ips, err := utils.ParseTargetContext(scanContext, target)
			if err != nil {
				ctx.Logger.Printf("Failed to parse CIDR %s: %v", target, err)
				if scanContext.Err() != nil {
					return scanContext.Err()
				}
				return err
			}

			ctx.Logger.Printf("Generated %d IPs from CIDR %s, checking liveness...", len(ips), target)

			// 🆕 Survival tests: Only the ones that survive.IP
			aliveIPs, err := e.checkCIDRAlive(scanContext, ips)
			if err != nil {
				return err
			}

			// Save the living.IP
			aliveCount := 0
			for _, aliveIP := range aliveIPs {
				ipModel := &models.IP{
					TaskID:    ctx.Task.ID,
					IPAddress: aliveIP,
					Source:    "cidr",
				}
				ctx.DB.Where("task_id = ? AND ip_address = ?", ctx.Task.ID, aliveIP).FirstOrCreate(ipModel)
				aliveCount++

				if aliveCount%10 == 0 {
					ctx.Logger.Printf("CIDR scan: found %d alive IPs so far...", aliveCount)
				}
			}

			ctx.Logger.Printf("CIDR %s: scanned %d IPs, found %d alive", target, len(ips), aliveCount)
		} else if net.ParseIP(target) != nil {
			// SingleIPAddress
			ctx.Logger.Printf("Parsing single IP: %s", target)
			ipModel := &models.IP{
				TaskID:    ctx.Task.ID,
				IPAddress: target,
				Source:    "input",
			}
			ctx.DB.Where("task_id = ? AND ip_address = ?", ctx.Task.ID, target).FirstOrCreate(ipModel)
		}
	}

	ctx.Logger.Printf("IP resolution completed")
	return nil
}

func isIPCIDRTarget(target string) bool {
	if !strings.Contains(target, "/") || strings.Contains(target, "://") {
		return false
	}
	prefix := strings.SplitN(target, "/", 2)[0]
	return net.ParseIP(prefix) != nil
}

func (e *Engine) checkCIDRAlive(ctx context.Context, ips []string) ([]string, error) {
	if len(ips) == 0 {
		return nil, nil
	}
	jobs := make(chan string)
	alive := make(chan string)
	const workerCount = 50

	var workers sync.WaitGroup
	workers.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go func() {
			defer workers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ip, ok := <-jobs:
					if !ok {
						return
					}
					if e.cSegmentScanner.IsAlive(ip) {
						select {
						case alive <- ip:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, ip := range ips {
			select {
			case jobs <- ip:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(alive)
	}()

	result := make([]string, 0, len(ips))
	for ip := range alive {
		result = append(result, ip)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// ScanCSegment CParagraph Scan
func (e *Engine) ScanCSegment(ctx *ScanContext) error {
	return e.cSegmentScanner.Scan(ctx)
}

// ScanPorts Port Scan
func (e *Engine) ScanPorts(ctx *ScanContext) error {
	return e.portScanner.Scan(ctx)
}

// DetectServices Service recognition
func (e *Engine) DetectServices(ctx *ScanContext) error {
	return e.serviceScanner.Detect(ctx)
}

// DetectSites Site recognition
func (e *Engine) DetectSites(ctx *ScanContext) error {
	return e.siteScanner.Detect(ctx)
}

// TakeScreenshots Site Screenshot
func (e *Engine) TakeScreenshots(ctx *ScanContext) error {
	return e.siteScanner.TakeScreenshots(ctx)
}

// CheckFileLeaks File leak detection
func (e *Engine) CheckFileLeaks(ctx *ScanContext) error {
	return e.siteScanner.CheckFileLeaks(ctx)
}

// RunPoCScanning Run SmartPoCScan - It's based on a fingerprint match.(AlternativeNuclei/XPOC/Afrog)
func (e *Engine) RunPoCScanning(ctx *ScanContext) error {
	ctx.Logger.Printf("Starting smart PoC scanning with fingerprint matching...")
	return e.smartPoCScanner.ScanWithFingerprints(ctx)
}

// CheckHostCollision TestHostCollision
func (e *Engine) CheckHostCollision(ctx *ScanContext) error {
	return e.hostCollision.Scan(ctx)
}

// DetectOS Test operating system
func (e *Engine) DetectOS(ctx *ScanContext) error {
	if ctx == nil || ctx.Task == nil || ctx.DB == nil {
		return fmt.Errorf("scan context, task, and database are required")
	}
	if !ctx.Task.Options.EnableOSDetect {
		return nil
	}

	scanContext := ctx.Ctx
	if scanContext == nil {
		scanContext = context.Background()
	}
	db := ctx.DB.WithContext(scanContext)

	var ips []models.IP
	if err := db.Where("task_id = ? AND (os IS NULL OR os = '')", ctx.Task.ID).Find(&ips).Error; err != nil {
		return fmt.Errorf("load IPs for OS detection: %w", err)
	}

	ctx.Logger.Printf("Detecting OS for %d IPs", len(ips))

	for _, ip := range ips {
		select {
		case <-scanContext.Done():
			return scanContext.Err()
		default:
		}
		if err := ctx.ValidateNetworkTarget(ip.IPAddress); err != nil {
			ctx.Logger.Printf("OS detection target blocked by scan scope: %s", ip.IPAddress)
			continue
		}
		// Get thatIPOpen port
		var ports []models.Port
		if err := db.Where("task_id = ? AND ip_address = ?", ctx.Task.ID, ip.IPAddress).Find(&ports).Error; err != nil {
			return fmt.Errorf("load ports for OS detection on %s: %w", ip.IPAddress, err)
		}

		if len(ports) == 0 {
			continue
		}

		openPorts := make([]int, len(ports))
		for i, p := range ports {
			openPorts[i] = p.Port
		}

		// TestOS
		os := e.osDetector.Detect(ip.IPAddress, openPorts)
		if os != "" && os != "Unknown" {
			result := db.Model(&models.IP{}).
				Where("id = ? AND task_id = ?", ip.ID, ctx.Task.ID).
				Update("os", os)
			if result.Error != nil {
				return fmt.Errorf("save OS detection for %s: %w", ip.IPAddress, result.Error)
			}
			if result.RowsAffected != 1 {
				return fmt.Errorf("save OS detection for %s: task-scoped row was not found", ip.IPAddress)
			}
			ctx.Logger.Printf("OS detected: %s -> %s", ip.IPAddress, os)
		}
	}

	return nil
}

// RunCustomScript Run Custom Scripts
func (e *Engine) RunCustomScript(ctx *ScanContext, scriptPath string) error {
	// Get all sites as targets
	var sites []models.Site
	ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&sites)

	if len(sites) == 0 {
		ctx.Logger.Printf("No sites found for custom script")
		return nil
	}

	ctx.Logger.Printf("Running custom script: %s for %d sites", scriptPath, len(sites))

	// Target extractionURLs
	var targets []string
	for _, site := range sites {
		targets = append(targets, site.URL)
	}

	// Execute Script
	vulns, err := e.customScriptRunner.RunScript(ctx, scriptPath, targets)
	if err != nil {
		return err
	}

	// Save the bug
	for _, vuln := range vulns {
		ctx.DB.Create(vuln)
	}

	ctx.Logger.Printf("Custom script completed, found %d vulnerabilities", len(vulns))
	return nil
}

// RunPassiveScan Run Passive Scan
func (e *Engine) RunPassiveScan(ctx *ScanContext) error {
	return e.passiveScanner.Scan(ctx)
}

// CheckSubdomainTakeover Subdomain name takes over the test
func (e *Engine) CheckSubdomainTakeover(ctx *ScanContext) error {
	return e.takeoverScanner.Scan(ctx)
}

// MapAssets Asset mapping
func (e *Engine) MapAssets(ctx *ScanContext) error {
	return e.assetMapper.MapAssets(ctx)
}
