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

// ScanContext 扫描上下文
type ScanContext struct {
	Task           *models.Task
	DB             *gorm.DB
	Logger         *log.Logger
	Ctx            context.Context    // 用于取消任务
	ProgressChan   chan *ScanProgress // WebSocket 进度推送通道
	ValidateTarget func(string) error // 主动网络目标的授权范围校验
}

// ValidateNetworkTarget applies the task authorization boundary. A nil
// callback preserves compatibility for scanner use outside task execution.
func (ctx *ScanContext) ValidateNetworkTarget(target string) error {
	if ctx == nil || ctx.ValidateTarget == nil {
		return nil
	}
	return ctx.ValidateTarget(target)
}

// TargetList 返回任务的原始、去空白目标列表。CIDR 不在这里展开，避免
// 被动收集和域名阶段把每个 IP 当成独立互联网目标。
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

// Engine 扫描引擎
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
	smartPoCScanner    *SmartPoCScanner // 智能PoC扫描器(替代Nuclei/XPOC/Afrog)
}

// NewEngine 创建扫描引擎
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
		smartPoCScanner:    NewSmartPoCScanner(), // 智能PoC扫描器
	}
}

// DiscoverDomains 域名发现
func (e *Engine) DiscoverDomains(ctx *ScanContext) error {
	return e.domainScanner.Scan(ctx)
}

// ResolveIPs IP解析（已在域名扫描中完成，保留此方法以保持兼容性）
func (e *Engine) ResolveIPs(ctx *ScanContext) error {
	// IP解析已经在域名扫描过程中自动完成
	// 这里处理直接输入的IP或CIDR格式

	if ctx == nil || ctx.Task == nil {
		return fmt.Errorf("scan context and task are required")
	}
	scanContext := ctx.Ctx
	if scanContext == nil {
		scanContext = context.Background()
	}

	// 获取目标列表；CIDR 由可取消的统一解析器展开。
	targets := ctx.TargetList()

	for _, target := range targets {
		select {
		case <-scanContext.Done():
			return scanContext.Err()
		default:
		}

		// 只有 IP 前缀的斜杠目标才是 CIDR；URL 中的路径斜杠不能进入 IP 探测。
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

			// 🆕 存活性检测：只保存存活的IP
			aliveIPs, err := e.checkCIDRAlive(scanContext, ips)
			if err != nil {
				return err
			}

			// 保存存活的IP
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
			// 单个IP地址
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

// ScanCSegment C段扫描
func (e *Engine) ScanCSegment(ctx *ScanContext) error {
	return e.cSegmentScanner.Scan(ctx)
}

// ScanPorts 端口扫描
func (e *Engine) ScanPorts(ctx *ScanContext) error {
	return e.portScanner.Scan(ctx)
}

// DetectServices 服务识别
func (e *Engine) DetectServices(ctx *ScanContext) error {
	return e.serviceScanner.Detect(ctx)
}

// DetectSites 站点识别
func (e *Engine) DetectSites(ctx *ScanContext) error {
	return e.siteScanner.Detect(ctx)
}

// TakeScreenshots 站点截图
func (e *Engine) TakeScreenshots(ctx *ScanContext) error {
	return e.siteScanner.TakeScreenshots(ctx)
}

// CheckFileLeaks 文件泄露检测
func (e *Engine) CheckFileLeaks(ctx *ScanContext) error {
	return e.siteScanner.CheckFileLeaks(ctx)
}

// RunPoCScanning 运行智能PoC扫描 - 基于指纹匹配(替代Nuclei/XPOC/Afrog)
func (e *Engine) RunPoCScanning(ctx *ScanContext) error {
	ctx.Logger.Printf("Starting smart PoC scanning with fingerprint matching...")
	return e.smartPoCScanner.ScanWithFingerprints(ctx)
}

// CheckHostCollision 检测Host碰撞
func (e *Engine) CheckHostCollision(ctx *ScanContext) error {
	return e.hostCollision.Scan(ctx)
}

// DetectOS 检测操作系统
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
		// 获取该IP的开放端口
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

		// 检测OS
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

// RunCustomScript 运行自定义脚本
func (e *Engine) RunCustomScript(ctx *ScanContext, scriptPath string) error {
	// 获取所有站点作为目标
	var sites []models.Site
	ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&sites)

	if len(sites) == 0 {
		ctx.Logger.Printf("No sites found for custom script")
		return nil
	}

	ctx.Logger.Printf("Running custom script: %s for %d sites", scriptPath, len(sites))

	// 提取目标URLs
	var targets []string
	for _, site := range sites {
		targets = append(targets, site.URL)
	}

	// 执行脚本
	vulns, err := e.customScriptRunner.RunScript(ctx, scriptPath, targets)
	if err != nil {
		return err
	}

	// 保存漏洞
	for _, vuln := range vulns {
		ctx.DB.Create(vuln)
	}

	ctx.Logger.Printf("Custom script completed, found %d vulnerabilities", len(vulns))
	return nil
}

// RunPassiveScan 运行被动扫描
func (e *Engine) RunPassiveScan(ctx *ScanContext) error {
	return e.passiveScanner.Scan(ctx)
}

// CheckSubdomainTakeover 子域名接管检测
func (e *Engine) CheckSubdomainTakeover(ctx *ScanContext) error {
	return e.takeoverScanner.Scan(ctx)
}

// MapAssets 资产测绘
func (e *Engine) MapAssets(ctx *ScanContext) error {
	return e.assetMapper.MapAssets(ctx)
}
