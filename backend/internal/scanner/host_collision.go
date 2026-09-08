package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/proxypool"
)

// HostCollisionScanner HostCollision scanner
type HostCollisionScanner struct {
	client *http.Client
}

// NewHostCollisionScanner CreateHostCollision scanner
func NewHostCollisionScanner() *HostCollisionScanner {
	return &HostCollisionScanner{
		client: &http.Client{
			Timeout: 10,
			Transport: proxypool.ConfigureTransport(&http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}),
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Scan ImplementationHostCollision detection
func (hcs *HostCollisionScanner) Scan(ctx *ScanContext) error {
	// Get all domain names and correspondingIP
	var domains []models.Domain
	ctx.DB.Where("task_id = ? AND ip_address != ''", ctx.Task.ID).Find(&domains)

	ctx.Logger.Printf("Checking host collision for %d domains", len(domains))

	for _, domain := range domains {
		if err := ctx.ValidateNetworkTarget(domain.Domain); err != nil {
			ctx.Logger.Printf("Host collision domain blocked by scan scope: %s", domain.Domain)
			continue
		}
		if err := ctx.ValidateNetworkTarget(domain.IPAddress); err != nil {
			ctx.Logger.Printf("Host collision IP blocked by scan scope: %s", domain.IPAddress)
			continue
		}
		// Direct accessIP
		ipResponse := hcs.requestByIP(domain.IPAddress, 80)
		if ipResponse == nil {
			continue
		}

		// UseHostHeader
		hostResponse := hcs.requestWithHost(domain.IPAddress, 80, domain.Domain)
		if hostResponse == nil {
			continue
		}

		// Relative response
		if hcs.isDifferent(ipResponse, hostResponse) {
			// FoundHostCollision gap.
			vuln := &models.Vulnerability{
				TaskID:      ctx.Task.ID,
				URL:         fmt.Sprintf("http://%s", domain.IPAddress),
				Type:        "host_collision",
				Severity:    "medium",
				Title:       "HostHead Collapse",
				Description: fmt.Sprintf("IP %s For different.HostHead back to different contents.There may be an inappropriate configuration of the virtual host..Test domain name: %s", domain.IPAddress, domain.Domain),
				Solution:    "Check virtual host configuration, Ensure that configuration is correctHostHeader Authentication",
			}
			ctx.DB.Create(vuln)
			ctx.Logger.Printf("Host collision found: %s -> %s", domain.IPAddress, domain.Domain)
		}
	}

	return nil
}

// requestByIP Directly throughIPVisits
func (hcs *HostCollisionScanner) requestByIP(ip string, port int) *http.Response {
	url := fmt.Sprintf("http://%s:%d/", ip, port)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}

	resp, err := hcs.client.Do(req)
	if err != nil {
		return nil
	}

	return resp
}

// requestWithHost Use AssignedHostHeader
func (hcs *HostCollisionScanner) requestWithHost(ip string, port int, host string) *http.Response {
	url := fmt.Sprintf("http://%s:%d/", ip, port)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}

	req.Host = host
	req.Header.Set("Host", host)

	resp, err := hcs.client.Do(req)
	if err != nil {
		return nil
	}

	return resp
}

// isDifferent Compare the two responses to be different
func (hcs *HostCollisionScanner) isDifferent(resp1, resp2 *http.Response) bool {
	defer resp1.Body.Close()
	defer resp2.Body.Close()

	// Compare Status Code
	if resp1.StatusCode != resp2.StatusCode {
		return true
	}

	// ComparisonContent-Length
	if resp1.ContentLength != resp2.ContentLength && resp1.ContentLength > 0 && resp2.ContentLength > 0 {
		return true
	}

	// ReadbodyAnd compare
	body1, err1 := io.ReadAll(resp1.Body)
	body2, err2 := io.ReadAll(resp2.Body)

	if err1 != nil || err2 != nil {
		return false
	}

	// If the length varies widely, Thinks it's different.
	if abs(len(body1)-len(body2)) > 100 {
		return true
	}

	// More critical features
	return hcs.compareFeatures(string(body1), string(body2))
}

// compareFeatures Compare response features
func (hcs *HostCollisionScanner) compareFeatures(body1, body2 string) bool {
	// Extracttitle
	title1 := extractTitleFromBody(body1)
	title2 := extractTitleFromBody(body2)

	if title1 != title2 && title1 != "" && title2 != "" {
		return true
	}

	// Number of key occurrences compared
	keywords := []string{"html", "body", "script", "div"}
	for _, keyword := range keywords {
		count1 := strings.Count(strings.ToLower(body1), keyword)
		count2 := strings.Count(strings.ToLower(body2), keyword)
		if abs(count1-count2) > 5 {
			return true
		}
	}

	return false
}

// extractTitleFromBody FrombodyExtracttitle
func extractTitleFromBody(body string) string {
	start := strings.Index(strings.ToLower(body), "<title>")
	end := strings.Index(strings.ToLower(body), "</title>")

	if start >= 0 && end > start {
		return body[start+7 : end]
	}

	return ""
}

// abs Absolute value [u]
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
