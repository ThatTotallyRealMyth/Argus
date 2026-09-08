package scanner

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/proxypool"
)

// WAFDetector WAFDetection
type WAFDetector struct {
	client *http.Client
}

// NewWAFDetector CreateWAFDetection
func NewWAFDetector() *WAFDetector {
	return &WAFDetector{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: proxypool.ConfigureTransport(&http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}),
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// WAFSignature WAFCharacteristics
type WAFSignature struct {
	Name    string
	Headers map[string]string
	Cookies []string
	Body    []string
}

// Detect TestWAF
func (d *WAFDetector) Detect(url string) []string {
	var detectedWAFs []string

	// Send Test Request
	resp, err := d.client.Get(url)
	if err != nil {
		return detectedWAFs
	}
	defer resp.Body.Close()

	// WAFFeature Library
	signatures := []WAFSignature{
		{
			Name: "Cloudflare",
			Headers: map[string]string{
				"server":          "cloudflare",
				"cf-ray":          "",
				"cf-cache-status": "",
			},
		},
		{
			Name: "AWS WAF",
			Headers: map[string]string{
				"x-amzn-requestid": "",
				"x-amzn-errortype": "",
			},
		},
		{
			Name: "Azure WAF",
			Headers: map[string]string{
				"x-azure-ref": "",
			},
		},
		{
			Name: "Akamai",
			Headers: map[string]string{
				"server": "AkamaiGHost",
			},
		},
		{
			Name: "Incapsula",
			Headers: map[string]string{
				"x-cdn": "Incapsula",
			},
			Cookies: []string{"incap_ses", "visid_incap"},
		},
		{
			Name: "Sucuri",
			Headers: map[string]string{
				"server":         "Sucuri",
				"x-sucuri-id":    "",
				"x-sucuri-cache": "",
			},
		},
		{
			Name: "ModSecurity",
			Headers: map[string]string{
				"server": "Mod_Security",
			},
		},
		{
			Name: "Barracuda",
			Headers: map[string]string{
				"server": "Barracuda",
			},
			Cookies: []string{"barra_counter_session", "BNI__BARRACUDA_LB_COOKIE"},
		},
		{
			Name: "F5 BIG-IP",
			Headers: map[string]string{
				"server": "BigIP",
			},
			Cookies: []string{"BIGipServer", "TS"},
		},
		{
			Name: "Fortinet FortiWeb",
			Headers: map[string]string{
				"server": "FortiWeb",
			},
			Cookies: []string{"FORTIWAFSID"},
		},
		{
			Name: "Ali Yun shiver.",
			Headers: map[string]string{
				"ali-swift-global-savetime": "",
				"eagleid":                   "",
			},
		},
		{
			Name: "Xing XingyunWAF",
			Headers: map[string]string{
				"waf-powered-by": "Tencent",
			},
		},
		{
			Name: "Safe Dog",
			Headers: map[string]string{
				"server": "Safedog",
			},
			Cookies: []string{"safedog-flow-item"},
		},
		{
			Name: "Cloud lock.",
			Headers: map[string]string{
				"server": "Yunsuo",
			},
		},
	}

	// Check Characteristics
	for _, sig := range signatures {
		if d.matchSignature(resp, sig) {
			detectedWAFs = append(detectedWAFs, sig.Name)
		}
	}

	// Send malignant request test
	if d.testMaliciousRequest(url) {
		if len(detectedWAFs) == 0 {
			detectedWAFs = append(detectedWAFs, "Unknown WAF")
		}
	}

	return detectedWAFs
}

// matchSignature Matching Characters
func (d *WAFDetector) matchSignature(resp *http.Response, sig WAFSignature) bool {
	// InspectionHeaders
	for header, value := range sig.Headers {
		headerValue := resp.Header.Get(header)
		if headerValue != "" {
			if value == "" || strings.Contains(strings.ToLower(headerValue), strings.ToLower(value)) {
				return true
			}
		}
	}

	// InspectionCookies
	for _, cookieName := range sig.Cookies {
		for _, cookie := range resp.Cookies() {
			if strings.Contains(cookie.Name, cookieName) {
				return true
			}
		}
	}

	return false
}

// testMaliciousRequest Test malignant request.
func (d *WAFDetector) testMaliciousRequest(baseURL string) bool {
	// TestSQLInject.
	testURL := baseURL + "?id=1' OR '1'='1"
	resp, err := d.client.Get(testURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// If returned403or similar status code, Maybe.WAF
	if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 419 {
		return true
	}

	return false
}
