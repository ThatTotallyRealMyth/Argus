package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/proxypool"
	"gopkg.in/yaml.v3"
)

// PoCExecutor PoCExecutor
type PoCExecutor struct {
	client        *http.Client
	neutronEngine *NeutronEngine
}

// NewPoCExecutor CreatePoCExecutor
func NewPoCExecutor() *PoCExecutor {
	return &PoCExecutor{
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: proxypool.ConfigureTransport(&http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			}),
		},
		neutronEngine: NewNeutronEngine(),
	}
}

// NucleiTemplate NucleiTemplate Structure (Simplified version)
type NucleiTemplate struct {
	ID   string `yaml:"id"`
	Info struct {
		Name        string   `yaml:"name"`
		Author      string   `yaml:"author"`
		Severity    string   `yaml:"severity"`
		Description string   `yaml:"description"`
		Reference   []string `yaml:"reference"`
		Tags        []string `yaml:"tags"`
	} `yaml:"info"`
	Requests []struct {
		Method   string            `yaml:"method"`
		Path     []string          `yaml:"path"`
		Headers  map[string]string `yaml:"headers"`
		Body     string            `yaml:"body"`
		Matchers []struct {
			Type   string   `yaml:"type"`
			Words  []string `yaml:"words"`
			Regex  []string `yaml:"regex"`
			Status []int    `yaml:"status"`
			Part   string   `yaml:"part"`
		} `yaml:"matchers"`
		MatchersCondition string `yaml:"matchers-condition"` // and/or
	} `yaml:"requests"`
}

// ExecuteResult Results of implementation
type ExecuteResult struct {
	Vulnerable bool
	Message    string
	Details    string
}

// Execute ImplementationPoC
func (e *PoCExecutor) Execute(poc *models.PoC, target string) (*ExecuteResult, error) {
	// EnsuretargetByhttporhttpsStart
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	switch strings.ToLower(strings.TrimSpace(poc.PoCType)) {
	case "nuclei":
		// UseNeutronEngine executionNucleiFormattedPoC
		return e.executeNucleiPoCWithNeutron(poc, target)
	case "custom":
		return e.executeCustomPoC(poc.PoCContent, target)
	default:
		return nil, fmt.Errorf("unsupported PoC type: %s", poc.PoCType)
	}
}

// executeNucleiPoCWithNeutron UseNeutronEngine executionNucleiFormattedPoC
func (e *PoCExecutor) executeNucleiPoCWithNeutron(poc *models.PoC, target string) (*ExecuteResult, error) {
	result, err := e.neutronEngine.ExecutePoC(poc, target)
	if err != nil {
		return nil, fmt.Errorf("neutron execution failed: %w", err)
	}

	return &ExecuteResult{
		Vulnerable: result.Vulnerable,
		Message:    result.Message,
		Details:    fmt.Sprintf("Template: %s, Matcher: %s", result.TemplateID, result.MatcherName),
	}, nil
}

// executeNucleiPoC ImplementationNucleiFormattedPoC (Retaining the original method asfallback)
func (e *PoCExecutor) executeNucleiPoC(poc *models.PoC, target string) (*ExecuteResult, error) {
	var template NucleiTemplate
	if err := yaml.Unmarshal([]byte(poc.PoCContent), &template); err != nil {
		return nil, fmt.Errorf("failed to parse nuclei template: %v", err)
	}

	// I've been through all the requests.
	for _, request := range template.Requests {
		// Default method isGET
		method := request.Method
		if method == "" {
			method = "GET"
		}

		// Walk through all paths
		for _, path := range request.Path {
			// Build FullURL
			url := target
			if !strings.HasSuffix(target, "/") && !strings.HasPrefix(path, "/") {
				url += "/"
			}
			url += strings.TrimPrefix(path, "/")

			// CreateHTTPRequest
			req, err := http.NewRequest(method, url, strings.NewReader(request.Body))
			if err != nil {
				continue
			}

			// Set request header
			for key, value := range request.Headers {
				req.Header.Set(key, value)
			}

			// Set DefaultUser-Agent
			if req.Header.Get("User-Agent") == "" {
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			}

			// Send Request
			resp, err := e.client.Do(req)
			if err != nil {
				continue
			}

			// Read Response
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			// Check Match
			matched := e.checkMatchers(request.Matchers, request.MatchersCondition, resp, body)
			if matched {
				return &ExecuteResult{
					Vulnerable: true,
					Message:    fmt.Sprintf("Vulnerability detected: %s", template.Info.Name),
					Details:    fmt.Sprintf("URL: %s\nStatus: %d\nSeverity: %s", url, resp.StatusCode, template.Info.Severity),
				}, nil
			}
		}
	}

	return &ExecuteResult{
		Vulnerable: false,
		Message:    "No vulnerability detected",
		Details:    "Target is safe",
	}, nil
}

// checkMatchers Check Match
func (e *PoCExecutor) checkMatchers(matchers []struct {
	Type   string   `yaml:"type"`
	Words  []string `yaml:"words"`
	Regex  []string `yaml:"regex"`
	Status []int    `yaml:"status"`
	Part   string   `yaml:"part"`
}, condition string, resp *http.Response, body []byte) bool {
	if len(matchers) == 0 {
		return false
	}

	// Default condition isor
	if condition == "" {
		condition = "or"
	}

	results := make([]bool, len(matchers))

	for i, matcher := range matchers {
		results[i] = e.checkSingleMatcher(matcher, resp, body)
	}

	// Group results according to conditions
	if condition == "and" {
		for _, result := range results {
			if !result {
				return false
			}
		}
		return true
	} else { // or
		for _, result := range results {
			if result {
				return true
			}
		}
		return false
	}
}

// checkSingleMatcher Check individual matches
func (e *PoCExecutor) checkSingleMatcher(matcher struct {
	Type   string   `yaml:"type"`
	Words  []string `yaml:"words"`
	Regex  []string `yaml:"regex"`
	Status []int    `yaml:"status"`
	Part   string   `yaml:"part"`
}, resp *http.Response, body []byte) bool {
	bodyStr := string(body)

	// Get the check part (Default Asbody)
	checkContent := bodyStr
	if matcher.Part == "header" {
		checkContent = fmt.Sprintf("%v", resp.Header)
	}

	switch matcher.Type {
	case "word", "words":
		// Check keywords (All keywords must exist.)
		for _, word := range matcher.Words {
			if !strings.Contains(checkContent, word) {
				return false
			}
		}
		return len(matcher.Words) > 0

	case "regex":
		// Check regular expressions
		for _, pattern := range matcher.Regex {
			matched, err := regexp.MatchString(pattern, checkContent)
			if err != nil || !matched {
				return false
			}
		}
		return len(matcher.Regex) > 0

	case "status":
		// Check the status code
		for _, status := range matcher.Status {
			if resp.StatusCode == status {
				return true
			}
		}
		return false

	case "dsl":
		// DSLExpression support (Simplified version: Only state code and length check is supported)
		// For example...: "status_code == 200 && len(body) > 100"
		// It's a simple process here., Check the status code only
		return resp.StatusCode == 200

	default:
		return false
	}
}

// BatchExecute Batch executionPoC
func (e *PoCExecutor) BatchExecute(pocs []*models.PoC, target string) []*ExecuteResult {
	results := make([]*ExecuteResult, 0, len(pocs))

	for _, poc := range pocs {
		if !poc.IsEnabled {
			continue
		}

		result, err := e.Execute(poc, target)
		if err != nil {
			results = append(results, &ExecuteResult{
				Vulnerable: false,
				Message:    fmt.Sprintf("Execution error: %v", err),
				Details:    "",
			})
			continue
		}

		results = append(results, result)
	}

	return results
}
