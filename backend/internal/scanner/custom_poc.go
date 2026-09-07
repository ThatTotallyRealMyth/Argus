package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	maxCustomPoCRequests     = 10
	maxCustomPoCHeaders      = 50
	maxCustomPoCBodyBytes    = 256 << 10
	maxCustomPoCResponseSize = 2 << 20
	maxCustomPoCRegex        = 32
	maxCustomPoCWords        = 64
	maxCustomPoCEvidence     = 2048
)

var customHeaderNamePattern = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

type CustomPoCTemplate struct {
	Requests []CustomPoCRequest `yaml:"requests" json:"requests"`
}

type CustomPoCRequest struct {
	Method            string             `yaml:"method,omitempty" json:"method,omitempty"`
	Path              string             `yaml:"path" json:"path"`
	Headers           map[string]string  `yaml:"headers,omitempty" json:"headers,omitempty"`
	Body              string             `yaml:"body,omitempty" json:"body,omitempty"`
	TimeoutSeconds    int                `yaml:"timeout_seconds,omitempty" json:"timeout_seconds,omitempty"`
	MatchersCondition string             `yaml:"matchers_condition,omitempty" json:"matchers_condition,omitempty"`
	Matchers          []CustomPoCMatcher `yaml:"matchers" json:"matchers"`
}

type CustomPoCMatcher struct {
	Type            string   `yaml:"type" json:"type"`
	Part            string   `yaml:"part,omitempty" json:"part,omitempty"`
	Condition       string   `yaml:"condition,omitempty" json:"condition,omitempty"`
	Words           []string `yaml:"words,omitempty" json:"words,omitempty"`
	Regex           []string `yaml:"regex,omitempty" json:"regex,omitempty"`
	Status          []int    `yaml:"status,omitempty" json:"status,omitempty"`
	MinSize         int64    `yaml:"min_size,omitempty" json:"min_size,omitempty"`
	MaxSize         int64    `yaml:"max_size,omitempty" json:"max_size,omitempty"`
	CaseInsensitive bool     `yaml:"case_insensitive,omitempty" json:"case_insensitive,omitempty"`
	Negative        bool     `yaml:"negative,omitempty" json:"negative,omitempty"`
}

func ValidatePoCContent(pocType, content string) error {
	pocType = strings.ToLower(strings.TrimSpace(pocType))
	if strings.TrimSpace(content) == "" {
		return errors.New("poc_content is required")
	}
	if len(content) > 1<<20 {
		return errors.New("poc_content exceeds 1 MiB")
	}
	switch pocType {
	case "nuclei":
		var document map[string]any
		if err := yaml.Unmarshal([]byte(content), &document); err != nil {
			return fmt.Errorf("parse nuclei PoC: %w", err)
		}
		id, hasID := document["id"].(string)
		if !hasID || strings.TrimSpace(id) == "" || document["info"] == nil {
			return errors.New("nuclei PoC requires id and info")
		}
		return nil
	case "custom":
		_, err := parseCustomPoC(content)
		return err
	default:
		return fmt.Errorf("unsupported poc_type %q; allowed: nuclei, custom", pocType)
	}
}

func parseCustomPoC(content string) (*CustomPoCTemplate, error) {
	decoder := yaml.NewDecoder(strings.NewReader(content))
	decoder.KnownFields(true)
	var template CustomPoCTemplate
	if err := decoder.Decode(&template); err != nil {
		return nil, fmt.Errorf("parse custom PoC: %w", err)
	}
	if len(template.Requests) == 0 {
		return nil, errors.New("custom PoC requires at least one request")
	}
	if len(template.Requests) > maxCustomPoCRequests {
		return nil, fmt.Errorf("custom PoC exceeds %d requests", maxCustomPoCRequests)
	}
	for index := range template.Requests {
		if err := validateCustomPoCRequest(&template.Requests[index]); err != nil {
			return nil, fmt.Errorf("request %d: %w", index+1, err)
		}
	}
	return &template, nil
}

func validateCustomPoCRequest(request *CustomPoCRequest) error {
	request.Method = strings.ToUpper(strings.TrimSpace(request.Method))
	if request.Method == "" {
		request.Method = http.MethodGet
	}
	allowedMethods := map[string]bool{
		http.MethodGet: true, http.MethodHead: true, http.MethodPost: true, http.MethodPut: true,
		http.MethodPatch: true, http.MethodDelete: true, http.MethodOptions: true,
	}
	if !allowedMethods[request.Method] {
		return fmt.Errorf("unsupported HTTP method %q", request.Method)
	}
	request.Path = strings.TrimSpace(request.Path)
	if request.Path == "" {
		return errors.New("path is required")
	}
	if len(request.Headers) > maxCustomPoCHeaders {
		return fmt.Errorf("headers exceed %d entries", maxCustomPoCHeaders)
	}
	for key, value := range request.Headers {
		if !customHeaderNamePattern.MatchString(key) {
			return fmt.Errorf("invalid header name %q", key)
		}
		switch strings.ToLower(key) {
		case "host", "content-length", "transfer-encoding", "connection":
			return fmt.Errorf("header %q is managed by the HTTP client", key)
		}
		if len(value) > 8192 || strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("invalid header value for %q", key)
		}
	}
	if len(request.Body) > maxCustomPoCBodyBytes {
		return fmt.Errorf("request body exceeds %d bytes", maxCustomPoCBodyBytes)
	}
	if request.TimeoutSeconds < 0 || request.TimeoutSeconds > 30 {
		return errors.New("timeout_seconds must be between 0 and 30")
	}
	request.MatchersCondition = normalizeCustomCondition(request.MatchersCondition)
	if request.MatchersCondition == "" {
		return errors.New("matchers_condition must be and or or")
	}
	if len(request.Matchers) == 0 {
		return errors.New("at least one matcher is required")
	}
	for index := range request.Matchers {
		if err := validateCustomMatcher(&request.Matchers[index]); err != nil {
			return fmt.Errorf("matcher %d: %w", index+1, err)
		}
	}
	return nil
}

func validateCustomMatcher(matcher *CustomPoCMatcher) error {
	matcher.Type = strings.ToLower(strings.TrimSpace(matcher.Type))
	matcher.Part = strings.ToLower(strings.TrimSpace(matcher.Part))
	if matcher.Part == "" {
		matcher.Part = "body"
	}
	if matcher.Part != "body" && matcher.Part != "header" && matcher.Part != "all" {
		return errors.New("part must be body, header, or all")
	}
	matcher.Condition = normalizeCustomCondition(matcher.Condition)
	if matcher.Condition == "" {
		return errors.New("condition must be and or or")
	}
	switch matcher.Type {
	case "status":
		if len(matcher.Status) == 0 {
			return errors.New("status matcher requires status values")
		}
		for _, status := range matcher.Status {
			if status < 100 || status > 599 {
				return fmt.Errorf("invalid HTTP status %d", status)
			}
		}
	case "word":
		if len(matcher.Words) == 0 || len(matcher.Words) > maxCustomPoCWords {
			return fmt.Errorf("word matcher requires 1-%d words", maxCustomPoCWords)
		}
		for _, word := range matcher.Words {
			if word == "" || len(word) > 8192 {
				return errors.New("word matcher contains an invalid value")
			}
		}
	case "regex":
		if len(matcher.Regex) == 0 || len(matcher.Regex) > maxCustomPoCRegex {
			return fmt.Errorf("regex matcher requires 1-%d patterns", maxCustomPoCRegex)
		}
		for _, pattern := range matcher.Regex {
			if len(pattern) > 4096 {
				return errors.New("regex pattern exceeds 4096 characters")
			}
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf("invalid regex %q: %w", pattern, err)
			}
		}
	case "size":
		if matcher.MinSize < 0 || matcher.MaxSize < 0 || (matcher.MaxSize > 0 && matcher.MinSize > matcher.MaxSize) {
			return errors.New("invalid size matcher range")
		}
	default:
		return fmt.Errorf("unsupported matcher type %q", matcher.Type)
	}
	return nil
}

func normalizeCustomCondition(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "and"
	}
	if value == "and" || value == "or" {
		return value
	}
	return ""
}

func (e *PoCExecutor) executeCustomPoC(pocContent, target string) (*ExecuteResult, error) {
	template, err := parseCustomPoC(pocContent)
	if err != nil {
		return nil, err
	}
	baseURL, err := normalizeCustomTarget(target)
	if err != nil {
		return nil, err
	}
	client := *e.client
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("custom PoC redirect limit exceeded")
		}
		if !sameCustomOrigin(baseURL, request.URL) {
			return errors.New("custom PoC redirect left the target origin")
		}
		return nil
	}

	lastEvidence := "No request matched"
	for index, customRequest := range template.Requests {
		result, evidence, err := executeCustomPoCRequest(&client, baseURL, customRequest)
		if err != nil {
			return nil, fmt.Errorf("request %d: %w", index+1, err)
		}
		lastEvidence = evidence
		if result {
			return &ExecuteResult{Vulnerable: true, Message: "Custom PoC matched", Details: evidence}, nil
		}
	}
	return &ExecuteResult{Vulnerable: false, Message: "No vulnerability detected", Details: lastEvidence}, nil
}

func normalizeCustomTarget(target string) (*url.URL, error) {
	target = strings.TrimSpace(target)
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errors.New("target must be a valid HTTP or HTTPS URL")
	}
	if parsed.User != nil {
		return nil, errors.New("target URL credentials are not supported")
	}
	parsed.Fragment = ""
	return parsed, nil
}

func executeCustomPoCRequest(client *http.Client, baseURL *url.URL, customRequest CustomPoCRequest) (bool, string, error) {
	requestURL, err := resolveCustomRequestURL(baseURL, customRequest.Path)
	if err != nil {
		return false, "", err
	}
	requestBody := renderCustomPoCValue(customRequest.Body, baseURL)
	timeout := 30 * time.Second
	if customRequest.TimeoutSeconds > 0 {
		timeout = time.Duration(customRequest.TimeoutSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, customRequest.Method, requestURL.String(), strings.NewReader(requestBody))
	if err != nil {
		return false, "", err
	}
	for key, value := range customRequest.Headers {
		request.Header.Set(key, renderCustomPoCValue(value, baseURL))
	}
	if request.Header.Get("User-Agent") == "" {
		request.Header.Set("User-Agent", "Eclipse-Recon-PoC/1.0")
	}
	response, err := client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		return false, "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxCustomPoCResponseSize+1))
	if err != nil {
		return false, "", err
	}
	if len(body) > maxCustomPoCResponseSize {
		return false, "", fmt.Errorf("response exceeds %d bytes", maxCustomPoCResponseSize)
	}

	headerText := customPoCHeaderText(response.Header)
	matched, descriptions, err := evaluateCustomMatchers(customRequest.Matchers, customRequest.MatchersCondition, response.StatusCode, headerText, body)
	if err != nil {
		return false, "", err
	}
	evidence := fmt.Sprintf("Request: %s %s\nStatus: %d\nMatched: %s\nResponse: %s", customRequest.Method, requestURL.Redacted(), response.StatusCode, strings.Join(descriptions, ", "), customPoCEvidenceSnippet(body))
	return matched, evidence, nil
}

func resolveCustomRequestURL(baseURL *url.URL, rawPath string) (*url.URL, error) {
	rendered := renderCustomPoCValue(rawPath, baseURL)
	reference, err := url.Parse(rendered)
	if err != nil {
		return nil, fmt.Errorf("invalid request path: %w", err)
	}
	resolved := baseURL.ResolveReference(reference)
	if !sameCustomOrigin(baseURL, resolved) {
		return nil, errors.New("custom PoC request must remain on the target origin")
	}
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return nil, errors.New("custom PoC request must use HTTP or HTTPS")
	}
	return resolved, nil
}

func sameCustomOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Hostname(), right.Hostname()) && customURLPort(left) == customURLPort(right)
}

func customURLPort(value *url.URL) string {
	if port := value.Port(); port != "" {
		return port
	}
	if value.Scheme == "https" {
		return "443"
	}
	return "80"
}

func renderCustomPoCValue(value string, baseURL *url.URL) string {
	replacements := strings.NewReplacer(
		"{{BaseURL}}", strings.TrimRight(baseURL.String(), "/"),
		"{{Scheme}}", baseURL.Scheme,
		"{{Host}}", baseURL.Host,
		"{{Hostname}}", baseURL.Hostname(),
	)
	return replacements.Replace(value)
}

func evaluateCustomMatchers(matchers []CustomPoCMatcher, condition string, statusCode int, headers string, body []byte) (bool, []string, error) {
	results := make([]bool, 0, len(matchers))
	descriptions := make([]string, 0, len(matchers))
	for _, matcher := range matchers {
		matched, description, err := evaluateCustomMatcher(matcher, statusCode, headers, body)
		if err != nil {
			return false, nil, err
		}
		results = append(results, matched)
		if matched {
			descriptions = append(descriptions, description)
		}
	}
	if condition == "or" {
		for _, result := range results {
			if result {
				return true, descriptions, nil
			}
		}
		return false, descriptions, nil
	}
	for _, result := range results {
		if !result {
			return false, descriptions, nil
		}
	}
	return true, descriptions, nil
}

func evaluateCustomMatcher(matcher CustomPoCMatcher, statusCode int, headers string, body []byte) (bool, string, error) {
	content := string(body)
	if matcher.Part == "header" {
		content = headers
	} else if matcher.Part == "all" {
		content = headers + "\n" + content
	}
	matched := false
	description := matcher.Type
	switch matcher.Type {
	case "status":
		for _, status := range matcher.Status {
			if statusCode == status {
				matched = true
				break
			}
		}
		description = "status=" + strconv.Itoa(statusCode)
	case "word":
		candidate := content
		if matcher.CaseInsensitive {
			candidate = strings.ToLower(candidate)
		}
		wordResults := make([]bool, 0, len(matcher.Words))
		for _, word := range matcher.Words {
			if matcher.CaseInsensitive {
				word = strings.ToLower(word)
			}
			wordResults = append(wordResults, strings.Contains(candidate, word))
		}
		matched = combineCustomResults(wordResults, matcher.Condition)
		description = fmt.Sprintf("word(%s)", matcher.Part)
	case "regex":
		regexResults := make([]bool, 0, len(matcher.Regex))
		for _, pattern := range matcher.Regex {
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				return false, "", err
			}
			regexResults = append(regexResults, compiled.MatchString(content))
		}
		matched = combineCustomResults(regexResults, matcher.Condition)
		description = fmt.Sprintf("regex(%s)", matcher.Part)
	case "size":
		size := int64(len(body))
		matched = size >= matcher.MinSize && (matcher.MaxSize == 0 || size <= matcher.MaxSize)
		description = fmt.Sprintf("size=%d", size)
	}
	if matcher.Negative {
		matched = !matched
		description = "not " + description
	}
	return matched, description, nil
}

func combineCustomResults(results []bool, condition string) bool {
	if condition == "or" {
		for _, result := range results {
			if result {
				return true
			}
		}
		return false
	}
	for _, result := range results {
		if !result {
			return false
		}
	}
	return len(results) > 0
}

func customPoCHeaderText(headers http.Header) string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var builder strings.Builder
	for _, key := range keys {
		for _, value := range headers.Values(key) {
			builder.WriteString(key)
			builder.WriteString(": ")
			builder.WriteString(value)
			builder.WriteByte('\n')
		}
	}
	return builder.String()
}

func customPoCEvidenceSnippet(body []byte) string {
	if len(body) == 0 {
		return "<empty>"
	}
	if len(body) > maxCustomPoCEvidence {
		body = body[:maxCustomPoCEvidence]
	}
	text := strings.ToValidUTF8(string(body), "?")
	text = strings.ReplaceAll(text, "\x00", "")
	return strings.TrimSpace(text)
}
