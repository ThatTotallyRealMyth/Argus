package services

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"golang.org/x/net/idna"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	maxScanScopeRules   = 500
	maxScanScopeTargets = 2000
	maxScanTargetBytes  = 64 << 10
	scanScopeLockName   = "scan-scope-default"
)

type scanScopeInputError struct{ message string }

func (err scanScopeInputError) Error() string { return err.message }

func scanScopeInputErrorf(format string, values ...any) error {
	return scanScopeInputError{message: fmt.Sprintf(format, values...)}
}

func IsScanScopeInputError(err error) bool {
	var inputError scanScopeInputError
	return errors.As(err, &inputError)
}

type ScanScopeTargetDecision struct {
	Input       string `json:"input"`
	Normalized  string `json:"normalized,omitempty"`
	Allowed     bool   `json:"allowed"`
	MatchedRule string `json:"matched_rule,omitempty"`
	Reason      string `json:"reason"`
}

type ScanScopeValidation struct {
	ScopeID          string                    `json:"scope_id,omitempty"`
	ScopeName        string                    `json:"scope_name,omitempty"`
	Enforced         bool                      `json:"enforced"`
	Allowed          bool                      `json:"allowed"`
	NormalizedTarget string                    `json:"normalized_target"`
	Targets          []ScanScopeTargetDecision `json:"targets"`
}

type scanScopeRule struct {
	raw      string
	wildcard string
	domain   string
	address  netip.Addr
	prefix   netip.Prefix
	kind     string
}

type scanTarget struct {
	input     string
	canonical string
	domain    string
	address   netip.Addr
	prefix    netip.Prefix
	kind      string
}

type ScanScopeService struct{}

func NewScanScopeService() *ScanScopeService { return &ScanScopeService{} }

func (s *ScanScopeService) Validate(scopeID, target string) (*ScanScopeValidation, error) {
	return s.validateWithDB(databaseDB(), scopeID, target)
}

// BuildValidator snapshots the resolved authorization boundary for one task.
// This avoids a database query for every port or crawler request while keeping
// all outbound scanner modules on the same normalized rule set.
func (s *ScanScopeService) BuildValidator(scopeID string) (func(string) error, error) {
	scope, err := resolveScanScope(databaseDB(), strings.TrimSpace(scopeID))
	if err != nil {
		return nil, err
	}
	if scope == nil {
		return nil, nil
	}
	return buildScanScopeValidator(*scope), nil
}

func buildScanScopeValidator(scope models.ScanScope) func(string) error {
	return func(target string) error {
		validation, validateErr := ValidateScanScopePreview(scope, target)
		if validateErr != nil {
			return validateErr
		}
		return ScanScopeBlockedError(validation)
	}
}

func (s *ScanScopeService) validateWithDB(db *gorm.DB, scopeID, target string) (*ScanScopeValidation, error) {
	if db == nil {
		return nil, errors.New("scan scope database is unavailable")
	}
	if len(target) > maxScanTargetBytes {
		return nil, scanScopeInputErrorf("scan target is too large")
	}
	targets, err := parseScanTargets(target)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, scanScopeInputErrorf("task target is required")
	}
	if len(targets) > maxScanScopeTargets {
		return nil, scanScopeInputErrorf("at most %d targets can be scanned at once", maxScanScopeTargets)
	}
	scope, err := resolveScanScope(db, scopeID)
	if err != nil {
		return nil, err
	}
	if scope == nil {
		decisions := make([]ScanScopeTargetDecision, 0, len(targets))
		for _, target := range targets {
			decisions = append(decisions, ScanScopeTargetDecision{Input: target.input, Normalized: target.canonical, Allowed: true, Reason: "No default range configured, Release in compatible mode"})
		}
		return &ScanScopeValidation{Allowed: true, Enforced: false, NormalizedTarget: joinScanTargets(targets), Targets: decisions}, nil
	}
	return validateParsedTargets(*scope, targets)
}

func ValidateScanScopePreview(scope models.ScanScope, target string) (*ScanScopeValidation, error) {
	allowRules, denyRules, err := NormalizeScanScopeRules(scope.AllowRules, scope.DenyRules)
	if err != nil {
		return nil, err
	}
	scope.AllowRules, scope.DenyRules = allowRules, denyRules
	targets, err := parseScanTargets(target)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, scanScopeInputErrorf("enter at least one target to validate")
	}
	return validateParsedTargets(scope, targets)
}

func NormalizeScanScopeRules(allowRules, denyRules []string) ([]string, []string, error) {
	if len(allowRules) == 0 {
		return nil, nil, scanScopeInputErrorf("at least one allow rule is required")
	}
	if len(allowRules) > maxScanScopeRules || len(denyRules) > maxScanScopeRules {
		return nil, nil, scanScopeInputErrorf("allow and deny lists support at most %d rules each", maxScanScopeRules)
	}
	normalize := func(values []string) ([]string, error) {
		seen := make(map[string]bool, len(values))
		result := make([]string, 0, len(values))
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			rule, err := parseScanScopeRule(value)
			if err != nil {
				return nil, err
			}
			canonical := rule.raw
			if !seen[canonical] {
				seen[canonical] = true
				result = append(result, canonical)
			}
		}
		return result, nil
	}
	allow, err := normalize(allowRules)
	if err != nil {
		return nil, nil, err
	}
	if len(allow) == 0 {
		return nil, nil, scanScopeInputErrorf("at least one allow rule is required")
	}
	deny, err := normalize(denyRules)
	if err != nil {
		return nil, nil, err
	}
	return allow, deny, nil
}

func resolveScanScope(db *gorm.DB, scopeID string) (*models.ScanScope, error) {
	scopeID = strings.TrimSpace(scopeID)
	var scope models.ScanScope
	if scopeID != "" {
		if _, err := uuid.Parse(scopeID); err != nil {
			return nil, scanScopeInputErrorf("invalid scan scope ID")
		}
		result := db.Limit(1).Find(&scope, "id = ?", scopeID)
		if result.Error != nil {
			return nil, result.Error
		}
		if result.RowsAffected == 0 {
			return nil, scanScopeInputErrorf("scan scope not found")
		}
		return &scope, nil
	}
	result := db.Where("is_default = ?", true).Order("updated_at DESC").Limit(1).Find(&scope)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, nil
	}
	return &scope, nil
}

var databaseDB = func() *gorm.DB {
	return database.DB
}

func lockScanScopeChanges(db *gorm.DB) error {
	return db.Exec("SELECT pg_advisory_xact_lock(hashtext(?))", scanScopeLockName).Error
}

func validateParsedTargets(scope models.ScanScope, targets []scanTarget) (*ScanScopeValidation, error) {
	allowRules, denyRules, err := compileScanScopeRules(scope.AllowRules, scope.DenyRules)
	if err != nil {
		return nil, err
	}
	result := &ScanScopeValidation{ScopeID: scope.ID, ScopeName: scope.Name, Enforced: true, Allowed: true, NormalizedTarget: joinScanTargets(targets), Targets: make([]ScanScopeTargetDecision, 0, len(targets))}
	for _, target := range targets {
		decision := ScanScopeTargetDecision{Input: target.input, Normalized: target.canonical}
		if rule := firstMatchingRule(denyRules, target); rule != nil {
			decision.Allowed = false
			decision.MatchedRule = rule.raw
			decision.Reason = "The Ejection Rule"
			result.Allowed = false
		} else if rule := firstMatchingRule(allowRules, target); rule != nil {
			decision.Allowed = true
			decision.MatchedRule = rule.raw
			decision.Reason = "The rules allowed by the hit."
		} else {
			decision.Allowed = false
			decision.Reason = "Not within the scope of the mandate."
			result.Allowed = false
		}
		result.Targets = append(result.Targets, decision)
	}
	return result, nil
}

func compileScanScopeRules(allowValues, denyValues []string) ([]scanScopeRule, []scanScopeRule, error) {
	allow, deny, err := NormalizeScanScopeRules(allowValues, denyValues)
	if err != nil {
		return nil, nil, err
	}
	parse := func(values []string) ([]scanScopeRule, error) {
		rules := make([]scanScopeRule, 0, len(values))
		for _, value := range values {
			rule, err := parseScanScopeRule(value)
			if err != nil {
				return nil, err
			}
			rules = append(rules, rule)
		}
		return rules, nil
	}
	allowRules, err := parse(allow)
	if err != nil {
		return nil, nil, err
	}
	denyRules, err := parse(deny)
	return allowRules, denyRules, err
}

func parseScanScopeRule(raw string) (scanScopeRule, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) > 512 {
		return scanScopeRule{}, scanScopeInputErrorf("scope rule is too long")
	}
	if strings.HasPrefix(raw, "*.") {
		domain, err := normalizeScopeDomain(strings.TrimPrefix(raw, "*."))
		if err != nil {
			return scanScopeRule{}, scanScopeInputErrorf("invalid wildcard scope rule %q", raw)
		}
		return scanScopeRule{raw: "*." + domain, wildcard: domain, kind: "wildcard"}, nil
	}
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Hostname() == "" || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
			return scanScopeRule{}, scanScopeInputErrorf("URL scope rules must describe a host boundary without a path, query, or fragment")
		}
	}
	target, err := parseScanTarget(raw)
	if err != nil {
		return scanScopeRule{}, scanScopeInputErrorf("invalid scope rule %q: %v", raw, err)
	}
	switch target.kind {
	case "domain":
		return scanScopeRule{raw: target.domain, domain: target.domain, kind: "domain"}, nil
	case "ip":
		return scanScopeRule{raw: target.address.String(), address: target.address, kind: "ip"}, nil
	case "cidr":
		return scanScopeRule{raw: target.prefix.String(), prefix: target.prefix, kind: "cidr"}, nil
	default:
		return scanScopeRule{}, scanScopeInputErrorf("unsupported scope rule %q", raw)
	}
}

func parseScanTargets(raw string) ([]scanTarget, error) {
	values := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
	seen := make(map[string]bool, len(values))
	targets := make([]scanTarget, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		target, err := parseScanTarget(value)
		if err != nil {
			return nil, scanScopeInputErrorf("invalid scan target %q: %v", value, err)
		}
		if !seen[target.canonical] {
			seen[target.canonical] = true
			targets = append(targets, target)
		}
	}
	return targets, nil
}

func parseScanTarget(raw string) (scanTarget, error) {
	value := strings.TrimSpace(raw)
	if value == "" || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return scanTarget{}, errors.New("target is empty or contains whitespace")
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		prefix = prefix.Masked()
		return scanTarget{input: raw, canonical: prefix.String(), prefix: prefix, kind: "cidr"}, nil
	}
	if address, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil {
		return scanTarget{input: raw, canonical: address.String(), address: address, kind: "ip"}, nil
	}
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Hostname() == "" {
			return scanTarget{}, errors.New("invalid URL")
		}
		if parsed.User != nil {
			return scanTarget{}, errors.New("URL credentials are not supported")
		}
		parsed.Scheme = strings.ToLower(parsed.Scheme)
		parsed.Fragment = ""
		host := parsed.Hostname()
		port := parsed.Port()
		if address, addressErr := netip.ParseAddr(strings.Trim(host, "[]")); addressErr == nil {
			parsed.Host = address.String()
			if port != "" {
				parsed.Host = net.JoinHostPort(address.String(), port)
			}
			return scanTarget{input: raw, canonical: parsed.String(), address: address, kind: "ip"}, nil
		}
		domain, domainErr := normalizeScopeDomain(host)
		if domainErr != nil {
			return scanTarget{}, domainErr
		}
		parsed.Host = domain
		if port != "" {
			parsed.Host = net.JoinHostPort(domain, port)
		}
		return scanTarget{input: raw, canonical: parsed.String(), domain: domain, kind: "domain"}, nil
	}
	host := value
	port := ""
	if parsedHost, parsedPort, err := net.SplitHostPort(value); err == nil {
		host, port = parsedHost, parsedPort
	} else if strings.Count(value, ":") == 1 {
		parts := strings.SplitN(value, ":", 2)
		if portNumber, portErr := strconv.Atoi(parts[1]); portErr == nil && portNumber >= 1 && portNumber <= 65535 {
			host = parts[0]
			port = parts[1]
		}
	}
	if address, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		canonical := address.String()
		if port != "" {
			canonical = net.JoinHostPort(address.String(), port)
		}
		return scanTarget{input: raw, canonical: canonical, address: address, kind: "ip"}, nil
	}
	domain, err := normalizeScopeDomain(host)
	if err != nil {
		return scanTarget{}, err
	}
	canonical := domain
	if port != "" {
		canonical = net.JoinHostPort(domain, port)
	}
	return scanTarget{input: raw, canonical: canonical, domain: domain, kind: "domain"}, nil
}

func normalizeScopeDomain(value string) (string, error) {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil || ascii == "" || len(ascii) > 253 {
		return "", errors.New("invalid domain")
	}
	labels := strings.Split(ascii, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid domain")
		}
		for _, char := range label {
			if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-') {
				return "", errors.New("invalid domain")
			}
		}
	}
	return ascii, nil
}

func firstMatchingRule(rules []scanScopeRule, target scanTarget) *scanScopeRule {
	for index := range rules {
		if scanScopeRuleMatches(rules[index], target) {
			return &rules[index]
		}
	}
	return nil
}

func scanScopeRuleMatches(rule scanScopeRule, target scanTarget) bool {
	switch rule.kind {
	case "domain":
		return target.kind == "domain" && target.domain == rule.domain
	case "wildcard":
		return target.kind == "domain" && target.domain != rule.wildcard && strings.HasSuffix(target.domain, "."+rule.wildcard)
	case "ip":
		return target.kind == "ip" && target.address == rule.address
	case "cidr":
		if target.kind == "ip" {
			return rule.prefix.Contains(target.address)
		}
		return target.kind == "cidr" && rule.prefix.Addr().BitLen() == target.prefix.Addr().BitLen() && rule.prefix.Bits() <= target.prefix.Bits() && rule.prefix.Contains(target.prefix.Addr())
	default:
		return false
	}
}

func joinScanTargets(targets []scanTarget) string {
	values := make([]string, 0, len(targets))
	for _, target := range targets {
		values = append(values, target.canonical)
	}
	return strings.Join(values, ",")
}

func ScanScopeBlockedError(validation *ScanScopeValidation) error {
	if validation == nil || validation.Allowed {
		return nil
	}
	blocked := make([]string, 0)
	for _, decision := range validation.Targets {
		if !decision.Allowed {
			blocked = append(blocked, decision.Input)
		}
	}
	sort.Strings(blocked)
	if len(blocked) > 5 {
		blocked = append(blocked[:5], fmt.Sprintf("and %d more", len(blocked)-5))
	}
	return scanScopeInputErrorf("targets are outside authorization scope %q: %s", validation.ScopeName, strings.Join(blocked, ", "))
}

func SaveScanScope(db *gorm.DB, scope *models.ScanScope) error {
	if db == nil {
		return errors.New("scan scope database is unavailable")
	}
	scope.Name = strings.TrimSpace(scope.Name)
	scope.Description = strings.TrimSpace(scope.Description)
	if scope.Name == "" || len([]rune(scope.Name)) > 255 {
		return scanScopeInputErrorf("scan scope name is required and must not exceed 255 characters")
	}
	if len([]rune(scope.Description)) > 2000 {
		return scanScopeInputErrorf("scan scope description is too long")
	}
	allow, deny, err := NormalizeScanScopeRules(scope.AllowRules, scope.DenyRules)
	if err != nil {
		return err
	}
	scope.AllowRules, scope.DenyRules = allow, deny
	tx := db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer tx.Rollback()
	if err := lockScanScopeChanges(tx); err != nil {
		return err
	}
	if scope.IsDefault {
		query := tx.Model(&models.ScanScope{}).Where("is_default = ?", true)
		if scope.ID != "" {
			if _, err := uuid.Parse(scope.ID); err != nil {
				return scanScopeInputErrorf("invalid scan scope ID")
			}
			query = query.Where("id <> ?", scope.ID)
		}
		if err := query.Update("is_default", false).Error; err != nil {
			return err
		}
	}
	if scope.ID == "" {
		if err := tx.Create(scope).Error; err != nil {
			return err
		}
	} else {
		if _, err := uuid.Parse(scope.ID); err != nil {
			return scanScopeInputErrorf("invalid scan scope ID")
		}
		var current models.ScanScope
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id", "is_default").First(&current, "id = ?", scope.ID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return scanScopeInputErrorf("scan scope not found")
			}
			return err
		}
		if current.IsDefault && !scope.IsDefault {
			return scanScopeInputErrorf("default scan scope cannot be unset; set another scope as default first")
		}
		result := tx.Model(&models.ScanScope{}).Where("id = ?", scope.ID).
			Select("name", "description", "allow_rules", "deny_rules", "is_default").Updates(scope)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return scanScopeInputErrorf("scan scope not found")
		}
	}
	return tx.Commit().Error
}

func SetDefaultScanScope(db *gorm.DB, id string) error {
	if _, err := uuid.Parse(strings.TrimSpace(id)); err != nil {
		return scanScopeInputErrorf("invalid scan scope ID")
	}
	tx := db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer tx.Rollback()
	if err := lockScanScopeChanges(tx); err != nil {
		return err
	}
	var scope models.ScanScope
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&scope, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return scanScopeInputErrorf("scan scope not found")
		}
		return err
	}
	if err := tx.Model(&models.ScanScope{}).Where("is_default = ?", true).Update("is_default", false).Error; err != nil {
		return err
	}
	if err := tx.Model(&scope).Update("is_default", true).Error; err != nil {
		return err
	}
	return tx.Commit().Error
}

func DeleteScanScope(db *gorm.DB, id string) error {
	if _, err := uuid.Parse(strings.TrimSpace(id)); err != nil {
		return scanScopeInputErrorf("invalid scan scope ID")
	}
	tx := db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer tx.Rollback()
	if err := lockScanScopeChanges(tx); err != nil {
		return err
	}
	var scope models.ScanScope
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&scope, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return scanScopeInputErrorf("scan scope not found")
		}
		return err
	}
	if scope.IsDefault {
		return scanScopeInputErrorf("default scan scope cannot be deleted")
	}
	var taskCount, scheduledCount, monitorCount int64
	if err := tx.Model(&models.Task{}).Where("scope_id = ?", id).Count(&taskCount).Error; err != nil {
		return err
	}
	if err := tx.Model(&models.ScheduledTask{}).Where("scope_id = ?", id).Count(&scheduledCount).Error; err != nil {
		return err
	}
	if err := tx.Model(&models.Monitor{}).Where("scope_id = ?", id).Count(&monitorCount).Error; err != nil {
		return err
	}
	if taskCount+scheduledCount+monitorCount > 0 {
		return scanScopeInputErrorf("scan scope is referenced by %d task or monitor records", taskCount+scheduledCount+monitorCount)
	}
	if err := tx.Delete(&scope).Error; err != nil {
		return err
	}
	return tx.Commit().Error
}
