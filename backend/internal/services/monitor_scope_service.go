package services

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"github.com/reconmaster/backend/internal/models"
	"gorm.io/gorm"
)

const (
	maxMonitorNameRunes   = 255
	maxMonitorTargetBytes = 4096
	maxMonitorInterval    = 366 * 24 * 60 * 60
)

type monitorInputError struct{ message string }

func (err monitorInputError) Error() string { return err.message }

func monitorInputErrorf(format string, values ...any) error {
	return monitorInputError{message: fmt.Sprintf(format, values...)}
}

func IsMonitorInputError(err error) bool {
	var inputError monitorInputError
	return errors.As(err, &inputError) || IsScanScopeInputError(err)
}

func MonitorInputErrorf(format string, values ...any) error {
	return monitorInputErrorf(format, values...)
}

func MonitorRequiresScanScope(monitorType models.MonitorType) bool {
	switch monitorType {
	case models.MonitorTypeDomain, models.MonitorTypeIP, models.MonitorTypeSite, models.MonitorTypeWIH:
		return true
	default:
		return false
	}
}

// SaveMonitor validates the monitor and its current targets while holding the
// same advisory lock used by scope changes and task creation.
func SaveMonitor(db *gorm.DB, monitor *models.Monitor) error {
	if db == nil {
		return errors.New("monitor database is unavailable")
	}
	if err := normalizeMonitorDefinition(monitor); err != nil {
		return err
	}
	tx := db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer tx.Rollback()
	if err := lockScanScopeChanges(tx); err != nil {
		return err
	}
	if _, err := authorizeMonitor(tx, monitor); err != nil {
		return err
	}
	if monitor.ID == "" {
		if err := tx.Create(monitor).Error; err != nil {
			return err
		}
	} else {
		result := tx.Model(&models.Monitor{}).Where("id = ?", monitor.ID).Updates(map[string]any{
			"name": monitor.Name, "type": monitor.Type, "target": monitor.Target,
			"status": monitor.Status, "interval": monitor.Interval, "options": monitor.Options,
			"notification_config": monitor.NotificationConfig, "asset_group_id": monitor.AssetGroupID,
			"scope_id": monitor.ScopeID,
		})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return monitorInputErrorf("monitor not found")
		}
	}
	return tx.Commit().Error
}

// AuthorizeMonitorExecution reloads group membership and reapplies the current
// authorization boundary immediately before a monitor performs network I/O.
func AuthorizeMonitorExecution(db *gorm.DB, monitor *models.Monitor) ([]string, error) {
	if err := normalizeMonitorDefinition(monitor); err != nil {
		return nil, err
	}
	return authorizeMonitor(db, monitor)
}

func authorizeMonitor(db *gorm.DB, monitor *models.Monitor) ([]string, error) {
	targets, err := LoadMonitorTargets(db, monitor.Type, monitor.Target, monitor.AssetGroupID)
	if err != nil {
		return nil, err
	}
	if !MonitorRequiresScanScope(monitor.Type) {
		if strings.TrimSpace(monitor.ScopeID) != "" {
			return nil, monitorInputErrorf("scan scopes apply only to domain, IP, site, and WIH monitors")
		}
		return targets, nil
	}
	validation, err := NewScanScopeService().validateWithDB(db, monitor.ScopeID, strings.Join(targets, "\n"))
	if err != nil {
		return nil, err
	}
	if err := ScanScopeBlockedError(validation); err != nil {
		return nil, err
	}
	monitor.ScopeID = validation.ScopeID
	if monitor.AssetGroupID == nil {
		monitor.Target = validation.NormalizedTarget
		targets = []string{monitor.Target}
	}
	return targets, nil
}

func normalizeMonitorDefinition(monitor *models.Monitor) error {
	if monitor == nil {
		return monitorInputErrorf("monitor is required")
	}
	monitor.Name = strings.TrimSpace(monitor.Name)
	monitor.Target = strings.TrimSpace(monitor.Target)
	monitor.ScopeID = strings.TrimSpace(monitor.ScopeID)
	if monitor.AssetGroupID != nil {
		groupID := strings.TrimSpace(*monitor.AssetGroupID)
		if groupID == "" {
			monitor.AssetGroupID = nil
		} else {
			monitor.AssetGroupID = &groupID
		}
	}
	if monitor.Name == "" || len([]rune(monitor.Name)) > maxMonitorNameRunes {
		return monitorInputErrorf("monitor name is required and must not exceed %d characters", maxMonitorNameRunes)
	}
	if len(monitor.Target) > maxMonitorTargetBytes {
		return monitorInputErrorf("monitor target is too large")
	}
	if monitor.Interval < 60 || monitor.Interval > maxMonitorInterval {
		return monitorInputErrorf("monitor interval must be between 60 seconds and 366 days")
	}
	switch monitor.Status {
	case models.MonitorStatusActive, models.MonitorStatusPaused, models.MonitorStatusStopped:
	default:
		return monitorInputErrorf("invalid monitor status")
	}
	switch monitor.Type {
	case models.MonitorTypeDomain, models.MonitorTypeIP, models.MonitorTypeSite, models.MonitorTypeGithub, models.MonitorTypeWIH, models.MonitorTypeCVE:
	default:
		return monitorInputErrorf("invalid monitor type")
	}
	if monitor.Target != "" && monitor.AssetGroupID != nil {
		return monitorInputErrorf("target and asset group are mutually exclusive")
	}
	if monitor.Target == "" && monitor.AssetGroupID == nil {
		return monitorInputErrorf("monitor target or asset group is required")
	}
	if monitor.AssetGroupID != nil {
		if monitor.Type != models.MonitorTypeDomain && monitor.Type != models.MonitorTypeIP && monitor.Type != models.MonitorTypeSite {
			return monitorInputErrorf("asset groups support domain, IP, or site monitors only")
		}
		return nil
	}
	normalized, err := normalizeMonitorTarget(monitor.Type, monitor.Target)
	if err != nil {
		return err
	}
	monitor.Target = normalized
	return nil
}

func normalizeMonitorTarget(monitorType models.MonitorType, target string) (string, error) {
	switch monitorType {
	case models.MonitorTypeDomain:
		domain, err := normalizeScopeDomain(target)
		if err != nil {
			return "", monitorInputErrorf("domain monitor target must be one valid domain")
		}
		return domain, nil
	case models.MonitorTypeIP:
		address, err := netip.ParseAddr(strings.Trim(target, "[]"))
		if err != nil {
			return "", monitorInputErrorf("IP monitor target must be one valid IP address")
		}
		return address.String(), nil
	case models.MonitorTypeSite, models.MonitorTypeWIH:
		parsed, err := url.Parse(target)
		if err != nil || parsed == nil {
			return "", monitorInputErrorf("site and WIH monitor targets must be HTTP or HTTPS URLs without credentials")
		}
		scheme := strings.ToLower(parsed.Scheme)
		if parsed.Hostname() == "" || (scheme != "http" && scheme != "https") || parsed.User != nil {
			return "", monitorInputErrorf("site and WIH monitor targets must be HTTP or HTTPS URLs without credentials")
		}
		normalized, err := parseScanTarget(target)
		if err != nil {
			return "", err
		}
		return normalized.canonical, nil
	case models.MonitorTypeGithub:
		if len(target) > 1024 || strings.IndexFunc(target, func(char rune) bool { return char == '\n' || char == '\r' || unicode.IsControl(char) }) >= 0 {
			return "", monitorInputErrorf("GitHub monitor query must be one line and at most 1024 bytes")
		}
		return target, nil
	case models.MonitorTypeCVE:
		parts := strings.Split(target, ",")
		if len(parts) > 20 {
			return "", monitorInputErrorf("CVE monitors support at most 20 product keywords")
		}
		cleaned := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" || len([]rune(part)) > 100 {
				return "", monitorInputErrorf("CVE product keywords must be non-empty and at most 100 characters")
			}
			cleaned = append(cleaned, part)
		}
		return strings.Join(cleaned, ", "), nil
	default:
		return "", monitorInputErrorf("invalid monitor type")
	}
}

func LoadMonitorTargets(db *gorm.DB, monitorType models.MonitorType, target string, groupID *string) ([]string, error) {
	if groupID == nil || strings.TrimSpace(*groupID) == "" {
		return []string{strings.TrimSpace(target)}, nil
	}
	if db == nil {
		return nil, errors.New("monitor database is unavailable")
	}
	var group models.AssetGroup
	if err := db.Select("id").First(&group, "id = ?", strings.TrimSpace(*groupID)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, monitorInputErrorf("asset group not found")
		}
		return nil, err
	}
	var items []models.AssetGroupItem
	if err := db.Where("group_id = ? AND (asset_type = ? OR asset_type = ?)", group.ID, string(monitorType), "canonical").Find(&items).Error; err != nil {
		return nil, err
	}
	legacyIDs := make([]string, 0, len(items))
	canonicalIDs := make([]string, 0, len(items))
	for _, item := range items {
		if item.AssetType == "canonical" {
			canonicalIDs = append(canonicalIDs, item.AssetID)
		} else {
			legacyIDs = append(legacyIDs, item.AssetID)
		}
	}
	values := make([]string, 0, len(items))
	if len(canonicalIDs) > 0 {
		var assets []models.AssetEntity
		if err := db.Select("display_value").Where("id IN ? AND kind = ?", canonicalIDs, string(monitorType)).Find(&assets).Error; err != nil {
			return nil, err
		}
		for _, asset := range assets {
			values = append(values, asset.DisplayValue)
		}
	}
	if len(legacyIDs) > 0 {
		switch monitorType {
		case models.MonitorTypeDomain:
			var assets []models.Domain
			if err := db.Select("domain").Where("id IN ?", legacyIDs).Find(&assets).Error; err != nil {
				return nil, err
			}
			for _, asset := range assets {
				values = append(values, asset.Domain)
			}
		case models.MonitorTypeIP:
			var assets []models.IP
			if err := db.Select("ip_address").Where("id IN ?", legacyIDs).Find(&assets).Error; err != nil {
				return nil, err
			}
			for _, asset := range assets {
				values = append(values, asset.IPAddress)
			}
		case models.MonitorTypeSite:
			var assets []models.Site
			if err := db.Select("url").Where("id IN ?", legacyIDs).Find(&assets).Error; err != nil {
				return nil, err
			}
			for _, asset := range assets {
				values = append(values, asset.URL)
			}
		default:
			return nil, monitorInputErrorf("asset group is not supported for this monitor type")
		}
	}
	seen := make(map[string]struct{}, len(values))
	targets := make([]string, 0, len(values))
	for _, value := range values {
		value, err := normalizeMonitorTarget(monitorType, strings.TrimSpace(value))
		if err != nil {
			continue
		}
		if _, exists := seen[value]; !exists {
			seen[value] = struct{}{}
			targets = append(targets, value)
		}
	}
	if len(targets) == 0 {
		return nil, monitorInputErrorf("asset group has no valid %s assets", monitorType)
	}
	sort.Strings(targets)
	return targets, nil
}
