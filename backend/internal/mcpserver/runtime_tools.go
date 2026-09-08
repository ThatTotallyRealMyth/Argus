package mcpserver

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/proxypool"
	"github.com/reconmaster/backend/internal/scanner"
	"github.com/reconmaster/backend/internal/services"
	"gorm.io/gorm"
)

const (
	maxMCPDictionaryContentBytes = 700 << 10
	dictionaryRootDirectory      = "./configs/dicts"
)

type DictionaryManagementInput struct {
	Action      string `json:"action" jsonschema:"required,Operation: list, upload, set_default, delete"`
	ID          string `json:"id,omitempty" jsonschema:"Dictionary ID; set_default and delete Required"`
	Type        string `json:"type,omitempty" jsonschema:"Dictionary Type: domain, port, file, file_leak"`
	Name        string `json:"name,omitempty" jsonschema:"Dictionary Name; upload Required"`
	Description string `json:"description,omitempty" jsonschema:"Dictionary Notes"`
	Content     string `json:"content,omitempty" jsonschema:"UTF-8 Text dictionary contents, Max 700 KiB; upload Required"`
	Confirm     bool   `json:"confirm,omitempty" jsonschema:"upload, set_default and delete It must be clearly defined. true"`
}

type ScannerSettingsInput struct {
	Action   string            `json:"action" jsonschema:"required,Operation: get, update"`
	Settings map[string]string `json:"settings,omitempty" jsonschema:"Scan for parameter key values; update Required, Values use string"`
	Confirm  bool              `json:"confirm,omitempty" jsonschema:"update It must be clearly defined. true"`
}

type ScanScopeManagementInput struct {
	Action      string   `json:"action" jsonschema:"required,Operation: create, update, set_default, delete"`
	ID          string   `json:"id,omitempty" jsonschema:"update, set_default and delete Mandated scope ID"`
	Name        *string  `json:"name,omitempty" jsonschema:"Name of authorized range; create Required, update Optional"`
	Description *string  `json:"description,omitempty" jsonschema:"Annotations; update Empty string to clear"`
	AllowRules  []string `json:"allow_rules,omitempty" jsonschema:"Allow Rules, Support domain names, General Sub Fields, IP, CIDR; update Reservation upon omission"`
	DenyRules   []string `json:"deny_rules,omitempty" jsonschema:"Exclusion rules and precedence over permissible rules; update Reservation upon omission"`
	IsDefault   *bool    `json:"is_default,omitempty" jsonschema:"Whether to use as default range; update Reservation upon omission"`
	Confirm     bool     `json:"confirm" jsonschema:"required,The change of authority will change the scanable boundary., It must be clearly defined. true"`
}

type ProxySpec struct {
	Name     *string `json:"name,omitempty" jsonschema:"Agent Name"`
	Scheme   *string `json:"scheme,omitempty" jsonschema:"Agreement: http, https, socks5"`
	Host     *string `json:"host,omitempty" jsonschema:"Agent Host Name or IP"`
	Port     *int    `json:"port,omitempty" jsonschema:"Proxy Port 1-65535"`
	Username *string `json:"username,omitempty" jsonschema:"Optional username; Empty string to clear"`
	Password *string `json:"password,omitempty" jsonschema:"Optional password; Write only, Never come back"`
	Enabled  *bool   `json:"enabled,omitempty" jsonschema:"Whether to enable"`
}

type ProxyPoolManagementInput struct {
	Action   string      `json:"action" jsonschema:"required,Operation: list, create, batch_create, update, toggle, delete, test, test_all"`
	ID       string      `json:"id,omitempty" jsonschema:"Single Agent ID"`
	IDs      []string    `json:"ids,omitempty" jsonschema:"Bulk delete or test Agent ID, Up to1000One."`
	Proxy    ProxySpec   `json:"proxy,omitempty" jsonschema:"create or update proxy fields"`
	Proxies  []ProxySpec `json:"proxies,omitempty" jsonschema:"batch_create proxy arrays, Up to100One."`
	Status   string      `json:"status,omitempty" jsonschema:"list Status Filter: unknown, healthy, dead"`
	Enabled  *bool       `json:"enabled,omitempty" jsonschema:"list Enable status filter, or toggle Target status"`
	Page     int         `json:"page,omitempty" jsonschema:"list Page Number, Default1"`
	PageSize int         `json:"page_size,omitempty" jsonschema:"list Number of pages per page, Default20, Max100"`
	Confirm  bool        `json:"confirm,omitempty" jsonschema:"Divide list All operations outside must be clearly identified as true"`
}

func RegisterRuntimeTools(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "manage_scan_scope",
		Description: "Create, Update, Set as default or delete authorized scan range.The range changes will change all scans., Network boundaries for surveillance and planning missions, Yes. confirm=true; Call before saving validate_scan_scope Sending provisional rule pre-screening.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ScanScopeManagementInput) (*mcp.CallToolResult, any, error) {
		result, err := manageScanScope(input)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(result)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "manage_dictionary",
		Description: "Read, Upload, Set as Default or Remove Scan Dictionary.Write must confirm=true; MCP Maximum Upload 700 KiB.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input DictionaryManagementInput) (*mcp.CallToolResult, any, error) {
		result, err := manageDictionary(input)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(result)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "manage_scanner_settings",
		Description: "Read Scanner Parameters Definition, Current value and entry source, or update by white list batch.Update must confirm=true, And only affect the start-up mission..",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(false), IdempotentHint: true, OpenWorldHint: boolPtr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ScannerSettingsInput) (*mcp.CallToolResult, any, error) {
		result, err := manageScannerSettings(input)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(result)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "manage_proxy_pool",
		Description: "Read, Create, Batch Creation, Update, Stop, Remove or detect proxy nodes.Password never returns; Divide list It's a must. confirm=true, Check-out external authentication services.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(true)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ProxyPoolManagementInput) (*mcp.CallToolResult, any, error) {
		result, err := manageProxyPool(input)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(result)
	})
}

func manageScanScope(input ScanScopeManagementInput) (map[string]any, error) {
	action := strings.ToLower(strings.TrimSpace(input.Action))
	if !input.Confirm {
		return nil, fmt.Errorf("%s requires confirm=true", action)
	}
	switch action {
	case "create":
		if input.Name == nil {
			return nil, fmt.Errorf("scan scope name is required")
		}
		var count int64
		if err := database.DB.Model(&models.ScanScope{}).Count(&count).Error; err != nil {
			return nil, fmt.Errorf("count scan scopes failed")
		}
		scope := &models.ScanScope{
			Name: strings.TrimSpace(*input.Name), AllowRules: input.AllowRules, DenyRules: input.DenyRules,
			IsDefault: count == 0 || (input.IsDefault != nil && *input.IsDefault), CreatedBy: "mcp",
		}
		if input.Description != nil {
			scope.Description = *input.Description
		}
		if err := services.SaveScanScope(database.DB, scope); err != nil {
			return nil, err
		}
		return map[string]any{"action": action, "scope": scope}, nil
	case "update":
		id := strings.TrimSpace(input.ID)
		if id == "" {
			return nil, fmt.Errorf("scan scope id is required")
		}
		var scope models.ScanScope
		if err := database.DB.First(&scope, "id = ?", id).Error; err != nil {
			return nil, fmt.Errorf("scan scope not found")
		}
		if input.Name != nil {
			scope.Name = strings.TrimSpace(*input.Name)
		}
		if input.Description != nil {
			scope.Description = *input.Description
		}
		if input.AllowRules != nil {
			scope.AllowRules = input.AllowRules
		}
		if input.DenyRules != nil {
			scope.DenyRules = input.DenyRules
		}
		if input.IsDefault != nil {
			scope.IsDefault = *input.IsDefault
		}
		if err := services.SaveScanScope(database.DB, &scope); err != nil {
			return nil, err
		}
		if err := database.DB.First(&scope, "id = ?", id).Error; err != nil {
			return nil, fmt.Errorf("reload scan scope failed")
		}
		return map[string]any{"action": action, "scope": scope}, nil
	case "set_default":
		id := strings.TrimSpace(input.ID)
		if err := services.SetDefaultScanScope(database.DB, id); err != nil {
			return nil, err
		}
		var scope models.ScanScope
		if err := database.DB.First(&scope, "id = ?", id).Error; err != nil {
			return nil, fmt.Errorf("reload scan scope failed")
		}
		return map[string]any{"action": action, "scope": scope}, nil
	case "delete":
		id := strings.TrimSpace(input.ID)
		if err := services.DeleteScanScope(database.DB, id); err != nil {
			return nil, err
		}
		return map[string]any{"action": action, "id": id, "deleted": true}, nil
	default:
		return nil, fmt.Errorf("unsupported scan scope action: %s", input.Action)
	}
}

func manageDictionary(input DictionaryManagementInput) (map[string]any, error) {
	action := strings.ToLower(strings.TrimSpace(input.Action))
	if action != "list" && !input.Confirm {
		return nil, fmt.Errorf("%s requires confirm=true", action)
	}
	switch action {
	case "list":
		if input.Type != "" && !validDictionaryType(input.Type) {
			return nil, fmt.Errorf("unsupported dictionary type: %s", input.Type)
		}
		var dictionaries []models.Dictionary
		query := database.DB.Order("is_default DESC, created_at DESC").Limit(200)
		if input.Type != "" {
			query = query.Where("type = ?", input.Type)
		}
		if err := query.Find(&dictionaries).Error; err != nil {
			return nil, fmt.Errorf("list dictionaries failed")
		}
		return map[string]any{"action": action, "dictionaries": dictionaries, "total": len(dictionaries)}, nil
	case "upload":
		dictionary, err := uploadMCPDictionary(input)
		if err != nil {
			return nil, err
		}
		return map[string]any{"action": action, "dictionary": dictionary}, nil
	case "set_default":
		dictionary, err := setDefaultDictionary(strings.TrimSpace(input.ID))
		if err != nil {
			return nil, err
		}
		return map[string]any{"action": action, "dictionary": dictionary}, nil
	case "delete":
		id := strings.TrimSpace(input.ID)
		if id == "" {
			return nil, fmt.Errorf("dictionary id is required")
		}
		var dictionary models.Dictionary
		if err := database.DB.First(&dictionary, "id = ?", id).Error; err != nil {
			return nil, fmt.Errorf("dictionary not found")
		}
		if dictionary.IsDefault {
			return nil, fmt.Errorf("cannot delete the default dictionary")
		}
		if err := database.DB.Delete(&dictionary).Error; err != nil {
			return nil, fmt.Errorf("delete dictionary failed")
		}
		if dictionaryPathWithinRoot(dictionary.FilePath) {
			_ = os.Remove(dictionary.FilePath)
		}
		return map[string]any{"action": action, "id": id, "deleted": true}, nil
	default:
		return nil, fmt.Errorf("unsupported dictionary action: %s", input.Action)
	}
}

func uploadMCPDictionary(input DictionaryManagementInput) (*models.Dictionary, error) {
	name := strings.TrimSpace(input.Name)
	dictionaryType := strings.TrimSpace(input.Type)
	if name == "" || len(name) > 100 {
		return nil, fmt.Errorf("dictionary name must be between 1 and 100 characters")
	}
	if !validDictionaryType(dictionaryType) {
		return nil, fmt.Errorf("unsupported dictionary type: %s", dictionaryType)
	}
	content := []byte(input.Content)
	if len(content) == 0 || len(content) > maxMCPDictionaryContentBytes {
		return nil, fmt.Errorf("dictionary content must be between 1 byte and 700 KiB")
	}
	lineCount, err := validateDictionaryContent(dictionaryType, input.Content)
	if err != nil {
		return nil, err
	}
	directory := filepath.Join(dictionaryRootDirectory, dictionaryType)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return nil, fmt.Errorf("create dictionary directory failed")
	}
	file, err := os.CreateTemp(directory, "mcp-*.dict")
	if err != nil {
		return nil, fmt.Errorf("create dictionary file failed")
	}
	path := file.Name()
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return nil, fmt.Errorf("write dictionary file failed")
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close dictionary file failed")
	}
	dictionary := &models.Dictionary{
		Name: name, Type: dictionaryType, FilePath: path, Size: int64(len(content)),
		LineCount: lineCount, Description: strings.TrimSpace(input.Description), CreatedBy: "mcp",
	}
	if err := database.DB.Create(dictionary).Error; err != nil {
		return nil, fmt.Errorf("create dictionary record failed")
	}
	keep = true
	return dictionary, nil
}

func validateDictionaryContent(dictionaryType, content string) (int, error) {
	if dictionaryType == "file_leak" {
		count, err := scanner.ValidateFileLeakDictionary(strings.NewReader(content))
		if err != nil {
			return 0, fmt.Errorf("invalid file leak dictionary: %w", err)
		}
		return count, nil
	}
	reader := bufio.NewScanner(strings.NewReader(content))
	reader.Buffer(make([]byte, 64*1024), 1024*1024)
	count := 0
	for reader.Scan() {
		value := strings.TrimSpace(reader.Text())
		if value != "" && !strings.HasPrefix(value, "#") {
			count++
		}
	}
	if err := reader.Err(); err != nil {
		return 0, fmt.Errorf("read dictionary content failed: %w", err)
	}
	if count == 0 {
		return 0, fmt.Errorf("dictionary content has no usable entries")
	}
	return count, nil
}

func validDictionaryType(value string) bool {
	switch value {
	case "domain", "port", "file", "file_leak":
		return true
	default:
		return false
	}
}

func setDefaultDictionary(id string) (*models.Dictionary, error) {
	if id == "" {
		return nil, fmt.Errorf("dictionary id is required")
	}
	var dictionary models.Dictionary
	if err := database.DB.First(&dictionary, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("dictionary not found")
	}
	if err := database.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&models.Dictionary{}).Where("type = ? AND is_default = ?", dictionary.Type, true).Update("is_default", false).Error; err != nil {
			return err
		}
		return tx.Model(&dictionary).Update("is_default", true).Error
	}); err != nil {
		return nil, fmt.Errorf("set default dictionary failed")
	}
	dictionary.IsDefault = true
	return &dictionary, nil
}

func dictionaryPathWithinRoot(path string) bool {
	root, err := filepath.Abs(dictionaryRootDirectory)
	if err != nil {
		return false
	}
	value, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(root, value)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}

func manageScannerSettings(input ScannerSettingsInput) (map[string]any, error) {
	action := strings.ToLower(strings.TrimSpace(input.Action))
	switch action {
	case "get":
		return scannerSettingsResult()
	case "update":
		if !input.Confirm {
			return nil, fmt.Errorf("update requires confirm=true")
		}
		if len(input.Settings) == 0 || len(input.Settings) > len(scanner.ScannerSettingSpecs()) {
			return nil, fmt.Errorf("settings must contain between 1 and %d entries", len(scanner.ScannerSettingSpecs()))
		}
		normalized := make(map[string]string, len(input.Settings))
		for key, value := range input.Settings {
			canonical, err := scanner.NormalizeScannerSettingValue(key, value)
			if err != nil {
				return nil, err
			}
			normalized[key] = canonical
		}
		if err := database.DB.Transaction(func(tx *gorm.DB) error {
			for key, value := range normalized {
				spec, _ := scanner.ScannerSettingDefinition(key)
				var setting models.Setting
				err := tx.Where("key = ?", key).First(&setting).Error
				if errors.Is(err, gorm.ErrRecordNotFound) {
					setting = models.Setting{Category: models.SettingCategoryScanner, Key: key, Value: value, Description: spec.Description}
					if err := tx.Create(&setting).Error; err != nil {
						return err
					}
					continue
				}
				if err != nil {
					return err
				}
				setting.Category = models.SettingCategoryScanner
				setting.Value = value
				setting.Description = spec.Description
				setting.IsEncrypted = false
				if err := tx.Save(&setting).Error; err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return nil, fmt.Errorf("update scanner settings failed")
		}
		proxypool.Refresh()
		result, err := scannerSettingsResult()
		if err == nil {
			result["updated"] = normalized
		}
		return result, err
	default:
		return nil, fmt.Errorf("unsupported scanner settings action: %s", input.Action)
	}
}

func scannerSettingsResult() (map[string]any, error) {
	var stored []models.Setting
	if err := database.DB.Where("category = ?", models.SettingCategoryScanner).Find(&stored).Error; err != nil {
		return nil, fmt.Errorf("load scanner settings failed")
	}
	values := make(map[string]string, len(stored))
	for _, setting := range stored {
		if _, ok := scanner.ScannerSettingDefinition(setting.Key); ok {
			values[setting.Key] = setting.Value
		}
	}
	type settingState struct {
		scanner.ScannerSettingSpec
		Value  string `json:"value"`
		Source string `json:"source"`
	}
	definitions := scanner.ScannerSettingSpecs()
	items := make([]settingState, 0, len(definitions))
	for _, spec := range definitions {
		value, source := spec.Default, "default"
		if storedValue, ok := values[spec.Key]; ok {
			if normalized, err := scanner.NormalizeScannerSettingValue(spec.Key, storedValue); err == nil {
				value, source = normalized, "database"
			}
		}
		items = append(items, settingState{ScannerSettingSpec: spec, Value: value, Source: source})
	}
	return map[string]any{"action": "get", "settings": items, "total": len(items), "applies_to": "new_tasks"}, nil
}

func manageProxyPool(input ProxyPoolManagementInput) (map[string]any, error) {
	action := strings.ToLower(strings.TrimSpace(input.Action))
	if action != "list" && !input.Confirm {
		return nil, fmt.Errorf("%s requires confirm=true", action)
	}
	switch action {
	case "list":
		return listProxyEndpoints(input)
	case "create":
		value, err := proxyFromSpec(input.Proxy)
		if err != nil {
			return nil, err
		}
		if err := database.DB.Create(value).Error; err != nil {
			return nil, fmt.Errorf("proxy address already exists")
		}
		proxypool.Refresh()
		return map[string]any{"action": action, "proxy": value}, nil
	case "batch_create":
		if len(input.Proxies) == 0 || len(input.Proxies) > 100 {
			return nil, fmt.Errorf("proxies must contain between 1 and 100 entries")
		}
		values := make([]models.ProxyEndpoint, 0, len(input.Proxies))
		for index, spec := range input.Proxies {
			value, err := proxyFromSpec(spec)
			if err != nil {
				return nil, fmt.Errorf("proxy %d: %w", index+1, err)
			}
			values = append(values, *value)
		}
		if err := database.DB.Transaction(func(tx *gorm.DB) error { return tx.Create(&values).Error }); err != nil {
			return nil, fmt.Errorf("batch create failed; duplicate proxy addresses are not allowed")
		}
		proxypool.Refresh()
		return map[string]any{"action": action, "proxies": values, "created": len(values)}, nil
	case "update":
		value, err := loadProxy(input.ID)
		if err != nil {
			return nil, err
		}
		addressChanged := applyProxySpec(value, input.Proxy)
		if err := value.Validate(); err != nil {
			return nil, err
		}
		if addressChanged {
			value.Status, value.LastError = "unknown", ""
		}
		if err := database.DB.Save(value).Error; err != nil {
			return nil, fmt.Errorf("proxy address already exists")
		}
		proxypool.Refresh()
		return map[string]any{"action": action, "proxy": value}, nil
	case "toggle":
		if input.Enabled == nil {
			return nil, fmt.Errorf("enabled is required for toggle")
		}
		value, err := loadProxy(input.ID)
		if err != nil {
			return nil, err
		}
		value.IsEnabled = *input.Enabled
		if err := database.DB.Save(value).Error; err != nil {
			return nil, fmt.Errorf("toggle proxy failed")
		}
		proxypool.Refresh()
		return map[string]any{"action": action, "proxy": value}, nil
	case "delete":
		ids, err := proxyInputIDs(input.ID, input.IDs, 1000)
		if err != nil {
			return nil, err
		}
		result := database.DB.Where("id IN ?", ids).Delete(&models.ProxyEndpoint{})
		if result.Error != nil {
			return nil, fmt.Errorf("delete proxies failed")
		}
		proxypool.Refresh()
		return map[string]any{"action": action, "requested": len(ids), "deleted": result.RowsAffected}, nil
	case "test":
		ids, err := proxyInputIDs(input.ID, input.IDs, 100)
		if err != nil {
			return nil, err
		}
		return testProxyEndpoints(ids)
	case "test_all":
		tested, healthy, dead, err := proxypool.CheckAll()
		if err != nil {
			return nil, fmt.Errorf("test proxy pool failed")
		}
		return map[string]any{"action": action, "tested": tested, "healthy": healthy, "dead": dead}, nil
	default:
		return nil, fmt.Errorf("unsupported proxy action: %s", input.Action)
	}
}

func listProxyEndpoints(input ProxyPoolManagementInput) (map[string]any, error) {
	page, pageSize := normalizePage(input.Page, input.PageSize)
	query := database.DB.Model(&models.ProxyEndpoint{})
	if input.Enabled != nil {
		query = query.Where("is_enabled = ?", *input.Enabled)
	}
	if input.Status != "" {
		status := strings.ToLower(strings.TrimSpace(input.Status))
		if status != "unknown" && status != "healthy" && status != "dead" {
			return nil, fmt.Errorf("unsupported proxy status: %s", input.Status)
		}
		query = query.Where("status = ?", status)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, fmt.Errorf("count proxies failed")
	}
	var values []models.ProxyEndpoint
	if err := query.Order("created_at DESC").Limit(pageSize).Offset((page - 1) * pageSize).Find(&values).Error; err != nil {
		return nil, fmt.Errorf("list proxies failed")
	}
	return map[string]any{"action": "list", "proxies": values, "total": total, "page": page, "page_size": pageSize}, nil
}

func proxyFromSpec(spec ProxySpec) (*models.ProxyEndpoint, error) {
	if spec.Name == nil || spec.Scheme == nil || spec.Host == nil || spec.Port == nil {
		return nil, fmt.Errorf("name, scheme, host and port are required")
	}
	value := &models.ProxyEndpoint{Status: "unknown", IsEnabled: true}
	applyProxySpec(value, spec)
	if err := value.Validate(); err != nil {
		return nil, err
	}
	return value, nil
}

func applyProxySpec(value *models.ProxyEndpoint, spec ProxySpec) bool {
	oldScheme, oldHost, oldPort, oldUsername, oldPassword := value.Scheme, value.Host, value.Port, value.Username, value.Password
	if spec.Name != nil {
		value.Name = strings.TrimSpace(*spec.Name)
	}
	if spec.Scheme != nil {
		value.Scheme = strings.ToLower(strings.TrimSpace(*spec.Scheme))
	}
	if spec.Host != nil {
		value.Host = strings.TrimSpace(*spec.Host)
	}
	if spec.Port != nil {
		value.Port = *spec.Port
	}
	if spec.Username != nil {
		value.Username = *spec.Username
	}
	if spec.Password != nil {
		value.Password = *spec.Password
	}
	if value.Username == "" {
		value.Password = ""
	}
	if spec.Enabled != nil {
		value.IsEnabled = *spec.Enabled
	}
	return oldScheme != value.Scheme || oldHost != value.Host || oldPort != value.Port || oldUsername != value.Username || oldPassword != value.Password
}

func loadProxy(id string) (*models.ProxyEndpoint, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("proxy id is required")
	}
	var value models.ProxyEndpoint
	if err := database.DB.First(&value, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("proxy not found")
	}
	return &value, nil
}

func proxyInputIDs(id string, ids []string, maximum int) ([]string, error) {
	if strings.TrimSpace(id) != "" {
		ids = append(ids, id)
	}
	if len(ids) == 0 || len(ids) > maximum {
		return nil, fmt.Errorf("proxy ids must contain between 1 and %d entries", maximum)
	}
	seen := make(map[string]struct{}, len(ids))
	result := make([]string, 0, len(ids))
	for _, value := range ids {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf("proxy id cannot be empty")
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}

func testProxyEndpoints(ids []string) (map[string]any, error) {
	var values []models.ProxyEndpoint
	if err := database.DB.Where("id IN ?", ids).Find(&values).Error; err != nil {
		return nil, fmt.Errorf("load proxies failed")
	}
	var wg sync.WaitGroup
	jobs := make(chan *models.ProxyEndpoint)
	workers := 10
	if len(values) < workers {
		workers = len(values)
	}
	var saveMu sync.Mutex
	var saveErr error
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for value := range jobs {
				_ = proxypool.CheckOne(value)
				if err := database.DB.Save(value).Error; err != nil {
					saveMu.Lock()
					if saveErr == nil {
						saveErr = err
					}
					saveMu.Unlock()
				}
			}
		}()
	}
	for index := range values {
		jobs <- &values[index]
	}
	close(jobs)
	wg.Wait()
	if saveErr != nil {
		return nil, fmt.Errorf("save proxy test results failed")
	}
	proxypool.Refresh()
	healthy := 0
	for _, value := range values {
		if value.Status == "healthy" {
			healthy++
		}
	}
	return map[string]any{
		"action": "test", "requested": len(ids), "tested": len(values),
		"healthy": healthy, "dead": len(values) - healthy, "proxies": values,
	}, nil
}
