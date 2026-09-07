package mcpserver

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"gorm.io/gorm"
)

type LibraryListInput struct {
	Library  string `json:"library" jsonschema:"required,库类型: fingerprints 或 pocs"`
	Search   string `json:"search" jsonschema:"按名称、产品、CVE或分类搜索"`
	Page     int    `json:"page" jsonschema:"页码，默认1"`
	PageSize int    `json:"page_size" jsonschema:"每页数量，默认20，最大100"`
}

type LibraryIDInput struct {
	Library string `json:"library" jsonschema:"required,库类型: fingerprints 或 pocs"`
	ID      string `json:"id" jsonschema:"required,记录 ID"`
}

type LibraryWriteInput struct {
	Library string         `json:"library" jsonschema:"required,库类型: fingerprints 或 pocs"`
	ID      string         `json:"id" jsonschema:"更新指定记录时填写；为空时按规则身份新增或覆盖"`
	Data    map[string]any `json:"data" jsonschema:"required,指纹或PoC字段"`
}

type fingerprintSummary struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Category  string `json:"category"`
	IsEnabled bool   `json:"is_enabled"`
}

type pocSummary struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Product          string `json:"product"`
	AffectedVersions string `json:"affected_versions"`
	CVE              string `json:"cve"`
	Severity         string `json:"severity"`
	Category         string `json:"category"`
	PoCType          string `json:"poc_type"`
	IsEnabled        bool   `json:"is_enabled"`
}

func RegisterLibraryTools(server *mcp.Server) {
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: boolPtr(false)}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_library_records",
		Description: "分页读取指纹库或漏洞库摘要。列表不返回完整DSL或PoC内容；需要内容时调用get_library_record。",
		Annotations: readOnly,
	}, func(ctx context.Context, req *mcp.CallToolRequest, input LibraryListInput) (*mcp.CallToolResult, any, error) {
		result, err := listLibraryRecords(input)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(result)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_library_record",
		Description: "按ID读取一条完整指纹或PoC记录，包括DSL或PoC模板内容。",
		Annotations: readOnly,
	}, func(ctx context.Context, req *mcp.CallToolRequest, input LibraryIDInput) (*mcp.CallToolResult, any, error) {
		record, err := getLibraryRecord(input.Library, input.ID)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(record)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "write_library_record",
		Description: "新增或更新指纹/PoC。ID为空时，同名指纹会覆盖；名称、CVE、产品和影响版本均相同的PoC会覆盖。",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: boolPtr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input LibraryWriteInput) (*mcp.CallToolResult, any, error) {
		log.Printf("[MCP audit] library=%s action=write id=%s", input.Library, input.ID)
		result, err := writeLibraryRecord(input)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(result)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "delete_library_record",
		Description: "直接删除一条指纹或PoC记录，不需要二次确认。",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, input LibraryIDInput) (*mcp.CallToolResult, any, error) {
		resource, err := libraryResource(input.Library)
		if err != nil {
			return errResult(err), nil, nil
		}
		log.Printf("[MCP audit] library=%s action=delete id=%s", input.Library, input.ID)
		result, err := deletePlatformRecord(resource, input.ID)
		if err != nil {
			return errResult(err), nil, nil
		}
		return jsonResult(result)
	})
}

func listLibraryRecords(input LibraryListInput) (map[string]any, error) {
	page, pageSize := normalizePage(input.Page, input.PageSize)
	search := strings.TrimSpace(input.Search)
	switch input.Library {
	case "fingerprints":
		query := searchLike(database.DB.Model(&models.Fingerprint{}), search, "name", "category", "description")
		var total int64
		var items []fingerprintSummary
		if err := query.Count(&total).Error; err != nil {
			return nil, err
		}
		if err := query.Select("id", "name", "category", "is_enabled").Order("created_at DESC").Limit(pageSize).Offset((page - 1) * pageSize).Scan(&items).Error; err != nil {
			return nil, err
		}
		return map[string]any{"library": input.Library, "items": items, "total": total, "page": page, "page_size": pageSize}, nil
	case "pocs":
		query := searchLike(database.DB.Model(&models.PoC{}), search, "name", "product", "affected_versions", "cve", "category", "tags")
		var total int64
		var items []pocSummary
		if err := query.Count(&total).Error; err != nil {
			return nil, err
		}
		if err := query.Select("id", "name", "product", "affected_versions", "cve", "severity", "category", "poc_type", "is_enabled").Order("created_at DESC").Limit(pageSize).Offset((page - 1) * pageSize).Scan(&items).Error; err != nil {
			return nil, err
		}
		return map[string]any{"library": input.Library, "items": items, "total": total, "page": page, "page_size": pageSize}, nil
	default:
		return nil, fmt.Errorf("unsupported library: %s", input.Library)
	}
}

func getLibraryRecord(library, id string) (any, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("id is required")
	}
	switch library {
	case "fingerprints":
		var value models.Fingerprint
		return &value, database.DB.First(&value, "id = ?", id).Error
	case "pocs":
		var value models.PoC
		return &value, database.DB.First(&value, "id = ?", id).Error
	default:
		return nil, fmt.Errorf("unsupported library: %s", library)
	}
}

func writeLibraryRecord(input LibraryWriteInput) (map[string]any, error) {
	resource, err := libraryResource(input.Library)
	if err != nil {
		return nil, err
	}
	if len(input.Data) == 0 {
		return nil, fmt.Errorf("data is required")
	}
	if input.ID != "" {
		return updateLibraryRecord(resource, input.ID, input.Data)
	}

	existingID, err := findExistingLibraryRecord(input.Library, input.Data)
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	if existingID != "" {
		return updateLibraryRecord(resource, existingID, input.Data)
	}
	return createPlatformRecord(resource, input.Data)
}

func findExistingLibraryRecord(library string, data map[string]any) (string, error) {
	switch library {
	case "fingerprints":
		var value models.Fingerprint
		if err := decodeMap(data, &value); err != nil {
			return "", err
		}
		if strings.TrimSpace(value.Name) == "" {
			return "", nil
		}
		var existing models.Fingerprint
		err := database.DB.Unscoped().Select("id").Where("name = ?", value.Name).First(&existing).Error
		return existing.ID, err
	case "pocs":
		var value models.PoC
		if err := decodeMap(data, &value); err != nil {
			return "", err
		}
		if strings.TrimSpace(value.Name) == "" {
			return "", nil
		}
		var existing models.PoC
		err := database.DB.Unscoped().Select("id").Where(
			"name = ? AND cve = ? AND product = ? AND affected_versions = ?",
			value.Name, value.CVE, value.Product, value.AffectedVersions,
		).First(&existing).Error
		return existing.ID, err
	default:
		return "", fmt.Errorf("unsupported library: %s", library)
	}
}

func updateLibraryRecord(resource, id string, data map[string]any) (map[string]any, error) {
	_, allowed, err := manageableModel(resource)
	if err != nil {
		return nil, err
	}
	updates := whitelist(data, allowed)
	if len(updates) == 0 {
		return nil, fmt.Errorf("no supported fields to update")
	}

	var record any
	switch resource {
	case "fingerprints":
		record = &models.Fingerprint{}
	case "pocs":
		record = &models.PoC{}
	default:
		return nil, fmt.Errorf("unsupported library: %s", resource)
	}
	if err := database.DB.Unscoped().First(record, "id = ?", id).Error; err != nil {
		return nil, err
	}
	if err := decodeMap(updates, record); err != nil {
		return nil, err
	}
	if err := validatePlatformRecord(record); err != nil {
		return nil, err
	}

	switch value := record.(type) {
	case *models.Fingerprint:
		value.DeletedAt = gorm.DeletedAt{}
	case *models.PoC:
		value.DeletedAt = gorm.DeletedAt{}
	}
	if err := database.DB.Unscoped().Save(record).Error; err != nil {
		return nil, err
	}
	return map[string]any{"action": "updated", "resource": resource, "id": id, "record": record}, nil
}

func libraryResource(library string) (string, error) {
	switch library {
	case "fingerprints", "pocs":
		return library, nil
	default:
		return "", fmt.Errorf("unsupported library: %s", library)
	}
}
