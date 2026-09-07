package services

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestFetchICPUsesCompatibleProtocol(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/query/web" {
			t.Errorf("path = %q, want /query/web", request.URL.Path)
		}
		if request.URL.Query().Get("search") != "Example Corp" {
			t.Errorf("search = %q", request.URL.Query().Get("search"))
		}
		if request.Header.Get("X-Tenant") != "red-team" {
			t.Errorf("X-Tenant = %q", request.Header.Get("X-Tenant"))
		}
		response.Header().Set("Content-Type", "application/json")
		response.Write([]byte(`{"code":200,"params":{"list":[{"domain":"https://WWW.Example.com/path","unitName":"Example Corp"}]}}`))
	}))
	defer server.Close()

	service := &EnterpriseService{client: server.Client()}
	assets, err := service.fetchICP(context.Background(), server.URL, map[string]string{"X-Tenant": "red-team"}, "Example Corp", "web")
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 || assets[0].Domain != "www.example.com" || assets[0].CompanyName != "Example Corp" {
		t.Fatalf("unexpected assets: %#v", assets)
	}
}

func TestNormalizeEnterpriseKinds(t *testing.T) {
	kinds, err := normalizeEnterpriseKinds([]string{"web", "MAPP", "web"})
	if err != nil {
		t.Fatal(err)
	}
	if len(kinds) != 2 || kinds[0] != "web" || kinds[1] != "mapp" {
		t.Fatalf("unexpected normalized kinds: %#v", kinds)
	}
	if _, err := normalizeEnterpriseKinds([]string{"company"}); err == nil {
		t.Fatal("expected unsupported query type to fail")
	}
}

func TestEnterpriseScanTargetsOnlyUsesNormalizedSelectedDomains(t *testing.T) {
	assets := []models.EnterpriseAsset{
		{ID: "1", Domain: "https://B.example.com/path"},
		{ID: "2", Domain: "a.example.com"},
		{ID: "3", Domain: "b.example.com"},
		{ID: "4", Name: "App without domain"},
		{ID: "5", Domain: "127.0.0.1"},
	}
	targets := enterpriseScanTargets(assets)
	if len(targets) != 2 || targets[0] != "a.example.com" || targets[1] != "b.example.com" {
		t.Fatalf("unexpected scan targets: %#v", targets)
	}
}

func TestEnterpriseQueryCompletionStatusAllowsPartialSuccess(t *testing.T) {
	if got := enterpriseQueryCompletionStatus(1); got != models.EnterpriseQueryCompleted {
		t.Fatalf("partial success status = %s, want completed", got)
	}
	if got := enterpriseQueryCompletionStatus(0); got != models.EnterpriseQueryFailed {
		t.Fatalf("zero success status = %s, want failed", got)
	}
}

func TestNormalizeEnterpriseAssetIDs(t *testing.T) {
	first, second := uuid.NewString(), uuid.NewString()
	ids, err := normalizeEnterpriseAssetIDs([]string{first, " " + second + " ", first})
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != first || ids[1] != second {
		t.Fatalf("normalized IDs = %#v", ids)
	}
	if _, err := normalizeEnterpriseAssetIDs([]string{"not-a-uuid"}); err == nil {
		t.Fatal("expected invalid UUID to fail")
	} else if !IsEnterpriseSyncInputError(err) {
		t.Fatalf("invalid UUID error was not classified as input error: %T", err)
	}
	if IsEnterpriseSyncInputError(errors.New("database unavailable")) {
		t.Fatal("internal error was misclassified as input error")
	}
}

func TestEnterpriseObservationStateIgnoresProvenanceMetadata(t *testing.T) {
	first := enterpriseDomainObservation{EnterpriseAssetID: uuid.NewString(), QueryID: uuid.NewString(), Provider: "icp_query", Kind: "web", Domain: "example.com", CompanyName: "Example Inc", License: "ICP-1", RawData: map[string]any{"version": 1}}
	second := first
	second.EnterpriseAssetID = uuid.NewString()
	second.QueryID = uuid.NewString()
	second.RawData = map[string]any{"version": 2}
	firstPayload, _, _, firstStateHash, err := marshalObservation("domain", "enterprise_domain", first)
	if err != nil {
		t.Fatal(err)
	}
	secondPayload, _, _, secondStateHash, err := marshalObservation("domain", "enterprise_domain", second)
	if err != nil {
		t.Fatal(err)
	}
	if firstPayload == secondPayload {
		t.Fatal("provenance payloads should differ")
	}
	if firstStateHash != secondStateHash {
		t.Fatalf("semantic enterprise state hashes differ: %s != %s", firstStateHash, secondStateHash)
	}
}

func TestEnterpriseCatalogSyncPostgres(t *testing.T) {
	dsn := os.Getenv("ASSET_CATALOG_INTEGRATION_DSN")
	if dsn == "" {
		t.Skip("set ASSET_CATALOG_INTEGRATION_DSN to run PostgreSQL enterprise sync coverage")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open integration database: %v", err)
	}
	previousDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = previousDB })

	now := time.Now().UTC().Truncate(time.Second)
	domain := "enterprise-" + uuid.NewString() + ".example"
	queries := []models.EnterpriseQuery{
		{Name: "enterprise sync A", Keyword: "Example", Provider: "icp_query", QueryTypes: []string{"web"}, Status: models.EnterpriseQueryCompleted},
		{Name: "enterprise sync B", Keyword: "Example", Provider: "icp_query", QueryTypes: []string{"web"}, Status: models.EnterpriseQueryCompleted},
	}
	if err := db.Create(&queries).Error; err != nil {
		t.Fatalf("seed enterprise queries: %v", err)
	}
	assets := []models.EnterpriseAsset{
		{QueryID: queries[0].ID, Provider: "icp_query", Kind: "web", CanonicalKey: domain, CompanyName: "Example Inc", Domain: domain, License: "ICP-1", RawData: `{}`, CreatedAt: now},
		{QueryID: queries[1].ID, Provider: "icp_query", Kind: "web", CanonicalKey: domain, CompanyName: "Example Inc", Domain: domain, License: "ICP-2", RawData: `{}`, CreatedAt: now.Add(time.Minute)},
	}
	if err := db.Create(&assets).Error; err != nil {
		t.Fatalf("seed enterprise assets: %v", err)
	}
	groupName := "enterprise-sync-" + uuid.NewString()
	var canonicalID, groupID string
	t.Cleanup(func() {
		if canonicalID != "" {
			db.Where("asset_id = ?", canonicalID).Delete(&models.AssetChange{})
			db.Where("asset_id = ?", canonicalID).Delete(&models.AssetObservation{})
			db.Where("asset_type = ? AND asset_id = ?", "canonical", canonicalID).Delete(&models.AssetGroupItem{})
			db.Delete(&models.AssetEntity{}, "id = ?", canonicalID)
		}
		if groupID != "" {
			db.Where("group_id = ?", groupID).Delete(&models.AssetGroupItem{})
			db.Delete(&models.AssetGroup{}, "id = ?", groupID)
		}
		db.Where("id IN ?", []string{assets[0].ID, assets[1].ID}).Delete(&models.EnterpriseAsset{})
		db.Where("id IN ?", []string{queries[0].ID, queries[1].ID}).Delete(&models.EnterpriseQuery{})
	})

	service := &EnterpriseService{assetCatalog: NewAssetCatalogService()}
	result, err := service.SyncAssets([]string{assets[0].ID, assets[1].ID}, "", groupName)
	if err != nil {
		t.Fatalf("sync enterprise assets: %v", err)
	}
	if result.SyncedCount != 2 || len(result.CanonicalAssetIDs) != 1 || result.CreatedGroupMembers != 1 {
		t.Fatalf("unexpected sync result: %#v", result)
	}
	canonicalID, groupID = result.CanonicalAssetIDs[0], result.GroupID
	var entity models.AssetEntity
	if err := db.First(&entity, "id = ?", canonicalID).Error; err != nil {
		t.Fatal(err)
	}
	if entity.ObservationCount != 2 || entity.ChangeCount != 1 || entity.LastOriginType != "enterprise_query" {
		t.Fatalf("unexpected canonical entity: %#v", entity)
	}
	var enterpriseObservations int64
	if err := db.Model(&models.AssetObservation{}).Where("asset_id = ? AND origin_type = ?", canonicalID, "enterprise_query").Count(&enterpriseObservations).Error; err != nil {
		t.Fatal(err)
	}
	if enterpriseObservations != 2 {
		t.Fatalf("enterprise observations = %d, want 2", enterpriseObservations)
	}
	repeated, err := service.SyncAssets([]string{assets[0].ID, assets[1].ID}, groupID, "")
	if err != nil {
		t.Fatalf("repeat enterprise sync: %v", err)
	}
	if repeated.CreatedGroupMembers != 0 || len(repeated.CanonicalAssetIDs) != 1 {
		t.Fatalf("repeat sync was not idempotent: %#v", repeated)
	}
	for _, query := range queries {
		var syncedCount int64
		if err := db.Model(&models.EnterpriseQuery{}).Select("synced_count").Where("id = ?", query.ID).Scan(&syncedCount).Error; err != nil {
			t.Fatal(err)
		}
		if syncedCount != 1 {
			t.Fatalf("query %s synced_count = %d, want 1", query.ID, syncedCount)
		}
	}
}

func TestNormalizeEnterpriseDomain(t *testing.T) {
	tests := map[string]string{
		"HTTPS://WWW.Example.COM/path?q=1": "www.example.com",
		"example.com:8443/path":            "example.com",
		"127.0.0.1":                        "",
		"localhost":                        "",
		"":                                 "",
	}
	for input, expected := range tests {
		if actual := normalizeEnterpriseDomain(input); actual != expected {
			t.Errorf("normalizeEnterpriseDomain(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestParseICPResponseListWrapperDeduplicatesDomains(t *testing.T) {
	body := []byte(`{"code":200,"params":{"list":[{"domain":"https://Example.com/a","unitName":"Example Inc","mainLicence":"ICP-1"},{"domain":"example.com","unitName":"Duplicate"},{"domain":"sub.example.com","serviceName":"Portal"}]}}`)
	assets, err := parseICPResponse(body, "web")
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 2 {
		t.Fatalf("got %d assets, want 2: %#v", len(assets), assets)
	}
	if assets[0].Domain != "example.com" || assets[0].CompanyName != "Example Inc" || assets[0].License != "ICP-1" {
		t.Fatalf("unexpected first asset: %#v", assets[0])
	}
}

func TestParseICPResponseArrayParams(t *testing.T) {
	body := []byte(`{"code":200,"params":[{"unitName":"Example Inc","serviceName":"Example App","serviceLicence":"APP-1"}]}`)
	assets, err := parseICPResponse(body, "app")
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 || assets[0].Kind != "app" || assets[0].Name != "Example App" || assets[0].CanonicalKey == "" {
		t.Fatalf("unexpected assets: %#v", assets)
	}
}

func TestParseICPResponseRejectsInvalidParams(t *testing.T) {
	if _, err := parseICPResponse([]byte(`{"code":200,"params":"bad"}`), "web"); err == nil {
		t.Fatal("expected invalid params to fail")
	}
	if _, err := parseICPResponse([]byte(`{"code":500,"params":[]}`), "web"); err == nil {
		t.Fatal("expected provider error code to fail")
	}
}
