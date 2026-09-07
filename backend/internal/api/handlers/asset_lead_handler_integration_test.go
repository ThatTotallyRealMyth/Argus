package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestAssetLeadTriageRepeatedUpsertPostgres(t *testing.T) {
	dsn := os.Getenv("ASSET_CATALOG_INTEGRATION_DSN")
	if dsn == "" {
		t.Skip("set ASSET_CATALOG_INTEGRATION_DSN to run PostgreSQL lead triage coverage")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open integration database: %v", err)
	}
	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("begin integration transaction: %v", tx.Error)
	}
	if err := tx.AutoMigrate(&models.AssetEntity{}, &models.AssetLeadTriage{}); err != nil {
		t.Fatalf("migrate lead triage tables: %v", err)
	}
	previousDB := database.DB
	database.DB = tx
	t.Cleanup(func() {
		database.DB = previousDB
		tx.Rollback()
	})

	now := time.Now().UTC()
	asset := models.AssetEntity{
		Kind: "site", CanonicalKey: "https://triage-" + uuid.NewString() + ".example", DisplayValue: "https://triage.example",
		LastTaskID: uuid.NewString(), CurrentData: "{}", FirstSeenAt: now, LastSeenAt: now,
	}
	if err := tx.Create(&asset).Error; err != nil {
		t.Fatalf("create canonical asset: %v", err)
	}
	handler := NewAssetLeadHandler()
	update := func(status, note string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(gin.H{"asset_id": asset.ID, "lead_id": "management:admin", "status": status, "note": note})
		response := httptest.NewRecorder()
		context, _ := gin.CreateTestContext(response)
		context.Request = httptest.NewRequest(http.MethodPut, "/assets/leads/triage", bytes.NewReader(body))
		context.Request.Header.Set("Content-Type", "application/json")
		handler.UpdateTriage(context)
		return response
	}
	if response := update(models.AssetLeadStatusNew, "first note"); response.Code != http.StatusOK {
		t.Fatalf("first update status=%d body=%s", response.Code, response.Body.String())
	}
	if response := update(models.AssetLeadStatusInvestigating, "second note"); response.Code != http.StatusOK {
		t.Fatalf("second update status=%d body=%s", response.Code, response.Body.String())
	}
	var rows []models.AssetLeadTriage
	if err := tx.Where("asset_id = ? AND lead_id = ?", asset.ID, "management:admin").Find(&rows).Error; err != nil {
		t.Fatalf("load triage rows: %v", err)
	}
	if len(rows) != 1 || rows[0].Status != models.AssetLeadStatusInvestigating || rows[0].Note != "second note" {
		t.Fatalf("unexpected triage rows: %#v", rows)
	}
}
