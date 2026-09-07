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

func TestAssetGroupCanonicalMembersPostgres(t *testing.T) {
	dsn := os.Getenv("ASSET_CATALOG_INTEGRATION_DSN")
	if dsn == "" {
		t.Skip("set ASSET_CATALOG_INTEGRATION_DSN to run PostgreSQL asset group coverage")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open integration database: %v", err)
	}
	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("begin integration transaction: %v", tx.Error)
	}
	previousDB := database.DB
	database.DB = tx
	t.Cleanup(func() {
		database.DB = previousDB
		tx.Rollback()
	})

	now := time.Now().UTC()
	group := models.AssetGroup{Name: "handler-group-" + uuid.NewString()}
	lastTaskID := uuid.NewString()
	assets := []models.AssetEntity{
		{Kind: "domain", CanonicalKey: "handler.example", DisplayValue: "handler.example", LastTaskID: lastTaskID, CurrentData: "{}", FirstSeenAt: now, LastSeenAt: now},
		{Kind: "port", CanonicalKey: "203.0.113.9:443/tcp", DisplayValue: "203.0.113.9:443/tcp", LastTaskID: lastTaskID, CurrentData: "{}", FirstSeenAt: now, LastSeenAt: now},
	}
	if err := tx.Create(&group).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := tx.Create(&assets).Error; err != nil {
		t.Fatalf("create canonical assets: %v", err)
	}
	taskDomain := models.Domain{TaskID: uuid.NewString(), Domain: "task.handler.example", Source: "integration"}
	if err := tx.Create(&taskDomain).Error; err != nil {
		t.Fatalf("create task domain: %v", err)
	}
	taskGroupItem := models.AssetGroupItem{GroupID: group.ID, AssetType: "domain", AssetID: taskDomain.ID}
	if err := tx.Create(&taskGroupItem).Error; err != nil {
		t.Fatalf("add task group member: %v", err)
	}

	handler := NewAssetGroupHandler()
	body, _ := json.Marshal(gin.H{"asset_type": "canonical", "asset_ids": []string{assets[0].ID, assets[1].ID}})
	response := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(response)
	context.Params = gin.Params{{Key: "id", Value: group.ID}}
	context.Request = httptest.NewRequest(http.MethodPost, "/asset-groups/"+group.ID+"/items", bytes.NewReader(body))
	context.Request.Header.Set("Content-Type", "application/json")
	handler.AddMembers(context)
	if response.Code != http.StatusOK {
		t.Fatalf("add canonical members status=%d body=%s", response.Code, response.Body.String())
	}
	var added struct {
		CreatedCount int `json:"created_count"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &added); err != nil || added.CreatedCount != 2 {
		t.Fatalf("add canonical members response=%s error=%v", response.Body.String(), err)
	}

	membersResponse := httptest.NewRecorder()
	membersContext, _ := gin.CreateTestContext(membersResponse)
	membersContext.Params = gin.Params{{Key: "id", Value: group.ID}}
	membersContext.Request = httptest.NewRequest(http.MethodGet, "/asset-groups/"+group.ID+"/items", nil)
	handler.ListMembers(membersContext)
	if membersResponse.Code != http.StatusOK {
		t.Fatalf("list canonical members status=%d body=%s", membersResponse.Code, membersResponse.Body.String())
	}
	var listed struct {
		Items []struct {
			Kind        string `json:"kind"`
			AssetSource string `json:"asset_source"`
			Label       string `json:"label"`
		} `json:"items"`
	}
	if err := json.Unmarshal(membersResponse.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode canonical members: %v", err)
	}
	if len(listed.Items) != 3 {
		t.Fatalf("listed members=%d, want 3", len(listed.Items))
	}
	kinds := map[string]bool{}
	canonicalCount := 0
	taskDomainFound := false
	for _, item := range listed.Items {
		if item.Label == "task.handler.example" && item.AssetSource == "task" && item.Kind == "domain" {
			taskDomainFound = true
			continue
		}
		if item.AssetSource != "catalog" || item.Label == "" {
			t.Fatalf("unexpected group member: %#v", item)
		}
		canonicalCount++
		kinds[item.Kind] = true
	}
	if canonicalCount != 2 || !taskDomainFound || !kinds["domain"] || !kinds["port"] {
		t.Fatalf("canonical member kinds=%v count=%d task_domain=%v", kinds, canonicalCount, taskDomainFound)
	}

	listResponse := httptest.NewRecorder()
	listContext, _ := gin.CreateTestContext(listResponse)
	listContext.Request = httptest.NewRequest(http.MethodGet, "/asset-groups?search="+group.Name, nil)
	handler.List(listContext)
	if listResponse.Code != http.StatusOK {
		t.Fatalf("list groups status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
	var groupList struct {
		Groups []struct {
			ID          string         `json:"id"`
			MemberCount int64          `json:"member_count"`
			AssetCounts map[string]int `json:"asset_counts"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(listResponse.Body.Bytes(), &groupList); err != nil {
		t.Fatalf("decode group list: %v", err)
	}
	if len(groupList.Groups) != 1 || groupList.Groups[0].ID != group.ID {
		t.Fatalf("listed groups=%#v, want group %s", groupList.Groups, group.ID)
	}
	if groupList.Groups[0].MemberCount != 3 || groupList.Groups[0].AssetCounts["domain"] != 2 || groupList.Groups[0].AssetCounts["port"] != 1 {
		t.Fatalf("unexpected mixed member counts: %#v", groupList.Groups[0])
	}
}
