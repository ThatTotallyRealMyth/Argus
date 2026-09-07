package scanner

import (
	"context"
	"io"
	"log"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/reconmaster/backend/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestDetectOSKeepsTaskIsolationPostgres(t *testing.T) {
	dsn := os.Getenv("ASSET_CATALOG_INTEGRATION_DSN")
	if dsn == "" {
		t.Skip("set ASSET_CATALOG_INTEGRATION_DSN to run PostgreSQL OS isolation coverage")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open integration database: %v", err)
	}
	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("begin integration transaction: %v", tx.Error)
	}
	t.Cleanup(func() { tx.Rollback() })
	if err := tx.AutoMigrate(&models.IP{}, &models.Port{}); err != nil {
		t.Fatalf("migrate scanner integration schema: %v", err)
	}

	currentTaskID := uuid.NewString()
	otherTaskID := uuid.NewString()
	sharedIP := "127.0.0.1"
	ips := []models.IP{
		{TaskID: currentTaskID, IPAddress: sharedIP, Source: "integration"},
		{TaskID: otherTaskID, IPAddress: sharedIP, Source: "integration"},
	}
	if err := tx.Create(&ips).Error; err != nil {
		t.Fatalf("seed task IPs: %v", err)
	}
	if err := tx.Create(&models.Port{TaskID: currentTaskID, IPAddress: sharedIP, Port: 22, Protocol: "tcp"}).Error; err != nil {
		t.Fatalf("seed current task port: %v", err)
	}

	engine := NewEngine()
	scanContext := &ScanContext{
		Task: &models.Task{
			ID:      currentTaskID,
			Options: models.TaskOptions{EnableOSDetect: true},
		},
		DB:     tx,
		Ctx:    context.Background(),
		Logger: log.New(io.Discard, "", 0),
	}
	if err := engine.DetectOS(scanContext); err != nil {
		t.Fatal(err)
	}

	var currentIP models.IP
	if err := tx.First(&currentIP, "id = ?", ips[0].ID).Error; err != nil {
		t.Fatalf("load current task IP: %v", err)
	}
	if currentIP.OS != "Linux/Unix" {
		t.Fatalf("current task OS = %q, want Linux/Unix", currentIP.OS)
	}
	var otherIP models.IP
	if err := tx.First(&otherIP, "id = ?", ips[1].ID).Error; err != nil {
		t.Fatalf("load other task IP: %v", err)
	}
	if otherIP.OS != "" {
		t.Fatalf("other task OS was modified: %q", otherIP.OS)
	}
}
