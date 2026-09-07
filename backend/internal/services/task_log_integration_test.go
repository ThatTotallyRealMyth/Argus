package services

import (
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestTaskLogWriterPostgres(t *testing.T) {
	dsn := os.Getenv("ASSET_CATALOG_INTEGRATION_DSN")
	if dsn == "" {
		t.Skip("set ASSET_CATALOG_INTEGRATION_DSN to run PostgreSQL task log coverage")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open integration database: %v", err)
	}
	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("begin integration transaction: %v", tx.Error)
	}
	if err := tx.AutoMigrate(&models.TaskLog{}); err != nil {
		t.Fatalf("migrate task logs: %v", err)
	}
	previousDB := database.DB
	database.DB = tx
	t.Cleanup(func() { database.DB = previousDB; tx.Rollback() })

	taskID := uuid.NewString()
	writer := &taskLogRecorder{db: tx, taskID: taskID, buffer: make([]models.TaskLog, 0, taskLogBatchSize)}
	if _, err := writer.Write([]byte("2026/07/16 10:00:00 开始端口扫描\n2026/07/16 10:00:01 端口扫描失败：timeout\n")); err != nil {
		t.Fatalf("write task logs: %v", err)
	}
	writer.Close()
	var rows []models.TaskLog
	if err := tx.Where("task_id = ?", taskID).Order("created_at ASC, sequence ASC").Find(&rows).Error; err != nil {
		t.Fatalf("load task logs: %v", err)
	}
	if len(rows) != 2 || rows[0].Message != "开始端口扫描" || rows[0].Level != "info" || rows[0].Sequence != 1 || rows[1].Level != "error" || rows[1].Sequence != 2 || rows[1].CreatedAt.Before(rows[0].CreatedAt) {
		t.Fatalf("unexpected task logs: %#v", rows)
	}
}
