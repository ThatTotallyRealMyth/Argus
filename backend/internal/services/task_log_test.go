package services

import (
	"testing"

	"github.com/reconmaster/backend/internal/models"
	"gorm.io/gorm"
)

func TestTaskLogRecorderCapturesOccurrenceOrder(t *testing.T) {
	recorder := &taskLogRecorder{
		db:     &gorm.DB{},
		taskID: "00000000-0000-0000-0000-000000000001",
		buffer: make([]models.TaskLog, 0, taskLogBatchSize),
	}
	if _, err := recorder.Write([]byte("first line\nsecond line\n")); err != nil {
		t.Fatalf("write logs: %v", err)
	}
	if len(recorder.buffer) != 2 {
		t.Fatalf("unexpected buffered log count: %d", len(recorder.buffer))
	}
	first, second := recorder.buffer[0], recorder.buffer[1]
	if first.Sequence != 1 || second.Sequence != 2 {
		t.Fatalf("unexpected sequences: %d, %d", first.Sequence, second.Sequence)
	}
	if first.CreatedAt.IsZero() || second.CreatedAt.IsZero() || second.CreatedAt.Before(first.CreatedAt) {
		t.Fatalf("unexpected occurrence times: %v, %v", first.CreatedAt, second.CreatedAt)
	}
}

func TestTaskLogRecorderDropsBareTimestampLines(t *testing.T) {
	recorder := &taskLogRecorder{
		db:     &gorm.DB{},
		taskID: "00000000-0000-0000-0000-000000000001",
		buffer: make([]models.TaskLog, 0, taskLogBatchSize),
	}
	if _, err := recorder.Write([]byte("2026/07/16 12:57:24 \nTop Services\n")); err != nil {
		t.Fatalf("write logs: %v", err)
	}
	if len(recorder.buffer) != 1 || recorder.buffer[0].Message != "Top Services" {
		t.Fatalf("unexpected timestamp-only log handling: %#v", recorder.buffer)
	}
}
