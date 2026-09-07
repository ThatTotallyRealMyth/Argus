package proxypool

import (
	"testing"
	"time"

	"github.com/reconmaster/backend/internal/database"
)

func TestSelectionIndexRoundRobin(t *testing.T) {
	now := time.Unix(0, 0)
	want := []int{0, 1, 2, 0, 1, 2}
	for sequence, expected := range want {
		if got := selectionIndex(uint64(sequence), 3, false, 30, now); got != expected {
			t.Fatalf("sequence %d: got index %d, want %d", sequence, got, expected)
		}
	}
}

func TestCheckAllFailsWithoutDatabase(t *testing.T) {
	previous := database.DB
	database.DB = nil
	t.Cleanup(func() { database.DB = previous })
	if _, _, _, err := CheckAll(); err == nil {
		t.Fatal("proxy health check succeeded without a database")
	}
}

func TestProxyConfigurationFailsClosedWithoutDatabase(t *testing.T) {
	previous := database.DB
	database.DB = nil
	t.Cleanup(func() { database.DB = previous })

	if enabled, _, err := checkConfig(); err == nil || enabled {
		t.Fatalf("health checker did not fail closed: enabled=%v err=%v", enabled, err)
	}
	if enabled, _, err := rotationConfig(); err == nil || enabled {
		t.Fatalf("proxy rotation did not fail closed: enabled=%v err=%v", enabled, err)
	}
}

func TestSelectionIndexRotatesWindow(t *testing.T) {
	start := time.Unix(0, 0)
	if got := selectionIndex(0, 3, true, 30, start); got != 0 {
		t.Fatalf("initial window: got index %d, want 0", got)
	}
	if got := selectionIndex(0, 3, true, 30, start.Add(30*time.Second)); got != 1 {
		t.Fatalf("next window: got index %d, want 1", got)
	}
}

func TestSelectionIndexEmptyPool(t *testing.T) {
	if got := selectionIndex(7, 0, true, 30, time.Now()); got != 0 {
		t.Fatalf("empty pool: got index %d, want 0", got)
	}
}
