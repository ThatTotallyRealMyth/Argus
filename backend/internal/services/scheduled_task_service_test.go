package services

import (
	"testing"
	"time"
)

func TestNormalizeScheduledCronRejectsSubMinuteSchedules(t *testing.T) {
	now := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	if _, _, err := NormalizeScheduledCron("custom", "*/10 * * * * *", now); err == nil {
		t.Fatal("sub-minute scheduled scan was accepted")
	}
}

func TestNormalizeScheduledCronCalculatesStableBuiltInSchedule(t *testing.T) {
	now := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.Local)
	expression, next, err := NormalizeScheduledCron("daily", "ignored", now)
	if err != nil {
		t.Fatalf("normalize daily schedule: %v", err)
	}
	if expression != "0 0 2 * * *" || next == nil || !next.After(now) || next.Hour() != 2 {
		t.Fatalf("unexpected daily schedule: expression=%q next=%v", expression, next)
	}
}

func TestNormalizeScheduledCronOnceRunsImmediately(t *testing.T) {
	now := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	expression, next, err := NormalizeScheduledCron("once", "", now)
	if err != nil || expression != "" || next == nil || !next.Equal(now) {
		t.Fatalf("unexpected once schedule: expression=%q next=%v err=%v", expression, next, err)
	}
}
