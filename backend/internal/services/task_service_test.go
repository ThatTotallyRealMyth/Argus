package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

func TestCancelTaskKeepsRunningMarkerUntilWorkerExits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	service := &TaskService{runningTasks: map[string]context.CancelFunc{"task-1": cancel}}
	if err := service.CancelTask("task-1"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("worker context was not cancelled")
	}
	if !service.IsTaskRunning("task-1") {
		t.Fatal("running marker was removed before worker exit")
	}
}

func TestMirrorPersistedTaskStatePreservesCancellation(t *testing.T) {
	workerEnd := time.Now().Add(time.Minute)
	cancelEnd := time.Now()
	task := models.Task{Status: models.TaskStatusCompleted, Progress: 100, EndedAt: &workerEnd}
	persisted := models.Task{Status: models.TaskStatusCancelled, Progress: 37, EndedAt: &cancelEnd, ErrorMsg: "Task was cancelled by user"}
	mirrorPersistedTaskState(&task, persisted)
	if task.Status != models.TaskStatusCancelled || task.Progress != 37 || task.EndedAt != &cancelEnd || task.ErrorMsg != persisted.ErrorMsg {
		t.Fatalf("worker state overwrote cancellation: %#v", task)
	}
}

func TestPublicTaskExecutionErrorRedactsInternalDetails(t *testing.T) {
	if got := publicTaskExecutionError(errors.New("dial tcp 10.0.0.8:443 via secret-proxy")); got != "Task execution failed" {
		t.Fatalf("internal error was exposed: %q", got)
	}
	input := taskInputErrorf("custom scripts are disabled for scope-enforced tasks")
	if got := publicTaskExecutionError(input); got != input.Error() {
		t.Fatalf("safe input error = %q", got)
	}
}

func TestRetryableTaskStatusOnlyAllowsTerminalTasks(t *testing.T) {
	tests := map[models.TaskStatus]bool{
		models.TaskStatusPending:   false,
		models.TaskStatusQueued:    false,
		models.TaskStatusRunning:   false,
		models.TaskStatusCompleted: true,
		models.TaskStatusFailed:    true,
		models.TaskStatusCancelled: true,
	}
	for status, want := range tests {
		if got := isRetryableTaskStatus(status); got != want {
			t.Errorf("isRetryableTaskStatus(%q) = %v, want %v", status, got, want)
		}
	}
}
