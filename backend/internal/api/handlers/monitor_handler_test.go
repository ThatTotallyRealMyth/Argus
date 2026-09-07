package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/services"
)

type fakeMonitorRunner struct {
	id  string
	err error
}

func (runner *fakeMonitorRunner) RunMonitorNow(id string) error {
	runner.id = id
	return runner.err
}

func TestValidateMonitorSourceAcceptsCVETargetOnly(t *testing.T) {
	monitor := &models.Monitor{Name: "CVE", Type: models.MonitorTypeCVE, Target: "nginx, grafana", Status: models.MonitorStatusActive, Interval: 3600}
	if _, err := services.AuthorizeMonitorExecution(nil, monitor); err != nil {
		t.Fatalf("valid CVE target rejected: %v", err)
	}
	groupID := "group-id"
	monitor.Target, monitor.AssetGroupID = "", &groupID
	if _, err := services.AuthorizeMonitorExecution(nil, monitor); err == nil {
		t.Fatal("CVE monitor unexpectedly accepted an asset group")
	}
}

func TestMonitorRunNowQueuesThroughRunner(t *testing.T) {
	gin.SetMode(gin.TestMode)
	runner := &fakeMonitorRunner{}
	handler := NewMonitorHandler(runner)
	response := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(response)
	context.Params = gin.Params{{Key: "id", Value: "monitor-1"}}
	handler.RunNow(context)
	if response.Code != http.StatusAccepted || runner.id != "monitor-1" {
		t.Fatalf("status=%d runner id=%q", response.Code, runner.id)
	}

	runner.err = errors.New("already running")
	response = httptest.NewRecorder()
	context, _ = gin.CreateTestContext(response)
	context.Params = gin.Params{{Key: "id", Value: "monitor-1"}}
	handler.RunNow(context)
	if response.Code != http.StatusConflict {
		t.Fatalf("conflict status=%d", response.Code)
	}
}
