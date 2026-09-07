package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/services"
)

func TestWriteScheduledTaskErrorMapsMissingTaskToNotFound(t *testing.T) {
	response := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(response)

	writeScheduledTaskError(context, errors.Join(errors.New("delete scheduled task"), services.ErrScheduledTaskNotFound))

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", response.Code, response.Body.String())
	}
}
