package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func TestLookupErrorsDistinguishMissingRowsFromDatabaseFailures(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name   string
		write  func(*gin.Context, error)
		err    error
		status int
	}{
		{name: "missing user", write: writeUserLookupError, err: gorm.ErrRecordNotFound, status: http.StatusNotFound},
		{name: "user database failure", write: writeUserLookupError, err: errors.New("database unavailable"), status: http.StatusInternalServerError},
		{name: "missing task", write: writeTaskLookupError, err: gorm.ErrRecordNotFound, status: http.StatusNotFound},
		{name: "task database failure", write: writeTaskLookupError, err: errors.New("database unavailable"), status: http.StatusInternalServerError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			context, _ := gin.CreateTestContext(response)
			test.write(context, test.err)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
		})
	}
}
