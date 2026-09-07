package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestParsePaginationRejectsInvalidValuesAndCapsPageSize(t *testing.T) {
	tests := []struct {
		query        string
		wantPage     int
		wantPageSize int
	}{
		{query: "?page=0&page_size=0", wantPage: 1, wantPageSize: 50},
		{query: "?page=-2&page_size=-10", wantPage: 1, wantPageSize: 50},
		{query: "?page=3&page_size=500", wantPage: 3, wantPageSize: 200},
	}
	for _, test := range tests {
		response := httptest.NewRecorder()
		context, _ := gin.CreateTestContext(response)
		context.Request = httptest.NewRequest(http.MethodGet, "/"+test.query, nil)
		page, pageSize := parsePagination(context, 50, 200)
		if page != test.wantPage || pageSize != test.wantPageSize {
			t.Fatalf("parsePagination(%q) = (%d, %d), want (%d, %d)", test.query, page, pageSize, test.wantPage, test.wantPageSize)
		}
	}
}
