package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAssetProfileHandlersRejectInvalidInputs(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewAssetProfileHandler()

	relationsResponse := httptest.NewRecorder()
	relationsContext, _ := gin.CreateTestContext(relationsResponse)
	relationsContext.Request = httptest.NewRequest(http.MethodGet, "/assets/relations?asset_type=unknown&asset_id=id", nil)
	handler.GetAssetRelations(relationsContext)
	if relationsResponse.Code != http.StatusBadRequest {
		t.Fatalf("invalid relation type status = %d, want 400", relationsResponse.Code)
	}

	graphResponse := httptest.NewRecorder()
	graphContext, _ := gin.CreateTestContext(graphResponse)
	graphContext.Request = httptest.NewRequest(http.MethodGet, "/assets/graph?asset_type=ip&asset_id=id&depth=99", nil)
	handler.GetAssetGraph(graphContext)
	if graphResponse.Code != http.StatusBadRequest {
		t.Fatalf("invalid graph depth status = %d, want 400", graphResponse.Code)
	}

	segmentResponse := httptest.NewRecorder()
	segmentContext, _ := gin.CreateTestContext(segmentResponse)
	segmentContext.Request = httptest.NewRequest(http.MethodGet, "/assets/c-segment?ip=203.0.113.1", nil)
	handler.AnalyzeCSegment(segmentContext)
	if segmentResponse.Code != http.StatusBadRequest {
		t.Fatalf("missing C segment task status = %d, want 400", segmentResponse.Code)
	}
}
