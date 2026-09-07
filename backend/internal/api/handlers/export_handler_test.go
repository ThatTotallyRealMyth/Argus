package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestValidExportFilename(t *testing.T) {
	for _, filename := range []string{"task_id_20260720_120000.json", "report_id_20260720_120000.html", "sites_id_20260720_120000.csv"} {
		if !validExportFilename(filename) {
			t.Fatalf("valid export filename rejected: %q", filename)
		}
	}
	for _, filename := range []string{"", "../secret", "nested/report.html", `nested\\report.html`, "report.exe", ".html"} {
		if validExportFilename(filename) {
			t.Fatalf("invalid export filename accepted: %q", filename)
		}
	}
}

func TestDownloadExportForcesAttachment(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Chdir(t.TempDir())
	if err := os.Mkdir("exports", 0700); err != nil {
		t.Fatal(err)
	}
	filename := "report_task_20260720_120000.html"
	if err := os.WriteFile(filepath.Join("exports", filename), []byte("<html>report</html>"), 0600); err != nil {
		t.Fatal(err)
	}

	router := gin.New()
	router.GET("/download", (&ExportHandler{}).DownloadExport)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/download?file="+filename, nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("download status = %d", recorder.Code)
	}
	disposition := recorder.Header().Get("Content-Disposition")
	if !strings.Contains(disposition, "attachment") || !strings.Contains(disposition, filename) {
		t.Fatalf("content disposition = %q", disposition)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache control = %q", got)
	}
}
