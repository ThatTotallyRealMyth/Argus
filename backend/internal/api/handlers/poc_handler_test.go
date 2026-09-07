package handlers

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnzipFileRejectsTraversal(t *testing.T) {
	archive := makeZip(t, map[string]string{"../escape.yaml": "id: bad"})
	if err := unzipFile(archive, filepath.Join(t.TempDir(), "out")); err == nil {
		t.Fatal("path traversal archive was accepted")
	}
}

func TestUnzipFileRejectsOversizedEntry(t *testing.T) {
	archive := makeZip(t, map[string]string{"large.yaml": strings.Repeat("x", (2<<20)+1)})
	if err := unzipFile(archive, filepath.Join(t.TempDir(), "out")); err == nil {
		t.Fatal("oversized archive entry was accepted")
	}
}

func TestUnzipFileExtractsValidArchive(t *testing.T) {
	archive := makeZip(t, map[string]string{"nested/poc.yaml": "id: test"})
	destination := filepath.Join(t.TempDir(), "out")
	if err := unzipFile(archive, destination); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(destination, "nested", "poc.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "id: test" {
		t.Fatalf("unexpected content: %q", content)
	}
}

func makeZip(t *testing.T, files map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.zip")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for name, content := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
