package scanner

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestReadHTTPBodyCapsAndMarksTruncation(t *testing.T) {
	response := &http.Response{Body: io.NopCloser(strings.NewReader("abcdef"))}
	body, truncated, err := readHTTPBody(response, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated || string(body) != "abcd" {
		t.Fatalf("unexpected capture: body=%q truncated=%v", body, truncated)
	}
}

func TestShouldStoreHTTPBodyRecognizesTextAndBinary(t *testing.T) {
	if !shouldStoreHTTPBody("application/json; charset=utf-8") {
		t.Fatal("JSON response was not classified as storable")
	}
	if shouldStoreHTTPBody("image/png") {
		t.Fatal("binary image response was classified as text")
	}
}
