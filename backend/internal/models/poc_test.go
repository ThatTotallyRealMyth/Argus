package models

import "testing"

func TestNormalizePoCContent(t *testing.T) {
	tests := []struct {
		name    string
		pocType string
		content string
		want    string
	}{
		{
			name:    "normalizes escaped nuclei document",
			pocType: "nuclei",
			content: `id: e2e-gateway-timeout\ninfo: {}`,
			want:    "id: e2e-gateway-timeout\ninfo: {}",
		},
		{
			name:    "preserves existing line breaks",
			pocType: "nuclei",
			content: "id: example\ninfo:\n  name: Example",
			want:    "id: example\ninfo:\n  name: Example",
		},
		{
			name:    "preserves escaped newline inside a scalar",
			pocType: "nuclei",
			content: `body: "first\nsecond"`,
			want:    `body: "first\nsecond"`,
		},
		{
			name:    "preserves non nuclei content",
			pocType: "custom",
			content: `id: custom\ninfo: {}`,
			want:    `id: custom\ninfo: {}`,
		},
		{
			name:    "preserves invalid normalized yaml",
			pocType: "nuclei",
			content: `id: example\ninfo: [`,
			want:    `id: example\ninfo: [`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := normalizePoCContent(test.pocType, test.content); got != test.want {
				t.Fatalf("normalizePoCContent() = %q, want %q", got, test.want)
			}
		})
	}
}
