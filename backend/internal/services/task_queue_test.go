package services

import "testing"

func TestNormalizeTaskWorkerCount(t *testing.T) {
	tests := []struct {
		name  string
		input int
		want  int
	}{
		{name: "defaults invalid values", input: 0, want: 1},
		{name: "keeps configured concurrency", input: 10, want: 10},
		{name: "caps excessive concurrency", input: 100, want: 64},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := normalizeTaskWorkerCount(test.input); got != test.want {
				t.Fatalf("normalizeTaskWorkerCount(%d) = %d, want %d", test.input, got, test.want)
			}
		})
	}
}
