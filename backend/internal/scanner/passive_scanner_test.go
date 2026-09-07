package scanner

import (
	"reflect"
	"testing"
)

func TestNormalizeDNSNameSupportsURLsAndSkipsNonDomainTargets(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		result string
	}{
		{name: "domain", input: "Example.COM.", result: "example.com"},
		{name: "url", input: "https://Example.COM:8443/path", result: "example.com"},
		{name: "ip", input: "192.0.2.1", result: ""},
		{name: "cidr", input: "192.0.2.0/30", result: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeDNSName(test.input)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.result {
				t.Fatalf("normalized target mismatch: got=%q want=%q", got, test.result)
			}
		})
	}
}

func TestSortedUniqueDNSRecords(t *testing.T) {
	got := sortedUnique([]string{" b ", "a", "b", "", "a"})
	want := []string{"a", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("records mismatch: got=%v want=%v", got, want)
	}
}

func TestQueryDNSRecordsReturnsAddressRecords(t *testing.T) {
	records, err := NewPassiveScanner().queryDNSRecords("localhost")
	if err != nil {
		t.Fatal(err)
	}
	if len(records["A"])+len(records["AAAA"]) == 0 {
		t.Fatalf("localhost returned no address records: %#v", records)
	}
}
