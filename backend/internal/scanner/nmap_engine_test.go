package scanner

import (
	"strings"
	"testing"
)

func TestCompactNmapPortsPreservesSelection(t *testing.T) {
	got, err := compactNmapPorts([]int{443, 80, 82, 81, 443, 1000})
	if err != nil {
		t.Fatal(err)
	}
	if got != "80-82,443,1000" {
		t.Fatalf("unexpected compact port selection: %s", got)
	}
}

func TestParseNmapXMLCapturesOpenPortsAndVersions(t *testing.T) {
	input := `<?xml version="1.0"?><nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports>
		<port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
		<port protocol="tcp" portid="443"><state state="open"/><service name="http" tunnel="ssl" product="nginx" version="1.25.4" extrainfo="Ubuntu"/></port>
	</ports></host></nmaprun>`
	results, err := parseNmapXML(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one open port, got %d", len(results))
	}
	result := results[0]
	if result.IP != "192.0.2.10" || result.Port != 443 || result.Service != "https" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.Product != "nginx" || result.Version != "1.25.4" || result.Banner != "nginx 1.25.4 Ubuntu" {
		t.Fatalf("service evidence was not retained: %#v", result)
	}
}

func TestCompactNmapPortsRejectsInvalidPorts(t *testing.T) {
	if _, err := compactNmapPorts([]int{80, 0}); err == nil {
		t.Fatal("expected an invalid-port error")
	}
}
