package services

import (
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestAssetProfileStructuredParsing(t *testing.T) {
	if got := registrableDomain("API.Shop.Example.CO.UK."); got != "example.co.uk" {
		t.Fatalf("registrable domain = %q, want example.co.uk", got)
	}
	if got := extractHostname("https://user:pass@[2001:db8::1]:8443/path"); got != "2001:db8::1" {
		t.Fatalf("IPv6 hostname = %q", got)
	}
	if got := siteURLPort("https://[2001:db8::1]/"); got != 443 {
		t.Fatalf("default HTTPS port = %d, want 443", got)
	}
	if got := siteURLPort("http://example.com:8080/"); got != 8080 {
		t.Fatalf("explicit HTTP port = %d, want 8080", got)
	}
}

func TestVulnerabilityMatchesProfileUsesExactStructuredTargets(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		assetType  string
		assetValue string
		want       bool
	}{
		{name: "exact domain", target: "https://api.example.com/admin", assetType: "domain", assetValue: "api.example.com", want: true},
		{name: "domain suffix collision", target: "https://evil-api.example.com/admin", assetType: "domain", assetValue: "api.example.com", want: false},
		{name: "IPv6 target", target: "https://[2001:db8::10]:8443/admin", assetType: "ip", assetValue: "2001:db8::10", want: true},
		{name: "same origin site", target: "https://app.example.com/admin", assetType: "site", assetValue: "https://app.example.com/login", want: true},
		{name: "exact port", target: "http://203.0.113.9:8080/admin", assetType: "port", assetValue: "203.0.113.9:8080/tcp", want: true},
		{name: "different port", target: "http://203.0.113.9:8081/admin", assetType: "port", assetValue: "203.0.113.9:8080/tcp", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := vulnerabilityMatchesProfile(test.target, test.assetType, test.assetValue); got != test.want {
				t.Fatalf("match = %v, want %v", got, test.want)
			}
		})
	}
}

func TestAssetProfileAndGraphKeepTaskIsolationPostgres(t *testing.T) {
	dsn := os.Getenv("ASSET_CATALOG_INTEGRATION_DSN")
	if dsn == "" {
		t.Skip("set ASSET_CATALOG_INTEGRATION_DSN to run PostgreSQL asset profile coverage")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open integration database: %v", err)
	}
	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("begin integration transaction: %v", tx.Error)
	}
	t.Cleanup(func() { tx.Rollback() })
	if err := tx.AutoMigrate(
		&models.Domain{}, &models.IP{}, &models.Port{}, &models.Site{}, &models.Vulnerability{},
		&models.AssetTag{}, &models.AssetTagRelation{},
	); err != nil {
		t.Fatalf("migrate asset profile integration schema: %v", err)
	}
	previousDB := database.DB
	database.DB = tx
	t.Cleanup(func() { database.DB = previousDB })

	taskA, taskB := uuid.NewString(), uuid.NewString()
	sharedIP := "203.0.113.190"
	domainA := models.Domain{TaskID: taskA, Domain: "app.profile-a.example.co.uk", IPAddress: sharedIP, Source: "integration"}
	domainB := models.Domain{TaskID: taskB, Domain: "app.profile-b.example.co.uk", IPAddress: sharedIP, Source: "integration"}
	ipA := models.IP{TaskID: taskA, IPAddress: sharedIP, Source: "integration"}
	ipB := models.IP{TaskID: taskB, IPAddress: sharedIP, Source: "integration"}
	portA := models.Port{TaskID: taskA, IPAddress: sharedIP, Port: 443, Protocol: "tcp", Service: "https"}
	portB := models.Port{TaskID: taskB, IPAddress: sharedIP, Port: 6379, Protocol: "tcp", Service: "redis"}
	siteA := models.Site{TaskID: taskA, URL: "https://app.profile-a.example.co.uk", IP: sharedIP, StatusCode: 200}
	siteB := models.Site{TaskID: taskB, URL: "http://app.profile-b.example.co.uk:6379", IP: sharedIP, StatusCode: 200}
	for _, value := range []any{&domainA, &domainB, &ipA, &ipB, &portA, &portB, &siteA, &siteB} {
		if err := tx.Create(value).Error; err != nil {
			t.Fatalf("seed isolated profile asset: %v", err)
		}
	}
	vulnerabilities := []models.Vulnerability{
		{TaskID: taskA, URL: "https://" + sharedIP + ":443/admin", Severity: "high", Title: "task A"},
		{TaskID: taskB, URL: "https://" + sharedIP + ":443/admin", Severity: "critical", Title: "task B"},
	}
	if err := tx.Create(&vulnerabilities).Error; err != nil {
		t.Fatalf("seed profile vulnerabilities: %v", err)
	}

	service := NewAssetProfileService()
	profile, err := service.GetAssetProfile("ip", ipA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(profile.Features.OpenPorts) != 1 || profile.Features.OpenPorts[0] != 443 {
		t.Fatalf("task A open ports = %#v, want [443]", profile.Features.OpenPorts)
	}
	if profile.RelatedDomains != 1 || profile.RelatedPorts != 1 || profile.RelatedSites != 1 {
		t.Fatalf("task A related counts = domains:%d ports:%d sites:%d", profile.RelatedDomains, profile.RelatedPorts, profile.RelatedSites)
	}
	if profile.VulnStats.Total != 1 || profile.VulnStats.High != 1 || profile.VulnStats.Critical != 0 {
		t.Fatalf("task A vulnerability stats = %#v", profile.VulnStats)
	}

	relations, err := service.GetAssetRelations("ip", ipA.ID)
	if err != nil {
		t.Fatal(err)
	}
	blockedIDs := map[string]bool{domainB.ID: true, ipB.ID: true, portB.ID: true, siteB.ID: true}
	for _, relation := range relations {
		if blockedIDs[relation.TargetID] {
			t.Fatalf("task B relation leaked into task A profile: %#v", relation)
		}
	}
	if len(relations) != 3 {
		t.Fatalf("task A direct relations = %d, want 3: %#v", len(relations), relations)
	}

	graph, err := service.GetAssetGraph("ip", ipA.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	assertGraphHasNoDanglingEdges(t, graph)
	if len(graph.Nodes) != 4 || len(graph.Edges) != 3 {
		t.Fatalf("depth-1 graph nodes/edges = %d/%d, want 4/3", len(graph.Nodes), len(graph.Edges))
	}
	for _, node := range graph.Nodes {
		if blockedIDs[node.ID] {
			t.Fatalf("task B node leaked into task A graph: %#v", node)
		}
	}
	segment, err := service.AnalyzeCSegment(taskA, sharedIP)
	if err != nil {
		t.Fatal(err)
	}
	if segment.TotalIPs != 1 || segment.TotalPorts != 1 || segment.TotalSites != 1 {
		t.Fatalf("task A C segment totals = IPs:%d ports:%d sites:%d, want 1/1/1", segment.TotalIPs, segment.TotalPorts, segment.TotalSites)
	}
	if len(segment.CommonPorts) != 1 || segment.CommonPorts[0] != 443 {
		t.Fatalf("task A C segment common ports = %#v, want [443]", segment.CommonPorts)
	}
	if _, err := service.GetAssetGraph("unknown", ipA.ID, 1); err == nil {
		t.Fatal("unsupported graph asset type was accepted")
	}
}

func assertGraphHasNoDanglingEdges(t *testing.T, graph *models.AssetGraph) {
	t.Helper()
	nodes := make(map[string]struct{}, len(graph.Nodes))
	for _, node := range graph.Nodes {
		nodes[node.ID] = struct{}{}
	}
	for _, edge := range graph.Edges {
		if _, ok := nodes[edge.Source]; !ok {
			t.Fatalf("graph edge source is missing: %#v", edge)
		}
		if _, ok := nodes[edge.Target]; !ok {
			t.Fatalf("graph edge target is missing: %#v", edge)
		}
	}
}
