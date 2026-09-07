package services

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/reconmaster/backend/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestAssetCanonicalization(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "domain lowercases and trims root dot", got: canonicalDomain(" API.Example.COM. "), want: "api.example.com"},
		{name: "ipv6 uses canonical representation", got: canonicalIP("2001:0db8::1"), want: "2001:db8::1"},
		{name: "site drops default port and root slash", got: canonicalSite("HTTPS://Example.COM:443/"), want: "https://example.com"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("canonical value = %q, want %q", test.got, test.want)
			}
		})
	}
}

func TestParseVulnerabilityTarget(t *testing.T) {
	target := parseVulnerabilityTarget("HTTPS://API.Example.COM:443/admin")
	if target.domain != "api.example.com" {
		t.Fatalf("domain = %q", target.domain)
	}
	if target.siteKey != "https://api.example.com/admin" {
		t.Fatalf("site key = %q", target.siteKey)
	}
	if target.origin != "https://api.example.com" {
		t.Fatalf("origin = %q", target.origin)
	}

	ipTarget := parseVulnerabilityTarget("http://203.0.113.8:8080/status")
	if ipTarget.ip != "203.0.113.8" || ipTarget.portKey != "203.0.113.8:8080/tcp" {
		t.Fatalf("IP target = %#v", ipTarget)
	}
}

func TestCanonicalObservationStateIgnoresRecordMetadata(t *testing.T) {
	first := models.Domain{ID: uuid.NewString(), TaskID: uuid.NewString(), Domain: "API.Example.com", IPAddress: "203.0.113.8", CreatedAt: time.Now()}
	second := first
	second.ID = uuid.NewString()
	second.TaskID = uuid.NewString()
	second.CreatedAt = first.CreatedAt.Add(time.Hour)
	firstPayload, firstPayloadHash, _, firstStateHash, err := marshalObservation("domain", "domain", first)
	if err != nil {
		t.Fatalf("marshal first observation: %v", err)
	}
	secondPayload, secondPayloadHash, _, secondStateHash, err := marshalObservation("domain", "domain", second)
	if err != nil {
		t.Fatalf("marshal second observation: %v", err)
	}
	if firstPayload == secondPayload || firstPayloadHash == secondPayloadHash {
		t.Fatal("raw observation metadata was unexpectedly identical")
	}
	if firstStateHash != secondStateHash {
		t.Fatalf("semantic state hashes differ: %s != %s", firstStateHash, secondStateHash)
	}
}

func TestAssetCatalogLifecyclePostgres(t *testing.T) {
	dsn := os.Getenv("ASSET_CATALOG_INTEGRATION_DSN")
	if dsn == "" {
		t.Skip("set ASSET_CATALOG_INTEGRATION_DSN to run PostgreSQL lifecycle coverage")
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
	if err := tx.AutoMigrate(&models.Vulnerability{}); err != nil {
		t.Fatalf("migrate vulnerability lifecycle schema: %v", err)
	}

	service := NewAssetCatalogService()
	taskA, taskB := uuid.NewString(), uuid.NewString()
	sharedDomain := "catalog-" + uuid.NewString() + ".example"
	sharedIP := "203.0.113.77"
	now := time.Now().UTC().Truncate(time.Second)
	rows := []models.Domain{
		{TaskID: taskA, Domain: sharedDomain, IPAddress: sharedIP, Source: "integration", CreatedAt: now},
		{TaskID: taskB, Domain: sharedDomain, IPAddress: sharedIP, Source: "integration", CDN: true, CreatedAt: now.Add(time.Minute)},
	}
	if err := tx.Create(&rows).Error; err != nil {
		t.Fatalf("seed task assets: %v", err)
	}
	sshPort := models.Port{TaskID: taskA, IPAddress: sharedIP, Port: 22, Protocol: "tcp", Service: "ssh", CreatedAt: now}
	if err := tx.Create(&sshPort).Error; err != nil {
		t.Fatalf("seed task port: %v", err)
	}
	vulnerabilities := []models.Vulnerability{
		{TaskID: taskA, URL: "https://" + sharedDomain + "/login", Severity: "high", Title: "integration high", Type: "integration", CreatedAt: now},
		{TaskID: taskB, URL: "https://" + sharedDomain + "/legacy", Severity: "medium", Title: "integration medium", Type: "integration", CreatedAt: now.Add(time.Minute)},
	}
	if err := tx.Create(&vulnerabilities).Error; err != nil {
		t.Fatalf("seed task vulnerabilities: %v", err)
	}

	if err := service.syncTask(tx, taskA); err != nil {
		t.Fatalf("sync first task: %v", err)
	}
	assertCatalogCounts(t, tx, sharedDomain, 1, 1, 1, 70, 0)
	assertExposureRisk(t, tx, sharedIP, 5, 10)
	assertDiscoveryCount(t, tx, sharedIP, 1)
	var groupedAsset models.AssetEntity
	if err := tx.Where("kind = ? AND canonical_key = ?", "domain", canonicalDomain(sharedDomain)).First(&groupedAsset).Error; err != nil {
		t.Fatalf("load grouped canonical asset: %v", err)
	}
	var firstFinding models.AssetVulnerabilityLink
	if err := tx.Where("asset_id = ? AND vulnerability_id = ?", groupedAsset.ID, vulnerabilities[0].ID).First(&firstFinding).Error; err != nil {
		t.Fatalf("load first vulnerability link: %v", err)
	}
	triage := models.AssetLeadTriage{
		AssetID: groupedAsset.ID, LeadID: "finding:" + firstFinding.ID,
		Status: models.AssetLeadStatusInvestigating, Note: "keep this hunter note",
	}
	if err := tx.Create(&triage).Error; err != nil {
		t.Fatalf("seed finding triage: %v", err)
	}
	var firstDiscovery models.AssetChange
	if err := tx.Where("asset_id = ? AND event_type = ?", groupedAsset.ID, "discovered").First(&firstDiscovery).Error; err != nil {
		t.Fatalf("load first discovery event: %v", err)
	}
	group := models.AssetGroup{Name: "catalog-group-" + uuid.NewString()}
	if err := tx.Create(&group).Error; err != nil {
		t.Fatalf("create integration asset group: %v", err)
	}
	groupItem := models.AssetGroupItem{GroupID: group.ID, AssetType: "canonical", AssetID: groupedAsset.ID}
	if err := tx.Create(&groupItem).Error; err != nil {
		t.Fatalf("add canonical group member: %v", err)
	}
	if err := service.syncTask(tx, taskA); err != nil {
		t.Fatalf("repeat first task sync: %v", err)
	}
	assertCatalogCounts(t, tx, sharedDomain, 1, 1, 1, 70, 0)
	assertExposureRisk(t, tx, sharedIP, 5, 10)
	var repeatedFinding models.AssetVulnerabilityLink
	if err := tx.Where("asset_id = ? AND vulnerability_id = ?", groupedAsset.ID, vulnerabilities[0].ID).First(&repeatedFinding).Error; err != nil {
		t.Fatalf("load repeated vulnerability link: %v", err)
	}
	var repeatedDiscovery models.AssetChange
	if err := tx.Where("asset_id = ? AND event_type = ?", groupedAsset.ID, "discovered").First(&repeatedDiscovery).Error; err != nil {
		t.Fatalf("load repeated discovery event: %v", err)
	}
	if repeatedFinding.ID != firstFinding.ID || repeatedDiscovery.ID != firstDiscovery.ID {
		t.Fatalf("derived identities changed after repeat sync: finding %s -> %s, discovery %s -> %s", firstFinding.ID, repeatedFinding.ID, firstDiscovery.ID, repeatedDiscovery.ID)
	}
	triages, err := LoadAssetLeadTriages(tx, []string{groupedAsset.ID})
	if err != nil {
		t.Fatalf("load preserved triage: %v", err)
	}
	leads := []AssetAttackLead{{AssetID: groupedAsset.ID, ID: "finding:" + repeatedFinding.ID}}
	ApplyAssetLeadTriages(leads, triages)
	if leads[0].TriageStatus != models.AssetLeadStatusInvestigating || leads[0].TriageNote != "keep this hunter note" {
		t.Fatalf("hunter triage was not preserved: %#v", leads[0])
	}

	if err := service.syncTask(tx, taskB); err != nil {
		t.Fatalf("sync shared task: %v", err)
	}
	assertCatalogCounts(t, tx, sharedDomain, 2, 2, 2, 72, 1)
	var modified models.AssetChange
	if err := tx.Where("asset_id = (SELECT id FROM asset_entities WHERE kind = ? AND canonical_key = ?) AND event_type = ?", "domain", canonicalDomain(sharedDomain), "modified").First(&modified).Error; err != nil {
		t.Fatalf("load modified change: %v", err)
	}
	if len(modified.ChangedFields) != 1 || modified.ChangedFields[0] != "cdn" {
		t.Fatalf("changed fields = %#v, want [cdn]", modified.ChangedFields)
	}
	if err := service.syncTask(tx, taskB); err != nil {
		t.Fatalf("repeat shared task sync: %v", err)
	}
	var repeatedModified models.AssetChange
	if err := tx.Where("asset_id = ? AND current_observation_id = ?", modified.AssetID, modified.CurrentObservationID).First(&repeatedModified).Error; err != nil {
		t.Fatalf("load repeated modified event: %v", err)
	}
	if repeatedModified.ID != modified.ID {
		t.Fatalf("modified event identity changed after repeat sync: %s -> %s", modified.ID, repeatedModified.ID)
	}
	if err := service.RemoveTask(tx, taskA); err != nil {
		t.Fatalf("remove first task: %v", err)
	}
	assertCatalogCounts(t, tx, sharedDomain, 1, 1, 1, 45, 0)
	assertExposureRisk(t, tx, sharedIP, 0, -1)
	assertGroupMemberCount(t, tx, group.ID, 1)
	if err := service.RemoveTask(tx, taskB); err != nil {
		t.Fatalf("remove final task: %v", err)
	}
	assertGroupMemberCount(t, tx, group.ID, 0)

	var entityCount, relationCount, findingCount int64
	if err := tx.Model(&models.AssetEntity{}).Where("canonical_key IN ?", []string{canonicalDomain(sharedDomain), canonicalIP(sharedIP)}).Count(&entityCount).Error; err != nil {
		t.Fatalf("count removed entities: %v", err)
	}
	if err := tx.Model(&models.CanonicalAssetRelation{}).
		Joins("JOIN asset_entities source ON source.id = asset_relations.from_asset_id").
		Where("source.canonical_key = ?", canonicalDomain(sharedDomain)).Count(&relationCount).Error; err != nil {
		t.Fatalf("count removed relations: %v", err)
	}
	if err := tx.Model(&models.AssetVulnerabilityLink{}).Where("vulnerability_id IN ?", []string{vulnerabilities[0].ID, vulnerabilities[1].ID}).Count(&findingCount).Error; err != nil {
		t.Fatalf("count removed vulnerability links: %v", err)
	}
	if entityCount != 0 || relationCount != 0 || findingCount != 0 {
		t.Fatalf("final removal left entities=%d relations=%d findings=%d", entityCount, relationCount, findingCount)
	}
}

func assertCatalogCounts(t *testing.T, db *gorm.DB, domain string, wantAssetObservations, wantRelationObservations, wantVulnerabilities int64, wantRisk int, wantChanges int64) {
	t.Helper()
	var entity models.AssetEntity
	if err := db.Where("kind = ? AND canonical_key = ?", "domain", canonicalDomain(domain)).First(&entity).Error; err != nil {
		t.Fatalf("load canonical domain: %v", err)
	}
	if entity.ObservationCount != wantAssetObservations {
		t.Fatalf("asset observation_count=%d, want %d", entity.ObservationCount, wantAssetObservations)
	}
	if entity.VulnerabilityCount != wantVulnerabilities || entity.RiskScore != wantRisk {
		t.Fatalf("asset vulnerabilities=%d risk=%d, want vulnerabilities=%d risk=%d", entity.VulnerabilityCount, entity.RiskScore, wantVulnerabilities, wantRisk)
	}
	if entity.ChangeCount != wantChanges {
		t.Fatalf("asset change_count=%d, want %d", entity.ChangeCount, wantChanges)
	}
	var relation models.CanonicalAssetRelation
	if err := db.Where("from_asset_id = ? AND relation_type = ?", entity.ID, "resolves_to").First(&relation).Error; err != nil {
		t.Fatalf("load canonical relation: %v", err)
	}
	if relation.ObservationCount != wantRelationObservations {
		t.Fatalf("relation observation_count=%d, want %d", relation.ObservationCount, wantRelationObservations)
	}
}

func assertExposureRisk(t *testing.T, db *gorm.DB, ip string, wantIPRisk, wantPortRisk int) {
	t.Helper()
	var ipEntity models.AssetEntity
	if err := db.Where("kind = ? AND canonical_key = ?", "ip", canonicalIP(ip)).First(&ipEntity).Error; err != nil {
		t.Fatalf("load canonical IP: %v", err)
	}
	if ipEntity.RiskScore != wantIPRisk {
		t.Fatalf("IP risk=%d, want %d", ipEntity.RiskScore, wantIPRisk)
	}
	var portEntity models.AssetEntity
	result := db.Where("kind = ? AND canonical_key = ?", "port", net.JoinHostPort(canonicalIP(ip), "22")+"/tcp").Limit(1).Find(&portEntity)
	if result.Error != nil {
		t.Fatalf("load canonical port: %v", result.Error)
	}
	if wantPortRisk < 0 {
		if result.RowsAffected != 0 {
			t.Fatalf("canonical port still exists with risk=%d", portEntity.RiskScore)
		}
		return
	}
	if result.RowsAffected != 1 || portEntity.RiskScore != wantPortRisk {
		t.Fatalf("port rows=%d risk=%d, want rows=1 risk=%d", result.RowsAffected, portEntity.RiskScore, wantPortRisk)
	}
}

func assertDiscoveryCount(t *testing.T, db *gorm.DB, canonicalKey string, want int64) {
	t.Helper()
	var count int64
	if err := db.Model(&models.AssetChange{}).
		Joins("JOIN asset_entities ON asset_entities.id = asset_changes.asset_id").
		Where("asset_entities.canonical_key = ? AND asset_changes.event_type = ?", canonicalKey, "discovered").Count(&count).Error; err != nil {
		t.Fatalf("count discovery events: %v", err)
	}
	if count != want {
		t.Fatalf("discovery count=%d, want %d", count, want)
	}
}

func assertGroupMemberCount(t *testing.T, db *gorm.DB, groupID string, want int64) {
	t.Helper()
	var count int64
	if err := db.Model(&models.AssetGroupItem{}).Where("group_id = ?", groupID).Count(&count).Error; err != nil {
		t.Fatalf("count group members: %v", err)
	}
	if count != want {
		t.Fatalf("group member count=%d, want %d", count, want)
	}
}
