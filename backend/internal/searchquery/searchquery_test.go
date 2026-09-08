package searchquery

import (
	"strings"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func dryRunDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.New(postgres.Config{DSN: "host=localhost user=test dbname=test", PreferSimpleProtocol: true}), &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestApplyBooleanExpression(t *testing.T) {
	query, err := Apply(dryRunDB(t).Table("tasks"), `name:"prod api" && !status:failed || target:10.0`, map[string]string{"name": "name", "status": "status", "target": "target"}, []string{"name", "target"})
	if err != nil {
		t.Fatal(err)
	}
	statement := query.Find(&[]map[string]any{}).Statement
	if !strings.Contains(statement.SQL.String(), "NOT") || len(statement.Vars) != 3 {
		t.Fatalf("unexpected SQL %s vars=%v", statement.SQL.String(), statement.Vars)
	}
}

func TestApplyRejectsUnknownField(t *testing.T) {
	_, err := Apply(dryRunDB(t), "secret:value", map[string]string{"name": "name"}, []string{"name"})
	if err == nil || !strings.Contains(err.Error(), "Fields Not Supported") {
		t.Fatalf("got %v", err)
	}
}

func TestApplyReportsSyntaxPosition(t *testing.T) {
	_, err := Apply(dryRunDB(t), `name:"broken`, map[string]string{"name": "name"}, []string{"name"})
	if err == nil || !strings.Contains(err.Error(), "Location") {
		t.Fatalf("got %v", err)
	}
}

func TestApplyExactAndNotEqual(t *testing.T) {
	query, err := Apply(dryRunDB(t).Table("tasks"), `status=running && name!="legacy task"`, map[string]string{"status": "status", "name": "name"}, []string{"name"})
	if err != nil {
		t.Fatal(err)
	}
	statement := query.Find(&[]map[string]any{}).Statement
	if !strings.Contains(statement.SQL.String(), " = ") || !strings.Contains(statement.SQL.String(), "NOT") {
		t.Fatalf("unexpected SQL %s", statement.SQL.String())
	}
	if len(statement.Vars) != 2 || statement.Vars[0] != "running" || statement.Vars[1] != "legacy task" {
		t.Fatalf("unexpected vars %v", statement.Vars)
	}
}
