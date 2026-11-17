package agentconfig_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/msaif95/opamp-backend/internal/agentconfig"
	"github.com/msaif95/opamp-backend/internal/testdb"
)

const body = "receivers:\n  otlp:\nexporters:\n  debug:\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [debug]\n"

func TestConfigVersioning(t *testing.T) {
	db, _ := testdb.Open(t)
	s := agentconfig.NewService(db, nil)
	ctx := context.Background()

	tmpl, v1, err := s.Create(ctx, nil, "prod", "", body, "alice", nil)
	if err != nil || v1.Version != 1 {
		t.Fatalf("create: %v", err)
	}
	if _, _, err := s.Create(ctx, nil, "prod", "", body, "alice", nil); !errors.Is(err, agentconfig.ErrNameTaken) {
		t.Errorf("duplicate name: err = %v", err)
	}
	var invalid *agentconfig.InvalidError
	if _, _, err := s.Create(ctx, nil, "bad", "", "receivers: [", "alice", nil); !errors.As(err, &invalid) {
		t.Errorf("invalid body: err = %v", err)
	}
	if _, err := s.AddVersion(ctx, tmpl.ID, body, "", "bob", nil); !errors.Is(err, agentconfig.ErrUnchanged) {
		t.Errorf("identical body: err = %v", err)
	}
	v2, err := s.AddVersion(ctx, tmpl.ID, body+"# tweak\n", "tweak", "bob", nil)
	if err != nil || v2.Version != 2 {
		t.Fatalf("add version: %+v, %v", v2, err)
	}

	got, versions, err := s.Get(ctx, tmpl.ID)
	if err != nil || got.LatestVersion != 2 || len(versions) != 2 || versions[0].Version != 2 || versions[0].Body != "" {
		t.Fatalf("get: %+v %+v %v", got, versions, err)
	}
	if v, err := s.VersionByNumber(ctx, tmpl.ID, 1); err != nil || v.Body != body {
		t.Fatalf("version 1 body: %v", err)
	}

	// Git-sourced configs are read-only through the service.
	if _, err := db.Exec(ctx, `UPDATE config_templates SET origin = 'git' WHERE id = $1`, tmpl.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddVersion(ctx, tmpl.ID, body+"# again\n", "", "bob", nil); !errors.Is(err, agentconfig.ErrReadOnly) {
		t.Errorf("git-sourced edit: err = %v", err)
	}
}

func TestDeleteRefusedWhileAssigned(t *testing.T) {
	db, _ := testdb.Open(t)
	s := agentconfig.NewService(db, nil)
	ctx := context.Background()
	tmpl, v1, err := s.Create(ctx, nil, "prod", "", body, "alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, `INSERT INTO agents (instance_uid, auth_mode, desired_config_version_id) VALUES (gen_random_uuid(), 'api_key', $1)`, v1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, tmpl.ID); !errors.Is(err, agentconfig.ErrInUse) {
		t.Fatalf("delete while assigned: err = %v", err)
	}
	if _, err := db.Exec(ctx, `DELETE FROM agents`); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, tmpl.ID); err != nil {
		t.Fatalf("delete once unassigned: %v", err)
	}
	if err := s.Delete(ctx, tmpl.ID); !errors.Is(err, agentconfig.ErrNotFound) {
		t.Fatalf("delete again: err = %v", err)
	}
}

func TestBuilderSpecIsStoredWithTheVersion(t *testing.T) {
	db, _ := testdb.Open(t)
	s := agentconfig.NewService(db, nil)
	ctx := context.Background()
	spec := []byte(`{"sources": [{"type": "otlp"}]}`)
	tmpl, v1, err := s.Create(ctx, nil, "built", "", body, "alice", spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddVersion(ctx, tmpl.ID, body+"# by hand\n", "", "bob", nil); err != nil {
		t.Fatal(err)
	}
	got, err := s.VersionByNumber(ctx, tmpl.ID, 1)
	if err != nil || !strings.Contains(string(got.BuilderSpec), `"otlp"`) {
		t.Fatalf("builder spec of v1 = %q, err %v", got.BuilderSpec, err)
	}
	if byID, _ := s.Version(ctx, v1.ID); len(byID.BuilderSpec) == 0 {
		t.Error("builder spec missing when loading by ID")
	}
	if hand, _ := s.VersionByNumber(ctx, tmpl.ID, 2); len(hand.BuilderSpec) != 0 {
		t.Errorf("hand-written version has a builder spec: %q", hand.BuilderSpec)
	}
	// The version list carries no bodies and no specs.
	_, versions, _ := s.Get(ctx, tmpl.ID)
	if len(versions[1].BuilderSpec) != 0 {
		t.Error("version list should not carry builder specs")
	}
}

const baseBody = "receivers:\n  otlp:\nprocessors:\n  batch:\n    timeout: 5s\nexporters:\n  debug:\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      processors: [batch]\n      exporters: [debug]\n"

func TestDerivedConfigs(t *testing.T) {
	db, _ := testdb.Open(t)
	s := agentconfig.NewService(db, nil)
	ctx := context.Background()
	var project uuid.UUID
	if err := db.QueryRow(ctx, `INSERT INTO projects (name, created_by) VALUES ('A', 'root') RETURNING id`).Scan(&project); err != nil {
		t.Fatal(err)
	}
	base, _, err := s.Create(ctx, &project, "base", "", baseBody, "alice", nil)
	if err != nil {
		t.Fatal(err)
	}

	prod, v1, err := s.CreateDerived(ctx, &project, "prod", "", base.ID, "processors:\n  batch:\n    timeout: 10s\n", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(v1.Body, "timeout: 10s") || !strings.HasPrefix(v1.Body, `# Derived from the base config "base"`) || *v1.BaseVersion != 1 || prod.Base.ID != base.ID {
		t.Fatalf("derived v1 = %+v", v1)
	}
	// What cannot be a base, and what a derived config cannot take.
	if _, _, err := s.CreateDerived(ctx, &project, "x", "", prod.ID, "", "alice"); !errors.Is(err, agentconfig.ErrBase) {
		t.Errorf("deriving from a derived config: %v", err)
	}
	if _, _, err := s.CreateDerived(ctx, nil, "x", "", base.ID, "", "alice"); !errors.Is(err, agentconfig.ErrBase) {
		t.Errorf("deriving across projects: %v", err)
	}
	var invalid *agentconfig.InvalidError
	if _, _, err := s.CreateDerived(ctx, &project, "x", "", base.ID, "exporters:\n  debug: ~\n", "alice"); !errors.As(err, &invalid) {
		t.Errorf("overrides that break the config: %v", err)
	}
	if _, err := s.AddVersion(ctx, prod.ID, baseBody, "", "alice", nil); !errors.Is(err, agentconfig.ErrDerived) {
		t.Errorf("whole body on a derived config: %v", err)
	}
	if _, err := s.AddDerivedVersion(ctx, base.ID, nil, "", "alice"); !errors.Is(err, agentconfig.ErrNotDerived) {
		t.Errorf("rebuilding an ordinary config: %v", err)
	}
	if err := s.Delete(ctx, base.ID); !errors.Is(err, agentconfig.ErrHasDerived) {
		t.Errorf("deleting a base in use: %v", err)
	}

	// Nothing to do while the base has not moved; new overrides make a new version on the same base.
	if _, err := s.AddDerivedVersion(ctx, prod.ID, nil, "", "alice"); !errors.Is(err, agentconfig.ErrUnchanged) {
		t.Errorf("rebuild with nothing new: %v", err)
	}
	over := "processors:\n  batch:\n    timeout: 20s\n"
	v2, err := s.AddDerivedVersion(ctx, prod.ID, &over, "slower", "bob")
	if err != nil || v2.Version != 2 || !strings.Contains(v2.Body, "timeout: 20s") || *v2.BaseVersion != 1 {
		t.Fatalf("new overrides: %+v, %v", v2, err)
	}
	got, err := s.VersionByNumber(ctx, prod.ID, 2)
	if err != nil || got.Overrides != over || *got.BaseVersion != 1 {
		t.Errorf("stored version = %+v, %v", got, err)
	}

	// A second derived config that overrides nothing the next base change touches.
	if _, _, err := s.CreateDerived(ctx, &project, "dev", "", base.ID, "", "alice"); err != nil {
		t.Fatal(err)
	}
	b, _, _ := s.Get(ctx, base.ID)
	if len(b.Derived) != 2 || !b.Derived[0].UpToDate || !b.Derived[1].UpToDate {
		t.Fatalf("derived before the base changes = %+v", b.Derived)
	}

	// The base changes something prod overrides (timeout) and something it does not (a new exporter setting).
	if _, err := s.AddVersion(ctx, base.ID, strings.Replace(strings.Replace(baseBody, "timeout: 5s", "timeout: 7s", 1), "debug:", "debug:\n    verbosity: detailed", 1), "", "alice", nil); err != nil {
		t.Fatal(err)
	}
	b, _, _ = s.Get(ctx, base.ID)
	if b.Derived[0].Name != "dev" || b.Derived[0].UpToDate || b.Derived[1].UpToDate || b.Derived[1].BaseVersion != 1 {
		t.Errorf("derived after the base changed = %+v", b.Derived)
	}
	// Derived versions already made are untouched: nothing follows the base by itself.
	if still, _ := s.VersionByNumber(ctx, prod.ID, 2); still.Body != v2.Body {
		t.Error("a saved derived version changed when its base did")
	}
	results, err := s.UpdateDerived(ctx, base.ID, "carol")
	if err != nil || len(results) != 2 || results[0].Version != 2 || results[1].Version != 3 {
		t.Fatalf("update derived = %+v, %v", results, err)
	}
	v3, _ := s.VersionByNumber(ctx, prod.ID, 3)
	if !strings.Contains(v3.Body, "timeout: 20s") || !strings.Contains(v3.Body, "verbosity: detailed") || *v3.BaseVersion != 2 || v3.Overrides != over ||
		v3.Description != "Updated from base v2" || v3.Author != "carol" {
		t.Errorf("rebuilt prod = %+v", v3)
	}
	b, _, _ = s.Get(ctx, base.ID)
	if !b.Derived[0].UpToDate || !b.Derived[1].UpToDate {
		t.Errorf("derived after updating = %+v", b.Derived)
	}
	if again, _ := s.UpdateDerived(ctx, base.ID, "carol"); again[0].Version != 0 || again[1].Version != 0 || again[0].Error != "" {
		t.Errorf("updating twice = %+v", again)
	}

	// A base change that breaks one derived config is reported for it and leaves it alone; the others still update.
	keepsBatch := "service:\n  pipelines:\n    logs:\n      processors: [batch]\n"
	if _, err := s.AddDerivedVersion(ctx, prod.ID, &keepsBatch, "", "bob"); err != nil {
		t.Fatal(err)
	}
	noProcessors := "receivers:\n  otlp:\nexporters:\n  debug:\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [debug]\n"
	if _, err := s.AddVersion(ctx, base.ID, noProcessors, "", "alice", nil); err != nil {
		t.Fatal(err)
	}
	results, err = s.UpdateDerived(ctx, base.ID, "carol")
	if err != nil || results[0].Name != "dev" || results[0].Version == 0 || results[0].Error != "" {
		t.Errorf("dev after the base dropped its processors = %+v, %v", results, err)
	}
	if results[1].Name != "prod" || results[1].Version != 0 || results[1].Error == "" || len(results[1].Issues) == 0 {
		t.Errorf("prod, whose overrides still name the dropped processor = %+v", results[1])
	}
	if latest, _, _ := s.Get(ctx, prod.ID); latest.LatestVersion != 4 {
		t.Errorf("prod is at v%d, want it left at v4", latest.LatestVersion)
	}

	// Lists carry the base; a base can be deleted once nothing derives from it.
	list, _ := s.List(ctx, allProjects{})
	for _, c := range list {
		if (c.Name == "base") != (c.Base == nil) {
			t.Errorf("%s base = %+v", c.Name, c.Base)
		}
	}
	for _, id := range []uuid.UUID{prod.ID, list[1].ID} {
		if err := s.Delete(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Delete(ctx, base.ID); err != nil {
		t.Errorf("deleting a base with nothing derived: %v", err)
	}
}

type allProjects struct{}

func (allProjects) Where(string, int) (string, []any) { return "TRUE", nil }
