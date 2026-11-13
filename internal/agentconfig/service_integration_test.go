package agentconfig_test

import (
	"context"
	"errors"
	"testing"

	"github.com/msaif95/opamp-backend/internal/agentconfig"
	"github.com/msaif95/opamp-backend/internal/testdb"
)

const body = "receivers:\n  otlp:\nexporters:\n  debug:\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [debug]\n"

func TestConfigVersioning(t *testing.T) {
	db, _ := testdb.Open(t)
	s := agentconfig.NewService(db)
	ctx := context.Background()

	tmpl, v1, err := s.Create(ctx, "prod", "", body, "alice")
	if err != nil || v1.Version != 1 {
		t.Fatalf("create: %v", err)
	}
	if _, _, err := s.Create(ctx, "prod", "", body, "alice"); !errors.Is(err, agentconfig.ErrNameTaken) {
		t.Errorf("duplicate name: err = %v", err)
	}
	var invalid *agentconfig.InvalidError
	if _, _, err := s.Create(ctx, "bad", "", "receivers: [", "alice"); !errors.As(err, &invalid) {
		t.Errorf("invalid body: err = %v", err)
	}
	if _, err := s.AddVersion(ctx, tmpl.ID, body, "", "bob"); !errors.Is(err, agentconfig.ErrUnchanged) {
		t.Errorf("identical body: err = %v", err)
	}
	v2, err := s.AddVersion(ctx, tmpl.ID, body+"# tweak\n", "tweak", "bob")
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
	if _, err := s.AddVersion(ctx, tmpl.ID, body+"# again\n", "", "bob"); !errors.Is(err, agentconfig.ErrReadOnly) {
		t.Errorf("git-sourced edit: err = %v", err)
	}
}

func TestDeleteRefusedWhileAssigned(t *testing.T) {
	db, _ := testdb.Open(t)
	s := agentconfig.NewService(db)
	ctx := context.Background()
	tmpl, v1, err := s.Create(ctx, "prod", "", body, "alice")
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
