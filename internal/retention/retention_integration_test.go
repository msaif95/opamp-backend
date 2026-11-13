package retention_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/msaif95/opamp-backend/internal/retention"
	"github.com/msaif95/opamp-backend/internal/testdb"
)

func TestPruneDeletesOnlyWhatIsPastRetention(t *testing.T) {
	db, rdb := testdb.Open(t)
	ctx := context.Background()
	mustExec := func(sql string) {
		t.Helper()
		if _, err := db.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	mustExec(`INSERT INTO audit_events (occurred_at, actor, actor_auth, action, target_type) VALUES
		(now() - interval '400 days', 'old', 'local', 'x', 'y'), (now() - interval '10 days', 'recent', 'local', 'x', 'y')`)
	mustExec(`INSERT INTO agents (instance_uid, auth_mode, connected, last_seen, attributes) VALUES
		(gen_random_uuid(), 'api_key', FALSE, now() - interval '60 days', '{"host.name":"gone"}'),
		(gen_random_uuid(), 'api_key', FALSE, now() - interval '5 days',  '{"host.name":"briefly-off"}'),
		(gen_random_uuid(), 'api_key', TRUE,  now() - interval '60 days', '{"host.name":"connected-stale"}')`)
	mustExec(`INSERT INTO config_templates (id, name) VALUES ('00000000-0000-0000-0000-0000000000aa', 'c')`)
	mustExec(`INSERT INTO config_versions (id, template_id, version, body, body_hash, author) VALUES
		('00000000-0000-0000-0000-0000000000bb', '00000000-0000-0000-0000-0000000000aa', 1, 'x', 'h', 'a')`)
	mustExec(`INSERT INTO rollouts (config_version_id, selector, status, created_by, finished_at) VALUES
		('00000000-0000-0000-0000-0000000000bb', '{}', 'completed', 'old',     now() - interval '300 days'),
		('00000000-0000-0000-0000-0000000000bb', '{}', 'completed', 'recent',  now() - interval '3 days'),
		('00000000-0000-0000-0000-0000000000bb', '{}', 'running',   'running', NULL)`)

	job := &retention.Job{DB: db, Redis: rdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		AuditDays: 365, RolloutDays: 180, AgentDays: 30}
	if err := job.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	for query, want := range map[string]string{
		`SELECT string_agg(actor, ',' ORDER BY actor) FROM audit_events`:                                 "recent",
		`SELECT string_agg(attributes->>'host.name', ',' ORDER BY attributes->>'host.name') FROM agents`: "briefly-off,connected-stale",
		`SELECT string_agg(created_by, ',' ORDER BY created_by) FROM rollouts`:                           "recent,running",
	} {
		var got string
		if err := db.QueryRow(ctx, query).Scan(&got); err != nil || got != want {
			t.Errorf("%s = %q (err %v), want %q", query, got, err, want)
		}
	}

	// 0 days means keep forever.
	mustExec(`INSERT INTO audit_events (occurred_at, actor, actor_auth, action, target_type) VALUES (now() - interval '9000 days', 'ancient', 'local', 'x', 'y')`)
	if err := (&retention.Job{DB: db, Redis: rdb, Log: job.Log}).Prune(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = db.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE actor = 'ancient'`).Scan(&n)
	if n != 1 {
		t.Error("retention of 0 days deleted data")
	}
}
