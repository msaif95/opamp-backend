// Package testdb gives integration tests a clean Postgres schema and Redis
// database. Tests using it are skipped unless OPAMP_TEST_POSTGRES_DSN is
// set; run them with `make test-integration`.
package testdb

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/msaif95/opamp-backend/internal/store"
)

// Open returns a migrated, emptied database and an emptied Redis database.
// The DSN must point at a database reserved for tests: every table is truncated.
func Open(t *testing.T) (*pgxpool.Pool, *redis.Client) {
	t.Helper()
	dsn := os.Getenv("OPAMP_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("OPAMP_TEST_POSTGRES_DSN not set; run `make test-integration`")
	}
	ctx := context.Background()

	_, file, _, _ := runtime.Caller(0)
	migrations := filepath.Join(filepath.Dir(file), "..", "..", "migrations")
	if err := store.Migrate(dsn, migrations); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, dsn, 10)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	_, err = db.Exec(ctx, `TRUNCATE agents, config_templates, agent_groups, rollouts, credentials, users, audit_events, settings CASCADE`)
	if err != nil {
		t.Fatal(err)
	}

	redisDB := 15
	if v := os.Getenv("OPAMP_TEST_REDIS_DB"); v != "" {
		if redisDB, err = strconv.Atoi(v); err != nil {
			t.Fatal(err)
		}
	}
	addr := os.Getenv("OPAMP_TEST_REDIS_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr, DB: redisDB})
	t.Cleanup(func() { _ = rdb.Close() })
	if err := rdb.FlushDB(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	return db, rdb
}
