package registry_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-telemetry/opamp-go/protobufs"

	"github.com/msaif95/opamp-backend/internal/registry"
	"github.com/msaif95/opamp-backend/internal/testdb"
)

var ctx = context.Background()

const acceptsRemoteConfig = uint64(protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig)

func kv(k, v string) *protobufs.KeyValue {
	return &protobufs.KeyValue{Key: k, Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: v}}}
}

func fullReport(host string, attrs ...*protobufs.KeyValue) *protobufs.AgentToServer {
	return &protobufs.AgentToServer{
		Capabilities: acceptsRemoteConfig,
		AgentDescription: &protobufs.AgentDescription{
			IdentifyingAttributes:    []*protobufs.KeyValue{kv("service.version", "1.2.3")},
			NonIdentifyingAttributes: append([]*protobufs.KeyValue{kv("host.name", host)}, attrs...),
		},
		Health: &protobufs.ComponentHealth{Healthy: true, Status: "ok"},
	}
}

var apiKey = registry.Identity{AuthMode: "api_key"}

func mustReport(t *testing.T, r *registry.Registry, uid uuid.UUID, msg *protobufs.AgentToServer) registry.ConfigState {
	t.Helper()
	st, err := r.Report(ctx, uid, apiKey, msg)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func lastSeen(t *testing.T, db *pgxpool.Pool, uid uuid.UUID) time.Time {
	t.Helper()
	var ts time.Time
	if err := db.QueryRow(ctx, `SELECT last_seen FROM agents WHERE instance_uid = $1`, uid).Scan(&ts); err != nil {
		t.Fatal(err)
	}
	return ts
}

func TestReportUpsertsAndKeepsOmittedFields(t *testing.T) {
	db, rdb := testdb.Open(t)
	r := registry.New(db, rdb, "replica-a", time.Minute)
	uid := uuid.New()

	mustReport(t, r, uid, fullReport("host-1", kv("env", "prod")))
	a, err := r.Get(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Connected || a.Attributes["env"] != "prod" || a.Attributes["host.name"] != "host-1" ||
		a.AgentVersion == nil || *a.AgentVersion != "1.2.3" || a.Healthy == nil || !*a.Healthy || a.RemoteConfigStatus != "unset" {
		t.Fatalf("after first report: %+v", a)
	}
	if route, _ := r.Route(ctx, uid); route != "replica-a" {
		t.Fatalf("route = %q", route)
	}

	// A later message carrying only health must not wipe the description.
	mustReport(t, r, uid, &protobufs.AgentToServer{Capabilities: acceptsRemoteConfig,
		Health: &protobufs.ComponentHealth{Healthy: false, Status: "degraded", LastError: "boom"}})
	a, _ = r.Get(ctx, uid)
	if a.Attributes["env"] != "prod" || *a.Healthy || *a.HealthLastError != "boom" {
		t.Fatalf("after health-only report: %+v", a)
	}
}

func TestRemoteConfigStatusWithoutHashClearsStoredHash(t *testing.T) {
	db, rdb := testdb.Open(t)
	r := registry.New(db, rdb, "replica-a", time.Minute)
	uid := uuid.New()
	mustReport(t, r, uid, fullReport("host-1"))

	st := mustReport(t, r, uid, &protobufs.AgentToServer{Capabilities: acceptsRemoteConfig, RemoteConfigStatus: &protobufs.RemoteConfigStatus{
		LastRemoteConfigHash: []byte("hash-1"), Status: protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLIED}})
	if string(st.RemoteConfigHash) != "hash-1" {
		t.Fatalf("hash not stored: %q", st.RemoteConfigHash)
	}

	// An agent that lost its state reports UNSET with no hash. Keeping the
	// old hash would make the server believe it still has the config.
	st = mustReport(t, r, uid, &protobufs.AgentToServer{Capabilities: acceptsRemoteConfig, RemoteConfigStatus: &protobufs.RemoteConfigStatus{}})
	if len(st.RemoteConfigHash) != 0 {
		t.Fatalf("stale hash kept after state loss: %q", st.RemoteConfigHash)
	}
}

func TestHeartbeatsAreBufferedNotWritten(t *testing.T) {
	db, rdb := testdb.Open(t)
	r := registry.New(db, rdb, "replica-a", time.Minute)
	uid := uuid.New()
	mustReport(t, r, uid, fullReport("host-1"))
	if _, err := db.Exec(ctx, `UPDATE agents SET last_seen = now() - interval '1 hour' WHERE instance_uid = $1`, uid); err != nil {
		t.Fatal(err)
	}
	before := lastSeen(t, db, uid)

	heartbeat := &protobufs.AgentToServer{Capabilities: acceptsRemoteConfig, SequenceNum: 7}
	mustReport(t, r, uid, heartbeat)
	if !lastSeen(t, db, uid).Equal(before) {
		t.Fatal("heartbeat wrote to Postgres immediately")
	}
	if err := r.FlushHeartbeats(ctx); err != nil {
		t.Fatal(err)
	}
	if !lastSeen(t, db, uid).After(before) {
		t.Fatal("flush did not update last_seen")
	}

	// A heartbeat from an agent the database thinks is offline takes the full path and brings it back.
	if _, err := db.Exec(ctx, `UPDATE agents SET connected = FALSE WHERE instance_uid = $1`, uid); err != nil {
		t.Fatal(err)
	}
	mustReport(t, r, uid, heartbeat)
	if a, _ := r.Get(ctx, uid); !a.Connected {
		t.Fatal("heartbeat did not bring an offline agent back")
	}

	// A heartbeat from an unknown agent creates it rather than failing.
	unknown := uuid.New()
	mustReport(t, r, unknown, heartbeat)
	if _, err := r.Get(ctx, unknown); err != nil {
		t.Fatalf("unknown agent not created: %v", err)
	}
}

func TestDisconnectedOnlyByOwningReplica(t *testing.T) {
	db, rdb := testdb.Open(t)
	a := registry.New(db, rdb, "replica-a", time.Minute)
	b := registry.New(db, rdb, "replica-b", time.Minute)
	uid := uuid.New()
	mustReport(t, a, uid, fullReport("host-1"))
	// The agent reconnects to replica B before A notices the old connection closed.
	mustReport(t, b, uid, fullReport("host-1"))

	if err := a.Disconnected(ctx, uid); err != nil {
		t.Fatal(err)
	}
	if ag, _ := a.Get(ctx, uid); !ag.Connected {
		t.Fatal("stale disconnect from the old replica marked a reconnected agent offline")
	}
	if err := b.Disconnected(ctx, uid); err != nil {
		t.Fatal(err)
	}
	if ag, _ := a.Get(ctx, uid); ag.Connected {
		t.Fatal("disconnect from the owning replica was ignored")
	}
}

func TestSweepSparesAgentsWithLiveRoute(t *testing.T) {
	db, rdb := testdb.Open(t)
	r := registry.New(db, rdb, "replica-a", time.Minute)
	gone, alive := uuid.New(), uuid.New()
	mustReport(t, r, gone, fullReport("gone"))
	mustReport(t, r, alive, fullReport("alive"))
	// Both look stale in Postgres (as after a database outage), but only one has lost its route.
	if _, err := db.Exec(ctx, `UPDATE agents SET last_seen = now() - interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	if err := rdb.Del(ctx, "opamp:route:"+gone.String()).Err(); err != nil {
		t.Fatal(err)
	}

	n, err := r.SweepOffline(ctx, 90*time.Second)
	if err != nil || n != 1 {
		t.Fatalf("swept %d agents, err %v; want 1", n, err)
	}
	if a, _ := r.Get(ctx, gone); a.Connected {
		t.Error("agent without a route was not swept")
	}
	if a, _ := r.Get(ctx, alive); !a.Connected {
		t.Error("agent with a live route was swept")
	}
}

func TestListFiltersSortsAndFacets(t *testing.T) {
	db, rdb := testdb.Open(t)
	r := registry.New(db, rdb, "replica-a", time.Minute)
	for i, env := range []string{"prod", "prod", "dev"} {
		mustReport(t, r, uuid.New(), fullReport("host-"+string(rune('c'-i)), kv("env", env)))
	}

	agents, total, err := r.List(ctx, registry.ListFilter{Attributes: map[string]string{"env": "prod"}})
	if err != nil || total != 2 || len(agents) != 2 || agents[0].Attributes["host.name"] != "host-b" {
		t.Fatalf("filtered list: total %d, first %v, err %v", total, agents, err)
	}
	agents, _, _ = r.List(ctx, registry.ListFilter{Sort: registry.SortName, Desc: true})
	if agents[0].Attributes["host.name"] != "host-c" {
		t.Fatalf("descending sort: first is %q", agents[0].Attributes["host.name"])
	}

	facets, err := r.Facets(ctx, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, f := range facets {
		if f.Key == "env" {
			for _, v := range f.Values {
				got[v.Value] = v.Count
			}
		}
	}
	if got["prod"] != 2 || got["dev"] != 1 {
		t.Fatalf("env facet = %v", got)
	}
	// host.name is different on every agent: an identifier, not something to target groups by.
	for _, f := range facets {
		if f.Key == "host.name" {
			t.Fatalf("identifier attribute offered as a facet: %+v", f)
		}
	}
}

func TestSetDesiredConfigNeedsCapability(t *testing.T) {
	db, rdb := testdb.Open(t)
	r := registry.New(db, rdb, "replica-a", time.Minute)
	uid := uuid.New()
	msg := fullReport("host-1")
	msg.Capabilities = 0
	mustReport(t, r, uid, msg)

	if err := r.SetDesiredConfig(ctx, uid, uuid.New()); !errors.Is(err, registry.ErrRemoteConfigUnsupported) {
		t.Fatalf("err = %v, want ErrRemoteConfigUnsupported", err)
	}
	if err := r.SetDesiredConfig(ctx, uuid.New(), uuid.New()); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

type selector map[string][]string

func (s selector) Where(col string, first int) (string, []any) {
	return col + "->>'env' = ANY($" + string(rune('0'+first)) + "::text[])", []any{s["env"]}
}

func TestListBySelectorCombinesWithOtherFilters(t *testing.T) {
	db, rdb := testdb.Open(t)
	r := registry.New(db, rdb, "replica-a", time.Minute)
	for _, env := range []string{"prod", "staging", "dev", "prod"} {
		mustReport(t, r, uuid.New(), fullReport("h-"+env, kv("env", env)))
	}
	connected := true
	agents, total, err := r.List(ctx, registry.ListFilter{Selector: selector{"env": {"prod", "staging"}}, Connected: &connected, Limit: 2})
	if err != nil || total != 3 || len(agents) != 2 {
		t.Fatalf("total %d, page %d, err %v; want 3 matching, page of 2", total, len(agents), err)
	}
}

func TestSetPaused(t *testing.T) {
	db, rdb := testdb.Open(t)
	r := registry.New(db, rdb, "replica-a", time.Minute)
	uid := uuid.New()
	mustReport(t, r, uid, fullReport("host-1"))

	// Nothing to come back to yet.
	if err := r.SetPaused(ctx, uid, true); !errors.Is(err, registry.ErrNoConfig) {
		t.Fatalf("pause without a config: %v", err)
	}
	if err := r.SetPaused(ctx, uuid.New(), true); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("pause unknown agent: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO config_templates (id, name) VALUES ('00000000-0000-0000-0000-0000000000aa', 'c')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO config_versions (id, template_id, version, body, body_hash, author)
		VALUES ('00000000-0000-0000-0000-0000000000bb', '00000000-0000-0000-0000-0000000000aa', 1, 'x', 'h', 'a')`); err != nil {
		t.Fatal(err)
	}
	if err := r.SetDesiredConfig(ctx, uid, uuid.MustParse("00000000-0000-0000-0000-0000000000bb")); err != nil {
		t.Fatal(err)
	}
	for _, paused := range []bool{true, false} {
		if err := r.SetPaused(ctx, uid, paused); err != nil {
			t.Fatal(err)
		}
		st, _ := r.ConfigState(ctx, uid)
		a, _ := r.Get(ctx, uid)
		// The assigned config is kept while paused, so resume has something to restore.
		if st.Paused != paused || a.Paused != paused || st.DesiredConfigVersionID == nil {
			t.Fatalf("paused=%v: state %+v, agent paused %v", paused, st, a.Paused)
		}
	}
}

// Every change to an agent leaves an entry in its history, whichever code path made it.
func TestAgentHistory(t *testing.T) {
	db, rdb := testdb.Open(t)
	r := registry.New(db, rdb, "replica-a", time.Minute)
	uid := uuid.New()
	kinds := func() []string {
		t.Helper()
		events, err := r.Events(ctx, uid, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]string, len(events))
		for i, e := range events { // newest first; reverse into the order things happened
			out[len(events)-1-i] = e.Kind
		}
		return out
	}
	last := func() registry.HistoryEvent {
		t.Helper()
		events, _ := r.Events(ctx, uid, 0, 1)
		return events[0]
	}
	expect := func(step string, want ...string) {
		t.Helper()
		got := kinds()
		if len(got) < len(want) || !slices.Equal(got[len(got)-len(want):], want) {
			t.Fatalf("%s: history ends with %v, want %v", step, got, want)
		}
	}

	mustReport(t, r, uid, fullReport("host-1"))
	expect("first report", "first_seen", "connected", "healthy")

	// Heartbeats and their flush add nothing.
	n := len(kinds())
	mustReport(t, r, uid, &protobufs.AgentToServer{Capabilities: acceptsRemoteConfig, SequenceNum: 2})
	if err := r.FlushHeartbeats(ctx); err != nil {
		t.Fatal(err)
	}
	if len(kinds()) != n {
		t.Fatalf("a heartbeat was recorded: %v", kinds())
	}

	mustReport(t, r, uid, &protobufs.AgentToServer{Capabilities: acceptsRemoteConfig,
		Health: &protobufs.ComponentHealth{Healthy: false, Status: "degraded", LastError: "exporter down"}})
	expect("turned unhealthy", "unhealthy")
	if d := last().Detail; d["error"] != "exporter down" || d["status"] != "degraded" {
		t.Fatalf("unhealthy detail = %v", d)
	}
	// Reporting the same health again is not a new event.
	mustReport(t, r, uid, &protobufs.AgentToServer{Capabilities: acceptsRemoteConfig,
		Health: &protobufs.ComponentHealth{Healthy: false, Status: "degraded", LastError: "exporter down"}})
	expect("same health again", "healthy", "unhealthy")
	mustReport(t, r, uid, &protobufs.AgentToServer{Capabilities: acceptsRemoteConfig, Health: &protobufs.ComponentHealth{Healthy: true, Status: "ok"}})
	expect("recovered", "unhealthy", "healthy")

	// Config: assigned, failed with the reason, then applied, each naming the config and version.
	if _, err := db.Exec(ctx, `INSERT INTO config_templates (id, name) VALUES ('00000000-0000-0000-0000-0000000000aa', 'linux-hosts')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO config_versions (id, template_id, version, body, body_hash, author)
		VALUES ('00000000-0000-0000-0000-0000000000bb', '00000000-0000-0000-0000-0000000000aa', 3, 'x', 'hash-v3', 'a')`); err != nil {
		t.Fatal(err)
	}
	if err := r.SetDesiredConfig(ctx, uid, uuid.MustParse("00000000-0000-0000-0000-0000000000bb")); err != nil {
		t.Fatal(err)
	}
	expect("assigned", "config_assigned")
	if d := last().Detail; d["config"] != "linux-hosts" || d["version"] != float64(3) {
		t.Fatalf("assigned detail = %v", d)
	}
	status := func(s protobufs.RemoteConfigStatuses, errMsg string) {
		mustReport(t, r, uid, &protobufs.AgentToServer{Capabilities: acceptsRemoteConfig, RemoteConfigStatus: &protobufs.RemoteConfigStatus{
			LastRemoteConfigHash: []byte("hash-v3"), Status: s, ErrorMessage: errMsg}})
	}
	status(protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLYING, "")
	expect("applying is not recorded", "config_assigned")
	status(protobufs.RemoteConfigStatuses_RemoteConfigStatuses_FAILED, "unknown exporter")
	expect("failed", "config_failed")
	if d := last().Detail; d["config"] != "linux-hosts" || d["version"] != float64(3) || d["error"] != "unknown exporter" {
		t.Fatalf("failed detail = %v", d)
	}
	status(protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLIED, "")
	expect("applied", "config_failed", "config_applied")
	if d := last().Detail; d["config"] != "linux-hosts" || d["version"] != float64(3) || d["error"] != nil {
		t.Fatalf("applied detail = %v", d)
	}

	if err := r.SetPaused(ctx, uid, true); err != nil {
		t.Fatal(err)
	}
	if err := r.SetPaused(ctx, uid, false); err != nil {
		t.Fatal(err)
	}
	expect("stop and resume", "collection_stopped", "collection_resumed")

	// A collector upgrade.
	upgraded := fullReport("host-1")
	upgraded.AgentDescription.IdentifyingAttributes = []*protobufs.KeyValue{kv("service.version", "2.0.0")}
	mustReport(t, r, uid, upgraded)
	expect("upgrade", "collector_version_changed")
	if d := last().Detail; d["from"] != "1.2.3" || d["to"] != "2.0.0" {
		t.Fatalf("version detail = %v", d)
	}

	// Going offline is recorded whether the agent disconnects or is swept as stale.
	if err := r.Disconnected(ctx, uid); err != nil {
		t.Fatal(err)
	}
	expect("disconnect", "offline")
	mustReport(t, r, uid, fullReport("host-1"))
	if _, err := db.Exec(ctx, `UPDATE agents SET last_seen = now() - interval '1 hour' WHERE instance_uid = $1`, uid); err != nil {
		t.Fatal(err)
	}
	if err := rdb.Del(ctx, "opamp:route:"+uid.String()).Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.SweepOffline(ctx, 90*time.Second); err != nil {
		t.Fatal(err)
	}
	expect("swept", "offline", "connected", "collector_version_changed", "offline")

	// Paging: "before" returns only older events.
	all, _ := r.Events(ctx, uid, 0, 0)
	older, _ := r.Events(ctx, uid, all[2].ID, 2)
	if len(older) != 2 || older[0].ID != all[3].ID {
		t.Fatalf("paging returned %+v", older)
	}
}
