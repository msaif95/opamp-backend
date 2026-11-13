package rollout

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-telemetry/opamp-go/protobufs"

	"github.com/msaif95/opamp-backend/internal/agentconfig"
	"github.com/msaif95/opamp-backend/internal/registry"
	"github.com/msaif95/opamp-backend/internal/targeting"
	"github.com/msaif95/opamp-backend/internal/testdb"
)

var ctx = context.Background()

const (
	accepts = uint64(protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig)
	bodyV1  = "receivers:\n  otlp:\nexporters:\n  debug:\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [debug]\n"
)

type fakePusher struct {
	mu     sync.Mutex
	pushed []uuid.UUID
}

func (f *fakePusher) RequestPush(_ context.Context, uids ...uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pushed = append(f.pushed, uids...)
	return nil
}

func (f *fakePusher) take() []uuid.UUID {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.pushed
	f.pushed = nil
	return out
}

// env is a rollout service over a real database with a fleet of fake agents.
type env struct {
	t        *testing.T
	db       *pgxpool.Pool
	reg      *registry.Registry
	svc      *Service
	push     *fakePusher
	outcomes []string
	v1, v2   *agentconfig.Version
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db, rdb := testdb.Open(t)
	e := &env{t: t, db: db, push: &fakePusher{}, reg: registry.New(db, rdb, "replica-a", time.Minute)}
	e.svc = NewService(db, e.push, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.svc.OnOutcome = func(_ context.Context, outcome string, _ *Rollout) { e.outcomes = append(e.outcomes, outcome) }

	configs := agentconfig.NewService(db)
	tmpl, v1, err := configs.Create(ctx, "cfg", "", bodyV1, "tester")
	if err != nil {
		t.Fatal(err)
	}
	v2, err := configs.AddVersion(ctx, tmpl.ID, bodyV1+"# v2\n", "", "tester")
	if err != nil {
		t.Fatal(err)
	}
	e.v1, e.v2 = v1, v2
	return e
}

// agent registers a connected agent with env=<envName>.
func (e *env) agent(envName string, caps uint64) uuid.UUID {
	e.t.Helper()
	uid := uuid.New()
	_, err := e.reg.Report(ctx, uid, registry.Identity{AuthMode: "api_key"}, &protobufs.AgentToServer{
		Capabilities: caps,
		AgentDescription: &protobufs.AgentDescription{NonIdentifyingAttributes: []*protobufs.KeyValue{
			{Key: "env", Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: envName}}},
		}},
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return uid
}

func (e *env) agents(n int) []uuid.UUID {
	uids := make([]uuid.UUID, n)
	for i := range uids {
		uids[i] = e.agent("prod", accepts)
	}
	return uids
}

// report makes agents report the outcome of applying a config version.
func (e *env) report(v *agentconfig.Version, status protobufs.RemoteConfigStatuses, uids ...uuid.UUID) {
	e.t.Helper()
	for _, uid := range uids {
		_, err := e.reg.Report(ctx, uid, registry.Identity{AuthMode: "api_key"}, &protobufs.AgentToServer{
			Capabilities:       accepts,
			RemoteConfigStatus: &protobufs.RemoteConfigStatus{LastRemoteConfigHash: v.BodyHash, Status: status, ErrorMessage: "bad config"},
		})
		if err != nil {
			e.t.Fatal(err)
		}
	}
}

func (e *env) applied(v *agentconfig.Version, uids ...uuid.UUID) {
	e.report(v, protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLIED, uids...)
}

func (e *env) failed(v *agentconfig.Version, uids ...uuid.UUID) {
	e.report(v, protobufs.RemoteConfigStatuses_RemoteConfigStatuses_FAILED, uids...)
}

func (e *env) start(p Params) *Rollout {
	e.t.Helper()
	if p.Selector == nil {
		p.Selector = targeting.Selector{"env": {"prod"}}
	}
	if p.BatchSize == 0 {
		p.BatchSize = 100
	}
	p.CreatedBy = "tester"
	r, err := e.svc.Create(ctx, p)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

func (e *env) get(id uuid.UUID) *Rollout {
	e.t.Helper()
	r, err := e.svc.Get(ctx, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

func (e *env) desired(uid uuid.UUID) *uuid.UUID {
	e.t.Helper()
	var v *uuid.UUID
	if err := e.db.QueryRow(ctx, `SELECT desired_config_version_id FROM agents WHERE instance_uid = $1`, uid).Scan(&v); err != nil {
		e.t.Fatal(err)
	}
	return v
}

func (e *env) expect(id uuid.UUID, status string, counts map[string]int) {
	e.t.Helper()
	r := e.get(id)
	if r.Status != status {
		e.t.Fatalf("status = %s (%v), want %s", r.Status, r.Counts, status)
	}
	for k, want := range counts {
		if r.Counts[k] != want {
			e.t.Fatalf("counts = %v, want %s=%d", r.Counts, k, want)
		}
	}
}

func TestFixedBatchesWaitForEachBatchToSettle(t *testing.T) {
	e := newEnv(t)
	e.agents(5)
	e.agent("dev", accepts) // not targeted
	r := e.start(Params{VersionID: e.v2.ID, BatchSize: 2, MaxFailurePct: 100})
	if r.TotalAgents != 5 || r.TotalBatches != 3 {
		t.Fatalf("created with %d agents in %d batches", r.TotalAgents, r.TotalBatches)
	}

	e.svc.tick(ctx)
	first := e.push.take()
	e.expect(r.ID, "running", map[string]int{"offered": 2, "pending": 3})
	if len(first) != 2 {
		t.Fatalf("pushed %d agents, want 2", len(first))
	}

	// Nothing more is released while the batch is in flight.
	e.svc.tick(ctx)
	if extra := e.push.take(); len(extra) != 0 {
		t.Fatalf("released %d more agents before the batch settled", len(extra))
	}

	// One applied, one failed: both are settled, so the next batch goes out.
	e.applied(e.v2, first[0])
	e.failed(e.v2, first[1])
	e.svc.tick(ctx)
	second := e.push.take()
	e.expect(r.ID, "running", map[string]int{"applied": 1, "failed": 1, "offered": 2, "pending": 1})

	e.applied(e.v2, second...)
	e.svc.tick(ctx)
	third := e.push.take()
	e.applied(e.v2, third...)
	e.svc.tick(ctx) // settles the last batch
	e.svc.tick(ctx) // finds nothing left
	e.expect(r.ID, "completed", map[string]int{"applied": 4, "failed": 1})
	if !slices.Equal(e.outcomes, []string{"completed"}) {
		t.Fatalf("outcomes = %v", e.outcomes)
	}
	if problems, _ := e.svc.Problems(ctx, r.ID); len(problems) != 1 || problems[0].Error != "bad config" {
		t.Fatalf("problems = %+v", problems)
	}
}

func TestAutoPauseThenResumeAcknowledgesFailures(t *testing.T) {
	e := newEnv(t)
	e.agents(4)
	r := e.start(Params{VersionID: e.v2.ID, BatchSize: 2, MaxFailurePct: 10})

	e.svc.tick(ctx)
	batch := e.push.take()
	e.applied(e.v2, batch[0])
	e.failed(e.v2, batch[1])
	e.svc.tick(ctx)
	e.expect(r.ID, "paused", map[string]int{"failed": 1, "pending": 2})
	if got := e.get(r.ID); got.Error == nil || !strings.Contains(*got.Error, "1 of 2 agents in batch 1 failed") {
		t.Fatalf("pause reason = %v", got.Error)
	}

	// Paused means paused: no further batch however many ticks pass.
	e.svc.tick(ctx)
	if extra := e.push.take(); len(extra) != 0 {
		t.Fatal("released a batch while paused")
	}
	var audited int
	_ = e.db.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'rollout.auto_pause' AND actor = 'system'`).Scan(&audited)
	if audited != 1 {
		t.Fatalf("auto-pause audited %d times", audited)
	}

	// Resume: the failure in batch 1 no longer blocks, and the next batch is released.
	if err := e.svc.Resume(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	e.svc.tick(ctx)
	if next := e.push.take(); len(next) != 2 {
		t.Fatalf("after resume released %d agents, want 2", len(next))
	}
	e.expect(r.ID, "running", nil)
	if !slices.Equal(e.outcomes, []string{"paused"}) {
		t.Fatalf("outcomes = %v", e.outcomes)
	}
	if err := e.svc.Resume(ctx, r.ID); !errors.Is(err, ErrBadState) {
		t.Fatalf("resume of a running rollout: err = %v", err)
	}
}

func TestAutoRollbackRestoresPreviousConfig(t *testing.T) {
	e := newEnv(t)
	onV1 := e.agents(3)
	fresh := e.agent("prod", accepts) // has never had a config

	// Put three agents on v1 first.
	setup := e.start(Params{VersionID: e.v1.ID, Selector: targeting.Selector{"env": {"prod"}}, MaxFailurePct: 100})
	e.svc.tick(ctx)
	e.push.take()
	e.applied(e.v1, onV1...)
	if _, err := e.db.Exec(ctx, `UPDATE agents SET desired_config_version_id = NULL WHERE instance_uid = $1`, fresh); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Abort(ctx, setup.ID); err != nil {
		t.Fatal(err)
	}
	e.outcomes = nil

	r := e.start(Params{VersionID: e.v2.ID, MaxFailurePct: 10, AutoRollback: true})
	e.svc.tick(ctx)
	e.push.take()
	e.applied(e.v2, onV1[0], onV1[1], fresh)
	e.failed(e.v2, onV1[2])
	e.svc.tick(ctx)

	e.expect(r.ID, "rolled_back", map[string]int{"rolled_back": 4})
	restored := e.push.take()
	slices.SortFunc(restored, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	want := slices.Clone(onV1)
	slices.SortFunc(want, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	if !slices.Equal(restored, want) {
		t.Fatalf("pushed the previous config to %d agents, want the 3 that had one", len(restored))
	}
	for _, uid := range onV1 {
		if d := e.desired(uid); d == nil || *d != e.v1.ID {
			t.Fatalf("agent not restored to v1: desired = %v", d)
		}
	}
	// The agent with no earlier config cannot be restored and is reported.
	problems, _ := e.svc.Problems(ctx, r.ID)
	if len(problems) != 1 || problems[0].InstanceUID != fresh || !strings.Contains(problems[0].Error, "no previous config") {
		t.Fatalf("problems = %+v", problems)
	}
	if !slices.Equal(e.outcomes, []string{"rolled_back"}) {
		t.Fatalf("outcomes = %v", e.outcomes)
	}
	if err := e.svc.Rollback(ctx, r.ID); !errors.Is(err, ErrBadState) {
		t.Fatalf("second rollback: err = %v", err)
	}
}

func TestCanaryStepSizes(t *testing.T) {
	e := newEnv(t)
	e.agents(20)
	r := e.start(Params{VersionID: e.v2.ID, CanarySteps: []int{10, 50, 100}, MaxFailurePct: 100})
	rows, err := e.db.Query(ctx, `SELECT count(*) FROM rollout_agents WHERE rollout_id = $1 GROUP BY step ORDER BY step`, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	var sizes []int
	for rows.Next() {
		var n int
		_ = rows.Scan(&n)
		sizes = append(sizes, n)
	}
	if !slices.Equal(sizes, []int{2, 8, 10}) {
		t.Fatalf("step sizes = %v, want [2 8 10]", sizes)
	}
}

func TestSkippedAndSupersededAgents(t *testing.T) {
	e := newEnv(t)
	normal := e.agent("prod", accepts)
	noRemoteConfig := e.agent("prod", 0)
	offline := e.agent("prod", accepts)
	if _, err := e.db.Exec(ctx, `UPDATE agents SET connected = FALSE WHERE instance_uid = $1`, offline); err != nil {
		t.Fatal(err)
	}
	r := e.start(Params{VersionID: e.v2.ID, MaxFailurePct: 100})

	e.svc.tick(ctx)
	if pushed := e.push.take(); len(pushed) != 1 || pushed[0] != normal {
		t.Fatalf("pushed %v, want only the connected, capable agent", pushed)
	}
	e.expect(r.ID, "running", map[string]int{"offered": 1, "skipped": 2})
	if e.desired(noRemoteConfig) != nil {
		t.Error("agent that cannot accept remote config was assigned one")
	}
	if d := e.desired(offline); d == nil || *d != e.v2.ID {
		t.Error("offline agent should still be assigned the config for when it reconnects")
	}

	// Someone assigns the in-flight agent a different version: this rollout lets go of it.
	if _, err := e.db.Exec(ctx, `UPDATE agents SET desired_config_version_id = $2 WHERE instance_uid = $1`, normal, e.v1.ID); err != nil {
		t.Fatal(err)
	}
	e.svc.tick(ctx)
	e.svc.tick(ctx)
	e.expect(r.ID, "completed", map[string]int{"skipped": 3})
}

func TestAgentsMatchingLaterJoinARunningRollout(t *testing.T) {
	e := newEnv(t)
	first := e.agents(2)
	r := e.start(Params{VersionID: e.v2.ID, BatchSize: 2, MaxFailurePct: 100})
	e.svc.tick(ctx)
	e.push.take()

	late := e.agent("prod", accepts) // connects while batch 1 is in flight
	e.agent("dev", accepts)          // does not match
	e.svc.tick(ctx)
	e.expect(r.ID, "running", map[string]int{"offered": 2, "pending": 1})

	e.applied(e.v2, first...)
	e.svc.tick(ctx)
	if pushed := e.push.take(); len(pushed) != 1 || pushed[0] != late {
		t.Fatalf("late agent not released in the next batch: pushed %v", pushed)
	}
	e.applied(e.v2, late)
	e.svc.tick(ctx)
	e.svc.tick(ctx)
	e.expect(r.ID, "completed", map[string]int{"applied": 3})

	// Once finished, the rollout stops picking up new agents.
	e.agent("prod", accepts)
	e.svc.tick(ctx)
	if got := e.get(r.ID); got.TotalAgents != 3 {
		t.Fatalf("finished rollout grew to %d agents", got.TotalAgents)
	}
}

func TestApplyTimeoutCountsAsFailure(t *testing.T) {
	e := newEnv(t)
	e.agents(1)
	r := e.start(Params{VersionID: e.v2.ID, MaxFailurePct: 100})
	e.svc.tick(ctx)
	// The agent never answers; pretend it was offered long ago.
	if _, err := e.db.Exec(ctx, `UPDATE rollout_agents SET updated_at = now() - interval '1 hour' WHERE rollout_id = $1`, r.ID); err != nil {
		t.Fatal(err)
	}
	e.svc.tick(ctx)
	// The timed-out agent settles the only batch, so the same tick finishes the rollout.
	e.expect(r.ID, "completed", map[string]int{"failed": 1})
	if problems, _ := e.svc.Problems(ctx, r.ID); len(problems) != 1 || !strings.Contains(problems[0].Error, "timed out") {
		t.Fatalf("problems = %+v", problems)
	}
}

func TestCreateRejectsEmptyTarget(t *testing.T) {
	e := newEnv(t)
	_, err := e.svc.Create(ctx, Params{VersionID: e.v2.ID, Selector: targeting.Selector{"env": {"nowhere"}}, BatchSize: 10, CreatedBy: "t"})
	if !errors.Is(err, ErrNoAgents) {
		t.Fatalf("err = %v, want ErrNoAgents", err)
	}
	if list, _ := e.svc.List(ctx); len(list) != 0 {
		t.Fatalf("a rollout with no agents was left behind: %+v", list)
	}
}

func TestGroupConfigReachesAgentsThatJoinAfterTheRollout(t *testing.T) {
	e := newEnv(t)
	groups := targeting.NewGroups(e.db)
	grp, err := groups.Create(ctx, "prod", "", targeting.Selector{"env": {"prod"}})
	if err != nil {
		t.Fatal(err)
	}
	members := e.agents(2)
	r := e.start(Params{VersionID: e.v2.ID, GroupID: &grp.ID, MaxFailurePct: 100})
	if err := groups.SetConfig(ctx, grp.ID, &e.v2.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := groups.Get(ctx, grp.ID); got.Config == nil || got.Config.Version != 2 || got.Config.TemplateName != "cfg" {
		t.Fatalf("group config = %+v", got.Config)
	}

	// While the rollout is running the group hands nothing out by itself:
	// a late agent joins the rollout's next batch instead.
	e.svc.tick(ctx)
	e.push.take()
	e.applied(e.v2, members...)
	e.svc.tick(ctx)
	e.svc.tick(ctx)
	e.expect(r.ID, "completed", map[string]int{"applied": 2})

	// After it completed, new matching agents get the config without a new rollout.
	late := e.agent("prod", accepts)
	other := e.agent("dev", accepts)
	incapable := e.agent("prod", 0)
	e.push.take()
	e.svc.tick(ctx)
	if pushed := e.push.take(); len(pushed) != 1 || pushed[0] != late {
		t.Fatalf("pushed %v, want only the late matching agent", pushed)
	}
	if d := e.desired(late); d == nil || *d != e.v2.ID {
		t.Fatal("late agent not given the group config")
	}
	if e.desired(other) != nil || e.desired(incapable) != nil {
		t.Fatal("config given to an agent outside the group or one that cannot accept it")
	}

	// A rolled-back version must not keep spreading.
	if err := e.svc.Rollback(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	e.push.take()
	afterRollback := e.agent("prod", accepts)
	e.svc.tick(ctx)
	if e.desired(afterRollback) != nil {
		t.Fatal("group handed out a config whose rollout was rolled back")
	}

	// Clearing the group config stops it too, and agents keep what they have.
	if err := groups.SetConfig(ctx, grp.ID, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := groups.Get(ctx, grp.ID); got.Config != nil {
		t.Fatal("group config not cleared")
	}
}
