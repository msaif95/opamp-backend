package compliance

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/msaif95/opamp-backend/internal/testdb"
)

func at(s string) time.Time {
	t, err := time.Parse("2006-01-02 15:04", s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestScheduleTimes(t *testing.T) {
	for _, tc := range []struct {
		frequency, now, next, from, to string
	}{
		// 2026-11-16 is a Monday.
		{Daily, "2026-11-16 10:00", "2026-11-17 00:05", "2026-11-15 00:00", "2026-11-16 00:00"},
		{Daily, "2026-11-16 00:02", "2026-11-16 00:05", "2026-11-15 00:00", "2026-11-16 00:00"},
		{Daily, "2026-11-16 00:05", "2026-11-17 00:05", "2026-11-15 00:00", "2026-11-16 00:00"},
		{Weekly, "2026-11-18 10:00", "2026-11-23 00:05", "2026-11-09 00:00", "2026-11-16 00:00"},
		{Weekly, "2026-11-22 23:59", "2026-11-23 00:05", "2026-11-09 00:00", "2026-11-16 00:00"},
		{Weekly, "2026-11-23 00:06", "2026-11-30 00:05", "2026-11-16 00:00", "2026-11-23 00:00"},
		{Monthly, "2026-11-16 10:00", "2026-12-01 00:05", "2026-10-01 00:00", "2026-11-01 00:00"},
		{Monthly, "2026-12-31 23:00", "2027-01-01 00:05", "2026-11-01 00:00", "2026-12-01 00:00"},
		{Monthly, "2027-01-01 00:10", "2027-02-01 00:05", "2026-12-01 00:00", "2027-01-01 00:00"},
		{Monthly, "2027-03-01 00:01", "2027-03-01 00:05", "2027-02-01 00:00", "2027-03-01 00:00"},
	} {
		now := at(tc.now)
		if got := NextRun(tc.frequency, now); !got.Equal(at(tc.next)) {
			t.Errorf("%s at %s: next run %s, want %s", tc.frequency, tc.now, got.Format("2006-01-02 15:04"), tc.next)
		}
		if from, to := Period(tc.frequency, now); !from.Equal(at(tc.from)) || !to.Equal(at(tc.to)) {
			t.Errorf("%s at %s: period %s..%s, want %s..%s", tc.frequency, tc.now, from.Format("2006-01-02"), to.Format("2006-01-02"), tc.from, tc.to)
		}
	}
	// A report made when a schedule fires covers the period that has just closed.
	run := NextRun(Weekly, at("2026-11-18 10:00"))
	if from, to := Period(Weekly, run); !from.Equal(at("2026-11-16 00:00")) || !to.Equal(at("2026-11-23 00:00")) {
		t.Errorf("weekly run at %s covers %s..%s", run, from, to)
	}
}

func TestCategorize(t *testing.T) {
	for action, want := range map[string]string{
		"config.create": CatConfig, "config.version.create": CatConfig, "library.save": CatConfig, "secret.set": CatConfig, "group.update": CatConfig,
		"rollout.start": CatPush, "rollout.auto_pause": CatPush,
		"agent.config.assign": CatCollectors, "agent.delete": CatCollectors, "agent.labels": CatCollectors,
		"project.member.set": CatAccess, "api_token.create": CatAccess, "credential.revoke": CatAccess, "setting.update": CatAccess,
		"auth.login": CatSignIn, "auth.login_failed": CatSignIn,
		"audit.export": CatExport, "agents.export": CatExport, "report.generate": CatExport, "report_schedule.create": CatExport,
		"something.new": CatOther,
	} {
		if got := Categorize(action); got != want {
			t.Errorf("%s filed under %q, want %q", action, got, want)
		}
	}
}

func TestRenderEscapesAndNames(t *testing.T) {
	yes, v := true, 3
	r := &Report{
		ID: uuid.New(), Name: `Q4 <script>alert(1)</script>`, GeneratedBy: "root", GeneratedAt: at("2026-11-16 10:00"),
		PeriodFrom: at("2026-11-01 00:00"), PeriodTo: at("2026-11-16 00:00"),
		Summary: Summary{Collectors: 1, Connected: 1, AuditIntact: true},
		Body: Body{
			Collectors: []Collector{{InstanceUID: uuid.New(), Host: "=cmd|x", Project: "A", Connected: true, Healthy: &yes, Config: "base", ConfigVersion: &v, InSync: true, Labels: map[string]string{"owner": "a"}}},
			Events:     []Event{{ID: 7, OccurredAt: at("2026-11-02 09:00"), Actor: "<b>eve</b>", Action: "config.create", Category: CatConfig, Details: map[string]any{"name": "x"}}},
			ByCategory: []Count{{CatConfig, 1}},
			Audit:      &Audit{Intact: true, TotalEvents: 9, HeadEventID: 9, HeadHash: "abc123", EventsInPeriod: 1},
		},
	}
	var html bytes.Buffer
	if err := r.WriteHTML(&html); err != nil {
		t.Fatal(err)
	}
	page := html.String()
	if strings.Contains(page, "<script>alert") || strings.Contains(page, "<b>eve</b>") {
		t.Error("report HTML does not escape names")
	}
	for _, want := range []string{"Audit log intact", "abc123", "base v3", "config.create", "&lt;b&gt;eve&lt;/b&gt;", "Configuration"} {
		if !strings.Contains(page, want) {
			t.Errorf("report HTML lacks %q", want)
		}
	}
	var csv bytes.Buffer
	if err := r.WriteCollectorsCSV(&csv); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(csv.String(), ",'=cmd|x,") || !strings.Contains(csv.String(), "owner=a") {
		t.Errorf("collectors CSV:\n%s", csv.String())
	}
	csv.Reset()
	if err := r.WriteChangesCSV(&csv); err != nil || !strings.Contains(csv.String(), "7,2026-11-02T09:00:00Z,Configuration,<b>eve</b>") {
		t.Errorf("changes CSV: %v\n%s", err, csv.String())
	}
	if got := r.FileName("html"); got != "compliance-q4-script-alert-1-script-20261116.html" {
		t.Errorf("file name = %q", got)
	}
}

func TestGenerateAndSchedules(t *testing.T) {
	db, _ := testdb.Open(t)
	ctx := context.Background()
	s := NewService(db)

	// Two collectors (one offline), one removed collector and a few audit events, one of them outside the period.
	var project uuid.UUID
	if err := db.QueryRow(ctx, `INSERT INTO projects (name, created_by) VALUES ('A', 'root') RETURNING id`).Scan(&project); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO agents (instance_uid, project_id, auth_mode, attributes, agent_version, connected, healthy, labels)
		 VALUES (gen_random_uuid(), '` + project.String() + `', 'api_key', '{"host.name": "h1"}', '0.140.0', TRUE, TRUE, '{"owner": "ana"}'),
		        (gen_random_uuid(), NULL, 'mtls', '{"host.name": "h2"}', '0.139.0', FALSE, NULL, '{}')`,
		`INSERT INTO deleted_agents (instance_uid, project_id, host_name, connector_type, auth_mode, first_seen, last_seen, deleted_by)
		 VALUES (gen_random_uuid(), '` + project.String() + `', 'gone', 'supervisor', 'api_key', now() - interval '9 days', now() - interval '3 days', 'root')`,
		`INSERT INTO audit_events (occurred_at, actor, actor_auth, action, target_type, target_id) VALUES
		 (now() - interval '2 days', 'ana', 'okta', 'config.create', 'config', 'c1'),
		 (now() - interval '2 days', 'ana', 'okta', 'rollout.start', 'rollout', 'r1'),
		 (now() - interval '1 day', 'bob', 'okta', 'api_token.create', 'api_token', 't1'),
		 (now() - interval '1 day', 'eve', 'local', 'auth.login_failed', 'user', 'eve'),
		 (now() - interval '1 day', 'ana', 'okta', 'auth.login', 'user', 'ana'),
		 (now() - interval '40 days', 'old', 'okta', 'config.delete', 'config', 'c0')`,
	} {
		if _, err := db.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}

	now := time.Now()
	r, err := s.Generate(ctx, "manual", now.AddDate(0, 0, -7), now, "root", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := Summary{Collectors: 2, Connected: 1, Healthy: 1, Removed: 1, Changes: 3, ConfigChanges: 1, Pushes: 1, AccessChanges: 1, FailedSignIns: 1, AuditIntact: true}
	if r.Summary != want {
		t.Errorf("summary = %+v\nwant      %+v", r.Summary, want)
	}
	if len(r.Events) != 5 || r.Audit.EventsInPeriod != 5 || r.Audit.LeftOut != 0 || r.Audit.TotalEvents != 6 || r.Audit.HeadHash == "" || !r.Audit.Intact {
		t.Errorf("audit = %+v with %d events listed", r.Audit, len(r.Events))
	}
	if len(r.ByProject) != 2 || len(r.ByVersion) != 2 || len(r.Collectors) != 2 || r.Collectors[1].Labels["owner"] != "ana" || r.Removed[0].Host != "gone" {
		t.Errorf("fleet = %+v / %+v / %+v", r.ByProject, r.Collectors, r.Removed)
	}
	if len(r.ByActor) != 2 || r.ByActor[0] != (Count{"ana", 2}) {
		t.Errorf("by actor = %+v (sign-ins are not changes)", r.ByActor)
	}

	// Stored as made: reading it back gives the same report, and lists leave the detail out.
	back, err := s.Get(ctx, r.ID)
	if err != nil || back.Summary != r.Summary || len(back.Collectors) != 2 || len(back.Events) != 5 || back.Audit.HeadHash != r.Audit.HeadHash {
		t.Errorf("read back: %v %+v", err, back)
	}
	list, _ := s.List(ctx)
	if len(list) != 1 || list[0].Collectors != nil || list[0].Summary.Collectors != 2 {
		t.Errorf("list = %+v", list)
	}

	// A schedule fires once when due, covers the period that just closed and moves on.
	clock := at("2026-11-16 10:00")
	s.now = func() time.Time { return clock }
	sch, err := s.CreateSchedule(ctx, "Weekly", Weekly, "root")
	if err != nil || !sch.NextRunAt.Equal(at("2026-11-23 00:05")) {
		t.Fatalf("create schedule: %v %+v", err, sch)
	}
	if _, err := s.CreateSchedule(ctx, "Weekly", Daily, "root"); err != ErrScheduleNameTaken {
		t.Errorf("duplicate name: %v", err)
	}
	if _, err := s.CreateSchedule(ctx, "x", "hourly", "root"); err != ErrFrequency {
		t.Errorf("bad frequency: %v", err)
	}
	if r, err := s.RunDue(ctx); err != nil || r != nil {
		t.Fatalf("not due yet: %v %v", r, err)
	}
	clock = at("2026-11-23 00:06")
	made, err := s.RunDue(ctx)
	if err != nil || made == nil {
		t.Fatalf("due run: %v %v", made, err)
	}
	if !made.PeriodFrom.Equal(at("2026-11-16 00:00")) || !made.PeriodTo.Equal(at("2026-11-23 00:00")) || made.Name != "Weekly, week of 16 Nov 2026" ||
		made.GeneratedBy != "schedule: Weekly" || made.ScheduleID == nil {
		t.Errorf("scheduled report = %+v", made)
	}
	if again, err := s.RunDue(ctx); err != nil || again != nil {
		t.Errorf("ran twice: %v %v", again, err)
	}
	schedules, _ := s.Schedules(ctx)
	if len(schedules) != 1 || !schedules[0].NextRunAt.Equal(at("2026-11-30 00:05")) || schedules[0].LastRunAt == nil {
		t.Errorf("schedule after run = %+v", schedules)
	}
	var audited int
	_ = db.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'report.generate' AND actor = 'system'`).Scan(&audited)
	if audited != 1 {
		t.Errorf("scheduled run audited %d times", audited)
	}

	// Paused schedules do not fire; resuming starts from the current period, without a backlog.
	if _, err := s.SetScheduleEnabled(ctx, sch.ID, false); err != nil {
		t.Fatal(err)
	}
	clock = at("2027-02-10 12:00")
	if r, _ := s.RunDue(ctx); r != nil {
		t.Error("a paused schedule fired")
	}
	resumed, err := s.SetScheduleEnabled(ctx, sch.ID, true)
	if err != nil || !resumed.NextRunAt.Equal(at("2027-02-15 00:05")) {
		t.Errorf("resumed = %+v, %v", resumed, err)
	}
	if now, err := s.RunNow(ctx, sch.ID, "root"); err != nil || !now.PeriodTo.Equal(at("2027-02-08 00:00")) || now.GeneratedBy != "root" {
		t.Errorf("run now = %+v, %v", now, err)
	}

	// Deleting a schedule keeps its reports; pruning removes old ones only.
	if err := s.DeleteSchedule(ctx, sch.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSchedule(ctx, sch.ID); err != ErrScheduleNotFound {
		t.Errorf("delete twice: %v", err)
	}
	if list, _ := s.List(ctx); len(list) != 3 {
		t.Errorf("%d reports after deleting the schedule, want 3", len(list))
	}
	if _, err := db.Exec(ctx, `UPDATE compliance_reports SET generated_at = now() - interval '500 days' WHERE id = $1`, r.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Prune(ctx, 400); err != nil || n != 1 {
		t.Errorf("pruned %d, %v", n, err)
	}
	if n, _ := s.Prune(ctx, 0); n != 0 {
		t.Errorf("retention 0 pruned %d", n)
	}
	if err := s.Delete(ctx, made.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, made.ID); err != ErrNotFound {
		t.Errorf("deleted report: %v", err)
	}
}
