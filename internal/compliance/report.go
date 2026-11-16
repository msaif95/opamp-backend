// Package compliance produces compliance reports: a snapshot of the fleet's
// state, the trail of changes over a period taken from the audit log, and a
// statement of the audit log's integrity. Reports are generated on request
// or on a schedule, stored, and exported as HTML, JSON or CSV.
package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// maxCollectors and maxEvents bound one report; what is left out is counted and said.
	maxCollectors = 50000
	maxEvents     = 10000
)

var ErrNotFound = errors.New("report not found")

// Summary is the headline of a report, also shown in lists.
type Summary struct {
	Collectors   int `json:"collectors"`
	Connected    int `json:"connected"`
	Healthy      int `json:"healthy"`
	Unhealthy    int `json:"unhealthy"`
	WithConfig   int `json:"with_config"`
	InSync       int `json:"in_sync"`
	ConfigFailed int `json:"config_failed"`
	Paused       int `json:"paused"`
	// Removed is how many collectors were removed from the fleet in the period.
	Removed int `json:"removed"`
	// Changes counts audit events in the period other than sign-ins.
	Changes       int `json:"changes"`
	ConfigChanges int `json:"config_changes"`
	Pushes        int `json:"pushes"`
	AccessChanges int `json:"access_changes"`
	FailedSignIns int `json:"failed_sign_ins"`
	// AuditIntact is whether the audit log's hash chain verified when the report was made.
	AuditIntact bool `json:"audit_intact"`
}

// Collector is one collector's state when the report was made.
type Collector struct {
	InstanceUID   uuid.UUID         `json:"instance_uid"`
	Host          string            `json:"host"`
	Project       string            `json:"project"`
	Version       string            `json:"version"`
	Connector     string            `json:"connector"`
	AuthMode      string            `json:"auth_mode"`
	Connected     bool              `json:"connected"`
	Healthy       *bool             `json:"healthy"`
	Paused        bool              `json:"paused"`
	Config        string            `json:"config"`
	ConfigVersion *int              `json:"config_version"`
	ConfigStatus  string            `json:"config_status"`
	InSync        bool              `json:"in_sync"`
	Labels        map[string]string `json:"labels"`
	FirstSeen     time.Time         `json:"first_seen"`
	LastSeen      time.Time         `json:"last_seen"`
}

// Group is a count of collectors sharing something (a project, a version, a config).
type Group struct {
	Name         string `json:"name"`
	Collectors   int    `json:"collectors"`
	Connected    int    `json:"connected"`
	Healthy      int    `json:"healthy"`
	WithConfig   int    `json:"with_config"`
	InSync       int    `json:"in_sync"`
	ConfigFailed int    `json:"config_failed"`
}

// Config is one config in the inventory.
type Config struct {
	Name          string `json:"name"`
	Project       string `json:"project"`
	Origin        string `json:"origin"`
	LatestVersion int    `json:"latest_version"`
	Assigned      int    `json:"assigned"`
}

// Removed is a collector removed from the fleet in the period.
type Removed struct {
	Host        string    `json:"host"`
	InstanceUID uuid.UUID `json:"instance_uid"`
	Project     string    `json:"project"`
	DeletedBy   string    `json:"deleted_by"`
	DeletedAt   time.Time `json:"deleted_at"`
}

// Event is one audit event in the period.
type Event struct {
	ID         int64          `json:"id"`
	OccurredAt time.Time      `json:"occurred_at"`
	Actor      string         `json:"actor"`
	ActorAuth  string         `json:"actor_auth"`
	Action     string         `json:"action"`
	Category   string         `json:"category"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	Details    map[string]any `json:"details"`
}

// Count is a named number.
type Count struct {
	Name string `json:"name"`
	N    int    `json:"n"`
}

// Audit states what was checked about the audit log itself.
type Audit struct {
	// Intact is whether every event's hash follows from the one before it.
	Intact             bool   `json:"intact"`
	FirstBrokenEventID *int64 `json:"first_broken_event_id"`
	// TotalEvents is the size of the whole log; the head is its newest event.
	// Keeping the head's hash lets a later reader show the log was not
	// rewritten after this report: the event with that ID must still have it.
	TotalEvents int64  `json:"total_events"`
	HeadEventID int64  `json:"head_event_id"`
	HeadHash    string `json:"head_hash"`
	// EventsInPeriod counts every event in the period; LeftOut how many of
	// them are not listed in this report because of its size limit.
	EventsInPeriod int `json:"events_in_period"`
	LeftOut        int `json:"left_out"`
}

// Report is a complete compliance report.
type Report struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	ScheduleID  *uuid.UUID `json:"schedule_id"`
	PeriodFrom  time.Time  `json:"period_from"`
	PeriodTo    time.Time  `json:"period_to"`
	GeneratedAt time.Time  `json:"generated_at"`
	GeneratedBy string     `json:"generated_by"`
	Summary     Summary    `json:"summary"`
	Body
}

// Body is the detail of a report; lists return reports without it.
type Body struct {
	ByProject []Group  `json:"by_project,omitempty"`
	ByVersion []Group  `json:"by_version,omitempty"`
	ByConfig  []Group  `json:"by_config,omitempty"`
	Configs   []Config `json:"configs,omitempty"`
	// Collectors is every collector's state; CollectorsLeftOut counts those beyond the report's size limit.
	Collectors        []Collector `json:"collectors,omitempty"`
	CollectorsLeftOut int         `json:"collectors_left_out,omitempty"`
	Removed           []Removed   `json:"removed,omitempty"`
	Events            []Event     `json:"events,omitempty"`
	ByCategory        []Count     `json:"by_category,omitempty"`
	ByActor           []Count     `json:"by_actor,omitempty"`
	Audit             *Audit      `json:"audit,omitempty"`
}

// Categories of audit events, in the order a report lists them.
const (
	CatConfig     = "Configuration"
	CatPush       = "Pushes"
	CatCollectors = "Collectors"
	CatAccess     = "Access and security"
	CatExport     = "Exports and reports"
	CatSignIn     = "Sign-ins"
	CatOther      = "Other"
)

var Categories = []string{CatConfig, CatPush, CatCollectors, CatAccess, CatExport, CatSignIn, CatOther}

// Categorize files an audit action under the heading a reader would look for it.
func Categorize(action string) string {
	prefix, _, _ := strings.Cut(action, ".")
	switch {
	case strings.HasSuffix(action, ".export") || prefix == "report" || prefix == "report_schedule":
		return CatExport
	case prefix == "config" || prefix == "library" || prefix == "secret" || prefix == "group":
		return CatConfig
	case prefix == "rollout":
		return CatPush
	case prefix == "agent" || prefix == "agents":
		return CatCollectors
	case prefix == "project" || prefix == "api_token" || prefix == "credential" || prefix == "setting" || prefix == "user":
		return CatAccess
	case prefix == "auth":
		return CatSignIn
	}
	return CatOther
}

// Service generates and stores reports and runs their schedules.
type Service struct {
	db *pgxpool.Pool
	// Notify, if set, is told when a scheduled report is ready.
	Notify func(text string)
	// PublicURL is the console's address, for links in notifications.
	PublicURL string
	now       func() time.Time
}

// NewService creates a Service.
func NewService(db *pgxpool.Pool) *Service { return &Service{db: db, now: time.Now} }

func groupBy(collectors []Collector, key func(Collector) string) []Group {
	byName := map[string]*Group{}
	for _, c := range collectors {
		name := key(c)
		g := byName[name]
		if g == nil {
			g = &Group{Name: name}
			byName[name] = g
		}
		g.Collectors++
		if c.Connected {
			g.Connected++
			if c.Healthy != nil && *c.Healthy {
				g.Healthy++
			}
		}
		if c.Config != "" {
			g.WithConfig++
		}
		if c.InSync {
			g.InSync++
		}
		if c.ConfigStatus == "failed" {
			g.ConfigFailed++
		}
	}
	out := make([]Group, 0, len(byName))
	for _, g := range byName {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Collectors != out[j].Collectors {
			return out[i].Collectors > out[j].Collectors
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func orDash(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// build gathers a report for the period [from, to). Everything is read in
// one repeatable-read transaction, so the parts describe the same moment.
func (s *Service) build(ctx context.Context, name string, from, to time.Time, by string, schedule *uuid.UUID) (*Report, error) {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	r := &Report{ID: uuid.New(), Name: name, ScheduleID: schedule, PeriodFrom: from.UTC(), PeriodTo: to.UTC(), GeneratedAt: s.now().UTC(), GeneratedBy: by}

	rows, err := tx.Query(ctx, `
SELECT a.instance_uid, COALESCE(a.attributes->>'host.name', ''), COALESCE(p.name, ''), COALESCE(a.agent_version, ''),
       a.connector_type::text, a.auth_mode::text, a.connected, a.healthy, a.paused, COALESCE(ct.name, ''), cv.version,
       a.remote_config_status::text, COALESCE(cv.body_hash = a.remote_config_hash AND a.remote_config_status = 'applied', FALSE),
       a.labels, a.first_seen, a.last_seen
FROM agents a
LEFT JOIN projects p ON p.id = a.project_id
LEFT JOIN config_versions cv ON cv.id = a.desired_config_version_id
LEFT JOIN config_templates ct ON ct.id = cv.template_id
ORDER BY 3, 2, 1`)
	if err != nil {
		return nil, err
	}
	all, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Collector, error) {
		var (
			c      Collector
			labels []byte
		)
		if err := row.Scan(&c.InstanceUID, &c.Host, &c.Project, &c.Version, &c.Connector, &c.AuthMode, &c.Connected, &c.Healthy, &c.Paused,
			&c.Config, &c.ConfigVersion, &c.ConfigStatus, &c.InSync, &labels, &c.FirstSeen, &c.LastSeen); err != nil {
			return c, err
		}
		return c, json.Unmarshal(labels, &c.Labels)
	})
	if err != nil {
		return nil, err
	}
	sum := &r.Summary
	for _, c := range all {
		sum.Collectors++
		if c.Connected {
			sum.Connected++
			if c.Healthy != nil {
				if *c.Healthy {
					sum.Healthy++
				} else {
					sum.Unhealthy++
				}
			}
		}
		if c.Config != "" {
			sum.WithConfig++
		}
		if c.InSync {
			sum.InSync++
		}
		if c.ConfigStatus == "failed" {
			sum.ConfigFailed++
		}
		if c.Paused {
			sum.Paused++
		}
	}
	r.ByProject = groupBy(all, func(c Collector) string { return orDash(c.Project, "(no project)") })
	r.ByVersion = groupBy(all, func(c Collector) string { return orDash(c.Version, "(not reported)") })
	r.ByConfig = groupBy(all, func(c Collector) string {
		if c.Config == "" {
			return "(no config assigned)"
		}
		return c.Config + " v" + strconv.Itoa(*c.ConfigVersion)
	})
	r.Collectors = all
	if len(all) > maxCollectors {
		r.Collectors, r.CollectorsLeftOut = all[:maxCollectors], len(all)-maxCollectors
	}

	rows, err = tx.Query(ctx, `
SELECT t.name, COALESCE(p.name, ''), t.origin::text, COALESCE((SELECT max(version) FROM config_versions v WHERE v.template_id = t.id), 0),
       (SELECT count(*) FROM agents a JOIN config_versions v ON v.id = a.desired_config_version_id WHERE v.template_id = t.id)
FROM config_templates t LEFT JOIN projects p ON p.id = t.project_id ORDER BY 2, 1`)
	if err != nil {
		return nil, err
	}
	if r.Configs, err = pgx.CollectRows(rows, pgx.RowToStructByPos[Config]); err != nil {
		return nil, err
	}

	rows, err = tx.Query(ctx, `
SELECT d.host_name, d.instance_uid, COALESCE(p.name, ''), d.deleted_by, d.deleted_at
FROM deleted_agents d LEFT JOIN projects p ON p.id = d.project_id
WHERE d.deleted_at >= $1 AND d.deleted_at < $2 ORDER BY d.deleted_at`, from, to)
	if err != nil {
		return nil, err
	}
	if r.Removed, err = pgx.CollectRows(rows, pgx.RowToStructByPos[Removed]); err != nil {
		return nil, err
	}
	sum.Removed = len(r.Removed)

	rows, err = tx.Query(ctx, `
SELECT id, occurred_at, actor, actor_auth, action, target_type, COALESCE(target_id, ''), details
FROM audit_events WHERE occurred_at >= $1 AND occurred_at < $2 ORDER BY id LIMIT $3`, from, to, maxEvents)
	if err != nil {
		return nil, err
	}
	if r.Events, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Event, error) {
		var (
			e   Event
			raw []byte
		)
		if err := row.Scan(&e.ID, &e.OccurredAt, &e.Actor, &e.ActorAuth, &e.Action, &e.TargetType, &e.TargetID, &raw); err != nil {
			return e, err
		}
		e.Category = Categorize(e.Action)
		return e, json.Unmarshal(raw, &e.Details)
	}); err != nil {
		return nil, err
	}

	// Counts come from the whole period, not only the events listed.
	audit := &Audit{}
	r.Audit = audit
	rows, err = tx.Query(ctx, `SELECT action, actor, count(*) FROM audit_events WHERE occurred_at >= $1 AND occurred_at < $2 GROUP BY 1, 2`, from, to)
	if err != nil {
		return nil, err
	}
	byCategory, byActor := map[string]int{}, map[string]int{}
	var action, actor string
	var n int
	if _, err := pgx.ForEachRow(rows, []any{&action, &actor, &n}, func() error {
		cat := Categorize(action)
		audit.EventsInPeriod += n
		byCategory[cat] += n
		switch cat {
		case CatSignIn:
			if action == "auth.login_failed" || action == "auth.login_denied" {
				sum.FailedSignIns += n
			}
			return nil
		case CatConfig:
			sum.ConfigChanges += n
		case CatPush:
			sum.Pushes += n
		case CatAccess:
			sum.AccessChanges += n
		}
		sum.Changes += n
		byActor[actor] += n
		return nil
	}); err != nil {
		return nil, err
	}
	audit.LeftOut = audit.EventsInPeriod - len(r.Events)
	for _, cat := range Categories {
		if byCategory[cat] > 0 {
			r.ByCategory = append(r.ByCategory, Count{cat, byCategory[cat]})
		}
	}
	for name, n := range byActor {
		r.ByActor = append(r.ByActor, Count{name, n})
	}
	sort.Slice(r.ByActor, func(i, j int) bool {
		if r.ByActor[i].N != r.ByActor[j].N {
			return r.ByActor[i].N > r.ByActor[j].N
		}
		return r.ByActor[i].Name < r.ByActor[j].Name
	})

	if err := tx.QueryRow(ctx, `SELECT audit_verify()`).Scan(&audit.FirstBrokenEventID); err != nil {
		return nil, err
	}
	audit.Intact = audit.FirstBrokenEventID == nil
	sum.AuditIntact = audit.Intact
	err = tx.QueryRow(ctx, `
SELECT (SELECT count(*) FROM audit_events), COALESCE(e.id, 0), COALESCE(encode(e.hash, 'hex'), '')
FROM (SELECT 1) one LEFT JOIN LATERAL (SELECT id, hash FROM audit_events ORDER BY id DESC LIMIT 1) e ON TRUE`).
		Scan(&audit.TotalEvents, &audit.HeadEventID, &audit.HeadHash)
	return r, err
}

// Generate makes a report for [from, to) and stores it.
func (s *Service) Generate(ctx context.Context, name string, from, to time.Time, by string, schedule *uuid.UUID) (*Report, error) {
	r, err := s.build(ctx, name, from, to, by, schedule)
	if err != nil {
		return nil, err
	}
	return r, s.store(ctx, s.db, r)
}

// execer is satisfied by a pool and by a transaction.
type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func (s *Service) store(ctx context.Context, db execer, r *Report) error {
	summary, _ := json.Marshal(r.Summary)
	body, err := json.Marshal(r.Body)
	if err != nil {
		return err
	}
	_, err = db.Exec(ctx, `
INSERT INTO compliance_reports (id, name, schedule_id, period_from, period_to, generated_at, generated_by, summary, body)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb)`,
		r.ID, r.Name, r.ScheduleID, r.PeriodFrom, r.PeriodTo, r.GeneratedAt, r.GeneratedBy, summary, body)
	return err
}

const reportColumns = `id, name, schedule_id, period_from, period_to, generated_at, generated_by, summary`

func scanReport(row pgx.Row, withBody bool) (*Report, error) {
	var (
		r             Report
		summary, body []byte
	)
	dst := []any{&r.ID, &r.Name, &r.ScheduleID, &r.PeriodFrom, &r.PeriodTo, &r.GeneratedAt, &r.GeneratedBy, &summary}
	if withBody {
		dst = append(dst, &body)
	}
	if err := row.Scan(dst...); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(summary, &r.Summary); err != nil {
		return nil, err
	}
	if withBody {
		if err := json.Unmarshal(body, &r.Body); err != nil {
			return nil, err
		}
	}
	return &r, nil
}

// List returns stored reports without their detail, newest first.
func (s *Service) List(ctx context.Context) ([]Report, error) {
	rows, err := s.db.Query(ctx, `SELECT `+reportColumns+` FROM compliance_reports ORDER BY generated_at DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Report, error) {
		r, err := scanReport(row, false)
		if err != nil {
			return Report{}, err
		}
		return *r, nil
	})
}

// Get returns one report in full.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (*Report, error) {
	r, err := scanReport(s.db.QueryRow(ctx, `SELECT `+reportColumns+`, body FROM compliance_reports WHERE id = $1`, id), true)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

// Delete removes a stored report.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM compliance_reports WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// Prune deletes reports older than the given number of days; 0 keeps them all.
func (s *Service) Prune(ctx context.Context, days int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}
	tag, err := s.db.Exec(ctx, `DELETE FROM compliance_reports WHERE generated_at < now() - make_interval(days => $1)`, days)
	return tag.RowsAffected(), err
}
