package compliance

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Frequencies a schedule can have. Each report covers the previous whole
// day, week (Monday to Sunday) or calendar month, in UTC.
const (
	Daily   = "daily"
	Weekly  = "weekly"
	Monthly = "monthly"
)

var (
	ErrScheduleNotFound  = errors.New("schedule not found")
	ErrScheduleNameTaken = errors.New("a schedule with this name already exists")
	ErrFrequency         = errors.New("frequency must be daily, weekly or monthly")
)

// runOffset is how long after the period closes a report is made, so late writes are in.
const runOffset = 5 * time.Minute

func day(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// periodStart returns the start of the day, week or month that t falls in.
func periodStart(frequency string, t time.Time) time.Time {
	d := day(t)
	switch frequency {
	case Weekly:
		// Monday is the first day of the week.
		return d.AddDate(0, 0, -((int(d.Weekday()) + 6) % 7))
	case Monthly:
		return time.Date(d.Year(), d.Month(), 1, 0, 0, 0, 0, time.UTC)
	}
	return d
}

func nextStart(frequency string, start time.Time) time.Time {
	switch frequency {
	case Weekly:
		return start.AddDate(0, 0, 7)
	case Monthly:
		return start.AddDate(0, 1, 0)
	}
	return start.AddDate(0, 0, 1)
}

// NextRun is when a schedule next produces a report after the given time:
// shortly after the current day, week or month ends.
func NextRun(frequency string, after time.Time) time.Time {
	run := periodStart(frequency, after).Add(runOffset)
	if !run.After(after) {
		run = nextStart(frequency, periodStart(frequency, after)).Add(runOffset)
	}
	return run
}

// Period is the span a report made at runAt covers: the last whole day,
// week or month that ended before then.
func Period(frequency string, runAt time.Time) (from, to time.Time) {
	to = periodStart(frequency, runAt)
	switch frequency {
	case Weekly:
		return to.AddDate(0, 0, -7), to
	case Monthly:
		return to.AddDate(0, -1, 0), to
	}
	return to.AddDate(0, 0, -1), to
}

// Schedule produces a report regularly.
type Schedule struct {
	ID        uuid.UUID  `json:"id"`
	Name      string     `json:"name"`
	Frequency string     `json:"frequency"`
	Enabled   bool       `json:"enabled"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	LastRunAt *time.Time `json:"last_run_at"`
	NextRunAt time.Time  `json:"next_run_at"`
}

const scheduleColumns = `id, name, frequency, enabled, created_by, created_at, last_run_at, next_run_at`

func validFrequency(f string) bool { return f == Daily || f == Weekly || f == Monthly }

// CreateSchedule adds a schedule; its first report comes when the current period ends.
func (s *Service) CreateSchedule(ctx context.Context, name, frequency, by string) (*Schedule, error) {
	if !validFrequency(frequency) {
		return nil, ErrFrequency
	}
	rows, err := s.db.Query(ctx, `
INSERT INTO report_schedules (name, frequency, created_by, next_run_at) VALUES ($1, $2, $3, $4) RETURNING `+scheduleColumns,
		strings.TrimSpace(name), frequency, by, NextRun(frequency, s.now()))
	if err != nil {
		return nil, err
	}
	sch, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[Schedule])
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return nil, ErrScheduleNameTaken
	}
	return &sch, err
}

// Schedules lists all schedules by name.
func (s *Service) Schedules(ctx context.Context) ([]Schedule, error) {
	rows, err := s.db.Query(ctx, `SELECT `+scheduleColumns+` FROM report_schedules ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Schedule])
}

// SetScheduleEnabled pauses or resumes a schedule. Resuming starts from the
// current period, so a long pause does not produce a backlog of reports.
func (s *Service) SetScheduleEnabled(ctx context.Context, id uuid.UUID, enabled bool) (*Schedule, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var frequency string
	err = tx.QueryRow(ctx, `SELECT frequency FROM report_schedules WHERE id = $1 FOR UPDATE`, id).Scan(&frequency)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrScheduleNotFound
	}
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `UPDATE report_schedules SET enabled = $2, next_run_at = $3 WHERE id = $1 RETURNING `+scheduleColumns,
		id, enabled, NextRun(frequency, s.now()))
	if err != nil {
		return nil, err
	}
	sch, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[Schedule])
	if err != nil {
		return nil, err
	}
	return &sch, tx.Commit(ctx)
}

// DeleteSchedule removes a schedule. Reports it produced are kept.
func (s *Service) DeleteSchedule(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM report_schedules WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrScheduleNotFound
	}
	return err
}

func reportName(sch Schedule, from, to time.Time) string {
	switch sch.Frequency {
	case Monthly:
		return fmt.Sprintf("%s, %s", sch.Name, from.Format("January 2006"))
	case Weekly:
		return fmt.Sprintf("%s, week of %s", sch.Name, from.Format("2 Jan 2006"))
	}
	return fmt.Sprintf("%s, %s", sch.Name, from.Format("2 Jan 2006"))
}

// RunNow produces a schedule's report for the last whole period at once, without moving its next run.
func (s *Service) RunNow(ctx context.Context, id uuid.UUID, by string) (*Report, error) {
	rows, err := s.db.Query(ctx, `SELECT `+scheduleColumns+` FROM report_schedules WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	sch, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[Schedule])
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrScheduleNotFound
	}
	if err != nil {
		return nil, err
	}
	from, to := Period(sch.Frequency, s.now())
	return s.Generate(ctx, reportName(sch, from, to), from, to, by, &sch.ID)
}

// RunDue produces the report of one schedule that is due, if any, and
// reports whether it did. The schedule's row is locked while its report is
// made and its next run is moved in the same transaction, so with several
// replicas each due report is made exactly once.
func (s *Service) RunDue(ctx context.Context) (*Report, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
SELECT `+scheduleColumns+` FROM report_schedules WHERE enabled AND next_run_at <= $1
ORDER BY next_run_at LIMIT 1 FOR UPDATE SKIP LOCKED`, s.now())
	if err != nil {
		return nil, err
	}
	sch, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[Schedule])
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	now := s.now()
	from, to := Period(sch.Frequency, now)
	r, err := s.build(ctx, reportName(sch, from, to), from, to, "schedule: "+sch.Name, &sch.ID)
	if err != nil {
		return nil, err
	}
	if err := s.store(ctx, tx, r); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE report_schedules SET last_run_at = $2, next_run_at = $3 WHERE id = $1`, sch.ID, now, NextRun(sch.Frequency, now)); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO audit_events (actor, actor_auth, action, target_type, target_id, details)
VALUES ('system', 'system', 'report.generate', 'report', $1, jsonb_build_object('name', $2::text, 'schedule', $3::text))`, r.ID.String(), r.Name, sch.Name); err != nil {
		return nil, err
	}
	return r, tx.Commit(ctx)
}

// Run makes due reports until ctx is cancelled, and prunes old ones.
// Every replica runs it; the row lock in RunDue keeps them from doubling up.
func (s *Service) Run(ctx context.Context, log *slog.Logger, retentionDays int) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	prune := time.NewTicker(6 * time.Hour)
	defer prune.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-prune.C:
			if n, err := s.Prune(ctx, retentionDays); err != nil {
				log.Error("prune compliance reports", "err", err)
			} else if n > 0 {
				log.Info("pruned compliance reports", "reports", n)
			}
		case <-tick.C:
			// A handful at most per tick, so one replica cannot be kept busy indefinitely.
			for range 10 {
				r, err := s.RunDue(ctx)
				if err != nil {
					if ctx.Err() == nil {
						log.Error("scheduled compliance report failed", "err", err)
					}
					break
				}
				if r == nil {
					break
				}
				log.Info("compliance report generated", "report", r.Name, "id", r.ID)
				if s.Notify != nil {
					text := fmt.Sprintf("Compliance report ready: %s (%d collectors, %d changes, audit log %s).", r.Name, r.Summary.Collectors, r.Summary.Changes,
						map[bool]string{true: "intact", false: "NOT intact"}[r.Summary.AuditIntact])
					if s.PublicURL != "" {
						text += " " + s.PublicURL + "/audit?tab=reports"
					}
					s.Notify(text)
				}
			}
		}
	}
}
