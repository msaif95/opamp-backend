// Package rollout pushes a config version to a selected set of agents in
// batches, tracks per-agent results and pauses when a batch fails too often.
package rollout

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-telemetry/opamp-go/protobufs"

	"github.com/msaif95/opamp-backend/internal/targeting"
)

const (
	tickInterval = 2 * time.Second
	// applyTimeout is how long an agent may sit in offered/applying before
	// it is counted as failed.
	applyTimeout = 5 * time.Minute
	problemLimit = 200

	DefaultBatchSize     = 100
	DefaultMaxFailurePct = 2.0
	maxBatchSize         = 5000
	maxCanarySteps       = 20
)

var (
	ErrNotFound = errors.New("rollout not found")
	// ErrInvalid wraps rejected rollout parameters.
	ErrInvalid = errors.New("invalid rollout")
	// ErrNoAgents is returned when the selector matches no agents.
	ErrNoAgents = errors.New("selector matches no agents")
	// ErrBadState is returned when a rollout cannot make the requested transition.
	ErrBadState = errors.New("rollout is not in a state that allows this action")
)

var acceptsRemoteConfig = int64(protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig)

// Pusher asks the replicas holding the agents' connections to deliver their desired config.
type Pusher interface {
	RequestPush(ctx context.Context, uids ...uuid.UUID) error
}

// Rollout is one bulk config push.
type Rollout struct {
	// ProjectID is the project whose agents the rollout targets; nil means unassigned agents.
	ProjectID       *uuid.UUID         `json:"project_id"`
	ID              uuid.UUID          `json:"id"`
	ConfigVersionID uuid.UUID          `json:"config_version_id"`
	ConfigID        uuid.UUID          `json:"config_id"`
	ConfigName      string             `json:"config_name"`
	ConfigVersion   int                `json:"config_version"`
	Selector        targeting.Selector `json:"selector"`
	// GroupID/GroupName are set when the rollout was started from a saved group.
	GroupID   *uuid.UUID `json:"group_id"`
	GroupName *string    `json:"group_name"`
	BatchSize int        `json:"batch_size"`
	// CanarySteps are cumulative percentages of the target (e.g. 1, 10, 50,
	// 100). Nil means fixed-size batches of BatchSize.
	CanarySteps   []int32 `json:"canary_steps_pct"`
	MaxFailurePct float64 `json:"max_failure_pct"`
	// AutoRollback rolls the rollout back instead of pausing when a batch exceeds MaxFailurePct.
	AutoRollback bool `json:"auto_rollback"`
	// ManualApproval pauses after every batch until an operator resumes.
	ManualApproval bool   `json:"manual_approval"`
	Status         string `json:"status"`
	// BatchesReleased is how many batches have been sent so far.
	BatchesReleased int        `json:"batches_released"`
	TotalBatches    int        `json:"total_batches"`
	TotalAgents     int        `json:"total_agents"`
	CreatedBy       string     `json:"created_by"`
	CreatedAt       time.Time  `json:"created_at"`
	FinishedAt      *time.Time `json:"finished_at"`
	// Error explains why the rollout paused.
	Error *string `json:"error"`
	// Counts is the number of targeted agents per status:
	// pending, offered, applying, applied, failed, skipped, rolled_back.
	Counts map[string]int `json:"counts"`
}

// AgentResult is one agent's outcome within a rollout.
type AgentResult struct {
	InstanceUID uuid.UUID `json:"instance_uid"`
	HostName    string    `json:"host_name"`
	Batch       int       `json:"batch"`
	Status      string    `json:"status"`
	Error       string    `json:"error"`
}

// Preview is the size of the agent set a selector matches.
type Preview struct {
	Total     int `json:"total"`
	Connected int `json:"connected"`
	// Eligible agents accept remote config; the rest are skipped.
	Eligible int `json:"eligible"`
}

// Service creates, tracks and drives rollouts.
type Service struct {
	db   *pgxpool.Pool
	push Pusher
	log  *slog.Logger

	// OnOutcome, if set, is called when the engine itself ends or stops a
	// rollout: "paused", "rolled_back" or "completed". It is called once,
	// by the replica that made the transition.
	OnOutcome func(ctx context.Context, outcome string, r *Rollout)
}

// NewService creates a Service.
func NewService(db *pgxpool.Pool, push Pusher, log *slog.Logger) *Service {
	return &Service{db: db, push: push, log: log}
}

// Preview counts the agents a selector matches right now.
func (s *Service) Preview(ctx context.Context, sel targeting.Selector, project *uuid.UUID) (Preview, error) {
	where, args := sel.WhereIn("attributes", "project_id", project, 2)
	var p Preview
	err := s.db.QueryRow(ctx, `
SELECT count(*), count(*) FILTER (WHERE connected), count(*) FILTER (WHERE capabilities & $1 <> 0)
FROM agents WHERE `+where, append([]any{acceptsRemoteConfig}, args...)...).Scan(&p.Total, &p.Connected, &p.Eligible)
	return p, err
}

// Params describes a new rollout.
type Params struct {
	VersionID uuid.UUID
	Selector  targeting.Selector
	// ProjectID confines the rollout to one project's agents (nil: unassigned agents).
	ProjectID *uuid.UUID
	// GroupID records the saved group the selector came from, if any.
	GroupID   *uuid.UUID
	BatchSize int
	// CanarySteps, when set, replaces fixed batches with cumulative
	// percentage steps. It must be strictly increasing and end at 100.
	CanarySteps   []int
	MaxFailurePct float64
	AutoRollback  bool
	// ManualApproval pauses after every batch until an operator resumes.
	ManualApproval bool
	CreatedBy      string
}

func (p Params) validate() error {
	if p.BatchSize < 1 || p.BatchSize > maxBatchSize {
		return fmt.Errorf("%w: batch_size must be between 1 and %d", ErrInvalid, maxBatchSize)
	}
	if p.MaxFailurePct < 0 || p.MaxFailurePct > 100 {
		return fmt.Errorf("%w: max_failure_pct must be between 0 and 100", ErrInvalid)
	}
	if p.CanarySteps == nil {
		return nil
	}
	if len(p.CanarySteps) == 0 || len(p.CanarySteps) > maxCanarySteps || p.CanarySteps[len(p.CanarySteps)-1] != 100 {
		return fmt.Errorf("%w: canary_steps_pct needs 1 to %d steps and must end at 100", ErrInvalid, maxCanarySteps)
	}
	prev := 0
	for _, pct := range p.CanarySteps {
		if pct <= prev {
			return fmt.Errorf("%w: canary_steps_pct must be increasing percentages above 0", ErrInvalid)
		}
		prev = pct
	}
	return nil
}

// stepBounds converts cumulative percentages into cumulative agent counts
// for a target of total agents. Steps that would add no agents are dropped,
// since the engine treats an empty batch as the end of the rollout.
func stepBounds(steps []int, total int) []int32 {
	var bounds []int32
	for _, pct := range steps {
		n := int32((total*pct + 99) / 100) // ceil, so even 1% of a small target is one agent
		if len(bounds) == 0 || n > bounds[len(bounds)-1] {
			bounds = append(bounds, n)
		}
	}
	return bounds
}

// Create snapshots the agents matching the selector, splits them into
// batches in random order (so the first batch is a representative canary)
// and starts the rollout.
func (s *Service) Create(ctx context.Context, p Params) (*Rollout, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	sel, versionID, batchSize, maxFailurePct, createdBy := p.Selector, p.VersionID, p.BatchSize, p.MaxFailurePct, p.CreatedBy
	var steps []int32
	for _, pct := range p.CanarySteps {
		steps = append(steps, int32(pct))
	}
	selJSON, err := json.Marshal(sel)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var id uuid.UUID
	err = tx.QueryRow(ctx, `
INSERT INTO rollouts (config_version_id, selector, group_id, batch_size, canary_steps_pct, max_failure_pct,
                      auto_rollback, manual_approval, status, created_by, started_at, project_id)
VALUES ($1, $2::jsonb, $3, $4, $5, $6, $7, $8, 'running', $9, now(), $10) RETURNING id`,
		versionID, selJSON, p.GroupID, batchSize, steps, maxFailurePct, p.AutoRollback, p.ManualApproval, createdBy, p.ProjectID).Scan(&id)
	if err != nil {
		return nil, err
	}

	// $2 is the batch size, or for canary rollouts the cumulative agent
	// count at which each step ends.
	where, args := sel.WhereIn("attributes", "project_id", p.ProjectID, 3)
	stepExpr, stepArg := `((rn - 1) / $2::int)::int`, any(batchSize)
	if p.CanarySteps != nil {
		var total int
		countWhere, countArgs := sel.WhereIn("attributes", "project_id", p.ProjectID, 1)
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM agents WHERE `+countWhere, countArgs...).Scan(&total); err != nil {
			return nil, err
		}
		stepExpr, stepArg = `(SELECT count(*) FROM unnest($2::int[]) AS bound WHERE bound < rn)::int`, stepBounds(p.CanarySteps, total)
	}
	tag, err := tx.Exec(ctx, `
INSERT INTO rollout_agents (rollout_id, instance_uid, step)
SELECT $1, instance_uid, `+stepExpr+`
FROM (SELECT instance_uid, row_number() OVER (ORDER BY random()) AS rn FROM agents WHERE `+where+`) t`,
		append([]any{id, stepArg}, args...)...)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNoAgents
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

const rolloutSelect = `
SELECT r.id, r.config_version_id, cv.template_id, ct.name, cv.version, r.selector, r.group_id, g.name, r.batch_size,
       r.canary_steps_pct, r.max_failure_pct::float8, r.auto_rollback, r.manual_approval, r.status::text, r.current_step, r.created_by, r.created_at, r.finished_at, r.error,
       COALESCE((SELECT jsonb_object_agg(status, n) FROM (
           SELECT status::text, count(*) AS n FROM rollout_agents WHERE rollout_id = r.id GROUP BY status) c), '{}'::jsonb),
       COALESCE((SELECT max(step) + 1 FROM rollout_agents WHERE rollout_id = r.id), 0), r.project_id
FROM rollouts r
JOIN config_versions cv ON cv.id = r.config_version_id
JOIN config_templates ct ON ct.id = cv.template_id
LEFT JOIN agent_groups g ON g.id = r.group_id`

func scanRollout(row pgx.CollectableRow) (Rollout, error) {
	var (
		r           Rollout
		sel, counts []byte
	)
	err := row.Scan(&r.ID, &r.ConfigVersionID, &r.ConfigID, &r.ConfigName, &r.ConfigVersion, &sel, &r.GroupID, &r.GroupName,
		&r.BatchSize, &r.CanarySteps, &r.MaxFailurePct, &r.AutoRollback, &r.ManualApproval, &r.Status, &r.BatchesReleased, &r.CreatedBy, &r.CreatedAt, &r.FinishedAt, &r.Error,
		&counts, &r.TotalBatches, &r.ProjectID)
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(sel, &r.Selector); err != nil {
		return r, err
	}
	if err := json.Unmarshal(counts, &r.Counts); err != nil {
		return r, err
	}
	for _, n := range r.Counts {
		r.TotalAgents += n
	}
	return r, nil
}

// List returns the most recent rollouts, newest first.
func (s *Service) List(ctx context.Context, scope targeting.Scope) ([]Rollout, error) {
	where, args := scope.Where("r.project_id", 1)
	rows, err := s.db.Query(ctx, rolloutSelect+` WHERE `+where+` ORDER BY r.created_at DESC LIMIT 100`, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanRollout)
}

// Get returns one rollout.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (*Rollout, error) {
	rows, err := s.db.Query(ctx, rolloutSelect+` WHERE r.id = $1`, id)
	if err != nil {
		return nil, err
	}
	r, err := pgx.CollectExactlyOneRow(rows, scanRollout)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &r, err
}

// Problems returns the failed and skipped agents of a rollout, plus
// rolled-back agents that could not be restored (capped).
func (s *Service) Problems(ctx context.Context, id uuid.UUID) ([]AgentResult, error) {
	rows, err := s.db.Query(ctx, `
SELECT ra.instance_uid, COALESCE(a.attributes->>'host.name', ''), ra.step + 1, ra.status::text, COALESCE(ra.error, '')
FROM rollout_agents ra JOIN agents a USING (instance_uid)
WHERE ra.rollout_id = $1 AND (ra.status IN ('failed', 'skipped') OR (ra.status = 'rolled_back' AND ra.error IS NOT NULL))
ORDER BY ra.status, ra.step, ra.instance_uid LIMIT $2`, id, problemLimit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (AgentResult, error) {
		var a AgentResult
		err := row.Scan(&a.InstanceUID, &a.HostName, &a.Batch, &a.Status, &a.Error)
		return a, err
	})
}

// Pause stops a running rollout from releasing further batches. Agents that
// were already offered the config still apply it.
func (s *Service) Pause(ctx context.Context, id uuid.UUID) error {
	return s.transition(ctx, id, `
UPDATE rollouts SET status = 'paused', error = 'paused by operator' WHERE id = $1 AND status = 'running'`)
}

// Resume continues a paused rollout. Failures in the batches released so
// far are treated as acknowledged and no longer count toward the threshold.
func (s *Service) Resume(ctx context.Context, id uuid.UUID) error {
	return s.transition(ctx, id, `
UPDATE rollouts SET status = 'running', error = NULL, ack_step = current_step - 1 WHERE id = $1 AND status = 'paused'`)
}

// Abort ends a rollout. Pending agents are never offered the config; agents
// already offered it keep it (there is no automatic rollback).
func (s *Service) Abort(ctx context.Context, id uuid.UUID) error {
	return s.transition(ctx, id, `
UPDATE rollouts SET status = 'aborted', finished_at = now() WHERE id = $1 AND status IN ('running', 'paused')`)
}

// Rollback re-assigns every agent this rollout touched to the config it had
// before, pushes that config, and ends the rollout. Agents that had no
// config assigned before cannot be restored through OpAMP and keep the new
// one; they are reported as problems.
func (s *Service) Rollback(ctx context.Context, id uuid.UUID) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var versionID uuid.UUID
	err = tx.QueryRow(ctx, `
SELECT config_version_id FROM rollouts
WHERE id = $1 AND status IN ('running', 'paused', 'completed', 'aborted') FOR UPDATE`, id).Scan(&versionID)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, err := s.Get(ctx, id); err != nil {
			return err
		}
		return ErrBadState
	}
	if err != nil {
		return err
	}
	restored, err := rollbackTx(ctx, tx, id, versionID, "rolled back by operator")
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.pushAll(ctx, id, restored)
	return nil
}

// rollbackTx restores the previous assignment of every agent still assigned
// this rollout's version and marks the rollout rolled back. It returns the
// agents whose previous config must now be pushed.
func rollbackTx(ctx context.Context, tx pgx.Tx, id, versionID uuid.UUID, reason string) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `
WITH targets AS (
    SELECT ra.instance_uid, ra.previous_config_version_id AS prev
    FROM rollout_agents ra JOIN agents a USING (instance_uid)
    WHERE ra.rollout_id = $1 AND ra.status <> 'pending' AND a.desired_config_version_id = $2
    ORDER BY ra.instance_uid FOR UPDATE OF a
), restored AS (
    UPDATE agents a SET desired_config_version_id = t.prev
    FROM targets t WHERE a.instance_uid = t.instance_uid
)
UPDATE rollout_agents ra SET
    status = 'rolled_back',
    error = CASE WHEN t.prev IS NULL THEN 'no previous config to restore; the agent keeps the new config' END
FROM targets t
WHERE ra.rollout_id = $1 AND ra.instance_uid = t.instance_uid
RETURNING ra.instance_uid, t.prev IS NOT NULL`, id, versionID)
	if err != nil {
		return nil, fmt.Errorf("restore previous configs: %w", err)
	}
	var restored []uuid.UUID
	for rows.Next() {
		var (
			uid     uuid.UUID
			hasPrev bool
		)
		if err := rows.Scan(&uid, &hasPrev); err != nil {
			rows.Close()
			return nil, err
		}
		if hasPrev {
			restored = append(restored, uid)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `UPDATE rollouts SET status = 'rolled_back', finished_at = now(), error = $2 WHERE id = $1`, id, reason)
	return restored, err
}

// auditSystem records an action the engine took on its own, in the same
// transaction as the action.
func auditSystem(ctx context.Context, tx pgx.Tx, action string, id uuid.UUID, reason string) error {
	details, _ := json.Marshal(map[string]string{"reason": reason})
	_, err := tx.Exec(ctx, `
INSERT INTO audit_events (actor, actor_auth, action, target_type, target_id, details)
VALUES ('system', 'system', $1, 'rollout', $2, $3::jsonb)`, action, id.String(), details)
	return err
}

// pushAll asks for delivery to each agent. Best effort: an agent that
// misses the push still gets its config with the response to its next message.
func (s *Service) pushAll(ctx context.Context, id uuid.UUID, uids []uuid.UUID) {
	if err := s.push.RequestPush(ctx, uids...); err != nil {
		s.log.WarnContext(ctx, "request push", "rollout_id", id, "agents", len(uids), "err", err)
	}
}

func (s *Service) transition(ctx context.Context, id uuid.UUID, sql string) error {
	tag, err := s.db.Exec(ctx, sql, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		if _, err := s.Get(ctx, id); err != nil {
			return err
		}
		return ErrBadState
	}
	return nil
}

// Run drives running rollouts until ctx is cancelled. It is safe to run on
// every replica: each rollout is advanced under a row lock.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(tickInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.tick(ctx)
		}
	}
}

func (s *Service) tick(ctx context.Context) {
	// Paused and aborted rollouts are still visited while they have agents in
	// flight, so results reported after the pause/abort are recorded.
	rows, err := s.db.Query(ctx, `
SELECT r.id FROM rollouts r
WHERE r.status = 'running' OR (r.status IN ('paused', 'aborted') AND EXISTS (
    SELECT 1 FROM rollout_agents ra WHERE ra.rollout_id = r.id AND ra.status IN ('offered', 'applying')))`)
	if err != nil {
		s.log.ErrorContext(ctx, "list running rollouts", "err", err)
		return
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		s.log.ErrorContext(ctx, "list running rollouts", "err", err)
		return
	}
	for _, id := range ids {
		var outcome string
		released, err := s.advance(ctx, id, &outcome)
		if err != nil {
			s.log.ErrorContext(ctx, "advance rollout", "rollout_id", id, "err", err)
			continue
		}
		s.pushAll(ctx, id, released)
		if outcome != "" && s.OnOutcome != nil {
			if r, err := s.Get(ctx, id); err == nil {
				s.OnOutcome(ctx, outcome, r)
			}
		}
	}
	if err := s.ReconcileGroups(ctx); err != nil && ctx.Err() == nil {
		s.log.ErrorContext(ctx, "assign group configs", "err", err)
	}
}

// reconcileBatch bounds how many agents one group is given its config per tick.
const reconcileBatch = 1000

// ReconcileGroups gives each group's config to agents that match the group
// and have no config assigned: collectors that connected, or started
// matching, after the group's rollout finished.
//
// It only acts once a rollout of that exact version to the group has
// completed (or when the group was empty and none was needed). While a
// rollout is running, late agents join it instead; if it was paused, aborted
// or rolled back, the version is suspect and must not spread on its own.
// An agent matching several groups gets the config of the first by name.
func (s *Service) ReconcileGroups(ctx context.Context) error {
	rows, err := s.db.Query(ctx, `
SELECT g.id, g.selector, g.config_version_id, g.project_id FROM agent_groups g
WHERE g.config_version_id IS NOT NULL AND (
    EXISTS (SELECT 1 FROM rollouts r WHERE r.group_id = g.id AND r.config_version_id = g.config_version_id AND r.status = 'completed')
    OR NOT EXISTS (SELECT 1 FROM rollouts r WHERE r.group_id = g.id AND r.config_version_id = g.config_version_id))
ORDER BY g.name`)
	if err != nil {
		return err
	}
	type group struct {
		id, versionID uuid.UUID
		sel           []byte
		project       *uuid.UUID
	}
	groups, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (group, error) {
		var g group
		err := row.Scan(&g.id, &g.sel, &g.versionID, &g.project)
		return g, err
	})
	if err != nil {
		return err
	}
	for _, g := range groups {
		var sel targeting.Selector
		if err := json.Unmarshal(g.sel, &sel); err != nil {
			return err
		}
		where, args := sel.WhereIn("attributes", "project_id", g.project, 4)
		rows, err := s.db.Query(ctx, `
UPDATE agents SET desired_config_version_id = $1 WHERE instance_uid IN (
    SELECT instance_uid FROM agents
    WHERE desired_config_version_id IS NULL AND capabilities & $2 <> 0 AND `+where+`
    ORDER BY instance_uid LIMIT $3 FOR UPDATE SKIP LOCKED)
RETURNING instance_uid`, append([]any{g.versionID, acceptsRemoteConfig, reconcileBatch}, args...)...)
		if err != nil {
			return fmt.Errorf("assign config of group %s: %w", g.id, err)
		}
		assigned, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return fmt.Errorf("assign config of group %s: %w", g.id, err)
		}
		if len(assigned) > 0 {
			s.log.InfoContext(ctx, "gave group config to newly matching agents", "group_id", g.id, "agents", len(assigned))
			s.pushAll(ctx, g.id, assigned)
		}
	}
	return nil
}

// advance performs one step of the rollout state machine and returns the
// agents that must be pushed a config: the newly released batch, or on an
// automatic rollback the agents being restored. outcome is set when this
// call paused, rolled back or completed the rollout.
func (s *Service) advance(ctx context.Context, id uuid.UUID, outcome *string) ([]uuid.UUID, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var (
		versionID         uuid.UUID
		status            string
		hash              []byte
		maxFailurePct     float64
		autoRollback      bool
		nextStep, ackStep int
		selJSON           []byte
		manualApproval    bool
		project           *uuid.UUID
	)
	err = tx.QueryRow(ctx, `
SELECT r.config_version_id, r.status::text, cv.body_hash, r.max_failure_pct::float8, r.auto_rollback,
       r.current_step, r.ack_step, r.selector, r.manual_approval, r.project_id
FROM rollouts r JOIN config_versions cv ON cv.id = r.config_version_id
WHERE r.id = $1 FOR UPDATE OF r SKIP LOCKED`, id).
		Scan(&versionID, &status, &hash, &maxFailurePct, &autoRollback, &nextStep, &ackStep, &selJSON, &manualApproval, &project)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil // another replica is advancing it
	}
	if err != nil {
		return nil, err
	}

	// 1. Fold agent-reported status into the rollout. updated_at is left
	// untouched so it keeps marking when the agent was offered the config.
	_, err = tx.Exec(ctx, `
UPDATE rollout_agents ra SET
    status = CASE
        WHEN a.desired_config_version_id IS DISTINCT FROM $2 THEN 'skipped'
        WHEN a.remote_config_hash = $3 AND a.remote_config_status = 'applied' THEN 'applied'
        WHEN a.remote_config_hash = $3 AND a.remote_config_status = 'failed' THEN 'failed'
        WHEN ra.updated_at < now() - $4::interval THEN 'failed'
        WHEN a.remote_config_hash = $3 AND a.remote_config_status = 'applying' THEN 'applying'
        ELSE ra.status END::rollout_agent_status,
    error = CASE
        WHEN a.desired_config_version_id IS DISTINCT FROM $2 THEN 'superseded by a newer config assignment'
        WHEN a.remote_config_hash = $3 AND a.remote_config_status = 'applied' THEN NULL
        WHEN a.remote_config_hash = $3 AND a.remote_config_status = 'failed' THEN a.remote_config_error
        WHEN ra.updated_at < now() - $4::interval THEN 'timed out waiting for the agent to apply the config'
        ELSE ra.error END
FROM agents a
WHERE ra.rollout_id = $1 AND ra.instance_uid = a.instance_uid AND ra.status IN ('offered', 'applying')`,
		id, versionID, hash, applyTimeout.String())
	if err != nil {
		return nil, fmt.Errorf("sync agent status: %w", err)
	}

	if status != "running" {
		return nil, tx.Commit(ctx)
	}

	// Agents that started matching the target after the rollout began (new
	// collectors, or ones whose attributes changed) join the next batch to
	// be released, so a long rollout does not leave them behind.
	var sel targeting.Selector
	if err := json.Unmarshal(selJSON, &sel); err != nil {
		return nil, fmt.Errorf("decode selector: %w", err)
	}
	where, args := sel.WhereIn("a.attributes", "a.project_id", project, 3)
	_, err = tx.Exec(ctx, `
INSERT INTO rollout_agents (rollout_id, instance_uid, step)
SELECT $1, a.instance_uid, $2 FROM agents a
WHERE `+where+` AND NOT EXISTS (
    SELECT 1 FROM rollout_agents ra WHERE ra.rollout_id = $1 AND ra.instance_uid = a.instance_uid)`,
		append([]any{id, nextStep}, args...)...)
	if err != nil {
		return nil, fmt.Errorf("add newly matching agents: %w", err)
	}

	// 2. Judge the batch in flight.
	if active := nextStep - 1; active >= 0 {
		var failed, inFlight, attempted int
		err = tx.QueryRow(ctx, `
SELECT count(*) FILTER (WHERE status = 'failed'),
       count(*) FILTER (WHERE status IN ('offered', 'applying')),
       count(*) FILTER (WHERE status IN ('offered', 'applying', 'applied', 'failed'))
FROM rollout_agents WHERE rollout_id = $1 AND step = $2`, id, active).Scan(&failed, &inFlight, &attempted)
		if err != nil {
			return nil, err
		}
		if active > ackStep && failed > 0 && float64(failed)*100/float64(attempted) > maxFailurePct {
			detail := fmt.Sprintf("%d of %d agents in batch %d failed (limit %.4g%%)", failed, attempted, active+1, maxFailurePct)
			if autoRollback {
				restored, err := rollbackTx(ctx, tx, id, versionID, "rolled back automatically: "+detail)
				if err != nil {
					return nil, err
				}
				if err := auditSystem(ctx, tx, "rollout.auto_rollback", id, detail); err != nil {
					return nil, err
				}
				*outcome = "rolled_back"
				return restored, tx.Commit(ctx)
			}
			msg := "paused automatically: " + detail
			if _, err := tx.Exec(ctx, `UPDATE rollouts SET status = 'paused', error = $2 WHERE id = $1`, id, msg); err != nil {
				return nil, err
			}
			if err := auditSystem(ctx, tx, "rollout.auto_pause", id, detail); err != nil {
				return nil, err
			}
			*outcome = "paused"
			return nil, tx.Commit(ctx)
		}
		if inFlight > 0 {
			return nil, tx.Commit(ctx)
		}
		// The batch is settled and within its failure limit. With manual
		// approval, wait here; Resume acknowledges this batch and lets the next one go.
		if manualApproval && active > ackStep {
			var pending int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM rollout_agents WHERE rollout_id = $1 AND status = 'pending'`, id).Scan(&pending); err != nil {
				return nil, err
			}
			if pending > 0 {
				msg := fmt.Sprintf("waiting for approval: batch %d is done (%d of %d agents failed); %d agents are still waiting",
					active+1, failed, attempted, pending)
				if _, err := tx.Exec(ctx, `UPDATE rollouts SET status = 'paused', error = $2 WHERE id = $1`, id, msg); err != nil {
					return nil, err
				}
				*outcome = "awaiting_approval"
				return nil, tx.Commit(ctx)
			}
		}
	}

	// 3. Release the next batch. Agents that cannot take the config now are
	// marked skipped; offline ones still get it assigned and apply it when
	// they reconnect.
	rows, err := tx.Query(ctx, `
WITH batch AS (
    SELECT ra.instance_uid, a.connected AND NOT a.paused AS connected, a.paused, a.capabilities & $4 <> 0 AS accepts,
           a.desired_config_version_id AS prev
    FROM rollout_agents ra JOIN agents a USING (instance_uid)
    WHERE ra.rollout_id = $1 AND ra.step = $2 AND ra.status = 'pending'
    -- Lock agents in a fixed order: heartbeat flushes and offline sweeps on
    -- other replicas update many agent rows too, and unordered locking deadlocks.
    ORDER BY ra.instance_uid FOR UPDATE OF a
), assigned AS (
    UPDATE agents a SET desired_config_version_id = $3
    FROM batch b WHERE a.instance_uid = b.instance_uid AND b.accepts
)
UPDATE rollout_agents ra SET
    status = CASE WHEN b.accepts AND b.connected THEN 'offered' ELSE 'skipped' END::rollout_agent_status,
    error = CASE WHEN NOT b.accepts THEN 'agent does not accept remote config'
                 WHEN b.paused THEN 'collection is paused; the config applies when it is resumed'
                 WHEN NOT b.connected THEN 'agent offline; the config applies when it reconnects' END,
    previous_config_version_id = b.prev,
    updated_at = now()
FROM batch b
WHERE ra.rollout_id = $1 AND ra.instance_uid = b.instance_uid
RETURNING ra.instance_uid, ra.status = 'offered'`, id, nextStep, versionID, acceptsRemoteConfig)
	if err != nil {
		return nil, fmt.Errorf("release batch: %w", err)
	}
	var (
		offered []uuid.UUID
		n       int
	)
	for rows.Next() {
		var (
			uid uuid.UUID
			ok  bool
		)
		if err := rows.Scan(&uid, &ok); err != nil {
			rows.Close()
			return nil, err
		}
		n++
		if ok {
			offered = append(offered, uid)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if n == 0 {
		// Batches are contiguous, so an empty one means every agent is settled.
		_, err = tx.Exec(ctx, `UPDATE rollouts SET status = 'completed', finished_at = now() WHERE id = $1`, id)
		*outcome = "completed"
	} else {
		_, err = tx.Exec(ctx, `UPDATE rollouts SET current_step = current_step + 1 WHERE id = $1`, id)
	}
	if err != nil {
		return nil, err
	}
	return offered, tx.Commit(ctx)
}
