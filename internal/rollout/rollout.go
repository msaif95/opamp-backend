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

// Pusher asks the replica holding an agent's connection to deliver its desired config.
type Pusher interface {
	RequestPush(ctx context.Context, uid uuid.UUID) error
}

// Rollout is one bulk config push.
type Rollout struct {
	ID              uuid.UUID          `json:"id"`
	ConfigVersionID uuid.UUID          `json:"config_version_id"`
	ConfigID        uuid.UUID          `json:"config_id"`
	ConfigName      string             `json:"config_name"`
	ConfigVersion   int                `json:"config_version"`
	Selector        targeting.Selector `json:"selector"`
	BatchSize       int                `json:"batch_size"`
	MaxFailurePct   float64            `json:"max_failure_pct"`
	Status          string             `json:"status"`
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
	// pending, offered, applying, applied, failed, skipped.
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
}

// NewService creates a Service.
func NewService(db *pgxpool.Pool, push Pusher, log *slog.Logger) *Service {
	return &Service{db: db, push: push, log: log}
}

// Preview counts the agents a selector matches right now.
func (s *Service) Preview(ctx context.Context, sel targeting.Selector) (Preview, error) {
	where, args := sel.Where("attributes", 2)
	var p Preview
	err := s.db.QueryRow(ctx, `
SELECT count(*), count(*) FILTER (WHERE connected), count(*) FILTER (WHERE capabilities & $1 <> 0)
FROM agents WHERE `+where, append([]any{acceptsRemoteConfig}, args...)...).Scan(&p.Total, &p.Connected, &p.Eligible)
	return p, err
}

// Create snapshots the agents matching sel, splits them into batches in
// random order (so the first batch is a representative canary) and starts
// the rollout.
func (s *Service) Create(ctx context.Context, versionID uuid.UUID, sel targeting.Selector, batchSize int, maxFailurePct float64, createdBy string) (*Rollout, error) {
	if batchSize < 1 || batchSize > maxBatchSize {
		return nil, fmt.Errorf("%w: batch_size must be between 1 and %d", ErrInvalid, maxBatchSize)
	}
	if maxFailurePct < 0 || maxFailurePct > 100 {
		return nil, fmt.Errorf("%w: max_failure_pct must be between 0 and 100", ErrInvalid)
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
INSERT INTO rollouts (config_version_id, selector, batch_size, max_failure_pct, status, created_by, started_at)
VALUES ($1, $2::jsonb, $3, $4, 'running', $5, now()) RETURNING id`,
		versionID, selJSON, batchSize, maxFailurePct, createdBy).Scan(&id)
	if err != nil {
		return nil, err
	}

	where, args := sel.Where("attributes", 3)
	tag, err := tx.Exec(ctx, `
INSERT INTO rollout_agents (rollout_id, instance_uid, step)
SELECT $1, instance_uid, (row_number() OVER (ORDER BY random()) - 1) / $2
FROM agents WHERE `+where, append([]any{id, batchSize}, args...)...)
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
SELECT r.id, r.config_version_id, cv.template_id, ct.name, cv.version, r.selector, r.batch_size,
       r.max_failure_pct::float8, r.status::text, r.current_step, r.created_by, r.created_at, r.finished_at, r.error,
       COALESCE((SELECT jsonb_object_agg(status, n) FROM (
           SELECT status::text, count(*) AS n FROM rollout_agents WHERE rollout_id = r.id GROUP BY status) c), '{}'::jsonb),
       COALESCE((SELECT max(step) + 1 FROM rollout_agents WHERE rollout_id = r.id), 0)
FROM rollouts r
JOIN config_versions cv ON cv.id = r.config_version_id
JOIN config_templates ct ON ct.id = cv.template_id`

func scanRollout(row pgx.CollectableRow) (Rollout, error) {
	var (
		r           Rollout
		sel, counts []byte
	)
	err := row.Scan(&r.ID, &r.ConfigVersionID, &r.ConfigID, &r.ConfigName, &r.ConfigVersion, &sel, &r.BatchSize,
		&r.MaxFailurePct, &r.Status, &r.BatchesReleased, &r.CreatedBy, &r.CreatedAt, &r.FinishedAt, &r.Error,
		&counts, &r.TotalBatches)
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
func (s *Service) List(ctx context.Context) ([]Rollout, error) {
	rows, err := s.db.Query(ctx, rolloutSelect+` ORDER BY r.created_at DESC LIMIT 100`)
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

// Problems returns the failed and skipped agents of a rollout (capped).
func (s *Service) Problems(ctx context.Context, id uuid.UUID) ([]AgentResult, error) {
	rows, err := s.db.Query(ctx, `
SELECT ra.instance_uid, COALESCE(a.attributes->>'host.name', ''), ra.step + 1, ra.status::text, COALESCE(ra.error, '')
FROM rollout_agents ra JOIN agents a USING (instance_uid)
WHERE ra.rollout_id = $1 AND ra.status IN ('failed', 'skipped')
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
		released, err := s.advance(ctx, id)
		if err != nil {
			s.log.ErrorContext(ctx, "advance rollout", "rollout_id", id, "err", err)
			continue
		}
		for _, uid := range released {
			// Best effort: an agent that misses the push still gets the
			// config with the response to its next message.
			if err := s.push.RequestPush(ctx, uid); err != nil {
				s.log.WarnContext(ctx, "request push", "rollout_id", id, "instance_uid", uid, "err", err)
			}
		}
	}
}

// advance performs one step of the rollout state machine and returns the
// agents that were just offered the config.
func (s *Service) advance(ctx context.Context, id uuid.UUID) ([]uuid.UUID, error) {
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
		nextStep, ackStep int
	)
	err = tx.QueryRow(ctx, `
SELECT r.config_version_id, r.status::text, cv.body_hash, r.max_failure_pct::float8, r.current_step, r.ack_step
FROM rollouts r JOIN config_versions cv ON cv.id = r.config_version_id
WHERE r.id = $1 FOR UPDATE OF r SKIP LOCKED`, id).
		Scan(&versionID, &status, &hash, &maxFailurePct, &nextStep, &ackStep)
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
			msg := fmt.Sprintf("paused automatically: %d of %d agents in batch %d failed (limit %.4g%%)",
				failed, attempted, active+1, maxFailurePct)
			if _, err := tx.Exec(ctx, `UPDATE rollouts SET status = 'paused', error = $2 WHERE id = $1`, id, msg); err != nil {
				return nil, err
			}
			return nil, tx.Commit(ctx)
		}
		if inFlight > 0 {
			return nil, tx.Commit(ctx)
		}
	}

	// 3. Release the next batch. Agents that cannot take the config now are
	// marked skipped; offline ones still get it assigned and apply it when
	// they reconnect.
	rows, err := tx.Query(ctx, `
WITH batch AS (
    SELECT ra.instance_uid, a.connected, a.capabilities & $4 <> 0 AS accepts
    FROM rollout_agents ra JOIN agents a USING (instance_uid)
    WHERE ra.rollout_id = $1 AND ra.step = $2 AND ra.status = 'pending'
), assigned AS (
    UPDATE agents a SET desired_config_version_id = $3
    FROM batch b WHERE a.instance_uid = b.instance_uid AND b.accepts
)
UPDATE rollout_agents ra SET
    status = CASE WHEN b.accepts AND b.connected THEN 'offered' ELSE 'skipped' END::rollout_agent_status,
    error = CASE WHEN NOT b.accepts THEN 'agent does not accept remote config'
                 WHEN NOT b.connected THEN 'agent offline; the config applies when it reconnects' END,
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
	} else {
		_, err = tx.Exec(ctx, `UPDATE rollouts SET current_step = current_step + 1 WHERE id = $1`, id)
	}
	if err != nil {
		return nil, err
	}
	return offered, tx.Commit(ctx)
}
