// Package retention deletes data that has outlived its configured
// retention period, so the audit log, rollout history and decommissioned
// agents do not grow without bound.
package retention

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

const (
	interval = 6 * time.Hour
	lockKey  = "opamp:retention"
	// Deletes are done in batches so one run never holds long locks.
	batch = 5000
)

// Job prunes old rows. A period of 0 days keeps that data forever.
type Job struct {
	DB    *pgxpool.Pool
	Redis *redis.Client
	Log   *slog.Logger

	AuditDays   int
	RolloutDays int
	AgentDays   int
	// AgentEventDays bounds each agent's history (the Activity tab).
	AgentEventDays int
}

// Run prunes shortly after start and then every few hours until ctx is
// cancelled. Every replica runs it; a Redis lock lets one do the work.
func (j *Job) Run(ctx context.Context) {
	if j.AuditDays+j.RolloutDays+j.AgentDays+j.AgentEventDays == 0 {
		return
	}
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			timer.Reset(interval)
			won, err := j.Redis.SetNX(ctx, lockKey, 1, interval-time.Minute).Result()
			if err != nil || !won {
				continue
			}
			if err := j.Prune(ctx); err != nil && ctx.Err() == nil {
				j.Log.Error("retention run failed", "err", err)
			}
		}
	}
}

// Prune deletes everything past its retention period.
func (j *Job) Prune(ctx context.Context) error {
	for _, rule := range []struct {
		what string
		days int
		sql  string
	}{
		{"audit events", j.AuditDays, `
DELETE FROM audit_events WHERE id IN (
    SELECT id FROM audit_events WHERE occurred_at < now() - make_interval(days => $1) LIMIT $2)`},
		{"agent history", j.AgentEventDays, `
DELETE FROM agent_events WHERE id IN (
    SELECT id FROM agent_events WHERE occurred_at < now() - make_interval(days => $1) LIMIT $2)`},
		// Only finished rollouts; their per-agent rows go with them.
		{"rollouts", j.RolloutDays, `
DELETE FROM rollouts WHERE id IN (
    SELECT id FROM rollouts WHERE finished_at < now() - make_interval(days => $1) LIMIT $2)`},
		// Offline agents only. One that comes back simply registers again.
		{"offline agents", j.AgentDays, `
DELETE FROM agents WHERE instance_uid IN (
    SELECT instance_uid FROM agents WHERE NOT connected AND last_seen < now() - make_interval(days => $1)
    ORDER BY instance_uid LIMIT $2 FOR UPDATE SKIP LOCKED)`},
	} {
		if rule.days == 0 {
			continue
		}
		var total int64
		for {
			tag, err := j.DB.Exec(ctx, rule.sql, rule.days, batch)
			if err != nil {
				return err
			}
			total += tag.RowsAffected()
			if tag.RowsAffected() < batch {
				break
			}
		}
		if total > 0 {
			j.Log.Info("retention: deleted old rows", "what", rule.what, "older_than_days", rule.days, "rows", total)
		}
	}
	return nil
}
