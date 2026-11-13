// Package settings holds the protections an administrator can switch on or
// off at runtime. Values live in Postgres; every replica keeps a cached
// copy that is refreshed on a Redis notification and, as a fallback, every
// few seconds, so a change takes effect fleet-wide without a restart.
package settings

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// Keys of the switchable protections.
const (
	SSO               = "sso"
	LocalLogin        = "local_login"
	AgentTLS          = "agent_tls"
	AgentMTLS         = "agent_mtls"
	AlertDelivery     = "alert_delivery"
	Telemetry         = "telemetry"
	Rebalancing       = "rebalancing"
	FleetHealthAlerts = "fleet_health_alerts"
	// SecondApprover requires someone other than the person who started a bulk push to resume or approve it.
	SecondApprover = "second_approver"
)

const (
	channel         = "opamp:settings-changed"
	refreshInterval = 5 * time.Second
)

var (
	ErrUnknown = errors.New("unknown setting")
	// ErrLocked is returned for a setting that can only be changed by redeploying.
	ErrLocked = errors.New("this setting cannot be changed at runtime; it is part of the deployment configuration")
	// ErrUnavailable is returned when enabling something that is not configured.
	ErrUnavailable = errors.New("this feature is not configured in the deployment, so it cannot be switched on")
	// ErrLockout is returned when a change would leave nobody able to sign in.
	ErrLockout = errors.New("refusing to switch off the last working sign-in method: nobody could sign in to switch it back on")
)

// Definition describes one protection as deployed.
type Definition struct {
	// Available is whether the deployment configured the feature at all
	// (for example, whether an alert webhook URL was provided).
	Available bool
	// Locked settings are shown but cannot be changed at runtime.
	Locked bool
	// Default applies while no administrator has made a choice.
	Default bool
}

// State is a protection's current state, for display.
type State struct {
	Key       string `json:"key"`
	Available bool   `json:"available"`
	Locked    bool   `json:"locked"`
	// Enabled is the administrator's switch; the protection is in effect
	// only when it is also Available.
	Enabled   bool       `json:"enabled"`
	UpdatedBy *string    `json:"updated_by"`
	UpdatedAt *time.Time `json:"updated_at"`
}

type row struct {
	enabled   bool
	updatedBy string
	updatedAt time.Time
}

// Store reads and changes settings.
type Store struct {
	db   *pgxpool.Pool
	rdb  *redis.Client
	defs map[string]Definition
	log  *slog.Logger

	mu   sync.RWMutex
	rows map[string]row
}

// New creates a Store and loads the current values.
func New(ctx context.Context, db *pgxpool.Pool, rdb *redis.Client, defs map[string]Definition, log *slog.Logger) (*Store, error) {
	s := &Store{db: db, rdb: rdb, defs: defs, log: log, rows: map[string]row{}}
	return s, s.reload(ctx)
}

func (s *Store) reload(ctx context.Context) error {
	rows, err := s.db.Query(ctx, `SELECT key, enabled, updated_by, updated_at FROM settings`)
	if err != nil {
		return err
	}
	defer rows.Close()
	loaded := map[string]row{}
	for rows.Next() {
		var (
			key string
			r   row
		)
		if err := rows.Scan(&key, &r.enabled, &r.updatedBy, &r.updatedAt); err != nil {
			return err
		}
		loaded[key] = r
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.rows = loaded
	s.mu.Unlock()
	return nil
}

// Run keeps the cache fresh until ctx is cancelled.
func (s *Store) Run(ctx context.Context) {
	sub := s.rdb.Subscribe(ctx, channel)
	defer sub.Close()
	t := time.NewTicker(refreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sub.Channel():
		case <-t.C:
		}
		if err := s.reload(ctx); err != nil && ctx.Err() == nil {
			// Keep the last known values: failing open or closed on a database blip would both be wrong.
			s.log.Warn("could not refresh settings; keeping the last known values", "err", err)
		}
	}
}

// switchOn reports the administrator's switch for key, or its default.
func (s *Store) switchOn(key string) bool {
	s.mu.RLock()
	r, ok := s.rows[key]
	s.mu.RUnlock()
	if ok {
		return r.enabled
	}
	return s.defs[key].Default
}

// Enabled reports whether the protection is in effect: configured in the
// deployment and not switched off.
func (s *Store) Enabled(key string) bool {
	return s.defs[key].Available && s.switchOn(key)
}

// Func returns Enabled bound to key, for components that take a func() bool.
func (s *Store) Func(key string) func() bool {
	return func() bool { return s.Enabled(key) }
}

// List returns every protection's state in a stable order.
func (s *Store) List() []State {
	order := []string{SSO, LocalLogin, AgentTLS, AgentMTLS, AlertDelivery, Telemetry, Rebalancing, FleetHealthAlerts, SecondApprover}
	out := make([]State, 0, len(order))
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, key := range order {
		def, ok := s.defs[key]
		if !ok {
			continue
		}
		st := State{Key: key, Available: def.Available, Locked: def.Locked, Enabled: def.Default}
		if r, ok := s.rows[key]; ok {
			st.Enabled, st.UpdatedBy, st.UpdatedAt = r.enabled, &r.updatedBy, &r.updatedAt
		}
		out = append(out, st)
	}
	return out
}

// Set switches a protection on or off.
func (s *Store) Set(ctx context.Context, key string, enabled bool, by string) error {
	def, ok := s.defs[key]
	switch {
	case !ok:
		return ErrUnknown
	case def.Locked:
		return ErrLocked
	case enabled && !def.Available:
		return ErrUnavailable
	}
	if !enabled && (key == SSO || key == LocalLogin) {
		other := LocalLogin
		if key == LocalLogin {
			other = SSO
		}
		if !s.Enabled(other) {
			return ErrLockout
		}
	}
	_, err := s.db.Exec(ctx, `
INSERT INTO settings (key, enabled, updated_by) VALUES ($1, $2, $3)
ON CONFLICT (key) DO UPDATE SET enabled = EXCLUDED.enabled, updated_by = EXCLUDED.updated_by, updated_at = now()`,
		key, enabled, by)
	if err != nil {
		return fmt.Errorf("save setting %s: %w", key, err)
	}
	if err := s.reload(ctx); err != nil {
		return err
	}
	// Best effort: replicas that miss this pick the change up on their next refresh.
	_ = s.rdb.Publish(ctx, channel, key).Err()
	return nil
}
