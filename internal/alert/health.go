package alert

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	healthInterval = time.Minute
	// RecentlyOfflineWindow is how long a disconnected agent counts toward
	// the offline alert. Older ones are treated as decommissioned, so a
	// retired host does not keep the alert firing forever.
	RecentlyOfflineWindow = time.Hour
	// Below this many affected agents a percentage is noise (1 of 3 agents is 33%).
	healthMinAgents = 5
	// A firing alert resolves only once the value falls below this fraction
	// of its threshold, so a fleet hovering at the line does not flap.
	healthResolveFactor = 0.8

	healthLockKey     = "opamp:health-eval"
	healthFiringKey   = "opamp:alert-firing:"
	ruleOffline       = "offline"
	ruleUnhealthy     = "unhealthy"
	healthLockSeconds = 55
)

// FleetStats is the input to the fleet-health rules.
type FleetStats struct {
	Connected int
	// RecentlyOffline agents disconnected within RecentlyOfflineWindow.
	RecentlyOffline int
	// Unhealthy agents are connected and report themselves unhealthy.
	Unhealthy int
}

// ruleState is one rule evaluated against the fleet.
type ruleState struct {
	rule     string
	pct      float64
	affected int
	limit    float64
	// what the affected agents are, for the message.
	firing, resolved string
}

func rules(s FleetStats, offlinePct, unhealthyPct float64) []ruleState {
	var out []ruleState
	if known := s.Connected + s.RecentlyOffline; offlinePct > 0 {
		pct := 0.0
		if known > 0 {
			pct = float64(s.RecentlyOffline) * 100 / float64(known)
		}
		out = append(out, ruleState{rule: ruleOffline, pct: pct, affected: s.RecentlyOffline, limit: offlinePct,
			firing:   fmt.Sprintf("%d of %d agents (%.0f%%) went offline in the last hour", s.RecentlyOffline, known, pct),
			resolved: fmt.Sprintf("offline agents are back under the limit: %d of %d (%.0f%%)", s.RecentlyOffline, known, pct)})
	}
	if unhealthyPct > 0 {
		pct := 0.0
		if s.Connected > 0 {
			pct = float64(s.Unhealthy) * 100 / float64(s.Connected)
		}
		out = append(out, ruleState{rule: ruleUnhealthy, pct: pct, affected: s.Unhealthy, limit: unhealthyPct,
			firing:   fmt.Sprintf("%d of %d connected agents (%.0f%%) report themselves unhealthy", s.Unhealthy, s.Connected, pct),
			resolved: fmt.Sprintf("unhealthy agents are back under the limit: %d of %d (%.0f%%)", s.Unhealthy, s.Connected, pct)})
	}
	return out
}

// transition decides whether a rule starts firing, resolves, or stays as it is.
func (r ruleState) transition(wasFiring bool) (nowFiring bool, message string) {
	switch {
	case !wasFiring && r.pct >= r.limit && r.affected >= healthMinAgents:
		return true, fmt.Sprintf("OpAMP fleet alert: %s (limit %.4g%%).", r.firing, r.limit)
	case wasFiring && (r.pct < r.limit*healthResolveFactor || r.affected < healthMinAgents):
		return false, fmt.Sprintf("OpAMP fleet alert resolved: %s.", r.resolved)
	}
	return wasFiring, ""
}

// HealthMonitor raises alerts when too much of the fleet is offline or
// unhealthy, and again when it recovers. Every replica runs one; a Redis
// lock lets a single replica evaluate each minute, and the firing state
// lives in Redis so a replica restart neither repeats nor loses an alert.
type HealthMonitor struct {
	Stats        func(ctx context.Context) (FleetStats, error)
	Redis        *redis.Client
	Notify       func(text string)
	OfflinePct   float64
	UnhealthyPct float64
	// PublicURL, if set, is appended to alerts as a link to the console.
	PublicURL string
	Log       *slog.Logger
}

// Run evaluates the rules every minute until ctx is cancelled.
func (m *HealthMonitor) Run(ctx context.Context) {
	if m.OfflinePct <= 0 && m.UnhealthyPct <= 0 {
		return
	}
	t := time.NewTicker(healthInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.Evaluate(ctx); err != nil && ctx.Err() == nil {
				m.Log.Warn("fleet health check failed", "err", err)
			}
		}
	}
}

// Evaluate runs one check, if this replica wins the lock for this minute.
func (m *HealthMonitor) Evaluate(ctx context.Context) error {
	won, err := m.Redis.SetNX(ctx, healthLockKey, 1, healthLockSeconds*time.Second).Result()
	if err != nil || !won {
		return err
	}
	stats, err := m.Stats(ctx)
	if err != nil {
		return err
	}
	for _, r := range rules(stats, m.OfflinePct, m.UnhealthyPct) {
		was, err := m.Redis.Exists(ctx, healthFiringKey+r.rule).Result()
		if err != nil {
			return err
		}
		now, message := r.transition(was == 1)
		if message == "" {
			continue
		}
		if now {
			err = m.Redis.Set(ctx, healthFiringKey+r.rule, 1, 0).Err()
		} else {
			err = m.Redis.Del(ctx, healthFiringKey+r.rule).Err()
		}
		if err != nil {
			return err
		}
		if m.PublicURL != "" {
			message += " " + m.PublicURL + "/agents"
		}
		m.Notify(message)
	}
	return nil
}
