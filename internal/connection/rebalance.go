package connection

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/msaif95/opamp-backend/internal/registry"
)

const (
	rebalanceInterval = 30 * time.Second
	// A replica must have been up this long before it sheds or is counted as
	// a destination: a fresh replica may not be taking traffic yet, and one
	// that just absorbed a reconnect storm has not settled.
	rebalanceMinUptime = time.Minute
	// Shedding starts, and stops, when a replica holds this much more than its
	// fair share. Tighter than this buys little and costs reconnects.
	rebalanceTolerancePct = 10
	rebalanceMinExcess    = 20
	// At most this share of a replica's connections is dropped per round.
	rebalanceMaxShedPct = 5
	// If this many consecutive rounds do not bring the load down, the load
	// balancer is probably sending agents straight back (sticky routing),
	// and shedding would only churn connections. Stop for a while.
	rebalanceFutileRounds = 10
	rebalanceBackoff      = 15 * time.Minute
)

// shedCount decides how many connections a replica holding mine should drop
// so they reconnect elsewhere, given what the other settled replicas hold.
// Dropped agents are spread by the load balancer over all replicas, this one
// included, so only half the excess is shed per round and the fleet
// converges without overshooting.
func shedCount(mine int, others []int) int {
	if len(others) == 0 {
		return 0
	}
	total := mine
	for _, n := range others {
		total += n
	}
	replicas := len(others) + 1
	fair := (total + replicas - 1) / replicas
	excess := mine - fair
	if excess < rebalanceMinExcess || excess*100 < fair*rebalanceTolerancePct {
		return 0
	}
	return min(excess/2, max(mine*rebalanceMaxShedPct/100, 1))
}

// Rebalancer evens out agent connections across replicas. Connections are
// long-lived, so without it a replica that restarts or is added stays
// nearly empty while the others carry the fleet.
type Rebalancer struct {
	Manager   *Manager
	ReplicaID string
	StartedAt time.Time
	// Replicas lists the running replicas with their connection counts.
	Replicas func(ctx context.Context) ([]registry.Replica, error)
	Log      *slog.Logger
	// Enabled, if set, is consulted every round; false skips it.
	Enabled func() bool

	futile      int
	streakStart int
	pausedUntil time.Time
}

// Run rebalances periodically until ctx is cancelled.
func (r *Rebalancer) Run(ctx context.Context) {
	t := time.NewTicker(rebalanceInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			r.round(ctx, now)
		}
	}
}

func (r *Rebalancer) round(ctx context.Context, now time.Time) {
	if now.Sub(r.StartedAt) < rebalanceMinUptime || now.Before(r.pausedUntil) || (r.Enabled != nil && !r.Enabled()) {
		return
	}
	replicas, err := r.Replicas(ctx)
	if err != nil {
		return // Redis is down; nothing sensible to do
	}
	var others []int
	for _, rep := range replicas {
		if rep.ID != r.ReplicaID && now.Sub(rep.StartedAt) >= rebalanceMinUptime {
			others = append(others, rep.Connections)
		}
	}
	mine := r.Manager.ConnectionCount()
	n := shedCount(mine, others)
	if n == 0 {
		r.futile = 0
		return
	}

	if r.futile == 0 {
		r.streakStart = mine
	}
	r.futile++
	if r.futile > rebalanceFutileRounds {
		if mine*10 > r.streakStart*9 { // less than 10% lower after all those rounds
			r.pausedUntil = now.Add(rebalanceBackoff)
			r.Log.Warn("rebalancing is not reducing this replica's load; pausing it. "+
				"Check that the load balancer in front of the OpAMP port does not pin agents to a replica",
				"connections", mine, "paused_for", rebalanceBackoff.String())
		}
		r.futile = 0
		return
	}

	dropped := r.Manager.Shed(n)
	r.Manager.shed.Add(ctx, int64(dropped), metric.WithAttributes(attribute.String("reason", "rebalance")))
	r.Log.Info("rebalancing: closed agent connections so they reconnect to less loaded replicas",
		"closed", dropped, "connections_before", mine, "other_replicas", others)
}

// Shed closes up to n agent connections, chosen arbitrarily, and returns how
// many were closed. The agents reconnect through the load balancer.
func (m *Manager) Shed(n int) int {
	m.mu.Lock()
	drop := make([]interface{ Disconnect() error }, 0, n)
	for conn := range m.conns {
		if len(drop) == n {
			break
		}
		drop = append(drop, conn)
	}
	m.mu.Unlock()
	for _, conn := range drop {
		_ = conn.Disconnect()
	}
	return len(drop)
}
