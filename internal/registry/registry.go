// Package registry persists agent state in Postgres and maintains the
// Redis-backed agent -> replica routing table used for horizontal fan-out.
package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/redis/go-redis/v9"

	"github.com/msaif95/opamp-backend/internal/logthrottle"
)

const (
	routeKeyPrefix = "opamp:route:"
	pushChanPrefix = "opamp:push:"
	// EventsChannel carries agent change notifications across replicas.
	EventsChannel = "opamp:agent-events"
)

var (
	// ErrNotFound is returned when an agent does not exist.
	ErrNotFound = errors.New("agent not found")
	// ErrRemoteConfigUnsupported is returned when assigning a config to an
	// agent that did not advertise the AcceptsRemoteConfig capability.
	ErrRemoteConfigUnsupported = errors.New("agent does not accept remote config")
)

// DesiredConfig describes the config version assigned to an agent.
type DesiredConfig struct {
	VersionID    uuid.UUID `json:"version_id"`
	TemplateID   uuid.UUID `json:"template_id"`
	TemplateName string    `json:"template_name"`
	Version      int       `json:"version"`
	// InSync is true once the agent reports this exact version as applied.
	InSync bool `json:"in_sync"`
}

// ConfigState is what the protocol layer needs to decide whether to offer
// an agent its remote config.
type ConfigState struct {
	Capabilities           uint64
	DesiredConfigVersionID *uuid.UUID
	RemoteConfigHash       []byte
	// Paused agents are sent an empty pipeline instead of their assigned config.
	Paused bool
}

// Agent is the API/storage representation of one collector instance.
type Agent struct {
	InstanceUID uuid.UUID `json:"instance_uid"`
	// ProjectID is the project the collector belongs to; nil means unassigned.
	ProjectID              *uuid.UUID        `json:"project_id"`
	ConnectorType          string            `json:"connector_type"`
	AuthMode               string            `json:"auth_mode"`
	Attributes             map[string]string `json:"attributes"`
	Capabilities           uint64            `json:"capabilities"`
	AgentVersion           *string           `json:"agent_version"`
	Healthy                *bool             `json:"healthy"`
	HealthStatus           *string           `json:"health_status"`
	HealthLastError        *string           `json:"health_last_error"`
	EffectiveConfigHash    []byte            `json:"effective_config_hash"`
	EffectiveConfig        *string           `json:"effective_config,omitempty"`
	RemoteConfigHash       []byte            `json:"remote_config_hash"`
	RemoteConfigStatus     string            `json:"remote_config_status"`
	RemoteConfigError      *string           `json:"remote_config_error"`
	DesiredConfigVersionID *uuid.UUID        `json:"desired_config_version_id"`
	DesiredConfig          *DesiredConfig    `json:"desired_config"`
	// Paused: collection is stopped; the collector runs an empty pipeline.
	Paused    bool      `json:"paused"`
	Connected bool      `json:"connected"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Event is published on EventsChannel whenever an agent's state changes.
type Event struct {
	Type        string    `json:"type"` // agent.updated | agent.connected | agent.disconnected
	InstanceUID uuid.UUID `json:"instance_uid"`
	ReplicaID   string    `json:"replica_id"`
	At          time.Time `json:"at"`
}

// Identity describes how the agent authenticated on this connection.
type Identity struct {
	AuthMode     string // mtls | api_key
	CredentialID *uuid.UUID
	// Set for mTLS: SHA-256 of the client certificate and its expiry.
	CertFingerprint []byte
	CertNotAfter    time.Time
}

// Registry is the agent registry service.
type Registry struct {
	db        *pgxpool.Pool
	rdb       *redis.Client
	replicaID string
	routeTTL  time.Duration

	redisWarn *logthrottle.Throttle
	// OnRestart is called on the replica holding the agent's connection when a restart is requested.
	OnRestart func(uid uuid.UUID)

	// Agents that heartbeated since the last flush; see FlushHeartbeats.
	hbMu       sync.Mutex
	heartbeats map[uuid.UUID]struct{}
}

// New creates a Registry. routeTTL bounds how long a routing entry survives
// without a heartbeat from the owning replica.
func New(db *pgxpool.Pool, rdb *redis.Client, replicaID string, routeTTL time.Duration) *Registry {
	return &Registry{db: db, rdb: rdb, replicaID: replicaID, routeTTL: routeTTL,
		heartbeats: make(map[uuid.UUID]struct{}), redisWarn: logthrottle.New(10 * time.Second)}
}

const (
	replicaKeyPrefix = "opamp:replica:"
	// ReplicaAnnounceInterval is how often a replica reports itself; it is
	// forgotten after three missed reports.
	ReplicaAnnounceInterval = 10 * time.Second
)

// Replica is one running backend instance, as last reported by itself.
type Replica struct {
	ID          string    `json:"id"`
	Connections int       `json:"connections"`
	StartedAt   time.Time `json:"started_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// AnnounceReplica records that this replica is alive and how many agent connections it holds.
func (r *Registry) AnnounceReplica(ctx context.Context, connections int, startedAt time.Time) error {
	b, _ := json.Marshal(Replica{ID: r.replicaID, Connections: connections, StartedAt: startedAt, UpdatedAt: time.Now().UTC()})
	return r.rdb.Set(ctx, replicaKeyPrefix+r.replicaID, b, 3*ReplicaAnnounceInterval).Err()
}

// WithdrawReplica removes this replica from the list at shutdown.
func (r *Registry) WithdrawReplica(ctx context.Context) error {
	return r.rdb.Del(ctx, replicaKeyPrefix+r.replicaID).Err()
}

// Replicas lists the backend instances that reported recently, by ID.
func (r *Registry) Replicas(ctx context.Context) ([]Replica, error) {
	var keys []string
	iter := r.rdb.Scan(ctx, 0, replicaKeyPrefix+"*", 100).Iterator()
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, nil
	}
	vals, err := r.rdb.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}
	replicas := make([]Replica, 0, len(vals))
	for _, v := range vals {
		var rep Replica
		if s, ok := v.(string); ok && json.Unmarshal([]byte(s), &rep) == nil {
			replicas = append(replicas, rep)
		}
	}
	sort.Slice(replicas, func(i, j int) bool { return replicas[i].ID < replicas[j].ID })
	return replicas, nil
}

// HeartbeatFlushInterval is how often buffered heartbeats are written to
// Postgres; last_seen can lag reality by this much.
const HeartbeatFlushInterval = 5 * time.Second

// IsHeartbeat reports whether the message carries no state change.
func IsHeartbeat(msg *protobufs.AgentToServer) bool {
	return msg.AgentDescription == nil && msg.Health == nil && msg.EffectiveConfig == nil &&
		msg.RemoteConfigStatus == nil && msg.PackageStatuses == nil && msg.AgentDisconnect == nil
}

// heartbeat handles a message with no state change without writing to
// Postgres: at fleet scale these are almost all messages, and one
// synchronous commit each would dominate the database's write load. The
// agent's liveness is recorded in Redis immediately and its last_seen is
// written in batches. ok is false when the stored row cannot be trusted
// (unknown agent, marked offline, or changed capabilities) and the caller
// must fall back to the full upsert.
func (r *Registry) heartbeat(ctx context.Context, uid uuid.UUID, msg *protobufs.AgentToServer) (st ConfigState, ok bool, err error) {
	var (
		caps      int64
		connected bool
	)
	err = r.db.QueryRow(ctx, `
SELECT capabilities, desired_config_version_id, remote_config_hash, connected, paused FROM agents WHERE instance_uid = $1`,
		uid).Scan(&caps, &st.DesiredConfigVersionID, &st.RemoteConfigHash, &connected, &st.Paused)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (!connected || uint64(caps) != msg.Capabilities)) {
		return st, false, nil
	}
	if err != nil {
		return st, false, fmt.Errorf("load agent %s: %w", uid, err)
	}
	st.Capabilities = uint64(caps)
	r.hbMu.Lock()
	r.heartbeats[uid] = struct{}{}
	r.hbMu.Unlock()
	return st, true, nil
}

// setRoute records which replica holds the agent's connection. A Redis
// failure is logged, not returned: the agent's state lives in Postgres, and
// failing its message would only make the whole fleet reconnect in a loop.
// Without a route the agent misses pushes but still receives its config
// with the response to its next message.
func (r *Registry) setRoute(ctx context.Context, uid uuid.UUID) {
	if err := r.rdb.Set(ctx, routeKeyPrefix+uid.String(), r.replicaID, r.routeTTL).Err(); err != nil && ctx.Err() == nil {
		r.redisWarn.Do(func(suppressed int64) {
			slog.WarnContext(ctx, "redis unavailable: agent routing not updated; pushes are delayed until agents next report",
				"err", err, "similar_errors_suppressed", suppressed)
		})
	}
}

// FlushHeartbeats writes last_seen for every agent that heartbeated since
// the previous flush, in one statement.
func (r *Registry) FlushHeartbeats(ctx context.Context) error {
	r.hbMu.Lock()
	batch := r.heartbeats
	r.heartbeats = make(map[uuid.UUID]struct{}, len(batch))
	r.hbMu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	uids := make([]uuid.UUID, 0, len(batch))
	for uid := range batch {
		uids = append(uids, uid)
	}
	// A consistent lock order keeps concurrent flushes from other replicas from deadlocking with this one.
	slices.SortFunc(uids, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	_, err := r.db.Exec(ctx, `
UPDATE agents SET last_seen = now() FROM (
    SELECT instance_uid FROM agents WHERE instance_uid = ANY($1) ORDER BY instance_uid FOR UPDATE) locked
WHERE agents.instance_uid = locked.instance_uid`, uids)
	if err != nil {
		// Keep them for the next flush; losing a heartbeat could age a live agent out.
		r.hbMu.Lock()
		for _, uid := range uids {
			r.heartbeats[uid] = struct{}{}
		}
		r.hbMu.Unlock()
		return fmt.Errorf("flush %d heartbeats: %w", len(uids), err)
	}
	return nil
}

const upsertSQL = `
WITH prev AS (SELECT connected FROM agents WHERE instance_uid = $1)
INSERT INTO agents (
    instance_uid, auth_mode, credential_id, attributes, capabilities, agent_version,
    healthy, health_status, health_last_error, health,
    effective_config_hash, effective_config,
    remote_config_hash, remote_config_status, remote_config_error,
    connected, sequence_num, last_seen, project_id)
VALUES (
    $1, $2::auth_mode, $3, COALESCE($4::jsonb, '{}'::jsonb), $5, $6,
    $7, $8, $9, $10::jsonb,
    $11, $12,
    $13, COALESCE($14::remote_config_status, 'unset'), $15,
    TRUE, $16, now(), (SELECT project_id FROM credentials WHERE id = $3))
ON CONFLICT (instance_uid) DO UPDATE SET
    auth_mode             = EXCLUDED.auth_mode,
    credential_id         = EXCLUDED.credential_id,
    -- A collector belongs to the project of the API key it connects with.
    -- Certificate-authenticated collectors keep the project an admin gave them.
    project_id            = CASE WHEN $3::uuid IS NULL THEN agents.project_id ELSE EXCLUDED.project_id END,
    attributes            = COALESCE($4::jsonb, agents.attributes),
    capabilities          = EXCLUDED.capabilities,
    agent_version         = COALESCE($6, agents.agent_version),
    healthy               = COALESCE($7, agents.healthy),
    health_status         = CASE WHEN $10::jsonb IS NULL THEN agents.health_status ELSE $8 END,
    health_last_error     = CASE WHEN $10::jsonb IS NULL THEN agents.health_last_error ELSE $9 END,
    health                = COALESCE($10::jsonb, agents.health),
    effective_config_hash = COALESCE($11, agents.effective_config_hash),
    effective_config      = COALESCE($12, agents.effective_config),
    -- When the agent reports a status, its hash is taken as reported, even if
    -- empty: an agent that lost its state (reinstall, wiped storage) reports
    -- no hash, and keeping the old one would stop the config being re-offered.
    remote_config_hash    = CASE WHEN $14::remote_config_status IS NULL THEN agents.remote_config_hash ELSE $13 END,
    remote_config_status  = COALESCE($14::remote_config_status, agents.remote_config_status),
    remote_config_error   = CASE WHEN $14::remote_config_status IS NULL THEN agents.remote_config_error ELSE $15 END,
    connected             = TRUE,
    sequence_num          = EXCLUDED.sequence_num,
    last_seen             = now()
RETURNING capabilities, desired_config_version_id, remote_config_hash, paused,
          COALESCE((SELECT connected FROM prev), FALSE)`

// Report applies an AgentToServer status report. Fields the agent omitted
// (unchanged since its last message) are left untouched.
func (r *Registry) Report(ctx context.Context, uid uuid.UUID, id Identity, msg *protobufs.AgentToServer) (ConfigState, error) {
	// The route is refreshed before touching Postgres: this replica holds the
	// connection whether or not the database is reachable, and a live route
	// is what stops the offline sweep from flapping the fleet after a
	// database outage.
	r.setRoute(ctx, uid)
	if IsHeartbeat(msg) {
		if st, ok, err := r.heartbeat(ctx, uid, msg); ok || err != nil {
			return st, err
		}
	}
	var (
		attrs, health                      []byte
		version, healthStatus, healthErr   *string
		healthy                            *bool
		effHash, remoteHash                []byte
		effBody, remoteStatus, remoteError *string
	)

	if d := msg.GetAgentDescription(); d != nil {
		m := FlattenAttributes(d)
		attrs, _ = json.Marshal(m)
		if v, ok := m["service.version"]; ok {
			version = &v
		}
	}
	if h := msg.GetHealth(); h != nil {
		health, _ = json.Marshal(h)
		healthy, healthStatus, healthErr = &h.Healthy, &h.Status, &h.LastError
	}
	if c := msg.GetEffectiveConfig().GetConfigMap(); c != nil {
		body := RenderConfigMap(c)
		sum := sha256.Sum256([]byte(body))
		effBody, effHash = &body, sum[:]
	}
	if s := msg.GetRemoteConfigStatus(); s != nil {
		status := remoteStatusName(s.Status)
		remoteStatus, remoteError, remoteHash = &status, &s.ErrorMessage, s.LastRemoteConfigHash
	}

	var (
		st           ConfigState
		caps         int64
		wasConnected bool
	)
	err := r.db.QueryRow(ctx, upsertSQL,
		uid, id.AuthMode, id.CredentialID, attrs, int64(msg.Capabilities), version,
		healthy, healthStatus, healthErr, health,
		effHash, effBody,
		remoteHash, remoteStatus, remoteError,
		int64(msg.SequenceNum)).Scan(&caps, &st.DesiredConfigVersionID, &st.RemoteConfigHash, &st.Paused, &wasConnected)
	if err != nil {
		return st, fmt.Errorf("upsert agent %s: %w", uid, err)
	}
	st.Capabilities = uint64(caps)

	// Plain heartbeats only refresh last_seen; publishing them would make
	// every UI refetch constantly at fleet scale.
	switch {
	case !wasConnected:
		r.publish(ctx, "agent.connected", uid)
	case attrs != nil || health != nil || effBody != nil || remoteStatus != nil:
		r.publish(ctx, "agent.updated", uid)
	}
	return st, nil
}

// ConfigState returns the agent's current config state.
func (r *Registry) ConfigState(ctx context.Context, uid uuid.UUID) (ConfigState, error) {
	var (
		st   ConfigState
		caps int64
	)
	err := r.db.QueryRow(ctx, `
SELECT capabilities, desired_config_version_id, remote_config_hash, paused FROM agents WHERE instance_uid = $1`,
		uid).Scan(&caps, &st.DesiredConfigVersionID, &st.RemoteConfigHash, &st.Paused)
	if errors.Is(err, pgx.ErrNoRows) {
		return st, ErrNotFound
	}
	st.Capabilities = uint64(caps)
	return st, err
}

// SetDesiredConfig assigns a config version to an agent and asks the replica
// holding its connection to push it. Agents that are offline or on HTTP
// polling receive it with the response to their next message.
func (r *Registry) SetDesiredConfig(ctx context.Context, uid, versionID uuid.UUID) error {
	tag, err := r.db.Exec(ctx, `
UPDATE agents SET desired_config_version_id = $2
WHERE instance_uid = $1 AND capabilities & $3 <> 0`,
		uid, versionID, int64(protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig))
	if err != nil {
		return fmt.Errorf("assign config to %s: %w", uid, err)
	}
	if tag.RowsAffected() == 0 {
		if _, err := r.ConfigState(ctx, uid); err != nil {
			return err
		}
		return ErrRemoteConfigUnsupported
	}
	r.publish(ctx, "agent.updated", uid)
	return r.RequestPush(ctx, uid)
}

const (
	pushChunk = 500
	// pushWorkers bounds concurrent deliveries on one replica, so a large
	// rollout batch cannot monopolise the database pool.
	pushWorkers = 32
	// pushBuffer must hold a full rollout batch: go-redis drops pub/sub
	// messages when the consumer falls behind.
	pushBuffer = 10000
)

// RequestPush notifies the replicas that own the agents' connections.
// Agents without a route (offline or polling) are skipped; they receive
// their config with the response to their next message.
func (r *Registry) RequestPush(ctx context.Context, uids ...uuid.UUID) error {
	for len(uids) > 0 {
		chunk := uids[:min(pushChunk, len(uids))]
		uids = uids[len(chunk):]

		keys := make([]string, len(chunk))
		for i, uid := range chunk {
			keys[i] = routeKeyPrefix + uid.String()
		}
		replicas, err := r.rdb.MGet(ctx, keys...).Result()
		if err != nil {
			return fmt.Errorf("look up routes: %w", err)
		}
		pipe := r.rdb.Pipeline()
		for i, replica := range replicas {
			if id, ok := replica.(string); ok {
				pipe.Publish(ctx, pushChanPrefix+id, chunk[i].String())
			}
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("publish push requests: %w", err)
		}
	}
	return nil
}

// HistoryEvent is one entry in an agent's history. Events are written by a database
// trigger on the agents table (see the migration), not by this package.
type HistoryEvent struct {
	ID         int64     `json:"id"`
	OccurredAt time.Time `json:"occurred_at"`
	// Kind is one of: first_seen, connected, offline, healthy, unhealthy,
	// config_assigned, config_unassigned, config_applied, config_failed,
	// collection_stopped, collection_resumed, collector_version_changed.
	Kind   string         `json:"kind"`
	Detail map[string]any `json:"detail"`
}

// Events returns an agent's history, newest first. before, if positive,
// returns only events older than that event ID (for paging).
func (r *Registry) Events(ctx context.Context, uid uuid.UUID, before int64, limit int) ([]HistoryEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := r.db.Query(ctx, `
SELECT id, occurred_at, kind, detail FROM agent_events
WHERE instance_uid = $1 AND ($2 <= 0 OR id < $2) ORDER BY id DESC LIMIT $3`, uid, before, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (HistoryEvent, error) {
		var (
			e   HistoryEvent
			raw []byte
		)
		if err := row.Scan(&e.ID, &e.OccurredAt, &e.Kind, &raw); err != nil {
			return e, err
		}
		return e, json.Unmarshal(raw, &e.Detail)
	})
}

// ProjectOf returns the project an agent belongs to (nil for unassigned).
func (r *Registry) ProjectOf(ctx context.Context, uid uuid.UUID) (*uuid.UUID, error) {
	var project *uuid.UUID
	err := r.db.QueryRow(ctx, `SELECT project_id FROM agents WHERE instance_uid = $1`, uid).Scan(&project)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return project, err
}

// SetProject moves an agent to a project (nil for unassigned). Collectors
// that connect with an API key are moved back to the key's project when
// they next reconnect, so this is for certificate-authenticated ones.
func (r *Registry) SetProject(ctx context.Context, uid uuid.UUID, project *uuid.UUID) error {
	tag, err := r.db.Exec(ctx, `UPDATE agents SET project_id = $2 WHERE instance_uid = $1`, uid, project)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	r.publish(ctx, "agent.updated", uid)
	return nil
}

// ErrNoConfig is returned when pausing an agent that has no assigned config to come back to.
var ErrNoConfig = errors.New("assign a config to this collector before pausing it, so there is something to resume to")

// SetPaused stops or resumes collection on an agent and pushes the change.
func (r *Registry) SetPaused(ctx context.Context, uid uuid.UUID, paused bool) error {
	tag, err := r.db.Exec(ctx, `
UPDATE agents SET paused = $2 WHERE instance_uid = $1 AND capabilities & $3 <> 0 AND desired_config_version_id IS NOT NULL`,
		uid, paused, int64(protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		st, err := r.ConfigState(ctx, uid)
		if err != nil {
			return err
		}
		if st.DesiredConfigVersionID == nil {
			return ErrNoConfig
		}
		return ErrRemoteConfigUnsupported
	}
	r.publish(ctx, "agent.updated", uid)
	return r.RequestPush(ctx, uid)
}

const restartPrefix = "restart:"

// RequestRestart asks the replica holding the agent's connection to send it
// a restart command. It reports false when the agent has no live connection.
func (r *Registry) RequestRestart(ctx context.Context, uid uuid.UUID) (bool, error) {
	replica, err := r.Route(ctx, uid)
	if err != nil || replica == "" {
		return false, err
	}
	return true, r.rdb.Publish(ctx, pushChanPrefix+replica, restartPrefix+uid.String()).Err()
}

// SubscribePush calls fn, concurrently, for every push request addressed to
// this replica until ctx is cancelled.
func (r *Registry) SubscribePush(ctx context.Context, fn func(uid uuid.UUID)) {
	sub := r.rdb.Subscribe(ctx, pushChanPrefix+r.replicaID)
	defer sub.Close()
	slots := make(chan struct{}, pushWorkers)
	msgs := sub.Channel(redis.WithChannelSize(pushBuffer))
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-msgs:
			if !ok {
				return
			}
			if rest, ok := strings.CutPrefix(msg.Payload, restartPrefix); ok {
				if uid, err := uuid.Parse(rest); err == nil && r.OnRestart != nil {
					go r.OnRestart(uid)
				}
				continue
			}
			uid, err := uuid.Parse(msg.Payload)
			if err != nil {
				continue
			}
			slots <- struct{}{}
			go func() {
				defer func() { <-slots }()
				fn(uid)
			}()
		}
	}
}

// Disconnected marks the agent offline and drops its route, but only if this
// replica still owns it (the agent may already have reconnected elsewhere).
func (r *Registry) Disconnected(ctx context.Context, uid uuid.UUID) error {
	owned, err := releaseRoute.Run(ctx, r.rdb, []string{routeKeyPrefix + uid.String()}, r.replicaID).Int()
	// If Redis cannot say who owns the agent, leave it to the offline sweep
	// rather than risk marking offline an agent that reconnected elsewhere.
	if err != nil {
		return fmt.Errorf("release route %s: %w", uid, err)
	}
	if owned == 0 {
		return nil
	}
	if _, err := r.db.Exec(ctx, `UPDATE agents SET connected = FALSE WHERE instance_uid = $1`, uid); err != nil {
		return fmt.Errorf("mark disconnected %s: %w", uid, err)
	}
	r.publish(ctx, "agent.disconnected", uid)
	return nil
}

var releaseRoute = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
end
return 0`)

// Route returns the replica currently holding the agent's connection, or "" if none.
func (r *Registry) Route(ctx context.Context, uid uuid.UUID) (string, error) {
	v, err := r.rdb.Get(ctx, routeKeyPrefix+uid.String()).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	return v, err
}

// sweepBatch bounds one sweep; the rest is picked up by the next one.
const sweepBatch = 5000

// SweepOffline marks agents not seen within offlineAfter as disconnected.
// Covers replicas that died without running Disconnected.
//
// An agent whose last_seen is stale but which still has a live route in
// Redis is left alone: after a Postgres outage every last_seen is stale
// although the agents never went away, and sweeping them would flap the
// whole fleet offline and back. If Redis cannot be asked, nothing is swept.
//
// Every replica runs the sweep, so rows are locked in a fixed order and rows
// another replica is already handling are skipped; unordered concurrent
// sweeps deadlock.
func (r *Registry) SweepOffline(ctx context.Context, offlineAfter time.Duration) (int64, error) {
	rows, err := r.db.Query(ctx, `
SELECT instance_uid FROM agents WHERE connected AND last_seen < now() - $1::interval
ORDER BY instance_uid LIMIT $2`, offlineAfter.String(), sweepBatch)
	if err != nil {
		return 0, err
	}
	candidates, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil || len(candidates) == 0 {
		return 0, err
	}

	var gone []uuid.UUID
	for chunk := range slices.Chunk(candidates, pushChunk) {
		keys := make([]string, len(chunk))
		for i, uid := range chunk {
			keys[i] = routeKeyPrefix + uid.String()
		}
		routes, err := r.rdb.MGet(ctx, keys...).Result()
		if err != nil {
			return 0, fmt.Errorf("check routes before sweeping: %w", err)
		}
		for i, route := range routes {
			if route == nil {
				gone = append(gone, chunk[i])
			}
		}
	}
	if len(gone) == 0 {
		return 0, nil
	}
	tag, err := r.db.Exec(ctx, `
UPDATE agents SET connected = FALSE WHERE instance_uid IN (
    SELECT instance_uid FROM agents
    WHERE instance_uid = ANY($1) AND connected AND last_seen < now() - $2::interval
    ORDER BY instance_uid FOR UPDATE SKIP LOCKED)`, gone, offlineAfter.String())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

const agentColumns = `instance_uid, connector_type::text, auth_mode::text, attributes, capabilities, agent_version,
    healthy, health_status, health_last_error, effective_config_hash, remote_config_hash,
    remote_config_status::text, remote_config_error, desired_config_version_id, connected, first_seen, last_seen,
    cv.template_id, ct.name, cv.version, a.paused, a.project_id,
    COALESCE(cv.body_hash = a.remote_config_hash AND a.remote_config_status = 'applied', FALSE)`

const agentFrom = ` FROM agents a
    LEFT JOIN config_versions cv ON cv.id = a.desired_config_version_id
    LEFT JOIN config_templates ct ON ct.id = cv.template_id`

// Sort orders for List.
const (
	SortName     = "name"
	SortLastSeen = "last_seen"
)

// ListFilter narrows and orders List results.
type ListFilter struct {
	// Attributes must all match exactly (JSONB containment).
	Attributes map[string]string
	// Selector, if set, must also match (see targeting.Selector).
	Selector interface {
		Where(attributesColumn string, firstParam int) (string, []any)
	}
	// Scope, if set, limits results to projects the caller may view.
	Scope Scope
	// Project, if set, narrows to one project (or to unassigned agents).
	Project   *ProjectRef
	Connected *bool
	Healthy   *bool
	// ConfigStatus filters on remote_config_status (unset, applied, applying, failed).
	ConfigStatus *string
	// Sort is SortName (default, stable between refreshes) or SortLastSeen.
	Sort   string
	Desc   bool
	Limit  int
	Offset int
}

// Scope limits rows to the projects a caller may view (see access.Scope).
type Scope interface {
	Where(projectColumn string, firstParam int) (string, []any)
}

// ProjectRef names one project, or the unassigned pool when ID is nil.
type ProjectRef struct{ ID *uuid.UUID }

// scopeWhere renders the scope and project conditions for the agents table aliased "a".
func scopeWhere(scope Scope, project *ProjectRef, args []any) (string, []any) {
	cond := "TRUE"
	if scope != nil {
		w, a := scope.Where("a.project_id", len(args)+1)
		cond, args = w, append(args, a...)
	}
	if project != nil {
		args = append(args, project.ID)
		cond += fmt.Sprintf(" AND a.project_id IS NOT DISTINCT FROM $%d", len(args))
	}
	return cond, args
}

// List returns agents matching the filter, plus the total match count.
func (r *Registry) List(ctx context.Context, f ListFilter) ([]Agent, int, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	attrs := []byte("{}")
	if len(f.Attributes) > 0 {
		attrs, _ = json.Marshal(f.Attributes)
	}
	const where = ` WHERE attributes @> $1::jsonb AND ($2::boolean IS NULL OR connected = $2)
    AND ($3::boolean IS NULL OR healthy = $3) AND ($4::text IS NULL OR remote_config_status::text = $4)`
	args := []any{attrs, f.Connected, f.Healthy, f.ConfigStatus}
	selWhere := "TRUE"
	if f.Selector != nil {
		var selArgs []any
		selWhere, selArgs = f.Selector.Where("attributes", len(args)+1)
		args = append(args, selArgs...)
	}
	scopeCond, args := scopeWhere(f.Scope, f.Project, args)
	filter := where + ` AND ` + selWhere + ` AND ` + scopeCond
	limitParams := fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)

	dir := "ASC"
	if f.Desc {
		dir = "DESC"
	}
	order := ` ORDER BY attributes->>'host.name' ` + dir + ` NULLS LAST, instance_uid`
	if f.Sort == SortLastSeen {
		order = ` ORDER BY last_seen ` + dir + `, instance_uid`
	}

	var total int
	if err := r.db.QueryRow(ctx, `SELECT count(*) FROM agents a`+filter, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.Query(ctx,
		`SELECT `+agentColumns+agentFrom+filter+order+limitParams,
		append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	agents, err := pgx.CollectRows(rows, scanAgent)
	return agents, total, err
}

// Get returns one agent including its effective config body.
func (r *Registry) Get(ctx context.Context, uid uuid.UUID) (*Agent, error) {
	rows, err := r.db.Query(ctx, `SELECT `+agentColumns+agentFrom+` WHERE instance_uid = $1`, uid)
	if err != nil {
		return nil, err
	}
	a, err := pgx.CollectExactlyOneRow(rows, scanAgent)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	err = r.db.QueryRow(ctx, `SELECT effective_config FROM agents WHERE instance_uid = $1`, uid).Scan(&a.EffectiveConfig)
	return &a, err
}

// Summary is the fleet-level rollup shown on the dashboard.
type Summary struct {
	Total        int `json:"total"`
	Connected    int `json:"connected"`
	Healthy      int `json:"healthy"`
	Unhealthy    int `json:"unhealthy"`
	ConfigFailed int `json:"config_failed"`
}

// Summarize returns fleet-wide counts.
// selector, if set, narrows the counts to agents it matches (a group).
func (r *Registry) Summarize(ctx context.Context, scope Scope, project *ProjectRef, selector interface {
	Where(attributesColumn string, firstParam int) (string, []any)
}) (Summary, error) {
	var s Summary
	cond, args := scopeWhere(scope, project, nil)
	if selector != nil {
		w, a := selector.Where("a.attributes", len(args)+1)
		cond, args = cond+" AND "+w, append(args, a...)
	}
	err := r.db.QueryRow(ctx, `
SELECT count(*),
       count(*) FILTER (WHERE connected),
       count(*) FILTER (WHERE connected AND healthy),
       count(*) FILTER (WHERE connected AND healthy = FALSE),
       count(*) FILTER (WHERE remote_config_status = 'failed')
FROM agents a WHERE `+cond, args...).Scan(&s.Total, &s.Connected, &s.Healthy, &s.Unhealthy, &s.ConfigFailed)
	return s, err
}

// FleetHealth counts connected agents, connected agents reporting
// themselves unhealthy, and agents that disconnected within recentWindow.
func (r *Registry) FleetHealth(ctx context.Context, recentWindow time.Duration) (connected, unhealthy, recentlyOffline int, err error) {
	err = r.db.QueryRow(ctx, `
SELECT count(*) FILTER (WHERE connected),
       count(*) FILTER (WHERE connected AND healthy = FALSE),
       count(*) FILTER (WHERE NOT connected AND last_seen > now() - $1::interval)
FROM agents`, recentWindow.String()).Scan(&connected, &unhealthy, &recentlyOffline)
	return
}

// maxFacetValues excludes high-cardinality attributes (host names, instance
// IDs) that are useless for targeting groups of agents.
const maxFacetValues = 50

// Facet is one attribute key with the values agents report for it.
type Facet struct {
	Key    string       `json:"key"`
	Values []FacetValue `json:"values"`
}

// FacetValue is one attribute value and the number of agents reporting it.
type FacetValue struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// Facets returns the low-cardinality attributes present in the fleet, for
// building selectors (region, cloud, datacenter, env, team, ...).
func (r *Registry) Facets(ctx context.Context, scope Scope, project *ProjectRef) ([]Facet, error) {
	cond, args := scopeWhere(scope, project, []any{maxFacetValues})
	rows, err := r.db.Query(ctx, `
SELECT key, value, n FROM (
    SELECT key, value, count(*) AS n, count(*) OVER (PARTITION BY key) AS distinct_values,
           max(count(*)) OVER (PARTITION BY key) AS largest
    FROM agents a, jsonb_each_text(a.attributes) WHERE `+cond+` GROUP BY key, value) t
-- Identifiers (host names, instance IDs) have a different value on every
-- agent. In a small fleet or project they slip under the value limit, so
-- they are also recognised by no value being shared by two agents.
WHERE distinct_values <= $1 AND (largest > 1 OR distinct_values <= 2) ORDER BY key, n DESC, value`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var facets []Facet
	for rows.Next() {
		var (
			key string
			v   FacetValue
		)
		if err := rows.Scan(&key, &v.Value, &v.Count); err != nil {
			return nil, err
		}
		if n := len(facets); n == 0 || facets[n-1].Key != key {
			facets = append(facets, Facet{Key: key})
		}
		facets[len(facets)-1].Values = append(facets[len(facets)-1].Values, v)
	}
	return facets, rows.Err()
}

func scanAgent(row pgx.CollectableRow) (Agent, error) {
	var (
		a        Agent
		attrs    []byte
		caps     int64
		tmplID   *uuid.UUID
		tmplName *string
		version  *int
		inSync   bool
	)
	err := row.Scan(&a.InstanceUID, &a.ConnectorType, &a.AuthMode, &attrs, &caps, &a.AgentVersion,
		&a.Healthy, &a.HealthStatus, &a.HealthLastError, &a.EffectiveConfigHash, &a.RemoteConfigHash,
		&a.RemoteConfigStatus, &a.RemoteConfigError, &a.DesiredConfigVersionID, &a.Connected, &a.FirstSeen, &a.LastSeen,
		&tmplID, &tmplName, &version, &a.Paused, &a.ProjectID, &inSync)
	if err != nil {
		return a, err
	}
	if a.DesiredConfigVersionID != nil && tmplID != nil {
		a.DesiredConfig = &DesiredConfig{VersionID: *a.DesiredConfigVersionID, TemplateID: *tmplID,
			TemplateName: *tmplName, Version: *version, InSync: inSync}
	}
	a.Capabilities = uint64(caps)
	return a, json.Unmarshal(attrs, &a.Attributes)
}

func (r *Registry) publish(ctx context.Context, typ string, uid uuid.UUID) {
	b, _ := json.Marshal(Event{Type: typ, InstanceUID: uid, ReplicaID: r.replicaID, At: time.Now().UTC()})
	// Best effort: UI live updates must never fail the agent-facing path.
	_ = r.rdb.Publish(ctx, EventsChannel, b).Err()
}

// FlattenAttributes merges identifying and non-identifying attributes into a
// flat string map. Identifying attributes win on key collision.
func FlattenAttributes(d *protobufs.AgentDescription) map[string]string {
	m := make(map[string]string, len(d.IdentifyingAttributes)+len(d.NonIdentifyingAttributes))
	for _, kvs := range [][]*protobufs.KeyValue{d.NonIdentifyingAttributes, d.IdentifyingAttributes} {
		for _, kv := range kvs {
			m[kv.Key] = anyValueString(kv.Value)
		}
	}
	return m
}

func anyValueString(v *protobufs.AnyValue) string {
	switch x := v.GetValue().(type) {
	case nil:
		return ""
	case *protobufs.AnyValue_StringValue:
		return x.StringValue
	case *protobufs.AnyValue_BoolValue:
		return fmt.Sprint(x.BoolValue)
	case *protobufs.AnyValue_IntValue:
		return fmt.Sprint(x.IntValue)
	case *protobufs.AnyValue_DoubleValue:
		return fmt.Sprint(x.DoubleValue)
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

// RenderConfigMap renders an AgentConfigMap as one deterministic text blob.
// A single-file map is returned verbatim; multi-file maps are concatenated
// in name order with a header comment per file.
func RenderConfigMap(c *protobufs.AgentConfigMap) string {
	if len(c.ConfigMap) == 1 {
		for _, f := range c.ConfigMap {
			return string(f.Body)
		}
	}
	names := make([]string, 0, len(c.ConfigMap))
	for n := range c.ConfigMap {
		names = append(names, n)
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, n := range names {
		fmt.Fprintf(&sb, "# --- %s ---\n%s\n", n, c.ConfigMap[n].Body)
	}
	return sb.String()
}

func remoteStatusName(s protobufs.RemoteConfigStatuses) string {
	switch s {
	case protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLIED:
		return "applied"
	case protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLYING:
		return "applying"
	case protobufs.RemoteConfigStatuses_RemoteConfigStatuses_FAILED:
		return "failed"
	default:
		return "unset"
	}
}
