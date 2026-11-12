// Package registry persists agent state in Postgres and maintains the
// Redis-backed agent -> replica routing table used for horizontal fan-out.
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/redis/go-redis/v9"
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
}

// Agent is the API/storage representation of one collector instance.
type Agent struct {
	InstanceUID            uuid.UUID         `json:"instance_uid"`
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
	Connected              bool              `json:"connected"`
	FirstSeen              time.Time         `json:"first_seen"`
	LastSeen               time.Time         `json:"last_seen"`
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
}

// Registry is the agent registry service.
type Registry struct {
	db        *pgxpool.Pool
	rdb       *redis.Client
	replicaID string
	routeTTL  time.Duration
}

// New creates a Registry. routeTTL bounds how long a routing entry survives
// without a heartbeat from the owning replica.
func New(db *pgxpool.Pool, rdb *redis.Client, replicaID string, routeTTL time.Duration) *Registry {
	return &Registry{db: db, rdb: rdb, replicaID: replicaID, routeTTL: routeTTL}
}

const upsertSQL = `
INSERT INTO agents (
    instance_uid, auth_mode, credential_id, attributes, capabilities, agent_version,
    healthy, health_status, health_last_error, health,
    effective_config_hash, effective_config,
    remote_config_hash, remote_config_status, remote_config_error,
    connected, sequence_num, last_seen)
VALUES (
    $1, $2::auth_mode, $3, COALESCE($4::jsonb, '{}'::jsonb), $5, $6,
    $7, $8, $9, $10::jsonb,
    $11, $12,
    $13, COALESCE($14::remote_config_status, 'unset'), $15,
    TRUE, $16, now())
ON CONFLICT (instance_uid) DO UPDATE SET
    auth_mode             = EXCLUDED.auth_mode,
    credential_id         = EXCLUDED.credential_id,
    attributes            = COALESCE($4::jsonb, agents.attributes),
    capabilities          = EXCLUDED.capabilities,
    agent_version         = COALESCE($6, agents.agent_version),
    healthy               = COALESCE($7, agents.healthy),
    health_status         = CASE WHEN $10::jsonb IS NULL THEN agents.health_status ELSE $8 END,
    health_last_error     = CASE WHEN $10::jsonb IS NULL THEN agents.health_last_error ELSE $9 END,
    health                = COALESCE($10::jsonb, agents.health),
    effective_config_hash = COALESCE($11, agents.effective_config_hash),
    effective_config      = COALESCE($12, agents.effective_config),
    remote_config_hash    = COALESCE($13, agents.remote_config_hash),
    remote_config_status  = COALESCE($14::remote_config_status, agents.remote_config_status),
    remote_config_error   = CASE WHEN $14::remote_config_status IS NULL THEN agents.remote_config_error ELSE $15 END,
    connected             = TRUE,
    sequence_num          = EXCLUDED.sequence_num,
    last_seen             = now()
RETURNING capabilities, desired_config_version_id, remote_config_hash`

// Report applies an AgentToServer status report. Fields the agent omitted
// (unchanged since its last message) are left untouched.
func (r *Registry) Report(ctx context.Context, uid uuid.UUID, id Identity, msg *protobufs.AgentToServer) (ConfigState, error) {
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
		st   ConfigState
		caps int64
	)
	err := r.db.QueryRow(ctx, upsertSQL,
		uid, id.AuthMode, id.CredentialID, attrs, int64(msg.Capabilities), version,
		healthy, healthStatus, healthErr, health,
		effHash, effBody,
		remoteHash, remoteStatus, remoteError,
		int64(msg.SequenceNum)).Scan(&caps, &st.DesiredConfigVersionID, &st.RemoteConfigHash)
	if err != nil {
		return st, fmt.Errorf("upsert agent %s: %w", uid, err)
	}
	st.Capabilities = uint64(caps)

	if err := r.rdb.Set(ctx, routeKeyPrefix+uid.String(), r.replicaID, r.routeTTL).Err(); err != nil {
		return st, fmt.Errorf("set route %s: %w", uid, err)
	}
	r.publish(ctx, "agent.updated", uid)
	return st, nil
}

// ConfigState returns the agent's current config state.
func (r *Registry) ConfigState(ctx context.Context, uid uuid.UUID) (ConfigState, error) {
	var (
		st   ConfigState
		caps int64
	)
	err := r.db.QueryRow(ctx, `
SELECT capabilities, desired_config_version_id, remote_config_hash FROM agents WHERE instance_uid = $1`,
		uid).Scan(&caps, &st.DesiredConfigVersionID, &st.RemoteConfigHash)
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

// RequestPush notifies the replica that owns the agent's connection.
func (r *Registry) RequestPush(ctx context.Context, uid uuid.UUID) error {
	replica, err := r.Route(ctx, uid)
	if err != nil || replica == "" {
		return err
	}
	return r.rdb.Publish(ctx, pushChanPrefix+replica, uid.String()).Err()
}

// SubscribePush calls fn for every push request addressed to this replica
// until ctx is cancelled.
func (r *Registry) SubscribePush(ctx context.Context, fn func(uid uuid.UUID)) {
	sub := r.rdb.Subscribe(ctx, pushChanPrefix+r.replicaID)
	defer sub.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-sub.Channel():
			if !ok {
				return
			}
			if uid, err := uuid.Parse(msg.Payload); err == nil {
				fn(uid)
			}
		}
	}
}

// Disconnected marks the agent offline and drops its route, but only if this
// replica still owns it (the agent may already have reconnected elsewhere).
func (r *Registry) Disconnected(ctx context.Context, uid uuid.UUID) error {
	owned, err := releaseRoute.Run(ctx, r.rdb, []string{routeKeyPrefix + uid.String()}, r.replicaID).Int()
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

// SweepOffline marks agents not seen within offlineAfter as disconnected.
// Covers replicas that died without running Disconnected.
func (r *Registry) SweepOffline(ctx context.Context, offlineAfter time.Duration) (int64, error) {
	tag, err := r.db.Exec(ctx,
		`UPDATE agents SET connected = FALSE WHERE connected AND last_seen < now() - $1::interval`,
		offlineAfter.String())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

const agentColumns = `instance_uid, connector_type::text, auth_mode::text, attributes, capabilities, agent_version,
    healthy, health_status, health_last_error, effective_config_hash, remote_config_hash,
    remote_config_status::text, remote_config_error, desired_config_version_id, connected, first_seen, last_seen,
    cv.template_id, ct.name, cv.version,
    COALESCE(cv.body_hash = a.remote_config_hash AND a.remote_config_status = 'applied', FALSE)`

const agentFrom = ` FROM agents a
    LEFT JOIN config_versions cv ON cv.id = a.desired_config_version_id
    LEFT JOIN config_templates ct ON ct.id = cv.template_id`

// ListFilter narrows List results.
type ListFilter struct {
	// Attributes must all match exactly (JSONB containment).
	Attributes map[string]string
	Connected  *bool
	Limit      int
	Offset     int
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
	const where = ` WHERE attributes @> $1::jsonb AND ($2::boolean IS NULL OR connected = $2)`

	var total int
	if err := r.db.QueryRow(ctx, `SELECT count(*) FROM agents`+where, attrs, f.Connected).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.Query(ctx,
		`SELECT `+agentColumns+agentFrom+where+` ORDER BY last_seen DESC, instance_uid LIMIT $3 OFFSET $4`,
		attrs, f.Connected, f.Limit, f.Offset)
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
func (r *Registry) Summarize(ctx context.Context) (Summary, error) {
	var s Summary
	err := r.db.QueryRow(ctx, `
SELECT count(*),
       count(*) FILTER (WHERE connected),
       count(*) FILTER (WHERE connected AND healthy),
       count(*) FILTER (WHERE connected AND healthy = FALSE),
       count(*) FILTER (WHERE remote_config_status = 'failed')
FROM agents`).Scan(&s.Total, &s.Connected, &s.Healthy, &s.Unhealthy, &s.ConfigFailed)
	return s, err
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
func (r *Registry) Facets(ctx context.Context) ([]Facet, error) {
	rows, err := r.db.Query(ctx, `
SELECT key, value, n FROM (
    SELECT key, value, count(*) AS n, count(*) OVER (PARTITION BY key) AS distinct_values
    FROM agents, jsonb_each_text(attributes) GROUP BY key, value) t
WHERE distinct_values <= $1 ORDER BY key, n DESC, value`, maxFacetValues)
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
		&tmplID, &tmplName, &version, &inSync)
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
