CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Agents -----------------------------------------------------------------
CREATE TYPE connector_type AS ENUM ('supervisor', 'extension', 'k8s_bridge');
CREATE TYPE auth_mode AS ENUM ('mtls', 'api_key');
CREATE TYPE remote_config_status AS ENUM ('unset', 'applied', 'applying', 'failed');

CREATE TABLE agents (
    instance_uid          UUID PRIMARY KEY,
    connector_type        connector_type NOT NULL DEFAULT 'supervisor',
    auth_mode             auth_mode NOT NULL,
    credential_id         UUID,
    -- Flattened from AgentDescription for indexed querying.
    attributes            JSONB NOT NULL DEFAULT '{}'::jsonb,
    capabilities          BIGINT NOT NULL DEFAULT 0,
    agent_version         TEXT,
    -- Health (from ComponentHealth).
    healthy               BOOLEAN,
    health_status         TEXT,
    health_last_error     TEXT,
    health                JSONB,
    -- Config state.
    effective_config_hash BYTEA,
    effective_config      TEXT,
    remote_config_hash    BYTEA,
    remote_config_status  remote_config_status NOT NULL DEFAULT 'unset',
    remote_config_error   TEXT,
    desired_config_version_id UUID,
    -- Liveness.
    connected             BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen            TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen             TIMESTAMPTZ NOT NULL DEFAULT now(),
    sequence_num          BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX agents_attributes_gin ON agents USING GIN (attributes jsonb_path_ops);
CREATE INDEX agents_last_seen_idx ON agents (last_seen);
CREATE INDEX agents_connected_idx ON agents (connected);
CREATE INDEX agents_desired_config_idx ON agents (desired_config_version_id) WHERE desired_config_version_id IS NOT NULL;
CREATE INDEX agents_host_name_idx ON agents ((attributes->>'host.name'), instance_uid);

-- Config templates / versions ---------------------------------------------
CREATE TYPE config_origin AS ENUM ('ui', 'git');

CREATE TABLE config_templates (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    origin      config_origin NOT NULL DEFAULT 'ui',
    git_path    TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE config_versions (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id    UUID NOT NULL REFERENCES config_templates(id) ON DELETE CASCADE,
    version        INTEGER NOT NULL,
    body           TEXT NOT NULL,
    body_hash      BYTEA NOT NULL,
    author         TEXT NOT NULL,
    description    TEXT,
    origin         config_origin NOT NULL DEFAULT 'ui',
    git_commit_sha TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (template_id, version)
);
CREATE INDEX config_versions_hash_idx ON config_versions (body_hash);

ALTER TABLE agents
    ADD CONSTRAINT agents_desired_config_fk
    FOREIGN KEY (desired_config_version_id) REFERENCES config_versions(id) ON DELETE SET NULL;

-- Agent groups (label selectors) ------------------------------------------
CREATE TABLE agent_groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    -- Selector: JSON array of {key, op, value} terms, AND-ed together.
    selector    JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Rollouts -----------------------------------------------------------------
CREATE TYPE rollout_status AS ENUM ('pending', 'running', 'paused', 'completed', 'failed', 'rolled_back', 'aborted');
CREATE TYPE rollout_agent_status AS ENUM ('pending', 'offered', 'applying', 'applied', 'failed', 'skipped', 'rolled_back');

CREATE TABLE rollouts (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_version_id   UUID NOT NULL REFERENCES config_versions(id),
    -- The saved group the target came from, if any. The rollout keeps its own
    -- selector snapshot, so deleting the group must not be blocked by history.
    group_id            UUID REFERENCES agent_groups(id) ON DELETE SET NULL,
    selector            JSONB NOT NULL,
    -- Strategy. NULL canary_steps_pct means fixed-size batches of batch_size;
    -- otherwise cumulative percentages of the target, e.g. {1,10,50,100}.
    canary_steps_pct    INTEGER[],
    batch_size          INTEGER NOT NULL DEFAULT 100,
    max_failure_pct     NUMERIC(5,2) NOT NULL DEFAULT 2.0,
    -- Roll back instead of pausing when a batch exceeds max_failure_pct.
    auto_rollback       BOOLEAN NOT NULL DEFAULT FALSE,
    status              rollout_status NOT NULL DEFAULT 'pending',
    current_step        INTEGER NOT NULL DEFAULT 0,
    -- Highest step whose failures an operator has acknowledged by resuming.
    -- The failure threshold is only enforced for steps above it.
    ack_step            INTEGER NOT NULL DEFAULT -1,
    created_by          TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at          TIMESTAMPTZ,
    finished_at         TIMESTAMPTZ,
    error               TEXT
);
CREATE INDEX rollouts_status_idx ON rollouts (status);

CREATE TABLE rollout_agents (
    rollout_id     UUID NOT NULL REFERENCES rollouts(id) ON DELETE CASCADE,
    instance_uid   UUID NOT NULL REFERENCES agents(instance_uid) ON DELETE CASCADE,
    step           INTEGER NOT NULL,
    status         rollout_agent_status NOT NULL DEFAULT 'pending',
    error          TEXT,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- What the agent was assigned before this rollout touched it, for rollback.
    previous_config_version_id UUID REFERENCES config_versions(id) ON DELETE SET NULL,
    PRIMARY KEY (rollout_id, instance_uid)
);
CREATE INDEX rollout_agents_status_idx ON rollout_agents (rollout_id, status);

-- Credentials (agent auth) -------------------------------------------------
CREATE TYPE credential_kind AS ENUM ('api_key', 'mtls_cert');

CREATE TABLE credentials (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind          credential_kind NOT NULL,
    name          TEXT NOT NULL,
    -- api_key: sha256 of the secret. mtls_cert: sha256 fingerprint of the leaf cert.
    key_hash      BYTEA NOT NULL UNIQUE,
    -- For mtls_cert: subject CN / SPIFFE ID; informational.
    subject       TEXT,
    -- Optional scoping: credential may be bound to one agent or a group.
    instance_uid  UUID REFERENCES agents(instance_uid) ON DELETE SET NULL,
    group_id      UUID REFERENCES agent_groups(id) ON DELETE SET NULL,
    created_by    TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ
);

ALTER TABLE agents
    ADD CONSTRAINT agents_credential_fk
    FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE SET NULL;

-- Human identity & RBAC ------------------------------------------------------
CREATE TYPE identity_provider AS ENUM ('okta', 'local');
CREATE TYPE rbac_role AS ENUM ('admin', 'operator', 'viewer');

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider      identity_provider NOT NULL,
    subject       TEXT NOT NULL,       -- Okta sub, or local username
    email         TEXT,
    display_name  TEXT,
    password_hash TEXT,                -- local provider only
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ,
    UNIQUE (provider, subject)
);

CREATE TABLE role_assignments (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       rbac_role NOT NULL,
    -- NULL = global scope. Future: group_id for per-group scoping.
    scope      UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, role, scope)
);

-- Audit ----------------------------------------------------------------------
CREATE TABLE audit_events (
    id          BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor       TEXT NOT NULL,           -- user subject, or 'system'
    actor_auth  TEXT NOT NULL,           -- okta | local | api_key | mtls | system
    action      TEXT NOT NULL,           -- e.g. config.create, rollout.start
    target_type TEXT NOT NULL,
    target_id   TEXT,
    details     JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_events_occurred_idx ON audit_events (occurred_at DESC);
CREATE INDEX audit_events_target_idx ON audit_events (target_type, target_id);
