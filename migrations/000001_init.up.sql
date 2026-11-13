CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Roles ------------------------------------------------------------------
CREATE TYPE rbac_role AS ENUM ('admin', 'operator', 'viewer');

-- Projects: a project owns collectors, configs, groups, bulk pushes and
-- library items. A NULL project_id means "unassigned"; those resources are
-- governed by a user's global role, as everything was before projects.
CREATE TABLE projects (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A person's role in a project. subject is the lower-cased sign-in name
-- (Okta email, or the local username).
CREATE TABLE project_members (
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    subject    TEXT NOT NULL,
    role       rbac_role NOT NULL,
    added_by   TEXT NOT NULL,
    added_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, subject)
);
CREATE INDEX project_members_subject_idx ON project_members (subject);

-- Agents -----------------------------------------------------------------
CREATE TYPE connector_type AS ENUM ('supervisor', 'extension', 'k8s_bridge');
CREATE TYPE auth_mode AS ENUM ('mtls', 'api_key');
CREATE TYPE remote_config_status AS ENUM ('unset', 'applied', 'applying', 'failed');

CREATE TABLE agents (
    instance_uid          UUID PRIMARY KEY,
    -- The project of the API key the collector connects with; NULL means unassigned.
    project_id            UUID REFERENCES projects(id),
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
    -- A paused collector is sent an empty pipeline instead of its assigned config.
    paused                BOOLEAN NOT NULL DEFAULT FALSE,
    -- Liveness.
    connected             BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen            TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen             TIMESTAMPTZ NOT NULL DEFAULT now(),
    sequence_num          BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX agents_attributes_gin ON agents USING GIN (attributes jsonb_path_ops);
CREATE INDEX agents_last_seen_idx ON agents (last_seen);
CREATE INDEX agents_connected_idx ON agents (connected);
CREATE INDEX agents_project_idx ON agents (project_id);
CREATE INDEX agents_desired_config_idx ON agents (desired_config_version_id) WHERE desired_config_version_id IS NOT NULL;
CREATE INDEX agents_host_name_idx ON agents ((attributes->>'host.name'), instance_uid);

-- Config templates / versions ---------------------------------------------
CREATE TYPE config_origin AS ENUM ('ui', 'git');

CREATE TABLE config_templates (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Owning project; NULL means unassigned. Deleting a project is refused while anything belongs to it.
    project_id  UUID REFERENCES projects(id),
    name        TEXT NOT NULL,
    description TEXT,
    origin      config_origin NOT NULL DEFAULT 'ui',
    git_path    TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Names only need to be unique within a project.
CREATE UNIQUE INDEX config_templates_project_name_key
    ON config_templates (COALESCE(project_id, '00000000-0000-0000-0000-000000000000'::uuid), name);

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
    -- The pipeline as built in the config builder; NULL for versions written as YAML.
    builder_spec   JSONB,
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
    -- Owning project; NULL means unassigned. Deleting a project is refused while anything belongs to it.
    project_id  UUID REFERENCES projects(id),
    name        TEXT NOT NULL,
    description TEXT,
    -- Selector: attribute -> accepted values. Values of one attribute are OR-ed, attributes AND-ed.
    selector    JSONB NOT NULL,
    -- A group may own a config: once a rollout of it to the group has completed,
    -- agents that match the group and have no config are given it automatically.
    config_version_id UUID REFERENCES config_versions(id) ON DELETE SET NULL,
    config_set_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX agent_groups_project_name_key
    ON agent_groups (COALESCE(project_id, '00000000-0000-0000-0000-000000000000'::uuid), name);

-- Rollouts -----------------------------------------------------------------
CREATE TYPE rollout_status AS ENUM ('pending', 'running', 'paused', 'completed', 'failed', 'rolled_back', 'aborted');
CREATE TYPE rollout_agent_status AS ENUM ('pending', 'offered', 'applying', 'applied', 'failed', 'skipped', 'rolled_back');

CREATE TABLE rollouts (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The project whose agents are targeted; NULL means unassigned agents.
    project_id          UUID REFERENCES projects(id),
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
    -- Stop after every batch and wait for an operator to approve the next one.
    manual_approval     BOOLEAN NOT NULL DEFAULT FALSE,
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
    -- The project that collectors connecting with this key join; NULL means unassigned.
    project_id    UUID REFERENCES projects(id),
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

-- Human identity ------------------------------------------------------
CREATE TYPE identity_provider AS ENUM ('okta', 'local');
CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider      identity_provider NOT NULL,
    subject       TEXT NOT NULL,       -- Okta sub, or local username
    email         TEXT,
    display_name  TEXT,
    password_hash TEXT,                -- local provider only
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ,
    -- The global role at the last sign-in, for the Users page. Okta decides it from groups each time.
    global_role   TEXT NOT NULL DEFAULT '',
    UNIQUE (provider, subject)
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

-- Console API tokens ------------------------------------------------------
-- Long-lived tokens for the CLI and automation, each with a fixed role.
CREATE TABLE api_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT NOT NULL UNIQUE,
    role         rbac_role NOT NULL,
    -- A viewer or operator token acts within one project; NULL means unassigned resources.
    project_id   UUID REFERENCES projects(id) ON DELETE CASCADE,
    token_hash   BYTEA NOT NULL UNIQUE,
    created_by   TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

-- Runtime settings --------------------------------------------------------
-- Protections an administrator has switched on or off from the console.
-- A key with no row uses its built-in default.
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    enabled    BOOLEAN NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Config builder library --------------------------------------------------
-- Sources, processors and destinations saved for reuse across configs in the builder.
CREATE TABLE library_components (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Owning project; NULL means unassigned.
    project_id UUID REFERENCES projects(id),
    kind       TEXT NOT NULL,
    name       TEXT NOT NULL,
    type       TEXT NOT NULL,
    params     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX library_components_project_kind_name_key
    ON library_components (COALESCE(project_id, '00000000-0000-0000-0000-000000000000'::uuid), kind, name);

-- Agent history -----------------------------------------------------------
-- Per-agent history: every change of connection, health, config and
-- collector version, for the Activity tab on the agent page. Written by a
-- trigger so no code path that changes an agent can forget to record it.
CREATE TABLE agent_events (
    id           BIGSERIAL PRIMARY KEY,
    instance_uid UUID NOT NULL REFERENCES agents(instance_uid) ON DELETE CASCADE,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    kind         TEXT NOT NULL,
    detail       JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX agent_events_agent_idx ON agent_events (instance_uid, id DESC);
CREATE INDEX agent_events_time_idx ON agent_events (occurred_at);

CREATE FUNCTION record_agent_events() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    cfg JSONB;
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO agent_events (instance_uid, kind, detail)
        VALUES (NEW.instance_uid, 'first_seen', jsonb_strip_nulls(jsonb_build_object('collector_version', NEW.agent_version)));
    END IF;

    IF NEW.connected AND (TG_OP = 'INSERT' OR NOT OLD.connected) THEN
        INSERT INTO agent_events (instance_uid, kind) VALUES (NEW.instance_uid, 'connected');
    ELSIF TG_OP = 'UPDATE' AND OLD.connected AND NOT NEW.connected THEN
        INSERT INTO agent_events (instance_uid, kind) VALUES (NEW.instance_uid, 'offline');
    END IF;

    IF NEW.healthy IS NOT NULL AND (TG_OP = 'INSERT' OR NEW.healthy IS DISTINCT FROM OLD.healthy) THEN
        INSERT INTO agent_events (instance_uid, kind, detail)
        VALUES (NEW.instance_uid, CASE WHEN NEW.healthy THEN 'healthy' ELSE 'unhealthy' END,
                jsonb_strip_nulls(jsonb_build_object('status', NULLIF(NEW.health_status, ''), 'error', NULLIF(NEW.health_last_error, ''))));
    END IF;

    IF TG_OP = 'UPDATE' AND NEW.agent_version IS DISTINCT FROM OLD.agent_version AND OLD.agent_version IS NOT NULL THEN
        INSERT INTO agent_events (instance_uid, kind, detail)
        VALUES (NEW.instance_uid, 'collector_version_changed', jsonb_build_object('from', OLD.agent_version, 'to', NEW.agent_version));
    END IF;

    IF TG_OP = 'UPDATE' AND NEW.desired_config_version_id IS DISTINCT FROM OLD.desired_config_version_id THEN
        SELECT jsonb_build_object('config', ct.name, 'version', cv.version) INTO cfg
        FROM config_versions cv JOIN config_templates ct ON ct.id = cv.template_id WHERE cv.id = NEW.desired_config_version_id;
        INSERT INTO agent_events (instance_uid, kind, detail)
        VALUES (NEW.instance_uid, CASE WHEN NEW.desired_config_version_id IS NULL THEN 'config_unassigned' ELSE 'config_assigned' END,
                COALESCE(cfg, '{}'::jsonb));
    END IF;

    IF TG_OP = 'UPDATE' AND NEW.paused IS DISTINCT FROM OLD.paused THEN
        INSERT INTO agent_events (instance_uid, kind)
        VALUES (NEW.instance_uid, CASE WHEN NEW.paused THEN 'collection_stopped' ELSE 'collection_resumed' END);
    END IF;

    -- What the collector reports about applying a config. The config is found
    -- by the hash it reports, preferring the one currently assigned.
    IF NEW.remote_config_status IN ('applied', 'failed')
       AND (TG_OP = 'INSERT' OR NEW.remote_config_status IS DISTINCT FROM OLD.remote_config_status
            OR NEW.remote_config_hash IS DISTINCT FROM OLD.remote_config_hash) THEN
        cfg := NULL;
        SELECT jsonb_build_object('config', ct.name, 'version', cv.version) INTO cfg
        FROM config_versions cv JOIN config_templates ct ON ct.id = cv.template_id
        WHERE cv.body_hash = NEW.remote_config_hash
        ORDER BY (cv.id IS NOT DISTINCT FROM NEW.desired_config_version_id) DESC, cv.created_at DESC LIMIT 1;
        INSERT INTO agent_events (instance_uid, kind, detail)
        VALUES (NEW.instance_uid, 'config_' || NEW.remote_config_status::text,
                COALESCE(cfg, CASE WHEN NEW.paused THEN '{"paused": true}'::jsonb ELSE '{}'::jsonb END)
                || jsonb_strip_nulls(jsonb_build_object('error',
                       CASE WHEN NEW.remote_config_status = 'failed' THEN NULLIF(NEW.remote_config_error, '') END)));
    END IF;
    RETURN NULL;
END $$;

CREATE TRIGGER agents_record_events_insert AFTER INSERT ON agents
    FOR EACH ROW EXECUTE FUNCTION record_agent_events();
-- Heartbeats only move last_seen, so the common update does not fire this.
CREATE TRIGGER agents_record_events_update AFTER UPDATE ON agents
    FOR EACH ROW WHEN (
        NEW.connected IS DISTINCT FROM OLD.connected OR NEW.healthy IS DISTINCT FROM OLD.healthy
        OR NEW.agent_version IS DISTINCT FROM OLD.agent_version
        OR NEW.desired_config_version_id IS DISTINCT FROM OLD.desired_config_version_id
        OR NEW.paused IS DISTINCT FROM OLD.paused
        OR NEW.remote_config_status IS DISTINCT FROM OLD.remote_config_status
        OR NEW.remote_config_hash IS DISTINCT FROM OLD.remote_config_hash)
    EXECUTE FUNCTION record_agent_events();

-- Audit integrity ------------------------------------------------------------
-- Each audit event carries a hash of itself and the previous event's hash, so
-- an edited, inserted or removed event breaks the chain (see audit_verify).
-- Events cannot be updated, and can only be deleted by the retention job.
ALTER TABLE audit_events ADD COLUMN prev_hash BYTEA, ADD COLUMN hash BYTEA;

CREATE FUNCTION audit_event_hash(prev BYTEA, e audit_events) RETURNS BYTEA LANGUAGE sql IMMUTABLE AS $$
    SELECT digest(COALESCE(prev, ''::bytea) || convert_to(concat_ws('|', e.id, extract(epoch FROM e.occurred_at), e.actor, e.actor_auth,
        e.action, e.target_type, COALESCE(e.target_id, ''), e.details::text), 'UTF8'), 'sha256')
$$;

CREATE FUNCTION audit_events_chain() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- One writer at a time, and the ID is taken under the lock, so ID order is chain order.
    PERFORM pg_advisory_xact_lock(727274);
    NEW.id := nextval('audit_events_id_seq');
    SELECT hash INTO NEW.prev_hash FROM audit_events ORDER BY id DESC LIMIT 1;
    NEW.hash := audit_event_hash(NEW.prev_hash, NEW);
    RETURN NEW;
END $$;
CREATE TRIGGER audit_events_chain BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION audit_events_chain();

CREATE FUNCTION audit_events_protect() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_setting('opamp.audit_prune', true) = 'on' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'audit events cannot be changed or deleted';
END $$;
CREATE TRIGGER audit_events_protect BEFORE UPDATE OR DELETE ON audit_events FOR EACH ROW EXECUTE FUNCTION audit_events_protect();
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events FOR EACH STATEMENT EXECUTE FUNCTION audit_events_protect();

-- audit_verify returns the ID of the first event that does not fit the chain,
-- or NULL when the log is intact. The oldest kept event is taken as the start,
-- because retention removes events from the old end.
CREATE FUNCTION audit_verify() RETURNS BIGINT LANGUAGE plpgsql AS $$
DECLARE
    e audit_events;
    prev BYTEA;
    first BOOLEAN := TRUE;
BEGIN
    FOR e IN SELECT * FROM audit_events ORDER BY id LOOP
        IF e.hash IS NULL THEN
            CONTINUE; -- recorded before integrity checking existed
        END IF;
        IF (NOT first AND e.prev_hash IS DISTINCT FROM prev) OR e.hash IS DISTINCT FROM audit_event_hash(e.prev_hash, e) THEN
            RETURN e.id;
        END IF;
        prev := e.hash;
        first := FALSE;
    END LOOP;
    RETURN NULL;
END $$;

-- Secrets referenced from configs as ${secret:NAME}. Values are encrypted
-- with a key held outside the database and only decrypted when a config is
-- sent to a collector.
CREATE TABLE secrets (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id),
    name       TEXT NOT NULL,
    ciphertext BYTEA NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX secrets_project_name_key ON secrets (COALESCE(project_id, '00000000-0000-0000-0000-000000000000'::uuid), name);
