-- Protections an administrator has switched on or off from the console.
-- A key with no row uses its built-in default.
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    enabled    BOOLEAN NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A group may own a config: once a rollout of it to the group has completed,
-- agents that match the group and have no config are given it automatically.
ALTER TABLE agent_groups
    ADD COLUMN config_version_id UUID REFERENCES config_versions(id) ON DELETE SET NULL,
    ADD COLUMN config_set_at TIMESTAMPTZ;

-- The pipeline as built in the console's config builder, when the version
-- was made there; NULL for versions written as YAML.
ALTER TABLE config_versions ADD COLUMN builder_spec JSONB;

-- Sources, processors and destinations saved for reuse across configs in the builder.
CREATE TABLE library_components (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind       TEXT NOT NULL,
    name       TEXT NOT NULL,
    type       TEXT NOT NULL,
    params     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (kind, name)
);

-- Stop after every batch and wait for an operator to approve the next one.
ALTER TABLE rollouts ADD COLUMN manual_approval BOOLEAN NOT NULL DEFAULT FALSE;

-- A paused collector is sent an empty pipeline instead of its assigned config.
ALTER TABLE agents ADD COLUMN paused BOOLEAN NOT NULL DEFAULT FALSE;

-- Long-lived tokens for the CLI and automation, each with a fixed role.
CREATE TABLE api_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT NOT NULL UNIQUE,
    role         rbac_role NOT NULL,
    token_hash   BYTEA NOT NULL UNIQUE,
    created_by   TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

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

-- Deleting a project is refused while anything still belongs to it.
ALTER TABLE credentials        ADD COLUMN project_id UUID REFERENCES projects(id);
ALTER TABLE agents             ADD COLUMN project_id UUID REFERENCES projects(id);
ALTER TABLE config_templates   ADD COLUMN project_id UUID REFERENCES projects(id);
ALTER TABLE agent_groups       ADD COLUMN project_id UUID REFERENCES projects(id);
ALTER TABLE rollouts           ADD COLUMN project_id UUID REFERENCES projects(id);
ALTER TABLE library_components ADD COLUMN project_id UUID REFERENCES projects(id);
-- A non-admin API token acts within one project.
ALTER TABLE api_tokens         ADD COLUMN project_id UUID REFERENCES projects(id) ON DELETE CASCADE;
CREATE INDEX agents_project_idx ON agents (project_id);

-- Names only need to be unique within a project.
ALTER TABLE config_templates DROP CONSTRAINT config_templates_name_key;
CREATE UNIQUE INDEX config_templates_project_name_key ON config_templates (COALESCE(project_id, '00000000-0000-0000-0000-000000000000'::uuid), name);
ALTER TABLE agent_groups DROP CONSTRAINT agent_groups_name_key;
CREATE UNIQUE INDEX agent_groups_project_name_key ON agent_groups (COALESCE(project_id, '00000000-0000-0000-0000-000000000000'::uuid), name);
ALTER TABLE library_components DROP CONSTRAINT library_components_kind_name_key;
CREATE UNIQUE INDEX library_components_project_kind_name_key ON library_components (COALESCE(project_id, '00000000-0000-0000-0000-000000000000'::uuid), kind, name);

-- The global role a person had at their last sign-in, for the Users page.
-- Okta decides it from groups on every sign-in; this is only a record.
ALTER TABLE users ADD COLUMN global_role TEXT NOT NULL DEFAULT '';

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
