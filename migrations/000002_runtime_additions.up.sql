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
