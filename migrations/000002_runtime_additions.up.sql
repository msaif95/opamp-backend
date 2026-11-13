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
