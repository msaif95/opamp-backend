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
