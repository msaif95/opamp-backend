ALTER TABLE config_versions DROP COLUMN IF EXISTS builder_spec;
ALTER TABLE agent_groups DROP COLUMN IF EXISTS config_version_id, DROP COLUMN IF EXISTS config_set_at;
DROP TABLE IF EXISTS settings;
