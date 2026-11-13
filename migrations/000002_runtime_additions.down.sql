DROP TABLE IF EXISTS api_tokens;
ALTER TABLE agents DROP COLUMN IF EXISTS paused;
ALTER TABLE rollouts DROP COLUMN IF EXISTS manual_approval;
DROP TABLE IF EXISTS library_components;
ALTER TABLE config_versions DROP COLUMN IF EXISTS builder_spec;
ALTER TABLE agent_groups DROP COLUMN IF EXISTS config_version_id, DROP COLUMN IF EXISTS config_set_at;
DROP TABLE IF EXISTS settings;
