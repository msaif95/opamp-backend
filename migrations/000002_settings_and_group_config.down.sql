ALTER TABLE agent_groups DROP COLUMN IF EXISTS config_version_id, DROP COLUMN IF EXISTS config_set_at;
DROP TABLE IF EXISTS settings;
