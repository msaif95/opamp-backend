DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS role_assignments;
DROP TABLE IF EXISTS users;
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_credential_fk;
DROP TABLE IF EXISTS credentials;
DROP TABLE IF EXISTS rollout_agents;
DROP TABLE IF EXISTS rollouts;
DROP TABLE IF EXISTS agent_groups;
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_desired_config_fk;
DROP TABLE IF EXISTS config_versions;
DROP TABLE IF EXISTS config_templates;
DROP TABLE IF EXISTS agents;
DROP TYPE IF EXISTS rbac_role, identity_provider, credential_kind, rollout_agent_status, rollout_status,
    config_origin, remote_config_status, auth_mode, connector_type;
