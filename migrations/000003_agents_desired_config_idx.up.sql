CREATE INDEX agents_desired_config_idx ON agents (desired_config_version_id) WHERE desired_config_version_id IS NOT NULL;
CREATE INDEX agents_host_name_idx ON agents ((attributes->>'host.name'), instance_uid);
