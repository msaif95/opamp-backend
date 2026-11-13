ALTER TABLE rollouts DROP CONSTRAINT rollouts_group_id_fkey;
ALTER TABLE rollouts ADD CONSTRAINT rollouts_group_id_fkey FOREIGN KEY (group_id) REFERENCES agent_groups(id);
ALTER TABLE rollout_agents DROP COLUMN previous_config_version_id;
UPDATE rollouts SET canary_steps_pct = '{1,10,50,100}' WHERE canary_steps_pct IS NULL;
ALTER TABLE rollouts
    DROP COLUMN auto_rollback,
    ALTER COLUMN canary_steps_pct SET NOT NULL,
    ALTER COLUMN canary_steps_pct SET DEFAULT '{1,10,50,100}';
