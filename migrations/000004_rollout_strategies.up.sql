-- NULL canary_steps_pct means fixed-size batches (batch_size); otherwise
-- cumulative percentages of the target, e.g. {1,10,50,100}.
ALTER TABLE rollouts
    ALTER COLUMN canary_steps_pct DROP DEFAULT,
    ALTER COLUMN canary_steps_pct DROP NOT NULL,
    ADD COLUMN auto_rollback BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE rollouts SET canary_steps_pct = NULL;

-- What the agent was assigned before this rollout touched it, for rollback.
ALTER TABLE rollout_agents
    ADD COLUMN previous_config_version_id UUID REFERENCES config_versions(id) ON DELETE SET NULL;

-- Rollouts keep their own selector snapshot, so deleting a group must not be blocked by history.
ALTER TABLE rollouts DROP CONSTRAINT rollouts_group_id_fkey;
ALTER TABLE rollouts ADD CONSTRAINT rollouts_group_id_fkey
    FOREIGN KEY (group_id) REFERENCES agent_groups(id) ON DELETE SET NULL;
