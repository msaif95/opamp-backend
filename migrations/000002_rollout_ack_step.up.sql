-- Highest step whose failures an operator has acknowledged by resuming.
-- The failure threshold is only enforced for steps above it.
ALTER TABLE rollouts ADD COLUMN ack_step INTEGER NOT NULL DEFAULT -1;
