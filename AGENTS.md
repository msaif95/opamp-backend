# opamp-backend agent notes

OpAMP control plane (Go, `opamp-go`) for OTel Collector fleet management. Design: `../PLAN.md`.

- Go via Homebrew: `export PATH=/opt/homebrew/bin:$PATH`.
- Verify: `make lint` (gofmt + vet) and `make test` (`go test -race ./...`).
- Dev: `make deps-up` (Postgres :5432 + Redis :6379 via `../opamp-deploy/compose`, needs Docker running), then `make run`.
  OpAMP listener on :4320 (`/v1/opamp`, plaintext unless `TLS_CERT_FILE`/`TLS_KEY_FILE` set), API on :8080.
  `make run` defaults to local admin `admin`/`admin` and a dev JWT key; both are dev-only.
- Simulated agents: `go run ./cmd/agentsim -n 200 -token <api key>`; issue the key with
  `POST /api/v1/credentials/api-keys` (admin) or from the UI's Agent credentials page.
- Migrations in `migrations/` are applied on startup (golang-migrate). The schema is a single `000001_init` pair
  (squashed before the first production deployment); from now on add new numbered files, never edit applied ones.
- Layout: `internal/connection` (listener, auth on connect, live conn tracking), `internal/protocol` (message
  handling, OpAMP-only), `internal/registry` (Postgres agent state + Redis `opamp:route:<uid>` routing table and
  `opamp:agent-events` pub/sub), `internal/agentconfig` (config templates, immutable versions, YAML/pipeline validation;
  `internal/config` is the server's own env config), `internal/auth` (agent mTLS/API key, human sessions + RBAC), `internal/api`
  (REST), `internal/events` (SSE fan-out).
- Deployment (compose, Helm chart) lives in `../opamp-deploy`; only the `Dockerfile` stays here.
- PKI is cert-manager with a self-signed CA (`../opamp-deploy/helm/opamp/templates/certificates.yaml`); the backend
  reads the server cert and client CA bundle from the mounted Secret. Any client cert chaining to that CA is
  accepted (no per-cert enrollment); revocation is by fingerprint in the `credentials` table.
- Dependencies: pin versions published at least 7 days ago.
- Remote config: `PUT /api/v1/agents/{uid}/config` sets `agents.desired_config_version_id`, then publishes to
  `opamp:push:<replica>` for the replica in the routing table; that replica sends the config over the agent's
  WebSocket. It is also offered on any agent message while the agent's reported hash differs from the desired one.
  A hash the agent reported as APPLYING/FAILED is not re-offered.
- `agentsim -apply-fail-pct N` makes N% of simulated agents report FAILED for pushed configs.
- When restarting `make run`, wait for the old process to release :4320 before starting the new one.
- Bulk push: `internal/targeting` (attribute selector -> SQL) and `internal/rollout` (batched push with per-batch
  failure threshold, pause/resume/abort). The engine ticks every 2s on every replica and advances each rollout
  under a row lock. `GET /api/v1/agents/facets` lists low-cardinality attributes for building selectors.
- Do not pipe `agentsim` through `head`: it dies of SIGPIPE once the pipe closes. Redirect to a file instead.
- Agent events (`opamp:agent-events`) are published only for real changes (connect, disconnect, description,
  health, effective config, remote config status), never for plain heartbeats; the UI relies on this to stay calm.
- `GET /api/v1/agents` defaults to a stable order by `host.name`; `sort=last_seen` reorders on every heartbeat.
- SSO: `internal/auth/oidc.go` (authorization code + PKCE, state/nonce in a signed short-lived cookie). Roles come
  from the ID token `groups` claim via `OKTA_ADMIN_GROUPS` / `OKTA_OPERATOR_GROUPS` / `OKTA_VIEWER_GROUPS`; a user in
  none of them is refused. The callback hands the session token to the UI in the URL fragment.
  Try it locally with `go run ./cmd/fakeidp -groups sre` + `make run-sso` (fakeidp is dev-only: it signs in anyone).
- Rollouts: fixed batches or cumulative canary percentages (`canary_steps_pct`); `auto_rollback` rolls back instead
  of pausing. Rollback restores `rollout_agents.previous_config_version_id`; agents with no previous config keep
  the new one and are reported. Engine-initiated pauses/rollbacks are audited as actor `system`.
- Groups (`internal/targeting/groups.go`) are saved selectors with live membership; rollouts snapshot the selector.
- Multi-replica and scale testing: `scripts/replicas.sh up|down|kill`, `scripts/scale-probe.py`, and
  `agentsim -backends ... -ramp ...`; procedure and results in `../opamp-deploy/docs/runbook.md`.
- Heartbeats (messages with no state change) take a read-only path: liveness goes to Redis and `last_seen` is
  flushed to Postgres in batches every 5 s. Do not add a per-heartbeat write.
- Anything that updates many `agents` rows in one statement must lock them in `instance_uid` order (see the sweep,
  heartbeat flush and rollout release); unordered multi-row updates deadlock across replicas.
- Hardening: live connections are re-checked every 30 s and closed if their credential was revoked or expired
  (`Manager.EnforceCredentials`); local login is rate-limited per client address in Redis; the client CA bundle and
  server cert reload from disk; rollout pauses/rollbacks/failed completions go to `ALERT_WEBHOOK_URL`.
- Self-telemetry (`internal/telemetry`) is off unless `OTEL_EXPORTER_OTLP_ENDPOINT` is set. Keep its semconv import
  on the same schema version as the OTel SDK's `resource.Default()` or the backend fails to start with it enabled.
- System page (`GET /api/v1/system`, admin): static protection flags from config, live replicas (each replica
  writes `opamp:replica:<id>` to Redis every 10 s with a 30 s TTL) and the last 100 alerts (`opamp:alerts` list;
  recorded whether or not a webhook is configured). It reports only on/off flags, never secret values.
- Tests: `make test` skips anything needing a database; `make test-integration` (after `make deps-up`) runs all of
  them against a separate `opamp_test` database and Redis DB 15 via `internal/testdb`. New SQL needs an integration test.
- Redis is best-effort: never fail an agent message because Redis is down (see `Registry.setRoute`), and readiness
  checks Postgres only. Log lines that can repeat per agent message go through `internal/logthrottle`.
- The offline sweep skips agents that still have a Redis route, so stale `last_seen` after a Postgres outage does not
  flap the fleet. `Report` refreshes the route before touching Postgres for the same reason.
- Rebalancing (`internal/connection/rebalance.go`) and fleet-health alerts (`internal/alert/health.go`) are pure
  decision functions plus a small loop; keep the logic in the tested functions.
- A running rollout picks up agents that start matching its selector (they join the next batch); a finished one does not.
- Production guards: `config.Load` refuses plaintext agent connections, the dev signing key, a short admin
  password or no sign-in method unless `DEV_MODE=true` (set by `make run*` and `scripts/replicas.sh`).
- Retention (`internal/retention`): audit events, finished rollouts and long-offline agents are pruned by
  `AUDIT_RETENTION_DAYS` (0 = keep), `ROLLOUT_RETENTION_DAYS` (180), `AGENT_RETENTION_DAYS` (30).
- CI (`.github/workflows/ci.yml`) runs lint, the integration tests and govulncheck, then builds the image.
- Runtime switches (`internal/settings`, table `settings`, `PUT /api/v1/system/settings/{key}`, admin): SSO, local
  login, agent mTLS, alert delivery, monitoring export, rebalancing and fleet-health alerts can be switched on/off
  from the System page. Each replica caches the values and refreshes on a Redis notification or every 5 s.
  Components take a `func() bool` gate rather than reading config. A switch can only turn on something the
  deployment configured (`Definition.Available`); agent TLS is `Locked`; the last working sign-in method cannot be
  switched off. Add a new protection by adding a key, a `Definition` in `cmd/server/main.go` and UI copy in
  `opamp-ui/src/features/system/System.tsx`.
- Group configs ("fleets"): `PUT /api/v1/groups/{id}/config` starts a rollout to the group and records the version
  on the group. `rollout.Service.ReconcileGroups` (every engine tick) then gives it to matching agents that have no
  config, but only once a rollout of that version to the group has completed; never while one is running, paused,
  aborted or rolled back. It does not replace a config an agent already has.
- Stock OpAMP Supervisor is supported and was tested end to end (opampsupervisor + otelcol-contrib 0.164.0): connect,
  attributes, health, remote config apply, and FAILED reporting when the collector rejects a config.
  `POST /api/v1/agents/install-command` (admin, `internal/api/install.go`) issues an API key and returns an install
  script for it; labels are restricted to a safe alphabet because they land in shell and YAML.
- Remote collector upgrades (OpAMP packages) are not built: the stock Supervisor refuses to start with
  `accepts_packages` (contrib issue #47272). Revisit when that lands.
- Config builder (`internal/pipeline`): `catalog.go` lists source/processor/destination types with form fields;
  `Render` turns a builder spec into collector YAML, one pipeline per signal that a source collects and a
  destination accepts. The spec is stored on the version (`config_versions.builder_spec`) so it can be reopened.
  Endpoints: `GET /configs/builder/catalog`, `POST /configs/builder/render`; `POST /configs` and
  `/configs/{id}/versions` accept `builder` instead of `body`. When adding a catalog type, render it and run
  `otelcol-contrib validate --config` on the result; all 15 current types passed that against contrib 0.164.0.
- The second migration is `000002_runtime_additions` (settings, group config, builder spec).
- Builder library (`internal/pipeline/library.go`, table `library_components`): saved sources/processors/destinations.
  A spec component may carry `library: <id>`; `Library.Resolve` substitutes the item's current settings at render and
  save time, and the stored spec keeps only the reference. Saved config versions are never rewritten when an item
  changes: a config picks the change up the next time it is saved.
- Throughput (`internal/throughput`): agents that advertise ReportsOwnMetrics are offered OpAMP own-metrics
  connection settings pointing at `/v1/metrics` on the agent listener (derived from `AGENT_ENDPOINT_URL`), with an
  HMAC token per agent. The intake keeps only the latest sample per agent in Redis (5 min TTL) and derives rates
  from the collector's `otelcol_receiver_*` / `otelcol_exporter_*` counters. Shown on agent detail as `throughput`.
  Verified with opampsupervisor + otelcol-contrib 0.164.0; the collector reports about once a minute.
