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
- The schema is one migration, `000001_init` (squashed again before first production use). After the first
  production deployment, add `00000N_<name>` files and never edit an applied one.
- Builder library (`internal/pipeline/library.go`, table `library_components`): saved sources/processors/destinations.
  A spec component may carry `library: <id>`; `Library.Resolve` substitutes the item's current settings at render and
  save time, and the stored spec keeps only the reference. Saved config versions are never rewritten when an item
  changes: a config picks the change up the next time it is saved.
- Throughput (`internal/throughput`): agents that advertise ReportsOwnMetrics are offered OpAMP own-metrics
  connection settings pointing at `/v1/metrics` on the agent listener (derived from `AGENT_ENDPOINT_URL`), with an
  HMAC token per agent. The intake keeps only the latest sample per agent in Redis (5 min TTL) and derives rates
  from the collector's `otelcol_receiver_*` / `otelcol_exporter_*` counters. Shown on agent detail as `throughput`.
  Verified with opampsupervisor + otelcol-contrib 0.164.0; the collector reports about once a minute.
- Collector charts: the same intake also reads `otelcol_process_cpu_seconds`, `process_memory_rss` and
  `process_runtime_heap_alloc_bytes`, and keeps up to 180 points per agent in a Redis list (`opamp:history:<uid>`,
  about 3 hours). `GET /api/v1/agents/{uid}/metrics` serves them; the UI charts them with recharts.
- Approval stages: a rollout with `manual_approval` pauses after every settled batch (error text starts with
  "waiting for approval", outcome `awaiting_approval`, which also raises an alert); `Resume` approves the next batch.
- Restart: `POST /api/v1/agents/{uid}/restart` (operator) publishes `restart:<uid>` on the owning replica's push
  channel; that replica sends the OpAMP Restart command. Needs the AcceptsRestartCommand capability (0x400), which
  install scripts now enable. Verified against opampsupervisor 0.164.0 (collector PID changed, came back healthy).
- Stop/resume collection: OpAMP has no stop command, so `POST /agents/{uid}/pause|resume` (operator) sets
  `agents.paused`; a paused agent is sent `protocol.PausedConfig` (nop receiver to nop exporter) instead of its
  assigned config, which is kept for resume. Bulk pushes mark paused agents skipped (the config applies on resume).
  Verified against opampsupervisor 0.164.0.
- Console API tokens (`internal/auth/tokens.go`, table `api_tokens`, admin endpoints under `/api/v1/auth/tokens`):
  secrets start with `opamp_pat_`, are stored hashed, carry a fixed role and are checked against the database on
  every request. `Sessions.Require` accepts them wherever it accepts a session.
- `cmd/opampctl`: CLI over the console API (`make build` → `bin/opampctl`). `apply -f` is idempotent create/update
  of `kind: Config` / `kind: Group` YAML and never deletes or pushes; `push --wait` exits 2 unless completed.
  Its tests use a fake API server; add a case there when adding a resource kind.
- Projects (`internal/access`, tables `projects`, `project_members`, `project_id` on credentials, agents,
  config_templates, agent_groups, rollouts, library_components, api_tokens). `access.Scope` = global admin, a global
  role that covers unassigned (NULL project) resources, and a role per project. Routes only require sign-in
  (`Sessions.Require(auth.RoleNone)` + `withScope`); every handler must filter lists with `scopeOf(ctx)` and check
  single resources with `s.allow` / `allowAgent` / `allowConfig` / `allowGroup` / `targetProject`. Something the
  caller cannot view answers 404, not 403. A collector takes the project of its API key at connect; selectors are
  always evaluated inside one project (`Selector.WhereIn`), so groups and pushes never cross projects.
  `internal/api/access_integration_test.go` is the access matrix: extend it with every new endpoint.
- `opampctl --project <name>` (or `OPAMP_PROJECT`) selects the project commands act in.
- `GET /api/v1/users` (admin) lists everyone who signed in (table `users`, updated by `Projects.RecordSignIn` on
  local and Okta sign-in) plus people added to a project before their first sign-in, with their memberships.
- Agent history (`agent_events`, `GET /api/v1/agents/{uid}/events`, viewer in the agent's project): written by the
  `record_agent_events` trigger on `agents`, so every code path is covered; heartbeats do not fire it. Kinds:
  first_seen, connected, offline, healthy, unhealthy, config_assigned/unassigned, config_applied/failed (with
  config name, version, error), collection_stopped/resumed, collector_version_changed. Pruned after
  `AGENT_EVENT_RETENTION_DAYS` (90). A new tracked column needs the trigger's WHEN clause and body updated.
- The SSE stream (`/api/v1/events`) sends only a generic "changed" cue, never agent IDs: any signed-in user can
  open it, so it must not reveal other projects' activity.
- Sessions: the JWT carries a session ID tracked in Redis (`auth.SessionStore`); `Verify` touches it, so idle
  timeout, sign-out (`POST /auth/logout`) and admin sign-out (`DELETE /users/{subject}/sessions`) work. If Redis is
  unreachable a validly signed session is accepted (fail open, logged) so an outage cannot lock admins out. The
  console enforces the idle timeout on user input itself because its background polling keeps the session alive.
- Audit log: `audit_events` is hash-chained by a BEFORE INSERT trigger and refuses UPDATE/DELETE/TRUNCATE unless the
  transaction sets `opamp.audit_prune = 'on'` (only the retention job and the test reset do). `audit_verify()`
  checks the chain. `Server.audit` also logs each event with `audit=true` for export.
- Config secrets (`internal/secrets`): `${secret:NAME}` in a config body is resolved per project only in
  `protocol.Handler.pendingConfig`, never stored resolved; the config hash stays that of the stored body.
  `RedactSecrets` puts references back into reported effective configs before they are stored. Values must be a
  single YAML-safe token (`checkValue`). Any new path that sends or stores a config body must go through these.
- Stores: outside dev mode `Validate` requires TLS to Postgres and Redis unless `ALLOW_UNENCRYPTED_STORES=true`.
- `second_approver` switch: the starter of a rollout cannot `resume` it (checked in `rolloutAction`).
- Own telemetry: `handler.OwnTelemetry` (wired in main) makes one `ConnectionSettingsOffers` per connection from the
  agent's capabilities, all pointing at this backend's agent port: `/v1/metrics` (`internal/throughput`: headline
  points plus, in `all.go`, every reported series as rate/gauge/average, max 300 series, 3h), `/v1/logs`
  (`internal/ownlogs`, newest 500 lines, 24h), `/v1/traces` (`internal/owntraces`, newest 300 spans, 24h, and
  forwarded unchanged to `OWN_TRACES_ENDPOINT` if set). All in Redis, secrets redacted. The stock Supervisor
  (checked at v0.164.0) supports all three; it has no code for "other connection settings" and only relays custom
  messages to collector components.
- Kubernetes (`internal/k8sbridge`): an OpAMP Bridge is one agent (`connector_type = k8s_bridge`, detected by the
  `opentelemetry.io/opamp.bridge.mode` attribute) reporting one file per OpenTelemetryCollector ("namespace/name" ->
  resource YAML, kept in `agents.effective_files`). Configs are assigned per collector (`bridge_collector_configs`,
  `PUT /agents/{uid}/collectors/config`); `Handler.bridgeConfig` sends EVERY managed collector back (the bridge
  deletes managed ones missing from a remote config), rebuilt from name/namespace/labels/spec so the hash is stable.
  Nothing is sent to a bridge with no assignment. Bridges are excluded from rollouts, group configs, whole-agent
  assign and pause. Tested against operator chart 0.129.0 (app 0.162.0) on docker-desktop.
- Projects are mandatory: `targetProject` rejects a create without `project_id` (400). The one exception is a global
  admin API token. Rows with a NULL project can still exist from before and stay governed by the global role.
