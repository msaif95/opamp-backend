# opamp-backend agent notes

OpAMP control plane (Go, `opamp-go`) for OTel Collector fleet management. Design: `../PLAN.md`.

- Go via Homebrew: `export PATH=/opt/homebrew/bin:$PATH`.
- Verify: `make lint` (gofmt + vet) and `make test` (`go test -race ./...`).
- Dev: `make deps-up` (Postgres :5432 + Redis :6379 via `../opamp-deploy/compose`, needs Docker running), then `make run`.
  OpAMP listener on :4320 (`/v1/opamp`, plaintext unless `TLS_CERT_FILE`/`TLS_KEY_FILE` set), API on :8080.
  `make run` defaults to local admin `admin`/`admin` and a dev JWT key; both are dev-only.
- Simulated agents: `go run ./cmd/agentsim -n 200 -token <api key>`; issue the key with
  `POST /api/v1/credentials/api-keys` (admin) or from the UI's Agent credentials page.
- Migrations in `migrations/` are applied on startup (golang-migrate); add new numbered files, never edit applied ones.
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
