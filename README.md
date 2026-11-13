# opamp-backend

Control plane for a fleet of OpenTelemetry Collectors, speaking [OpAMP](https://github.com/open-telemetry/opamp-spec).
It holds the agents' connections, tracks their state, stores collector configs and pushes them out in controlled
batches. The console is [opamp-ui](../opamp-ui); deployment lives in [opamp-deploy](../opamp-deploy), whose
[runbook](../opamp-deploy/docs/runbook.md) covers operations.

## What it does

- **Agents** connect over WebSocket (`:4320/v1/opamp`) and authenticate with an API key or a client certificate.
- **Fleet state** (attributes, health, effective config) is kept in PostgreSQL; Redis holds which replica has each
  agent's connection, and carries pushes and live console updates between replicas.
- **Configs** are named and versioned; each version is validated before it can be saved.
- **Bulk pushes** send a config version to agents selected by attribute, in fixed batches or canary steps, pausing or
  rolling back when too many agents in a batch fail.
- **Console API** (`:8080/api/v1`) with Okta single sign-on, a break-glass local admin, three roles and an audit log.

Any number of replicas can run side by side; none holds state the others need.

## Run it locally

Needs Go and Docker.

```bash
make deps-up     # Postgres and Redis from ../opamp-deploy/compose
make run         # backend with development defaults: admin / admin, plaintext agents
```

Then issue an agent API key (console → Agent credentials, or `POST /api/v1/credentials/api-keys`) and start some
simulated agents:

```bash
go run ./cmd/agentsim -n 200 -token <key>
```

`make run` sets `DEV_MODE=true`. Without it the backend refuses to start with plaintext agent connections, the
development signing key, a short admin password or no sign-in method.

## Configuration

Everything is set through environment variables; the full table is in the
[runbook](../opamp-deploy/docs/runbook.md#2-configuration-backend-environment). The minimum for production:

| Variable | Purpose |
|---|---|
| `POSTGRES_DSN`, `REDIS_ADDR` | Stores |
| `JWT_SIGNING_KEY` | Signs console sessions; 32+ random bytes |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | Certificate for the agent listener |
| `TLS_CLIENT_CA_FILE` | CA that agent client certificates must chain to (enables mTLS) |
| `OKTA_*` or `LOCAL_ADMIN_PASSWORD` | At least one way to sign in |

## Test

```bash
make lint               # gofmt and go vet
make test               # unit tests; anything needing a database is skipped
make test-integration   # everything, against a separate opamp_test database (needs `make deps-up`)
```

## Layout

```
cmd/server        the backend
cmd/agentsim      simulated agents, for development and scale tests
cmd/fakeidp       development-only stand-in for Okta
internal/         connection (listener), protocol (OpAMP messages), registry (agent state), agentconfig,
                  targeting (selectors, groups), rollout (bulk push engine), auth, api, events, alert,
                  retention, telemetry
migrations/       database schema, applied at start-up
scripts/          multi-replica and scale-test helpers
```

## Build and release

`docker build --build-arg VERSION=<version> -t opamp-backend .` builds the image. CI runs the tests and publishes
`ghcr.io/<owner>/opamp-backend:sha-<commit>` from `main`; the `release` workflow publishes a versioned image and tag.

## Database changes

The schema is `migrations/000001_init.up.sql`. From the first production deployment onward, never edit an applied
migration: add `00000N_<name>.up.sql` and `.down.sql`.
