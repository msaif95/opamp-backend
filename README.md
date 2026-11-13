# OpAMP Fleet

Fleet management for OpenTelemetry Collectors, built on [OpAMP](https://github.com/open-telemetry/opamp-spec).
One console to see every collector, change its config safely, and control who can do what.

The system is three repositories that sit side by side:

| Repository | What it is |
|---|---|
| `opamp-backend` (this one) | Go service: holds collector connections, stores state, runs bulk pushes, serves the console API. Also the `opampctl` command-line tool. |
| [`opamp-ui`](../opamp-ui) | The web console (React, TypeScript, Vite). |
| [`opamp-deploy`](../opamp-deploy) | Docker Compose for local stores, the Helm chart, deploy scripts and the [operations runbook](../opamp-deploy/docs/runbook.md). |

Contents: [How it fits together](#how-it-fits-together) · [1. Development](#1-development) ·
[2. Deployment](#2-deployment) · [3. Features and usage](#3-features-and-usage)

## How it fits together

```
 collectors (OpAMP Supervisor)                people (browser)      automation
        │  WebSocket :4320 /v1/opamp              │                  │ opampctl
        │  own metrics  :4320 /v1/metrics         ▼                  ▼
        ▼                                   opamp-ui (nginx) ──► console API :8080 /api/v1
  ┌───────────────────────── opamp-backend (any number of replicas) ─────────────────────────┐
  │ connection · protocol · registry · rollout engine · access · api                          │
  └──────────────┬───────────────────────────────────────────────┬────────────────────────────┘
                 ▼                                               ▼
        PostgreSQL (all durable state)        Redis (which replica holds each collector, pushes
                                              between replicas, live updates, short histories)
```

- Collectors connect **out** to the backend; the backend never connects to a collector.
- Replicas hold no state the others need. Postgres is the source of truth; if Redis is down, collectors stay
  connected and only pushes and live updates are delayed.

## 1. Development

### Prerequisites

| Tool | Version | Used for |
|---|---|---|
| Go | 1.27+ | backend, `opampctl`, simulator |
| Node.js | 22 | console |
| Docker | any recent | Postgres and Redis locally, images |
| Helm, kubectl | recent | only for Kubernetes deployment |

On macOS with Homebrew: `brew install go node@22 helm`, then
`export PATH=/opt/homebrew/bin:/opt/homebrew/opt/node@22/bin:$PATH`.

### First run

Clone the three repositories next to each other, then:

```bash
# 1. Stores (Postgres :5432, Redis :6379)
cd opamp-backend
make deps-up

# 2. Backend: agents on :4320, console API on :8080. Development defaults: admin / admin, plaintext agents.
make run

# 3. Console, in another terminal: http://localhost:5174
cd ../opamp-ui
npm ci
npm run dev

# 4. Some collectors to look at, in another terminal. Create a key in the console
#    (Admin → Agent credentials → Issue API key), then:
cd ../opamp-backend
go run ./cmd/agentsim -n 200 -token <key>
```

Sign in at http://localhost:5174 as `admin` / `admin`.

`make run` sets `DEV_MODE=true`. Without it the backend refuses to start with plaintext agent connections, the
development signing key, a short admin password or no sign-in method.

### Useful commands

| Command (in `opamp-backend`) | What it does |
|---|---|
| `make deps-up` / `make deps-down` | Start / stop Postgres and Redis |
| `make run` | Run the backend with development defaults |
| `make run-sso` | Same, with single sign-on pointed at the stand-in provider (below) |
| `make build` | Build `bin/opamp-backend` and `bin/opampctl` |
| `make lint` | `gofmt` check and `go vet` |
| `make test` | Unit tests; anything needing a database is skipped |
| `make test-integration` | Every test, against a separate `opamp_test` database and Redis DB 15 |
| `scripts/replicas.sh up 3` / `down` | Run several replicas locally; the runbook describes the scale test |

| Command (in `opamp-ui`) | What it does |
|---|---|
| `npm run dev` | Dev server on :5174, `/api` proxied to the backend |
| `npm run lint` / `npm test` / `npm run build` | oxlint / unit tests / type-check and production build |

### Trying single sign-on locally

A real Okta tenant is not needed for development:

```bash
go run ./cmd/fakeidp -groups opamp-admins     # stand-in identity provider on :9999; signs in anyone
make run-sso                                  # backend with Okta settings pointing at it
```

The login page then shows "Sign in with Okta". Keep the stand-in on localhost only.

### Trying a real collector

The console generates an install script (Fleet → Add collectors) that downloads the official collector and OpAMP
Supervisor and connects them to your local backend. Run it with `INSTALL_DIR=/tmp/otel sh install.sh` to avoid
needing root, then start the Supervisor with the command it prints.

### Layout

```
cmd/server        the backend
cmd/opampctl      command-line client
cmd/agentsim      simulated collectors, for development and scale tests
cmd/fakeidp       development-only stand-in for Okta
internal/
  connection      agent listener, live connections, rebalancing
  protocol        OpAMP message handling
  registry        collector state and history
  agentconfig     configs, versions, validation
  pipeline        config builder: catalog, rendering, reusable library
  targeting       selectors and groups
  rollout         bulk push engine
  access          projects, memberships, who may see and change what
  auth            agent credentials, sessions, Okta, API tokens
  api             console API
  alert, retention, settings, telemetry, throughput, events, store, config
migrations/       database schema, applied at start-up
scripts/          multi-replica and scale-test helpers
```

### Conventions

- **Schema:** one migration, `migrations/000001_init`. After the first production deployment, never edit an applied
  migration; add `00000N_<name>.up.sql` and `.down.sql`.
- **Tests:** new SQL needs an integration test. New endpoints need a case in
  `internal/api/access_integration_test.go`, which checks who can see and change what.
- **Access:** every handler filters lists by the caller's projects and checks single resources; see `AGENTS.md`.
- `AGENTS.md` in each repository records the detailed rules and the reasons behind them.

## 2. Deployment

### Local, with Docker Compose

The Compose file runs only the stores; the backend and console run from source as in [First run](#first-run).

```bash
docker compose -f ../opamp-deploy/compose/docker-compose.yml up -d --wait     # same as `make deps-up`
```

### Local Kubernetes (Docker Desktop)

Runs the real images and the Helm chart, with TLS and client certificates from cert-manager.

```bash
cd opamp-deploy

# once per cluster
helm repo add jetstack https://charts.jetstack.io
helm --kube-context docker-desktop upgrade --install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace --set crds.enabled=true --wait

scripts/build-images.sh dev      # builds opamp-backend:dev and opamp-ui:dev from the sibling checkouts
scripts/deploy.sh dev            # 2 backend replicas, throwaway Postgres and Redis, admin / admin
```

`deploy.sh dev` only ever targets the `docker-desktop` context unless `OPAMP_KUBE_CONTEXT` is set, and prints the
port-forward commands for the console and the agent endpoint. Cluster nodes cache images by tag, so after
rebuilding use a new tag: `scripts/build-images.sh v2 && OPAMP_IMAGE_TAG=v2 scripts/deploy.sh dev`.
Remove it with `scripts/deploy.sh dev delete`.

### Production Kubernetes

**You provide:**

- cert-manager in the cluster.
- PostgreSQL (with backups) and Redis that you operate.
- Released images: CI publishes `ghcr.io/<owner>/opamp-backend` and `opamp-ui`; the `release` workflow in each
  repository publishes a versioned image.
- A Secret (named by `existingSecret`) with:

| Key | Required | Purpose |
|---|---|---|
| `POSTGRES_DSN` | yes | Database connection string; must use `sslmode=require` or stricter |
| `JWT_SIGNING_KEY` | yes | Signs console sessions; 32+ random bytes |
| `SECRETS_ENCRYPTION_KEY` | for config secrets | Encrypts secrets referenced from configs; 32+ random characters. Keep a copy: without it stored secrets are unreadable |
| `REDIS_PASSWORD` | if Redis needs one | Redis authentication |
| `OKTA_CLIENT_SECRET` | with Okta | Okta application secret |
| `LOCAL_ADMIN_PASSWORD` | optional | Break-glass admin login; 16+ characters |
| `ALERT_WEBHOOK_URL` | optional | Slack-compatible webhook for alerts |

**Deploy:**

```bash
cd opamp-deploy
cp helm/opamp/values-prod.yaml my-values.yaml          # fill in every CHANGE
OPAMP_KUBE_CONTEXT=<context> scripts/deploy.sh prod my-values.yaml render   # review the manifests
OPAMP_KUBE_CONTEXT=<context> scripts/deploy.sh prod my-values.yaml
```

The script refuses a values file that still contains `CHANGE`. The main values:

| Value | Meaning |
|---|---|
| `replicaCount` | Backend replicas; plan about 5,000 collectors each and never fewer than 3 |
| `agentEndpointUrl` | `wss://…/v1/opamp` as collectors reach it; written into install scripts |
| `service.opampType` | How the agent port is exposed; use a layer-4 load balancer |
| `ui.ingress.*` | Console hostname and TLS |
| `okta.*` | Issuer, client ID, redirect URL and the groups that grant admin, operator and viewer |
| `certManager.*` | Self-signed CA created by the chart (default), or an existing issuer |
| `retention.*` | Days to keep the audit log, finished pushes, offline collectors and collector history |
| `networkPolicy.enabled` | Restrict the console API to the console pods |

**Networking:** collectors reach the backend through a layer-4 load balancer, never an HTTP ingress, because TLS and
client certificates must arrive at the backend untouched. Both `/v1/opamp` and `/v1/metrics` are served on that
port. The console is exposed over HTTPS through the ingress.

**After deploying:** sign in, open Admin → System and confirm the protections you expect are on. Day-to-day
operations, alerts, failure scenarios and scaling are in the [runbook](../opamp-deploy/docs/runbook.md).

### Configuration reference

Everything is set through environment variables (the chart sets them from values). The full table is in the
[runbook](../opamp-deploy/docs/runbook.md#2-configuration-backend-environment).

## 3. Features and usage

### Fleet

- **See every collector** with its status, version, attributes and config state. The cards at the top (total,
  connected, healthy, unhealthy, config failed) filter the list; so do the project and group dropdowns and
  `key=value` attribute filters.
- **Collector page, Overview tab:** identity, attributes, the assigned and effective config, and charts of the
  collector's own CPU, memory and throughput for the last three hours.
- **Collector page, Activity tab:** a timeline of everything that happened to it: connected, offline, healthy,
  unhealthy, config assigned, applied or failed (naming the config and version), collection stopped or resumed,
  and collector upgrades. Kept for 90 days by default.
- **Restart** the collector process, or **Stop collection** (the collector stays connected but collects nothing
  until resumed).

### Adding collectors

Fleet → **Add collectors** (admins). Choose the platform, collector version, project and labels; the console issues
an API key and shows a script once. The script downloads the official collector and OpAMP Supervisor, verifies
their checksums, writes the Supervisor config and installs a service (systemd on Linux, launchd on macOS, when run
with `sudo`). The labels decide which groups the collector falls into.

Collectors authenticate with an API key or, when a client CA is configured, a client certificate.

### Configs

- **Build a config** from sources, processors and destinations chosen from a catalog. The collector YAML is
  generated and shown as you go, and logs, metrics and traces are each routed only through pieces that handle them.
- **Write YAML** directly when the builder does not cover what you need.
- Every save is a new, numbered **version**; versions can be compared, and each is validated before it is saved.
- **Library:** save a configured source, processor or destination once and reuse it in other configs.

### Changing collectors' configs

| Way | When to use it |
|---|---|
| **Push to one collector** (its page → Push config) | Trying a change on one host |
| **Bulk push** (Bulk push → New bulk push) | Rolling a version out to many collectors |
| **Group config** (Groups → Set config) | A group should always have this config, including collectors that join later |

A bulk push targets collectors by attribute or by a saved group and goes out in fixed batches or canary steps
(for example 1%, 10%, 50%, 100%). It pauses, or rolls back automatically if you choose, when too many collectors
in a batch fail; it can also wait for a person to approve every batch. Pause, resume, abort and roll back are
available while it runs, and collectors that connect during a push join it.

### Groups

A group is a saved target such as "prod collectors on AWS owned by SRE". Membership is live: any collector whose
attributes match belongs to it. Groups are used to filter the fleet, to target bulk pushes, and can own a config.

### Projects and access

- A **project** owns collectors, configs, groups, bulk pushes and library items. A collector joins the project of
  the API key it was installed with.
- People see a project only when added to it, as **viewer** (can look) or **operator** (can change configs, push,
  restart and stop collectors) in that project. **Admins** see and manage everything.
- Admin → **Projects** creates projects and manages their people. Admin → **Users** lists everyone who has signed
  in, their role and their projects, and adds people to projects.
- Groups and bulk pushes never cross a project.
- Anything outside a project is governed by a person's global role, which comes from Okta groups.

Sign-in is through **Okta** (roles from groups), with an optional local administrator as a break-glass login.

### Administration

| Page (under Admin) | What it is for |
|---|---|
| Projects, Users | Access, as above |
| Agent credentials | Four tabs: agent API keys, revoked client certificates, console API tokens, config secrets |
| Audit log | Every sign-in and every change, with who made it. Events cannot be edited or deleted, and "Check integrity" detects tampering |
| System | Which protections are on, with switches for most; backend replicas and their load; recent alerts |

Alerts go to a Slack-compatible webhook: bulk pushes that pause, wait for approval, roll back or finish with
failures, and fleet-wide trouble (a large share of collectors offline or unhealthy).

### Security controls

- **Config secrets:** store a value such as a destination API key under a name (Admin → Agent credentials → Config
  secrets) and write `${secret:NAME}` in the config. It is stored encrypted, filled in only when the config goes to
  a collector, and never shown again.
- **Sessions:** signed out after 30 minutes without use and after 8 hours regardless (both configurable). Sign out
  ends the session on the server; admins can sign a person out everywhere from Users.
- **Second approver:** an optional switch on the System page so that whoever starts a bulk push cannot also resume
  or approve it.
- **Audit log:** append-only and hash-chained, with every event also written to the backend log for shipping to a
  SIEM.
- **Encrypted connections:** TLS to collectors, and outside development mode the backend refuses to start without
  TLS to Postgres and Redis. Encryption of data on disk is configured in those stores.

### Command line and GitOps

`opampctl` does from a terminal or a pipeline what the console does. Create a token under Admin → Agent
credentials → Console API tokens, then:

```bash
make build                                             # builds bin/opampctl
export OPAMP_URL=https://opamp.example.com OPAMP_TOKEN=opamp_pat_...
export OPAMP_PROJECT=payments                          # optional: the project to act in

opampctl agents --selector env=prod,team=sre
opampctl configs
opampctl config linux-hosts@3                          # print a version's YAML
opampctl apply -f fleet/ --dry-run                     # show what would change
opampctl apply -f fleet/                               # create or update configs and groups
opampctl push --config linux-hosts --group prod-sre --approve-each-batch --wait
opampctl rollout <id> resume                           # or pause, abort, rollback
opampctl restart <collector-uid>                       # or stop, resume
```

`apply` reads YAML documents so configs and groups can live in Git:

```yaml
kind: Config
name: linux-hosts
description: Host metrics for Linux servers
bodyFile: linux-hosts.collector.yaml      # or inline `body: |`
---
kind: Group
name: prod-sre
selector:
  env: [prod]
  team: [sre]
```

It creates what is missing and adds a config version only when the body changed. It never deletes and never pushes
to collectors, so it is safe to run on every merge; `push` is the deliberate step.

### Not built yet

- Upgrading collectors from the console. The stock Supervisor does not support it yet; re-run the install script
  with a newer version instead.
- Viewing sample telemetry from a collector, and previewing a processor's effect before a push.
- Renewing collectors' own client certificates automatically.
- Kubernetes-native collectors through the OpenTelemetry Operator.
