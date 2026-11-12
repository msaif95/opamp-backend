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
  `opamp:agent-events` pub/sub), `internal/auth` (agent mTLS/API key, human sessions + RBAC), `internal/api`
  (REST), `internal/events` (SSE fan-out).
- Deployment (compose, Helm chart) lives in `../opamp-deploy`; only the `Dockerfile` stays here.
- PKI is cert-manager with a self-signed CA (`../opamp-deploy/helm/opamp/templates/certificates.yaml`); the backend
  reads the server cert and client CA bundle from the mounted Secret. Any client cert chaining to that CA is
  accepted (no per-cert enrollment); revocation is by fingerprint in the `credentials` table.
- Dependencies: pin versions published at least 7 days ago.
