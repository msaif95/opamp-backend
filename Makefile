.PHONY: deps-up deps-down run run-sso build test test-integration lint

# Dev-only defaults; never use these values outside a local machine.
export JWT_SIGNING_KEY ?= dev-only-signing-key-do-not-use-in-prod
export LOCAL_ADMIN_PASSWORD ?= admin
export DEV_MODE ?= true

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

COMPOSE := docker compose -f ../opamp-deploy/compose/docker-compose.yml

deps-up:
	$(COMPOSE) up -d --wait

deps-down:
	$(COMPOSE) down

run:
	go run ./cmd/server

# Dev-only single sign-on against cmd/fakeidp. Start it first: go run ./cmd/fakeidp -groups opamp-admins
run-sso:
	OKTA_ISSUER=http://127.0.0.1:9999 OKTA_CLIENT_ID=opamp-dev OKTA_CLIENT_SECRET=dev \
	OKTA_REDIRECT_URL=http://localhost:5174/api/v1/auth/okta/callback \
	OKTA_ADMIN_GROUPS=opamp-admins OKTA_OPERATOR_GROUPS=sre OKTA_VIEWER_GROUPS=everyone \
	go run ./cmd/server

build:
	go build -ldflags "$(LDFLAGS)" -o bin/opamp-backend ./cmd/server

test:
	go test -race ./...

# Runs every test, including those that need Postgres and Redis (`make deps-up` first).
# Uses a separate `opamp_test` database and Redis database 15, so dev data is untouched.
# -p 1: the integration tests share that database, so packages must not run in parallel.
test-integration:
	docker exec opamp-postgres-1 psql -U opamp -tAc "SELECT 1 FROM pg_database WHERE datname = 'opamp_test'" | grep -q 1 \
		|| docker exec opamp-postgres-1 psql -U opamp -c "CREATE DATABASE opamp_test"
	OPAMP_TEST_POSTGRES_DSN='postgres://opamp:opamp@localhost:5432/opamp_test?sslmode=disable' \
		go test -race -p 1 ./...

lint:
	test -z "$$(gofmt -l .)"
	go vet ./...
