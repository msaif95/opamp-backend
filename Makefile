.PHONY: deps-up deps-down run run-sso build cli-dist test test-integration lint

# Dev-only defaults; never use these values outside a local machine.
export JWT_SIGNING_KEY ?= dev-only-signing-key-do-not-use-in-prod
export LOCAL_ADMIN_PASSWORD ?= admin
export DEV_MODE ?= true
export SECRETS_ENCRYPTION_KEY ?= dev-only-secrets-key-do-not-use-in-prod

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
	go build -ldflags "$(LDFLAGS)" -o bin/opampctl ./cmd/opampctl

# opampctl for every platform the console offers to download, in bin/dist
# (where the dev server looks; the image build does the same into /opampctl).
CLI_PLATFORMS := linux_amd64 linux_arm64 darwin_amd64 darwin_arm64 windows_amd64
cli-dist:
	@for p in $(CLI_PLATFORMS); do \
		os=$${p%_*}; arch=$${p#*_}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "opampctl $$p"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "-s -w $(LDFLAGS)" -o bin/dist/opampctl_$$p$$ext ./cmd/opampctl || exit 1; \
	done

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
