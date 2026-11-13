.PHONY: deps-up deps-down run run-sso build test lint

# Dev-only defaults; never use these values outside a local machine.
export JWT_SIGNING_KEY ?= dev-only-signing-key-do-not-use-in-prod
export LOCAL_ADMIN_PASSWORD ?= admin

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
	go build -o bin/opamp-backend ./cmd/server

test:
	go test -race ./...

lint:
	test -z "$$(gofmt -l .)"
	go vet ./...
