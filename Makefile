.PHONY: deps-up deps-down run build test lint

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

build:
	go build -o bin/opamp-backend ./cmd/server

test:
	go test -race ./...

lint:
	test -z "$$(gofmt -l .)"
	go vet ./...
