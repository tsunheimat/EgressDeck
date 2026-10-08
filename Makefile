.PHONY: all build build-go build-web test test-go test-web lint fmt fmt-check check schema-validate docker-build

GO ?= go
WEB_DIR := apps/web
WEB_PM ?= npm

all: check build

build: build-go build-web

build-go:
	$(GO) build ./...

build-web:
	$(WEB_PM) --prefix $(WEB_DIR) run build

test: test-go test-web

test-go:
	$(GO) test ./...

test-web:
	$(WEB_PM) --prefix $(WEB_DIR) test -- --run

fmt:
	$(GO) fmt ./...

fmt-check:
	@test -z "$$(gofmt -l $$(find cmd internal tests -name '*.go' -type f))"

lint:
	$(GO) vet ./...
	$(WEB_PM) --prefix $(WEB_DIR) run typecheck

check: fmt-check lint test

schema-validate:
	@test -n "$$DATABASE_URL" || (echo "Set DATABASE_URL to an isolated disposable PostgreSQL database" >&2; exit 1)
	psql "$$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/schema.sql
	psql "$$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/schema.sql

docker-build:
	docker build -f deploy/compose/Dockerfile --tag egressdeck/controller:dev .
