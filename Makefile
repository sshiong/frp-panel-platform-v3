SHELL := /bin/zsh

GO_CACHE ?= /private/tmp/frp-cf-gocache
GO_MODULE_CACHE ?= /private/tmp/frp-cf-gomodcache
GO_ENV = GOCACHE=$(GO_CACHE) GOMODCACHE=$(GO_MODULE_CACHE)

.PHONY: install-web build test lint dev-server dev-client clean

install-web:
	cd web/admin && npm install
	cd web/client && npm install

build:
	cd web/admin && npm run build
	cd web/client && npm run build
	mkdir -p build
	cd server && $(GO_ENV) go build -o ../build/frp-panel-server ./cmd/server
	cd server && $(GO_ENV) go build -o ../build/frp-panel-backup-restore ./cmd/backup-restore
	cd client && $(GO_ENV) go build -o ../build/frp-panel-client ./cmd/client

test:
	cd server && $(GO_ENV) go test ./...
	cd client && $(GO_ENV) go test ./...

lint:
	cd server && $(GO_ENV) go fmt ./... && $(GO_ENV) go vet ./...
	cd client && $(GO_ENV) go fmt ./... && $(GO_ENV) go vet ./...
	cd web/admin && npm run typecheck
	cd web/client && npm run typecheck

dev-server:
	cd server && $(GO_ENV) go run ./cmd/server

dev-client:
	cd client && $(GO_ENV) go run ./cmd/client

clean:
	rm -rf web/admin/dist web/client/dist server/bin client/bin
