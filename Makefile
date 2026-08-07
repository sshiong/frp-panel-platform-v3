SHELL := /bin/bash

GO_CACHE ?= $(shell go env GOCACHE)
GO_MODULE_CACHE ?= $(shell go env GOMODCACHE)
GO_ENV = GOCACHE="$(GO_CACHE)" GOMODCACHE="$(GO_MODULE_CACHE)"
STATICCHECK ?= staticcheck
FRPC_VERIFY_VERSION ?= 0.68.0
SERVER_VERSION ?= 0.1.0
CLIENT_VERSION ?= 0.1.0
MINIMUM_CLIENT_VERSION ?= 0.1.0
LATEST_CLIENT_VERSION ?= $(CLIENT_VERSION)
MINIMUM_FRPC_VERSION ?= 0.68.0

SERVER_LDFLAGS ?= -X github.com/ricardo/frp-panel-platform/server/internal/version.ServerVersion=$(SERVER_VERSION) -X github.com/ricardo/frp-panel-platform/server/internal/version.MinimumClientVersion=$(MINIMUM_CLIENT_VERSION) -X github.com/ricardo/frp-panel-platform/server/internal/version.LatestClientVersion=$(LATEST_CLIENT_VERSION) -X github.com/ricardo/frp-panel-platform/server/internal/version.MinimumFRPCVersion=$(MINIMUM_FRPC_VERSION)
CLIENT_LDFLAGS ?= -X github.com/ricardo/frp-panel-platform/client/internal/version.ClientVersion=$(CLIENT_VERSION)

.PHONY: install-web build test lint accessibility contract migration-check license security fuzz perf fault-injection frpc-verify network-e2e plugin-e2e external-acceptance sbom checksums manifest release-version-check sign release checkpoint key-rotate dev-server dev-client clean

install-web:
	npm ci
	cd web/admin && npm ci
	cd web/client && npm ci

build:
	cd web/admin && npm run build
	cd web/client && npm run build
	./scripts/embed-web-assets.sh web/admin/dist server/internal/httpapi/static/generated
	./scripts/embed-web-assets.sh web/client/dist client/internal/httpapi/static/generated
	mkdir -p build
	cd server && $(GO_ENV) go build -ldflags "$(SERVER_LDFLAGS)" -o ../build/frp-panel-server ./cmd/server
	cd client && $(GO_ENV) go build -ldflags "$(CLIENT_LDFLAGS)" -o ../build/frp-panel-client ./cmd/client

accessibility:
	npm ci
	cd web/admin && npm run build
	cd web/client && npm run build
	npm run test:accessibility

test:
	cd server && $(GO_ENV) go test -race ./...
	cd client && $(GO_ENV) go test -race ./...

lint:
	./scripts/check-format.sh
	ruby scripts/css-token-policy.rb
	cd server && $(GO_ENV) go vet ./...
	cd client && $(GO_ENV) go vet ./...
	@command -v $(STATICCHECK) >/dev/null || (echo "staticcheck is required for lint; install honnef.co/go/tools/cmd/staticcheck" >&2; exit 1)
	cd server && $(GO_ENV) $(STATICCHECK) ./...
	cd client && $(GO_ENV) $(STATICCHECK) ./...
	cd web/admin && npm run typecheck
	cd web/admin && npm run lint
	cd web/admin && npm run test:policy
	cd web/client && npm run typecheck
	cd web/client && npm run lint
	cd web/client && npm run test:policy

contract:
	npm run generate:contracts
	ruby scripts/acceptance-matrix-policy.rb
	ruby scripts/validate-openapi.rb
	ruby scripts/test-external-acceptance.rb
	ruby scripts/release-version-policy.rb
	cd server && $(GO_ENV) go test ./internal/httpapi -run '^TestHTTPContract' -count=1

migration-check:
	cd server && $(GO_ENV) go test ./internal/db -run '^TestMigration' -count=1

license:
	ruby scripts/license-policy.rb

security:
	ruby scripts/secret-scan.rb

fuzz:
	cd server && $(GO_ENV) go test -run='^$$' -fuzz=FuzzNormalizeDomain -fuzztime=$${FUZZ_TIME:-15s} ./internal/service
	cd server && $(GO_ENV) go test -run='^$$' -fuzz=FuzzSnapshotRoundTrip -fuzztime=$${FUZZ_TIME:-15s} ./internal/router
	cd client && $(GO_ENV) go test -run='^$$' -fuzz=FuzzNormalizeServerURL -fuzztime=$${FUZZ_TIME:-15s} ./internal/security

perf:
	cd server && $(GO_ENV) FRP_PERF=1 FRP_PERF_SCALE=1 go test -v -run '^TestPerformance(Baseline|Scale|SessionReplacement)$$' -count=1 ./internal/httpapi
	cd client && $(GO_ENV) FRP_PERF_SCALE=1 go test -v -run '^TestPerformanceConfigSubmitToClientApply$$' -count=1 ./internal/app

fault-injection:
	./scripts/linux-fault-injection.sh

frpc-verify:
	@test -n "$(FRPC_VERIFY_BINARY)" || (echo "FRPC_VERIFY_BINARY is required" >&2; exit 1)
	cd client && $(GO_ENV) FRPC_VERIFY_BINARY="$(abspath $(FRPC_VERIFY_BINARY))" FRPC_VERIFY_VERSION="$(FRPC_VERIFY_VERSION)" go test -race ./internal/supervisor -run '^TestRenderTOMLIsAcceptedByFixedFRPCWhenConfigured$$'

network-e2e:
	./scripts/frp-network-e2e.sh

plugin-e2e:
	@test -n "$(FRP_E2E_FRPS_BINARY)" || (echo "FRP_E2E_FRPS_BINARY is required" >&2; exit 1)
	@test -n "$(FRP_E2E_FRPC_BINARY)" || (echo "FRP_E2E_FRPC_BINARY is required" >&2; exit 1)
	cd server && $(GO_ENV) FRP_PLUGIN_E2E=1 FRP_E2E_FRPS_BINARY="$(abspath $(FRP_E2E_FRPS_BINARY))" FRP_E2E_FRPC_BINARY="$(abspath $(FRP_E2E_FRPC_BINARY))" go test -race ./internal/httpapi -run '^TestFRPPluginNetworkE2E$$' -count=1 -v

external-acceptance:
	ruby scripts/external-acceptance.rb

sbom: build
	ruby scripts/generate-sbom.rb

checksums: build
	shasum -a 256 build/frp-panel-server build/frp-panel-client > build/SHA256SUMS
	@if test -f build/frps; then shasum -a 256 build/frps build/frpc >> build/SHA256SUMS; fi

release-version-check:
	ruby scripts/release-version-policy.rb

manifest: build release-version-check
	ruby scripts/generate-release-manifest.rb

sign: checksums sbom manifest
	@test -n "$(COSIGN_KEY)" || (echo "COSIGN_KEY is required for release signing" >&2; exit 1)
	@command -v cosign >/dev/null || (echo "cosign is required for release signing" >&2; exit 1)
	@for artifact in build/frp-panel-server build/frp-panel-client build/frps build/frpc build/SHA256SUMS build/sbom.spdx.json build/release-manifest.json; do \
		cosign sign-blob --key "$(COSIGN_KEY)" --output-signature "$${artifact}.sig" "$${artifact}"; \
		cosign verify-blob --key "$(COSIGN_KEY)" --signature "$${artifact}.sig" "$${artifact}"; \
	done

release: sign

checkpoint:
	cd server && $(GO_ENV) go run ./cmd/db-checkpoint -db "$${FRP_SERVER_DB:-./data/server.db}"

key-rotate:
	cd server && $(GO_ENV) go run ./cmd/key-rotate

dev-server:
	cd server && $(GO_ENV) go run ./cmd/server

dev-client:
	cd client && $(GO_ENV) go run ./cmd/client

clean:
	rm -rf web/admin/dist web/client/dist server/bin client/bin
	find server/internal/httpapi/static/generated -mindepth 1 -maxdepth 1 ! -name .gitkeep -exec rm -rf {} +
	find client/internal/httpapi/static/generated -mindepth 1 -maxdepth 1 ! -name .gitkeep -exec rm -rf {} +
