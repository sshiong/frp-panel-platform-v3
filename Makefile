SHELL := /bin/zsh

GO_CACHE ?= /private/tmp/frp-cf-gocache
GO_MODULE_CACHE ?= /private/tmp/frp-cf-gomodcache
GO_ENV = GOCACHE=$(GO_CACHE) GOMODCACHE=$(GO_MODULE_CACHE)
STATICCHECK ?= staticcheck
FRPC_VERIFY_VERSION ?= 0.68.0

.PHONY: install-web build test lint contract security fuzz perf frpc-verify network-e2e plugin-e2e sbom checksums manifest sign release checkpoint dev-server dev-client clean

install-web:
	cd web/admin && npm install
	cd web/client && npm install

build:
	cd web/admin && npm run build
	cd web/client && npm run build
	mkdir -p build
	cd server && $(GO_ENV) go build -o ../build/frp-panel-server ./cmd/server
	cd client && $(GO_ENV) go build -o ../build/frp-panel-client ./cmd/client

test:
	cd server && $(GO_ENV) go test -race ./...
	cd client && $(GO_ENV) go test -race ./...

lint:
	./scripts/check-format.sh
	cd server && $(GO_ENV) go vet ./...
	cd client && $(GO_ENV) go vet ./...
	@command -v $(STATICCHECK) >/dev/null || (echo "staticcheck is required for lint; install honnef.co/go/tools/cmd/staticcheck" >&2; exit 1)
	cd server && $(GO_ENV) $(STATICCHECK) ./...
	cd client && $(GO_ENV) $(STATICCHECK) ./...
	cd web/admin && npm run typecheck
	cd web/admin && npm run test:policy
	cd web/client && npm run typecheck
	cd web/client && npm run test:policy

contract:
	ruby scripts/validate-openapi.rb

security:
	ruby scripts/secret-scan.rb

fuzz:
	cd server && $(GO_ENV) go test -run='^$$' -fuzz=FuzzNormalizeDomain -fuzztime=$${FUZZ_TIME:-15s} ./internal/service
	cd server && $(GO_ENV) go test -run='^$$' -fuzz=FuzzSnapshotRoundTrip -fuzztime=$${FUZZ_TIME:-15s} ./internal/router
	cd client && $(GO_ENV) go test -run='^$$' -fuzz=FuzzNormalizeServerURL -fuzztime=$${FUZZ_TIME:-15s} ./internal/security

perf:
	cd server && $(GO_ENV) FRP_PERF=1 FRP_PERF_SCALE=1 go test -run '^TestPerformance(Baseline|Scale|SessionReplacement)$$' -count=1 ./internal/httpapi
	cd client && $(GO_ENV) FRP_PERF_SCALE=1 go test -run '^TestPerformanceConfigSubmitToClientApply$$' -count=1 ./internal/app

frpc-verify:
	@test -n "$(FRPC_VERIFY_BINARY)" || (echo "FRPC_VERIFY_BINARY is required" >&2; exit 1)
	cd client && $(GO_ENV) FRPC_VERIFY_BINARY="$(FRPC_VERIFY_BINARY)" FRPC_VERIFY_VERSION="$(FRPC_VERIFY_VERSION)" go test -race ./internal/supervisor -run '^TestRenderTOMLIsAcceptedByFixedFRPCWhenConfigured$$'

network-e2e:
	./scripts/frp-network-e2e.sh

plugin-e2e:
	@test -n "$(FRP_E2E_FRPS_BINARY)" || (echo "FRP_E2E_FRPS_BINARY is required" >&2; exit 1)
	@test -n "$(FRP_E2E_FRPC_BINARY)" || (echo "FRP_E2E_FRPC_BINARY is required" >&2; exit 1)
	cd server && $(GO_ENV) FRP_PLUGIN_E2E=1 FRP_E2E_FRPS_BINARY="$(FRP_E2E_FRPS_BINARY)" FRP_E2E_FRPC_BINARY="$(FRP_E2E_FRPC_BINARY)" go test -race ./internal/httpapi -run '^TestFRPPluginNetworkE2E$$' -count=1 -v

sbom: build
	ruby scripts/generate-sbom.rb

checksums: build
	shasum -a 256 build/frp-panel-server build/frp-panel-client > build/SHA256SUMS
	@if test -f build/frps; then shasum -a 256 build/frps build/frpc >> build/SHA256SUMS; fi

manifest: build
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

dev-server:
	cd server && $(GO_ENV) go run ./cmd/server

dev-client:
	cd client && $(GO_ENV) go run ./cmd/client

clean:
	rm -rf web/admin/dist web/client/dist server/bin client/bin
