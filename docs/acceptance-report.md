# Development acceptance report

This report records evidence available in the local development environment. It is intentionally not a production-release sign-off: real FRPS/FRPC, Cloudflare Sandbox, ACME Staging, TLS termination, security scanners, SBOM and signing still require their external environments.

## Verified locally

- Separate Server and Client Go modules compile and test independently.
- Two independent Vue 3 + TypeScript + Vite + Element Plus apps build successfully.
- Admin login does not render a Server address field; Client login does not render admin or device-registration fields.
- Client Panel exposes separate Mapping and Domain Binding surfaces; the Domain Binding view shows normalized IDNA names and keeps `pending_dns` visibly distinct from `active`.
- Argon2id password hashing, first-login password change and user creation work.
- Second Client login returns `SESSION_REPLACED` for the old opaque session.
- TCP Mapping auto-allocation reserves port `6000`; TCP/UDP conflict returns upstream HTTP 409.
- Desired/applied config versions converge after Client verifies the signed snapshot and applies through Supervisor.
- HTTP Mapping and IDNA/Punycode Domain Binding creation produce explicit `pending_dns` states.
- SQLite WAL encrypted backup endpoint generated an `.fppb` package in a temporary test data directory.
- FPPB1 decode, password rejection, SQLite integrity validation, and atomic restore with a recoverable pre-restore filename pass unit tests.
- Cloudflare HTTP Provider unit tests cover bearer auth, zone-record discovery, create, update, and delete without requiring a live network.
- Durable Job Worker tests cover deduplication, lease heartbeat, expired-lease reclaim, retry backoff, Cloudflare token verification, DNS conflict handling and Router snapshot promotion.
- Mapping updates enforce `expected_revision` and persist PUT idempotency records; long-running jobs renew their leases, Cloudflare 401/403 errors are classified as permission failures, and ACME renewal/deletion jobs are re-seeded after restart.
- Domain deletion removes the Router route after the Client acknowledgement and only deletes Cloudflare DNS when `managed_by_panel=true`; adopted unmanaged records remain external.
- Router tests cover HMAC/hash rejection, last-good retention, control/business Host routing, unknown Host 404 and offline upstream 502. Router runtime has no database dependency.
- ACME DNS-01 provider is implemented with the Go ACME client, encrypted account material, TXT propagation polling and cleanup; it remains disabled unless an operator supplies a staging/production directory, email and verified Cloudflare Token.
- FRPS fixed-binary process tests cover SHA-256 verification, PID ownership and controlled stop.
- Server/Client WebSocket tests cover the v1 envelope boundary, heartbeat session renewal, remote disable cleanup, bounded exponential backoff with jitter, and signed full-sync recovery after configuration notifications.
- Pending quotas cover mappings, pending port leases, domain operations and certificate jobs; metrics expose resource counts, job backlog, Router lag and SQLite WAL size without user-input labels.
- Mapping deletion retains domain bindings until managed DNS cleanup succeeds; a focused service test proves managed records are deleted and mapping operations only finalize after compensation. Port rotation proves the old lease is released only after the new revision applies.
- Mapping toggle, Domain deletion and DNS conflict actions persist request hashes under the authenticated session generation; retries return the original outcome and conflicting bodies return `IDEMPOTENCY_KEY_REUSED`. Toggle also enforces optional expected config/revision values.
- Formal FPPB1 backup tests include protected data-directory files, per-entry checksums, wrong-password rejection, SQLite integrity validation, session/runtime credential revocation and atomic restore.
- `scripts/validate-openapi.rb` validates OpenAPI 3.1 paths, unique operation IDs and the WebSocket metadata; `make sbom` emits a local SPDX inventory and `make checksums` emits SHA-256 checksums for the three local artifacts. Artifact signing and third-party scanner attestations remain release work.
- Final local regression: Server and Client `go test -race ./...`, repository `make test lint build contract sbom checksums`, whitespace validation and secret-pattern scan pass. Vite reports a non-blocking warning for the current JavaScript chunk size.
- Browser screenshots: [`admin-overview.png`](../output/playwright/admin-overview.png), [`client-tunnels.png`](../output/playwright/client-tunnels.png), [`client-domains.png`](../output/playwright/client-domains.png).

## Not signed off yet

Real FRPS/FRPC Plugin Login/NewProxy/WorkConn E2E, Cloudflare Sandbox timeout compensation, ACME Staging against a real CA, Router TLS SNI certificate hot reload, a clean-host disaster restore drill, implementation-level API Contract tests, fuzz/SAST/SCA/secret scan, performance baseline, SBOM/signing, and a production HTTPS deployment remain release gates. Local tests never mark those external integrations active.
