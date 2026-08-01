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
- Browser screenshots: [`admin-overview.png`](../output/playwright/admin-overview.png), [`client-tunnels.png`](../output/playwright/client-tunnels.png), [`client-domains.png`](../output/playwright/client-domains.png).

## Not signed off yet

Real FRPS Plugin Login/NewProxy/WorkConn E2E, Cloudflare Sandbox timeout compensation, ACME Staging against a real CA, Router TLS SNI certificate hot reload, encrypted restore drill, fuzz/SAST/SCA/secret scan, performance baseline, SBOM/signing, and a production HTTPS deployment remain release gates. Local tests never mark those external integrations active.
