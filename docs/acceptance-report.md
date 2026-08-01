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
- Browser screenshots: [`admin-overview.png`](../output/playwright/admin-overview.png), [`client-tunnels.png`](../output/playwright/client-tunnels.png), [`client-domains.png`](../output/playwright/client-domains.png).

## Not signed off yet

Real FRPS Plugin Login/NewProxy/WorkConn E2E, Cloudflare DNS conflict/adoption and timeout compensation, ACME DNS-01, Router SNI/Host proxying and hot reload, encrypted restore drill, fuzz/SAST/SCA/secret scan, performance baseline, SBOM/signing, and a production HTTPS deployment remain release gates.
