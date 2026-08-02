# Security notes

- Passwords use Argon2id with a per-password salt and versioned encoded parameters.
- Server Sessions are opaque random values; only their SHA-256 hashes are stored. Browser storage never receives a Server Session.
- Cloudflare Tokens are encrypted with AES-256-GCM using a purpose-specific AAD. They are never returned by API responses or written to logs.
- Config snapshots use a distinct Ed25519 signing key. Certificate wrapping, Router snapshot HMAC, Session handling, and backup password derivation use separate purposes.
- Server startup creates `router-snapshot.key` and `certificate-wrapping.key` separately from `server-master.key` and the Ed25519 signing key. Certificate private keys use only the certificate wrapping key; Router snapshots use only the Router HMAC key.
- Encryption keys use a versioned key ring. `make key-rotate` (with the Server process drained) creates the next master and certificate-wrapping versions, re-wraps FRP credentials, Cloudflare Tokens, and certificate private keys in one SQLite transaction, and retains old versions for restart/rollback compatibility. The command prints row counts; release operators must still complete the environment rotation rehearsal and sign-off.
- Client local browser sessions are in memory, `HttpOnly`, `SameSite=Strict`, and CSRF-protected for writes.
- Server admin cookie sessions are bound to a per-session CSRF hash; unsafe browser requests require the matching `frp_server_csrf` token. Bearer-only Client Panel calls do not rely on cookies.
- Sensitive Server writes (Cloudflare, FRP credential rotation, user lifecycle, Router rebuild and encrypted backup) use a short-lived reauthentication ticket bound to the authenticated user and session generation; only its hash is stored, and direct current-password proofs are not accepted by browser routes when a ticket is required.
- Client LAN exposure is opt-in: a concrete non-loopback bind address requires `CLIENT_ALLOW_LAN=true`, a CIDR allowlist, Host allowlist, and a TLS certificate/key; the default allowlist is loopback-only. Login and API request boundaries have bounded in-memory rate limits.
- Client-to-Server and Server-to-Cloudflare/ACME HTTP clients do not follow redirects, preventing bearer or provider authorization material from being replayed at an unexpected endpoint.
- Runtime FRP secrets are outside the durable config snapshot and are cleared on logout, session replacement, server switch, and client shutdown.
- Client login receives the FRP username, per-user FRP secret, deployment-scoped FRPS transport secret, and session runtime credential only through the Client Panel backend. The Supervisor writes 0600 runtime secret files and the fixed FRPC binary hash is checked before verify/start; it uses `auth.tokenSource.file` for FRP versions that support file-backed native auth.
- FRPS Plugin checks user, per-user FRP secret, session, generation, runtime credential, mapping ownership, proxy type/name, revision, port, and hostname on every operation.
- ACME without an explicitly configured provider remains `pending_certificate`/blocked; no self-signed or placeholder certificate is promoted to `valid`.
- `/internal/frp/plugin` is additionally guarded by a loopback-only HTTP middleware; binding the public control server does not make the internal authorization hook remotely callable.
- The development Supervisor simulation is explicit (`mode=simulated`); it never claims that a real FRPC binary established a tunnel.
