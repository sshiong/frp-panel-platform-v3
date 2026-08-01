# Security notes

- Passwords use Argon2id with a per-password salt and versioned encoded parameters.
- Server Sessions are opaque random values; only their SHA-256 hashes are stored. Browser storage never receives a Server Session.
- Cloudflare Tokens are encrypted with AES-256-GCM using a purpose-specific AAD. They are never returned by API responses or written to logs.
- Config snapshots use a distinct Ed25519 signing key. Certificate wrapping, Router snapshot HMAC, Session handling, and backup password derivation use separate purposes.
- Server startup creates `router-snapshot.key` and `certificate-wrapping.key` separately from `server-master.key` and the Ed25519 signing key. Certificate private keys use only the certificate wrapping key; Router snapshots use only the Router HMAC key.
- Client local browser sessions are in memory, `HttpOnly`, `SameSite=Strict`, and CSRF-protected for writes.
- Runtime FRP secrets are outside the durable config snapshot and are cleared on logout, session replacement, server switch, and client shutdown.
- Client login receives the FRP username, FRP secret, and session runtime credential only through the Client Panel backend; they remain in memory and are used to render a 0600 FRPC config. The fixed FRPC binary hash is checked before verify/start.
- FRPS Plugin checks user, session, generation, runtime credential, mapping ownership, revision, port, and hostname on every operation.
- ACME without an explicitly configured provider remains `pending_certificate`/blocked; no self-signed or placeholder certificate is promoted to `valid`.
- `/internal/frp/plugin` is additionally guarded by a loopback-only HTTP middleware; binding the public control server does not make the internal authorization hook remotely callable.
- The development Supervisor simulation is explicit (`mode=simulated`); it never claims that a real FRPC binary established a tunnel.
