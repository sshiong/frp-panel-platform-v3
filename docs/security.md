# Security notes

- Passwords use Argon2id with a per-password salt and versioned encoded parameters.
- Server Sessions are opaque random values; only their SHA-256 hashes are stored. Browser storage never receives a Server Session.
- Cloudflare Tokens are encrypted with AES-256-GCM using a purpose-specific AAD. They are never returned by API responses or written to logs.
- Config snapshots use a distinct Ed25519 signing key. Certificate wrapping, Router snapshot HMAC, Session handling, and backup password derivation use separate purposes.
- Client local browser sessions are in memory, `HttpOnly`, `SameSite=Strict`, and CSRF-protected for writes.
- Runtime FRP secrets are outside the durable config snapshot and are cleared on logout, session replacement, server switch, and client shutdown.
- FRPS Plugin checks user, session, generation, runtime credential, mapping ownership, revision, port, and hostname on every operation.
- `/internal/frp/plugin` is additionally guarded by a loopback-only HTTP middleware; binding the public control server does not make the internal authorization hook remotely callable.
- The development Supervisor simulation is explicit (`mode=simulated`); it never claims that a real FRPC binary established a tunnel.
