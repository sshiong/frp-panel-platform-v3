# API contract

The canonical contract is [`contracts/openapi.yaml`](../contracts/openapi.yaml). All Server routes use `/api/v1`; writes require an `Idempotency-Key` and a configuration version where the operation changes desired state. Errors use RFC 9457 Problem Details with a stable `code` and `request_id`.

The Client Panel exposes a separate local API to its own browser. It proxies only the allowed resources to Server using its in-memory opaque session. It never exposes arbitrary command execution or arbitrary configuration paths.

Important boundaries:

- `/internal/frp/plugin` is loopback-only and fail-closed.
- `/api/v1/config/full` is a signed full snapshot; Client verifies the Ed25519 signature before writing `frpc.toml`.
- `desired_config_version` and `applied_config_version` are intentionally separate.
- `pending_dns`, `pending_certificate`, `pending_router`, and `pending_apply` are not rendered as `active`.
- Cloudflare DNS operations use the provider interface and the HTTP adapter supports token verification, zone discovery, create/update and delete. The Service keeps these operations pending until a configured provider job completes; a successful token verification alone is not proof that a DNS record is active.
