# API contract

The canonical contract is [`contracts/openapi.yaml`](../contracts/openapi.yaml). All Server routes use `/api/v1`; writes require an `Idempotency-Key` and a configuration version where the operation changes desired state. Mapping updates additionally carry `expected_revision`; stale writes return `409 RESOURCE_REVISION_CONFLICT`. Errors use RFC 9457 Problem Details with a stable `code` and `request_id`.

All successful JSON responses include the generated `request_id` correlation field; response schemas in the OpenAPI contract include it explicitly. The Client Panel exposes a separate local API to its own browser. It proxies only the allowed resources to Server using its in-memory opaque session. It never exposes arbitrary command execution or arbitrary configuration paths.

Important boundaries:

- `/internal/frp/plugin` is loopback-only and fail-closed.
- `/api/v1/config/full` is a signed full snapshot; Client verifies the Ed25519 signature before writing `frpc.toml`.
- Client login also receives the short-lived runtime credential and FRP auth material only for in-memory use by the Client Panel backend; those fields are omitted from admin login and durable signed snapshots.
- `desired_config_version` and `applied_config_version` are intentionally separate.
- `pending_dns`, `pending_certificate`, `pending_router`, and `pending_apply` are not rendered as `active`.
- Cloudflare DNS operations use the provider interface and the HTTP adapter supports token verification, zone discovery, create/update and delete. Token replacement is a two-phase `pending → verified_pending → valid` flow: verification stores capabilities and the domains that would lose Zone access; only an explicit reauthenticated activation switches `users.active_cloudflare_token_version`. The Client local API proxies status/upload/activation/clear to the Server and never caches the Token.
- `POST /api/v1/domains/{id}/dns-action` accepts only `adopt`, `overwrite`, or `cancel`; `adopt` stores `managed_by_panel=false`, while `overwrite` stores `managed_by_panel=true`.
- `POST /api/v1/operations/{id}/retry` requeues failed/canceled Domain operations with their user-scoped resource filter. Admins can inspect and retry all operations.
- Admins can inspect `/api/v1/admin/router/status` and enqueue `/api/v1/admin/router/rebuild`; the reported `adapter=file-last-good` is an explicit local adapter, not evidence of a production TLS Router deployment.

## WebSocket protocol

`GET /api/v1/ws` is available only with a valid Client Panel bearer session and an allowed `Origin`. The connection uses the envelope declared in `contracts/openapi.yaml` and always carries `message_id`, `protocol_version`, `timestamp`, `type`, and `payload`.

The Server sends session invalidation (`session_replaced`, `user_disabled`), configuration invalidation (`config_version_changed`, `force_full_sync`, `mapping_deleted`), and safety events (`shutdown_frpc`). The Client sends a heartbeat every 20 seconds, renews the session idle lease, reconnects with exponential backoff from one second to 60 seconds with jitter, and performs a signed full configuration fetch after a configuration event. WebSocket messages are notifications only; the database version and `/api/v1/config/full` remain authoritative.
