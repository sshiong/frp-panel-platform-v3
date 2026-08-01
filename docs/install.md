# Installation and deployment

## Server Panel

The Server Panel is the public control plane. It must run with a persistent local filesystem; do not place SQLite on NFS/SMB.

```bash
export SERVER_LISTEN_ADDR=127.0.0.1:7400
export FRPS_PUBLIC_HOST=frp.example.com
export FRPS_PUBLIC_PORT=7000
export FRPS_BINARY=/opt/frp/frps
export FRPS_BINARY_SHA256='sha256-from-release-manifest'
export FRPS_CONFIG_PATH=/etc/frp/frps.toml
export FRPS_VHOST_HTTP_PORT=8080
export FRP_ROUTER_CONTROL_HOSTS=panel.example.com
export FRP_ROUTER_LISTEN_ADDR=127.0.0.1:7443
export FRP_ACME_ENABLED=false
export FRP_SERVER_DATA_DIR=/var/lib/frp-panel-server
export FRP_PANEL_ENV=production
export FRP_ADMIN_WEB_DIR=/opt/frp-panel/web/admin/dist
./build/frp-panel-server
```

When `FRPS_BINARY`, `FRPS_BINARY_SHA256`, and `FRPS_CONFIG_PATH` are all set, Server verifies the fixed FRPS artifact before starting it and stops it with the control process. The FRPS HTTP plugin should target the loopback-only `POST /internal/frp/plugin` endpoint; the plugin remains fail-closed when the Server is unavailable.

The Client Panel keeps its Server bearer session in memory and maintains `/api/v1/ws` with an allowed local Origin. It sends heartbeats, reconnects with bounded exponential backoff and jitter, and performs a signed full sync after a missed-notification recovery event. Session replacement, logout, or user disable stops FRPC and removes runtime secret files.

Production must put HTTPS in front of the control routes and configure an IP SAN, trusted CA, or explicit certificate fingerprint trust for Client Panel users connecting by IP. The initial admin credential is delivered through the protected `initial-admin.txt` file; it is never meant to be a long-lived deployment secret.

Router snapshots are written to `FRP_ROUTER_SNAPSHOT_DIR` (default `data/router`) and contain separate `control_routes` and `business_routes`. The Server can run the DB-free Router HTTP runtime with `FRP_ROUTER_LISTEN_ADDR`; it watches the atomically replaced `last-good.json`, verifies schema/hash/HMAC, and retains the previous in-memory route table on invalid input. Put a production TLS/SNI termination layer in front of this listener or supply a certificate-aware Router adapter before exposing it publicly. `FRP_ACME_ENABLED=false` intentionally leaves `auto_certificate` and `cloudflare_proxy` domains in `pending_certificate` until a mature ACME DNS-01 provider is configured and staged.

## Client Panel

Client Panel defaults to localhost only and stores only non-sensitive local state under its data directory. It does not create a local user or persist a Server Session.

```bash
export CLIENT_LISTEN_ADDR=127.0.0.1:7410
export FRP_CLIENT_DATA_DIR=/var/lib/frp-panel-client
export FRP_PANEL_ENV=production
export FRP_CLIENT_WEB_DIR=/opt/frp-panel/web/client/dist
export FRPC_BINARY=/opt/frp/frpc
export FRPC_BINARY_SHA256='sha256-from-release-manifest'
./build/frp-panel-client
```

For LAN access, bind a specific LAN address, enable HTTPS, configure allowed CIDRs/Hosts, and validate WebSocket Origin. Never expose the development HTTP listener to the public internet.
