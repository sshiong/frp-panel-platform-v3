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
export FRPS_TRANSPORT_SECRET_FILE=/var/lib/frp-panel-server/frps-transport.secret
export FRPS_VHOST_HTTP_PORT=8080
export FRP_ROUTER_CONTROL_HOSTS=panel.example.com
export FRP_ROUTER_LISTEN_ADDR=127.0.0.1:7443
export FRP_ROUTER_TLS_ENABLED=false
export FRP_ACME_ENABLED=false
export FRP_SERVER_DATA_DIR=/var/lib/frp-panel-server
export FRP_PANEL_ENV=production
export FRP_ADMIN_WEB_DIR=/opt/frp-panel/web/admin/dist
./build/frp-panel-server
```

When `FRPS_BINARY`, `FRPS_BINARY_SHA256`, and `FRPS_CONFIG_PATH` are all set, Server verifies the fixed FRPS artifact before starting it and stops it with the control process. Server creates or validates `FRPS_TRANSPORT_SECRET_FILE` with mode 0600; the same file must be referenced by FRPS `auth.tokenSource.file.path`. Configure the FRPS HTTP plugin for the loopback-only `POST /internal/frp/plugin` endpoint; the plugin remains fail-closed when the Server is unavailable. See [FRP Plugin E2E](frp-plugin-e2e.md) for the exact `httpPlugins` block and fixed-version checks.

The Client Panel keeps its Server bearer session in memory and maintains `/api/v1/ws` with an allowed local Origin. It sends heartbeats, reconnects with bounded exponential backoff and jitter, and performs a signed full sync after a missed-notification recovery event. Session replacement, logout, or user disable stops FRPC and removes runtime secret files.

Production must put HTTPS in front of the control routes and configure an IP SAN, trusted CA, or explicit certificate fingerprint trust for Client Panel users connecting by IP. The initial admin credential is delivered through the protected `initial-admin.txt` file; it is never meant to be a long-lived deployment secret.

Router snapshots are written to `FRP_ROUTER_SNAPSHOT_DIR` (default `data/router`) and contain separate `control_routes` and `business_routes`. The Server can run the DB-free Router runtime with `FRP_ROUTER_LISTEN_ADDR`; it watches the atomically replaced `last-good.json`, verifies schema/hash/HMAC, and retains the previous in-memory route table on invalid input. Set `FRP_ROUTER_TLS_ENABLED=true` to terminate TLS in this process: the control side decrypts validated ACME private keys, passes only an in-memory certificate set to Router, polls for atomic certificate replacement, and rejects unknown SNI. Keep it disabled when an independently managed TLS/SNI proxy terminates before the Router. `FRP_ACME_ENABLED=false` intentionally leaves `auto_certificate` and `cloudflare_proxy` domains in `pending_certificate` until a mature ACME DNS-01 provider is configured and staged.

## Client Panel

Client Panel defaults to localhost only and stores only non-sensitive local state under its data directory. It does not create a local user or persist a Server Session.

```bash
export CLIENT_LISTEN_ADDR=127.0.0.1:7410
export CLIENT_ALLOWED_HOST=127.0.0.1,localhost,[::1]
export CLIENT_ALLOWED_CIDRS=127.0.0.0/8,::1/128
export CLIENT_ALLOW_LAN=false
export CLIENT_TLS_CERT_FILE=/etc/frp-panel-client/tls.crt
export CLIENT_TLS_KEY_FILE=/etc/frp-panel-client/tls.key
export FRP_CLIENT_DATA_DIR=/var/lib/frp-panel-client
export FRP_PANEL_ENV=production
export FRP_CLIENT_WEB_DIR=/opt/frp-panel/web/client/dist
export FRPC_BINARY=/opt/frp/frpc
export FRPC_BINARY_SHA256='sha256-from-release-manifest'
export FRPC_VERSION=0.68.0
./build/frp-panel-client
```

For LAN access, bind a specific LAN address (never `0.0.0.0`/`::`), set `CLIENT_ALLOW_LAN=true`, configure `CLIENT_ALLOWED_CIDRS` and `CLIENT_ALLOWED_HOST`, and provide `CLIENT_TLS_CERT_FILE`/`CLIENT_TLS_KEY_FILE`. The Client process refuses to start when those conditions are incomplete. Never expose the development HTTP listener to the public internet.
