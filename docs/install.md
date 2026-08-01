# Installation and deployment

## Server Panel

The Server Panel is the public control plane. It must run with a persistent local filesystem; do not place SQLite on NFS/SMB.

```bash
export SERVER_LISTEN_ADDR=127.0.0.1:7400
export FRPS_PUBLIC_HOST=frp.example.com
export FRPS_PUBLIC_PORT=7000
export FRP_SERVER_DATA_DIR=/var/lib/frp-panel-server
export FRP_PANEL_ENV=production
export FRP_ADMIN_WEB_DIR=/opt/frp-panel/web/admin/dist
./build/frp-panel-server
```

Production must put HTTPS in front of the control routes and configure an IP SAN, trusted CA, or explicit certificate fingerprint trust for Client Panel users connecting by IP. The initial admin credential is delivered through the protected `initial-admin.txt` file; it is never meant to be a long-lived deployment secret.

## Client Panel

Client Panel defaults to localhost only and stores only non-sensitive local state under its data directory. It does not create a local user or persist a Server Session.

```bash
export CLIENT_LISTEN_ADDR=127.0.0.1:7410
export FRP_CLIENT_DATA_DIR=/var/lib/frp-panel-client
export FRP_PANEL_ENV=production
export FRP_CLIENT_WEB_DIR=/opt/frp-panel/web/client/dist
export FRPC_BINARY=/opt/frp/frpc
./build/frp-panel-client
```

For LAN access, bind a specific LAN address, enable HTTPS, configure allowed CIDRs/Hosts, and validate WebSocket Origin. Never expose the development HTTP listener to the public internet.
