# 部署配置参考

## Server

| 变量 | 作用 | 生产要求 |
|---|---|---|
| `SERVER_LISTEN_ADDR` | Server Panel API/UI 监听地址 | 由 HTTPS 证书保护 |
| `SERVER_TLS_CERT_FILE` / `SERVER_TLS_KEY_FILE` | Server Panel TLS | `FRP_PANEL_ENV=production` 必填 |
| `FRP_SERVER_DATA_DIR` / `FRP_SERVER_DB` | SQLite WAL 与秘密数据目录 | 本地持久磁盘，权限 0700 |
| `FRPS_PUBLIC_HOST` / `FRPS_PUBLIC_PORT` | 下发给 Client 的公网地址 | 不得填写 bind 地址 |
| `FRPS_BINARY` / `FRPS_BINARY_SHA256` / `FRPS_CONFIG_PATH` | 固定 FRPS 托管与启动前校验 | 三项成组配置 |
| `FRPS_TRANSPORT_SECRET_FILE` | FRPS native tokenSource 文件 | 权限 0600，不进入 API |
| `FRP_ALLOWED_ORIGINS` | 管理面板浏览器 Origin | 生产只允许 HTTPS Origin |
| `FRP_ROUTER_LISTEN_ADDR` | DB-free Router 监听地址 | 非回环监听必须启用 Router TLS |
| `FRP_ROUTER_CONTROL_HOSTS` | Control Route Host 列表 | 与业务 Host 分离 |
| `FRP_ACME_ENABLED` / `FRP_ACME_EMAIL` | ACME DNS-01 Provider | 先用 Staging 验证 |

## Client 与局域网 HTTPS

| 变量 | 作用 | 生产要求 |
|---|---|---|
| `CLIENT_LISTEN_ADDR` | Client Panel 监听地址 | 默认回环；LAN 需绑定具体地址 |
| `CLIENT_ALLOW_LAN` | 是否允许 LAN 访问 | 必须同时配置 CIDR、Host 和证书 |
| `CLIENT_ALLOWED_CIDRS` / `CLIENT_ALLOWED_HOST` | LAN 来源边界 | 拒绝任意公网来源 |
| `CLIENT_TLS_CERT_FILE` / `CLIENT_TLS_KEY_FILE` | Client LAN HTTPS | LAN 模式必填 |
| `FRP_CLIENT_DATA_DIR` | last-good 与受保护运行时文件 | 权限 0700，秘密文件 0600 |
| `FRPC_BINARY` / `FRPC_BINARY_SHA256` / `FRPC_VERSION` | 固定 FRPC Supervisor | 版本低于兼容下限时拒绝应用 |

完整示例见 [`install.md`](install.md)；局域网 Client 不得暴露开发 HTTP
监听器到公网。
