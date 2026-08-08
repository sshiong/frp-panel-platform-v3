# FRP Panel Platform v3

公开仓库：[github.com/sshiong/frp-panel-platform-v3](https://github.com/sshiong/frp-panel-platform-v3)

一个单仓库、双发行物的 FRP 多用户云隧道管理平台：

- `server/`：公网 Server Panel，负责认证、资源权威、端口租约、配置版本、审计、Cloudflare/Router/Job 边界。
- `client/`：本地 Client Panel，负责用户登录代理、单活动本地浏览器会话、FRPC Supervisor、原子配置与回滚。
- `contracts/`：版本化 API/OpenAPI 与共享协议定义，不包含业务实现。
- `web/admin/`、`web/client/`：两个完全独立的 Vue 3 + TypeScript + Vite + Element Plus 前端。

## 快速开始

```bash
make install-web
make build
make dev-server
# 新终端
make dev-client
```

`make build` first compiles both independent Vue panels and embeds their
static assets into the matching Go binary. `FRP_ADMIN_WEB_DIR` and
`FRP_CLIENT_WEB_DIR` remain optional development/test overrides; a release
binary does not require an external web directory.

默认地址：

- Server Panel API/UI：`http://127.0.0.1:7400`
- Client Panel API/UI：`http://127.0.0.1:7410`

首次启动的管理员初始凭据写入 `server/data/initial-admin.txt`（权限 0600）。正式部署时必须配置 HTTPS、密钥文件、FRPS 公网地址、固定版本二进制、`FRPS_TRANSPORT_SECRET_FILE` 和外部 Provider；Router 可用 `FRP_ROUTER_TLS_ENABLED=true` 启用进程内 SNI TLS 热加载。FRPS Plugin/固定 FRPC 的配置和验证见 [docs/frp-plugin-e2e.md](docs/frp-plugin-e2e.md)。

发布前的本地门禁与外部证据统一由 `make external-acceptance` 收集；固定 FRP 二进制、Cloudflare Sandbox、ACME Staging、目标硬件和 cosign 证据的配置见 [docs/external-acceptance.md](docs/external-acceptance.md)。缺少外部依赖时报告为 `blocked`，不会被算作通过。

Linux 故障边界可在 Ubuntu 24.04 disposable runner 上运行 `make fault-injection`；它验证真实 tmpfs `ENOSPC` 下 Router last-good 保护和 Provider/ACME clock-skew fail-safe，但不替代正式发布环境签收。

Client 默认只监听回环地址。局域网部署必须显式设置 `CLIENT_ALLOW_LAN=true`，绑定具体 LAN IP，配置 `CLIENT_ALLOWED_CIDRS`/`CLIENT_ALLOWED_HOST`，并提供 `CLIENT_TLS_CERT_FILE` 与 `CLIENT_TLS_KEY_FILE`；不完整的非回环配置会被 Client 拒绝启动。

## 合规边界

两个面板独立编译、独立运行、独立部署，不共享业务数据库；只通过版本化 HTTPS REST/WebSocket 和 `/contracts` 中的协议通信。代码中不包含设备注册、永久 `client_id`、`device_token` 或设备 HMAC 流程。

完整开发与验收基线见 [frp_cloudflare_platform_v3_development_acceptance_standard.md](frp_cloudflare_platform_v3_development_acceptance_standard.md)，当前实现状态见 [PROGRESS.md](PROGRESS.md)。

实现级逐项矩阵见 [`docs/acceptance-matrix.md`](docs/acceptance-matrix.md)；部署配置、用户操作、升级回滚和已知限制分别见 [`docs/config-reference.md`](docs/config-reference.md)、[`docs/user-manual.md`](docs/user-manual.md)、[`docs/upgrade-rollback.md`](docs/upgrade-rollback.md) 和 [`docs/known-issues.md`](docs/known-issues.md)。
