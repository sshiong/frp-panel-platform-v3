# FRP 固定版本与 Plugin 验证

平台把 FRP 的原生 Token 和 Server Plugin 二次鉴权分成两层：

- `frps_transport_secret` 是部署级原生 Token，只写入受保护文件，并通过 Client Supervisor 的运行时 Secret 文件提供给 FRPC。
- `frp_user_secret`、`frp_runtime_credential`、`session_generation`、`mapping_id` 和 `mapping_revision` 通过 FRP metadata 发送给 loopback Plugin；Plugin 每次请求重新查询 Server 数据库并 fail-closed。

Server 的 `FRPS_CONFIG_PATH` 指向的配置必须把 Plugin 指向同一个控制面监听地址：

```toml
bindAddr = "0.0.0.0"
bindPort = 7000
proxyBindAddr = "127.0.0.1"
vhostHTTPPort = 8080
auth.method = "token"
auth.tokenSource.type = "file"
auth.tokenSource.file.path = "/var/lib/frp-panel-server/frps-transport.secret"

[[httpPlugins]]
name = "frp-panel-platform"
addr = "127.0.0.1:7400"
path = "/internal/frp/plugin"
ops = ["Login", "NewProxy", "CloseProxy", "Ping", "NewWorkConn", "NewUserConn"]
```

实际部署时，`auth.tokenSource.file.path` 必须与 `FRPS_TRANSPORT_SECRET_FILE` 相同，文件权限为 `0600`，运行 FRPS 的用户必须可读。Server Panel 不会把这个文件内容放进 SQLite 或管理员响应。

固定版本要求：

- Server 与 Client 默认目标为 FRP `v0.68.0`，发布清单必须同时记录 `frps`/`frpc` SHA-256。
- 平台最低支持 `frpc` `v0.68.0`，并使用 `auth.tokenSource.type = "file"` 和 `auth.tokenSource.file.path`。
- 更早版本只保留开发兼容分支，会把 native token 放进 TOML；生产发布不得使用该分支。

## 可复现验证

协议级测试直接发送真实 FRP Server Plugin 的 `POST ?version=0.1.0&op=...`、`{"content": ...}` envelope，并覆盖 Login、NewProxy、CloseProxy 和旧 generation 拒绝：

```bash
cd server
GOCACHE=/private/tmp/frp-cf-gocache \
GOMODCACHE=/private/tmp/frp-cf-gomodcache \
go test -race ./internal/httpapi -run TestFRPPluginUsesRealServerPluginEnvelope
```

如果本机有固定官方 FRPS/FRPC v0.68.0 二进制，可以执行真正的网络级 Plugin 验证。测试会在临时 SQLite 中创建用户、Session 和 Mapping，启动 loopback `/internal/frp/plugin`、FRPS、FRPC 与本地 TCP 服务，并验证 FRPS/FRPC 通过 Plugin 后的真实代理响应：

```bash
cd server
FRP_PLUGIN_E2E=1 \
FRP_E2E_FRPS_BINARY=/opt/frp/frps \
FRP_E2E_FRPC_BINARY=/opt/frp/frpc \
GOCACHE=/private/tmp/frp-cf-gocache \
GOMODCACHE=/private/tmp/frp-cf-gomodcache \
go test -race ./internal/httpapi -run TestFRPPluginNetworkE2E -count=1 -v
```

也可以从仓库根目录执行 `make plugin-e2e FRP_E2E_FRPS_BINARY=/opt/frp/frps FRP_E2E_FRPC_BINARY=/opt/frp/frpc`。

该测试不伪造 Cloudflare、ACME 或生产 TLS；Linux release matrix 仍应使用同一入口重复验证。

仓库 CI 的 `frp-linux-e2e` job 在 Ubuntu 24.04 上从官方 FRP v0.68.0
release asset 下载并校验 GitHub release digest，然后执行 `frps/frpc verify`、
原生 TCP 代理 E2E 和真实 FRPS/FRPC + loopback Plugin 网络 E2E。该 job 只证明
固定 Linux runner 的兼容性，不替代目标部署机、Cloudflare Sandbox、ACME
Staging 或发布签字证据。

如果本机有固定 `frpc` 二进制，可验证 Client 生成配置：

```bash
make frpc-verify \
  FRPC_VERIFY_BINARY=/opt/frp/frpc \
  FRPC_VERIFY_VERSION=0.68.0
```

完整 FRPS/FRPC 网络 E2E 使用仓库内的可复现入口。先用临时 Server Panel/Client Session 生成带真实 metadata 的 `frpc.toml`，再准备含 loopback Plugin 和独立 transport-token 文件的 `frps.toml`，最后运行：

```bash
FRP_E2E_FRPS_BINARY=/opt/frp/frps \
FRP_E2E_FRPS_CONFIG=/tmp/frps-e2e.toml \
FRP_E2E_FRPC_BINARY=/opt/frp/frpc \
FRP_E2E_FRPC_CONFIG=/tmp/frpc-e2e.toml \
FRP_E2E_URL=http://127.0.0.1:18080/ \
FRP_E2E_FRPS_READY_PORT=7000 \
FRP_E2E_FRPS_SHA256='<release-manifest-sha256>' \
FRP_E2E_FRPC_SHA256='<release-manifest-sha256>' \
make network-e2e
```

入口会先执行两个固定二进制的 `verify`，再启动并清理 FRPS/FRPC，轮询真实代理 URL；失败时输出双方日志。它不伪造 Cloudflare、ACME 或 Plugin 成功。没有固定二进制、FRPS 配置、真实 Session metadata 和隔离端口时，CI 只能运行协议级测试，不得把它标记为真实网络 E2E 通过。
