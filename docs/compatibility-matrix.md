# 版本兼容矩阵

当前开发版本采用独立 Server/Client 发行物，但共享协议兼容边界如下：

| 组件 | 当前版本/最低版本 | 协议与配置 | 备注 |
|---|---|---|---|
| Server Panel | `0.1.0` | API `v1`、config schema `v1` | Server 是资源和 Session 权威 |
| Client Panel | `0.1.0` | API `v1`、config schema `v1` | 只通过版本化 HTTPS REST/WebSocket 与 Server 通信 |
| FRPC | `0.68.0` | file-backed native token、Plugin metadata | Client `verify` 前拒绝低版本 |
| FRPS | `0.68.0` | file-backed native token、HTTP Plugin | 运行前校验发布清单中的 SHA-256 |
| Router Snapshot | schema `v1` | HMAC/hash、control/business routes | 新快照坏时继续 last-good |
| WebSocket | protocol `v1` | fixed envelope + heartbeat/full sync | 不支持版本返回 426 |

Server `/api/v1/compatibility` 始终返回：

```json
{
  "server_version": "0.1.0",
  "minimum_client_version": "0.1.0",
  "latest_client_version": "0.1.0",
  "minimum_frpc_version": "0.68.0",
  "protocol_version": "v1",
  "config_schema_version": "v1"
}
```

Client 请求 `/api/v1/auth/client-login` 和后续 Server API 时发送
`X-FRP-Client-Version: <semver>`。版本缺失、格式非法或低于
`minimum_client_version` 时，Server 返回 HTTP `426`、`Upgrade-Required:
client/<minimum>` 和 `CLIENT_VERSION_UNSUPPORTED`，Client 不会继续创建
Session；当前版本高于最低版本但低于 Server 宣布的 latest 版本时，登录仍可
继续，但 Client Panel 显示可升级提示。旧 Server 若没有 compatibility 端点，
Client 保持向后兼容并继续使用登录响应。

`server_version` and the two panel artifact versions are independent release
metadata. The release manifest records them under `panel_versions.server` and
`panel_versions.client`; a future release may advance one without silently
changing the other. `make build SERVER_VERSION=x.y.z CLIENT_VERSION=a.b.c`
injects those values into the two independent binaries, and the release
workflow validates the values with `scripts/release-version-policy.rb` before
generating the manifest. The manifest also records
`minimum_client_version`, `latest_client_version` and `minimum_frpc_version`
under `compatibility`.

Patch/Minor 版本只增加可忽略字段；删除或改变字段必须升级 API 主版本或经过弃用周期。Server/Client 发行版本可以独立递增，但在兼容矩阵没有声明前不得应用配置。正式发布还要在 Linux release matrix 重复固定 FRPS/FRPC 和 Plugin 验证，并把具体二进制 hash 写入 `build/release-manifest.json`。
