# 升级、回滚与已知限制

## 升级前

1. 记录当前 Server/Client 版本、FRPS/FRPC 版本和 release manifest SHA-256。
2. 停止写操作窗口，执行 `make checkpoint FRP_SERVER_DB=/var/lib/frp-panel-server/server.db`。
3. 使用加密备份工具生成 FPPB1 备份，并在隔离目录执行一次 Decode、SQLite
   `integrity_check` 和 `TestMigrationUpgradeFromPreviousStableBackup`。
4. 先升级 Server，再升级 Client；确认 `/api/v1/compatibility` 与兼容矩阵
   后再应用 Client 配置。

## 密钥轮换维护窗口

1. 停止或排空 Server 写入与后台 Worker，确认最近的 FPPB1 备份可恢复。
2. 执行 `make key-rotate`（使用与 Server 相同的 `FRP_SERVER_DATA_DIR`、
   `FRP_SERVER_DB` 和 `FRP_SERVER_MASTER_KEY_FILE` 环境变量）。命令会创建
   新的版本化 master/certificate-wrapping key，并在一个 SQLite 事务中重加密
   FRP 凭据、Cloudflare Token 和证书私钥。
3. 记录命令输出的 key version/row counts，启动 Server，验证 Client 登录、DNS
   Job、Router TLS 与 ACME 账户恢复，再保留旧 key 版本至少一个发布回滚周期。

如果事务失败，旧版本 key 仍保留，数据库事务回滚；修复根因后可重复执行。
key 文件已经生成而数据库事务失败时也不会丢失旧密文，下一次轮换会继续使用
新的当前版本并重新包裹全部记录。生产发布仍需完成真实停机窗口、备份恢复和
签字，不得把本地测试结果当作外部演练结果。

Migration 只向前编号，启动时只执行未记录的 migration，不自动删除列或表。
升级前的备份副本会在当前版本打开并记录最新 migration 后才视为可用。

## 回滚

如果新版本无法启动或配置应用失败，停止新进程，恢复上一版本的两个发行物，
保留数据库和 `data/`，然后检查日志、Operation 和 Router last-good。不得
用旧二进制直接打开已经执行了新破坏性 migration 的数据库；应在停机窗口使用
最近的 FPPB1 备份恢复，并让恢复流程撤销所有 Session/Runtime Credential、
重新生成 Router Snapshot。恢复前会保留 `.before-restore-*` 副本。

Client 的配置回滚由 Supervisor 使用 `frpc.last-good.toml` 完成；如果新
FRPC `verify`、reload 或 restart 失败，旧配置不会被标记为成功。

## 发布记录要求

发布包必须同时提供 `frp-panel-server`、`frp-panel-client`、FRP 兼容版本、
`SHA256SUMS`、SPDX SBOM、release manifest、签名和本文件。Server 与 Client
版本独立记录在 manifest 的 `panel_versions` 中。
