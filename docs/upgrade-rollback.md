# 升级、回滚与已知限制

## 升级前

1. 记录当前 Server/Client 版本、FRPS/FRPC 版本和 release manifest SHA-256。
2. 停止写操作窗口，执行 `make checkpoint FRP_SERVER_DB=/var/lib/frp-panel-server/server.db`。
3. 使用加密备份工具生成 FPPB1 备份，并在隔离目录执行一次 Decode、SQLite
   `integrity_check` 和 `TestMigrationUpgradeFromPreviousStableBackup`。
4. 先升级 Server，再升级 Client；确认 `/api/v1/compatibility` 与兼容矩阵
   后再应用 Client 配置。

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
