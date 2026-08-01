# FRP Cloudflare Platform v3 进度跟踪

> 最后更新：2026-08-01
>
> 本文是实现进度的单一记录入口。每次完成一个可验证的垂直切片，更新状态、证据和未决项；未通过验收的能力不得标记为完成。

公开仓库：<https://github.com/sshiong/frp-panel-platform-v3>

## 当前状态

| 阶段 | 状态 | 证据 |
|---|---|---|
| 阶段 0：技术验证 | 进行中 | Server/Client Supervisor 与 Router/Provider 接口已建立；Provider 无监听单测通过，真实 FRPS/Cloudflare/ACME E2E 待外部环境 |
| 阶段 1：身份与基础安全 | 进行中 | Argon2id、单活动 Client Session、审计、地址规范化 API 已实现，待自动化验收 |
| 阶段 2：Client/FRPC 闭环 | 进行中 | Supervisor 串行队列、verify/原子写入/last-good 回滚、Server/Client WebSocket 心跳/退避/全量恢复已实现，真实 frpc 二进制兼容测试待补 |
| 阶段 3：TCP/UDP Mapping | 进行中 | Mapping/Revision/Port Lease/幂等 API 已实现，待 FRPS Plugin E2E |
| 阶段 4：域名和 Cloudflare | 进行中 | Domain/DNS/Token 加密模型与 Operation API 已实现，Provider 实际调用待配置 Token |
| 阶段 5：Router 和证书 | 进行中 | Router Snapshot control/business 分离、HMAC/last-good、DB-free Host runtime 与 ACME DNS-01 Provider 已实现；真实 TLS 监听/热切换仍需外部部署验收 |
| 阶段 6：任务、删除、备份和发布 | 进行中 | Job/Audit、pending 配额、删除补偿、全数据加密备份 Decode/Restore、OpenAPI 校验、本地 SBOM 与校验和目标已建立；正式签名和第三方扫描待完成 |

## 已实现

- [x] 单仓库、多模块：`server/`、`client/`、`contracts/`、`web/admin/`、`web/client/`。
- [x] Server SQLite WAL、外键、busy timeout、synchronous FULL、顺序 migration。
- [x] 管理员初始化、Argon2id 密码哈希、首次改密限制。
- [x] 不透明服务端 Session；普通用户 Client Panel 全局单活动 Session；Session generation 替换旧会话。
- [x] API Problem Details、请求 ID、CORS/安全 Header、限速边界和敏感日志过滤。
- [x] Mapping 归属用户；不可变 Revision；端口全局唯一租约；配置版本与 expected version 冲突。
- [x] 核心用户资源写 API 的 Idempotency-Key；审计记录；用户资源 SQL 级 `user_id` 过滤。
- [x] Client Server 地址规范化（Scheme/Host/端口/IPv6/Userinfo/Path 校验）。
- [x] Client 内存 Local Proxy Session；Server token 不进入 localStorage；单 Supervisor 队列、原子配置回滚、last-good 启动可读状态和代理项优先 reload。
- [x] 两个独立 Vue 前端，采用石墨/象牙/钢蓝/状态色视觉体系，不使用浅紫色。
- [x] Client Panel 提供 Mapping 与 Domain Binding 独立导航，展示 IDNA 标准化结果、HTTPS 模式和 pending/active 状态。
- [x] Cloudflare Provider HTTP 适配器支持 Verify/ListZones/UpsertDNS/DeleteDNS，并以独立单元测试覆盖请求方法与路径。
- [x] Domain DNS 意图支持 A/AAAA/CNAME、TTL 和由 HTTPS 模式派生的 proxied；目标记录先落库再进入可重试 Provider Operation，Client Domain 页面展示记录状态。
- [x] Cloudflare Job Worker 支持 token pending 验证、Zone 分页、DNS 冲突 adopt/overwrite/cancel、幂等去重、租约接管与可重试 Operation。
- [x] Cloudflare 401/403 权限错误与网络错误分流；ACME blocked job 重启唤醒、到期前检查、证书/chain 原子文件写入与 managed DNS 删除补偿已接入。
- [x] Mapping Update 校验 `expected_revision` 并持久化 PUT 幂等记录；Domain 删除在 Client ACK 后进入独立 DNS 清理 Job，不会删除 adopted/unmanaged 外部记录。
- [x] Mapping 启停、Domain 删除和 DNS 冲突处理使用持久化幂等记录，并校验 `expected_config_version` / `expected_revision`；Client 浏览器请求保留同一 Idempotency-Key 透传到 Server。
- [x] Router Snapshot 通过独立 HMAC 密钥原子写入；保存 `router_config_version`、`router_applied_version`、last-good 路径/哈希；DB-free Runtime 按 Host 选择 control/business 路由并 fail-closed。
- [x] HTTPS 域名按模式进入 `pending_certificate`；ACME Provider 使用官方 `x/crypto/acme` 执行 DNS-01、TXT 传播检查与清理，证书私钥只使用独立 wrapping key 加密。
- [x] FRPS 可选固定二进制托管，启动前验证配置中声明的 SHA-256；Plugin 保持 loopback-only 与 fail-closed。
- [x] FPPB1 加密备份使用随机 per-package salt；提供解密、SQLite integrity check 和带 `.before-restore-*` 保留副本的原子恢复函数。
- [x] `/internal/frp/plugin` 增加 loopback-only 网络边界；Cloudflare Token 替换保留旧版本直到新版本完成 pending 验证。
- [x] Server/Client WebSocket 使用固定 v1 envelope；Client 心跳续租、指数退避抖动重连、Session 替换/停用安全停机和配置事件全量同步已实现。
- [x] Pending 配额检查覆盖 Mapping、端口租约、Domain Operation 和证书任务；指标端点增加 Port Lease、Job、Certificate、Router lag 与 SQLite WAL gauges。
- [x] Mapping 删除保留 Domain Binding 直到 managed DNS 清理完成；Domain 删除失败可重试，Mapping 删除操作在补偿完成后才成功；端口更新成功后释放旧租约。
- [x] 管理员用户删除进入 `deleting` 状态并立即撤销 Session/运行时凭据；Domain、Mapping 按依赖顺序进入持久化补偿队列，强制删除会记录 `external_residues`，本地用户删除后保留用户级 Operation 证据。
- [x] Client 固定 FRPC 进程写入受保护 PID 标记；启动时只回收命令行匹配固定二进制的孤儿进程，PID 复用时拒绝终止并清除运行时秘密。
- [x] 正式 FPPB1 包包含数据库、受保护数据目录密钥/证书/ACME 文件，逐文件校验并安全恢复；Server 启动会重新排队 Router 快照。
- [x] OpenAPI 3.1 路径/operationId/WebSocket 元数据校验脚本、双模块 CI contract job、`make sbom` 与 `make checksums` 已加入；正式发布仍需签名和第三方扫描。

## 验证记录

| 时间 | 命令/场景 | 结果 |
|---|---|---|
| 2026-08-01 | 初始项目盘点 | 工作区仅包含验收标准，未存在既有代码或 Git remote |
| 2026-08-01 | `server` `go test ./...` | 通过；包括 Provider、备份、密码、加密、Router、Domain 与 Service 测试 |
| 2026-08-01 | `server`/`client` `go vet ./...` | 通过 |
| 2026-08-01 | 两个前端 `npm run typecheck` 与 `npm run build` | 通过；无浅紫色主题，见 `output/playwright/admin-overview.png`、`client-tunnels.png`、`client-domains.png` |
| 2026-08-01 | 本机临时 Server + Client API 闭环 | 通过；登录、签名配置校验、原子应用、`state=running`、`mode=simulated`、`last_good_available=true` |
| 2026-08-01 | HTTP Mapping、IDNA Domain、冲突版本、加密备份 | 通过；端口 6000 自动租约、域名 Punycode 规范化、HTTP 409、`.fppb` 生成与恢复测试 |
| 2026-08-01 | Client Domain Binding UI | 通过；独立域名页面、HTTPS 三模式、pending DNS 标签、删除确认，见 `output/playwright/client-domains.png` |
| 2026-08-01 | `make test` / `make lint` / `make build` | 通过；两个 Go 模块测试/vet、两个 Vue typecheck/build、Server/Client 两个发行物均成功；备份恢复命令保留为 Server 源码内的受控运维工具 |
| 2026-08-01 | Git 发布 | 单仓库 `main` 已推送公开 GitHub；源码、契约、文档和验收截图已纳入，运行数据与密钥未纳入 |
| 2026-08-01 | Router/ACME/FRPS vertical slice | 通过；Router Snapshot HMAC/last-good、Host 404/offline 502、ACME provider compile boundary、FRPS fixed-binary hash/start/stop、Cloudflare/Router job chain 单测通过 |
| 2026-08-01 | Contract/lease/cleanup hardening | 通过；OpenAPI 29 路由可解析、长任务 Lease heartbeat、更新 Revision/PUT 幂等、Cloudflare 403 分类、ACME wake-up 与 Domain 删除 Job 代码回归通过 |
| 2026-08-01 | WebSocket/backup/quota/compensation hardening | 通过；Client WebSocket 集成测试、Server 全量 Go 测试、备份逐文件校验/恢复、DNS 删除补偿和端口租约轮换测试通过；真实外部依赖仍未签收 |
| 2026-08-01 | Contract and release helpers | 通过；Ruby OpenAPI 结构校验与 `make checksums` 目标已加入，CI 仍需在 GitHub Actions 实际运行并补齐外部扫描工具 |
| 2026-08-01 | Final hardening regression | 通过；Server/Client `go test -race ./...`、用户删除补偿与孤儿 FRPC 回收测试、`make test lint build contract sbom checksums`、`git diff --check` 和敏感凭据模式扫描均通过；发行构建为 Server/Client 两个产物，前端仅保留 Vite 大 chunk 警告 |

## 未决与发布阻断项

以下不是“已实现”的替代品，必须在发布前完成：

1. 真实固定版本 FRPS/FRPC 二进制的 Login/NewProxy/Ping/WorkConn Plugin E2E。
2. Cloudflare Sandbox Token 权限、DNS 三种冲突语义和超时补偿。
3. 使用真实 Cloudflare Sandbox + ACME Staging 完成 DNS-01 传播、TXT 清理、证书原子替换与 Router TLS SNI/Host 热切换；本地 Provider 已实现但未伪造外部成功。
4. 加密归档备份恢复的 clean-host 灾备演练、WAL checkpoint 受控执行和磁盘满故障注入。
5. OpenAPI 与实现的自动 Contract test、SAST/SCA/secret scan、真实性能基线、SBOM/签名；本地已加入结构校验与 fuzz seed，但尚未替代正式工具链。
6. 完成 P0/P1 全量验收前，仓库只能作为开发预览，不得声明生产就绪。

## 更新规则

- 只在有文件、测试输出、运行日志、截图或外部环境结果等证据时推进状态。
- 外部凭据/真实 FRPS/ACME 未配置时，UI 必须显示 pending/blocked/error，不得显示 active/running。
- 每次实现变更都要同步错误码、API contract、文档和对应测试。
