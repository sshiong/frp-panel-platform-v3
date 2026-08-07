# FRP Cloudflare Platform v3 进度跟踪

> 最后更新：2026-08-03
>
> 本文是实现进度的单一记录入口。每次完成一个可验证的垂直切片，更新状态、证据和未决项；未通过验收的能力不得标记为完成。

公开仓库：<https://github.com/sshiong/frp-panel-platform-v3>

## 当前状态

| 阶段 | 状态 | 证据 |
|---|---|---|
| 阶段 0：技术验证 | 本地实现完成，外部验证待执行 | Server/Client Supervisor、Router/Provider、固定 FRP v0.68.0 配置验证和真实 FRPS/FRPC + Server Plugin TCP 网络 E2E 已通过；Cloudflare/ACME 仍需隔离环境 |
| 阶段 1：身份与基础安全 | 本地实现完成 | Argon2id、单活动 Client Session、审计、地址规范化、Server Cookie CSRF、敏感写入再认证、登录/API 限速、LAN 安全边界、证书检查/SPKI pin 和内存态 CSRF 已通过 race/vet/staticcheck 测试 |
| 阶段 2：Client/FRPC 闭环 | 本地实现完成，外部矩阵待执行 | Supervisor 串行队列、verify/原子写入/last-good 回滚、Server/Client WebSocket 心跳/退避/全量恢复、固定 FRPC v0.68.0 兼容性和真实 Plugin 网络链路已验证；离线只读缓存、运行时秘密清理和 Operations 状态面板已接入 |
| 阶段 3：TCP/UDP Mapping | 本地实现完成，平台矩阵待执行 | Mapping/Revision/Port Lease/幂等 API、真实 FRP Plugin envelope 与固定 v0.68.0 FRPS/FRPC + loopback Plugin metadata 网络 E2E 已通过 |
| 阶段 4：域名和 Cloudflare | 本地实现完成，外部 Sandbox 待执行 | Domain/DNS/Token 加密模型、权限分流、冲突语义、补偿 Job 和重定向隔离已实现；真实测试 Zone/Token 尚未配置 |
| 阶段 5：Router 和证书 | 本地实现完成，ACME/TLS 待执行 | Router Snapshot control/business 分离、HMAC/last-good、DB-free Host runtime 与 ACME DNS-01 Provider 已实现；真实 ACME Staging、TLS/SNI 热切换仍需外部部署验收 |
| 阶段 6：任务、删除、备份和发布 | 本地与 CI 门禁完成，发布签署待执行 | Job/Audit、pending 配额、删除补偿、全数据加密备份 Decode/Restore、OpenAPI 34/39 路由与显式成功响应 schema、上一稳定版 migration 演练、ESLint、许可证策略、SPDX SBOM、SHA-256 清单和 `make external-acceptance` 证据收集器已通过；GitHub Actions `ci` 与 CodeQL 已在最终修复提交上全绿，仍需正式签名、外部环境和发布签字 |

## 已实现

- [x] 单仓库、多模块：`server/`、`client/`、`contracts/`、`web/admin/`、`web/client/`。
- [x] 发行边界：`make build` 和 Docker 构建分别把 Admin/Client 静态资源嵌入对应 Go 二进制；外部 web 目录仅保留为显式开发/测试覆盖。
- [x] Server SQLite WAL、外键、busy timeout、synchronous FULL、顺序 migration。
- [x] 管理员初始化、Argon2id 密码哈希、首次改密限制。
- [x] 不透明服务端 Session；普通用户 Client Panel 全局单活动 Session；Session generation 替换旧会话。
- [x] API Problem Details、请求 ID、CORS/安全 Header、限速边界和敏感日志过滤。
- [x] Mapping 归属用户；不可变 Revision；端口全局唯一租约；配置版本与 expected version 冲突。
- [x] 所有认证写 API 强制 `Idempotency-Key`；资源事务与通用写入均持久化幂等记录，通用重放响应使用 Server 主密钥加密；审计记录；用户资源 SQL 级 `user_id` 过滤。
- [x] Client Server 地址规范化（Scheme/Host/端口/IPv6/Userinfo/Path 校验）。
- [x] Client 内存 Local Proxy Session；Server token 不进入 localStorage；单 Supervisor 队列、原子配置回滚、last-good 启动可读状态和代理项优先 reload。
- [x] 两个独立 Vue 前端，采用石墨/象牙/钢蓝/状态色视觉体系，不使用浅紫色。
- [x] 前端关键策略模块有 Node test runner 覆盖：Admin 首次身份设置/危险操作再认证与 Client 状态/危险操作 guard 均为 100% line/branch/function coverage。
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
- [x] Server 管理员 Cookie Session 使用会话绑定的 CSRF hash；Cloudflare、用户生命周期、Router rebuild、加密备份和 FRP 凭证重置等敏感操作要求短期 `reauth_ticket`，只存 hash，不记录明文。
- [x] Client 非 loopback 监听必须显式开启 LAN、配置 CIDR/Host allowlist 和 TLS 证书；Server/Client 登录/API 具备有界限速、并发上限和服务间 HTTP 重定向隔离。
- [x] Server/Client WebSocket 使用固定 v1 envelope；Client 心跳续租、指数退避抖动重连、Session 替换/停用安全停机和配置事件全量同步已实现。
- [x] Pending 配额检查覆盖 Mapping、端口租约、Domain Operation 和证书任务；指标端点增加 Port Lease、Job、Certificate、Router lag 与 SQLite WAL gauges。
- [x] Mapping 删除保留 Domain Binding 直到 managed DNS 清理完成；Domain 删除失败可重试，Mapping 删除操作在补偿完成后才成功；端口更新成功后释放旧租约。
- [x] Client 应用失败事务化回滚 pending Revision：Revision 留存为 `failed`、`pending_revision_id` 清空、旧 active Revision/端口保持有效、新端口 pending lease 释放，失败后可继续创建下一条不可变 Revision。
- [x] 管理员用户删除进入 `deleting` 状态并立即撤销 Session/运行时凭据；Domain、Mapping 按依赖顺序进入持久化补偿队列，强制删除会记录 `external_residues`，本地用户删除后保留用户级 Operation 证据。
- [x] Client 固定 FRPC 进程写入受保护 PID 标记；启动时只回收命令行匹配固定二进制的孤儿进程，PID 复用时拒绝终止并清除运行时秘密。
- [x] Client 登录前只做 TLS 证书检查，不发送登录密码；生产 HTTPS 需系统 CA、IP SAN/custom CA 或用户确认的 SPKI pin，pin 仅驻留内存并绑定当前 Server；切换 Server 会注销旧会话、停止旧 FRPC 并清理缓存/秘密。
- [x] Client 离线回退只允许当前登录会话的 GET 快照，4xx/会话替换/停用永不被缓存掩盖；退出、切换 Server、会话失效会清理缓存和内存运行时秘密；浏览器 `localStorage` 仅保存 `last_server_panel_url`。
- [x] Client Operations 页面展示阶段、步骤、状态、错误、重试和 external residues；所有异步操作保留可见的 loading/error/retry 反馈。
- [x] PERF-001~007 本地验收 profile：并发读写、目标规模 Router/Domain 快照、200 Mapping 配置签名、Client 提交到应用以及旧 HTTP/WS/FRP Plugin 会话在替换后失效均有可重复测试；目标 Linux/硬件基线仍需外部环境签收。
- [x] `http_only` 固定为无证书、无 HTTPS 跳转；API、服务层、Client 表单和 SQLite CHECK/trigger migration 均拒绝冲突配置。
- [x] 正式 FPPB1 包包含数据库、受保护数据目录密钥/证书/ACME 文件，逐文件校验并安全恢复；Server 启动会重新排队 Router 快照。
- [x] OpenAPI 3.1 路径/operationId/WebSocket 元数据校验脚本、双模块 CI contract job、`make sbom`、`make checksums`、固定 FRP 版本下载归档校验和发布清单已加入；正式发布仍需签名和第三方扫描。
- [x] 开发标准门禁已补齐：两个 Vue 应用的 ESLint/strict typecheck/build、OpenAPI 响应契约测试、上一稳定版 migration upgrade rehearsal、npm SPDX 许可证 allowlist、Router Header/Body/上游超时边界和独立 Server/Client 版本元数据。
- [x] Client/Server 版本兼容边界已补齐：Client 发送 `X-FRP-Client-Version`，Server 对缺失/非法/过旧版本返回 426 与 `Upgrade-Required`，兼容但非 latest 版本显示升级建议；Server/Client 回归与 OpenAPI 契约测试通过。
- [x] OpenAPI 类型化契约已补齐：`openapi-typescript` 生成 Server 与 Client Local API 的 `contracts/generated/*-api.d.ts`，两个面板请求层与页面模型引用对应生成类型，CI 检查生成文件漂移；root tooling 依赖纳入 SPDX SBOM 与许可证门禁。
- [x] 密钥迁移期轮换已补齐：master/certificate wrapping key-ring 保留旧版本，`make key-rotate` 重包裹 FRP、Cloudflare 和证书私钥；重启兼容、旧密文解密、服务层行数/登录回归测试通过，真实生产轮换演练仍待外部环境。
- [x] WCAG 2.1 AA 自动化已补齐：构建后的 Admin/Client 登录页、全部认证导航面板以及 Admin 创建用户、Client Mapping/Domain 对话框均通过 axe、标签、键盘/reduced-motion 与 390px 横向溢出检查；脚本使用无秘密的确定性 API fixture，并已接入既有 `web (admin)` CI job。
- [x] 前端性能与颜色 token 收口已补齐：两个独立面板改为按需注册 Element Plus Dialog/Message/MessageBox，移除全量 Element Plus CSS；Admin/Client 生产 bundle 分别降至约 225.44/235.93 kB JS 与 66.13/69.74 kB CSS，Vite chunk 警告消失；重复面板、输入、侧栏、导航、对话框和边框颜色已集中到各自 `tokens.css`。
- [x] API 成功响应契约已收紧：Server OpenAPI 为所有成功 JSON 响应声明 schema，统一 `request_id` 元数据，补齐 `/me` 实际会话字段、分页 envelope、异步 Operation、备份、Token、Router 和用户管理响应；`responseMetadata` 现在也覆盖 API GET 响应，契约回归验证通过。
- [x] 外部验收证据收集器已补齐：`make external-acceptance` 运行本地契约/迁移/安全/许可证/构建门禁，在显式提供固定 FRP 二进制时运行真实网络 E2E，并对 Cloudflare Sandbox、ACME Staging、目标硬件、故障注入和签名证据缺失返回 `blocked`/退出码 2；流程见 [`external-acceptance.md`](docs/external-acceptance.md)。

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
| 2026-08-02 | Security and release gates | 通过；OpenAPI 34 paths/39 operations、Server/Client 全量 race、go vet/staticcheck、Vue typecheck/build、secret scan、3 个 2 秒 fuzz、PERF-001/002、官方 FRPC/FRPS v0.68.0 verify、带归档 SHA-256 的原生 transport E2E、真实 FRPS/FRPC + loopback Plugin metadata E2E、SPDX SBOM、产物校验和与 release manifest 均通过 |
| 2026-08-02 | Coverage and Revision rollback gate | 通过；Server Go 总体行覆盖率 75.1%，Client 76.0%；认证 94.7%、Token 加密 91.4%、Router runtime/snapshot 92.1%，Session/端口租约错误路径与 Revision 成功切换/失败回滚测试通过；失败回滚保留旧 active Revision/旧端口并释放新端口 |
| 2026-08-02 | Frontend policy guard gate | 通过；Admin 与 Client `npm run test:policy` 均通过，策略模块 line/branch/function coverage 100%，并纳入 `make lint` 与 GitHub Actions web job |
| 2026-08-02 | Session/address/cache hardening | 通过；Client TLS inspection 在提交密码前完成，正确 SPKI pin 才允许连接，错误 pin 不触发 HTTP 请求；Server 切换会注销旧会话，断线仅回退当前会话 GET 缓存，退出/失效后缓存不可见 |
| 2026-08-02 | API protocol/idempotency hardening | 通过；Server/Client API 统一请求 ID 与 `X-FRP-Protocol-Version: v1`，未知版本返回 426；认证写入强制幂等键，重复请求重放加密响应，不同请求体复用同键返回 409；OpenAPI 保持 34 paths/39 operations |
| 2026-08-02 | Fixed TLS mode and browser visual QA | 通过；`http_only` 与 redirect 冲突在 API/服务层/表单均被阻断；Playwright 检查 Admin 与 Client 登录页，石墨/象牙/钢蓝/状态色体系，无浅紫色；当前页面截图已核对 |
| 2026-08-02 | Database constraint and final regression | 通过；SQLite CHECK/trigger migration 拒绝 `http_only + redirect`，全量 `make test`（Server/Client race）、`make lint`、`make build`、SBOM/checksum/manifest、OpenAPI 和 secret scan 均通过；Vite 仅保留非阻断的大 chunk 警告 |
| 2026-08-02 | Responsive/performance acceptance hardening | 通过；Admin/Client 390×844 Playwright 检查 `scrollWidth === innerWidth`，移动端断点、表格容器滚动、44px 触控目标和 reduced-motion 已接入；`make perf` 的 PERF-001~007 本地 profile 通过，其中 PERF-007 覆盖旧 HTTP/WS/FRP Plugin 会话替换失效 |
| 2026-08-02 | Frontend technical audit | 通过并留有发布建议；`docs/ui-audit.md` 评分 15/20，未发现 P0/P1 UI 阻断项；P2 为生产 bundle 分包与颜色 token 收敛，P3 为将认证路由 WCAG 自动化纳入 CI |
| 2026-08-02 | CI failure analysis and local gate repair | 本地通过；Ubuntu CI 的 go/web/contract/container/fuzz/release-metadata/CodeQL 已通过，security 仅因 gosec 新规则命中而失败；已逐项修复/说明 TLS inspection、文件边界、固定命令、Cookie 和整数转换，复跑本地 gosec Server/Client 均为 0 findings |
| 2026-08-02 | Development-standard gate completion | 本地通过；`make lint`、`make test`、`make build`、`make contract`、`make migration-check`、`make license` 通过；响应契约、迁移升级、Router 请求边界、独立版本字段和逐项 [`acceptance-matrix.md`](docs/acceptance-matrix.md) 已入库 |
| 2026-08-02 | Final GitHub CI and CodeQL gates | 通过；提交 [`2f73156`](https://github.com/sshiong/frp-panel-platform-v3/commit/2f731567da6933d4fc2ae1db333ad9d61fc2ca19) 的 [`ci` run 30745496136](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/30745496136) 九个 job 全部成功，包含 security、双前端、双 Go 模块、fuzz、contract、container-scan、release-metadata；[`CodeQL run 30745496145`](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/30745496145) 成功，双 gosec SARIF 使用独立 category 上传 |

| 2026-08-02 | 版本兼容、密钥轮换与 WCAG 托管门禁 | 通过；Server/Client 版本升级提示与 426 回归、版本化密钥环/`make key-rotate` 重包裹与重启兼容回归、两个已构建前端的 axe WCAG 2.1 AA/标签/键盘/移动端检查均通过；PR #2 的 [`ci` run 30757304002](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/30757304002) 与 [`CodeQL run 30757303990`](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/30757303990) 全部成功，真实生产轮换仍待外部环境 |

| 2026-08-03 | 发行边界与生成契约补齐 | 通过；`make build` 将两个独立 Vue dist 分别嵌入 Server/Client Go 二进制，`go test ./internal/httpapi` 覆盖 fallback embed；Server/Client `go test -race ./...`、`make lint`、`make contract`、OpenAPI 生成文件漂移检查、npm 许可证门禁和 SPDX SBOM 均通过。新增 Client Local API OpenAPI 与独立 route manifest；Vite 仍只有非阻断的大 chunk 警告，真实 Cloudflare/ACME/Linux FRP 矩阵和签名仍待外部环境 |

| 2026-08-03 | Docker 构建修复与托管门禁 | 通过；提交 [`4e0cbc1`](https://github.com/sshiong/frp-panel-platform-v3/commit/4e0cbc1) 为镜像 UI 构建阶段复制生成契约类型，PR #2 的 [`ci` run 30760001938](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/30760001938)（含 container-scan/release-metadata）与 [`CodeQL run 30760001941`](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/30760001941) 全部通过；正式签名和外部集成验收仍待发布环境 |

| 2026-08-03 | 响应契约与外部证据门禁 | 通过；`make contract`、Server/Client `go test -race ./...`、`make lint`、`make build`、`npm run test:accessibility`、`make sbom`、校验和/发布清单和 secret/license/migration 门禁均通过；新增 `request_id`/`/me` 实际字段契约与 `scripts/external-acceptance.rb`，本机无外部 Provider/签名证据时按设计生成 `blocked`，不伪造 Release Candidate |
| 2026-08-03 | 最终托管门禁记录 | 通过；提交 [`0f0b353`](https://github.com/sshiong/frp-panel-platform-v3/commit/0f0b3538ba678ec685deb72e283dce9d4df9b038) 的 [`ci` run 30761382419](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/30761382419) 与 [`CodeQL run 30761382415`](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/30761382415) 全部成功；PR #2 检查全绿但仍需人工 review，外部真实环境证据仍按标准保持 blocked |
| 2026-08-03 | 固定 FRP 外部验收收集器 | 通过/按标准阻断；隔离 fixture 下 `frp-network-e2e.sh`、固定 FRPC `verify`、真实 FRPS/FRPC Plugin 网络 E2E 及本地契约/迁移/安全/许可证/构建均通过；`scripts/external-acceptance.rb` 仅因缺少 Cloudflare/ACME/目标硬件/故障注入/签名证据返回 blocked（退出码 2），未伪造 P0/P1 外部通过 |
| 2026-08-03 | 固定 FRP 证据提交托管复核 | 通过；提交 [`49a21b0`](https://github.com/sshiong/frp-panel-platform-v3/commit/49a21b00f0e75afbf1c30772ab210e8b9d3dc98c) 的 [`ci` run 30762128928](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/30762128928) 与 [`CodeQL` run 30762128925](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/30762128925) 全部成功，包含容器扫描、发布元数据、双面板可访问性和安全门禁；PR #2 仍需人工 review |
| 2026-08-03 | 认证面板可访问性与对比度收口 | 通过；`npm run test:accessibility` 扫描两个独立面板的全部导航 surface 与创建对话框，发现并修复导航类别标签、Mapping/Domain 元数据的 WCAG AA 对比度问题；登录页、认证页、对话框的 axe/标签/键盘/reduced-motion/390px 检查均通过 |
| 2026-08-03 | 最终本地门禁与外部证据收集 | 本地通过；`make contract`（含证据 schema 回归）、`make test`、`make lint`、`make build`、`make perf`、`make security`、`make license`、`make migration-check`、`make sbom`、`make checksums` 和浏览器可访问性均通过；`make manifest` 因未提供固定 FRPS/FRPC 只拒绝生成正式清单，`make external-acceptance` 因同一固定版本依赖及 Cloudflare/ACME、目标硬件、故障注入和签名证据缺失按标准返回 blocked（退出码 2），未伪造发布通过 |
| 2026-08-03 | 认证面板修复提交的最终托管复核 | 通过；提交 [`92cf1a3`](https://github.com/sshiong/frp-panel-platform-v3/commit/92cf1a379aab096dc2800a92eaa3d43e41a5e77c) 的 [`ci` run 30763715852](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/30763715852) 与 [`CodeQL` run 30763715867](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/30763715867) 全部成功，新增 evidence schema regression、双面板认证可访问性、fuzz、container scan 和 release metadata 均通过 |
| 2026-08-03 | 前端性能与设计 token 收口 | 本地通过；两个面板按需加载 Element Plus 组件与样式，Admin/Client 生产 JS/CSS 分别为 225.44/66.13 kB 与 235.93/69.74 kB，Vite 大 chunk 警告消失；独立 token 层收敛重复颜色；两个面板 typecheck、lint、policy、build 与完整 WCAG/390px 认证面板扫描均通过 |
| 2026-08-03 | 前端性能与设计 token 收口托管复核 | 通过；提交 [`b91412f`](https://github.com/sshiong/frp-panel-platform-v3/commit/b91412f00d73d70f54bbdae8eade65339f98f4be) 的 [`ci` run 30764876448](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/30764876448) 与 [`CodeQL` run 30764876452](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/30764876452) 全部成功，CSS token policy、双面板构建/可访问性、安全、fuzz、容器扫描和发布元数据均通过 |
| 2026-08-03 | 仓库治理与 PR 验收模板收口 | 已核对公开仓库、`main` 分支保护、线性历史、禁止强推/删除、CODEOWNERS、两次审批和必需 CI/CodeQL 检查；新增 PR 验收/风险模板；第二位安全/数据库/加密指定评审者和外部发布签字仍待配置 |
| 2026-08-03 | Server/Client 独立版本发行链路 | 通过；Server/Client 版本改为构建时独立 `-ldflags` 注入，compatibility API 与 release manifest 同步独立版本/最低兼容版本；新增 SemVer/最低版本策略校验、手动 release 输入和注入版本的 Go 测试；分离 `1.2.3`/`2.4.5` 构建验证、`make contract`、`make test`、完整 lint 均通过 |
| 2026-08-03 | 独立版本发行链路最终托管复核 | 通过；提交 [`a1cb4ae`](https://github.com/sshiong/frp-panel-platform-v3/commit/a1cb4ae) 的 [`ci` run 30766492825](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/30766492825) 与 [`CodeQL` run 30766492828](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/30766492828) 全部成功；PR #2 仍待仓库要求的人工审核，外部真实集成与正式签名继续按标准保持 blocked |
| 2026-08-03 | 验收证据提交绑定与标准矩阵同步门禁 | 通过；外部证据包现在必须绑定公开仓库和当前 40 位 commit，拒绝其他 revision 的旧证据；新增标准 141 项与矩阵 142 行的同步策略并接入 `make contract`，当前真实 Provider/目标环境缺失仍按标准返回 blocked |
| 2026-08-07 | 验收增强最终托管复核 | 通过；提交 [`97f5d9e`](https://github.com/sshiong/frp-panel-platform-v3/commit/97f5d9e) 的 [`ci` run 31180964158](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/31180964158) 与 [`CodeQL` run 31180966657](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/31180966657) 全部成功；PR #2 仍需人工审核，真实 Cloudflare/ACME/Linux/签名证据继续按标准保持 blocked |
| 2026-08-07 | 当前验收证据文档托管复核 | 通过；提交 [`2a058fe`](https://github.com/sshiong/frp-panel-platform-v3/commit/2a058fe3b07ab9505ebeae3d4fb77e3b5abd4a55) 的 [`ci` run 31181350965](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/31181350965) 与 [`CodeQL` run 31181352584](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/31181352584) 全部成功；PR #2 仍需人工审核，真实 Cloudflare/ACME/Linux/签名证据继续按标准保持 blocked |
| 2026-08-07 | Go 1.25.4 与固定 FRP 外部收集器复验 | 本地通过；使用 Go 1.25.4 新模块缓存重新通过 `make contract/test/lint/build/perf/migration-check/security/license`、双面板 WCAG、SBOM/校验和/发行清单、Server runtime smoke、固定 FRP v0.68.0 `verify`、原生 TCP E2E 和真实 FRPS/FRPC Plugin 网络 E2E；`make external-acceptance` 9 个步骤中 8 个 passed，仅因 Cloudflare/ACME/目标硬件/故障注入/签字证据缺失返回 blocked（退出码 2） |
| 2026-08-07 | 固定 FRP 验收证据托管复核 | 通过；提交 [`9fe4b92`](https://github.com/sshiong/frp-panel-platform-v3/commit/9fe4b92) 的 [`ci` run 31183385079](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/31183385079) 与 [`CodeQL` run 31183385781](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/31183385781) 全部成功，包含双 Go race/staticcheck、双面板 WCAG、容器扫描和 release metadata；真实 Provider/目标环境/签字仍按标准保持 blocked |
| 2026-08-07 | 发布前外部验收硬门禁 | 已实现；release workflow 现在必须验证仓库根目录、当前 revision 绑定的 `release-evidence.json`，并在 cosign 前运行固定 FRP v0.68.0 原生 TCP/Plugin E2E；缺少真实 Provider、ACME、目标环境、故障注入或三方签字会 fail-closed，不能生成正式 Release |
| 2026-08-07 | Fuzz 安全边界修复与最新托管复核 | 通过；修复 Client `NormalizeServerURL` 接受 `https://%` 非法主机名的问题并加入回归测试；本地与远端 fuzz 全部通过，提交 [`935a1f7`](https://github.com/sshiong/frp-panel-platform-v3/commit/935a1f7) 的 [`ci` run 31185032520](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/31185032520) 与 [`CodeQL` run 31185032236](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/31185032236) 全部成功；PR #2 仍需人工审核，真实外部验收/签名按标准保持 blocked |

## 未决与发布阻断项

以下不是“已实现”的替代品，必须在发布前完成：

1. 在 Linux release matrix/目标部署环境重复真实固定版本 FRPS/FRPC + loopback Plugin metadata E2E，并验证正式 FRPS 配置和权限边界。
2. Cloudflare Sandbox Token 权限、DNS 三种冲突语义、超时补偿和真实外部残留验证。
3. 使用真实 Cloudflare Sandbox + ACME Staging 完成 DNS-01 传播、TXT 清理、证书原子替换与 Router TLS SNI/Host 热切换；本地 Provider 已实现但未伪造外部成功。
4. 加密归档备份恢复的 clean-host 灾备演练、WAL checkpoint 受控执行和磁盘满/时钟偏差故障注入。
5. 1000 Mapping/2000 Domain、200 Mapping、配置同步和会话替换等 PERF-003~007 的目标环境基线；本地开发 profile 已通过，但尚未替代 Linux/生产目标机的容量基线。
6. 生成正式 cosign 签名并完成发布负责人、安全负责人和测试负责人签字；GitHub Actions/CodeQL、SAST/SCA、Secret scan 和 container scan 已在提交 [`2f73156`](https://github.com/sshiong/frp-panel-platform-v3/commit/2f731567da6933d4fc2ae1db333ad9d61fc2ca19) 全绿。
7. 完成上述 P0/P1 外部验收前，仓库只能作为开发预览，不得声明生产就绪。

## 更新规则

- 只在有文件、测试输出、运行日志、截图或外部环境结果等证据时推进状态。
- 外部凭据/真实 FRPS/ACME 未配置时，UI 必须显示 pending/blocked/error，不得显示 active/running。
- 每次实现变更都要同步错误码、API contract、文档和对应测试。
