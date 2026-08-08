# v3 验收矩阵

本矩阵逐项对应开发验收标准第 99—115 节。记录环境为：本机 macOS
开发环境（Go 1.25.4 toolchain、Node 前端）以及 GitHub Actions Ubuntu
CI；执行人为 Codex，外部发布签字人尚未指定。`本地通过` 只表示代码和
自动化证据已通过，不等同于 Cloudflare/ACME/Linux 生产签收。详细命令和
未决外部门禁见 [`PROGRESS.md`](../PROGRESS.md) 与
[`acceptance-report.md`](acceptance-report.md)。

状态含义：

- `本地通过`：已有自动化测试、代码检查或浏览器证据；
- `部分通过`：本地实现已有证据，但标准要求的外部/目标环境仍未完成；
- `待外部`：需要真实 Provider、Linux、Docker、CA、签字或目标硬件。

## 架构、身份和地址

| ID | 状态 | 实际结果与证据 |
|---|---|---|
| ARCH-001 | 本地通过 | `make build` 只产出 `build/frp-panel-server` 和 `build/frp-panel-client`，并将匹配的 Admin/Client 静态资源分别嵌入对应 Go 二进制。 |
| ARCH-002 | 本地通过 | `server/`、`client/` 为独立 Go module；Client 无管理员 API、SQLite、Router、Plugin 依赖。 |
| ARCH-003 | 本地通过 | Server/Client 数据目录由各自配置管理；架构说明与代码边界见 [`architecture.md`](architecture.md)。 |
| ARCH-004 | 本地通过 | 代码与 Secret scan 未发现设备注册、`device_token`、永久 `client_id` 业务流程。 |
| ARCH-005 | 本地通过 | OpenAPI、REST、固定 v1 WebSocket envelope 和协议拒绝测试通过。 |
| ARCH-006 | 本地通过 | 管理 API、FRP Plugin loopback 边界及配置校验测试通过。 |
| AUTH-001 | 本地通过 | Client 登录表单只有 Server 地址、用户名、密码；UI 截图和 Client API 测试通过。 |
| AUTH-002 | 本地通过 | Admin 登录页无 Server 地址字段；独立面板 Playwright 检查通过。 |
| AUTH-003 | 本地通过 | Session/密码只驻留内存或受保护文件；localStorage/日志/Secret scan 测试通过。 |
| AUTH-004 | 本地通过 | 第二次 Client 登录使旧 Session 返回 `SESSION_REPLACED`。 |
| AUTH-005 | 本地通过 | SQLite 唯一活动 Session 约束与并发 race 测试通过。 |
| AUTH-006 | 本地通过 | 旧 WebSocket、心跳、配置和 FRP runtime generation 失效测试通过。 |
| AUTH-007 | 本地通过 | Client local proxy session 替换和旧浏览器注销测试通过。 |
| AUTH-008 | 本地通过 | Admin session 不受普通用户 Client 唯一索引限制；服务层覆盖。 |
| AUTH-009 | 本地通过 | 用户停用撤销 Session、runtime credential 和 FRP Plugin 授权测试通过。 |
| AUTH-010 | 本地通过 | 初始密码/用户名标记和首次修改策略测试通过。 |
| AUTH-011 | 本地通过 | Argon2id、随机 Salt、参数编码和不可逆校验测试通过。 |
| ADDR-001 | 本地通过 | 域名、端口、IPv4、IPv6 和 bracket 形式规范化测试通过。 |
| ADDR-002 | 本地通过 | Userinfo、Path、Query、Fragment、危险 Scheme 及无效 host 被拒绝。 |
| ADDR-003 | 本地通过 | 生产 HTTP/TLS 配置拒绝绕过；inspection/pin 仅限显式本地信任流程。 |
| ADDR-004 | 本地通过 | IP 证书未信任时只检查证书，不发送密码；错误 pin 无 HTTP 请求测试通过。 |
| ADDR-005 | 本地通过 | Client 地址可修改并重新登录，不产生设备绑定流程。 |
| ADDR-006 | 本地通过 | Client 配置只接收 Server 下发的公网 FRPS 地址，不下发 bind 地址。 |
| ADDR-007 | 本地通过 | 远程地址由 FRPS 公网 Host 与 remote port 生成并展示。 |
| ADDR-008 | 本地通过 | 切换 Server 停止旧 FRPC、清理缓存/秘密并建立新 session。 |

## FRPC、FRPS、Mapping 和 DNS

| ID | 状态 | 实际结果与证据 |
|---|---|---|
| FRPC-001 | 本地通过 | Supervisor 所有进程/配置写入经单队列；队列测试通过。 |
| FRPC-002 | 本地通过 | Supervisor 保持单 running process，重复启动路径测试通过。 |
| FRPC-003 | 本地通过 | 固定 FRPC `verify` 先于写入/应用；真实 v0.68.0 verify 通过。 |
| FRPC-004 | 本地通过 | 临时文件 + fsync + rename 的原子配置测试通过。 |
| FRPC-005 | 本地通过 | reload/restart 失败恢复 last-good 并再次启动旧配置。 |
| FRPC-006 | 本地通过 | 代理项变化优先 reload，公共参数变化 restart 测试通过。 |
| FRPC-007 | 本地通过 | Client 只渲染固定 TOML 字段，无任意命令或路径 API。 |
| FRPC-008 | 本地通过 | 重启无有效 Session 时显示 last-good 只读状态。 |
| FRPC-009 | 本地通过 | 退出、替换和停用事件停止 FRPC。 |
| FRPC-010 | 本地通过 | orphan PID 需匹配固定二进制命令行，否则拒绝终止并清理秘密。 |
| FRPS-001 | 本地通过 | 无有效 session/generation 的 Login 被 Plugin 授权拒绝。 |
| FRPS-002 | 本地通过 | 未分配端口的 NewProxy 被拒绝。 |
| FRPS-003 | 本地通过 | 非归属域名的 NewProxy 被拒绝。 |
| FRPS-004 | 本地通过 | 旧 Mapping Revision 被拒绝。 |
| FRPS-005 | 本地通过 | 旧 generation 的 Ping/NewWorkConn/NewUserConn 被拒绝。 |
| FRPS-006 | 本地通过 | 停用用户不能创建新连接。 |
| FRPS-007 | 本地通过 | Plugin 超时/未知状态 fail-closed 测试通过。 |
| FRPS-008 | 本地通过 | FRP 凭证重置使旧 Secret、Session、generation 失效。 |
| FRPS-009 | 部分通过 | 固定 FRPS/FRPC v0.68.0 的真实 Plugin 网络 E2E、transport secret 与 Plugin 分权/loopback 测试通过；Ubuntu 24.04 CI 已加入官方 release digest、`verify`、原生 TCP 和 Plugin E2E；仍需目标部署环境的正式 FRPS 权限/兼容矩阵签收。 |
| MAP-001 | 本地通过 | TCP/UDP 端口数字使用 DB 唯一租约约束。 |
| MAP-002 | 本地通过 | offline/disabled/config_error 不释放租约。 |
| MAP-003 | 本地通过 | 并发自动端口分配无重复 lease。 |
| MAP-004 | 本地通过 | 更新先占新端口，成功后释放旧端口。 |
| MAP-005 | 本地通过 | 更新失败释放新端口并保留旧 Revision/代理。 |
| MAP-006 | 本地通过 | reserved/pending/running/offline 状态在 API/UI 中分离。 |
| MAP-007 | 本地通过 | 可变 Mapping 字段仅在 immutable Revision 中。 |
| MAP-008 | 本地通过 | Idempotency-Key 重放不重复创建 Mapping。 |
| MAP-009 | 本地通过 | stale expected config version 返回 409。 |
| MAP-010 | 本地通过 | 强制删除后旧配置不能重新注册代理。 |
| DNS-001 | 本地通过 | normalized_domain 全局 UNIQUE。 |
| DNS-002 | 本地通过 | 大小写、末尾点和 IDNA/Punycode 规范化通过。 |
| DNS-003 | 本地通过 | Zone 后缀匹配按完整合法 label 处理。 |
| DNS-004 | 本地通过 | Cloudflare Zone 分页 Provider/Job 测试通过；真实 API 待外部。 |
| DNS-005 | 本地通过 | 已存在的面板域名不会出现重复添加选项。 |
| DNS-006 | 本地通过 | 冲突语义固定为 cancel/adopt/overwrite。 |
| DNS-007 | 本地通过 | adopt 记录 `adopted=true, managed_by_panel=false`，删除不清外部记录。 |
| DNS-008 | 本地通过 | overwrite 记录 `adopted=true, managed_by_panel=true`，允许同步/删除。 |
| DNS-009 | 本地通过 | A/AAAA/CNAME、TTL、proxied 字段和校验通过。 |
| DNS-010 | 本地通过 | 一键同步仅更新 panel-managed record。 |
| DNS-011 | 本地通过 | Token 清除不触发已有 DNS 删除。 |
| DNS-012 | 部分通过 | Provider ambiguous-timeout query/recovery 已测试；真实 Cloudflare Sandbox 待外部。 |
| DNS-013 | 部分通过 | managed/unmanaged 删除分支本地通过；真实外部残留待 Sandbox。 |
| DNS-014 | 本地通过 | Domain deletion Operation 可重试，强制删除生成 residue。 |

## Cloudflare、TLS、Router、删除和备份

| ID | 状态 | 实际结果与证据 |
|---|---|---|
| CF-001 | 本地通过 | Token API 只返回 configured/status/version，不返回明文。 |
| CF-002 | 本地通过 | AES-256-GCM、随机 nonce、AAD、key_version 测试通过。 |
| CF-003 | 本地通过 | 日志/审计/trace 脱敏和 Secret scan 通过。 |
| CF-004 | 本地通过 | 401/403 权限错误返回缺少 capability 信息。 |
| CF-005 | 本地通过 | 新 Token pending 验证失败时旧 Token 保持 active。 |
| CF-006 | 本地通过 | UI 三秒倒计时、reauth ticket 和删除语义测试通过。 |
| CF-007 | 部分通过 | Job blocked/retry 状态已实现；真实 Provider 停止/阻塞待 Sandbox。 |
| TLS-001 | 本地通过 | UI、API、服务层、SQLite CHECK/trigger 同时拒绝非法模式。 |
| TLS-002 | 本地通过 | 未知 SNI 返回错误，不提供其他证书。 |
| TLS-003 | 本地通过 | 未绑定 Host=404，offline=502。 |
| TLS-004 | 本地通过 | WebSocket/streaming 代理和 in-flight snapshot reload 测试通过。 |
| TLS-005 | 本地通过 | Forwarded/X-Forwarded 头在 Router Director 中先清理。 |
| TLS-006 | 本地通过 | control_routes 与 business_routes 物理分组、不同 target。 |
| TLS-007 | 本地通过 | Runtime 只读签名 snapshot；坏 DB/快照不影响 last-good。 |
| TLS-008 | 本地通过 | bad HMAC/schema/version 保留旧路由。 |
| TLS-009 | 部分通过 | 证书文件原子替换、内存 CertificateStore 热加载已测；真实 SNI 部署待外部。 |
| TLS-010 | 待外部 | ACME Staging、DNS TXT propagation/cleanup 和 Retry-After 需真实 CA。 |
| TLS-011 | 本地通过 | certificate wrapping key 独立于 master/router key，私钥只存密文。 |
| TLS-012 | 待外部 | Cloudflare Full (strict) 源站证书需真实 Zone/代理环境签收。 |
| USR-001 | 本地通过 | 停用后 login/API/WebSocket/Plugin 全部拒绝。 |
| USR-002 | 本地通过 | 停用不释放端口和域名记录。 |
| USR-003 | 本地通过 | 删除按 Domain、Mapping、DNS、凭证顺序进入持久化 Operation。 |
| USR-004 | 本地通过 | 外部清理失败保留本地 Operation/residue，不宣称成功。 |
| USR-005 | 本地通过 | 可取消阶段可取消，不可逆阶段只能补偿/完成。 |
| USR-006 | 本地通过 | force delete 生成外部残留和审计。 |
| USR-007 | 本地通过 | 所有用户资源查询带 user_id 权限过滤，越权测试通过。 |
| KEY-001 | 本地通过 | master、config signing、router、certificate wrapping、backup key 用途分离。 |
| KEY-002 | 本地通过 | 主密钥文件重启稳定，旧密文可解密。 |
| KEY-003 | 本地通过 | 主密钥不写普通 DB、不进日志。 |
| KEY-004 | 部分通过 | 版本化 master/certificate key-ring、旧版本解密、`make key-rotate` 和 FRP/Cloudflare/证书私钥重包裹回归测试已通过；完整生产轮换窗口与回滚演练仍待外部环境。 |
| BKP-001 | 本地通过 | FPPB1 全包 AES-GCM 加密、manifest SHA-256 校验。 |
| BKP-002 | 本地通过 | SQLite WAL 下 VACUUM INTO/恢复和 integrity_check 测试通过。 |
| BKP-003 | 本地通过 | 无密码无法解包读取秘密。 |
| BKP-004 | 本地通过 | 恢复撤销 Session/Runtime Credential、保留 before-restore 副本并触发 Router 重建。 |
| BKP-005 | 本地通过 | JSON/备份输出不包含明文 Token、Cookie、密码或私钥。 |

## API、性能、稳定性和安全

| ID | 状态 | 实际结果与证据 |
|---|---|---|
| API-001 | 本地通过 | Server OpenAPI 3.1 34 paths/39 operations 与 chi route manifest 对齐；Client Local API 20 paths/23 operations 也与独立 route manifest 对齐；成功 JSON 响应均声明 schema（含统一 `request_id` 元数据），`/me` 的实际会话字段已纳入契约；`contracts/generated/server-api.d.ts`、`contracts/generated/client-api.d.ts`、响应契约测试和生成文件漂移检查已纳入 CI。 |
| API-002 | 本地通过 | Problem Details、稳定 code、request_id 和错误测试通过。 |
| API-003 | 本地通过 | 权限中间件分离，越权拒绝不暴露资源存在性。 |
| API-004 | 本地通过 | 不支持 HTTP/WS protocol 返回 426。 |
| API-005 | 本地通过 | Client 发送 `X-FRP-Client-Version`；过旧/非法版本返回 426、`Upgrade-Required` 和 `CLIENT_VERSION_UNSUPPORTED`，兼容版本可登录并显示可升级提示，回归测试通过；Server/Client 发行版本可由独立 `-ldflags` 注入并进入 compatibility API。 |
| API-006 | 本地通过 | WebSocket 指数退避、抖动、lease heartbeat 测试通过。 |
| API-007 | 本地通过 | 丢通知触发 full sync，配置 hash/version 收敛测试通过。 |
| PERF-001 | 本地通过 | 本机 profile 通过；Ubuntu 24.04 hosted run 31191465839 的 100 并发读 p95=102.321716ms、错误率 0；固定 Linux 2 vCPU/2 GiB release 基线仍待签收。 |
| PERF-002 | 本地通过 | 本机 profile 通过；同一 hosted run 的 20 并发写 p95=45.921474ms、错误率 0；目标机基线仍待外部。 |
| PERF-003 | 部分通过 | Ubuntu 24.04 hosted run 31191465839 的 1000 Mapping + 2000 Domain Router snapshot generate/apply=523.973835ms；固定目标硬件结果尚未签收。 |
| PERF-004 | 本地通过 | snapshot reload 不主动中断 in-flight HTTP 流。 |
| PERF-005 | 本地通过 | 本机 profile 通过；同一 hosted run 的 200 Mapping config generate/sign=4.54487ms；目标机结果待外部。 |
| PERF-006 | 本地通过 | 本机 profile 通过；同一 hosted run 的配置提交到 Client apply=6.235335ms；目标网络矩阵待外部。 |
| PERF-007 | 本地通过 | 本机 profile 通过；同一 hosted run 的 WebSocket=65.514317ms、旧 HTTP=0.376666ms、旧 FRP Login=0.325481ms；生产延迟基线待外部。 |
| REL-001 | 本地通过 | Supervisor 临时配置/last-good/重启恢复测试通过。 |
| REL-002 | 本地通过 | Port lease/Mapping 事务和 SQLite rollback race 测试通过。 |
| REL-003 | 本地通过 | Worker lease、ambiguous Provider query 和 malformed payload recovery 测试通过。 |
| REL-004 | 本地通过 | Router bad snapshot 保留 last-good 测试通过。 |
| REL-005 | 部分通过 | WAL bytes 指标、checkpoint 命令和 `TestCheckpointUnderWALPressure` 已通过；Ubuntu 24.04 `make fault-injection` 会在 disposable tmpfs 中验证 WAL 压力、checkpoint 和重启恢复，长时间/生产磁盘演练仍待外部。 |
| REL-006 | 本地通过 | WebSocket 断线后全量同步/心跳恢复测试通过。 |
| REL-007 | 部分通过 | Ubuntu 24.04 [`ci` run 31189601927](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/31189601927) 的 disposable 32MiB tmpfs 真实填满文件系统，验证 Router 原子写失败不覆盖 last-good；本地 backup archive 无 partial output、restore post-install 失败回滚测试通过；目标部署磁盘演练仍待外部。 |
| REL-008 | 部分通过 | 同一 Ubuntu 24.04 fault-injection job 验证 Cloudflare/ACME Provider Date 偏差的 fail-safe 路径；真实系统时钟偏差、Session/ACME 长时行为仍待外部。 |
| SEC-001 | 本地/CI 通过 | 本地 gosec/govulncheck 和 secret scan 清零；最终提交 [`2f73156`](https://github.com/sshiong/frp-panel-platform-v3/commit/2f731567da6933d4fc2ae1db333ad9d61fc2ca19) 的 [`ci` security job](https://github.com/sshiong/frp-panel-platform-v3/actions/runs/30745496136) 与 CodeQL 均成功，双 gosec SARIF 已独立上传。 |
| SEC-002 | 本地通过 | Auth/domain/port/file path 权限测试和 race 测试通过。 |
| SEC-003 | 本地通过 | CSRF、CORS、Origin、Host、WebSocket 和 XSS 边界测试通过。 |
| SEC-004 | 本地通过 | Server URL parser 拒绝危险 Scheme/Userinfo/redirect 绕过。 |
| SEC-005 | 本地通过 | Secret scan 与日志脱敏测试未发现密码、Token、Cookie、私钥。 |
| SEC-006 | 本地通过 | Plugin provider unavailable/timeout fail-closed 测试通过。 |
| SEC-007 | 本地通过 | Domain、URL、IDNA、Snapshot、JSON fuzz seed/短时 fuzz 已纳入 CI。 |
| SEC-008 | 部分通过 | SPDX SBOM、SHA-256、manifest 和 release cosign workflow 存在；签名后会校验 GitHub Actions OIDC issuer 与当前 workflow/ref，正式 tag 签名结果仍待发布环境。 |

## UI、DoD 和发布结论

| ID | 状态 | 实际结果与证据 |
|---|---|---|
| UI-001 | 本地通过 | Admin/Client 登录字段、路由和组件完全独立；390×844 Playwright 检查通过。 |
| UI-002 | 本地通过 | 删除、Token 清除、凭证重置、DNS 冲突均有统一确认、reauth/倒计时和防重复提交。 |
| UI-003 | 本地通过 | reserved/pending/running/offline/error 文案和状态色分离。 |
| UI-004 | 本地通过 | Cloudflare capability missing 列表在 Admin UI 展示。 |
| UI-005 | 本地通过 | DNS adopt/overwrite/cancel 与 managed/adopted 文案一致。 |
| UI-006 | 本地通过 | Token 页面只显示 configured/status/version/verified_at。 |
| UI-007 | 本地/CI 通过 | Admin/Client 构建后运行 axe WCAG 2.1 AA、表单标签、键盘 Tab/reduced-motion、390px 无横向溢出检查均通过；PR #2 的 `web (admin)` 与 `web (client)` 门禁通过。 |
| UI-008 | 本地通过 | Operations 展示阶段、步骤、失败原因、residue 和 retry。 |
| DOD-001 | 待外部 | 所有 P0/P1 尚未完成真实 Cloudflare、ACME、Linux/FRP、灾备和签字，因此当前版本不是 Release Candidate。 |

## 发布前剩余动作

1. 已完成最终提交的 `ci`、CodeQL、container scan 和 release metadata 全绿，并把 run URL/commit 写入 [`PROGRESS.md`](../PROGRESS.md)。
2. 已完成仓库治理：仓库保持公开，`main` 启用保护、线性历史、禁止强推/删除、CODEOWNERS、两次审批和必需 CI/CodeQL 检查；正式安全/数据库/加密变更仍需在 CODEOWNERS 中补入指定的第二位专业评审者。
3. 在 Linux 目标机完成 FRPS/FRPC Plugin、PERF、disk-full/clock、clean-host
   restore；在 Cloudflare Sandbox 与 ACME Staging 完成 DNS/证书链路。
4. 以 tag 发布双发行物，验证签名、SBOM、SHA-256、migration、升级/回滚文档，
   再由发布/安全/测试负责人签字。
