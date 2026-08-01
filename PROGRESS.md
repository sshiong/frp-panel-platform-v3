# FRP Cloudflare Platform v3 进度跟踪

> 最后更新：2026-08-01
>
> 本文是实现进度的单一记录入口。每次完成一个可验证的垂直切片，更新状态、证据和未决项；未通过验收的能力不得标记为完成。

## 当前状态

| 阶段 | 状态 | 证据 |
|---|---|---|
| 阶段 0：技术验证 | 进行中 | Server/Client Supervisor 与 Router/Provider 接口已建立；Provider 无监听单测通过，真实 FRPS/Cloudflare/ACME E2E 待外部环境 |
| 阶段 1：身份与基础安全 | 进行中 | Argon2id、单活动 Client Session、审计、地址规范化 API 已实现，待自动化验收 |
| 阶段 2：Client/FRPC 闭环 | 进行中 | Supervisor 串行队列、verify/原子写入/last-good 回滚已实现，真实 frpc 二进制兼容测试待补 |
| 阶段 3：TCP/UDP Mapping | 进行中 | Mapping/Revision/Port Lease/幂等 API 已实现，待 FRPS Plugin E2E |
| 阶段 4：域名和 Cloudflare | 进行中 | Domain/DNS/Token 加密模型与 Operation API 已实现，Provider 实际调用待配置 Token |
| 阶段 5：Router 和证书 | 计划 | Snapshot/Provider 边界已预留，ACME/真实 Router 热切换未完成 |
| 阶段 6：任务、删除、备份和发布 | 进行中 | Job/Audit/导出、加密备份 Decode/Restore 与 CI 基线已建立；SBOM、签名待完成 |

## 已实现

- [x] 单仓库、多模块：`server/`、`client/`、`contracts/`、`web/admin/`、`web/client/`。
- [x] Server SQLite WAL、外键、busy timeout、synchronous FULL、顺序 migration。
- [x] 管理员初始化、Argon2id 密码哈希、首次改密限制。
- [x] 不透明服务端 Session；普通用户 Client Panel 全局单活动 Session；Session generation 替换旧会话。
- [x] API Problem Details、请求 ID、CORS/安全 Header、限速边界和敏感日志过滤。
- [x] Mapping 归属用户；不可变 Revision；端口全局唯一租约；配置版本与 expected version 冲突。
- [x] 写 API 的 Idempotency-Key；审计记录；用户资源 SQL 级 `user_id` 过滤。
- [x] Client Server 地址规范化（Scheme/Host/端口/IPv6/Userinfo/Path 校验）。
- [x] Client 内存 Local Proxy Session；Server token 不进入 localStorage；单 Supervisor 队列与原子配置回滚。
- [x] 两个独立 Vue 前端，采用石墨/象牙/钢蓝/状态色视觉体系，不使用浅紫色。
- [x] Client Panel 提供 Mapping 与 Domain Binding 独立导航，展示 IDNA 标准化结果、HTTPS 模式和 pending/active 状态。
- [x] Cloudflare Provider HTTP 适配器支持 Verify/ListZones/UpsertDNS/DeleteDNS，并以独立单元测试覆盖请求方法与路径。
- [x] FPPB1 加密备份使用随机 per-package salt；提供解密、SQLite integrity check 和带 `.before-restore-*` 保留副本的原子恢复函数。
- [x] `/internal/frp/plugin` 增加 loopback-only 网络边界；Cloudflare Token 替换保留旧版本直到新版本完成 pending 验证。

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

## 未决与发布阻断项

以下不是“已实现”的替代品，必须在发布前完成：

1. 真实固定版本 FRPS/FRPC 二进制的 Login/NewProxy/Ping/WorkConn Plugin E2E。
2. Cloudflare Sandbox Token 权限、DNS 三种冲突语义和超时补偿。
3. ACME DNS-01 Staging、证书私钥独立包装密钥、Router SNI/Host 热切换。
4. 加密归档备份恢复、灾备演练、WAL checkpoint 监控和磁盘满故障注入。
5. OpenAPI contract test、Fuzz、SAST/SCA/secret scan、真实性能基线、SBOM/签名。
6. 完成 P0/P1 全量验收前，仓库只能作为开发预览，不得声明生产就绪。

## 更新规则

- 只在有文件、测试输出、运行日志、截图或外部环境结果等证据时推进状态。
- 外部凭据/真实 FRPS/ACME 未配置时，UI 必须显示 pending/blocked/error，不得显示 active/running。
- 每次实现变更都要同步错误码、API contract、文档和对应测试。
