# FRP Cloudflare Platform v3 威胁模型

本文记录编码前确定的信任边界、资产、攻击者能力和主要缓解措施。它不是渗透测试报告；真实 Cloudflare、ACME、Linux FRP 矩阵和发布扫描仍需在对应环境执行。

## 资产与信任边界

| 边界 | 受保护资产 | 进入/离开方式 |
|---|---|---|
| 管理员浏览器 ↔ Server Panel | 管理员 Session、CSRF、用户/资源操作 | HTTPS、HttpOnly/SameSite Cookie、会话绑定 CSRF、Problem Details |
| 用户浏览器 ↔ Client Panel | 本地会话、FRPC 运行状态 | 默认 loopback；LAN 必须显式开启、CIDR/Host allowlist、HTTPS、Origin、CSRF |
| Server Panel ↔ SQLite | 用户、租约、Revision、Operation、审计、加密秘密密文 | 单连接 WAL、外键、事务、migration、敏感字段不明文返回 |
| Client Panel ↔ Server Panel | Server 地址、短期 opaque Session、签名配置 | HTTPS 生产强制；拒绝重定向；Bearer 仅内存；Ed25519 全量配置验签 |
| Server ↔ FRPS Plugin | FRP 原生 Token、用户 Secret、Runtime Credential | transport token 文件化；Plugin loopback-only；每个操作重新校验用户/Session/generation/Revision/端口/域名 |
| Server ↔ Cloudflare/ACME | Token、DNS 记录、ACME 账户、证书私钥 | Token/账户/证书分用途加密；外部调用超时；权限失败不重试；Operation/Job 补偿 |
| Control ↔ Router | 路由快照、证书集合 | HMAC/hash、原子写、last-good、DB-free Router、未知 SNI fail-closed |

## 攻击者能力

- 未登录公网请求者：可发送任意 HTTP、Host、Origin、JSON、WebSocket 和 FRP Plugin 输入。
- 已登录普通用户：可控制自己的资源，尝试枚举或修改其他用户 ID、端口、域名、Revision 和配置版本。
- 被盗用的普通用户 Session：可在有效期内调用其授权 API，但不能读取其他用户资源或控制面板管理 API。
- 恶意本地用户：可读取 Client 所在主机可访问的文件/进程，但不能通过面板 API 获得本地管理员绕过；运行时秘密使用 0600 并在退出/替换时清除。
- 外部 Provider 的超时、权限变化、部分成功或返回异常：系统必须保持 pending/failed/residue，而不是将外部成功假设为本地成功。

不假设主机 root、部署密钥、数据库文件和 TLS 私钥已经被攻破；这些属于基础设施响应范围。

## 主要滥用路径与控制

1. 越权读取：所有用户资源 SQL 带 `user_id` 过滤；管理员路由独立 middleware；不存在的资源使用统一 Problem Details。
2. Session 替换绕过：Client Session 使用唯一活动索引、generation 和 revoked_at；旧 HTTP/WS/FRP Runtime Credential 在每次请求/Plugin 操作重验。
3. CSRF/重定向窃取：浏览器写请求要求会话绑定 CSRF；Client/Provider HTTP client 不跟随重定向。
4. 端口/Revision 重放：端口 lease 使用数据库唯一约束；写请求校验 expected version/revision 和 Idempotency-Key；同键不同请求体返回冲突。
5. Plugin 伪造：仅 loopback Plugin 入口接受请求；transport token 不等于用户授权；Plugin 每次解析并校验完整 metadata，未知操作 fail-closed。
6. 配置/快照篡改：Server Ed25519 签名、Router HMAC/hash、原子替换和 last-good；Client 在 `frpc verify` 前不替换 active 配置。
7. DNS/证书外部部分成功：Provider 请求有超时和时钟检查；DNS 任务可重试/查询实际状态；ACME TXT 传播/清理失败保持错误或补偿状态。
8. 日志泄密：日志和审计禁止密码、Cookie、Authorization、Token、FRP Secret、证书私钥和主密钥；request ID、资源 ID 和白名单错误上下文用于追踪。
9. 磁盘/进程故障：SQLite WAL + checkpoint、FPPB 加密备份、临时文件 + fsync + rename、FRPC last-good、Router last-good 和进程孤儿回收。

## 残余风险与验证

- 生产 TLS 证书链、Cloudflare Token 最小权限、ACME Staging DNS-01、Linux FRPS/FRPC 组合和 cosign/SAST/SCA 结果必须由发布环境提供证据。
- 本地测试覆盖协议、模拟 Provider、固定官方 FRP v0.68.0 网络 Plugin、故障边界和性能；不能替代真实外部系统签收。
