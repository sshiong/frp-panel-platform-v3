# 稳定错误码

Server API 错误使用 RFC 9457 Problem Details，响应包含 `type`、`title`、`status`、`detail`、`instance`、`code` 和 `request_id`。`detail` 面向用户，日志使用 `code`、资源 ID 和 request ID，不记录敏感请求体。

| 错误码 | HTTP | 含义 | 客户端动作 |
|---|---:|---|---|
| `AUTH_INVALID_CREDENTIALS` | 401 | 用户名/密码或一次性凭据错误 | 重新输入；不要无限重试 |
| `AUTH_REAUTH_REQUIRED` | 401 | 敏感操作缺少/过期二次认证票据 | 重新输入当前密码取得 ticket |
| `AUTH_PASSWORD_CHANGE_REQUIRED` | 403 | 首次生成凭据尚未完成修改 | 只调用修改凭据接口 |
| `SESSION_EXPIRED` | 401 | Session 超时或已撤销 | 重新登录 |
| `SESSION_REPLACED` | 401 | 普通用户 Session 被新登录替换 | 停止 FRPC 并重新登录 |
| `AUTH_USER_DISABLED` | 401 | 用户已停用 | 联系管理员 |
| `FORBIDDEN` | 403/404 | 无权限；资源存在性不泄漏 | 不重试越权请求 |
| `IDEMPOTENCY_KEY_REQUIRED` | 428 | 写请求缺少 16–128 字符幂等键 | 生成新的 UUIDv7 幂等键 |
| `IDEMPOTENCY_KEY_REUSED` | 409 | 同一幂等键对应不同请求体 | 刷新资源并使用新键 |
| `IDEMPOTENCY_LOOKUP_FAILED` | 500 | 幂等记录暂时不可读 | 稍后使用同一键重试并检查 Server 存储 |
| `IDEMPOTENCY_RESPONSE_UNAVAILABLE` | 500 | 幂等响应无法用当前主密钥恢复 | 停止重复写入并联系管理员检查密钥/备份 |
| `CONFIG_VERSION_CONFLICT` | 409 | 期望配置版本过期 | 重新读取并合并后提交 |
| `RESOURCE_REVISION_CONFLICT` | 409 | Mapping Revision 过期 | 重新读取资源后提交 |
| `PORT_ALREADY_RESERVED` | 409 | 端口已被有效 lease 占用 | 选择其他端口或自动分配 |
| `QUOTA_EXCEEDED` | 429 | 资源或 pending 配额已满 | 等待 Operation 或联系管理员 |
| `INVALID_JSON` | 400 | JSON、字段或请求体格式错误 | 按契约修正字段；不发送未知字段 |
| `REQUEST_BODY_TOO_LARGE` | 413 | 请求体超过 1 MiB 限制 | 缩小请求体后重试 |
| `UPGRADE_REQUIRED` | 426 | 协议版本不支持 | 升级 Client/FRPC 到兼容版本 |
| `SERVER_TLS_VALIDATION_FAILED` | 400/502 | Server Panel TLS 未通过系统信任或已固定指纹校验 | 检查证书；未发送密码前完成 CA/SPKI 信任 |
| `SERVER_CERTIFICATE_INSPECTION_FAILED` | 400 | 无法在发送密码前读取 Server Panel 证书 | 检查地址、端口和 TLS 服务 |
| `FRPC_VERIFY_FAILED` | 400/502 | 固定 FRPC 未接受新配置 | 保留 last-good，检查二进制/本地服务 |
| `CLOUDFLARE_TOKEN_INVALID` | 400 | Token pending 验证失败 | 修正权限；旧 active Token 保持不变 |
| `CLOUDFLARE_PERMISSION_DENIED` | 403 | 缺少具体 Provider 权限 | 查看 capabilities.missing 后补权限 |
| `DNS_CONFLICT_REQUIRES_ACTION` | 409 | 外部 DNS 已存在且未选择策略 | 选择 adopt、overwrite 或 cancel |
| `FRP_RUNTIME_CREDENTIAL_INVALID` | 403 | FRP Plugin Runtime Credential/generation 不匹配 | 停止重放，刷新配置/Session |
| `FRP_USER_CREDENTIAL_INVALID` | 403 | FRP 用户 Secret 或映射归属不匹配 | 重新登录并获取当前配置 |

未知错误不得把底层密码、Token、Cookie、私钥或完整 Authorization 放入 `detail`；5xx 只返回通用服务不可用文案。
