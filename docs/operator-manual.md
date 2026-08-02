# 管理员与用户操作手册

## 管理员

1. 启动 Server 后从权限为 0600 的 `initial-admin.txt` 取得一次性凭据。
2. 登录 Admin Panel；首次生成的管理员必须同时修改用户名和密码，普通初始用户只能修改密码。
3. 在 Users 页面创建、停用、重置密码、重置 FRP 凭证或进入删除补偿流程。敏感操作先完成 5 分钟 reauth ticket。
4. 在 Cloudflare 页面提交 Token。页面只显示配置/验证状态和缺失权限，不显示 Token；新 Token 验证成功前旧 Token 保持 active。
5. 在 Operations 页面查看 DNS、证书、删除和外部残留阶段；失败 Operation 只能通过重试入口重新入队。
6. 在 System 页面查看 Router/备份状态。备份密码应通过受保护渠道交付；恢复前停止 Server，恢复后执行 checkpoint/完整性检查并重新生成 Router Snapshot。

停用或删除用户会立即撤销 Session/Runtime Credential；Mapping、Domain、受管 DNS 按依赖顺序补偿。外部清理失败时不得把本地成功当成外部成功，必须处理 Operation 的 residue 清单。

## 普通用户

1. 在 Client Panel 输入 Server Panel HTTPS 地址、用户名和密码；Client 不建立本地用户体系。
2. 首次登录先修改初始密码。Server 不可达时只能查看仍在本地有效期内的只读缓存，不能创建/修改/删除资源。
3. 在 Mappings 创建 TCP/UDP/HTTP Mapping。Server 先保留端口和 Revision；Client 验证本地服务、固定 FRPC 配置并成功应用后才显示 running。
4. 在 Domain Binding 中选择已有 HTTP Mapping，设置域名、A/AAAA/CNAME、TTL 和 HTTPS 模式。`pending_dns`、`pending_certificate`、`pending_router`、`offline` 和 `error` 不等同于 active。
5. DNS 冲突时明确选择仅接管、覆盖或取消；仅接管的外部记录在删除 Domain 时不会被面板删除。
6. 重置自己的 FRP 凭证后旧 Session/FRPC 会停止，需要重新登录。退出、Session 替换和用户停用也会清除 Client 运行时秘密。

任何写操作失败都应保留页面展示的 request ID；用它在 Server 审计/Operation 中定位，不要重复发送同一个写请求体而不保留 Idempotency-Key。
