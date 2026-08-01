# FRP 多用户云隧道管理平台技术设计方案 v3

> 文档状态：开发基线 / 验收基线
> 适用产品：`frp-panel-server`、`frp-panel-client`
> 数据库基线：SQLite + WAL
> 文档版本：v3.0
> 更新日期：2026-08-01

---

## 0. 文档目的与规范性说明

本文件是 FRP 多用户云隧道管理平台 v3 的完整技术、开发和验收基线，用于统一：

- 产品边界；
- 术语和字段命名；
- 系统架构；
- 安全边界；
- 数据模型；
- API、WebSocket 和状态机；
- FRPC/FRPS 管理流程；
- Cloudflare、DNS、证书和 Router 自动化；
- 开发、测试、发布和运维标准；
- 功能、安全、性能、可靠性和恢复验收标准。

本版本以最终收口规则为准，明确删除永久 Client 设备绑定、设备注册、设备 HMAC、`device_token` 和永久 `client_id` 模型。

### 0.1 规范词

本文中的规范词具有以下含义：

| 规范词 | 含义 |
|---|---|
| **必须 / MUST** | 实现和验收的强制要求，不满足则不得发布 |
| **禁止 / MUST NOT** | 绝对不允许的实现 |
| **应该 / SHOULD** | 默认必须执行，只有记录充分理由并经评审后才能偏离 |
| **不应该 / SHOULD NOT** | 默认禁止，只有记录充分理由并经评审后才能采用 |
| **可以 / MAY** | 可选能力，不影响基础验收 |

### 0.2 决策优先级

发生设计冲突时按以下顺序裁决：

1. 本文“最终强制规则”；
2. 本文数据库约束、状态机和验收标准；
3. 已发布的版本化 OpenAPI、WebSocket Schema 和数据库 migration；
4. 代码实现；
5. UI 文案。

代码和 UI 不得反向定义产品规则。

---

# 第一部分：产品定义与系统边界

## 1. 最终产品模型

系统只有两个独立产品：

```text
frp-panel-server
frp-panel-client
```

两者必须：

- 独立编译；
- 独立发布；
- 独立部署；
- 独立运行进程；
- 独立前端；
- 独立后端；
- 不共享业务数据库；
- 不互相读取对方本地文件；
- 只通过版本化 HTTPS REST API 和 WebSocket 通信。

部署 `frp-panel-server` 不会自动部署 Client Panel；部署 `frp-panel-client` 不包含管理员后台。

## 2. Server Panel 定义

Server Panel 部署在公网 FRPS 服务器，是全局控制面和资源权威源。

必须负责：

- 管理员登录和管理员会话；
- 普通用户创建、停用、删除和密码管理；
- Client Panel 用户认证和单活动 Client Session；
- 平台管理的 FRP 用户凭证和会话级 FRP 运行凭证；
- 用户 Mapping、Revision 和配置版本；
- 远程端口全局分配和强占用约束；
- 业务域名全局占用；
- Cloudflare Token 加密存储与权限验证；
- Cloudflare DNS 创建、修改、同步和清理；
- ACME 证书申请、续期和异常恢复；
- Server Router 的控制路由和业务路由；
- FRPS Plugin 二次鉴权；
- 后台任务、Operation、补偿和重试；
- SQLite 中央数据库；
- 审计、日志、指标、加密备份和恢复。

Server Panel 不得直接读写 Client Panel 本地 `frpc.toml`，只能发布期望配置并接收应用结果。

## 3. Client Panel 定义

Client Panel 部署在用户本地，是带 Web UI 的常驻本地服务，同时承担原本 Agent 的职责。

必须负责：

- 显示普通用户登录页面；
- 连接用户填写的 Server Panel；
- 代理用户向 Server Panel 登录；
- 在内存中维护当前活动 Server Session；
- 管理一个本地 FRPC 进程；
- 拉取当前用户的完整期望配置；
- 生成、校验、原子替换和回滚 `frpc.toml`；
- 执行 FRPC `verify`、`start`、`stop`、`reload` 和 `restart`；
- 检查本地 TCP、UDP 和 HTTP 服务；
- 串行化所有 FRPC 进程和配置操作；
- 上报配置版本、应用结果、FRPC 状态和错误；
- 展示脱敏本地日志。

Client Panel 不建立本地用户体系，不拥有管理员后台，不保存 Cloudflare Token。

## 4. 明确删除的旧模型

v3 禁止实现以下概念：

```text
永久 client_id
installation_instance_id
owner_user_id
设备首次注册
设备绑定确认
设备名称确认
device_token
device_credentials
device_request_nonces
frp_device_token
设备 HMAC 注册
设备凭证轮换
解除设备
切换设备所属用户
CLIENT_OWNER_MISMATCH
server_binding_revision
危险切换 Server Panel
```

同时禁止出现以下用户操作：

- 将当前安装实例绑定到账号；
- 退出并解除当前设备；
- 撤销设备凭证；
- 重新注册设备；
- 设备 Token 轮换；
- 切换设备所属用户。

`server_instance_id` 可以保留为 Server Panel 自身的备份、恢复和实例识别字段，但不得用于建立永久 Client 绑定，也不得阻止用户修改 Server Panel 地址。

## 5. 数据权威边界

### 5.1 Server Panel 是最终依据

以下数据必须以 Server Panel 数据库为准：

- 用户、角色、状态和密码状态；
- 当前活动 Client Session；
- `session_generation`；
- FRP 用户凭证和运行凭证；
- Mapping、Revision 和期望状态；
- 远程端口租约；
- Domain Binding 和 DNS 关系；
- Cloudflare Token 状态；
- HTTPS 模式；
- 证书和 Router 配置版本；
- 配额、删除状态和审计记录。

### 5.2 Client Panel 是本地运行状态依据

以下数据以当前在线 Client Panel 实际检测结果为准：

- FRPC 是否运行；
- 实际加载的配置哈希；
- `applied_config_version`；
- FRPC reload/restart 是否成功；
- 本地目标端口是否可达；
- 本地日志；
- 当前代理是否在 FRPC 中建立；
- 最近一次成功应用的 Revision。

Server 保存“期望状态”，Client 上报“实际状态”。不得把数据库插入成功直接显示为 `running`。

---

# 第二部分：术语、定义与命名标准

## 6. 核心术语表

| 术语 | 正式定义 |
|---|---|
| Server Panel | 公网控制面、认证方和全局资源仲裁方 |
| Client Panel | 用户本地控制服务和 FRPC Supervisor |
| Client Session | 普通用户通过某个 Client Panel 登录 Server Panel 后创建的唯一活动远程会话 |
| Local Proxy Session | 浏览器与本地 Client Panel 之间的临时代理会话，不代表独立用户 |
| Session Generation | 用户每次成功创建新 Client Session 时递增的世代号，用于使旧 Client 和旧 FRP 运行凭证失效 |
| Mapping | 一个可被 FRPC 应用的本地服务转发定义 |
| Mapping Revision | Mapping 的不可变配置版本 |
| Active Revision | 当前已成功应用的 Revision |
| Pending Revision | 已被 Server 保留、等待 Client 应用的 Revision |
| Port Lease | 数据库中对远程端口的强占用记录 |
| Domain Binding | 业务域名与 HTTP Mapping 的绑定 |
| Operation | 跨数据库、Client、Cloudflare、ACME 或 Router 的长流程状态记录 |
| Job | 可重试、可租约接管的后台任务 |
| Router Snapshot | Control 生成、Router 只读加载的版本化路由快照 |
| FRP Runtime Credential | 绑定当前 Client Session 和 generation 的短期 FRP 运行凭证，不是设备凭证 |
| Desired Config Version | Server 期望 Client 应用的用户配置版本 |
| Applied Config Version | 当前在线 Client 最近成功应用的版本 |

## 7. 地址术语和字段命名

所有 UI、API、数据库和日志必须使用明确术语，禁止只写“服务器地址”“IP”“域名”等模糊名称。

| 术语 | 推荐字段 | 示例 | 用途 |
|---|---|---|---|
| Client Panel 访问地址 | `client_panel_access_url` | `https://192.168.1.20:7410` | 浏览器访问本地 Client Panel |
| Server Panel 连接地址 | `server_panel_url` / `normalized_server_url` | `https://panel.example.com:8443` | Client 登录和调用 Server API |
| FRPS 监听地址 | `frps_bind_address`、`frps_bind_port` | `0.0.0.0:7000` | FRPS 服务端监听，不得下发为公网地址 |
| FRPS 公网地址 | `frps_public_host`、`frps_public_port` | `frp.example.com:7000` | FRPC 连接 FRPS |
| 本地目标服务地址 | `local_ip`、`local_port` | `192.168.1.50:8080` | FRPC 转发目标 |
| 远程访问地址 | `remote_endpoint` | `frp.example.com:6000` | 外部访问 TCP/UDP Mapping |
| 业务映射域名 | `hostname`、`normalized_domain` | `app.example.com` | 外部访问 HTTP/HTTPS 服务 |

Server Panel 连接地址、FRPS 公网地址和远程访问地址必须分开计算、保存和展示。

## 8. Mapping 类型定义

v3 只支持以下业务 Mapping：

```text
tcp
udp
http
```

- `tcp`、`udp` 属于 IP+端口模式；
- `http` 属于域名模式；
- HTTPS 在 Server Router 终止，FRPC 后端仍是 HTTP Mapping；
- STCP、XTCP、SUDP、TCPMUX、P2P、文件服务等不属于 v3 必做范围。

## 9. 状态定义

### 9.1 用户状态

```text
active
disabled
deleting
deleted
```

### 9.2 Client Session 状态

```text
active
replaced
logged_out
expired
disabled
revoked
```

### 9.3 Mapping 生命周期状态

```text
reserved
pending_apply
running
offline
config_error
disabled
deleting
deleted
```

### 9.4 Revision 状态

```text
pending
applying
active
failed
superseded
rolled_back
```

### 9.5 Domain Binding 状态

```text
reserved
pending_dns
pending_client
pending_certificate
pending_router
active
offline
dns_error
certificate_error
router_error
deleting
deleted
```

### 9.6 Cloudflare Token 状态

```text
missing
pending
valid
invalid
permission_denied
retired
```

### 9.7 证书状态

```text
pending
valid
renewing
expired
blocked_missing_token
blocked_invalid_token
error
deleting
```

### 9.8 Job 状态

```text
pending
running
retry_wait
succeeded
failed
canceled
```

---

# 第三部分：总体架构与发行边界

## 10. 总体拓扑

```text
浏览器
  ↓ 本地 HTTPS/HTTP
frp-panel-client Web UI / Local API
  ↓ HTTPS REST + WebSocket
frp-panel-server Router / Control API
  ├── SQLite WAL
  ├── FRPS Plugin
  ├── Cloudflare API
  ├── ACME CA
  └── Router Snapshot

本地服务 ← FRPC ← FRPS ← 外部访问者
```

## 11. 两类业务入口

### 11.1 IP+端口模式

```text
访问者
  ↓
FRPS 公网主机:remote_port
  ↓
FRPS
  ↓
FRPC
  ↓
local_ip:local_port
```

该模式：

- 支持 TCP、UDP；
- 不需要业务域名；
- 不需要 Cloudflare；
- 不需要 DNS；
- 不需要证书；
- 不经过 Server Router；
- 不进入 ACME 任务；
- 平台不附加业务层 TLS。

### 11.2 域名模式

```text
访问者
  ↓
Cloudflare（可选）
  ↓
Server Router :80/:443
  ↓ TLS 终止、HTTP 反代
FRPS vhostHTTPPort（127.0.0.1）
  ↓
FRPC HTTP Mapping
  ↓
本地 HTTP 服务
```

## 12. 发行产物

### 12.1 `frp-panel-server`

必须包含：

- 管理员前端；
- Server Control API；
- Server Router；
- FRPS Plugin；
- 数据库 migration；
- Cloudflare Provider；
- ACME Manager；
- Job Worker；
- 审计和备份工具；
- 经过兼容性验证的 FRPS 二进制或明确的固定依赖方式。

禁止包含：

- Client 用户前端；
- FRPC Supervisor；
- Client 本地配置管理器。

### 12.2 `frp-panel-client`

必须包含：

- Client 用户前端；
- Local API；
- Server 登录代理；
- 单活动 Local Proxy Session Manager；
- FRPC Supervisor；
- 配置生成、verify、原子替换和回滚；
- 本地服务检测；
- Server REST/WebSocket 客户端；
- 经过兼容性验证的 FRPC 二进制。

禁止包含：

- 管理员后台；
- Server SQLite；
- Server Router；
- FRPS Plugin；
- Cloudflare Token 持久化；
- 任意命令执行接口。

## 13. 源码与模块边界

代码仓库采用单仓库、多模块结构，但构建图必须隔离：

```text
/server
/client
/contracts
/web/admin
/web/client
/build
/docs
```

强制规则：

- `server` 不得导入 `client` 内部包；
- `client` 不得导入 `server` 内部包；
- 两端只能共享 `/contracts` 生成的 OpenAPI、JSON Schema、错误码和枚举；
- `/contracts` 不得包含数据库实现、业务 Service 或秘密处理代码；
- CI 必须分别构建两个发行产物。

---

# 第四部分：技术选型

## 14. 后端技术

Server 和 Client 后端统一使用 Go。

固定选型：

- HTTP：`net/http` + `chi`；
- 数据访问：`database/sql` + `sqlc`；
- 数据迁移：顺序 migration，推荐 `golang-migrate`；
- SQLite：固定驱动版本，开启 WAL；
- WebSocket：固定维护中的 Go WebSocket 库；
- Cloudflare：官方 Go SDK 外包 Provider 接口；
- ACME：`go-acme/lego` 或同等成熟库，统一封装；
- 日志：结构化 JSON；
- 指标：Prometheus 格式；
- Trace：OpenTelemetry 接口，默认可关闭；
- 配置：TOML/YAML 只用于部署配置，业务数据进入数据库；
- 前端静态文件嵌入各自 Go 二进制。

禁止使用重量 ORM 隐藏事务和唯一约束。端口租约、Session 替换、Revision 切换和删除补偿必须使用显式 SQL。

## 15. 前端技术

两套前端独立构建：

- Vue 3；
- TypeScript 严格模式；
- Vite；
- Element Plus；
- Pinia；
- 统一由 OpenAPI 生成类型化 API Client；
- 禁止手写重复 DTO；
- localStorage 只保存 Server Panel 地址自动填充值和非敏感 UI 偏好。

## 16. 数据库标准

Server Panel 默认 SQLite，启动必须设置并校验：

```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
PRAGMA synchronous = FULL;
```

必须满足：

- 数据库位于本机磁盘；
- 禁止放在 NFS、SMB 和不可靠网络文件系统；
- 外部 Cloudflare、ACME、Router、FRP 操作不得发生在 SQLite 写事务中；
- 写事务必须短小；
- 必须提供 WAL checkpoint 监控和受控 checkpoint；
- 备份必须使用一致性快照，不得只复制主 `.db` 文件而忽略 WAL 状态。

## 17. FRP 版本标准

- Server 发行包固定一个已测试 FRPS 版本；
- Client 发行包固定同一兼容系列 FRPC；
- FRPC/FRPS 版本和 SHA-256 写入发布清单；
- 启动时校验二进制哈希；
- 禁止运行时从用户输入 URL 下载并执行 FRPC；
- 升级必须经过兼容矩阵和回滚验证；
- `frpc verify` 必须使用严格配置校验；
- 代理项变化可使用 `reload`；
- Server 地址、认证、WebServer 等公共配置变化必须使用 `restart`，不得错误地假设 reload 能修改公共参数。

---

# 第五部分：登录、Session 与地址配置

## 18. Client Panel 登录页

Client Panel 登录只需要：

```text
Server Panel 连接地址
用户名
密码
登录
```

UI 可以默认折叠地址字段，显示：

```text
用户名
密码
登录

配置 Server Panel 地址
```

点击后展开地址输入框。

Client Panel 不得显示：

- Client 名称确认；
- 设备注册；
- FRPS 地址；
- FRP Token；
- device_token；
- 本地管理员或本地密码。

## 19. Server Panel 管理员登录页

管理员登录页只显示：

```text
管理员用户名
管理员密码
登录
```

禁止显示：

- Server Panel 连接地址；
- 上游 Server 地址；
- Client Panel 地址；
- FRPS 地址输入框。

Server Panel 不连接另一个 Server Panel，但仍需部署级配置自身监听、公网 URL、管理员 Host、FRPS 地址和 TLS。

## 20. Server Panel 地址输入和规范化

接受：

```text
panel.example.com
panel.example.com:8443
203.0.113.10
203.0.113.10:8443
[2001:db8::1]
[2001:db8::1]:8443
https://panel.example.com
https://203.0.113.10:8443
```

未填写 Scheme 时补全 `https://`；未填写端口时使用 443。

拒绝：

```text
http://...                 # 除显式开发模式
https://user:pass@host
https://host/path
https://host?query=1
https://host#fragment
file://...
ftp://...
unix://...
```

规范化结果必须：

- Host 转小写；
- IDNA/Punycode 规范化；
- IPv6 使用方括号；
- 删除默认 `:443`；
- 不包含 Path、Query、Fragment、Userinfo；
- 解析后再次校验 Scheme 和目标。

## 21. IP 地址 TLS 规则

生产环境禁止“跳过 TLS 验证”。使用 IP 连接时必须满足以下至少一种方式：

1. Server 证书包含对应 IP SAN；
2. Client 管理员导入可信自定义 CA；
3. 首次连接显示证书主题、有效期和 SPKI SHA-256，由用户在未发送密码前明确核对并固定指纹。

指纹变化必须阻止登录并显示高风险警告，除非用户主动重新信任。

## 22. 地址保存规则

浏览器 localStorage 只允许保存：

```text
last_server_panel_url
非敏感 UI 偏好
```

禁止保存：

- 用户名；
- 密码；
- Server Session；
- Local Proxy Session；
- FRP Token；
- Cloudflare Token；
- Cookie；
- 证书私钥。

Client 后端可以持久化 `last_server_panel_url` 作为自动填充来源，但不得持久化 Server Session 明文。

用户可以自由修改 Server Panel 地址并重新登录，不需要比较 `server_instance_id`、解除设备或注册设备。

从当前 Server 切换到另一地址时，Client 必须执行以下非绑定式切换流程：

1. 验证新地址 TLS；
2. 使用新地址完成登录；
3. 新登录成功后停止当前 FRPC；
4. 尽力注销旧 Server Session；
5. 清除旧 Server Session、FRP Runtime Credential 和内存配置；
6. 拉取新 Server 的完整配置；
7. 校验并应用新配置；
8. 旧 Server 不可达时，本地也不得继续使用旧运行凭证，旧 Session 由服务端超时回收。

该流程不是设备解绑，也不要求 `server_instance_id` 相同。

## 23. 普通用户单活动 Client Session

强制规则：

> 同一个普通用户账号，同一时间只允许一个活动 Client Panel Session。

管理员 Session 不受该限制。

新 Client 登录必须在一个短事务中：

```text
验证密码和用户状态
  ↓
撤销该用户旧的 active client_panel Session
  ↓
增加 users.active_session_generation
  ↓
创建新 Session
  ↓
提交事务
```

数据库约束：

```sql
CREATE UNIQUE INDEX one_active_client_session_per_user
ON sessions(user_id)
WHERE login_channel = 'client_panel'
  AND revoked_at IS NULL;
```

新登录成功后：

- 旧 Client HTTP 请求返回 `401 SESSION_REPLACED`；
- 旧 WebSocket 关闭；
- 旧心跳和状态上报被拒绝；
- 旧 FRP Runtime Credential 失效；
- 旧 Client 立即停止 FRPC；
- 新 Client 拉取完整配置并成为执行端。

## 24. Client Panel 单活动浏览器会话

一个 Client Panel 进程同一时间只维护一个：

```text
active_proxy_session
```

新浏览器登录成功后，本地旧浏览器会话必须失效。该限制只发生在同一个 Client Panel 进程中。

Local Proxy Session 必须：

- 使用随机不可预测 Cookie；
- Cookie 设置 `HttpOnly`；
- 正式 HTTPS 模式设置 `Secure`；
- 设置 `SameSite=Strict`；
- 使用独立 CSRF Token；
- 只存于 Client 内存；
- 绑定对应 Server Session、来源 IP、User-Agent 和过期时间；
- Client 重启后全部失效。

Client Panel 不是独立认证方。Server Session 失效后，本地代理 Session 不得继续获得写权限。

## 25. Server Session 设计

采用服务端不透明 Session，不使用 localStorage JWT。

登录成功后 Server 生成：

- 256-bit 随机 Session Token；
- 只在 Client 内存保存明文；
- Server 数据库只保存 Token 哈希；
- Session 绑定 `user_id`、`session_generation`、`login_channel`；
- 设定绝对过期和空闲过期；
- 每次敏感安全事件可轮换 Token。

Client 后台调用使用：

```http
Authorization: Bearer <opaque_server_session_token>
```

必须通过 HTTPS；日志、错误和 Trace 必须过滤 `Authorization`。

不使用设备 HMAC、设备 Nonce 或永久后台凭证。

## 26. 心跳、租约和替换生效

默认：

- 心跳周期：30 秒；
- 随机抖动：±5 秒；
- Server 离线判定：连续 3 次心跳缺失；
- WebSocket 重连：指数退避，1 秒起步，上限 60 秒，并加入抖动；
- 401/403 不得自动无限重试。

Session 被替换或撤销时 Client 必须立即停止 FRPC。

网络中断时允许短暂运行宽限，但不得无限离线运行：

- Client 继续尝试恢复 Server Session；
- 超过配置的运行租约宽限期后停止 FRPC；
- 默认宽限期 120 秒；
- 恢复登录后拉取全量配置，不能仅依赖遗漏的 WebSocket 事件。

## 27. 初始密码与密码管理

Server 首次启动：

- 创建管理员 `admin`；
- 生成一次性随机 12 位以上高强度密码；
- 通过受保护初始化文件或本机终端显示；
- Docker 场景不得只依赖可能长期保留的普通容器日志；
- 首次登录必须修改管理员用户名和密码。

Server 必须提供：

- 普通用户修改密码；
- 管理员修改自己的用户名和密码；
- 管理员重置普通用户密码；
- 首次登录强制修改密码；
- 撤销指定 Session；
- 撤销用户全部 Session。

使用初始密码登录后只允许修改密码，禁止创建 Mapping、修改域名、上传 Cloudflare Token 或启动 FRPC。

密码使用 Argon2id，参数必须按部署硬件基准测试确定，并记录算法、参数、Salt 和版本，支持未来重新哈希。

---

# 第六部分：FRP 凭证、FRPS 鉴权与 Client 配置

## 28. FRP 凭证模型

每个普通用户拥有平台管理的：

- `frp_username`；
- 用户级 FRP Secret；
- Secret 版本。

用户登录页面不显示这些字段。登录成功后 Server 自动下发 FRPS 公网地址和当前运行所需的 FRP 配置。

为了使新 Client 替换旧 Client，Server 还必须签发会话级 `frp_runtime_credential`：

- 绑定 `user_id`；
- 绑定 `server_session_id`；
- 绑定 `session_generation`；
- 有短期过期时间；
- Server 仅保存哈希或可验证签名；
- 不持久绑定机器；
- Session 替换、退出、停用或过期后立即失效。

## 29. FRPS 原生认证与插件边界

FRP 原生 Token 是 FRPS 级公共认证能力，不能单独表达平台的用户、Mapping 和端口授权。

实现必须同时使用：

1. FRPS 原生安全传输/认证；
2. FRPS HTTP Plugin 二次鉴权；
3. FRP global metadata 携带用户、Session、generation 和运行凭证；
4. Proxy metadata 携带 `mapping_id` 和 `mapping_revision`。

任何 Client 即使手工修改 `frpc.toml`，也不得绕过 Plugin 创建未授权端口或域名。

## 29.1 FRPS 集群传输 Secret

由于 FRP 原生 `auth.token` 是 FRPS 实例级能力，v3 固定使用独立的：

```text
frps_transport_secret
```

它只用于通过 FRP 原生 Login 的第一层传输认证，不代表用户、Mapping、端口或域名授权。

规则：

- 由 Server 部署时生成并保存在受保护 Secret 文件；
- 通过当前有效 Client Session 临时下发到 Client；
- Client 写入只读运行时 Secret 文件，并通过 FRPC `tokenSource.file` 使用；
- 不在普通 UI 展示；
- 不写日志；
- 不进入 Client 持久化数据库；
- 登出、Session 替换、Client 重启或 Server 切换时清除；
- 即使该 Secret 被某个普通用户取得，FRPS Plugin 仍必须依靠用户 FRP Secret、Runtime Credential、generation、Mapping ID 和 Revision 做最终授权；
- Plugin 不可用、超时或返回异常时必须 fail-closed。

因此平台安全边界不是单独的 FRP 原生 Token，而是“原生传输认证 + Plugin 完整授权”。

## 30. FRPS Plugin 校验

### 30.1 Login

必须校验：

- 用户存在且为 active；
- `frp_username` 正确；
- 用户级 FRP Secret 正确；
- Server Session 仍 active；
- `session_generation` 等于用户当前 generation；
- FRP Runtime Credential 有效且未过期；
- Client/FRPC 版本满足最低要求。

### 30.2 NewProxy

必须校验：

- Mapping 属于当前用户；
- Mapping 类型与请求类型一致；
- Mapping 未 disabled/deleting/deleted；
- Revision 是当前允许应用的 active 或 pending Revision；
- TCP/UDP `remote_port` 与数据库 Port Lease 一致；
- HTTP `customDomains` 与 Domain Binding 一致；
- 代理名称符合平台命名规则；
- 禁止手工新增未授权代理。

### 30.3 Ping、NewWorkConn、NewUserConn

必须重复校验：

- Session 仍 active；
- generation 未过期；
- 用户未停用；
- Runtime Credential 未撤销。

旧 generation 必须拒绝新的工作连接。已建立连接通过 WebSocket、Client 停止、FRP 心跳和 Plugin 拒绝尽快清理。

## 31. FRPS 公网端点

部署配置必须同时区分：

```yaml
frps_bind_address: "0.0.0.0"
frps_bind_port: 7000
frps_public_host: "frp.example.com"
frps_public_port: 7000
```

`frps_bind_address` 不能下发给 Client。FRPC 必须使用 `frps_public_host/frps_public_port`。

TCP/UDP 远程访问地址固定由：

```text
FRPS 公网地址 + remote_port
```

生成，不得使用 Server Panel 管理域名或 Router 地址。

## 32. 配置版本

每个用户维护：

```text
desired_config_version
applied_config_version
last_failed_config_version
```

以下事件必须增加 `desired_config_version`：

- 创建、修改、删除或启停 Mapping；
- Domain Binding 影响 FRPC `customDomains`；
- FRP 用户 Secret 重置；
- FRPS 公网端点变化；
- 管理员强制全量同步；
- 兼容性所需配置变更。

Client 登录、重连或版本不一致时必须拉取完整配置。

## 33. 配置快照签名

Server 生成完整配置快照并使用独立 Ed25519 密钥签名：

```text
schema_version
config_version
user_id
session_generation
issued_at
expires_at
config_hash
signing_key_id
signature
payload
```

规则：

- 签名覆盖规范化完整 payload 和上述元数据；
- 签名密钥不得与 Server 主密钥、证书密钥或 Router HMAC 密钥共用；
- Client 通过已验证 HTTPS 获取当前公钥集；
- Client 必须先验签、再生成 `frpc.toml`；
- 签名失败不得应用配置；
- 配置快照不包含 Cloudflare Token、证书私钥或管理员秘密。

## 34. FRPC 配置组织

推荐：

```text
config/frpc.toml                  # 不含明文秘密的公共配置
config/confd/*.toml               # 代理配置
state/active-manifest.json
state/last-good-manifest.json
runtime/secrets/transport-token   # 临时文件
runtime/secrets/user-frp-secret   # 临时文件
runtime/secrets/runtime-token     # 临时文件
```

必须：

- 配置文件位于受控持久化目录；
- 运行时 Secret 位于独立临时目录，优先使用 tmpfs、操作系统 Runtime Directory 或等效安全位置；
- 不允许 UI 指定任意路径；
- Secret 文件权限仅服务用户可读；
- `frpc.toml` 只引用 Secret 文件路径，不嵌入明文；
- 配置快照和 last-good manifest 不包含 Secret 明文；
- 登出、Session 替换、Server 切换和 Client 重启时删除运行时 Secret；
- 日志禁止打印完整 Secret；
- 代理名称包含稳定 Mapping ID，不依赖用户可变名称；
- Client 只能管理平台命名空间中的代理。

## 35. FRPC 配置应用流程

```text
接收并验证完整配置快照
  ↓
检查 expected_config_version
  ↓
生成临时目录和 frpc.toml
  ↓
执行 frpc verify --strict-config
  ↓
备份当前有效配置和 manifest
  ↓
原子替换配置文件
  ↓
按变更类型执行 reload 或 restart
  ↓
查询 FRPC status / Plugin 状态
  ↓
确认所有期望代理建立
  ↓
提交本地 last-good
  ↓
向 Server 上报应用成功
```

失败时：

- 恢复上一份有效配置；
- 再次启动/reload 旧配置；
- 标记 `config_error`；
- 保留脱敏错误日志；
- 上报失败版本和错误码；
- 不释放旧端口或旧 Revision。

## 36. reload 与 restart 判定

- 仅代理项新增、修改、删除：优先 `reload`；
- 公共配置、Server 地址、认证、FRP 用户、WebServer 或传输参数变化：必须 `restart`；
- 无法安全分类时默认 `restart`；
- restart 必须由 Supervisor 串行执行并校验 PID；
- 禁止同时启动两个 FRPC。

## 37. FRPC Supervisor

所有操作进入单一队列：

```text
verify
apply
start
stop
reload
restart
rollback
status
```

必须满足：

- 同一时刻最多一个变更操作；
- 状态查询可以并发但不得修改；
- 进程 PID 和启动时间双重校验，防止误杀复用 PID；
- 进程退出自动收集 Exit Code；
- 不暴露任意命令、参数或 Shell；
- FRPC Admin API 只监听 127.0.0.1，并使用随机凭证或操作系统权限隔离；
- Client Panel 启动时必须识别并停止由上一进程遗留、但没有有效当前 Session 的 FRPC；
- Client Panel 启动、登出、Session 替换或 Server 切换时必须清理运行时 Secret 文件。

---

# 第七部分：Mapping、Revision 与端口

## 38. Mapping 数据模型

Mapping 归属于用户，不归属于永久 Client。

`mappings` 只保存身份和生命周期：

```text
id
user_id
name
proxy_type
lifecycle_status
desired_state
observed_state
active_revision_id
pending_revision_id
created_at
updated_at
```

所有可修改配置只保存在 `mapping_revisions`：

```text
id
mapping_id
revision
local_ip
local_port
remote_port NULL
health_check_json
status
created_at
applied_at
```

禁止在 `mappings` 和 Revision 重复保存 `local_ip`、`local_port`、`remote_port`。

## 39. Revision 规则

- Revision 创建后不可修改；
- 修改 Mapping 必须创建新 Revision；
- `active_revision_id` 指向当前已应用版本；
- `pending_revision_id` 指向等待 Client 应用版本；
- 应用成功后 pending 原子切换为 active；
- 应用失败后 pending 置 failed，active 保持不变；
- 旧 Revision 只读保留用于审计和回滚。

## 40. 端口唯一约束

```sql
UNIQUE(server_id, remote_port)
```

协议不进入唯一键。即使 TCP 和 UDP 不同，同一端口数字也不允许重复。

占用规则：

- Client 在线时占用；
- Client 离线时占用；
- FRPC 异常时占用；
- 用户停用时占用；
- `config_error` 时占用；
- pending 修改时新旧端口可以同时占用；
- 只有正式删除 Mapping 或修改成功释放旧租约后才释放。

## 41. 端口范围和保留

Server 配置必须定义：

```text
allocatable_port_ranges
system_reserved_ports
admin_reserved_ports
```

至少禁止普通用户申请：

- FRPS bind port；
- Server Panel 管理/API 端口；
- Router 80/443；
- FRPS vhostHTTPPort；
- 数据库、监控和内部 Plugin 端口；
- 操作系统明确保留端口。

自动分配必须在事务中尝试插入 Port Lease，冲突后选择下一个端口。前端“端口可用性检查”只用于提示，不构成占用。

## 42. 创建 Mapping 流程

```text
用户在 Client 填写类型、本地地址和端口
  ↓
Client 检查本地服务
  ↓
提交 expected_config_version + Idempotency-Key
  ↓
Server 校验用户和配额
  ↓
事务内创建 Mapping、Revision、Port Lease（如需要）
  ↓
状态 reserved / pending_apply
  ↓
增加 desired_config_version
  ↓
Client 拉取完整配置
  ↓
verify + apply + reload/restart
  ↓
Client 上报结果
  ↓
Server 将 Revision 设为 active，Mapping 设为 running
```

“服务端资源保留成功”和“客户端运行成功”必须分开显示。

## 43. 修改 Mapping 事务

远程端口从 6000 修改为 7000：

1. 创建 pending Revision；
2. 事务内先占用 7000；
3. 6000 继续保留；
4. 增加配置版本；
5. Client 应用新配置；
6. 新代理成功后将 pending 切为 active；
7. 释放旧端口 6000；
8. 如果应用失败，释放 7000，保留旧 Revision 和 6000。

禁止先释放旧端口。

## 44. 删除 Mapping 流程

正常流程：

```text
标记 deleting
  ↓
增加配置版本
  ↓
Client 删除本地代理并应用配置
  ↓
Client 上报成功
  ↓
删除/归档 Domain Binding（HTTP）
  ↓
删除 Mapping 数据
  ↓
释放端口租约
```

当前 Client 离线时允许管理员强制删除：

- Server 删除数据库资源并增加配置版本；
- 旧 Session/旧 generation 不得重新注册代理；
- 下次登录必须全量同步；
- 强制删除必须记录外部残留和审计。

---

# 第八部分：HTTP Mapping、域名与 Cloudflare DNS

## 45. HTTP Mapping 与 Domain Binding

固定关系：

```text
HTTP Mapping 1 -> N Domain Bindings
```

- Mapping 描述一个本地 HTTP 服务；
- Domain Binding 描述一个业务域名、HTTPS 模式、DNS 和证书；
- 给已有服务增加第二个域名时不得重复创建相同 HTTP Mapping；
- FRPC `customDomains` 由有效 Domain Binding 集合生成。

## 46. 域名标准化和唯一约束

标准化步骤：

1. 去除首尾空白；
2. 去除末尾句点；
3. 转小写；
4. IDNA/Punycode；
5. 校验总长度和 DNS Label；
6. 禁止通配符，除非未来单独设计；
7. 保存 `hostname` 和 `normalized_domain`。

数据库：

```sql
UNIQUE(normalized_domain)
```

离线、停用、DNS 错误和证书错误都不释放域名。

## 47. Cloudflare Zone 匹配

上传 Token 后分页获取全部可访问 Zone。

对标准化 hostname 执行最长合法 DNS Label 后缀匹配，只允许：

```text
hostname == zone
```

或：

```text
hostname 以 "." + zone 结尾
```

选择 Label 数最多的 Zone。Token 没有对应 Zone 权限时拒绝创建。

## 48. Cloudflare Token 上传和权限验证

传输路径：

```text
浏览器 -> Client Panel -> HTTPS -> Server Panel
```

Client Panel：

- 不持久化 Token；
- 不记录请求体；
- 不打印 Token；
- 请求完成后清除临时内存引用。

Server Panel 使用 AES-256-GCM 加密保存：

```text
ciphertext
nonce
key_version
token_version
```

验证必须分别报告：

- Token 是否有效；
- Zone Read；
- DNS Read；
- DNS Write；
- 可访问 Zone；
- 如果产品启用 Zone SSL 自动修改，再验证 Zone Settings Write。

权限不足必须返回缺失权限列表，不得统一显示“Token 错误”。

## 49. Cloudflare Token 替换

不得直接覆盖 active Token：

```text
上传新 Token
  ↓
作为 pending 版本加密保存
  ↓
验证权限和 Zone
  ↓
检查现有域名是否仍可管理
  ↓
显示将失去权限的域名
  ↓
用户确认
  ↓
切换 active_token_version
  ↓
新任务使用新版本
  ↓
稳定后退休旧 Token
```

失败时继续使用旧 Token。

## 50. 清除 Cloudflare Token

UI 按钮必须叫“清除 Cloudflare Token”，不能与 FRP Secret 重置混称。

流程：

1. 红色危险确认；
2. 前端 3 秒倒计时；
3. Server 再次验证当前 Session；
4. 删除/退休密文、Nonce 和 Zone 缓存；
5. 取消未执行任务；
6. 运行任务检查 Token 版本并停止；
7. DNS 操作立即返回 `CLOUDFLARE_TOKEN_MISSING`；
8. 自动续期标记 `blocked_missing_token`。

已有 Cloudflare DNS 不自动消失，UI 必须明确提示。

## 50.1 重置 FRP 凭证

UI 按钮必须叫“重置 FRP 凭证”，不能叫“重置 Token”。

固定安全策略：

- 普通用户和管理员都不能查看既有 FRP Secret 明文；
- 普通用户可在完成二次认证后自助重置；
- 管理员可为普通用户执行强制重置；
- 重置生成新的用户级 FRP Secret 和 Secret Version；
- 旧 Secret 立即失效；
- `active_session_generation + 1`；
- 当前 Client Session 和 FRP Runtime Credential 被撤销；
- `desired_config_version + 1`；
- 用户必须重新登录；
- 新 Client 获取新凭证并以 restart 方式重启 FRPC；
- 仍使用旧 Secret 或旧 generation 的 FRP 连接被 Plugin 拒绝。

UI 只显示 FRP 凭证是否存在、版本、最近重置时间和状态，不显示明文，也不提供“一键复制既有 Secret”。

## 51. DNS 数据模型

至少包含：

```text
type                 # A / AAAA / CNAME
name
normalized_name
content
ttl
proxied
zone_id
record_id
managed_by_panel
adopted
locked
sync_status
last_synced_at
last_error_code
last_error_message
```

功能范围：

- A、AAAA、CNAME；
- TTL；
- 小橙云切换；
- 状态同步；
- 一键更新面板管理记录到当前 Router 公网 IP；
- 删除 Domain 时按管理语义清理 DNS；
- 记录 Zone ID 和 Record ID；
- 区分平台创建和平台接管。

## 52. DNS 冲突语义

### 52.1 当前用户面板已有该域名

提供：

- 查看；
- 修改；
- 同步；
- 证书管理；
- 删除；
- 取消。

不得再次“添加到面板”。

### 52.2 Cloudflare 有记录、面板没有

只提供：

1. 取消；
2. 仅添加到面板；
3. 覆盖 DNS 并添加。

“仅添加到面板”：

```text
adopted = true
managed_by_panel = false
```

面板只显示和同步，不修改、不自动删除。如果记录未指向当前服务端，必须显示不可用警告。

“覆盖并添加到面板”：

```text
adopted = true
managed_by_panel = true
```

平台后续可以修改和删除该记录。

## 53. 域名创建 Operation

```text
Client 检查本地 HTTP 服务
  ↓
Server 标准化域名并占用 UNIQUE
  ↓
Zone 匹配和权限检查
  ↓
检查 Cloudflare 已有 DNS
  ↓
用户选择冲突策略
  ↓
创建 Domain Binding 和 Operation
  ↓
执行 DNS
  ↓
创建/更新 HTTP Mapping Revision
  ↓
增加配置版本并等待 Client 应用
  ↓
确认 FRPS HTTP Proxy
  ↓
按模式申请或加载证书
  ↓
生成 Router Snapshot
  ↓
Router ACK
  ↓
Domain active
```

每一步必须写入 Operation，不得只依赖单一 `domain.status`。

必须处理：

- DNS 成功但 Client 应用失败；
- Client 成功但证书失败；
- 证书成功但 Router 应用失败；
- Cloudflare 请求超时但实际成功；
- Token 在任务中被替换或清除；
- Client 离线。

## 53.1 删除 Domain Binding

正常流程：

```text
用户发起删除
  ↓
Server 标记 Domain deleting
  ↓
从 Router 业务路由中移除并等待 ACK
  ↓
按证书策略删除/归档证书
  ↓
如果 managed_by_panel=true，删除 Cloudflare DNS
  ↓
如果 managed_by_panel=false，只解除面板接管，不删除外部 DNS
  ↓
更新 HTTP Mapping 的 customDomains
  ↓
增加 desired_config_version
  ↓
Client 应用新配置并上报
  ↓
删除 Domain Binding，释放 normalized_domain
```

失败规则：

- Router、DNS、证书和 Client 应用分别记录 Operation Step；
- 外部 DNS 删除失败时不得显示“全部删除成功”；
- 用户可以重试；
- 管理员可以强制删除本地绑定，但必须保存外部残留清单；
- `adopted=true, managed_by_panel=false` 的记录永远不得由平台自动删除；
- Client 离线时可以先移除 Router 和外部资源，再增加配置版本；下次登录全量同步后旧域名不得重新注册。

---

# 第九部分：HTTPS、Router 与证书

## 54. HTTPS 三种固定模式

| 模式 | `https_mode` | `proxied` | 源站证书 |
|---|---|---:|---|
| 自动证书 | `auto_certificate` | false | 公共 CA |
| Cloudflare 代理 | `cloudflare_proxy` | true | 有效源站证书 |
| 仅 HTTP | `http_only` | false | 无 |

禁止：

```text
http_only + proxied=true
cloudflare_proxy + proxied=false
auto_certificate + proxied=true
```

UI 必须以三种整体模式切换，不允许用户任意组合两个字段。

## 55. 自动证书模式

- Cloudflare 小橙云关闭；
- 使用 Let's Encrypt 或 ZeroSSL；
- 使用 Cloudflare DNS-01；
- Server Router 终止 TLS；
- 可按域名单独开启 HTTP -> HTTPS 跳转；
- 源站可被直接访问。

## 56. Cloudflare 代理模式

- 小橙云开启；
- 浏览器到 Cloudflare 使用边缘证书；
- Cloudflare 到 Server Router 继续使用 HTTPS；
- Router 必须提供匹配域名且有效的源站证书；
- 推荐 Full (strict)；
- 默认源站仍使用公共 CA 证书，使关闭小橙云后浏览器仍可验证；
- 只有明确长期保持代理时才可选择 Origin CA；
- 面板默认只检测和提示 Zone SSL 模式，不自动修改整个 Zone 设置。

关闭小橙云前，如果当前只使用 Origin CA，必须先取得公共 CA 证书。

## 57. 仅 HTTP 模式

- 不申请证书；
- 不为该域名加载 TLS 证书；
- 不做 HTTP -> HTTPS 跳转；
- 只允许 80；
- Router 全局仍监听 443，不能因为某一个域名无证书影响其他域名；
- 对该 SNI 必须拒绝 TLS 握手，不能回退到其他用户证书。

## 58. Router 两类路由

Router Snapshot 必须分开：

```text
control_routes
business_routes
```

### 58.1 Control Routes

来自部署配置：

```text
panel.example.com/admin/* -> Server Control
panel.example.com/api/*   -> Server Control
```

普通用户不能修改，不从 Domain Binding 生成。

### 58.2 Business Routes

来自用户 Domain Binding：

```text
app.example.com -> FRPS vhostHTTPPort
```

管理员 Host 和用户业务域名不得进入同一个可修改集合。

## 59. Router 配置分发

固定实现：

```text
Control 生成版本化只读快照
  ↓
计算哈希和 HMAC
  ↓
原子写入受保护目录
  ↓
Unix Socket / Windows Named Pipe 通知 Router
  ↓
Router 读取、校验 Schema/版本/哈希/HMAC
  ↓
构建新内存路由表
  ↓
原子切换
  ↓
ACK applied_version
```

必须保存：

```text
router_config_version
router_applied_version
last_good_snapshot
```

Router 不直接访问业务数据库。Control 不可用时 Router 使用最后一份有效快照继续服务。

## 60. Router 行为

必须：

- 严格按 SNI 选择证书；
- 严格按 Host 选择业务路由；
- 未知 SNI 拒绝 TLS 握手；
- 未绑定 Host 返回 404；
- Client/FRPC 离线返回统一 502 页面；
- 保留原始 Host；
- 支持 WebSocket；
- 支持流式响应；
- 设置 `X-Forwarded-For`；
- 设置 `X-Forwarded-Proto`；
- 清理客户端伪造的 Forwarded/X-Forwarded 头；
- 限制 Header 和请求体大小；
- 设置合理的 Header、Idle 和上游超时；
- HTTP 到 HTTPS 跳转按域名单独配置。

## 61. 证书存储和密钥隔离

证书私钥只使用：

```text
certificate_wrapping_key
```

加密。

禁止使用 Server 主密钥、Router HMAC 密钥、配置签名密钥或 Session 密钥加密证书私钥。

推荐目录：

```text
/data/certificates/<domain-binding-id>/
  cert.pem
  chain.pem
  metadata.json
```

私钥可以只以加密形式保存，由受限证书加载组件在内存解密。落盘明文临时文件必须最小化、权限为 0600，并在失败路径清理。

## 62. ACME 自动化

必须支持：

- Staging 与 Production；
- ACME 账户和联系邮箱；
- DNS-01 TXT 创建；
- 权威 DNS 传播检测；
- TXT 清理；
- 同一域名单任务锁；
- 自动续期；
- 指数退避；
- 遵守 `Retry-After`；
- Token 缺失/无权限时暂停；
- 证书文件原子替换；
- Router 热加载；
- 手动续期 60 秒冷却由 Server 强制。

默认每日检查，到期前 30 天进入续期窗口。实际重试时间应结合 CA 返回和 ARI/Retry-After。

---

# 第十部分：用户、密钥、备份和删除

## 62.1 角色与资源隔离

角色固定为：

```text
admin
user
```

管理员可以管理所有用户、查看全局状态、处理失败 Operation、执行备份恢复和强制清理。

普通用户只能访问自己的：

- Session 状态；
- Mapping 和 Revision；
- Port Lease 展示；
- Domain Binding；
- DNS Record；
- Cloudflare Token 状态；
- Certificate；
- Operation 和审计摘要。

每个普通用户查询必须在 SQL 层包含 `user_id` 条件。禁止先按资源 ID 查询再只在业务层判断。对于无权限资源统一返回 404 或受控 403，避免泄露资源是否存在。

## 63. 用户创建

管理员创建用户时：

- 生成唯一用户名；
- 生成初始随机密码或一次性邀请信息；
- 设置 `must_change_password=true`；
- 设置 active 状态和配额；
- 生成平台管理的 `frp_username` 和 FRP Secret；
- 不向日志输出密码或 Secret；
- 只允许在创建响应中展示一次初始密码。

## 64. 停用用户

停用必须立即：

- 禁止新登录；
- 撤销全部 Session；
- 关闭 WebSocket；
- 拒绝 Client REST 请求；
- 增加 session generation；
- 撤销 FRP Runtime Credential；
- FRPS Plugin 拒绝 Login/NewProxy/Ping/NewWorkConn/NewUserConn；
- 通知在线 Client 停止 FRPC。

端口和域名继续占用，避免停用用户资源被他人抢占。

## 65. 删除用户 Operation

顺序：

1. 进入 `deleting` 并停用；
2. 撤销 Session 和运行凭证；
3. 停止 FRP 授权；
4. 删除平台管理的 Cloudflare DNS；
5. 删除 Router 业务路由；
6. 删除/归档证书；
7. 删除 Domain Binding；
8. 删除 Mapping 和 Port Lease；
9. 删除 FRP Secret；
10. 删除 Cloudflare Token；
11. 匿名化或保留必要审计；
12. 删除用户。

外部清理失败必须支持：

- 重试；
- 在尚未进入不可逆阶段时取消；
- 进入不可逆阶段后执行补偿或继续完成；
- 管理员强制删除本地数据；
- 强制删除必须展示并记录外部残留清单。

## 66. 主密钥和用途隔离

必须使用不同密钥：

```text
server_master_key
certificate_wrapping_key
router_snapshot_key
config_signing_key
session_signing_or_hashing_key
backup_kdf_context
```

用途：

- `server_master_key`：Cloudflare Token、可恢复 FRP Secret 等业务秘密；
- `certificate_wrapping_key`：证书私钥；
- `router_snapshot_key`：Router Snapshot HMAC；
- `config_signing_key`：Client 配置 Ed25519；
- Session 密钥：Cookie/CSRF 或 Session 相关用途；
- 备份 KDF Context：备份密码派生，不复用在线主密钥。

主密钥：

- 优先从环境变量或外部 Secret Manager 读取；
- 没有时只在首次启动生成一次；
- 持久化到 0600 受保护文件；
- 不进入普通数据库；
- 不写日志；
- 每次 AES-GCM 加密使用新随机 Nonce；
- AAD 必须绑定 `user_id`、数据类型和版本；
- 密文保存 `key_version`；
- 支持在线或维护窗口密钥轮换。

## 67. 正式备份

正式恢复格式固定为“加密归档包”，JSON 不作为完整恢复格式。

备份包包含：

- SQLite 一致性快照；
- migration 版本；
- 加密 Cloudflare Token 和 FRP Secret；
- 证书和加密证书私钥；
- Server 部署必要设置；
- Router/Config 签名公钥和必要私钥材料；
- 系统实例标识；
- 文件清单和 SHA-256 校验和。

整个归档再使用管理员输入的备份密码通过现代 KDF 派生密钥后加密。

恢复后必须：

- 校验包完整性；
- 校验 migration 兼容；
- 恢复密钥或明确要求用户重新上传 Token/重置 Secret；
- 运行数据库一致性检查；
- 生成新的运行 Session 密钥；
- 撤销旧活动 Session；
- 重新生成 Router Snapshot；
- 输出恢复报告。

## 68. JSON 导入导出

JSON 仅用于：

- 非敏感配置预览；
- 调试；
- 迁移 Mapping/Domain 的非秘密字段。

禁止明文导出：

- Cloudflare Token；
- FRP Secret；
- Server Session；
- 证书私钥；
- 主密钥；
- Cookie/CSRF 秘密。

导入必须通过 Schema、版本、权限和冲突预检，不得直接执行未验证 SQL。

---

# 第十一部分：数据库设计

## 69. 核心表

### 69.1 `system_identity`

```text
singleton_id PRIMARY KEY CHECK(singleton_id = 1)
server_instance_id UNIQUE
created_at
restored_from_backup_at
```

### 69.2 `users`

```text
id
username UNIQUE
password_hash
role
status
must_change_password
auth_version
active_session_generation
desired_config_version
applied_config_version
last_failed_config_version
active_cloudflare_token_version
max_mappings
max_domains
max_pending_mappings
max_pending_port_leases
max_pending_domain_operations
max_certificate_jobs
created_at
updated_at
deleted_at
```

### 69.3 `sessions`

```text
id
user_id
session_hash
login_channel             # admin_panel / client_panel
session_generation
source_ip
client_forwarded_browser_ip NULL
user_agent
expires_at
idle_expires_at
last_seen_at
revoked_at
revoke_reason
created_at
```

只允许一个普通用户活动 Client Session，管理员可以有多 Session。

### 69.4 `frp_credentials`

```text
id
user_id UNIQUE
frp_username UNIQUE
secret_hash
secret_ciphertext
secret_nonce
key_version
secret_version
created_at
rotated_at
```

### 69.5 `frp_runtime_credentials`

```text
id
user_id
server_session_id
session_generation
token_hash
expires_at
revoked_at
created_at
UNIQUE(server_session_id)
```

### 69.6 `user_runtime_state`

```text
user_id PRIMARY KEY
active_server_session_id
observed_client_status
client_panel_version
frpc_version
protocol_version
config_schema_version
last_heartbeat_at
last_applied_config_version
last_error_code
last_error_message
updated_at
```

### 69.7 `idempotency_records`

```text
id
user_id
session_generation
http_method
normalized_path
idempotency_key
request_body_hash
response_status
response_body_json
operation_id
expires_at
created_at
UNIQUE(user_id, session_generation, http_method, normalized_path, idempotency_key)
```

### 69.8 `mappings`

```text
id
user_id
name
proxy_type
lifecycle_status
desired_state
observed_state
active_revision_id
pending_revision_id
created_at
updated_at
```

### 69.9 `mapping_revisions`

```text
id
mapping_id
revision
local_ip
local_port
remote_port NULL
health_check_json
status
created_at
applied_at
UNIQUE(mapping_id, revision)
```

### 69.10 `port_leases`

```text
id
server_id
mapping_id
mapping_revision_id
remote_port
lease_role                # active / pending
created_at
UNIQUE(server_id, remote_port)
```

### 69.11 `domain_bindings`

```text
id
user_id
mapping_id
hostname
normalized_domain UNIQUE
zone_id
https_mode
http_redirect
status
revision
created_at
updated_at
```

### 69.12 `dns_records`

```text
id
user_id
domain_binding_id
type
name
normalized_name
content
ttl
proxied
zone_id
record_id
managed_by_panel
adopted
locked
sync_status
last_synced_at
last_error_code
last_error_message
```

### 69.13 `cloudflare_credentials`

```text
id
user_id
token_version
ciphertext
nonce
key_version
status
capabilities_json
verified_at
activated_at
retired_at
created_at
UNIQUE(user_id, token_version)
```

### 69.14 `certificates`

```text
id
domain_binding_id
provider
status
not_before
not_after
renew_after
cert_path
private_key_ciphertext
private_key_nonce
wrapping_key_version
cert_hash
last_error_code
last_error_message
updated_at
```

### 69.15 `config_snapshots`

```text
id
user_id
version
schema_version
session_generation
config_json
config_hash
config_signing_key_id
config_signature
created_at
UNIQUE(user_id, version)
```

### 69.16 `router_snapshots`

```text
version PRIMARY KEY
schema_version
snapshot_path
snapshot_hash
snapshot_hmac
status
generated_at
applied_at
last_error
```

### 69.17 `router_state`

```text
singleton_id PRIMARY KEY CHECK(singleton_id = 1)
router_config_version
router_applied_version
last_good_snapshot_version
last_good_snapshot_path
last_good_snapshot_hash
last_router_apply_error
updated_at
```

### 69.18 `operations`

```text
id
user_id
resource_type
resource_id
operation_type
status
phase
step
idempotency_key
cancelable
compensation_status
error_code
error_message
created_at
updated_at
completed_at
```

### 69.19 `jobs`

```text
id
type
resource_type
resource_id
status
run_after
attempts
max_attempts
lock_owner
locked_at
lock_expires_at
heartbeat_at
deduplication_key
token_version NULL
last_error
payload_json
created_at
updated_at
completed_at
```

活动任务唯一索引：

```sql
CREATE UNIQUE INDEX one_active_deduplicated_job
ON jobs(type, deduplication_key)
WHERE status IN ('pending', 'running', 'retry_wait');
```

### 69.20 `audit_logs`

```text
id
actor_type
actor_id
server_session_id
session_generation
source_ip
client_forwarded_browser_ip NULL
user_agent
request_id
operation_id
action
resource_type
resource_id
result
metadata_json
created_at
```

metadata 必须使用字段白名单。

## 70. Client 本地持久化

Client 不保存用户体系、设备绑定或 Server Session。`server_instance_id` 和 `user_id` 不得作为永久绑定字段写入 Client 本地数据库。

建议保存：

```text
client_settings
  last_server_panel_url
  listen_address
  lan_access_enabled
  allowed_cidrs
  allowed_hosts
  tls_settings
  data_schema_version

config_state
  desired_config_version
  applied_config_version
  last_good_config_hash
  last_sync_at

frpc_runtime_state
  frps_public_host
  frps_public_port
  frpc_version
  pid
  process_start_time
  executable_hash
  observed_state

local_log_settings
  level
  retention_days
  max_file_size
```

配置文件和回滚文件必须存放在持久化数据目录。

默认目录：

- Linux：`/var/lib/frp-panel-client/`；
- Windows：`C:\ProgramData\FRPPanelClient\`；
- macOS：`/Library/Application Support/FRPPanelClient/` 或用户模式对应目录；
- Docker：必须挂载 `/data` 持久化卷。

---

# 第十二部分：API、WebSocket 与错误标准

## 71. Server API 路由

```text
/api/v1/auth/client-login
/api/v1/auth/logout
/api/v1/auth/change-password
/api/v1/session/heartbeat
/api/v1/session/runtime-config
/api/v1/config/full
/api/v1/config/apply-result
/api/v1/mappings/*
/api/v1/domains/*
/api/v1/cloudflare/*
/api/v1/certificates/*
/api/v1/operations/*
/api/v1/admin/*
/internal/frp/plugin
```

`/internal/frp/*` 只能监听 127.0.0.1 或 Unix Socket，禁止公网访问。

## 72. API 版本规则

- URL 主版本使用 `/api/v1`；
- 兼容字段只能新增，不能改变原字段语义；
- 删除字段必须经过至少一个弃用周期；
- 请求和响应由 OpenAPI 定义；
- 生成 Client 不得修改生成文件；
- 所有写请求返回 `request_id` 和资源 Revision；
- 长操作返回 `operation_id`；
- 创建、修改和删除必须支持 `Idempotency-Key`。

## 73. 错误格式

统一使用 `application/problem+json`：

```json
{
  "type": "https://docs.example.invalid/problems/config-version-conflict",
  "title": "Configuration version conflict",
  "status": 409,
  "detail": "配置已发生变化，请刷新后重试。",
  "instance": "/api/v1/mappings/xxx",
  "code": "CONFIG_VERSION_CONFLICT",
  "request_id": "...",
  "current_version": 12
}
```

`detail` 不得包含栈、SQL、Token、路径秘密或内部网络信息。

## 74. 核心错误码

```text
AUTH_INVALID_CREDENTIALS
AUTH_USER_DISABLED
AUTH_PASSWORD_CHANGE_REQUIRED
SESSION_REPLACED
SESSION_EXPIRED
SESSION_GENERATION_MISMATCH
SERVER_TLS_VALIDATION_FAILED
SERVER_ADDRESS_INVALID
CONFIG_VERSION_CONFLICT
RESOURCE_REVISION_CONFLICT
IDEMPOTENCY_KEY_REUSED
PORT_ALREADY_RESERVED
PORT_NOT_ALLOWED
DOMAIN_ALREADY_RESERVED
CLOUDFLARE_TOKEN_MISSING
CLOUDFLARE_TOKEN_INVALID
CLOUDFLARE_PERMISSION_DENIED
ZONE_NOT_ACCESSIBLE
DNS_RECORD_CONFLICT
CLIENT_OFFLINE
LOCAL_SERVICE_UNREACHABLE
FRPC_VERIFY_FAILED
FRPC_RELOAD_FAILED
FRPC_RESTART_FAILED
ROUTER_APPLY_FAILED
CERTIFICATE_ISSUANCE_FAILED
RATE_LIMITED
```

## 75. WebSocket 协议

WebSocket 只在有效 Client Session 下建立。

Server -> Client：

```text
session_replaced
user_disabled
config_version_changed
force_full_sync
frp_secret_rotated
mapping_deleted
shutdown_frpc
```

Client -> Server：

```text
heartbeat
config_apply_started
config_apply_succeeded
config_apply_failed
frpc_status_changed
local_health_changed
```

每条消息必须包含：

```text
message_id
protocol_version
timestamp
type
payload
```

WebSocket 仅作通知，不能代替数据库版本和全量同步。

## 76. 并发与幂等

所有写操作必须携带：

```text
expected_config_version
resource_revision 或 mapping_revision
Idempotency-Key
```

旧版本返回 409，不得用 Last-Write-Wins 覆盖新配置。

幂等记录范围：

```text
user_id
session_generation
HTTP method
normalized path
Idempotency-Key
```

同一键不同请求体必须返回 `409 IDEMPOTENCY_KEY_REUSED`。

---

# 第十三部分：安全标准

## 77. Client Panel 本地访问安全

默认只监听：

```text
127.0.0.1
```

正式局域网访问必须：

- 显式开启；
- 绑定指定 LAN 地址；
- 使用 HTTPS；
- 配置 IP/CIDR 白名单；
- 配置 Host 白名单；
- 校验 WebSocket Origin；
- 禁止 `Access-Control-Allow-Origin: *`；
- 启用 CSRF；
- 登录/API 限速；
- 限制请求体和并发连接；
- 未登录请求不能调用 FRPC 控制 API。

不额外建立本地密码。用户仍使用 Server Panel 用户名和密码。

## 78. Server 断线行为

Server 不可达时，只有当前尚未本地过期的代理会话可以只读查看：

- FRPC 运行状态；
- 当前配置版本；
- Mapping 缓存状态；
- 本地服务健康；
- 脱敏日志。

禁止：

- 新登录；
- 创建、修改或删除 Mapping；
- 修改域名、DNS 或证书；
- 上传、替换、清除 Cloudflare Token；
- 重置 FRP Secret；
- 通过网页 start/stop/reload/restart FRPC。

紧急 FRPC 控制通过操作系统服务命令完成，不增加离线本地管理员绕过授权。

## 79. Web 安全

必须：

- CSP；
- `X-Content-Type-Options: nosniff`；
- `Referrer-Policy`；
- Frame 防护；
- 输出编码；
- 严格输入验证；
- CSRF Token；
- Secure/HttpOnly/SameSite Cookie；
- 登录失败统一提示；
- 密码和敏感 API 禁止缓存；
- 管理/API Host 与业务 Host 隔离；
- 依赖安全扫描和 Secret 扫描。

## 80. 日志脱敏

日志中禁止出现：

- 用户密码；
- Session Token；
- Cookie；
- CSRF Secret；
- Cloudflare Token；
- FRP Secret/Runtime Credential；
- 证书私钥；
- Server 主密钥；
- 完整 `Authorization`；
- 完整敏感请求体。

错误日志只记录错误码、资源 ID、请求 ID 和经过白名单的上下文。

## 81. 审计标准

以下操作必须审计：

- 登录成功/失败；
- Session 替换、退出和撤销；
- 用户创建、停用、删除；
- 密码修改/重置；
- FRP Secret 重置；
- Cloudflare Token 上传、替换、清除；
- Mapping 创建、修改、启停、删除；
- 端口自动/手动分配；
- Domain 添加、接管、覆盖、删除；
- DNS 修改和小橙云切换；
- 证书申请、续期和失败；
- Router Snapshot 应用；
- 备份、恢复、JSON 导入导出；
- 管理员强制删除和补偿。

审计记录必须包含 actor、session、generation、来源地址、User-Agent、request_id、operation_id、资源和结果。

---

# 第十四部分：后台任务、可观测性与可靠性

## 82. Job 租约

Worker 获取任务时设置：

```text
lock_owner
locked_at
lock_expires_at
heartbeat_at
```

长任务定期续租。Worker 崩溃后，锁过期可由其他 Worker 接管。

外部 API 调用期间不得持有 SQLite 写事务。

## 83. Job 去重

同一资源同类活动任务使用 `deduplication_key`：

- 同一域名一个 ACME 任务；
- 同一 DNS Record 不并发创建/修改/删除；
- 同一用户一个删除 Operation；
- 同一 Router 配置版本一个 apply Job。

历史成功任务不得阻止未来新任务。

## 84. 重试规则

- 只重试明确可重试错误；
- 指数退避 + 抖动；
- 尊重外部 `Retry-After`；
- 认证/权限错误不高频重试；
- 每次重试记录 attempt；
- 超过上限进入 failed 并可人工重试；
- 对超时但可能成功的 Cloudflare 请求先查询实际状态，再决定补发。

## 85. Pending 资源配额

每用户至少定义：

```text
max_mappings
max_domains
max_pending_mappings
max_pending_port_leases
max_pending_domain_operations
max_certificate_jobs
```

Pending 资源：

- 计入配额；
- 可由用户取消；
- 可由管理员取消；
- 长期 Pending 产生提醒；
- 显示占用原因；
- 取消动作写审计。

## 86. 可观测性

必须提供结构化日志和以下指标：

- 活动 Client Session 数；
- 登录成功/失败/替换次数；
- Client 心跳延迟；
- desired/applied 配置版本差；
- Mapping 各状态数量；
- Port Lease 数；
- Domain/Certificate 各状态数量；
- Cloudflare API 延迟和错误；
- ACME 任务、重试和失败；
- Router config/applied version 差；
- SQLite busy、WAL 大小和 checkpoint；
- Job 队列长度、租约过期和重试；
- FRPS Plugin 拒绝原因。

指标标签禁止使用 Token、完整域名大基数或用户输入原文。

---

# 第十五部分：开发标准

## 87. 代码质量标准

Go：

- `gofmt`、`go vet`、`staticcheck` 必须通过；
- 启用明确的 lint 配置；
- 禁止忽略错误；
- Context 必须从入口向下传递；
- 外部调用必须设置超时；
- goroutine 必须有退出和泄漏测试；
- 禁止包级可变全局业务状态；
- 秘密类型必须实现安全字符串化，防止 `%v` 打印明文。

TypeScript/Vue：

- `strict=true`；
- ESLint 和格式化检查通过；
- 禁止 `any` 绕过 API 类型，例外必须注释；
- 组件不得直接拼接 API URL；
- 表单必须有客户端和服务端双重校验；
- 危险操作必须使用统一确认组件。

## 88. SQL 与 Migration 标准

- Schema 只能通过 migration 修改；
- migration 必须单向编号、可重复检测；
- 生产 migration 不允许自动丢列/丢表；
- 破坏性变更使用“新增 -> 回填 -> 切换 -> 后续清理”；
- migration 必须在旧版本备份副本上演练；
- 唯一约束必须真实落到数据库，不得只在代码检查；
- 外键必须开启；
- 每个事务必须明确边界和失败回滚；
- SQLC 查询必须经过代码评审。

## 89. API 开发标准

- OpenAPI 先行；
- 所有端点定义权限、输入 Schema、错误码和幂等性；
- 错误使用 RFC 9457 Problem Details；
- 时间统一 RFC 3339 UTC；
- ID 使用 UUIDv7 或同类可排序随机 ID；
- 金额/容量/端口使用整数，禁止浮点表达离散值；
- 列表 API 必须分页；
- 敏感写操作需要 `reauth_ticket`；
- API 响应不得包含未声明字段；
- 管理员 API 和普通用户 API 权限中间件分离。

## 90. 状态机开发标准

- 状态转换必须集中定义，禁止在多个 Handler 中散落；
- 非法转换返回明确 409；
- 每次转换记录 actor、旧状态、新状态和原因；
- 跨系统流程使用 Operation，不使用单个布尔字段；
- Operation 每一步必须可重入；
- 补偿动作必须幂等；
- 不得将外部 API 成功假设为数据库成功，反之亦然。

## 91. 安全开发标准

- Threat Model 在编码前完成；
- PR 必须标记是否涉及认证、权限、秘密、文件、命令、网络或 SQL；
- 禁止拼接 Shell；
- 禁止任意文件路径；
- 禁止 TLS `InsecureSkipVerify` 进入生产配置；
- 启用 SAST、依赖漏洞扫描、Secret 扫描；
- 关键解析器和地址规范化使用 Fuzz Test；
- 加密必须使用标准库/成熟库，不得自创算法；
- 所有随机 Token 使用 CSPRNG；
- 安全事件必须有审计。

## 92. 测试标准

测试分层：

1. 单元测试；
2. 数据库集成测试；
3. API Contract 测试；
4. Server/Client 双端集成测试；
5. FRPC/FRPS 真二进制 E2E；
6. Cloudflare/ACME Provider 模拟与沙箱测试；
7. Router TLS/HTTP 测试；
8. 故障注入；
9. 安全测试；
10. 升级和恢复测试。

覆盖率最低标准：

- 总体 Go 行覆盖率 >= 75%；
- 认证、Session、端口租约、Revision 切换、Token 加密、Router 快照模块 >= 90%；
- 前端关键 Store、权限 Guard 和危险操作逻辑 >= 80%；
- 覆盖率不能替代关键场景测试。

## 93. Git 与评审标准

- 主分支受保护；
- 所有变更通过 PR；
- 至少一名评审者；
- 安全/数据库/加密变更至少两名评审者；
- Commit 或 PR 必须关联需求/Issue；
- 禁止直接提交生成的秘密、数据库和证书；
- Contract、Migration、状态机变更必须附兼容说明；
- PR 必须包含测试证据和风险说明。

## 94. CI 标准

每次 PR 必须执行：

- Go format/vet/staticcheck/lint；
- TypeScript lint/typecheck/build；
- 单元和集成测试；
- Migration 从空库和上一稳定版升级；
- OpenAPI Schema 校验和 breaking change 检查；
- Secret 扫描；
- SCA/依赖漏洞扫描；
- Container 镜像扫描；
- 双发行产物构建；
- SBOM 生成；
- 许可证策略检查。

## 95. 发布标准

每次发布必须：

- 使用 SemVer；
- Server 和 Client 独立版本号；
- 标明 `protocol_version`、`config_schema_version` 和 FRP 兼容范围；
- 发布 SHA-256；
- 生成 SBOM；
- 对二进制/镜像签名；
- 包含 migration；
- 包含升级、回滚和已知问题；
- 在干净环境完成安装和升级验收；
- 不在启动日志打印任何一次性密码以外的秘密；一次性密码也应提供受保护交付方式。

## 96. 兼容性标准

Server 返回：

```text
minimum_client_version
latest_client_version
minimum_frpc_version
protocol_version
config_schema_version
```

规则：

- Patch/Minor 版本优先向后兼容；
- 不支持的协议版本返回 `426 UPGRADE_REQUIRED`；
- 新字段默认可忽略；
- 删除/改变字段必须提升 API 主版本或经过弃用周期；
- Client 必须区分“建议升级”和“强制升级”；
- FRPC/FRPS 版本不兼容时禁止应用配置而非冒险运行。

## 97. 文档标准

发布前必须具备：

- 安装文档；
- Server 部署配置参考；
- Client 安装和局域网 HTTPS 文档；
- 管理员操作手册；
- 用户操作手册；
- API 文档；
- 错误码文档；
- 备份恢复手册；
- 故障排查手册；
- 安全说明和秘密轮换手册；
- 版本兼容矩阵。

---

# 第十六部分：验收标准

## 98. 验收等级

| 等级 | 定义 | 发布规则 |
|---|---|---|
| P0 | 安全边界、数据一致性、资源越权、秘密泄露、无法恢复 | 任一失败禁止发布 |
| P1 | 核心功能、状态闭环、Session 替换、回滚、DNS/证书 | 任一失败禁止正式发布 |
| P2 | 可用性、性能、可观测性、UI 体验 | 必须达到约定阈值或有批准的延期 |
| P3 | 优化和增强项 | 可进入后续版本 |

每个验收项必须保存：测试环境、步骤、期望、实际结果、日志/截图/请求 ID 和执行人。

## 99. 架构与产品边界验收

- **ARCH-001 / P0**：只产生 `frp-panel-server` 和 `frp-panel-client` 两个独立发行物。
- **ARCH-002 / P0**：Client 不包含管理员 API、Server SQLite、Router 或 FRPS Plugin。
- **ARCH-003 / P0**：Server 不读写 Client 本地配置目录。
- **ARCH-004 / P0**：代码中不存在设备注册、`device_token`、设备 HMAC 和永久 `client_id` 业务流程。
- **ARCH-005 / P1**：两端只通过版本化 HTTPS API/WebSocket 通信。
- **ARCH-006 / P1**：Server Control 内部端口和 `/internal/frp/*` 无法从公网访问。

## 100. 登录和 Session 验收

- **AUTH-001 / P0**：Client 登录只要求 Server 地址、用户名和密码。
- **AUTH-002 / P0**：Server 管理员页不显示 Server 地址输入。
- **AUTH-003 / P0**：用户密码、Server Session 不落盘、不进 localStorage、不进日志。
- **AUTH-004 / P0**：同一普通用户第二个 Client 登录后，旧 Session 返回 `SESSION_REPLACED`。
- **AUTH-005 / P0**：Session 替换事务在并发登录压力下始终只存在一条活动 Client Session。
- **AUTH-006 / P0**：旧 WebSocket、心跳、配置请求和 FRP Runtime Credential 全部失效。
- **AUTH-007 / P1**：同一 Client 新浏览器登录替换旧浏览器 Local Proxy Session。
- **AUTH-008 / P1**：管理员多 Session 不受普通用户唯一约束。
- **AUTH-009 / P0**：用户停用后所有 Session 和 FRP 授权立即失效。
- **AUTH-010 / P1**：首次密码用户只能修改密码。
- **AUTH-011 / P0**：Argon2id 参数、Salt 和版本正确保存，密码不可逆。

## 101. 地址和 TLS 验收

- **ADDR-001 / P1**：域名、域名端口、IPv4、IPv4 端口、IPv6、IPv6 端口全部规范化正确。
- **ADDR-002 / P0**：拒绝 Userinfo、Path、Query、Fragment 和非允许 Scheme。
- **ADDR-003 / P0**：生产模式不存在跳过 TLS 验证选项。
- **ADDR-004 / P0**：IP 无合法证书时，未完成 CA/指纹信任前不发送密码。
- **ADDR-005 / P1**：用户可修改 Server Panel 地址并重新登录，不触发设备绑定流程。
- **ADDR-006 / P0**：FRPS bind 地址 `0.0.0.0` 永不下发给 Client。
- **ADDR-007 / P1**：远程地址正确显示为 FRPS 公网主机 + remote_port。
- **ADDR-008 / P0**：切换 Server 成功后旧 FRPC 停止，旧 Session/运行凭证从内存清除，新配置不得混用旧 Server 数据。

## 102. FRPC 管理验收

- **FRPC-001 / P0**：所有进程和配置写操作通过单 Supervisor 队列。
- **FRPC-002 / P0**：无法启动第二个 FRPC。
- **FRPC-003 / P0**：配置写入前必须 `frpc verify` 成功。
- **FRPC-004 / P0**：配置使用原子替换，掉电/崩溃不会留下半文件。
- **FRPC-005 / P0**：reload 失败自动恢复 last-good 并再次启动旧配置。
- **FRPC-006 / P1**：公共参数变化使用 restart，代理项变化优先 reload。
- **FRPC-007 / P0**：Client 不提供任意命令和任意配置路径。
- **FRPC-008 / P1**：Client 重启后浏览器重新登录，但 last-good 配置可供只读状态展示。
- **FRPC-009 / P0**：Session 被替换/退出/停用后 Client 停止 FRPC。
- **FRPC-010 / P0**：Client 重启后无有效 Session 时会停止孤儿 FRPC，并清除所有运行时 Secret 文件。

## 103. FRPS 鉴权验收

- **FRPS-001 / P0**：手工 FRPC 缺少有效 Session/generation 被 Login 拒绝。
- **FRPS-002 / P0**：用户尝试申请未分配端口被 NewProxy 拒绝。
- **FRPS-003 / P0**：用户尝试使用他人域名被拒绝。
- **FRPS-004 / P0**：旧 Mapping Revision 被拒绝。
- **FRPS-005 / P0**：旧 generation 的 Ping/NewWorkConn/NewUserConn 被拒绝。
- **FRPS-006 / P0**：停用用户不能创建新连接。
- **FRPS-007 / P1**：Plugin 超时采用 fail-closed，不能放行未知代理。
- **FRPS-008 / P0**：FRP 凭证重置后旧 Secret、旧 Session 和旧 generation 均无法建立连接。
- **FRPS-009 / P0**：仅持有 `frps_transport_secret` 无法创建任何未授权 Mapping；Plugin 故障时请求被拒绝。

## 104. Mapping 和端口验收

- **MAP-001 / P0**：TCP、UDP 同一端口数字发生唯一冲突。
- **MAP-002 / P0**：离线、停用、config_error 不释放端口。
- **MAP-003 / P0**：自动分配在并发创建下无重复端口。
- **MAP-004 / P0**：修改端口先占新端口，成功后释放旧端口。
- **MAP-005 / P0**：修改失败释放新端口并保留旧端口和旧代理。
- **MAP-006 / P1**：服务端 reserved 与客户端 running 两阶段状态正确展示。
- **MAP-007 / P0**：Mapping 可修改字段只存在 Revision 中。
- **MAP-008 / P1**：Idempotency-Key 重试不创建重复 Mapping。
- **MAP-009 / P1**：旧 `expected_config_version` 返回 409。
- **MAP-010 / P1**：强制删除后旧配置不能重新注册代理。

## 105. 域名和 DNS 验收

- **DNS-001 / P0**：`normalized_domain` 全局唯一。
- **DNS-002 / P0**：域名标准化正确处理大小写、末尾点和 IDNA。
- **DNS-003 / P0**：Zone 匹配只接受合法 Label 后缀。
- **DNS-004 / P1**：获取 Cloudflare Zones 全部分页。
- **DNS-005 / P1**：当前面板已有域名不出现再次添加选项。
- **DNS-006 / P1**：Cloudflare 已有记录提供取消、仅添加、覆盖三选一。
- **DNS-007 / P0**：仅添加后 `adopted=true, managed_by_panel=false`，删除 Domain 不删除外部记录。
- **DNS-008 / P0**：覆盖后 `adopted=true, managed_by_panel=true`，允许同步和删除。
- **DNS-009 / P1**：支持 A、AAAA、CNAME、TTL 和 proxied。
- **DNS-010 / P1**：一键更新只修改平台管理记录。
- **DNS-011 / P0**：Cloudflare Token 清除后已有 DNS 不被自动删除。
- **DNS-012 / P1**：Cloudflare 超时后通过查询实际状态避免重复创建。
- **DNS-013 / P0**：删除 managed Domain 时同步删除 DNS；删除 unmanaged adopted Domain 时绝不删除外部 DNS。
- **DNS-014 / P1**：Domain 删除各阶段失败可重试，强制删除会生成外部残留清单。

## 106. Cloudflare Token 验收

- **CF-001 / P0**：Token 永不从 Server API 明文返回。
- **CF-002 / P0**：Token 使用 AES-256-GCM、新随机 Nonce、AAD 和 key_version。
- **CF-003 / P0**：日志、Trace、审计不包含 Token。
- **CF-004 / P1**：权限不足返回具体缺少的权限。
- **CF-005 / P0**：替换 Token 先 pending 验证，失败继续使用旧 Token。
- **CF-006 / P0**：清除 Token 的 3 秒 UI 倒计时和 Server 再认证都生效。
- **CF-007 / P1**：清除后 DNS/ACME Job 正确停止或阻塞。

## 107. HTTPS、Router 和证书验收

- **TLS-001 / P0**：三种模式的非法组合无法通过 UI、API 和数据库约束。
- **TLS-002 / P0**：未知 SNI 不返回管理员或其他用户证书。
- **TLS-003 / P1**：未绑定 Host 返回 404，离线返回统一 502。
- **TLS-004 / P1**：WebSocket 和流式响应可正常代理。
- **TLS-005 / P0**：清理伪造的 Forwarded/X-Forwarded 头。
- **TLS-006 / P0**：Control Route 与 Business Route 分离。
- **TLS-007 / P0**：Router 不访问业务数据库，Control 故障时继续使用 last-good。
- **TLS-008 / P0**：坏 Snapshot/HMAC/Schema 被拒绝并保留旧路由。
- **TLS-009 / P1**：证书续期后原子替换并热加载，无错误证书窗口。
- **TLS-010 / P1**：ACME Staging、DNS 传播、TXT 清理和 Retry-After 正常。
- **TLS-011 / P0**：证书私钥只使用 certificate_wrapping_key。
- **TLS-012 / P1**：Cloudflare 代理模式源站证书满足 Full (strict)。

## 108. 用户停用、删除和补偿验收

- **USR-001 / P0**：停用后登录、API、WebSocket 和 FRPS 全拒绝。
- **USR-002 / P0**：停用不释放端口和域名。
- **USR-003 / P1**：删除按定义顺序执行并显示阶段。
- **USR-004 / P0**：外部清理失败不会静默删除本地数据并宣称成功。
- **USR-005 / P1**：可取消阶段可以取消；不可逆阶段只允许补偿或完成。
- **USR-006 / P1**：强制删除输出外部残留清单并写审计。
- **USR-007 / P0**：普通用户无法读取、修改或推断其他用户资源。

## 109. 密钥、备份和恢复验收

- **KEY-001 / P0**：不同用途密钥隔离。
- **KEY-002 / P0**：主密钥重启后稳定，不会导致旧 Token 无法解密。
- **KEY-003 / P0**：主密钥不进入普通数据库和日志。
- **KEY-004 / P1**：密钥轮换后新旧密文均可在迁移期正确处理。
- **BKP-001 / P0**：正式备份包全包加密且校验和正确。
- **BKP-002 / P0**：SQLite WAL 活跃状态下备份恢复一致。
- **BKP-003 / P0**：备份文件泄漏时不输入密码无法读取秘密。
- **BKP-004 / P1**：恢复后 Session 全撤销、Router 重建、数据库检查通过。
- **BKP-005 / P0**：JSON 导出不含任何明文秘密。

## 110. API、兼容和版本验收

- **API-001 / P1**：OpenAPI 与实现 Contract 测试一致。
- **API-002 / P1**：所有错误符合 Problem Details 和稳定错误码。
- **API-003 / P0**：权限越权请求统一拒绝且无资源存在性泄漏。
- **API-004 / P1**：不支持的协议版本返回 426。
- **API-005 / P1**：旧 Client 收到明确升级提示，不发生解析崩溃。
- **API-006 / P1**：WebSocket 断开后指数退避，无高频重连。
- **API-007 / P1**：WebSocket 丢消息后全量同步恢复一致。

## 111. 性能验收基线

参考环境：

```text
2 vCPU
2 GiB RAM
本地 SSD
Linux
SQLite WAL
```

不包含 Cloudflare/CA 外部延迟的本地控制 API：

- **PERF-001 / P2**：100 并发只读请求，p95 <= 300ms，错误率 < 1%；
- **PERF-002 / P2**：20 并发写请求，数据库无永久 lock，p95 <= 800ms；
- **PERF-003 / P2**：1000 Mapping + 2000 Domain 的 Router Snapshot 生成与应用 <= 5 秒；
- **PERF-004 / P2**：Router 热切换不主动中断已有正常 HTTP 连接；
- **PERF-005 / P2**：单用户 200 Mapping 配置生成和验签 <= 2 秒；
- **PERF-006 / P2**：正常网络下配置提交到 Client 开始应用 <= 5 秒；
- **PERF-007 / P2**：Session 替换后旧 HTTP/WS 权限 <= 5 秒失效，旧 FRP 新连接 <= 30 秒被拒绝。

如果目标硬件更低，必须在发布说明中给出重新测得的支持规模，不得删除测试。

## 112. 稳定性和故障注入验收

- **REL-001 / P0**：Client 在配置文件原子替换中被杀死，重启后恢复有效配置。
- **REL-002 / P0**：Server 在端口事务中被杀死，不出现重复租约或半 Mapping。
- **REL-003 / P1**：Worker 在 Cloudflare 请求后、数据库更新前崩溃，可通过查询恢复。
- **REL-004 / P0**：Router 应用坏 Snapshot 后继续使用 last-good。
- **REL-005 / P1**：WAL 增长可监控并 checkpoint，不耗尽磁盘。
- **REL-006 / P1**：WebSocket 长时间断开后配置全量同步。
- **REL-007 / P0**：磁盘满时不覆盖 last-good、不丢数据库一致性。
- **REL-008 / P1**：时钟偏差被检测，ACME/Session 有明确错误而非静默异常。

## 113. 安全验收

- **SEC-001 / P0**：SAST、依赖扫描、Secret 扫描无未豁免 Critical/High。
- **SEC-002 / P0**：认证、域名、端口和文件路径权限测试无越权。
- **SEC-003 / P0**：XSS、CSRF、CORS、Host Header、WebSocket Origin 测试通过。
- **SEC-004 / P0**：Server 地址解析不存在危险 Scheme、Userinfo 和重定向绕过。
- **SEC-005 / P0**：日志自动扫描未发现密码、Token、Cookie 或私钥。
- **SEC-006 / P0**：FRPS Plugin 故障时 fail-closed。
- **SEC-007 / P1**：地址、域名、IDNA、Snapshot 和 API JSON 解析完成 Fuzz 测试。
- **SEC-008 / P1**：发布包包含 SBOM、签名和校验和。

## 114. UI 验收

- **UI-001 / P1**：Client 与 Admin 登录组件完全分离，不出现错误字段。
- **UI-002 / P1**：危险操作有清晰后果、二次确认和防重复提交。
- **UI-003 / P1**：状态文案区分 reserved、pending、running、offline 和 error。
- **UI-004 / P1**：Cloudflare 权限缺失显示具体权限。
- **UI-005 / P1**：DNS 接管三选一语义与 managed/adopted 完全一致。
- **UI-006 / P1**：Token 页面只显示是否配置、状态、验证时间，不显示明文。
- **UI-007 / P2**：键盘导航、表单标签、对比度达到 WCAG 2.1 AA 的核心要求。
- **UI-008 / P1**：所有异步 Operation 可查看当前步骤、失败原因和重试入口。

## 115. 发布准入 Definition of Done

一个版本只有同时满足以下条件才可标记为 Release Candidate：

- 所有 P0、P1 验收通过；
- 所有 Migration 和回滚演练通过；
- Server/Client/FRP 兼容矩阵完成；
- 真实 FRPC/FRPS E2E 通过；
- Cloudflare Sandbox/测试 Zone 通过；
- ACME Staging 通过；
- 加密备份恢复通过；
- 安全扫描无未批准 Critical/High；
- 文档和错误码同步；
- SBOM、签名、校验和生成；
- 发布负责人、安全负责人和测试负责人签字。

---

# 第十七部分：开发阶段

## 116. 阶段 0：技术验证

完成：

- FRPS Plugin 操作校验 PoC；
- FRPC verify/reload/restart/rollback PoC；
- Router Snapshot + IPC + 热切换 PoC；
- SQLite WAL 并发、备份和故障测试；
- Cloudflare Token 权限验证 PoC；
- ACME DNS-01 Staging PoC。

## 117. 阶段 1：身份与基础安全

完成：

- 管理员初始化；
- 用户管理；
- Argon2id；
- 普通用户单活动 Client Session；
- Local Proxy Session；
- 地址规范化和 TLS 信任；
- 审计和日志脱敏。

## 118. 阶段 2：Client/FRPC 闭环

完成：

- FRPC Supervisor；
- 配置签名和全量同步；
- verify、原子替换、reload/restart；
- 失败回滚；
- 心跳、WebSocket 和运行租约；
- FRPS Plugin Login/Ping/WorkConn。

## 119. 阶段 3：TCP/UDP Mapping

完成：

- Mapping/Revision；
- Port Lease；
- 手动和自动端口；
- 创建、修改、删除；
- 幂等和并发冲突；
- FRPS NewProxy 授权。

## 120. 阶段 4：域名和 Cloudflare

完成：

- Token 加密；
- 权限和 Zone；
- DNS 模型；
- 接管/覆盖；
- HTTP Mapping 1:N Domain；
- Domain Operation。

## 121. 阶段 5：Router 和证书

完成：

- control/business route；
- SNI/Host；
- 三种 HTTPS 模式；
- ACME；
- 证书热加载；
- 404/502；
- WebSocket/流式代理。

## 122. 阶段 6：任务、删除、备份和发布

完成：

- Job 租约和重试；
- Pending 配额；
- 删除补偿；
- 用户停用/删除；
- 加密备份恢复；
- 版本兼容；
- 性能、安全和稳定性验收；
- 签名发布。

---

# 第十八部分：最终强制规则汇总

## 123. 最终规则

1. 系统只有 Server Panel 和 Client Panel 两个独立产品。
2. Client Panel 没有本地用户体系。
3. Client 登录只需要 Server Panel 地址、用户名和密码。
4. 不存在设备注册、设备绑定、永久 client_id、device_token 或设备 HMAC。
5. 用户可以自由修改 Server Panel 地址并重新登录。
6. 同一个普通用户同一时间只允许一个活动 Client Panel Session。
7. 新 Client 登录自动替换旧 Client，旧 Web/WS/FRP 权限全部失效。
8. Client Panel 同时只维护一个活动浏览器代理 Session。
9. Mapping 永久归属于用户，不归属于设备。
10. Client 登录后拉取完整配置并管理一个本地 FRPC。
11. FRPC 配置必须 verify、原子替换、串行应用、失败回滚。
12. IP+端口模式只处理 TCP/UDP FRP 转发。
13. IP+端口模式不进入域名、DNS、证书和 Router 流程。
14. 域名模式固定为自动证书、Cloudflare 代理、仅 HTTP。
15. Server Panel 地址、FRPS 地址、远程访问地址和本地服务地址必须分开。
16. FRPS 公网地址由 Server 配置并自动下发。
17. Mapping 可修改字段只保存在不可变 Revision。
18. 端口和域名占用由数据库唯一约束决定，与在线状态无关。
19. HTTP Mapping 可以关联多个 Domain Binding。
20. Cloudflare DNS 接管语义固定，不保留二选一实现。
21. Cloudflare Token 只由 Server 加密保存和使用。
22. Router 使用版本化只读快照，不访问业务数据库。
23. 管理员/API 路由和用户业务路由必须分开。
24. FRPS Plugin 必须阻止手工伪造配置。
25. Session、配置版本、Revision、幂等、回滚、任务、备份和审计均为必做能力。
26. 所有 P0 和 P1 验收项通过前禁止正式发布。

---

# 第十九部分：官方能力参考

以下参考用于确认基础能力边界，具体依赖版本必须在发布时重新验证：

- FRP Client 动态 reload、公共参数限制和 status：`https://gofrp.org/en/docs/features/common/client/`
- FRP 配置 verify 和 TOML 配置：`https://gofrp.org/en/docs/features/common/configure/`
- FRP Server Plugin 操作类型：`https://gofrp.org/en/docs/features/common/server-plugin/`
- FRP Authentication：`https://gofrp.org/en/docs/features/common/authentication/`
- FRP Server 配置：`https://gofrp.org/en/docs/reference/server-configures/`
- Cloudflare API Token 权限：`https://developers.cloudflare.com/fundamentals/api/reference/permissions/`
- Cloudflare DNS Records API：`https://developers.cloudflare.com/api/resources/dns/subresources/records/`
- Cloudflare Full (strict)：`https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/`
- Cloudflare Origin CA：`https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/`
- SQLite WAL：`https://sqlite.org/wal.html`
- Argon2：`https://www.rfc-editor.org/info/rfc9106/`
- HTTP Problem Details：`https://www.rfc-editor.org/info/rfc9457/`
- Let's Encrypt Rate Limits：`https://letsencrypt.org/docs/rate-limits/`

---

# 第二十部分：变更记录

## v3.0

- 删除永久设备绑定、设备 Token、设备 HMAC 和 client_id 资源归属；
- 固定普通用户全局单活动 Client Session；
- 固定 Client Panel 单活动浏览器代理 Session；
- Mapping 改为用户归属；
- FRP 凭证改为用户级 Secret + Session 级运行凭证；
- Server Panel 地址允许自由更换；
- 分离 IP+端口与域名模式；
- 收口 Mapping/Revision 数据模型；
- 固定 DNS 接管语义；
- 补齐 FRPS 公网地址；
- 固定 Router control/business route 边界；
- 增加完整开发标准；
- 增加分层、编号化验收标准；
- 增加发布准入 Definition of Done。
