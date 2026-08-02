# 用户操作手册

## 首次登录

在 Client Panel 输入 Server Panel 的 HTTPS 地址、用户名和密码。Client
不会创建本地账号，也不会把 Server Session 或密码写入浏览器存储。首次
登录必须按页面提示修改一次性初始密码。

如果按 IP 连接，先使用“检查证书 / 查看 SPKI 指纹”完成 CA 或明确的
SPKI 信任；未完成信任前 Client 不会发送登录密码。切换 Server 地址会
停止旧 FRPC、清除旧 Session 和运行时秘密，再建立新连接。

## Mapping

在 Mappings 创建 TCP、UDP 或 HTTP Mapping。填写本地服务地址和端口；
TCP/UDP 可以填写远程端口，留空时由 Server 自动租赁。Server 先创建
不可变 Revision 并显示 `reserved`/`pending`，Client 完成本地服务检查、
固定 FRPC 的 `verify` 和原子应用后才显示 `running`。

编辑会创建新 Revision。旧端口在新 Revision 成功应用后才释放；失败时
页面保留失败原因，旧 Revision 和旧端口继续有效。

## Domain Binding

只有 HTTP Mapping 可以绑定 Domain。选择 A、AAAA 或 CNAME、TTL 和以下
一种 HTTPS 模式：自动证书、Cloudflare 代理、仅 HTTP。`http_only` 不允
许开启 HTTP 到 HTTPS 重定向。DNS 冲突时明确选择仅接管、覆盖或取消：
仅接管的外部记录不会在删除 Domain 时被面板删除，覆盖后的面板管理记录
才会进入同步和删除流程。

## 状态和异步操作

`reserved`、`pending_*`、`running`、`offline`、`error` 和 `active` 是不
同状态。不要把 pending 当作成功。Operations 页面展示每一步、失败错误
码、外部残留和重试入口；网络或 Provider 超时后先刷新 Operation 状态，
不要用新 Idempotency-Key 重复创建。

## 离线和退出

Server 暂时不可达时，只能查看当前登录会话的短期只读缓存，不能创建、
修改或删除资源。退出登录、Session 被替换、用户停用或重置 FRP 凭证后，
Client 会停止 FRPC 并清除运行时秘密。若页面显示 `SESSION_REPLACED`，
重新登录即可恢复新的活动 Session。
