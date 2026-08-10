# Target environment acceptance

目标环境验收入口是 `make target-acceptance`，实现文件为
`scripts/target-acceptance.rb`。它把标准中必须在 Linux 目标画像上重复确认的
性能、故障注入和真实 FRP 网络检查组合成一个可审计报告：
`output/target-acceptance.json`，以及 `output/target-acceptance/` 下的脱敏原始日志。
报告和日志均使用 `0600` 权限。

目标画像固定为 Ubuntu 24.04/Linux、2 vCPU、2 GiB 内存、2 GiB swap、SQLite
WAL。固定性能步骤通过 `scripts/fixed-performance.sh` 使用 Docker 的精确
`--cpus=2 --memory=2g --memory-swap=2g` 限制；随后执行 Linux tmpfs 磁盘满、WAL
压力、干净临时数据目录的加密备份解码/恢复和时钟偏差故障注入，再执行固定 FRP v0.68.0 的 `frps/frpc verify`、真实 TCP
网络代理和真实 Plugin 网络 E2E。

## 本地运行

在 macOS 或没有固定 FRP 二进制的环境中，入口会返回退出码 `2` 并记录
`blocked`，而不是模拟目标机结果：

```bash
make target-acceptance
```

要获得完整结果，需要 Linux 目标机并提供官方固定版本 `frps`/`frpc`、隔离配置和
测试 URL。所有必需变量与现有入口相同：

```bash
FRP_E2E_FRPS_BINARY=/opt/frp/frps \
FRP_E2E_FRPS_CONFIG=/var/tmp/frps-e2e.toml \
FRP_E2E_FRPC_BINARY=/opt/frp/frpc \
FRP_E2E_FRPC_CONFIG=/var/tmp/frpc-e2e.toml \
FRP_E2E_URL=http://127.0.0.1:17080/ \
FRPC_VERIFY_BINARY=/opt/frp/frpc \
FRPC_VERIFY_VERSION=0.68.0 \
make target-acceptance
```

二进制 SHA-256、就绪端口、隔离 fixture 和等待时间变量见
[`frp-plugin-e2e.md`](frp-plugin-e2e.md)。目标验收不会写入 token、私钥或生产
凭据，也不会把 `blocked` 当作通过。

## Hosted runner

`.github/workflows/target-acceptance.yml` 是可手动触发、也可由 PR CI 复用的 Ubuntu 24.04 工作流。它
从官方 FRP v0.68.0 release asset 获取 Linux amd64 二进制，先用 GitHub release
digest 校验，再调用同一个 Ruby collector，并上传同一 revision 的报告和日志。
工作流通过 `scripts/target-acceptance-workflow-policy.rb` 纳入 `make contract`。

这个工作流证明固定 hosted target profile；它不等同于生产容量、Cloudflare
Sandbox、ACME Staging、真实生产 TLS、cosign 签名或三方发布负责人 sign-off。
这些证据仍须由发布负责人在对应环境中执行并附到 acceptance matrix。
