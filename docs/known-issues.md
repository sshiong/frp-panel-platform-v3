# 已知限制和发布阻断项

这些限制必须在发布说明中保留，不能通过 UI 把 `pending` 或 `blocked` 渲染
成 `active`：

- 真实 Cloudflare Sandbox/测试 Zone、Token 权限、超时补偿和 DNS 残留尚未
  在本开发环境执行。
- 真实 ACME Staging 的 DNS-01 传播、TXT 清理、证书续期和 Router SNI 热切
  换需要部署环境验证。
- Linux 2 vCPU/2 GiB 目标基线、1000 Mapping/2000 Domain 仍需要 release 环境
  执行。CI 已加入 Ubuntu 24.04 disposable tmpfs 磁盘满保护和 Provider/ACME
  clock-skew fail-safe 检查，但这不是目标机容量、备份恢复或系统时钟演练的
  替代品。
- Docker 镜像构建与 Trivy 容器扫描由 GitHub Actions 执行；本机 Docker daemon
  不可用时不应将本地结果误报为镜像已扫描。
- `cosign` 签名和发布负责人、安全负责人、测试负责人签字属于发布门禁。

在上述 P0/P1 外部验收完成前，仓库定位为开发预览，不声明生产就绪。
