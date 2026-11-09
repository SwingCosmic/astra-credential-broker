# Broker 验收

2026-11-09，Windows x64 的本地自包含组件 `0.3.0` 已通过 B2/B3 协议验证。协议为 1，API 为 3，存储格式为 1。完整组件内含 .NET 和 SQLite，Windows DPAPI 保护实际服务密钥及客户端授权。

| 检查 | 结果 | 覆盖范围 |
| --- | --- | --- |
| .NET 构建与格式 | 通过 | SDK 10.0.300，锁定依赖 |
| 单元及管道测试 | 135 通过，1 个 Unix 专用测试跳过 | 独立发布、失败恢复、权限与幂等、稳定身份唯一性、租约与 fence、事件、认证、跨运行时密码向量 |
| 自包含进程测试 | 33 通过 | 四客户端并发启动、发布后直接写入、服务重启、DPAPI 解锁、安装中断恢复、权限保留、显式迁址及旧登记隔离 |
| 在线组件升级 | 7 通过 | 0.2.0 → 0.3.0，升级排空、密钥与授权保留、原存储版本和记录修订可读 |

以下命令使用虚构凭据和隔离安装目录。升级测试需要完整的旧版自包含组件。

```powershell
dotnet restore --locked-mode
dotnet build --no-restore
dotnet test --no-build
dotnet format --verify-no-changes --no-restore
./scripts/publish.ps1
./scripts/verify-local.ps1
./scripts/verify-compatibility-upgrade.ps1 -OldPublish 'X:\old-publish' -Publish './artifacts/publish/win-x64'
```

产品页面、双向迁移、私有快照和两款 Electron 的联合验收由 AstraConductor 仓库的 `test:credential-sharing-loop` 运行。非 Windows 平台仍需提供用户身份、私有目录和系统密钥保护适配。
