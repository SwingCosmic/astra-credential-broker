# Astra Credential Broker

Astra Credential Broker 是主要为 [AstraConductor](https://github.com/SwingCosmic/astra-conductor) 提供的独立凭据管理工具。它以本机服务的形式集中保存和共享 API 密钥、访问令牌等认证信息，让多个AI大模型应用工具共用一份凭据，用户无需在每个工具中重复导入和分别维护。

它可以独立安装、运行和管理，为 `PolyQuota`的订阅用量查询，`Graph Agent`的API接入提供统一的凭据管理能力，也允许其他获得授权的应用通过本地协议接入。

## 典型使用场景

同一个账号或服务的凭据，可能同时被配额查询、模型调用、自动化任务等多个工具使用。如果每个工具各自保存一份，用户就需要逐个导入；更换密钥、重新登录或更新令牌后，还要分别同步和维护。

接入 Credential Broker 后，这些工具可以围绕同一个共享凭据库工作：

- **导入一次，多处使用**：将凭据导入共享库，已接入并获得授权的工具即可使用同一份信息。
- **统一更新和维护**：凭据变化时更新共享库，其他工具读取最新版本，减少手动复制和逐个替换。
- **新工具复用已有凭据**：为新接入的工具授权后，即可访问已有凭据，无需再单独导入一份。

对于需要刷新访问令牌的服务，Broker 还提供更新许可和变更通知，帮助多个工具协调刷新，减少重复请求以及旧凭据覆盖新凭据的问题。

## 它能做什么

- **共享凭据**：集中保存认证信息，向获得授权的应用提供访问。
- **加密存储**：凭据以密文保存在本机，Windows 版本使用当前系统用户的 DPAPI 保护存储密钥。
- **协调更新**：为客户端分配更新许可，检查提交版本，避免旧结果覆盖新凭据。
- **通知变更**：应用可以订阅凭据变化，断开后也能继续获取遗漏的事件。
- **独立运行**：服务按需启动，空闲后退出；多个应用可以共同使用，关闭其中一个应用不会停止其他应用正在使用的服务。

应用负责完成登录或向在线服务刷新令牌，再把结果交给 Broker 保存。Broker 通过本地通信协议提供服务，可供不同语言编写的桌面应用、命令行工具和后台程序接入。

## 当前状态

项目目前面向应用开发者，通过命令行管理。应用需要接入协议才能使用共享凭据，安装服务本身不会自动接管现有应用的登录信息。

当前完整运行和安装验收支持 **Windows x64**。Linux、macOS 已有共享的通信与进程管理实现，用户身份、私有目录权限和系统密钥保护仍待补齐。当前提供从源码构建与本地安装，签名发行和应用集成尚未完成。

当前组件草稿为 `0.2.0`：组件版本是只用于更新检查的完整 SemVer，协议版本是决定通信的整数 `1`，API 版本是决定功能兼容的级别，当前为 `2`。三者独立；组件较旧但 API 足够仍可工作，组件较新但 API 不足仍拒绝。现有数据格式保持 v1，本轮不迁移数据；升级保留 vault、服务密钥、客户端授权和导入绑定。详细规则见[协议](./docs/protocol.md)与[安装/升级](./docs/installation.md)。

## 从源码试用

在 Windows x64 上安装 .NET SDK **10.0.300**，进入仓库目录后运行：

```powershell
dotnet restore --locked-mode
./scripts/publish.ps1

$publish = Join-Path $PWD 'artifacts/publish/win-x64'
$ctl = Join-Path $publish 'brokerctl.exe'
$vault = Join-Path $env:LOCALAPPDATA 'AstraCredentialBrokerData/v1'

& $ctl install-local --source $publish
& $ctl register-vault --vault $vault
& $ctl ensure-running --vault $vault
& $ctl status --vault $vault
```

这些命令会构建并安装组件、创建一个空凭据库，然后启动服务并查看状态。要开始共享凭据，还需要授权客户端、导入初始凭据并完成应用接入，具体接口见[协议文档](docs/protocol.md)。

构建后的 `artifacts/publish/win-x64/` 包含完整运行时和 SQLite。复制到其他 Windows x64 机器使用时，需要携带整个目录，运行机器无需预装 .NET。

日常管理可以继续使用上面的 `$ctl` 和 `$vault`：

```powershell
& $ctl stop --vault $vault
& $ctl restart --vault $vault
```

安装、重装、卸载和故障恢复的完整说明见[安装文档](docs/installation.md)。卸载运行组件会保留凭据数据和密钥。

## 开发与验证

完成依赖还原后，可以运行：

```powershell
dotnet build --no-restore
dotnet test --no-restore
dotnet format --verify-no-changes --no-restore
./scripts/verify-local.ps1
```

本机验收脚本使用发布后的独立组件，检查安装、授权、凭据更新、进程恢复、卸载和重装。所有凭据测试均使用虚构数据，结果及验证范围见[验收记录](docs/validation.md)。

当前协议和存储格式均为 v1。跨语言密码格式验证使用 Node.js 标准库，测试向量可通过 `node test/interop/vector.mjs --generate` 重新生成并验证。

## 文档

- [详细设计与数据结构](docs/detailed-design.md)
- [通信、API 与错误语义](docs/protocol.md)
- [本地安装、发现、运行及恢复](docs/installation.md)
- [验收记录与复现](docs/validation.md)
- [结构化协议 schema](schemas/protocol-v1.schema.json)
- [跨运行时测试向量](test/vectors/transfer-v1.json)

## 代码结构

| 目录 | 职责 |
| --- | --- |
| `src/Broker` | 凭据存储、更新协调、通信协议和服务管理 |
| `src/Broker/Platform` | 平台能力接口及共享、系统专用实现 |
| `src/Brokerctl` | 独立 CLI、前台服务与后台监督入口 |
| `test/Broker.Tests` | 密码、权限、并发、时钟、回执、恢复与管道测试 |
| `test/Broker.Smoke` | 使用真实发布 EXE 的本机离线安装/运行/恢复验收 |
| `test/interop` | 仅用 Node 标准库验证 HKDF、AES-GCM、JCS 互操作 |
| `scripts` | 发布与离线验收入口 |
