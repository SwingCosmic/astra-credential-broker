# A1/A2 验收记录

日期：2026-11-01。独立工作目录：`E:\dev\js\astra-credential-broker`。本次未提交、未推送、未发布 Release。A1/A2 已按用户确认的本机验收方式完成；A3—A8 尚未接线。

## 1. 环境与产物

| 项目 | 实测 |
| --- | --- |
| OS | Windows 10 build 19044，x64，当前普通用户（中完整性级别） |
| 开发 SDK | .NET SDK 10.0.300 |
| 本机预装 runtime | .NET 10.0.8（另有 8.0.27） |
| 发布运行时 | 自包含 .NET 10.0.13，System.Private.CoreLib 实际来自复制安装目录 |
| SQLite / DPAPI | Microsoft.Data.Sqlite 10.0.13；ProtectedData 10.0.13 |
| 组件目录 | `artifacts/publish/win-x64/`，含 native SQLite 和完整 runtime |
| 验收工具 | `artifacts/smoke-tools/win-x64/broker-smoke.exe`，独立自包含 |
| 最终本机报告 | `artifacts/acceptance-shared-host/validation-result.json`，passed=true，29 项检查 |
| 数据 | 全部为虚构不透明字节，无供应商请求，无产品数据库访问 |

最终 publish 目录共 83,244,560 字节；`component.json` 的 SHA-256 为 `df6175921c6bdbc97459ede34de5ca369398f7a3ffaab3f3150d43d4fa4e3b83`。该摘要用于对应本机验收产物，不是生产发行签名。

按用户要求直接在本机验证，没有执行干净虚拟机测试，也未人为关闭整台机器网络。安装和验收代码只使用本地文件、进程、DPAPI 与命名管道，没有下载入口或供应商网络请求；工具不调用系统 dotnet/Node/pnpm。bundled-runtime-and-sqlite 检查实际运行时路径，证明未使用本机预装的 10.0.8。

## 2. 独立检查

```powershell
dotnet restore --locked-mode
dotnet format --verify-no-changes --no-restore
dotnet build --no-restore
dotnet test --no-restore
dotnet list package --vulnerable --include-transitive
node test/interop/vector.mjs --dotnet test/Broker.Tests/bin/Debug/net10.0/interop-dotnet.json
./scripts/publish.ps1
./scripts/verify-local.ps1 -Root '<独立私有测试目录>'
```

- **82 项独立测试：81 通过、1 项 Unix 文件模式集成测试在 Windows 上跳过**：元数据类型、64 对/UTF-8/16 KiB 精确边界、重复字段、严格整数、修订/base64url、JCS Unicode、RFC 5869/NIST 向量、跨运行时迁移、缺失数据库不重建、AEAD 归属防篡改、ACL 拒绝、初始版本故障注入、丢响应恢复、错误主密钥/LOCKED、一次性准备/交接水位、权限、四客户端、会话/空闲退出、真实管道认证、队列、TTL/hardDeadline、fence/代次、失败释放、事务回滚、C1→C2→C3、分页、元数据补丁与广播订阅。
- .NET 构建通过，warnings-as-errors，0 警告/0 错误；C# 格式检查通过。
- JavaScript 生成的包由 .NET 解密，.NET 生成的包由 JavaScript 解密，双向通过；包括 U+2028/U+2029、非 BMP 字符、UTF-16 排序和不透明二进制。
- NuGet 的当前漏洞源未报告任何直接或传递依赖漏洞；这是本次检查结果，不代表未来持续保证。

## 3. 真实 publish 安装冒烟

最终报告中的 29 项检查全部通过：

| # | 检查 |
| --- | --- |
| 1 | bundled-runtime-and-sqlite：运行时和 SQLite 来自自包含目录 |
| 2 | initial-not-installed：初始状态准确 |
| 3 | local-copy-install-and-register：复制到独立位置并登记 |
| 4 | discovery-does-not-start-service：发现不拉起服务 |
| 5 | four-concurrent-starts-one-generation：四方同时 ensureRunning 只有一个代次 |
| 6 | initial-export-independent-of-products：无产品依赖完成初次导出 |
| 7 | migration-validation-and-wrong-key-rejection：错误密钥拒绝，正确密钥验证 |
| 8 | prepared-handoff-and-idempotent-receipt：准备/交接及回执重放 |
| 9 | metadata-discovery-filter：排除仅推理的示例凭据 |
| 10 | opaque-c1-c2-c3-and-commit-replay：不透明内容更新及成功重放 |
| 11 | durable-replayable-change-events：持久变更通知 |
| 12 | verified-crash-target-identity：故障注入前校验 PID/创建时间 |
| 13 | independent-supervisor-crash-restart：worker 被终止后监督进程自动恢复 |
| 14 | restart-retains-original-lease-deadlines：重启不延长租约 |
| 15 | missing-service-key-is-locked：密钥缺失进入 LOCKED |
| 16 | independent-management-unlock：独立管理端解锁 |
| 17 | interrupted-replacement-restores-old-registration：替换异常恢复旧登记 |
| 18 | installer-process-crash-leaves-durable-journal：安装器进程中断保留恢复事实 |
| 19 | next-controller-recovers-interrupted-install：下次管理恢复未完成安装 |
| 20 | same-version-reinstall-independent-directory：同版本重装使用新唯一目录 |
| 21 | reinstall-retains-data-keys-and-client-grants：保留数据/密钥/授权 |
| 22 | explicit-force-recovery-confirms-old-processes-exit：强制恢复先确认退出和锁 |
| 23 | uninstall-preserves-vault-keys-and-bindings：卸载保留 vault 和绑定 |
| 24 | service-survives-launching-controller-exit：启动控制器退出不停止服务 |
| 25 | reinstall-restores-control-receipts：重装恢复准备/移交回执 |
| 26 | cli-grant-protects-access-material：CLI 授权材料写 DPAPI 文件，不输出令牌 |
| 27 | cli-read-writes-only-explicit-dpapi-response：CLI 读取秘密只写显式响应文件 |
| 28 | foreground-entry-shares-business-and-key-recovery：前台复用服务与密钥恢复 |
| 29 | foreground-graceful-stop：前台排空退出 |

验收结束已卸载该测试组件，停止 worker/supervisor；保留测试 vault、虚构凭据的 DPAPI 材料与结果报告供复核。没有修改默认产品凭据后端。

## 4. 已确认的实施选择

用户确认后台采用独立隐藏监督进程、默认按需启动。最终实现移除了任务计划方案，没有计划任务、PowerShell 启动包装器或 SCM 服务注册。默认没有登录常驻；手动重启/按需启动和 60 秒空闲退出均复用同一业务入口。

用户确认 A2 直接在本机验证。本记录明确保留未执行干净虚拟机、未执行其他 OS/架构、未执行真实 provider 账号的边界。生产 Release 签名、下载校验和安全解包由 A3/A4 完成，本地清单 SHA-256 不被当作发行签名。

## 5. AstraConductor 文档与回归

父仓库只追加/更新凭据共享设计、实施计划、A1/A2 详细设计及文档索引，没有接入产品。

- pnpm typecheck：通过。
- pnpm test：333/333 通过（contract 6、core 191、UI 60、desktop 76）。
- pnpm build：通过。
- 本次四份文档的 Prettier 检查：通过。
- pnpm format:check 全仓检查：未通过，报告 121 个本次未修改文件的既有格式问题；未扩大修改范围去修复它们。

本次没有修改 Electron/native/产品打包实现，没有运行产品 package；broker 自身的自包含 publish 与本地安装/重装已实际执行。

## 6. 平台隔离与缺失能力复查

2026-11-01 按平台边界重组后重新发布并执行 82 项单元测试（81 通过、1 项 Unix 专用用例跳过），并通过双向互操作与 29 项真实组件验收；最新报告时间为北京时间 16:00:43。原始报告及上一轮复查报告保留在 artifacts/acceptance-a1-a2、artifacts/acceptance-platform-review 、artifacts/acceptance-platform-isolation 和 artifacts/acceptance-shared-pipes，仅作历史记录；上方产物大小、摘要和最终报告均对应当前平台隔离版本。

- 所有 C# 项目以 net10.0 编译。Windows 标注只存在于 Platform/Windows 的身份/文件/密钥实现；共享 ComponentHost 只在执行权限等实际差异处检查 OS，平台组合由 BrokerPlatform 工厂选择；未禁用 CA1416 或降低 warnings-as-errors。业务、安装编排和 CLI 没有 OS 判断或 Windows 标注。
- 增加 11 个平台相关测试用例，覆盖五组缺失能力的名称/平台信息、目录创建拒绝、客户端及服务端传输拒绝、缺失密钥保护不发布版本/不落明文，以及使用不同身份与密钥保护实现的初始化、租约提交和重开读取。测试替身只在 test/ 内，不作为生产权限实现。
- Windows 适配集成测试使用明确的 WindowsFact/WindowsTheory 标记；协议/密码和 PlatformTests 不需要这些标记。本次在 Windows 上 81 项通过，1 项 Unix 文件模式集成测试明确跳过。Linux/macOS 的真实宿主运行仍未验证，模拟缺失能力不等于交付这些 OS 的完整服务。
- 独立 net10.0 外部调用方可直接引用 Vault、BrokerService、ComponentManager 的业务 API，无需 OS 断言或 Windows 标注；同时运行中立 schema/crypto 并确认模拟缺失 secret-protection 的专门异常。探针保留在忽略目录 artifacts/platform-analyzer-check。
- 实际发布 CLI 的 help/schema 命令成功；生成 schema 与 schemas/protocol-v1.schema.json 的 SHA-256 一致，协议 v1 结构未变。Windows SID、DPAPI entropy/槽文件名、目录身份、默认 home 和命名管道地址保持兼容。
- 移除旧 WindowsSecurity/PlatformSupport；原生目录查询保留在 WindowsPrivateFileSystem，DPAPI 在 WindowsSecretProtector，本地管道在 Shared/NamedPipeTransport，隐藏启动/资产/进程核验在共享 ComponentHost/Profile。LocalFiles 保留中立文件机制。
- 向量继续使用纯 ASCII JSON 的可见 Unicode 转义，并通过 .NET/JavaScript 双向认证解密。生成器与 .NET 测试保留 U+2028/U+2029、中文键和 emoji 的语义检查。
- 当前测试组件已卸载，worker/supervisor 已退出；没有接入产品、提交或推送。

## 7. NamedPipe 共享实现修正

NamedPipeServerStream/NamedPipeClientStream 的字节模式与 CurrentUserOnly 有 .NET Unix 实现；此前把不含 Windows 专用操作的适配标为 Windows-only 属于边界划分过度。现移到 Platform/Shared/NamedPipeTransport，移除 Windows 标注，工厂在 Windows/Linux/macOS 复用该实现。ILocalTransport 仍隔离协议与具体传输。

新增两项不带 Windows 测试标记的实际传输测试：无需用户身份/存储适配的双向帧收发、取消监听后同地址重新监听收发。该轮在 Windows 上通过，当时总测试数为 67；当前总数及最新产物以本节上方与下一节为准。Linux/macOS 的源码/API 支持依据不替代实机验收，完整服务仍缺少其他平台能力。

## 8. Windows/Linux/macOS 共享组件宿主

WindowsComponentHost 已移到 Shared/ComponentHost，去掉整类平台限制。进程身份、探测/worker 等待、超时、核验后终止共用一份实现。ComponentHostProfile 提供 win/linux/osx 的 apphost、原生库、默认 home、文件名和路径比较策略；实际运行 RID 保留 linux-musl。Unix 复制会保留普通权限、去除特殊权限并补 apphost owner execute。

新增 15 个测试用例：三系统/架构及 musl 资产布局、两个 Unix 平台的参数/stdio 策略、Windows 隐藏 Shell 启动保持、默认目录与 XDG 回退、Unix 文件名/路径策略、当前进程创建时间核验，以及仅在 Unix 执行的复制权限集成。当前 Windows 运行结果为 81 通过、1 跳过；不能将 Linux/macOS 策略用例当作这两个 OS 的实机运行证据。

最新共享宿主产物已重新通过 29 项真实 Windows 安装/监督重启/卸载重装/强制恢复/前台验收，测试组件卸载且 worker/supervisor 退出。Linux/macOS 工厂现在提供 Transport 与 Components；仍缺少用户身份、私有目录权限和系统密钥保护。发布/验收脚本与完整组件交付当前仍是 Windows x64，没有宣称已交付完整 Unix broker。
