# Windows 本地安装、发现与恢复

本次只实现 A2 的显式本地复制安装。没有 Release URL、生产下载器、自动下载、系统服务或计划任务依赖。用户已确认采用 **独立隐藏监督进程，默认按需启动**；不要求产品进程常驻。

当前完整生产组合和自包含发布架构为 Windows x64；命名管道和组件进程宿主已采用 Windows/Linux/macOS 共享实现，当前缺少的是 Linux/macOS 的用户身份、私有文件系统和密钥保护适配。库、CLI 与状态机使用平台接口；尚未实现的能力在调用时抛出 `PlatformFeatureUnavailableException`。CLI 返回 `platform-feature-unavailable`、具体 feature/platform 和退出码 1，不先做全局 Windows-only 拒绝；help/schema 等中立操作不依赖安装宿主。

发布/验收 PowerShell 脚本明确面向 win-x64 工作流，脚本入口会拒绝其他宿主。从其他 OS 直接执行 win-x64 EXE 时，操作系统/宿主也可能在托管入口前拒绝加载，该情况无法由 CLI 格式化为 JSON。需要目标平台的可运行宿主及实际平台适配，才能交付该平台完整服务。

## 1. 发布产物

开发工具链固定 .NET SDK 10.0.300，应用自包含 runtime 固定 10.0.13，Microsoft.Data.Sqlite 与 ProtectedData 固定 10.0.13，传递依赖由 packages.lock.json 固定。

```powershell
dotnet restore --locked-mode
./scripts/publish.ps1
```

`artifacts/publish/win-x64/` 包含 brokerctl.exe/DLL、deps/runtimeconfig、.NET runtime、hostfxr/hostpolicy/coreclr、SQLite native DLL 与 component.json。SelfContained=true；PublishAot、PublishTrimmed、PublishSingleFile 均为 false。验收工具另发布到 `artifacts/smoke-tools/win-x64/`，不能作为运行服务的依赖。

component.json 包含组件 SemVer、`apiRevision`、RID、协议/数据格式范围及每个文件的相对路径、长度、SHA-256。组件 SemVer 只用于更新检查；协议整数版本只决定通信；API decimal 级别决定关键功能兼容。当前未发布 release 草稿仍为 `0.2.0`、协议为 `1`、API 为 `2`，三者独立演进。release 唯一定义位于 `Directory.Build.props`，manifest、CLI help/component-info 与握手从 InformationalVersion 读取完整 SemVer，保留 prerelease/build metadata。现有数据格式继续保持 v1，本轮不执行存储迁移。

来源和复制后的完整性校验通过后，安装器执行候选组件的 component-info，要求 component/version/apiRevision 与 manifest 一致，实际 protocol/storage 落在声明范围且符合当前格式、SQLite 可运行，才进入维护与替换。此处 release 一致性检查证明清单描述的是该候选产物，属于安装完整性，不是 release 功能门槛。缺失/不足 API 在业务操作前报告 incompatible；有效 SemVer 更旧或更高均不影响 API 级别比较。A2 的显式本地来源属于用户选择的开发信任输入；摘要用于完整性检查，不代替后续发行签名与可信下载配置。

## 2. 安装和登记

```powershell
$ctl = 'X:\copied-publish\brokerctl.exe'
& $ctl install-local --source 'X:\copied-publish'
& $ctl register-vault --vault "$env:LOCALAPPDATA\AstraConductor\Credentials\v1"
& $ctl install-status
& $ctl ensure-running --vault "$env:LOCALAPPDATA\AstraConductor\Credentials\v1"
& $ctl status --vault "$env:LOCALAPPDATA\AstraConductor\Credentials\v1"
```

可对每个命令统一指定 `--home <独立私有服务目录>`。home 与 vault 必须分离，不得互相包含。源码输出目录不登记为常驻安装；install-local 把完整 publish 复制到 home/components 下的新唯一目录，再验证、探测和原子登记。默认不会创建产品业务库，也不会接入任何产品。

安装过程持有当前用户组件管理锁。先验证来源和暂存副本，再建立恢复日志/维护标志，排空全部已登记 vault，最后原子替换 installation.json。两个并发安装或 ensureRunning 请求在同一锁下合并/串行处理；下载/复制/探测失败保留旧安装。

install-status 与 status 都不启动服务。安装状态与运行状态分开：安装完整但连接失败不会被报告为未安装。FAILED/LOCKED 也不触发自动重建共享库。

普通管理连接（包括 grant 前的认证）和 ensureRunning 的实例复用先校验安装清单，再校验运行握手的协议和实际 API 级别。运行组件 SemVer 与安装登记不同不会拒绝业务，运行 API 更高也无需与清单精确相等；只要其满足客户端所需 API。握手仍认证所有版本字段。完整组件摘要验证在短时管道连接计时之前完成，避免校验耗时消耗连接预算。

## 3. 按需运行与监督

ensureRunning 校验安装、逻辑 vault 身份及登记，取得组件锁后复用已有端点；没有可用服务时从已登记组件目录隐藏启动独立 supervise 进程。启动器在 Windows 使用隐藏 Shell 方式；Linux/macOS 使用 nohup 与固定 shell 重定向/exec，EXE 与参数通过 ArgumentList 传入，标准输入输出在 exec 前切到 /dev/null。Unix 需要 /usr/bin/nohup 与 /bin/sh，缺失时报告 detached-launcher-unavailable。调用它的 CLI/产品退出不停止 supervisor 或 worker。

supervisor 取得 supervisor.lock，记录自己的 PID/创建时间，然后隐藏启动 serve worker。worker 独占 vault.lock，恢复版本、回执和原租约，写入端点后接受连接。并发请求只能得到同一有效 worker。进程监督只针对该 vault，不包含产品进程。

worker 正常排空或空闲退出时，supervisor 一起退出。worker 异常退出时最多重新尝试 3 次，按有限退避执行；预算耗尽保留 FAILED 状态，用户可诊断后重新 ensureRunning。主密钥保存在服务自身的 DPAPI 槽，不依赖最早导出客户端。

默认没有登录自启或常驻模式：全部会话和在途许可结束后空闲 60 秒退出。当前版本不创建计划任务或注册 Windows SCM 服务。未来若需要常驻，可在平台适配层扩展，不能改变租约和唯一写入者规则。

## 4. 独立管理与前台调试

```powershell
& $ctl stop --vault <vault>
& $ctl restart --vault <vault>
& $ctl serve --vault <vault>     # 同一业务入口，前台控制台/断点调试
& $ctl recover --force --vault <vault>
```

普通协议客户端没有 stop/recover/授权/安装权限。管理 RPC 使用独立 DPAPI 材料；CLI stop 先持久化 stop.request，再通过管理通道排空，确认 worker 与 supervisor 都已退出且能取得两个 OS 锁后才返回。

recover --force 是用户显式管理动作：可终止已验证 PID、进程创建时间和已登记 EXE 路径的本 vault worker/supervisor。确认旧进程退出并取得锁后才启动新 generation。正常 ensureRunning 不杀进程；无法确认旧进程退出的卸载/替换报告失败，不启动竞争写入者。

前台 serve 与后台 worker 共用加密、授权和数据库入口，Ctrl+C 请求排空。前台调试仍需登记 vault；不能绕过逻辑 vault 身份/OS 锁。调试结束使用 stop 或 Ctrl+C，原数据与主密钥保留。

## 5. 重装、升级与卸载

重装从 **外部 publish 控制器副本** 执行，避免 Windows 中替换正在运行的安装控制器文件。直接从被替换目录运行会返回 external-controller-required，A4 的产品安装引导需要使用独立 bootstrap/controller 副本。

```powershell
& 'X:\copied-publish\brokerctl.exe' install-local --source 'X:\copied-publish'
& 'X:\copied-publish\brokerctl.exe' uninstall
```

新安装成功登记后才移除旧组件目录。卸载暂停同一 home 下全部 vault，设置维护状态，排空/确认退出，移除组件与活动安装登记。保留 vaults 登记、数据、服务密钥、客户端授权和迁移/交接回执。重装复用原服务身份与密钥，客户端原令牌继续有效；无法解锁时进入 LOCKED。

当前 0.2.0 安装器可排空仍在运行且无 API 声明的 0.1.0 产物：仅 TryStatus/Stop 管理路径使用旧握手，连接内白名单只有 status/stop/disconnect，普通产品连接要求所需 API 2。失败回滚可以校验并恢复旧组件原有文件摘要和登记；该旧产物仍因缺失 API 声明而 incompatible，而非因 SemVer 是 0.1.0。升级不转换 storage v1、不重建 vault、不清除主密钥或导入绑定。

新式 Greeting 无需 release 兼容例外：普通管理、产品和生命周期连接都只按协议及所需 API 判断功能兼容。生命周期连接仍限制三项方法，并使用固定生命周期 API 2；SemVer 只检查格式并参与认证，不作版本大小或运行版本一致性门槛。

本地失败恢复日志记录 previous/candidate/phase。prepared 阶段发生异常或安装器进程中断，下一次管理命令恢复旧登记、清除未发布候选并退出维护；committed 阶段恢复已完成的新登记。安装器与 vault 数据事务相互独立，任何失败都不删除共享数据。

卸载不调用产品清理逻辑，产品卸载也不调用 broker uninstall。数据/密钥永久删除未作为本次默认管理命令提供。

## 6. 离线验收

将完整 publish 和完整 smoke-tools 目录复制到任意本地位置，直接运行：

```powershell
./scripts/verify-local.ps1 -Publish 'X:\publish' -Tools 'X:\smoke-tools' -Root 'X:\private-validation'
# 也可不携带脚本，直接运行自包含验收工具：
& 'X:\smoke-tools\broker-smoke.exe' --publish 'X:\publish' --root 'X:\private-validation'
```

安装、登记、启动和验收路径不下载任何内容，不调用 dotnet/Node/pnpm，不加载产品。root 为独立测试目录，结束后卸载测试组件/停止测试进程，保留虚构凭据、DPAPI 测试材料与无秘密 validation-result.json，便于检查恢复证据。

本次按用户要求直接在本机验收。不存在“已执行干净虚拟机验收”的结论；本机可用 bundled-runtime-and-sqlite 检查确认实际运行的 System.Private.CoreLib 来自复制目录，而非系统预装 runtime。

旧版在线升级的隔离验证入口：

```powershell
./scripts/verify-compatibility-upgrade.ps1 -OldPublish 'X:\old-0.1.0-publish' -Publish 'X:\new-0.2.0-publish'
```

脚本为旧产物建立独立 service-home/vault，创建虚构加密凭据，保持旧服务在线，检查新控制器只读拒旧，再由新安装器排空升级并验证原 vault 版本和记录修订保留。结束卸载测试组件，保留无秘密 upgrade-result.json；不覆盖用户实际安装、导入状态或共享目录。

## 7. 共享宿主的 Unix 策略

ComponentHostProfile 已提供 Linux（包括 musl RID）与 macOS 的 apphost、原生库、默认 home 和路径策略。Unix 组件复制调用 PrepareCopiedFile 保留普通权限并补 apphost owner execute；PID/创建时间与 EXE 路径核验、工具超时、worker 等待和终止逻辑共用。

本仓库 publish/verify-local 脚本和 Smoke 工具目前仍面向 Windows x64 的完整交付验收。共享宿主实现可由 Linux/macOS 工厂选择，不代表这两个系统的完整 broker 已能安装运行：用户身份、私有目录与系统密钥保护仍明确报缺失能力。没有执行 Linux/macOS 实机验收，Unix 文件模式集成测试在 Windows 上明确跳过。

## 7. 用户所选目录与手动备份

新建 vault 接受不存在或为空的目录，已有目录的 ACL 和文件属主不作为拒绝条件，不自动收紧用户目录 ACL。broker 检查自己是否能创建、写入、改名、删除和打开所需数据；仅为自己新建的内部目录和文件设置权限，不遍历比较已有 ACL。加密、认证及完整性校验维持不变。

备份或移动应先 stop 并等待完成，再完整复制 vault；服务 home 的系统保护密钥需要保留，跨用户或缺少系统密钥时使用迁移密钥流程。还原不要求保留目录文件系统 ID 或原 ACL。旧 manifest 的 DirectoryIdentity 字段仍可读取，但不再绑定物理目录。新位置执行 register-vault 重新登记相同 vaultId；若该 vault 仍在运行则拒绝同时重绑。只复制 manifest 而缺少 control.db 的不完整备份不能创建空库替代。

## 8. 停止回复与空闲维护

停止 RPC 可能与 draining ticker 关闭连接竞争。收到 EOF 或传输超时后，控制器仍须等待旧进程退出并取得 vault.lock 与 supervisor.lock；未确认退出则报告失败，不继续覆盖组件。没有活动/排队操作的空闲轮询与没有本客户端排队票据的管理断开保持只读，避免等待空闲退出时持续追加凭据数据库 WAL。

## 9. API revision 2 本机验收（2026-11-06）

按独立的 SemVer/协议/API 语义修订后，127 项测试通过、1 项 Unix 测试在 Windows 跳过。覆盖 SemVer prerelease/build metadata、较旧 release 配足够 API 的握手和业务、新 release 配不足 API 的零请求拒绝、所需 API 1/1.5 连接服务 API 2、manifest/probe 候选完整性、旧管理方法白名单、decimal 指数归一化/大于 Int32 与 JS 安全整数/28 位小数精度、无法精确表示时拒绝，以及整数 API 原认证字节不变。

两端使用相同 verifier/身份/nonce 和组件 `0.0.1-beta+build.7` 的固定黄金向量核对认证字节及 HMAC：API `2.125`、`9007199254740993`、`2.0000000000000000000000000001` 三项均一致。期望证明由独立 Node crypto 对字面 canonical JSON 生成，.NET 与 TS 分别以固定常量断言，不是各自 roundtrip；普通迁移包 canonical 规则未扩展。

decimal 语义修订后的最终独立产物 `artifacts/publish/versions-separated-win-x64` 已重新完成 29 项生命周期验收，覆盖四客户端并发启动、迁移/接管、C1→C2→C3、崩溃重启、原许可截止时间、缺钥 LOCKED、重装回滚与恢复、卸载保留、CLI 秘密文件和前台停止；实际 runtime 来自自包含 .NET 10.0.13。最终结果为 `C:/Users/a/AppData/Local/AstraBrokerValidation/db638b7f032f421195a571ed450d44c0/validation-result.json`，测试组件已卸载。

分别使用 A3—A5 的 0.1.0 完整本地备份和 A6—A8 已增加方法但尚无 apiRevision 的 0.1.0 完整产物进行在线升级，两轮各 7 项检查通过：旧服务保持在线、新控制器只读判不兼容、新安装器排空替换、原 vault 版本及服务密钥保留、加密记录修订不变、新二进制报告 0.2.0/API 2/wire 1/storage 1。两个测试组件均已卸载；用户实际安装和导入绑定未在此验证中修改。

decimal 语义修订的最终产物另对 A6—A8 无 API 声明的旧产物复测在线升级，7 项全部通过，原数据版本、服务密钥和记录修订均保留。最终结果为 `C:/Users/a/AppData/Local/Temp/astra-broker-upgrade-27f308cbe58142df9e4a5e5cc65b315f/upgrade-result.json`；此检查拒绝旧产物的原因是缺 API 声明，而不是旧 SemVer。

新增严格安装验证时，首轮发现完整文件摘要读取消耗了原 300 ms 管道连接预算，导致新服务已 READY 仍被超时拒绝。校验现已移到连接计时之前，保留完整摘要校验；修复后的两套旧产物升级均通过。此验证使用隔离目录和虚构凭据，不代替生产下载或干净系统验收。
