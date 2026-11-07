# 协议 v1 与 API

本协议面向应用后台与第三方协议实现。产品 UI 不直接接管道，不接收完整 payload。SDK 可选；broker 不依赖 TS 包。结构定义见 [protocol-v1.schema.json](../schemas/protocol-v1.schema.json)，由严格 DTO 生成，额外字节限制、权限、密码白名单和状态语义以本文及服务实现为准。

## 1. 传输、握手与授权

Windows 命名管道名：

```text
astra-credentials-v1-BASE64URL(SHA256(UTF8(ownerSid + ":" + vaultId)))
```

客户端从当前用户独立安装登记找到 vaultId 与规范数据路径，再用管道连接；runtime/endpoint.json 提供辅助诊断，不能代替认证。共享 NamedPipeTransport 的两端都使用 `PipeOptions.CurrentUserOnly`，中立协议层只处理 Stream；.NET 在 Unix 使用 Unix domain socket，仍采用字节模式和同用户校验。完整非 Windows 服务仍需其他平台能力的实现。没有 TCP/HTTP 端口。

一帧为 **4 字节小端有符号长度 + UTF-8 JSON 字节**。长度须为 1 至 2 MiB，最大 JSON 深度 32。拒绝重复属性、未知 DTO 字段、非规范二进制编码及不匹配协议版本。不接受字符串冒充整数或布尔值。

三种版本职责分别定义：组件版本是 SemVer 字符串，供更新检查使用，支持 prerelease/build metadata，不参与能否工作的大小或精确匹配判断；协议版本是从 1 起的整数，只决定通信格式能否打通；API 版本（沿用字段名 `apiRevision`）是 decimal 功能级别，通常写整数，类似 API level，实际服务 API 必须满足客户端所需级别。三者独立演进，不要求 API 变化与组件 SemVer 同步递增。

当前未发布组件草稿仍为 `0.2.0`，协议版本为 `1`，API 级别为 `2`，包含 A6—A8 所需 `getSharingState` 和 `cancelQueuedUpdate`。例如较旧组件 `0.1.0-alpha+build` 的 API `2.5` 可以满足所需 API `2`；较新组件 `99.0.0` 的 API `1.9` 仍不满足。组件版本字段的 SemVer 语法和认证完整性仍检查，但不比较它与已安装 release 是否相同。

现有存储/迁移包格式是独立的数据读写边界，本轮保持 v1，不执行数据迁移，也不把它混入上述三种版本职责。

1. server → client：`Greeting { protocolVersion:1, apiRevision:2, componentVersion:"0.2.0", vaultId, generation, nonce }`，nonce 为随机 32 字节 base64url。
2. client → server：`Hello { protocolVersion:1, apiRevision:2, clientId, instanceId, clientNonce, proof, management:false }`。clientNonce 同为随机 32 字节。apiRevision 表示本客户端所需 API，服务只要求非负精确 decimal 且 `client.apiRevision <= server.apiRevision`；API 1/1.5 客户端可连接 API 2 服务，所需 2.125 不行。缺字段由严格 DTO 拒绝，不等同于所需 0；不额外设客户端 API 最低下界。
3. 双方使用 `verifier = SHA256(accessTokenBytes)`。client proof 为以下数组规范 JSON UTF-8 字节的 HMAC-SHA-256，编码 base64url：

```text
["astra.pipe-auth.v1", "client", serverProtocolVersion, serverApiRevision,
 serverComponentVersion, vaultId, generation, serverNonce,
 clientApiRevision, clientId, instanceId, clientNonce, management]
```

4. 服务校验授权身份与证明后返回 `Welcome { proof }`，server proof 使用相同数组，仅将 `"client"` 换为 `"server"`。客户端验证后才发送业务秘密。

API 字段在线上仍为 JSON number，不接受字符串代替。两个 API 证明位置也仍是 JSON numeric token，专用编码器使用精确规范十进制：`2`、`2.0`、`2e0` 均编码为 `2`，`2.50` 编码为 `2.5`；不经 IEEE-754 浮点，不把数字改为字符串。其余证明元素保持原规范编码；已有整数 API 2 的证明逐字节不变，普通记录和迁移包的 canonical 数字域仍只接受安全整数。

API 数值采用 .NET decimal 的精确非负域：96 位系数不超过 `79228162514264337593543950335`，去除无意义零后的 scale 为 0—28。指数输入可归一化；`9007199254740993` 和 `2.0000000000000000000000000001` 均精确支持。无法精确表示的输入直接拒绝，不舍入为邻近级别；不以 Int32 或 JavaScript 安全整数限制 API。DTO 使用 decimal，schema 为 number；客户端解析原始数字文本后精确比较。

版本字段与客户端 API 声明均纳入双向证明，防止字段篡改；认证组件版本不代表以其大小决定功能兼容。缺失 apiRevision 或 API 不足的服务在业务请求前拒绝，禁止先发 `getSharingState` 再以 method-not-found 推断能力。原无 API 声明的客户端须更新握手。

升级控制器仅在显式生命周期管理路径允许旧版管理握手，且连接强制限制为 `status`、`stop`、`disconnect`；不能读取 payload、导出、授权、解锁或执行共享业务。普通客户端不能开启该通道。此通道用于安全排空正在运行的 0.1.0 服务，不放宽新安装/产品连接的兼容与完整性检查。

生命周期通道以固定的生命周期 API 2 构造新式 Hello，并继续认证完整版本字段。普通管理和生命周期管理都只按通信协议与 API 需求判断可服务性，不设 release 最低值或运行 release 精确匹配门槛；生命周期连接额外限制方法白名单。只有无 API 声明的旧握手需要显式旧版生命周期通道。

`management:true` 只能使用该 vault 独立 DPAPI 管理材料认证，普通客户端接入令牌不能提升为管理权限。管理入口与普通入口共用管道传输，但认证域与授权判断分离。握手最长 5 秒，单连接闲置读取最长 50 秒，同时连接最多 64。客户端应定期 heartbeat，或通过普通请求维持会话。

clientId 为稳定登记身份；instanceId 是客户端自己维护的逻辑实例 ID，重连/查原操作时保留，真正新实例重新生成。不同客户端/实例不能操作彼此的许可或回执。

## 2. 请求与响应

```json
{
  "protocolVersion": 1,
  "id": "request-unique-id",
  "method": "listCredentials",
  "params": {
    "limit": 50,
    "metadataEquals": { "supportsUsage": "true" }
  }
}
```

成功：`{ id, ok:true, result, error:null }`。失败：`{ id, ok:false, result:null, error:"stable-code" }`。请求 id 只做响应关联，不代替跨请求幂等 operationId。每个连接的请求/响应按顺序处理；长轮询用独立连接，避免阻塞同连接提交。

所有 ID 匹配 `[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}`。修订、fence 与事件游标为无前导零的非负十进制 Int64 字符串；时间戳是 Unix 毫秒整数。未知方法报 method-not-found。

## 3. 数据对象

```typescript
type CredentialDescription = {
  credentialId: string;
  revision: string;
  createdByClientId: string;
  lastUpdatedByClientId: string;
  metadata: Record<string, string>;
  contentType: string;
  payloadFormatVersion: number;
};
type Credential = { description: CredentialDescription; payload: string };
type LeaseRef = {
  operationId: string;
  leaseId: string;
  fence: string;
  generation: string;
  baseRevision: string;
};
```

payload 是无填充 base64url，解码最多 1 MiB。contentType 长度 1—256 字符，payloadFormatVersion 为 1—1000 的整数，broker 不解释其含义。描述和事件不含 payload。metadata 的所有限制同时用于创建、完整结果与筛选条件。

Operation 包含 operationId/credentialId/clientId/instanceId/status、leaseId/fence/generation/baseRevision、grantedAt/expiresAt/hardDeadline、resultRevision/requestHash 及失败分类。Operation 不保存 payload、迁移密钥或主密钥。

## 4. 普通后台 API

| method | params | result | 权限与行为 |
| --- | --- | --- | --- |
| `status` | `{}` | ServiceStatus | 不读取 payload；进程状态、版本、ownership、generation、会话数、无秘密错误码分别返回 |
| `getSharingState` | `{}` | `{ vaultId, storageVersion, attemptId, keyId, sourceWatermark, sourceClientId, preparedClientIds, ownership }` | import 或 handoff scope；只含当前版本与来源水位匹配且未撤销的准备身份，供接收方证明与来源交接；不返回 payload 或密钥 |
| `heartbeat` | `{}` | `{ expiresAt }` | 延长本逻辑实例会话 45 秒；不延长记录许可 |
| `disconnect` | `{}` | `{ disconnected:true }` | 只解绑当前实例，取消其未获准队列；在途许可保留到原 TTL |
| `listCredentials` | `{ limit?:50, afterCredentialId?, createdByClientId?, lastUpdatedByClientId?, metadataEquals? }` | `{ items:CredentialDescription[], nextCursor }` | describe scope；页大小上限 1—200，达到消息字节预算时提前分页，权限内过滤，多个筛选 AND；nextCursor 用作下一次 afterCredentialId |
| `getCredential` | `{ credentialId }` | Credential | read scope 与该记录授权；读取当前已提交记录 |
| `createCredential` | `{ credentialId, operationId, contentType, payloadFormatVersion, payload, metadata, coordinationKey? }` | Credential | create+read scope 与记录授权，仅 ownership=broker；归属取认证身份；同 ID 不复活墓碑 |
| `beginUpdate` | `{ credentialId, observedRevision, operationId }` | `{ status, credential, operation }` | update+read scope；granted 返回许可和当前记录，queued 不返回 payload，stale 返回当前记录；queued 用原请求轮询 |
| `markUpdateStarted` | LeaseRef | Operation | 收到持久化回执后客户端才调用供应商；不改变截止时间 |
| `renewUpdate` | LeaseRef | Operation | 只在未过期且匹配当前许可时续期，最晚到 hardDeadline |
| `commitUpdate` | `{ lease:LeaseRef, payload?, contentType?, payloadFormatVersion?, setMetadata?, removeKeys?, delete?:false }` | Operation | 必须 started；省略字段保留当前内容，元数据补丁与 payload/修订/事件原子提交；delete 额外需要 delete 权限 |
| `abortUpdate` | `{ lease, result:"failed", failureCode, retryable, upstreamOutcome:"unchanged"\|"unknown" }` | Operation | 立即失败释放；成功、过期或已释放操作返回相应终态；不会释放新持有者 |
| `getOperation` | `{ operationId }` | Operation 或无秘密控制回执 | 只能查询自己的更新操作；初始化/准备/移交回执按 clientId 保护，管理端可查控制回执 |
| `cancelQueuedUpdate` | `{ operationId }` | Operation | 仅取消当前 clientId/instanceId 的 queued 票据；已授予或终结时返回现态，授予竞争需按返回许可主动 abort，不解绑同实例其他请求 |
| `getEvents` | `{ cursor?:"0", limit?:100 }` | `{ items, nextCursor }` | events scope；每次扫描最多 1000 条，返回最多 200 条获准事件；即使 items 空也保留返回游标 |
| `watchEvents` | `{ cursor?:"0", limit?:100, waitMilliseconds?:5000 }` | EventPage | 0—5000ms 长轮询，提交广播唤醒；事件可重放，客户端按修订防乱序 |

事件为 `{ credentialId, revision, eventSequence, kind:"credentialChanged"|"credentialDeleted" }`。metadata 变化也递增修订并通知，筛选客户端需重新查询描述。删除只发无秘密墓碑事件。

createCredential 重放不会重复创建；返回该记录当前已提交视图。commitUpdate 重放返回原成功 Operation，revision 不变。终结的失败操作不能重新使用 operationId 发起刷新。

failureCode 只接受：network-error、request-timeout、provider-error、parse-error、cancelled、upstream-unknown、authorization-required、invalid-result、client-shutdown、unknown-error。供应商原始错误或可能包含 token 的文本不得写入失败分类。

## 5. 初始化、迁移与共享建立 API

| method | params | result | 规则 |
| --- | --- | --- | --- |
| `initialize` | `{ operationId, sourceWatermark, records:InitialRecord[] }` | `{ storageVersion, attemptId, keyId, state:"exported", migrationKey }` | initialize scope；单次至多 1000 条且总请求/迁移包受 2 MiB 限制；初次响应含迁移密钥，回执重放的 migrationKey 为 null |
| `recoverDelivery` | `{}` | `{ migrationKey }` | 仅来源 initialize 身份、且尚未 acknowledgeDelivery；不能从普通回执恢复秘密 |
| `acknowledgeDelivery` | `{}` | `{ acknowledged:true }` | 来源确认已向用户交付，持久记录后删除服务交付恢复槽 |
| `validateMigration` | `{ migrationKey }` | `{ vaultId, storageVersion, attemptId, keyId, recordCount }` | import scope；完整 AEAD 验证初始包，不返回主密钥；应用仍须自行验证并缓存主密钥 |
| `prepareChallenge` | `{}` | `{ challengeId, nonce, expiresAt }` | import scope；60 秒、一次性、绑定当前 clientId |
| `prepareClient` | `{ operationId, sourceWatermark, challengeId, proof }` | `{ storageVersion, state:"prepared" }` | import scope；主密钥 HMAC 证明，成功回执幂等；同挑战不能换 operationId 再使用 |
| `handoff` | `{ operationId, sourceWatermark, requiredClientIds:string[] }` | `{ storageVersion, ownership:"broker" }` | handoff scope、来源身份、匹配水位、至少两个已准备身份并包含来源；不同于版本发布 |

`InitialRecord = { credentialId, contentType, payloadFormatVersion, payload, metadata, coordinationKey? }`。不接受客户端提供归属字段。

准备证明为 base64url(HMAC-SHA-256(masterKey, UTF8(JCS(array))))，其中 array 是：

```text
["astra.prepare.v1", vaultId, storageVersion, clientId,
 operationId, sourceWatermark, challengeId, challengeNonce]
```

该证明说明客户端持有正确主密钥；产品自己的“已完成安全缓存”和“来源已冻结/水位复查”由客户端保证。broker 不读取产品库验证这些事实。

## 6. 独立管理 API

| method | params | result |
| --- | --- | --- |
| `registerClient` | `{ clientId, scopes:string[], credentialIds:string[], allCredentials?:false }` | `{ clientId, accessToken }`，只在显式授权响应返回随机令牌 |
| `revokeClient` | `{ clientId }` | `{ revoked:true }`；保留历史身份和归属，移除活跃会话/排队 |
| `unlock` | `{ masterKey }` | ServiceStatus；masterKey 为 32 字节 base64url，验证后保存服务自己的 DPAPI 槽 |
| `stop` | `{}` | DRAINING ServiceStatus；禁止新许可，在途排空，最长 30 秒后退出 |

允许授予的 scopes：describe、read、create、update、events、initialize、import、handoff、delete。allCredentials=false 时每条记录都还需匹配 credentialIds。管理认证不是可授予普通客户端的 scope；它不能由 Hello 的 management 标志自行取得。

## 7. 错误与恢复

| 分类 | 典型错误码 | 客户端处理 |
| --- | --- | --- |
| 能力支持 | platform-feature-unavailable | 当前平台缺少所调用能力的实现，不按临时故障重试或创建替代空库；CLI 同时给出 feature/platform，库抛出 PlatformFeatureUnavailableException |
| 格式 | invalid-request、duplicate-property、message-too-large、invalid-metadata、invalid-base64url、invalid-revision | 修正请求，不重放错误结构 |
| 身份 | unauthorized、forbidden、management-required、client-revoked、session-expired、server-identity-mismatch | 重新授权/连接；不自动提高权限 |
| 通信与 API | protocol-incompatible、api-incompatible | 前者表示通信协议不匹配，后者表示实际 API 不满足客户端所需；组件 SemVer 大小不参与判断 |
| 安装与数据边界 | component-incompatible、component-probe-failed、storage-incompatible | 检查平台/产物一致性或独立数据格式；不创建新空库代替旧数据 |
| 状态 | vault-locked、ownership-not-transferred、service-draining、already-published、client-not-prepared | 根据状态继续解锁/准备/回执查询 |
| 并发 | lease-expired、stale-fence、revision-conflict、operation-terminal、update-not-started | 停止旧请求，查询原操作并读取当前记录；需要刷新时新 operationId |
| 幂等 | operation-conflict | 同一 operationId 的身份/参数不同；禁止静默覆盖 |
| 密码 | authentication-failed、invalid-proof、invalid-challenge、migration-digest-mismatch、invalid-crypto-parameters | 不导入、不返回明文，保持现有数据 |
| 平台 | lock-busy、io-failure、access-denied、vault-identity-mismatch、component-integrity-failed、detached-launcher-unavailable | 保留数据，独立诊断后重试 |

业务异常只返回稳定分类，不回显异常消息、请求体或供应商错误。操作提交响应丢失先查 getOperation 或重放相同 commit；不能把未知提交结果报成刷新失败并再次使用旧 token。

## 8. CLI 秘密文件

`grant` 从 stdin 读取 RegisterClient，输出令牌只写 `--out` 指定的受控私有目录文件。`rpc` 的 initialize/recoverDelivery/getCredential/beginUpdate/createCredential/registerClient 必须提供 `--response-file`；stdout 仅返回保存位置。文件内容是 DPAPI(CurrentUser) 加密的 JSON，purpose 为 `cli-secret:<vaultId>`。测试/后台可调用相同平台组合的 Secrets.Unprotect 读取，普通设置页不得读取并展示。

使用 `rpc --client-file <file> --instance <stable-id>`，或独立管理端的 `--admin`。请求体统一从 stdin 传入；不要把迁移密钥、主密钥、accessToken 或供应商秘密写入 shell 历史、环境变量、URL 或命令行参数。
