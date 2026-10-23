# 安全握手与密钥


## 摘要

本模块回答三个问题：节点身份从哪来、name+secret 如何证明入网资格、两节点之间不被中继读到的会话钥匙怎么建立。用户已确认 P1 `network.token` 仅接受由 CSPRNG 生成的高熵 bearer secret（至少 128 bits），人类可记忆口令不在本版。当前 proposed 认证分支为 Noise/PSK；安全强度只适用于实际满足该生成政策的 token，字符串非空本身不能证明熵，软件当前也不宣称能从任意输入检测熵。

- **身份**：每个 Network 实例生成一对 X25519 静态密钥（进程内存），NodeID = `SHA-256(公钥)` 前 16 字节；
- **入网证明（已选定的高熵 token 分支；熵由调用方生成保证）**：`PSK = HKDF-Expand(HKDF-Extract(salt=name_utf8_raw, IKM=secret_raw_bytes), info=NetworkContext.Prologue("simpletier-v1/psk", nil), L=32)`；完整 name/canonical CIDR 经版本化 Descriptor 进入 Expand info。`name_utf8_raw` 是 network.name 的原始合法 UTF-8，非空且不含 NUL，不 trim、不做 Unicode normalization、不折叠大小写；空 secret 在 Runtime 和握手两层都拒绝。精确编码与有限观察见 3.1.1；派生成功不等于入网认证成功。
- **链路握手（有限实现观察）**：`internal/link.Handshake` 已使用固定 `github.com/flynn/noise v1.1.0` 的 Noise_XXpsk3（X25519 / ChaCha20-Poly1305 / SHA-256），绑定完整 Descriptor 和 Link tuple，验证静态公钥/NodeID。初建 CAPABILITY v1 是历史实现观察；当前实现报告为双向加密 CAPABILITY v2 strict-version gate，最终集成验证仍 pending。Network 当前只接入 CONTROL Lane；PACKET/STREAM 邻接、事实同步和完整 key-use/rekey 策略仍未完成。成熟库调用及同库两端测试不是独立协议互操作或完整产品安全证明；
- **端到端会话（选定的 proposed P1 分支）**：每条安装的 Path 按 SessionClass 建立 Noise_IKpsk2；握手消息逐跳转发且中继不可读。模式无关要求是每 Path 输出新鲜且独立的 session root/traffic keys，不同 Path 可并发持有不同 SessionID/root key；未来若新增人类口令支持，须另行设计认证与 key schedule。

被明确舍弃的复杂方案：自研握手、证书/PKI 体系、双套加密栈、按节点撤销与平滑轮换（P1 延后，见 3.4）。2026-09-22 应用户要求对照 EasyTier 安全设计（secure mode v3 / relay 会话 / credential）复核：其 nonce=epoch(u32)||seq(u64) 构造与本设计逐字节同构；采纳其 root_key 派生层次、双代际密钥保留、握手竞态规则和会话-公钥绑定；其弱项（弱摘要、弱加密、空凭据、未认证降级、AAD 留空）不采纳（对照表见第 5 节）。

## 1. 需求与模块约束


### 1.1 上层需求与边界

上层需求：[多协议覆盖网络](../multiprotocol-overlay.md) 的共享组认证（抗离线猜测要求调用方遵守已确认的 ≥128-bit CSPRNG token policy，软件不从非空字符串推断熵）、[TCP 虚拟覆盖网络](../tcp-overlay-network.md) 的认证邻接。本模块产出 [线上帧协议](wire.md) 所需的链路钥匙、逐跳子钥匙和端到端会话钥匙；帧格式、随机数、防重放不在本模块重复定义。

不负责：代理入口认证（SOCKS5/HTTP Basic，见多协议 feature）、地址分配（见 [拓扑与路由](topology.md)）、ACL 细则（P1 范围见多协议 feature）。

### 身份与入网凭据

每个 Network 实例生成一对 X25519 静态密钥，只存在于进程内存；NodeFact 必须携带 `StaticPublicKey`，NodeID = `SHA-256(静态公钥)` 前 16 字节。**重启后 NodeID 改变**（见 3.1），需要稳定寻址的部署用 `FixedIP` 钉住虚拟 IP。NodeID 不随 VirtualIP/Token 变化。接收方独立重算 NodeID 与公钥绑定。P1 provenance 已确认采用已认证 ingress Link + StaticPublicKey/NodeID 绑定，不要求 origin signature；FactEnvelope 的 Signature 字段只保留给未来更强隔离方案。当前配置只拒绝空 `network.token`，无法从字符串本身证明 CSPRNG 来源或 128-bit 熵；P1 使用者必须按已确认策略安全生成/保管 token，文档不对任意非空值提供抗离线猜测保证。

### 链路握手（每条 TCP 连接）

按用户已确认的高熵 token policy，当前 proposed Link handshake 为 Noise_XXpsk3_25519_ChaChaPoly_SHA256（X25519、ChaCha20-Poly1305、SHA-256），prologue = `NetworkContext.Prologue("simpletier-v1/link", NetworkID:u64be || LinkID:u64be || LinkEpoch:u64be || LinkGeneration:u32be || LaneID:u8)`（完整 Descriptor 经 3.1.1 编码进入 prologue；NetworkID 只作外层 locator，不是钥匙或状态隔离根）。LinkID 由发起方 CSPRNG 生成且不可复用；LinkEpoch 是每个 initiator/Network/Lane 下单调递增的物理连接代际；LinkGeneration 是本次 Noise Link 的非零 CSPRNG u32，仅在该 Link generation 内使用，重连重新随机生成，不要求等于 LinkEpoch。PSK 作为 psk 输入。三消息完成：Msg1/Msg2 先建立 Noise transcript，Msg3 完成静态公钥交换和 PSK 密钥确认（PSK/name/prologue 不在 Msg2 前宣称已认证）。双方最终互证静态公钥（→ NodeID）并证明 name+secret 成员资格；Noise 成功后按 [Wire CAPABILITY v2 目标](wire.md) 双向交换version2/mask0x7f，bit1为fact-sync.v2、bits6..63保留；严格拒绝v1或缺P1必需位，失败关闭且不交换FACT。初建 v1 是历史实现记录；当前 v2 gate 已有实现，最终运行链和验证见3.1.2。超时 5 秒。产出两方向 `link_root_key`；任一环节失败即断链，不降级、不重试弱模式。LinkID/LinkEpoch/LinkGeneration 元数据、静态公钥映射 NodeID、已有 NodeFact 时的 key-match 检查及认证后 CAPABILITY gate 是模式无关要求。LinkEpoch 由每个 initiator 维护一个本地单调计数器，键为 `(scope, ContextID, LaneID)`（ContextID 是完整 Descriptor 的 SHA-256，不能只按 u64 NetworkID locator 分区；`NextLinkEpoch` 及当前 CONTROL initiator 调用已实现）。该 NodeID 在此 Network/Lane 发起的所有 Link 尝试共用计数器，因此不依赖握手前识别 remote NodeID 或 endpoint，DNS/underlay 地址变化也不会重置。首次为 1；每次尝试在选定认证握手发送首条记录前原子递增，失败尝试允许留下 gap。**计数器在进程内存中，进程重启即从 1 重新开始**——这是移除磁盘状态后的既定取舍，见 3.1。接收方高水位键为 `(scope, ContextID, initiator NodeID, LaneID)`（`AcceptLinkEpoch` 已在 CONTROL responder 的 Noise/CAPABILITY 成功后、activeLinks 登记前调用；同 epoch 要求 LinkID **与 transcript hash 都相同**才幂等，transcript 不同返回 `ErrLinkEpochReplay`（`memory_state_test.go` 有对应断言））；只在 Noise 身份/PSK 认证成功后比较并更新。更低 epoch 的 NEW attempt 拒绝；相同 epoch 仅允许同一 LinkID/transcript 幂等。接受较高 epoch 后只提高该键的 NEW-attempt floor，不因 epoch 较旧自动 drain 已经认证且健康的不同 LinkID。每个已建立物理实例只由自身真实物理/安全故障、完整实例 FactKey/version 的明确撤销或既定事实生命周期独立退休；撤销 L1 不影响同 Peer/Lane 的 L2。此并存方向由 parallel_link_epoch 具体选择批准，不由 map 多对象的代码观察倒推授权。发送方须在同 ContextID/initiator/Lane 下序列化 epoch 分配到 handshake/admission 完成的窗口；接收方按 floor 原子提交，11先提高floor时迟到未准入10仍拒绝。跨 endpoint/并发接收的排序机制与 transcript 绑定仍需实现/验证，不放松或拆分floor以适配并行。已准入10随后准入11可独立并存，与上述迟到10不是同一情况。双向并行连接属于不同 initiator 高水位域。LinkFact 由本次 Noise initiator 发布；responder 不替对方发布竞争事实。CONTROL Lane 至少一条 active Link 是该 Peer 的控制/事实交换前提；PACKET/STREAM data Lane 只在 CONTROL Link active 后建立/发布，最后一条 CONTROL Link 失效时撤销该邻接可用性并使依赖 Path 进入失效处理。LinkGeneration 是每个 Noise Link 的非零随机 u32，不参与 LinkEpoch 单调比较；u64 LinkEpoch 耗尽时该 NodeID/Lane 拒绝新建 Link，不回绕。
### 端到端会话（每个 Path/SessionClass 懒建立）

按用户已确认的高熵 token policy，当前 proposed E2E session handshake 使用 Noise_IKpsk2_25519_ChaChaPoly_SHA256（initiator 已从拓扑知道 responder 静态公钥），两消息完成。IK pattern、Split 映射与 KDF 应用域已由 （seq1875/seq1885 人工确认）批准；精确 HKDF salt/info 字段顺序与 LP32 编码是在该已批准算法/域/Split 内的实现细化，经独立设计评审与组件验证后写入（见 3.5.3），不是 seq1885 逐字批准，也不构成外部第三方互操作；人类口令不在 P1，未来若新增 PAKE scope 须重新设计 SESSION_CTRL 与 key schedule。以下 Path/Session scope、attempt/target_epoch、ReadyPending/SESSION_READY commit 和旧 epoch grace 是握手模式无关的 session lifecycle 要求。作用域是单个 `(NetworkID, SrcNodeID, DstNodeID, PathID, PathGeneration, SessionClass)`；每 Path/Generation/Class 至多一个当前 SessionID，独立 Path 可并行持有不同 SessionID/root，不做节点对全局 SessionID 选主。所选 Noise/IK handshake 的 initiator 固定为该 PATH_OPEN 逻辑源端；其他模式也必须由该逻辑源端发起。每次握手/重钥匙都新鲜派生 root/traffic keys；SessionID 由发起方 CSPRNG 生成 16 字节并由对端回显。所选 Noise/PSK branch 使用同一 network PSK；Session、Path、Lane、attempt 和 Noise transcript 绑定，不能跨物理连接搬运。所选 Noise/IK design 的 prologue = `NetworkContext.Prologue("simpletier-v1/session", canonical binding)`；canonical binding 为完整 102B：`ContextID:32B | SrcNodeID:16B | DstNodeID:16B | SessionID:16B | SessionClass:u8 | data_lane_id:u8(PACKET=0x01/STREAM=0x02) | attempt:u32be | target_epoch:u32be | PathID:u64be | PathGeneration:u32be`（不是旧 8B NetworkID locator 绑定），data_lane_id 必须等于 SessionClass 和 Path Lane；CONTROL=0 只标识承载 ROUTE_CTRL 的物理 Link，不是 SessionClass。每个 Session key 只允许一个 pending rekey（`target_epoch=current+1`）；由该 Path owner 发起，同一 attempt 的并发触发合并为同一 transcript，重传必须逐字节相同，不同 transcript 返回 SessionAttemptConflict。待处理 attempt 未提交/超时关闭前不接受另一个 attempt；旧 epoch 只在匹配的所选 rekey handshake 成功且 SESSION_READY 对该 Path 提交后切换，`grace_start` 仍按 wire 规则由首个有效新 epoch E2E 消息启动。不同 Path 的 SessionID/rekey 状态完全独立。握手消息作为 `FrameKind=ROUTE_CTRL, MessageType=SESSION_CTRL` 帧的载荷传输——此类帧在会话建立前只有逐跳 bootstrap 子钥匙保护（载荷本身是 Noise 密文，中继不可读）。IK 成功后 initiator 发送逐跳保护的 `SESSION_READY`；各 Path hop 验证它绑定当前 SessionID/Class/data_lane_id/attempt/PathGeneration 后将 ReadyPending 转 Active。完成后所有其他 MessageType 均走对应 SessionClass 的端到端流量钥匙。SessionClass 作用域和换路：PACKET Session 与 STREAM Session 都固定到各自的一条 lane/数据连接；PACKET Path 失效先建立新 Path/Session，丢失的数据报不重放；STREAM Path 失效返回 SessionLost，不自动迁移已建立 Circuit，新 Circuit 重新建立 Stream Session。


| 场景 | 期望结果 | 关联 |
|---|---|---|
| 错误 secret / 空 secret / 空 name | 握手或 Runtime 拒绝，不建立任何可用状态 |
| name 不一致 | 拒绝入网 |
| 选定 Noise/PSK 分支的静态身份/首次连接 | 已有 NodeFact 时 key/NodeID 不匹配即拒绝；无事实时从 Noise static key 派生 NodeID，Msg3/PSK 与 CAPABILITY 成功后才建立 Link/发布事实；token 熵仍是调用方必须遵守的生成政策，非空校验不证明熵 |
| 选定 proposed Noise/PSK 链路握手 | 三消息取得一致 root；消息/schema 参数须完成当前独立评审和互操作验证后方可冻结 |
| 握手超时/中继窃听 | 5 秒超时断链；中继对握手和会话载荷均不可读 |
| Path/Session scope | 每 Path/Generation/SessionClass 独立 SessionID/root；当前选定的 proposed Noise IK 以两消息建立该 root，具体 handshake vectors 需通过互操作评审 |
| 并发重钥 | 同一 Session 同时触发多次 rekey 只建立一个 pending attempt；重复 transcript 幂等，冲突 transcript 被拒；不同 Path 不互相覆盖 |
| LinkEpoch 网络隔离 | initiator 在 network A 的高 LinkEpoch 不影响 network B；相同 Network/initiator/Lane 的旧 epoch 被拒；高水位在进程内存中，重启即清零 |
| 重启/重连 | 重启后 NodeID 改变；每次连接/会话的流量钥匙新鲜，无随机数回退风险 |

## 2. 概要设计


### 2.1 内部职责与依赖

```text
[CSPRNG X25519（内存）] --> [Identity: NodeID]
                              |
[已选 token policy：name+secret -> PSK/Noise_XXpsk3 proposed handshake] --> [链路钥匙] --> [wire 逐跳子钥匙]
                              |
                              +--> [选定的 proposed Noise_IKpsk2 handshake] --> [会话流量钥匙] --> [wire 端到端钥匙]
```

Identity 拥有静态密钥和 NodeID；本模块拥有握手状态机和密钥派生标签；[线上帧协议](wire.md) 消费派生结果。标签字面量（`"simpletier-v1"`、子钥匙标签）一经发布即为协议常量。

### 2.2 链路握手流程

用户已选定高熵 bearer-token 分支；下图展示所选 proposed Noise_XXpsk3 链路流程（Msg1/2/3），具体 schema/参数仍待独立设计评审和互操作验证。人类口令不属于 P1；未来新增 PAKE scope 时须重新设计消息序列/prologue/身份认证。NodeID 映射、已知 NodeFact 的 key-match、认证成功后才交换 CAPABILITY/发布事实是模式无关要求。

```text
[TCP 连接建立]
   |
   v
[发起方发送 Msg1: e]
   |
   v
[响应方验证 Network/Lane/Link prologue，发送 Msg2: e, ee, s, es]
   |
   v
[发起方解密 responder static key，计算 NodeID]
   |
   +--本地已有 NodeFact 且 key/NodeID 不匹配--> [IdentityMismatch；断链]
   |
   v
[发起方发送 Msg3: s, se, psk3]
   |
   v
[响应方解密 initiator static key，计算 NodeID]
   |
   +--本地已有 NodeFact 且 key/NodeID 不匹配--> [IdentityMismatch；断链]
   |
   v
[安装 link_root_key / hop subkeys]
   |
   v
[双向 LINK_CTRL CAPABILITY v2（局部实现报告；最终验证 pending）]
   |
   +--version/mask 不匹配--> [VersionMismatch；断链]
   v
[Link Established；之后同步/发布 NodeFact]
```

在当前已选 Noise/PSK 分支中，PSK 校验在 Noise 失败中无法区分“错 secret”与“错 name”（防猜测），对外统一为握手失败并限速计数。双向同时建链由 LinkID 区分，不要求连接级去重协议。

首次 upstream 连接只要求已配置 underlay 地址，不要求预先 pin responder NodeID/静态公钥。任何最终选定的认证握手都必须在 Link Established 前提供可认证的对端静态身份以计算 NodeID；若本地已有该 NodeID 的 NodeFact，公钥必须逐字节匹配，否则 `IdentityMismatch`；若无事实，则使用握手认证后的身份派生 NodeID，并在 CAPABILITY 成功后同步 NodeFact。当前已选 Noise/PSK 分支中，静态公钥在 Msg2 出现、Msg3/PSK 后才认证；若未来新增 PAKE scope，需另行定义等价的公钥身份绑定时序。信任锚仍是共享 name+token，不新增 TOFU/证书 ACL。


### 2.3 密钥数据流

以下 Noise XX/IK root derivation 展示用户已选高熵 token 分支的 proposed key schedule；详细实现/互操作仍待评审，人类口令与 PAKE 不属于 P1。模式无关的方向隔离和后续子钥匙域见下表。

```text
[PSK + 静态密钥 + 对端公钥]
        |
        v
[选定的 proposed Noise_XXpsk3 branch] --> [link_root_key] --派生--> [hop 控制/数据子钥匙]
        |
        v
[选定的 proposed Noise_IKpsk2 branch] --> [session_root_key] --按 KeyEpoch/方向派生--> [端到端流量钥匙]
        |
        v
[wire-protocol: AEAD 随机数=Generation|Counter]
```

密钥只存内存，不落盘、不入日志；进程内零化由实现保证（Go 无强制保证，敏感缓冲用后尽力覆盖并缩短生命周期）。

## 3. 详细设计


### 3.1 IdentityStore（observed）

`internal/security.OpenIdentityStore(...string)` 是一个运行态 API（参数已保留但忽略），不读取配置文件、不写磁盘。它每次构造都生成一份新的 X25519 密钥并返回一个独立 scope（形如 `ephemeral://N`），**不读取、也不创建任何文件**。

它的历史形态是「一个 state_dir 上一个 OS 文件锁 + 磁盘 `identity.key`」，同进程多 handle 共享、跨进程用 `ErrIdentityInUse` 互斥。**该形态已整体移除**：`RuntimeOptions.StateDir` 字段已删除，`ErrIdentityInUse`、`identity.key`、`identity.lock` 都不再存在。

后果是明确的取舍：

- **重启后 NodeID 改变**，对端看到的是一个新节点。需要稳定地址的部署用 `RuntimeOptions.FixedIP` 钉住虚拟 IP，而不是依赖 NodeID 不变。
- **放弃跨重启防重放**。LinkEpoch 单调性、接收者 floor、Sequence 水位全部只在进程内存中，进程重启即清零。

`IdentityStore.StateDir()` 方法名保留，但它现在返回的是 **scope 标识**（例如 `ephemeral://3`），不是可写路径。任何把它当目录用的代码都会构造出非法文件名——这一点由测试 `TestRuntimeScopeIsNotAFilePath` 守着。

```text
[OpenIdentityStore() 创建新 scope]
                 |
                 v
[CSPRNG X25519] -> [Identity: private key + public key + NodeID]
                 |
                 +--> [同一 store 的多个 handle 共享这一份 identity]
                 |
                 +--> [不同 store 各自独立，即使在同一进程内]

不写盘、无锁文件、无跨重启状态。
```

### 3.1.1 完整网络上下文与派生（已确认方向；有限实现观察）

用户已具体确认完整原始 name/canonical IPv4 CIDR 绑定；其不可变实现入口为 `internal/security.NewNetworkContext`，而非依据 u64 locator 推断成员。下列编码已在 [实现](../../internal/security/network_context.go) 和 [字面向量测试](../../internal/security/network_context_test.go) 中存在，属于已批准方向的例行、无歧义字节实现，不替代尚未确认的使用上限或换钥协议：

```text
Descriptor = ASCII("simpletier-v1/network-context")
           | name_len:u32be | name_utf8_raw
           | cidr_len:u32be | cidr_canonical_ascii
ContextID  = SHA256(Descriptor)  // 完整 32B，不含 token
Prologue(domain,binding) = ASCII("simpletier-v1/prologue")
           | domain_len:u32be | domain_utf8_raw
           | descriptor_len:u32be | Descriptor
           | binding_len:u32be | binding_raw
PSK = HKDF-Expand-SHA256(
        HKDF-Extract-SHA256(salt=name_utf8_raw, IKM=token_raw_bytes),
        info=Prologue("simpletier-v1/psk", nil), L=32)
```

各 u32 长度按字节而非字符计。name/domain 非空、有效 UTF-8、无 NUL，不 trim/case-fold/Unicode-normalize；canonical CIDR 是 IPv4、prefix 1..32，拒绝 `/0`、IPv6、主机位非零或非 canonical 字面形式。token 仅要求非空，不以 UTF-8 标识符规则拒绝其不透明 bytes，熵仍由调用方负责。零 NetworkContext 拒绝派生；Descriptor 与 Prologue 返回独立副本，binding 不保存，ID 是值。保持 name/CIDR 不变而换 token 时 ContextID 不变、PSK 改变；不偷偷以 token 指纹替代状态分区，跨 token runtime 并存/轮换的策略仍不能由此推出。

`NetworkContext.Prologue` 已可生成绑定 Link/Session 域及其 binary tuple 的字节。当前 `normalizeConfig` 准备 networkContext/networkPSK，NewNetwork 保存准备值，并在 CONTROL `admitConnectionLink` 调用实际 Noise 握手。Link prologue 的 binding 为 29B：NetworkID:u64be、LinkID:u64be、LinkEpoch:u64be、Generation:u32be、LaneID:u8；WireID 是 legacy `SHA256("simpletier-v1" || 0x00 || raw name || 0x00 || canonical CIDR)` 前 8B 大端 locator，不能替代完整 ContextID。纯派生、raw codec、Noise/加密 CAPABILITY、epoch 准入校验和 Network 注册是不同步骤；初建 CONTROL 已接线，不代表已发布 Fact 或存在 RouteView。Session prologue 消费、地址/incarnation/FactStore 的完整 ContextID 分区仍未实施。独立固定派生向量来自 Node 标准 SHA-256/HMAC，这些是项目回归向量，不是 Noise 跨实现互操作证据。

### 3.1.2 CONTROL Link 准入与 epoch 状态

实现入口：[Link Handshake](../../internal/link/handshake.go)、[生命周期](../../internal/link/lifecycle.go)、[epoch 状态](../../internal/security/link_epoch.go) 与 [Network admission](../../pkg/simpletier/network.go)。固定依赖是 flynn/noise v1.1.0、x/crypto v0.55.0；这不是新加密算法或独立互操作批准。

```text
[Connector / TCP accept -> metadata-bearing Connection]
                         |
                         v
[IdentityStore scope + identity + full context/PSK]
                         |
         +--initiator: allocate CONTROL epoch + fresh ID/generation
                         |
                         v
[raw bounded XX1/XX2/XX3 -> peer static/NodeID -> application roots]
                         |
                         v
[encrypted LINK_CTRL CAPABILITY v1: version1 / mask0x7f / counter0]
                         |
       +--responder: AcceptLinkEpoch after authentication
                         |
                         v
[NewEstablishedLink -> lock/check Network still open -> activeLinks]
                         |
                         v
[Network Close snapshots/closes links, waits workers, releases identity]
```

`Handshake` 参数校验拒绝不接管原始流；I/O 开始后的取消/错误由内部 once-close wrapper 解除阻塞，成功时同步解除建立 context，不修改宿主 deadline。它验证本地 X25519 key/public/NodeID 一致性、可选 pinned peer、完整 Noise context；CAPABILITY 的固定 59B frame length 在 body allocation 前检查，要求 LINK_CTRL、零路由字段、正确 generation/counter0 和加密的 ControlType=0x04、payload 9B。initiator 先写后读，responder 先读后写；两端验证后才返回，不能以本地 Msg3/Split 代替 peer confirmation。Split 按 canonical I→R/R→I 映射，一次性导出后经 descriptor/transcript/direction 分域派生应用 roots；不继续用这些 Noise CipherStates 加密应用。成功已消费两个方向的 LINK_CTRL counter0：后续 TX 从1开始，RX 必须保留已认证0的重放 floor，不能重新构造 counter0并重复 nonce。

`NextLinkEpoch` 在 `(scope, ContextID, Lane)` 内分配 sender counter，失败不发送首条记录；`AcceptLinkEpoch` 在同一键下保存 receiver epoch 与 LinkID；floor 绑定 `(LinkID, transcriptHash)`，同 epoch 但 transcript 不同即拒绝。其时序为 Noise/CAPABILITY 之后、Network 登记前，失败关闭。**计数与 floor 都在进程内存中**，进程重启后从 1 重新开始，不提供跨重启或崩溃恢复保证。

Network当前只登记CONTROL：数据Lane初始准入仍拒绝，16入站gate/5秒context、target occupancy和Close/cancel/注册竞争清理既有。登记后ProtectedControlIO/controlPump独占认证读写、PING→有界PONG，EOF/error关闭并按实例身份移除LinkID；没有主动probe owner、FACT control consumer/RouteView、完整来源速率/Link上限/accountant、数据Lane池或远端业务。Link.Read/Write自身只是lifetime包裹，保护帧由泵调用，不把Ready或payload可解密当拓扑/业务功能。初建CAPABILITY v1 是历史实现观察；当前报告的v2严格版本拒绝实现及对应测试属于局部实现观察，最终集成验证仍 pending。不不断流换钥也未实现。

当前 FactStore 已有 33 个测试用例，覆盖 provenance、retention、sender digest 与 atomic snapshot；这是 store/helper 层，不等同于 FACT control parser/consumer。集成复核发现 revokedThrough 可能下降，须修复并通过反例验证；因此一致性/撤销运行链路仍不完整。

### 3.2 密钥派生表

无论最终认证模式，Security 都必须向通用子钥匙 KDF 提供互相独立的 `link_root_key[dir]` 与 `session_root_key[dir]`，防止中继取得端到端钥匙。当前已选的高熵 token/Noise proposed branch 使用 Noise Split；其顺序为 `split[0]` initiator→responder、`split[1]` responder→initiator，`dir=0/1` 不拼接。该 Split 映射已批准；精确 HKDF 字段顺序与 LP32 编码是在该批准内的实现细化，见 3.5.3。若未来新增 PAKE scope，需另行定义两方向 root 输出。

当前初建 Link adapter 的具体代码观察：`exportRoots/deriveRoot` 在全部 XX消息后按canonical方向复制UnsafeKey，`root_dir = HKDF-Key-SHA256(IKM=split_dir, salt=PSK, info=ASCII("simpletier/v1/link-root/"+dir) || 0x00 || LP32(Descriptor) || LP32(ChannelBinding), L=32)`，dir 为 i2r/r2i。这些是项目应用roots，不是Noise chaining-key exporter；输出再由FrameProtector按完整descriptor、LinkID、方向和用途派生。控制/引导密钥不纳入SessionID/Class，逐跳data才按Session分域；source已显示该分离，最终向量/回归需当前验证绑定。应用KDF域常量不能随意变更，不能同时用原Split CipherStates再加密traffic。Session root/traffic 已在 `internal/session` 有组件级实现（Noise provider + e2e traffic KDF），但仍未接入 Network/Path；组件状态与证据口径见 3.5.3。

统一 KDF 的旧候选记法仍为 `PRK = HMAC-SHA256(key=root_key, data=context)`、`OKM = HKDF-Expand(PRK, info="simpletier-v1" || label, L=32)`；它不是当前 `FrameProtector` 的具体 `hkdf.Key(IKM=root, salt=Descriptor, info="simpletier/v1/frame-key"|purpose|direction|purpose-specific fields|LP32(Descriptor),32)` 公式，也不能把 `deriveRoot` 的 Split/PSK/transcript 公式当作该旧记法的等价实现。完整Descriptor和用途/方向/代际分域方向已批准，但具体应用KDF常量/顺序/提取-扩展形式仍须定向裁决、统一冻结及独立字节向量，不能靠同库两端通过或本文描述原型静默批准兼容性变化。以下表保留用途需求与旧候选字段，不构成当前原型公式已经满足正式契约的证明；整数大端，NodeID/SessionID/LinkID为原始字节。

| 根/输出 | 派生（HKDF-SHA256） | 用途 |
|---|---|---|
| `link_root_key[dir]` | Noise_XXpsk3 `split[dir]`（已选的 proposed 分支） | 每条 TCP Link 的逐跳域 |
| `session_root_key[dir]` | Noise_IKpsk2 `split[dir]`（已批准；dir=0 i2r、dir=1 r2i，不拼接） | 每个 E2E SessionClass 的端到端域 |
| PSK（已选高熵 token/Noise-PSK 分支） | `HKDF-Extract(salt=name_utf8_raw, IKM=secret_raw_bytes)` + Expand(`NetworkContext.Prologue("simpletier-v1/psk",nil)`,32) | 全 name/CIDR 绑定的握手输入；派生本身不认证 |
| hop 控制子钥匙 | KDF(`link_root_key[dir]`, `hop-ctrl || LinkID:u64 || dir:u8`) | LINK_CTRL |
| hop bootstrap 子钥匙 | KDF(`link_root_key[dir]`, `hop-route-ctrl || dir:u8`) | ROUTE_CTRL；nonce 使用 LinkGeneration/RouteCtrlCounter |
| hop 数据子钥匙 | KDF(`link_root_key[dir]`, `hop-data || SessionID:16B || SessionClass:u8 || dir:u8`) | E2E 帧逐跳 |
| 会话流量钥匙 | KDF(`session_root_key[dir]`, `simpletier/v2/session-traffic` || dir:u8 || SessionID:16B || SessionClass:u8 || KeyEpoch:u32be || LP32(Descriptor)`) | 端到端 AEAD |

`SessionClass=PACKET(0x01)` 供 IP_PACKET/UDP_DATAGRAM 共用一个 Packet lane session；`SessionClass=STREAM(0x02)` 供 Stream/Circuit multiplex 使用一个 Stream lane session。每个 `(NetworkID, SrcNodeID, DstNodeID, PathID, PathGeneration, SessionClass)` 有独立 SessionID/root key；同一路径同一类至多一个 current session，不同并行 Path 可以各自建立 Session。SessionID 由该 Path 的逻辑源端 CSPRNG 生成 16 字节并由对端回显、绑定当前选定 Noise handshake 的 transcript/prologue；若未来新增其他认证模式，需单独定义 transcript binding。ROUTE_CTRL 不使用 session_root_key。

**代际密钥保留**：同时保留当前与上一代际两把会话流量钥匙；新代际第一条有效消息到达时开始 30 秒 grace，过期后旧代际窗口/钥匙释放。中继只持有各自 Link 的 `link_root_key`，永远不能由它派生 `session_root_key`。

### 3.3 会话状态流转

会话生命周期本身模式无关；下图展示用户已选定的 proposed Noise IK 分支，具体 transcript/state 细节仍待当前设计评审。

```text
[Idle]
  |
  v
[Selected-handshake pending: attempt a, target_epoch=current+1]
  |
  +--同 attempt、同 transcript 重传--> [重发缓存结果]
  +--并发 rekey trigger--> [合并到当前 pending attempt]
  +--同 attempt 不同 transcript--> [SessionAttemptConflict]
  +--握手失败/超时--> [保留当前 epoch；按失败语义重试/关闭]
  |
  +--所选握手成功 + 匹配 SESSION_READY--> [Established: KeyEpoch=N+1]
  |
  +--Path/Link 硬故障--> [Closed]
```


重钥模式独立的不变量是每个 SessionID 仅允许一个 pending rekey，不另定义业务数据报文；每个 SessionID 仅允许一个 pending rekey，发起者只能是该 Path 的 PATH_OPEN 逻辑源端。`target_epoch=current+1`；并发触发合并到同一 pending attempt，不再递增 attempt；同 attempt 只接受字节级相同的所选握手 transcript，冲突 transcript 返回 `SessionAttemptConflict`。Active Path 上通过最终选择的 rekey handshake 得到 pending root 后，旧 epoch 仍可正常收发；该 Session 进入 `RekeyPending(target_epoch,attempt)`，SESSION_READY 经 CONTROL Link 提交后切换 current epoch，并在 data Link 上按序释放已缓冲的新 epoch 帧。目标 epoch tag 在 queue/drain 时验证；未 Ready 前不推进新 epoch replay/grace，旧 epoch 保留。30 秒 pending 超时清理新 key/队列并打破 Path/Session，流映射为 `SessionLost`；不把同一 SessionID 回退复用。旧 KeyEpoch 按 Wire 规则至首个有效新代际 E2E 消息启动 30 秒 grace 后回收。不同 Path/SessionClass 的 rekey 状态相互独立。当前选定的高熵 Noise/PSK proposed branch 使用重跑 IK rekey；人类口令/PAKE 不属于 P1，未来若新增该 scope 须另立决策并重新设计 rekey transcript 与 SESSION_CTRL 流程后再冻结。**会话绑定对端 (NodeID, 静态公钥)**，拓扑公告公钥变化即废弃对应 Path sessions 并重新握手。

### 3.4 失败语义与安全不变量

- 握手失败分类：`AuthFailed`（当前选定 Noise/PSK handshake 的 PSK/name/prologue 不符；如未来新增其他认证机制，也须映射等价认证失败并统一对外表现）、`IdentityMismatch`（静态公钥与公告 NodeID 不符）、`HandshakeTimeout`（5 秒）、`VersionMismatch`。均断链并计数，不降级重试。
- 不变量：Token/PSK/私钥/流量钥匙不入日志和诊断输出；空凭据双层拒绝；不允许明文/弱加密模式；中继永远拿不到 PSK、静态私钥和端到端流量钥匙。
- 拓扑公告的公钥与 NodeID 派生关系由接收方独立重算校验（防公告伪造身份）。

### 3.5 可自主部分与选定方案的待评审细节

实现自由：Noise 库选型（成熟实现即可，如 Go 生态 Noise 库）、goroutine 组织、超时重试计数细节、缓冲零化方式。

已确认的 P1 token policy：`network.token` 必须由 CSPRNG 生成且至少 128 bits；人类可记忆口令/PAKE 不属于本版。当前选定的 handshake/key schedule 为 X25519 静态身份 + NodeID 哈希 16 字节、HKDF PSK、链路 Noise_XXpsk3、端到端 Noise_IKpsk2、原 Link 内换钥事务（ControlType 0x09 + capability bit6，见 3.5.3）、握手超时 5 秒。Session IK/Split/应用域与换钥事务已批准；精确 KDF 字节是实现细化。Noise 跨实现互操作与最终集成验证仍待进行，本方案不据此宣称互操作已冻结。运行时非空校验不能证明熵，文档不得承诺任意非空 token 均有强认证；未来若新增口令支持须另立决策并重审 PAKE/SESSION_CTRL/rekey。

### 3.5.1 当前独立协议复核的待冻结项

以下仍约束尚未完成的长寿命 traffic/key-update/Session 实现，不因初建 CONTROL 握手代码存在而自动冻结或消除。当前初建 Noise/CAPABILITY 与 epoch 接线观察见 3.1.2，不以旧评审的不完整快照否认这些实际代码：

- **每密钥域使用上限与双向重钥触发**：目前只禁止 u64 计数器回绕，未规定每把 E2E、逐跳数据、LINK_CTRL、ROUTE_CTRL AEAD 子钥匙的 suite-specific invocation/byte ceiling。Path owner 固定为重钥发起方时，responder 方向接近上限还必须有经认证的 rekey-needed 通知路径；否则须在密钥使用上限前 fail closed。24 小时 Session rekey 仍只是候选，不替代每个密钥域的硬上限。
- **NetworkID 碰撞域**：3.5.2 已确认保留 u64 locator 并用完整 name/CIDR 描述绑定 KDF/prologue 与本地 ContextID。纯派生、初建 CONTROL Noise prologue 的29B tuple、sender/receiver epoch目录及门禁已存在；FactStore/地址/incarnation 分区及完整跨网络运行隔离仍缺失，不能把局部 KDF/admission 当成全网状态隔离完成。
- **首次 SESSION_CTRL 基线**： 3.5.2 已具体确认首个 attempt=0,target_epoch=1 和显式 haveAttempt/cache 规则，终止失败新 SessionID。缺失字节级向量和实际状态机验证，不能仅凭文档确认宣称 bootstrap 已可用。

以上协议项未阻止不声明 Link/Session 已认证、也不发布拓扑事实的 SDK startup/IdentityStore 接线；具体 Noise 库与互操作仍须独立验证；key-use 数值现由协调者按 3.5.4 的 AI 授权默认操作策略选择（非 human gate、非 RFC 通用保证）。

### 3.5.2 已确认的协议方向

来源：完整功能目标 round 1 问答，用户选择完整网络上下文绑定、明确首次会话基线与新会话重启，并要求“密钥到期不能打断长业务流”。此确认覆盖以下行为，不追认未选的数值策略：

- 完整 NetworkDescriptor 以长度前缀编码原始合法 UTF-8 name 与 canonical IPv4 CIDR，不做 trim/case/Unicode normalization。PSK HKDF-Expand、Link/Session prologue 和应用 KDF context 绑定完整描述；外层 u64 NetworkID 仅作 locator。本地状态和路由分区使用完整 ContextID，并先验证预期上下文再接受远端事实，不能因短 ID 碰撞共用密钥/高水位。具体域标签/字节向量需定向冻结和测试。
- 新 Session 首次 attempt=0,target_epoch=1，未安装 epoch=0；haveAttempt 独立于 lastSeenAttempt。只对同 role/step/attempt 的 byte-identical 重传回放缓存，不重复消费 Noise 状态；冲突字节拒绝，终止失败用新 SessionID。bootstrap envelope 的 KeyEpoch/MessageNumber 仍为 0，READY 才提交 epoch1。
- 正常密钥更新/到期必须保持长业务流连续。不能以新 Link 重建并向所有旧 pinned Stream 返回 SessionLost 达成此要求；需要原 Link 内协调换钥事务，确认新钥匙后有界共存、切换并回收旧钥匙，保证 nonce、顺序、窗口和数据确认不回退。真实线路失败与无法安全换钥而 fail-closed 不能伪装成正常到期行为。in-place 控制编码/双向提交已批准（ControlType 0x09 + capability bit6，capability v2 required mask 0x7f）；每钥匙数值/资源上限按 3.5.4 的协调者授权默认操作策略选定（非 RFC 通用保证、非 human gate），实现尚未验收（link 内 same-stream FENCE 路径测试未绿），见 3.5.3。
- 2^32 成功 Seal、2^48 bytes、24h 以及失败验证风险预算在 3.5.2 问答中未获批准，当时仍是候选项目策略；后续新 human 要求将数值决策交给协调者后，由 3.5.4 作为 AI 授权默认操作策略初选。研究主源说明它们不是 RFC 的通用 ChaCha 成功调用上限。Suite 使用计量及实际 AAD/块数分析仍需补齐，不能简单清零 CipherState 计数或靠 Session 更新延续 Link 控制钥匙。

因此上一小节的 NetworkID 隔离与首次 Session 行为已有具体确认；尚缺的是忠实的域标签/字节向量与实际实施，而不再以“使用者没有方向”笼统阻塞它们。每钥匙数值策略按 3.5.4 由协调者授权选择（非 human gate）；保持长流的协调更新协议已批准，但实现与验收未完成。

### 3.5.3 原 Session/rekey 批准恢复与实现细化（seq1875/seq1885）

来源：主 transcript line 1876/seq 1875 的 `ask_user_question`（`session_protocol_freeze`、`link_rekey_freeze`）与 line 1886/seq 1885 回答 `{"answers":[{"id":"session_protocol_freeze","selected":["批准推荐会话契约"]},{"id":"link_rekey_freeze","selected":["批准推荐原 Link 换钥契约"]}]}`。该回答是直接人工确认，原批准有效。

**人工已批准（seq1885）**：

- Noise 模式 `Noise_IKpsk2`；SESSION_CTRL 布局 `SessionID:16B | class:u8 | lane:u8 | attempt:u32be | target_epoch:u32be | noise_len:u16be | noise_message`；首次 `attempt=0`、`target_epoch=1`。
- prologue 包装 `NetworkContext.Prologue("simpletier-v1/session", canonical binding)`；canonical binding 为完整 102B：`ContextID:32B | SrcNodeID:16B | DstNodeID:16B | SessionID:16B | SessionClass:u8 | data_lane_id:u8 | attempt:u32be | target_epoch:u32be | PathID:u64be | PathGeneration:u32be`；不绑定旧 8B NetworkID locator。
- Split 方向：`i2r = split[0]`、`r2i = split[1]`，不拼接。
- 应用域标签 `simpletier/v2/session-root` 与 `simpletier/v2/session-traffic`。
- 原 Link 内换钥：`ControlType 0x09 = LINK_KEY_UPDATE` + capability bit6；capability v2 `required mask 0x7f`，严格拒绝 v1、缺必需位或保留位非零，不降级。取代 Wire@29 的“bit6 保留、未批准 0x09”描述。
- 同 attempt 重传逐字节一致且幂等；SESSION_READY 提交后才交付数据。

**实现细化（不是 seq1885 逐字批准）**：精确 HKDF salt/info 字段顺序与 LP32/64B 编码是在上述已批准算法/域/Split 内的实现细化，经独立设计评审与组件验证后写入；组件 root 绑定不是外部第三方 interop 证据。当前源码：

```text
session_root_key[dir] = HKDF-Key-SHA256(
    IKM  = Noise split[dir],
    salt = PSK,
    info = ASCII("simpletier/v2/session-root/" + ("i2r"|"r2i")) || 0x00
         || LP32(Descriptor) || LP32(NoiseChannelBinding),
    L    = 32)
e2e_traffic_key[dir] = HKDF-Key-SHA256(
    IKM  = session_root_key[dir],
    salt = Descriptor,
    info = ASCII("simpletier/v2/session-traffic") || dir:u8
         || SessionID:16B || SessionClass:u8 || KeyEpoch:u32be
         || LP32(Descriptor),
    L    = 32)
```

字段顺序由 `internal/session/noise_provider.go`、`internal/session/e2e.go` 与只读 review + postfix probes 确认；viewOwnership/tmp probes 只审该组件，不构成外部独立第三方 interop。

**当前实现与证据边界（observed，仅组件级）**：

- N-0 数值 key-use 预算现由协调者按 3.5.4 以其 AI 授权选择默认操作策略（非 human gate、非 RFC 通用保证）：初选每方向成功调用 2^32、明文 2^48 bytes、age 24h、失败验签预算 1024（**Network aggregate**，全域共用 fail 计数，不是每钥无限复制）。需 actual AAD/块计算与全域共用 fail 计数/earlyHeadroom 独立复核后才能声明实现满足；当前 `zeroPolicy` 未配置，且实际 Link policy 每 physical Link 合计 3 域与规范的 Network aggregate 不一致（整改项，见 3.5.4），仍不构成完整自动重钥触发的已验收实现。
- rekey：`internal/link/key_update.go` 已有 0x09/capability bit6/状态机；link 内 same-stream FENCE 路径测试（AStable/BFenced）未绿，不能宣称换钥实现已验收。
- A-B 新 runtime 5 tests（80 KiB echo / no-port / deadlines / twoConcurrent）为真实源码，仍等全部收齐后最终 binding。

### 3.5.4 生产 key-use 策略：协调者 AI 授权默认（新 human 要求）

来源：最新直接 human 要求“所有具体决策都有你自己来决定，我只要求我需要的业务能力，足够简单，使用 SDK 就能用”。据此替换刚提出的“显式 `production_key_policy`，否则拒启动”方案：**SDK 内置安全/资源/换钥默认，调用者无需填写内部 budget**；`NewNetwork` 的五个外层核心配置仍可即用，不增加必填 policy。

边界：

- 这些数值是协调者（AI）自主应用的操作策略，**不是 RFC 通用安全保证**，也不是 seq1885 逐字批准的数值；数值从 human gate 变为 AI 授权选择/分析。
- SDK 默认不启用 TUN/OS 资源 Agent；需要时由调用者显式选择，语义不变。
- 不得先把 crypto 保证写成已验证；需 independent review 后才可作为实现验收依据。
- **失败验签预算口径（明确整改）**：规范规定 `1024` 是 **Network aggregate**（全域共用 fail 计数）。当前实际 Link policy 是**每 physical Link 合计 3 个域**，与规范不一致，列为明确整改项；**不得为了让代码看齐而改 spec**（应为代码收敛到 spec）。
- Link C1/C2/C3 修复 DONE（Link 39 当前 `ccb0…`）；failedbudget/poll seam 待 SDK 接入；内层 Session root 桥也待接；retire rootSerial 纠正（随机 gen 数值比较 + 仅实际 DATA 根换钥才更新其 usageBaseline）新 tests 绿，仍是组件而非整体。

初选保守操作策略（待独立复核）：每方向成功调用 `2^32`；每方向明文 `2^48` bytes；key age `24h`；失败验签预算 `1024`。失败计数为网络聚合/全域共用，**不是每钥无限复制**；需 actual AAD/块计算与 earlyHeadroom 独立复核。


**P1 信任边界：已确认。** 所有持有正确 `name+secret` 的成员属于同一信任组；事实来源由已认证 Link + `StaticPublicKey -> NodeID` 绑定证明，不新增每事实 origin 签名钥匙。任一认证成员均可提交/转发 REVOCATION；撤销者由 Envelope.Origin 和 ingress provenance 记录，目标事实/版本明确绑定。代价是恶意组成员可伪造拓扑、地址或撤销他人事实；按节点撤销/平滑轮换延期。独立 Ed25519 origin signature 作为未来更强隔离方案保留，不进入本版本。

## 4. 实现状态

身份、握手、LinkEpoch 与 Session 密钥派生均已实现。身份与 epoch 计数保存在进程内存中，
进程重启即重新生成，因此不提供跨重启的防重放保证。


## 5. 偏差、未知和继续入口

- **EasyTier 对照（observed，2026-09-22）**：
  - 采纳：`peer_conn_secure_mode_v3.md` 的 nonce=epoch(u32be)‖seq(u64be)（与本项目冻结构造同构）、root_key→按 (epoch,方向) 派生流量钥匙、双代际保留+旧代际 30s 回收（窗口大小仍用已冻结的 1024）；`relay_peer_manager_design.md` 的 1-RTT IK 数据面会话作为已选高熵-token Noise/PSK 分支的参考（不代表互操作验证），以及静态公钥取自拓扑；其文档把 min(peer_id) 作为避免双向建会话竞态的可选建议，不是实现观察，本项目以 PATH_OPEN 源端作为当前 selected session-handshake initiator；会话绑定公钥指纹；其链路 Noise_XX + 中继会话 Noise_IK 双层结构作为当前已选 proposed 分支的设计参考；具体实现/互操作仍待评审，不构成安全验证。
  - 不采纳（弱项反例）：`config/mod.rs` 用 `DefaultHasher` 生成 network_secret 摘要；XOR/NullCipher/关加密路径；空 secret 默认值；`EncryptedUnauthenticated` 未认证降级（本设计无降级）；默认空 AAD（本设计 AAD 覆盖信封与路由头）。
  - 延期项的参考设计：`credential_peer.md` 的 X25519 临时凭据 + 信任公钥列表经拓扑传播 + 撤销即全网断开，是未来“按节点撤销/平滑轮换”的现成蓝本；其 SecureAuthLevel 多级认证可作为未来多角色成员模型参考。
- “会话钥匙每次握手/重钥都必须新鲜派生”是 [线上帧协议](wire.md) 的模式无关前置要求。当前选定的 Noise IK proposed branch 用临时密钥满足；若未来新增其他认证模式，须另行设计等价的新鲜 root/key schedule。若最终机制使用长期钥匙派生，必须回到线上协议重新评审 nonce/replay 域。
- 具体 Noise 库与互操作矩阵在实现阶段选择；当前 selected high-entropy token 的 Noise/PSK 参数是 proposed，需独立设计评审与互操作后冻结；P1 不支持人类口令/PAKE；运行时不证明任意非空 token 的熵。
- 撤销/轮换延期的风险已在 3.4 披露；如需按节点撤销，属新增设计选择，需回到讨论。
