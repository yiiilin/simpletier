# Link 握手实现契约

Research-note: NOTE-LINK-HANDSHAKE-IMPLEMENTATION
Note revision: 4
Note status: proposed / observed implementation guidance
Observation: current filesystem source; final verifier binding not yet collected
Scope: initial CONTROL Noise/CAPABILITY/epoch/lifecycle plus ProtectedControlIO PING/PONG pump and instance EOF withdrawal exist; FACT parser/data/routes/rekey absent
Verification boundary: no new passed Evidence claim in this note

## 摘要

本说明将用户确认的 Link 目标、实际实现与剩余缺口分开。项目已有 `internal/link.Handshake` 的 XXpsk3、静态NodeID/pinned检查、完整context prologue、Split-to-app roots及正式LINK_CTRL双向encrypted CAPABILITY；sender/receiver epoch和Network CONTROL注册也已接线。当前 ProtectedControlIO/controlPump 继续处理认证控制帧、PING/PONG及EOF/error对应实例退出，outbound target在Ready失效后重拨取得较高epoch。它没有FACT parser/consumer、业务数据Lane/拓扑路由/远端Stream或原Link内不断流换钥，因此不是完整组网交付。本说明不批准新的FACT/能力版本、控制opcode、使用上限或独立互操作；最终测试基线待主agent实际收集。

既有契约来源：[安全握手与密钥](../internals/security.md#L39)、[线上帧协议](../internals/wire.md#L89)、[连接接口](../internals/connections.md#L34)。本说明仅用于实现和 review 指引，不替换这些当前拥有者文档。

## 1. 已确认前提与当前观察

### 已确认前提

- 连接由已批准的 Connector/Connection 接口提供；`Connection.Info().Type` 是 underlay 描述，不是身份或入网凭据。Connector 只负责建立，统一 Link 流程负责认证。
- 网络上下文使用完整、长度前缀的原始有效 UTF-8 name 与 canonical IPv4 CIDR，绑定 PSK 派生和握手 prologue；wire u64 NetworkID 仅作 locator。上下文与密钥状态不能只按短 ID 合并。
- 选定的链路 pattern 是 `Noise_XXpsk3_25519_ChaChaPoly_SHA256`；完整 NetworkContext prologue 还绑定 LinkID、LinkEpoch、LinkGeneration 与 LaneID。静态 X25519 公钥认证后派生 NodeID=SHA-256(public key) 的前 16 bytes，并和已有 NodeFact 做 key-match。
- 单独完成本机 Noise message 或得到本机 Split keys 都不等于对端已完成/接受握手。Msg1/Msg2 阶段不得发布认证结论；initiator 写 Msg3 后，responder 仍必须实际读取并成功验证 Msg3。
- Noise完成后双方必须互验逐跳加密CAPABILITY；本轮已具体确认目标schema v2/version2/mask0x3f且bit1=fact-sync.v2、bits6..63=0，严格拒绝v1才可开始FACT v2。当前观察的初建代码仍v1，表中记录的是实现现状，不将文档目标当代码已升级。
- 每个读写/握手失败都关闭该专用流，禁止降级到明文或复用已部分消费的记录。安全失败不生成节点、邻接、AddressFact 或路由副作用。

### 当前实际实现观察

| 层 | 当前观察 | 入口 |
|---|---|---|
| Connection | 实现 `io.ReadWriteCloser`、稳定 Type、TCP/WS 提供者；类型只描述底层方式 | [`connection.go`](../../pkg/simpletier/connection.go), [`websocket.go`](../../pkg/simpletier/websocket.go) |
| NetworkContext | 已实现完整 descriptor、full ContextID、PSK 派生，并在 Config normalization / Network 中准备 | [`network_context.go`](../../internal/security/network_context.go), [`config.go`](../../pkg/simpletier/config.go), [`identity.go`](../../internal/security/identity.go) |
| Raw handshake record | 已实现 length-bounded HANDSHAKE record、Link metadata 与 Msg1/2/3 顺序结构校验；Payload 是 opaque bytes | [`handshake.go`](../../internal/wire/handshake.go) |
| Noise / initial Link admission | XXpsk3、static/NodeID、可选peer pin、方向roots及加密CAPABILITYv1已经有代码；counter0已消耗，成功返回后须从1/floor0继续 | [`handshake.go`](../../internal/link/handshake.go), [`capability.go`](../../internal/link/capability.go) |
| Durable epoch | canonical StateDir，fullContextID sender与receiver文件，receiver在认证后登记前；同epoch只按LinkID，不包含transcript | [`link_epoch.go`](../../internal/security/link_epoch.go) |
| Network 接线 | 统一私有admission只保留CONTROL activeLinks，16入站并发/5秒/cancel/Close所有权；登记后ProtectedControlIO泵独占读写，PING→有界PONG、EOF/error→关闭并移除对应LinkID，target失活后重新分配epoch重拨；无FACT parser/consumer或路由，虚拟Dial仍NoRoute | [`network.go`](../../pkg/simpletier/network.go), [`control_pump.go`](../../pkg/simpletier/control_pump.go), [`framed_io.go`](../../internal/link/framed_io.go), [`lifecycle.go`](../../internal/link/lifecycle.go) |

Raw `HandshakeSequence.Done()` 只表示三条记录在结构上完整，不能用作 Noise success、身份认证、Capability admission 或事实发布条件。相应 wire codec 测试也只证明字节布局与 structural sequencing，不是密码学互操作。

## 2. 概要流程

```text
[Connector / inbound accept / host handoff]
                     |
                     v
[Dedicated Connection + stable underlay Type]
                     |
                     v
[Freeze expected NetworkContext + Link metadata]
                     |
                     v
[Raw bounded HANDSHAKE records: XX Msg1 / Msg2 / Msg3]
                     |
                     v
[Noise_XXpsk3 transcript + full context prologue]
                     |
          +----------+-----------+
          |                      |
          v                      v
 [failure / timeout]     [responder actually reads Msg3]
          |                      |
          v                      v
 [Close; publish nothing] [validate both static keys / NodeIDs]
                                 |
                                 v
                    [encrypted CAPABILITY each direction]
                                 |
                     +-----------+-----------+
                     |                       |
                     v                       v
               [either fails]        [both pass target version=2,
                     |                required bits, no reserved bits]
                     v                       |
             [Close; publish nothing]         v
                                  [Established Link]
                                           |
                                           v
                                [Topology admission may begin]
```

Only the authenticated Link owner may pass a `VerifiedLink`-like value to topology admission; raw records, local Noise completion and unverified remote fields must never enter FactStore. The future implementation must make this gate explicit at its interface, not rely on caller convention.

## 3. Detailed handshake invariants

### Roles, context and records

The Link initiator is the Connector caller/outbound dial owner, or the explicit role selected by an inbound handoff wrapper. Both roles must agree on one nonzero LinkID, LinkEpoch, LinkGeneration and LaneID before the Noise transcript is accepted. The exact NetworkContext descriptor and these fields are encoded by the confirmed `NetworkContext.Prologue("simpletier-v1/link", binding)` contract. Descriptor encoding and PSK are present in the current security module; Link metadata allocation/persistence and handshake orchestration are not implied by that fact.

On the dedicated raw stream only, the structural codec consumes records in the exact order Msg1, Msg2, Msg3. Records are length-prefixed with the existing bounded header codec. A partial prefix/header/payload, invalid metadata, wrong step, changed Link fields, timeout or I/O error is terminal for that stream. The caller closes it; it does not attempt to resume frame mode or replay a partially written record. No ordinary FrameKind is read or emitted until the full Link admission gate succeeds.

### Noise state and mutual confirmation

Configure the released `flynn/noise` API exactly for XX with PSK placement 3, ChaChaPoly and SHA256, using the persisted local static X25519 identity, the derived context PSK and the full context-bound prologue. Verify the API's responder/initiator role and peer-static behavior against the pinned library source/version and its exact XXpsk3 vectors; the vectors are library fixtures, not independent SimpleTier interoperability.

`Split()` returns canonical initiator-to-responder then responder-to-initiator states on both peers. Initiator TX=first/RX=second; responder TX=second/RX=first. Never implement “first key is my TX” symmetrically on both ends. The `UnsafeKey()` API exports a copied Split transport key, not a chaining-key exporter. If adapting Noise keys to SimpleTier's separate AEAD nonce/AAD, export only after complete handshake, treat them as direction-specific roots, derive domain/context-separated application keys once, and do not also use the same Split CipherStates for application transport. This adapter needs direct direction, context-separation and interop tests before any claim of production authentication.

The responder's successful Msg3 verification is necessary but not proof that both applications admitted the Link. Both peers must send/validate encrypted CAPABILITY. The specifically approved target is schema/version2, mask0x3f with bit1=fact-sync.v2 and all reserved bits6..63 zero; v1 is rejected, not silently reinterpreted. Current observed code still implements v1. Each side may become Established for the target version only after peer capability validation and its own write completion; no fact, route or endpoint admission before that condition.

### CAPABILITY binding and dispatch

Use the existing `FrameKind=LINK_CTRL`, `ControlType=CAPABILITY` schema `version:u8 | capability_bits:u64be`; do not invent a handshake message kind or bypass the established Wire codec. Capability records are sent only after the raw Noise handshake has completely transitioned both local Noise states to transport and the directional hop AEAD keys are installed. They must be protected under the Link's directional control subkeys and counters, with the Link metadata/context already bound by the transcript/prologue.

The capability validator must distinguish malformed encoding from a well-formed but incompatible version/mask, close either case, and have no topology side effects. Only the pair `(authenticated peer identity, bidirectional capability success)` may create the internal established Link admission result. The result retains LinkID, epoch, generation, LaneID, Connection Type snapshot, identity binding and its own lifecycle; Connection Type never proves identity.

## 4. Failure and acceptance coverage

Required executable cases before an implementation can claim authenticated Link:

| Scenario | Required result |
|---|---|
| Correct context/token and matching X25519 identities | Both roles complete XX, agree on context and opposite directional keys, then exchange and validate CAPABILITY before Established |
| Wrong token, wrong name/CIDR or context mismatch | Generic fail-closed handshake result; no plaintext fallback, no established Link, no fact publication |
| Existing NodeFact binds a different public key for claimed NodeID | Reject before admission; test forged identity/public-key mismatch |
| Truncated/oversized/out-of-order/changed-metadata raw record or stalled peer | Bounded failure, Connection closed once, no ordinary frames and no state publication |
| Initiator emits Msg3 but responder never reads/accepts it | Initiator is not Established until peer encrypted CAPABILITY arrives; responder publishes nothing |
| One-sided or invalid CAPABILITY | Both sides fail closed; neither side admits topology |
| Tampered Noise record, prologue/context/link metadata or protected CAPABILITY | Cryptographic/validation failure, no Established state |
| Replay a previous handshake/capability against a fresh generation/epoch | Reject according to authenticated epoch and per-connection transcript; never reuse old successful state |
| Network Close/context cancel during blocking read/write | Close interrupts I/O, worker exits, keys/state are not promoted |
| Successful Connect or local Noise Split without peer gate | Still not a Link and cannot make virtual `DialContext` route succeed |

Do not report these scenarios passed until real project tests execute the concrete runtime path. A raw HANDSHAKE codec test, Noise library self-vector, fake stream-only callback or passing structural checker is not authenticated SimpleTier interoperability evidence. A second independent implementation or frozen project vectors plus two actual Network peers is needed before claiming interoperability.

## 5. 下一 FACT/并行 Link 切片的具体确认与实施差距

父协调者报告本轮问答：parallel_link_epoch选“独立并存和撤销（Recommended）”、fact_protocol_upgrade选“统一升级并拒绝 v1（Recommended）”。已合入拥有者规格。Type展示既有授权未重复询问；没有因此批准数值策略、换钥opcode/能力位或KDF原型差异。

目标FACT v2 LINK在既有payload末尾追加TypeLen:u16+非空literal UTF-8/no-NUL Type，实例target为From16|To16|Lane1|LinkID8（41B）。最大REVOCATION target74、FactKey93、encoded record4253；Type仍计入原4096-byte Payload，其他页/snapshot/Link/内存配额不变。撤销/EOF L1仅排除L1，健康不同LinkID的L2可继续；更高NEW epoch不自动退休旧健康已建立实例。

CAPABILITY schema v2仍精确version:u8|mask:u64be：bit0 frame.v1、bit1 fact-sync.v2、bit2 path.v1、bit3 session.v1、bit4 packet-lane.v1、bit5 stream-lane.v1，fullmask0x3f，bits6..63保留至未来换钥具体批准。全组协调升级、strict拒绝v1，无mixed-version fallback或v1-labelled v2 record；不以未见部署证明兼容性代价不存在。当前本轮回读capability/fact codec仍v1，后续代码须同步门禁、Type、实例key和v2 digest；文档确认不等于FACT consumer已经存在。

持久NEW-attempt floor仍按ContextID/initiator/Lane：11先提高floor时迟到未准入10拒绝；10已经准入后11准入可独立并存。同域分配到admission完成窗口应序列化，receiver提交次序与same-epoch transcript持久绑定仍须实现/验证，不能降低/拆分floor。Link.Close/Done只移除当前运行实例，不构成尚未实现的实例FACT tombstone/撤销广播。

本轮仅更新文档；不运行或声明v2/并行撤销功能测试、不修改Go/dependency、不开新passed E。

## 6. Evidence boundary

This note deliberately adds no new passed Evidence record before final source/review results are collected. Current code has real initial CONTROL authentication, encrypted capability and epoch-gated lifetime registration; earlier no-internal/link/no-Noise observations describe the prior scan only and are superseded by the refreshed table. They do not prove independent interoperability, persistent transcript idempotence, peer stability, data/fact/route consumers, long-stream key update or whole P1 completion. The final verifier/binder must reread the last source changes and bind actual checks rather than update historical hashes.
