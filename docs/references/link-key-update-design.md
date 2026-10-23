# 原 Link 内换钥：双向 FENCE 方案与承诺边界

> 状态：供评审的具体提案，不是 accepted 线上协议，不是已实现/已运行证据。用户确认的是正常密钥到期不得打断长业务流；下面的控制编码、提交/撤销事务和资源策略仍需评审。本文只记录设计，不修改现行规格、源码或历史证据。

## 依据与不改动的对象

- [Security:44](../internals/security.md#L44) 区分物理 LinkEpoch、Noise LinkGeneration、已认证身份和 CONTROL/data Lane；[Security:262](../internals/security.md#L262) 记录正常更新不断长流的要求。
- [Wire:227](../internals/wire.md#L227) 的 32B hop header/85B envelope 不增加换钥选择字段。[Wire:239](../internals/wire.md#L239) 要求 E2E hop nonce 恰为 envelope KeyEpoch|MessageNumber，不能把它改成 Link crypto generation。LINK_CTRL/ROUTE_CTRL 使用 LinkGeneration|各自 counter。
- [Wire:66](../internals/wire.md#L66) 和 [Wire:81](../internals/wire.md#L81) 要求计数由单 writer 按实际 wire order 分配；[Wire:71](../internals/wire.md#L71) 的队列/accountant 上限仍适用。
- [实际 frame codec:64](../../internal/wire/frame.go#L64) 只做有界外层解析；[frame codec:123](../../internal/wire/frame.go#L123) 写失败后结果可能含已发送前缀。它不实现 AEAD、解密后 ControlType 或本提案。
- [Noise 主源研究](security-protocol-research.md) 支持 canonical Split 方向和一次性应用 KDF adapter；官方同库向量不等于项目互操作。

保持物理 Connection、LinkID、LinkEpoch、NodeID、LaneID、ConnectionType、PathID/Generation、CircuitID、SessionID、E2E KeyEpoch/MessageNumber、stream_seq、credit/window 不变。只改变 Link 逐跳根/控制与 bootstrap 子钥匙以及由新根派生的 SessionID 逐跳子钥匙；不触碰端到端 Session rekey。旧物理连接不能被替换后称为无损更新。

每条 Link 增加独立 CryptoUpdateSeq:u64，当前为 0 时首次更新为 1，严格单调且不回绕；物理新 Link 独立作用域。每次重新握手使用新鲜 ephemeral 和非零 CSPRNG generation:u32，至少排除 current/pending/live receive slots 的 generation。Seq 不是 nonce、NodeID 或可替代 LinkEpoch 的重启高水位；钥匙的新鲜性和完整上下文共同保证不同更新不复用 (key,nonce)。一条 Link 至多一个未决更新，完成 DONE 或协调 ABORT 前不得创建第三代。

## 协调与承载

目标 Link 的原始 initiator 是唯一更新协调者 I，另端为 R；这与承载 CONTROL Link 的 initiator 可能不同。任一端可发认证 REQUEST，多个触发合并到唯一 pending sequence。

PACKET/STREAM 的协商走已有独立 CONTROL Link；DATA reader/业务队列不能阻塞 CONTROL 的握手处理。目标 DATA stream 只需要携带自己的 FENCE、CONFIRM 和正常帧。CONTROL 自更新则所有阶段在自身 stream 上按单 writer 顺序运行，reader 不能等待读业务消费完成。

所有 XX1/XX2/XX3 都是现有 AEAD 保护下的 LINK_CTRL 内载荷，绝不在 established stream 插入初始 raw HANDSHAKE。所谓 OLD 是切换前的承载控制钥匙，不能用尚未确认的目标新根来冒充外层 admission；FENCE 由目标 stream 的旧控制子钥匙保护，CONFIRM 由目标 stream 的新控制子钥匙保护。

最小实现先序列化同一 Peer 的 CONTROL 更新与其他目标更新的协商，以免另一个事务跨 CONTROL 的换钥边界继续声称固定 old carrier root。该排程可服务所有业务，不重建 Link；但 DATA FENCE 长期停滞会阻止进一步更新，不能承诺任意慢端下有限完成。若需要并行，必须补明确的 carrier-slot 绑定及 CONTROL 更新交错证明，不能仅以 target sequence 代替承载钥匙选择。

## 提议编码与认证

[Wire:36](../internals/wire.md#L36) 当前只分配 0x01..0x08，0x09+ 保留；[Wire:245](../internals/wire.md#L245) 当前 capability version1/mask0x3f 排斥 bit6。提案分配 ControlType 0x09=LINK_KEY_UPDATE，并采用 capability version2、强制 bit6=link-key-update.v1，mask0x7f；旧节点拒绝而不降级。这是未合入的兼容性变化，不宣称现行 codec 接受它。

每条解密后的更新消息为 ControlType:u8 加以下公共 36B；全部整数大端：

```text
version:u8 (=1)
phase:u8
lane:u8
flags:u8 (=0)
target_link_id:u64
target_link_epoch:u64
update_seq:u64
old_generation:u32
new_generation:u32
```

REQUEST 不授权切换：new_generation=0、seq 表示请求下一次更新，只有协调者分配正式 seq/new generation；正式 XX1 起两端逐字段锁定目标。未知 phase/flags、无目标 Link、错误 Lane/epoch/旧 generation、零或 live generation、冲突 seq/transcript 在状态修改前拒绝。

phase 分配也是提案：REQUEST=1、XX1=2、XX2=3、XX3=4、READY=5、COMMIT=6、ARMED=7、FENCE=8、CONFIRM=9、DONE=10；协调撤销另需 ABORT=11、ABORT_ACK=12、ABORT_REJECT=13，不能省略后声称超时安全回滚。

| 阶段 | 候选附加字段与意义 |
|---|---|
| REQUEST | 无附加字段；可信更新请求，不靠对端自报流量修改本地计量 |
| XX1/XX2/XX3 | previous_transcript_hash:32B、noise_len:u16、noise_bytes；同 seq/step 字节完全一致才可重发缓存 |
| READY/COMMIT/ARMED | new_transcript_hash:32B、proof:32B；proof 为新方向确认子钥匙的 HMAC-SHA256，绑定公共字段、phase、双方 pinned identities 和方向 |
| FENCE | new_transcript_hash:32B；在目标 stream 上作为最后旧钥匙帧，方向由已认证 ingress 推出 |
| CONFIRM | new_transcript_hash:32B、proof:32B；第一条新钥匙目标 stream 帧，验证新控制 AEAD 与新方向确认 MAC |
| DONE | new_transcript_hash:32B、observed_direction_mask:u8；只有双向新钥匙确认均完成后发送，mask 必须 0x03 |
| ABORT/ABORT_ACK/ABORT_REJECT | new_transcript_hash:32B；请求暂停撤销、atomic no-FENCE 承诺、或明确拒绝撤销而向前完成，不是只发超时通知 |

公共字段长度确定，不代表其他新字段已冻结。XX 每次消息和总状态必须先按已有 frame/handshake 尺寸预算检查后分配；初始 [HANDSHAKE:92](../internals/wire.md#L92) 的 length<=8192/累计<=24576 是现有记录口径，不能不扣新控制 metadata 就宣称同一个 noise_len 上限已获批。新的更新载荷限制和协议错误枚举仍需明确；本文不随意增加任意新资源数值。

候选 prologue 用 NetworkContext 的完整 Descriptor，域 simpletier-v2/link-key-update，绑定 target LinkID/Epoch/Lane、CryptoUpdateSeq、old/new generation、双方按 canonical role 排列的 NodeID/静态公钥及 previous transcript hash；上下文/身份任一差异拒绝。原始静态身份保持 pinned，不能把更新握手当成更换 NodeID 的机会。

三消息完成后一次性复制 Noise canonical Split[0]=I->R、Split[1]=R->I，R 本地 TX/RX 反向映射。应用 KDF 为 full context、目标 tuple、seq/generation、完整新 transcript、用途与方向分域；确认、hop-ctrl、hop-route-ctrl、hop-data(SessionID/Class) 子钥匙互不共享。不得继续使用导出的 Split CipherState 加密业务，亦不称这些 transport keys 为标准 chaining-key exporter。

R 在 XX3 验证后发 READY 的新 R->I proof；I 验证后才能发 COMMIT 的新 I->R proof。R 验证 COMMIT 后才能发 ARMED。old-key ACK 只能证明旧通道，不证明双方拥有新钥匙；它不允许 FENCE 或 DONE。

## 正常双向提交与 writer/RX 规则

```text
I                                  R
| ---- XX1 (old encrypted) --------> |
| <--- XX2 (old encrypted) --------- |
| ---- XX3 (old encrypted) --------> |
| <--- READY (new-key proof) ------- |
| ---- COMMIT (new-key proof) -----> |  I irrevocably authorizes this seq
| <--- ARMED (new-key proof) ------- |  R irrevocably authorizes this seq
|                                  |
| target old selected bytes drain  | target old selected bytes drain
| ---- FENCE [old target key] ----> |
| ---- CONFIRM [new target key] --> |
| <--- FENCE [old target key] ----- |
| <--- CONFIRM [new target key] --- |
|                                  |
| <----- DONE (both directions) --> |
```

I 在收到 ARMED 前不能开始本地 FENCE。R 发出 ARMED 后可开始本地 FENCE，因为收到 COMMIT 已证明 I 安装且承诺保留 pending RX；这允许双向独立推进，不假装 CONTROL 与 DATA 有跨连接顺序。

目标唯一 writer 关闭该 seq 的旧 TX admission gate：producer 只能排尚未分配 hop nonce/未 Seal 的 logical frame；先完成已选取旧帧及正在进行的完整有序 write，再在 writer 内原子标记 fenceStarted、分配旧控制 nonce/Seal FENCE 并写出。随后安装 new TX slot，CONFIRM 为该方向首条新控制帧，之后才重新服务待选业务/控制帧。未选 logical frame 不被抛弃；它们使用新 hop root，内层 E2E bytes/seq/windows 不变。计数只由这个 writer 分配，不回滚不提前批量预留。

每个方向的 CTRL/ROUTE counters 从新 root 独立初始化；E2E hop nonce 仍复制 envelope epoch/msgNo，不能清零或修改 E2E 状态。目标 RX 只用当前 implicit hop root 处理 E2E，在当前旧控制 root 验证 FENCE 后切换为 pending root；紧随其后的 CONFIRM 必须先通过新控制 AEAD/MAC。在这个目标 stream 收到 FENCE 前，不因 CONTROL 的 READY/COMMIT/ARMED 到达而切 RX，也不猜两个 E2E roots。

已有 reader 在旧 root 下完成的 hop 验证必须保存 verified inner bytes/不可变 header/已提交 replay provenance，再交付有界队列。不能到 drain 时拿原 wire bytes重新执行旧 hop Open，亦不能按墙钟提前删掉它们需要的旧 root。[现行 pending queue:83](../internals/wire.md#L83) 描述持有完整 wire bytes，需要有意识的表示/计账调整，不能把该语义差异隐藏成实现细节。跨 FENCE 后只有尚未完成的旧 RX 解析需要旧钥匙；已验证数据不依赖旧 hop root，E2E 验证仍照原 Session 执行。

DONE 不是“本端发了 COMMIT”：本端新 TX CONFIRM 已完整写出且新 RX CONFIRM 已验证，才可发 mask0x03 的 DONE；对方同样完成并回显 DONE 才收敛到 Stable(seq)。在此之前最多 current/old 与 pending/new 两个 slot，不允许第三次更新；DONE/CONTROL 阶段可按 seq/hash 幂等回放，不能回退 direction 状态或再次消费 Noise。

## 承诺边界、超时与 ABORT

关键不变量是“本端没看见 FENCE”不等于“对端没有或永远不会发送 FENCE”。来源为父协调者提供的独立 tool-less Mentor challenge；本文将它作为待验证反例，不称作正式外部审计或已通过测试。

```text
I sends COMMIT -> R sends ARMED -> R serializes DATA FENCE
                    |
                    +-- DATA reader/transport is slow
I local timeout; I has observed no DATA FENCE yet
I discards pending RX -> delayed valid old-key FENCE reaches I
I cannot validate following new-key CONFIRM/data: long flow breaks
```

因此以下本地承诺点均不能无条件删除 pending：

| 角色/状态 | 已可能发生的远端行为 | 安全处理 |
|---|---|---|
| 未发送更新消息、未向 peer 暴露 seq | 无本事务 | 可本地清理，但 burned seq/generation 不回用 |
| I 发 XX1/XX3，尚未发 COMMIT | R 可能已发 READY；本地不能让迟到消息激活被撤销 seq | 保守保留 pending，或进入带 tombstone 的 ABORT 协调；拒绝冲突重试/迟到 step |
| R 发 READY，尚未看到 COMMIT | I 可能已经发送 COMMIT，尚在 CONTROL 中 | READY 表示 prepared 且有新钥匙，不能靠 local timeout 盲删 RX pending；等待同 seq/撤销协调 |
| I 已发 COMMIT，尚未看到 ARMED/FENCE | R 可能已授权并开始 FENCE | 保留两 slot，只重发同事务 CONTROL；不得发新 seq |
| R 已发 ARMED | I 可在收到后随时发送 FENCE | 保留两 slot，不得因本地没看到 FENCE自行回滚 |
| 任一方向 fenceStarted/读到 FENCE | 部分或完整新方向可能存在 | 不允许 rollback/ABORT_ACK；保留提交状态并向前完成 |

最保守的规则：首条更新已暴露后，不以 local timer 自动回收/新建 seq。deadline 只触发协调撤销或停发未必安全的新业务；不能触发“全局尚未 Fence”的猜测。真实连接故障与明确安全 fail-closed 可终止，但不能将常规正常到期包装成这两者。

已授权、尚可能无 FENCE 的撤销必须通过以下协议，而不是只有 ABORT 发送成功。仅协调者 I 创建 ABORT 事务；R 的本地 deadline 只报告状态/请求协调且保留 pending，不擅自开并行撤销。以下“请求方”为 I、“响应方”为 R：

1. 请求方先向自己的目标唯一 writer 发 cancel-gate 命令。writer 的 phase CAS 与 fenceStarted 共用同步点：只有没有任何 FENCE write 开始、未完成 TX switch且本地 RX尚未消费 FENCE，才可进入 CancelPending，暂停本 seq的 FENCE。正在写旧选中帧可完成，但 writer不能在其后偷跑 FENCE。CancelPending不是全局已撤销，也不是永久不会更新的承诺；只有第3步收到认证 ACK才变为不可恢复的 Aborted。
2. 发 ABORT(seq/hash)。响应方原子检查自己的 writer gate及 RX状态；若本地没有 FENCE write起点/切换、也未消费 peer FENCE，锁定本 seq为 Aborted并发送 ABORT_ACK。ACK承诺“我方未发且以后绝不会发这条 Fence”。响应方知道请求方在等待撤销时 gate暂停；只要自己这端确实不 Fence，就没有合法 peer FENCE信号能使请求方重新开放。响应方可在 ACK完整写出后释放 pending keys，但必须保留 terminal-abort seq、完整幂等 ACK及取消 tombstone，避免 ACK迟到/重发时复活旧事务。
3. 请求方只有本地 CancelPending仍有效且收到对应 ABORT_ACK，才将自身 gate原子变为 Aborted并释放 pending；此时双向 no-FENCE已由本地 gate和远端不可恢复 ACK共同证明，旧 root继续服务正常流。不得只因已发 ABORT或等到 local timeout就丢弃。只有协调者确认 terminal-abort后才能创建下一 seq；仍需消息收敛/缓存回收规则，但不能强求无穷 ACK链来证明双方都知道对方已知。
4. 若响应方的 FENCE已 wins CAS、write已开始或 RX已消费 FENCE，禁止 ABORT_ACK；发认证 ABORT_REJECT(seq/hash)，保留 slots并向前完成原事务。请求方只有收到这条拒绝，或在目标 stream验证了该 seq的真实 peer FENCE，才可把 CancelPending恢复为原提交 gate以发自己的 FENCE，不更换 root、不重跑 Noise。仅超时/本端没见 Fence不能恢复或清理；已收到 ABORT_ACK的 Aborted绝不复活。若 ABORT/ACK/REJECT不可达，保留有界槽位且阻止第三代。晚到 XX/READY/COMMIT/ARMED不能 resurrect terminal-abort seq。

补充反例：请求方永久 AbortLocked，peer已经 FenceStarted而拒绝撤销；请求方即便验证 peer新钥匙也永远不发自己的 FENCE，DONE条件永远不成立。上述 CancelPending/Aborted区分及认证 REJECT修正这个活性缺口。它是本记录写入者的独立反例，尚未经过模型/代码或 Mentor验证，不是新的通过证据。

FENCE/CONFIRM 在可靠目标 stream 上各方向仅发送一次。目标 write 返回错误或半写时，可能已经发送；不能重新加密/重发 Fence、重新开同一 seq 或切回旧 root。CONTROL 的 byte-identical phase 重发在新外层计数下幂等可行；重发逻辑状态不重新消费 Noise。恢复握手状态不等于恢复失去的物理 transport。

## 资源、慢端与活性边界

复用现有每 Link data<=4MiB、control<=64帧/256KiB、Network control<=8MiB/global buffers<=64MiB/owned heap<=256MiB；均是同时约束的上限，不是额外预留。本提案不借换钥提高这些数字。每 Link 一份 pending Noise/metadata 和两个 root slot都须计入同一 accountant；手工 state/cache 上限、保留预算与协调 abort tombstone 配额需要进一步冻结。

提前触发需要为已选 old write、XX/READY/COMMIT/ARMED/FENCE、abort/确认所需保护域留出可证明 headroom；尚未确定 successful-call/byte/age/failed-verification limits，不能只填任意“提前 10%”称为证明。OldRX 接受已在途/已验证数据的 open-vs-drain 政策要与硬 limit 一起说明，不能靠计数清零延寿。

独立 CONTROL 可以完成协商，不意味着慢 DATA consumer一定让 FENCE 及时到达。full bounded queue 下 reader必须能先认证和按序记录关键阶段，但若为等业务消费无限缓存仍违反资源限；阻塞已选 TCP/WS write时，后面的 FENCE 不能插到已发送帧中间。一条 WS 母连接的物理 HOL也不能靠 logical Lane消除。永久不读的 peer、耗尽保留控制预算或无法在硬限前安全提交时不存在有限、无限缓存且永不断流的通用方案；这需要具体安全/可用性取舍，不是本文批准了关闭策略。

## 设计性质与反例验证矩阵

条件性安全论证：可靠有序 stream、正确 AEAD、固定身份/上下文、唯一 writer、确实遵守承诺的 peer成立时，旧业务在 FENCE 前使用旧 hop root完成且保留内层状态；新业务只能在同 stream FENCE 后以新 root出现。每个方向 RX 顺序与隐式 root选择一致，且正常提交不改变 Stream/Session/E2E 顺序/窗口，所以可保留业务流。它不是形式证明、运行结果或对恶意组成员任意行为的保证。

| 必测场景 | 应保持的不变量/反例 |
|---|---|
| 满 data queue、CONTROL 可读 | 握手能协商；无法完成 DATA FENCE不能盲删 pending或承诺有限完成 |
| ARMED 已发送，本端 timeout，DATA FENCE迟到 | 两 slot仍在；正确处理旧 Fence和新 Confirm，不产生 SessionLost |
| READY 已发，迟到 COMMIT | 不能把 prepared RX删掉；已 abort terminal必须拒绝 resurrect |
| ABORT 与 Fence gate CAS并发 | 仅一方胜出；任何可能已序列化 FENCE都不得 ACK cancel |
| 请求方 CancelPending、peer已 FenceStarted | 只有认证 REJECT或真实 peer Fence可恢复向前提交；永久 AbortLocked会死锁；ACK后不得复活 |
| 丢/迟到 ABORT_ACK、DONE | 没 ACK不删/不开第三代；复发仅幂等，已切换状态不回滚 |
| old-key ACK替代新 proof | 拒绝；CONFIRM必须以新 AEAD/MAC验证后才可完成 |
| 两方向同时压力触发 | 仅原 initiator协调一个 seq，REQUEST合并，无双 Noise current |
| CONTROL 自更新 | 自身 reader/writer无业务等待循环；CONFIRM/DONE顺序明确，不把 raw HANDSHAKE插帧 |
| TARGET tuple/static/full context错误 | 在任何提交、replay或slot修改前拒绝 |
| 相同 seq/step不同 bytes、旧 seq重放 | conflict或terminal/tombstone拒绝，不重复 ReadMessage |
| 第三代/nonce边界/重复 generation | 在 old/new未收敛时拒绝；从不 reset E2E counter或复用 (key,nonce) |
| E2E KeyEpoch/MessageNumber跨 Fence | 字段原样保留，hop nonce复制关系不变；不能充当 Link root selector |
| old-hop 已认证队列延迟 drain | 消費 verified inner bytes，不在删旧 root后重开旧 ciphertext |
| 定时 normal expiry、真实物理故障 | 前者应协调保持流；后者按已确认 P1故障语义，不冒称可无损迁移 |

仍需 owner/定向评审：新 opcode/capability兼容性、更新/撤销字段版本与所有成功/失败计量政策、headroom/oldRX-open-vs-drain、prepared/tombstone的有界生命周期及在永久慢端下的取舍。本文不重新请求已经确认的完整 context、首次 Session 0/1或不断长流目标；不写 passed、不运行测试、不重绑旧证据。
