# 线上帧协议与链路安全


## 摘要

本模块是两节点之间的**加密外层 TCP 连接（控制/数据连接池）**上的唯一线上契约：怎么把多条逻辑消息切分成帧、怎么加密防止偷看和伪造、怎么防止重放旧密文、一条帧多大、队列/内存多少，以及加密外层下的性能机制。v0.2 原文称其为“消息封装与端到端安全”；用户已确认按推荐整包冻结。当前修订已整合独立评审的帧、bootstrap、Path、Fact、性能和安全边界。

调用方是 Carrier/Link（建链、调度、断链）、Packet 平面（IP_PACKET）、Flow 平面（UDP_DATAGRAM、STREAM_DATA）和控制面（拓扑、Path、探测消息）。本模块**不负责**：选路/拓扑语义、TCP/UDP/ICMP 业务语义、代理协议、密钥交换握手本身（属安全设计）；本模块约定握手完成后密钥如何用于帧保护，并对握手提出钥匙派生的前置要求。

## 1. 需求与模块约束


### 1.1 上层需求与边界

上层需求：[多协议覆盖网络](../multiprotocol-overlay.md) 的加密外层与资源边界、[TCP 虚拟覆盖网络](../tcp-overlay-network.md) 的 Stream 帧边界、[L3 覆盖 VPN](../l3-vpn.md) 的包帧保护。本模块承担它们共用的帧/加密/防重放契约，不复制各自的业务语义。

前提：Wire 使用同一套可靠、有序、专用全双工 Connection 字节流 framing，不为 TCP/WS/WSS/宿主实现复制协议；这是用户已确认 Connector/Connection 方向对旧“载体只有 TCP”提案的修订。TCP 是内置实现，WS binary 边界由 [WebSocket 适配](websocket.md) 展开；ConnectionType 不是 LaneID。控制/数据 Lane 隔离与池资源约束继续保留，但一条物理 WS 上复用逻辑子流仍有共享故障/队头阻塞，不能等价宣称独立 TCP 池的性能隔离，该取舍仍须明确。已选的 Noise/PSK proposed 握手与密钥派生见 [安全握手与密钥](security.md)（每次握手新鲜派生，满足随机数唯一的前提）；有效认证强度仅在实际 token 符合已确认的 ≥128-bit CSPRNG policy 时成立，运行时不声称能验证任意字符串的熵。明文、XOR、NullCipher 等弱加密或明文降级一律不存在。逐跳子钥匙按 (Link, 方向, 用途) 隔离，保证每条子钥匙拥有独立的随机数空间。

术语：本文“代际”按上下文指 `KeyEpoch`（端到端）、`LinkGeneration`（链路控制）或 `PathGeneration`（路径，不进入密钥状态）；用户冻结的“随机数 = 代际 32 位 + 消息号 64 位”特指 `KeyEpoch | MessageNumber` 构造，逐跳层沿用同一构造形式。

### 帧定界、大小与上限

TCP 字节流上每帧为 `length(4 字节大端) | FrameKind(1 字节) | hop_hdr(32 字节) | optional envelope(85 字节) | body`；`length` 覆盖其后的所有字节（FrameKind + hop_hdr + optional envelope + body），总帧字节数为 `4 + length`。**大小口径（冻结）**：`length ≤ 65536`（64 KiB 指 length 字段值，即 kind+hop header+envelope+body 的上限）。固定最小值按 FrameKind/MessageType 解码。LINK_CTRL payload 编码固定：PING/PONG=`ProbeID:16B`；LINK_ERROR=`error_code:u16|detail_len:u16|detail`；CAPABILITY=`version:u8|capability_bits:u64`；TEARDOWN=`request_id:u64|reason:u16`；FACT_* 使用下文 schema。ControlType 是解密后 LINK_CTRL 明文载荷的首字节，由 hop AEAD 认证。pre-decrypt minimum is `length ≥ 50` for LINK_CTRL (`FrameKind+hop_hdr+ControlType+16B tag`); after hop AEAD authentication, enforce the exact minimum and payload length for each ControlType (PING/PONG 66, LINK_ERROR 54 with empty detail, CAPABILITY 59, TEARDOWN 60, plus corresponding FACT schema). `E2E` minimum remains `1+32+85+32=150` (kind+hop header+envelope+two tags); `ROUTE_CTRL` minimum remains `1+32+85+1+16=135` (kind+hop header+envelope+one nonempty payload byte+tag); `SESSION_CTRL`/PATH bootstrap 载荷还必须非空且不超过 8 KiB。小于对应下限判 `FrameMalformed`。先校验长度再分配内存。`FrameKind` 取值 `LINK_CTRL=0x01`（链路本地控制）、`E2E=0x02`（端到端业务）、`ROUTE_CTRL=0x03`（需要中继读取的路径/会话 bootstrap），其他值判 `FrameMalformed`。body 恒不为空（至少包含 AEAD 输出与 tag）；允许空业务载荷。LINK_CTRL 的 `ControlType` 为 `PING=0x01、PONG=0x02、LINK_ERROR=0x03、CAPABILITY=0x04、TEARDOWN=0x05、FACT_SUMMARY=0x06、FACT_PAGE=0x07、FACT_ACK=0x08、LINK_KEY_UPDATE=0x09`；未知值或其他保留值判 `FrameMalformed`。0x09 仅在双方 CAPABILITY v2 协商 bit6 `link-key-update.v1` 后合法，未协商时收到即拒绝且不降级。LaneID v1 枚举固定：CONTROL=0x00、PACKET=0x01、STREAM=0x02；Path 只允许 PACKET/STREAM Lane。超长消息由调用方显式分块，禁止无界长度、隐式拼接或截断后当完整帧。

All multi-byte integers in every v1 message payload use unsigned big-endian/network byte order unless a field is explicitly a raw byte string; bare `u16/u32/u64` aliases in tables therefore mean `u16be/u32be/u64be`. IPv4 fields are four network-order address bytes. Reserved enum/flag values are rejected unless assigned below.

### 双层加密与认证覆盖

每帧 body 经**逐跳 AEAD**（ChaCha20-Poly1305，逐跳子钥匙）保护，AAD 含 `length`、`FrameKind`、hop header 和 E2E/ROUTE envelope（若存在）以及该跳可见路由字段。**逐跳子钥匙按用途隔离**：数据帧按 (Link, 方向, SessionID) 从链路根钥匙派生；`LINK_CTRL` 用 (Link, 方向) 的控制子钥匙；`ROUTE_CTRL` 用 (Link, 方向, bootstrap 用途) 子钥匙，仅做逐跳保护。中继逐跳解密校验后只允许修改 cursor、剩余预算、OverlayHopLimit 三类字段，并用下一跳的对应子钥匙重新封包。`E2E` 帧内另有一层**端到端 AEAD**（ChaCha20-Poly1305，会话根钥匙派生的会话钥匙）：密文是业务载荷，AAD 覆盖全部不可变字段——NetworkID、SrcNodeID、DstNodeID、MessageType、PathID、PathGeneration、SessionID、KeyEpoch、MessageNumber、内层长度。由此保证：

- 中继能转发但读不到业务载荷；
- **能通过目的端端到端校验的消息**必然由源端签发：来源、最终目的、MessageType 端到端绑定，任何一层不可改写；中继仍可注入伪造帧，但它们只会被目的端判为 `TamperDetected`，违规归属规则（见 3.3）防止借此关掉受害会话；
- E2E 帧的 `PathID/PathGeneration` 双重绑定（逐跳 + 端到端），任何跳不能改而不被目的端拒绝；ROUTE_CTRL 的 Path 字段只有逐跳认证，认证成员互信边界内不提供恶意成员防护；
- cursor、剩余预算、OverlayHopLimit 等可修改字段只受逐跳保护，不进入端到端认证（否则中继一改就解不开）。

### 消息编号、随机数与防重放

**两层使用同一 96 位随机数构造** `Generation(4 字节) | Counter(8 字节)`：

| 密钥域 | Generation | Counter | 唯一性边界 |
|---|---|---|---|
| 端到端会话钥匙 | `KeyEpoch` | `MessageNumber` | 单会话方向内严格递增、永不重复 |
| 逐跳数据子钥匙（按 SessionID 隔离） | 沿用 `KeyEpoch` | 沿用 `MessageNumber` | 子钥匙域独立，构造复用 |
| 链路控制子钥匙 | `LinkGeneration` | `ControlCounter` | 单 Link 方向内独立递增 |
| ROUTE_CTRL bootstrap 子钥匙 | `LinkGeneration` | `RouteCtrlCounter` | 单 Link 方向内独立递增，所有 Path/Session bootstrap 共用 |

不变量：同一密钥域内 `(Generation, Counter)` 永不重复；MessageNumber 在固定 `(SessionID,KeyEpoch,direction)` 内严格递增；同一 Session/Path 不重置计数。PathGeneration 不进入密钥状态；Path 失效后旧 Session 关闭，新 Path 使用新 SessionID/新 root key。计数器接近 u64 上限时必须提前换钥，禁止回绕；正常 key age/use 更新要走原 Link 内协调事务并保留长业务流，不能把重建物理 Link 后的 SessionLost 当作成功换钥。若真实故障或已经无法安全更新而达到安全硬限，仍 fail closed，不能为不断流重用 nonce。原 Link 更新协议/控制记录/双向切换屏障尚待定向评审，不将目前 Session rekey 规则视作已更新 Link 控制/引导钥匙。KeyEpoch 到 u32 上限时关闭旧 Session 并以新 SessionID 建立新 root key，不回绕。LinkEpoch 达 u64 上限时该 Network/Lane 的 initiator fail closed，拒绝新建 Link（仅换 LinkID 不重置高水位）；PathGeneration 达 u32 上限时关闭该 Path 并分配全新 PathID/Generation=1，旧 PathID 不复用。

**换钥匙（Rekeying）**：Session 首次建立/重连必须由最终 Security contract 选定的握手派生 fresh session root（当前选定的 proposed Noise/PSK branch）；定期换钥或计数逼近上限时由 Path owner 执行最终 Security contract 选定的 rekey handshake，派生新 root/traffic keys 并安装 `target_epoch=current+1`；当前选定的高熵-token Noise/PSK branch 采用重跑 IK；若未来新增 PAKE scope，须另立决策并重审 rekey pattern 与 SESSION_CTRL payload。推荐初值 24 小时，仍属实现候选。同一 `(SessionID,attempt,target_epoch=current+1)` 只有一个 pending rekey handshake；同 attempt 仅接受所选握手模式的字节级相同 transcript，冲突 transcript 拒绝；并发 trigger 合并，不得并行派生两把 current key。pending epoch 期间旧 epoch 仍可收发。每个 Session/direction 建立跨 epoch egress barrier：提交第一条 target-epoch frame 前，先有序写完该方向所有已排队 old-epoch frame；barrier 后不得再向新队列追加 old-epoch frame，以保持 STREAM_DATA stream_seq 跨 epoch 单调。匹配 SESSION_READY 在 CONTROL Link 到达前，data Link 上的 target-epoch E2E frame 仅能进入 bounded queue；不推进 current epoch/replay/grace。SESSION_READY commit 后按序处理 pending frames，首个 E2E tag 有效的 target-epoch message 才设置 `grace_start`；旧 epoch从该单调时刻起保留 30 秒再释放。无对应 pending rekey handshake 的未来 KeyEpoch、不同 attempt/transcript 或超时后迟到 epoch 判 `EpochMismatch`；pending READY 在 30 秒内未完成则 Path/Session 失败并清 queue。

滑动规则：E2E/逐跳/ROUTE_CTRL 接受高于窗口上界的消息并滑窗，窗口内洞位容忍乱序（容忍距离 1024）；窗口内重复判重；低于窗口下界判过旧；换代际开新窗口，旧窗口保留至 grace 结束后释放。每条 Session 方向固定绑定一条数据连接；该 Session 的单一 egress writer 在优先级调度确定 wire order 后才分配 MessageNumber、加密并串行写出，不得在排队前由并发 producer 预留 counter。LINK_CTRL 不使用业务 bitmap replay window，但接收端按 `(LinkID,LinkGeneration,direction)` 保存 last_control_counter，只接受 counter 严格递增的帧（TCP 有序允许跳号），counter≤last 时丢弃；PING/PONG 还必须匹配 outstanding ProbeID，FACT 通过 snapshot/page/FactKey 幂等。

### 加密外层的资源与性能

资源硬上限：`length ≤ 65536`；每 Peer active Link总数≤6（所有Lane/initiator/Type/LinkID合计；并行实例不扩容），replacement drain≤6；每 Link 数据队列≤4MiB；每 Link 控制保留≤64帧/256KiB；网络级控制保留≤8MiB且计入全局数据缓冲≤64MiB；每 Session replay window 1024 位。认证前每监听器≤128连接、每连接待读≤8KiB、并发握手≤16、每来源速率4新连接/s（burst 8）；每个已认证 Link 的 ROUTE_CTRL/FACT/CONTROL_RPC 入站控制速率≤100 msg/s（burst 200），每节点全部 Link 控制总速率≤10000 msg/s（burst 20000）；**`WINDOW_UPDATE` 例外，不计入该预算**（它是接收端由自身消费速率产生的信用反馈，对端无法放大；计入会使 64 KiB 窗口每帧消耗一个令牌，把大载荷吞吐锁在约 3 MB/s）；每节点 Path 表项≤1024、PATH_OPEN 并发≤64且 TTL≤45秒、ReadyPending≤64且 TTL≤30秒、pre-READY reservation≤64且 TTL≤30秒、Session_CTRL cache≤64且 TTL≤30秒、每来源 FACT staging≤8MiB/2 snapshot、每 Network FACT staging≤64MiB、FACT PayloadLength≤4KiB、encoded FactRecord≤4253B（v2 LINK target41、REVOCATION target74、FactKey93；Payload仍≤4096）、FactStore≤32MiB（包括 Record bytes/provenance）、live facts≤8192；单 sender snapshot≤8192 facts/64 pages/3MiB canonical facts、Fact high-watermark≤16384、每 FactKey provenance≤8、每 HostAdapter 包队列≤1024包/2MiB、每 Peer Packet≤10000 pps burst 2000、每 Network Stream session≤4096。每 Network 所有核心拥有的 heap/state/byte-buffer 统一硬上限≤256MiB；各子限额为上限而非预分配，分配前统一计账。控制面超限先限速/隔离，无法入保留队列则明确关闭对应 Link/session，不静默丢控制。每流实际缓冲≤64KiB，256KiB 是 credit 上限而非预分配。**超限处置按 MessageType 冻结**：

| MessageType | 队列满/缓冲超限 |
|---|---|
| `STREAM_DATA` | 绝不静默丢帧：反压，超时返回 RESET/资源错误（外层可靠，丢帧等于静默截断字节流） |
| `IP_PACKET` / `UDP_DATAGRAM` | 丢弃 + 计数 |
| `LINK_CTRL` / `ROUTE_CTRL` / `CONTROL_RPC` | 永不静默丢弃；保留控制预算，无法发送时进入有界 teardown/资源失败路径 |

队列计数按完整 wire frame bytes 计算（`4+length`，含 4-byte prefix、AEAD tags 和队列持有 buffer），frame count 单独计。Per-Link 4MiB/256KiB 和 64 帧是对象上限而非预留额度；多个 Link 共享 Network 的 8MiB control/64MiB data/256MiB total accountant，不能按 Link 数把各上限预分配或承诺全额可用。控制池耗尽时按上表 fail-closed/teardown；分配前记账，释放后归还。

性能机制：发送缓冲池（TCP 写完成或拷贝完成即归还）；每个 E2E Session/direction 的 egress scheduler 先在尚未分配 MessageNumber 的候选队列中选择下一帧（可让 CONTROL_RPC 优先于未选取的 STREAM_DATA），再分配 MessageNumber、执行 E2E 加密并提交给 Link writer。`CIRCUIT_OPEN` 的 LinkWriter admission 是同步 all-or-none；明确拒绝必须保证未入队且不会稍后发送，可留下已分配的 MessageNumber gap；admission pending 时不得切换候选；接纳完整 frame 才达到 TCP 定义的 `EgressCommitted`，无法证明拒绝的结果按可能已接纳处理。Link writer 必须保持同一 Session 已提交帧的顺序；可以在不同 SessionID 间公平交错，但不得重排已编号的同 Session 帧。STREAM_DATA 的 `stream_seq` 字节顺序始终不变。LINK_CTRL 的 ControlCounter 和 ROUTE_CTRL 的 RouteCtrlCounter 在各自 Link 的串行 writer 中按实际 wire emission 分配，不能由并发 producer 先取号后乱序写。小帧合并用聚合 I/O 或拷贝入合并缓冲，禁止向已入队缓冲追加帧；控制/数据独立 TCP 连接池，数据池再分为 Packet/Datagram 低延迟 lane 与 Stream/Bulk lane，同一 Stream 固定 lane/连接，Packet/UDP 不得排在单一 bulk Stream 的无限 burst 后；交互/控制连接启用 TCP_NODELAY。强制加密不得为性能提供明文或弱加密开关。性能承诺必须有基准测试证据（吞吐、RTT、p95/p99 排队时延、CPU、内存），数值目标在基准后另行冻结。

`SESSION_READY` 跨 Link 时序/重钥匙队列：初建会话时它走 CONTROL Link，E2E frame 走独立 PACKET/STREAM data Link，TCP 无跨连接顺序保证。每 hop 的 Path/Session 处于初建 `ReadyPending` 时，或 Active Path 上的 Session 处于 `RekeyPending(target_epoch,attempt)` 时，先完成 hop AEAD/replay 校验，再暂存完整 wire frame（包含 4-byte length prefix），不交付/转发；中继不尝试 E2E 解密，目的端也不在 rekey commit 前提交新的 KeyEpoch/replay/grace。匹配 SESSION_READY 提交对应 Path 或 rekey epoch 后按 data-Link 接收顺序 drain；目的端正常验证 E2E tag 并原子提交 replay window。每 Path/Session/direction pending queue retained wire bytes≤65,897（最大 Flow UDP datagram 两帧总 wire bytes：65,540+357，均含 prefix；亦覆盖单方向 64KiB Stream credit 的 65,894 bytes in-flight），metadata 计入 Network-owned state；所有字节仍受每 Link/Network 聚合 buffer 限制。Packet/UDP 队列满时丢弃计数，STREAM/CONTROL_RPC 反压并超时 RESET/资源错误。READY/rekey pending 30 秒内未提交时清队列并发送 PATH_BROKEN；rekey失败关闭该 Path Session，映射 SessionLost。重复/迟到 SESSION_READY 幂等或拒绝，不回滚已提交 epoch。

 SessionClass 作用域：每个 `(NetworkID,SrcNodeID,DstNodeID,PathID,PathGeneration,SessionClass)` 有唯一 SessionID；PACKET SessionID 只承载 IP_PACKET/UDP_DATAGRAM，固定到该 Path 的 Packet lane 数据连接；Path/连接失效后建立新 Path 和新 SessionID，不迁移旧 replay 域。STREAM SessionID 只承载 STREAM_DATA/相关 CONTROL_RPC，固定到该 Path 的 Stream lane；Path 失效返回 SessionLost，不自动迁移已建立 Circuit。不同 Path 的 SessionID/root/replay 域彼此独立，不做节点对全局会话选主。

SESSION_CTRL 在控制连接上传输，但 PATH 表项为每个 SessionClass 选择对应的 `LinkID+LinkEpoch+lane`；所选 Session handshake 完成后，双方只在该 Path 的同一 data Link/lane 上发送该 SessionID。找不到对应 data Link、LinkEpoch 变化或池内连接重建时，旧 Session 失效，必须重新 PATH/SESSION_CTRL，不把同一 SessionID 迁移到未确认的物理连接。

### 启动握手与控制挑战

按已确认的高熵 token policy，当前 proposed Link handshake 使用 Noise XX：链路 Noise XX 握手发生在加密帧模式之前，使用独立的 length-prefixed `HANDSHAKE` 记录：`length:u32be | message_kind:u8 | link_id:u64be | link_epoch:u64be | link_generation:u32be | lane_id:u8 | noise_payload`，`message_kind=XX_MSG1=0x01、XX_MSG2=0x02、XX_MSG3=0x03`。发起方在 Msg1 生成 CSPRNG LinkID、使用按 `(ContextID,LaneID)` 单调递增、跨所有对端和 endpoint 共用的 LinkEpoch（进程内，重启后从 1 重新开始）（ContextID 来自 Security 的版本化 Descriptor，u64 NetworkID 仅 locator；NextLinkEpoch 已供当前 CONTROL initiator 在发送首记录前调用）、生成非零 CSPRNG LinkGeneration，并声明 LaneID；响应方 Msg2/Msg3 原样回显全部字段；它们进入 Security 的完整 `NetworkContext.Prologue("simpletier-v1/link", binding)`，不能只用短 locator 绑定。HANDSHAKE `length` 与 Frame length 一样只计其后 `message_kind+link_id+link_epoch+link_generation+lane_id+noise_payload`，不含 4-byte prefix；单记录 `length≤8192`，累计实际 wire bytes（含所有 4-byte prefixes）≤24576；只允许顺序的 Msg1/Msg2/Msg3，握手完成前拒绝其他记录和业务帧；EOF/半帧为 `TruncatedHandshake`，未知 message_kind、LinkID/LinkEpoch/LinkGeneration 不一致或重复/越序消息为 `HandshakeMalformed`。握手成功后才安装 hop keys 和正常 FrameKind。

结构实现观察（不等于认证运行）：[handshake.go](../../internal/wire/handshake.go) 已提供 `ReadHandshake`、`WriteHandshake`、`HandshakeSequence`。固定 header 是 22B（kind1 + LinkID8 + LinkEpoch8 + LinkGeneration4 + Lane1），`length` 的最小结构值为 22、最大 8192；Noise 是否接受 empty opaque Payload 由后续密码握手决定，codec 本身可处理 empty。读取先检查 prefix 与固定元数据，再分配受界 Payload；记录间 clean EOF 为 `io.EOF`，半 prefix/header/payload 为 `ErrTruncatedHandshake`，原始错误可被 `errors.Is` 查询。codec 不关闭流，也不认证或检查 PSK。

`HandshakeSequence.Accept/Read/Write` 单 owner严格消费sent/received 1/2/3，每步元数据一致，累计按 `4+length` 计账且≤24576；Read在payload allocation前检查剩余累计预算，Write在输出前校验，非法/I/O失败terminal不能回退。`Done()`只表示结构完整。实际 `internal/link.Handshake` 已消费sequence并调用Noise XXpsk3，完成静态身份和双向加密CAPABILITY后才返回；部分写/读取/取消失败关闭流，无明文降级。固定字节向量/net.Pipe结构测试与密码握手测试是不同证据，均不自动证明跨实现互操作。

selected P1 Noise/PSK branch: 端到端 Noise IK 尚无会话钥匙时使用 `FrameKind=ROUTE_CTRL, MessageType=SESSION_CTRL`：PATH_READY 成功后才允许该消息。发起方生成随机 SessionID(16B)，对端回显；`KeyEpoch=0`、envelope `MessageNumber=0` 表示 bootstrap，hop header 使用 LinkGeneration|RouteCtrlCounter；`attempt` 首次显式为 0，`target_epoch` 首次为 1；bootstrap envelope 仍 `KeyEpoch=0/MessageNumber=0`。必须单独有 haveAttempt 状态，按 role/step/attempt 缓存 byte-identical 重传，不重复消费已推进 Noise 状态；终止失败新建 SessionID，不复用失败 transcript。这是用户具体确认的基线，SESSION_CTRL/READY codec 与实际状态机仍未实施；后续 `target_epoch=current+1`。载荷只做逐跳 bootstrap 子钥匙保护，载荷自身是 Noise 密文；完成 IK 后才允许该 SessionID 的 E2E 业务 MessageType。完成 IK 后 initiator 必须在该 Path 上发送 `SESSION_READY`（同一 SessionID/SessionClass/data_lane_id/attempt/target_epoch）；每个 hop 仅在 PATH_READY 后收到匹配的 SESSION_READY 时将 ReadyPending 转 Active。PATH_OPEN/READY/BROKEN 的同一 PathID+Generation 重复消息同样幂等，旧 Generation 判 `PathGenerationExpired`。


| 场景 | 期望结果 | 关联 |
|---|---|---|
| 帧往返与混合类型 | 多条 LINK_CTRL/E2E 帧在同连接上交错收发，接收端正确切分和分派 |
| 超长/过短/非法类型 | `length > 65536` 或低于 FrameKind 通用最小值在分配前拒绝；LINK_CTRL 通过 hop AEAD 后再按解出的 ControlType 校验子类型最小值；FrameKind/MessageType 映射不匹配则拒绝 |
| 篡改/伪造 | 修改任一认证字段或载荷、伪造来源节点，接收端解密失败并丢弃 |
| 中继不透明 | 中继能读路由字段并转发，但拿不到业务载荷、改不了来源/目的/类型；改 PathID/Generation 会被目的端拒绝 |
| 重放/旧消息 | 重复消息号和窗口外旧消息被丢弃并计数，持续违规只关会话不关 Link |
| 换路/换钥匙 | 换 Path 不重编号；新代际提前到达被正常推进；换代际后窗口独立、随机数不重复 |
| 队列/内存超限 | STREAM 反压→超时 RESET；包/报丢弃+计数；控制帧不丢 |
| 顺序不变量 | 同一会话方向 STREAM_DATA 不被控制帧插队重排；会话方向不跨数据连接拆散 |
| E2E 重放窗口抗投毒 | 收到 hop AEAD 有效但 E2E tag 无效且 MessageNumber 为窗口最大值的帧；目标丢弃但窗口/epoch/grace 不变，后续合法 counter 仍可接收 |
| Egress nonce 顺序 | 并发 producer 和高优先 RPC 下，计数仅由 Session/Link 串行 writer 在选定 wire order 后分配；不会 counter 11 先于 10 写出 |
| ReadyPending/RekeyPending cross-Link maximum | Deliver maximum legal frame (`length=65536`) before SESSION_READY; per-direction cap 65,897 accommodates the full 65,507 UDP_DATAGRAM’s two frames; release after READY, and additional bytes follow per-MessageType overflow rules |
| 重复路由字段不一致 | 修改 ROUTE_CTRL payload 的 PathID/Generation/Lane、src/dst 或 SessionID 与 envelope/header 不一致；FrameMalformed 且不产生部分状态 |
| 字节级帧向量 | HANDSHAKE prefix/count、E2E inner_len/AAD、各 LINK_CTRL 最小负载及 FrameKind 长度在两份独立 codec 中往返一致 |
| CIRCUIT_READY 未知结果 | EXPIRED status 只允许 `OUTCOME_UNKNOWN` error code，并映射公开 ErrOutcomeUnknown；响应 request_id/attempt 不匹配时被忽略 |
| 最大 Flow UDP datagram | 65,507-byte UDP_DATAGRAM 编为两片且 per-fragment 长度合法；目的端仅重组完整 payload，缺片/超时/duplicate ID 不重复交付 |
| Initial Stream credit | source/target initial window 必须恰为 65,536 bytes；0/window-over-cap 在 Open/Ready 前拒绝，不能出现零窗死锁 |
| Active Path rekey early data | 新 target_epoch frame 在 READY 先到时停留在 RekeyPending queue；旧 epoch 可用，Ready 后新 epoch/replay atomically commits；timeout breaks bound Session |
| UDP association isolation | Two SrcNodeIDs use identical AssociationID/DatagramID; target replay/assembly state remains distinct by authenticated NetworkID/SrcNodeID. Per Association/direction only one incomplete ID; terminal conflict/resource/timeout consumes ID |
| Cancel fence under saturation | CONTROL_RPC scheduler sends CANCEL before queued Open on another Path; tombstone/independent 30s peer fence rejects delayed Open even when an unrelated reservation expires first |
| Fact size units | `PayloadLength=4096` produces a v2 encoded FactRecord≤4253; Link target41/revocation target74/FactKey93 recomputed, other quotas unchanged |
| CAPABILITY exchange | 选定的Link认证后双方发Version=2/mask=0x7f，bit1=fact-sync.v2；严格拒绝v1、缺必需bit和bits6..63，门禁失败无FACT交换 |
| 性能 | 基准测试给出吞吐/时延/CPU/内存实测值；小帧合并与连接池生效 |

## 2. 概要设计


### 2.1 内部职责与依赖

```text
[调用方: Packet / Flow / 控制面]
        |
        v
[Framer 组帧/切帧] <-> [Session Cipher 端到端加解密]
        |                        |
        v                        v
[Hop Cipher 逐跳加解密] <-> [Replay Tracker 防重放]
        |                        (按 KeyEpoch+方向)
        v
[Scheduler 控制优先/顺序不变量/缓冲池]
        |
        v
[Carrier: 加密外层 TCP 连接池(控制/数据)]
```

Framer 拥有帧边界和大小上限；Session Cipher 拥有会话钥匙/代际/消息号；Hop Cipher 拥有逐跳子钥匙（按 Link/方向/用途隔离）和允许修改字段的规则；Replay Tracker 拥有按 (KeyEpoch,方向) 的窗口；Scheduler 拥有队列上限、顺序不变量和发送策略。密钥的生成/交换属于安全设计，本模块消费“已建立的链路钥匙”，并要求会话钥匙每会话新鲜派生。

### 2.2 发送与接收处理流程

```text
[调用方 logical message]
    |
    +--超长--> [FrameTooLarge；不入队]
    v
[按 Session 入逻辑队列：尚未分配 nonce/counter]
    |
    v
[Session egress 调度下一帧；保持 Stream byte 顺序]
    |
    v
[分配 KeyEpoch|MessageNumber -> E2E AEAD]
    |
    v
[Link writer 分配 Link nonce -> Hop AEAD -> 有序 TCP write]
    |
    +--路径含中继--> [逐跳 AEAD 校验；仅合法路由字段可变]
    |                              |
    |                              +--hop tag/replay 失败--> [丢弃；不转发]
    |                              v
    |                        [下一跳 Link writer]
    +------------------------------+
    v
[目的端 Hop AEAD 校验]
    |
    +--E2E replay read-only precheck: definite duplicate/old--> [丢弃]
    v
[E2E AEAD 校验]
    |
    +--tag 失败--> [TamperDetected；不推进 E2E replay/epoch]
    v
[原子 recheck + commit E2E replay/epoch]
    |
    v
[按 MessageType 交付 Packet/Flow/控制面]
```

发送是异步入队：入队成功不代表对端已收（尤其 UDP_DATAGRAM 不得由本层重放）。接收路径上任何一步失败都不得把半条消息交给上层；截断帧按链路故障处理（见 3.3 失败分类）。

### 2.3 数据流与归属

```text
[A 载荷: IP包/UDP报/Stream字节/控制消息]
        |
        v
[端到端封包] --密文载荷+不可变信封--> [逐跳封包]
        |                                  |
        |                                  v
        |                       [TCP 字节流: length|FrameKind|body]
        |                                  |
        |                     +--中继只见路由信封--+
        |                     v                    v
        |                 [转发]              [目的端逐跳解包]
        |                                        |
        +<-----端到端解包校验<-------------------+
        v
[B 载荷交付]
```

不可变信封随端到端密文一起被认证，归属发送端；可改路由字段（cursor、预算、OverlayHopLimit）归属各跳链路保护；PathID/Generation 双重绑定；消息号/代际归属会话方向。接收缓冲归接收方所有，发送侧复用缓冲池但不得在入队后继续写入。

## 3. 详细设计


### 3.1 帧布局与字段

| 字段 | 长度 | 可见性 | 保护 |
|---|---|---|---|
| `length` | 4 字节大端 | 所有跳可见 | 逐跳 AEAD 的 AAD |
| `FrameKind` | 1 字节 | 所有跳可见 | 逐跳 AEAD 的 AAD |
| 可改路由字段 | cursor、OverlayHopLimit、剩余预算 | 中继可见**可改** | 仅逐跳 AEAD |
| 双重绑定字段 | PathID、PathGeneration | 中继可见**不可改** | 逐跳 AEAD + 端到端 AAD |
| 不可变信封 | NetworkID、SrcNodeID、DstNodeID、MessageType、SessionID、KeyEpoch、MessageNumber、PathID、PathGeneration、内层长度（85 字节） | 中继可见 | 端到端 AEAD 的 AAD + 逐跳 AEAD 的 AAD |
| 载荷密文 | < 65536 减去头部 | 仅源/目的可读 | 端到端 AEAD |

**二进制布局 v1（冻结）**：

```text
frame   = len:u32be | kind:u8 | hop_hdr(32B) | [envelope(85B, E2E/ROUTE_CTRL)] | body
hop_hdr = generation:u32be | counter:u64be | path_id:u64be | path_gen:u32be
          | cursor:u8 | hop_limit:u8 | remaining_budget_us:u32be | pad:u16
envelope= network_id:u64be | src:16B | dst:16B | message_type:u8
          | session_id:16B | key_epoch:u32be | message_number:u64be
          | path_id:u64be | path_gen:u32be | inner_len:u32be
body    = AEAD 密文 + 16B tag
```

E2E 帧：`generation|counter` 复制自 envelope 的 `key_epoch|message_number`；ROUTE_CTRL 帧：`generation=LinkGeneration`、`counter=RouteCtrlCounter`，由每个 Link 方向单调分配，所有 ROUTE_CTRL 消息共用该 nonce/replay 域；E2E/ROUTE_CTRL 的 hop_hdr PathID/PathGeneration 必须与 envelope 副本一致。LINK_CTRL 的 path_id/path_gen/cursor/hop_limit/remaining_budget/pad 全为 0。所有保留 `pad` 字段必须发送零，接收非零判 FrameMalformed。envelope 明文位于逐跳密文之外（中继路由需要读 dst/path），同时进入逐跳 AAD 与端到端 AAD；body = `AEAD_hop(key=hop 子钥匙, nonce=generation|counter, aad=len|kind|hop_hdr|envelope, plaintext=AEAD_e2e(payload))`。ROUTE_CTRL 的 body 是 `AEAD_hop` 包装的 bootstrap payload，无端到端层。LINK_CTRL 帧无 envelope，body plaintext 的首字节是 `ControlType`，随后是 ControlType 固定 payload，再整体做 `AEAD_hop`；nonce 取 `LinkGeneration|ControlCounter`。

**AAD 与长度单位**：`AAD_hop` 是原始 `length:u32be | FrameKind:u8 | hop_hdr:32B | optional envelope:85B` 字节串；E2E `AAD_e2e` 是 envelope 的准确 85 个原始字节，严格按上表字段顺序，既不包含 hop_hdr 也不重新编码字段。E2E `inner_len` 是完整明文 MessageType payload 的字节数（IP_PACKET 时为完整 IPv4 packet），不包括 E2E 或 hop AEAD tag；ROUTE_CTRL `inner_len` 是 bootstrap 明文 payload 的字节数，不包括 hop tag。外层 `length` 仍包含两层输出的 tag。

**FrameKind 与 MessageType 映射**：`FrameKind=E2E` ⇔ 帧内含 envelope、使用端到端会话钥匙，且 `MessageType ∈ {IP_PACKET=0x01, UDP_DATAGRAM=0x02, STREAM_DATA=0x03, CONTROL_RPC=0x04}`；`FrameKind=ROUTE_CTRL` ⇔ 帧内含 envelope、只使用逐跳 bootstrap 子钥匙，且 `MessageType ∈ {SESSION_CTRL=0x05, PATH_OPEN=0x06, PATH_READY=0x07, PATH_BROKEN=0x08, SESSION_READY=0x09}`；`FrameKind=LINK_CTRL` ⇔ 无 envelope（MessageType 不适用）。映射不一致判 `FrameMalformed`。

**CAPABILITY schema v2（已确认的目标）**：字段仍为 `version:u8 | capability_bits:u64be`，payload9B、受保护LINK_CTRL frame length59保持不变。version必须为2；bit0 `frame.v1`、bit1 `fact-sync.v2`、bit2 `path.v1`、bit3 `session.v1`、bit4 `packet-lane.v1`、bit5 `stream-lane.v1`，完整必需mask为0x7f：bit6 `link-key-update.v1` 为必需位，bits7..63保留且必须为0。（seq1875/seq1885）批准 ControlType 0x09 与原 Link 内换钥事务，取代本修订前 Wire@29 的“bit6 保留、未批准 0x09”描述。version!=2、缺必需bit或保留bit非零以VersionMismatch关闭，不降级、不发布事实。全组协调升级，严格拒绝v1，无混版本层，不能静默重新解释v1 bit1或发送v1-labelled v2 FACT。Noise后双方在同一Link各发送并验证加密CAPABILITY，两端门禁完成后才可进行v2 FACT交换。`packet.ipv4`/实际业务数据实现仍由自己的NodeFact和runtime决定，能力位声明不构成数据功能验收。

目标与观察分开：此前 `internal/link/capability.go` 固定version1/mask0x7f、FACT codec仍v1的说法是历史实现观察，不再描述当前代码。当前实现报告显示 CAPABILITY v2/FACT v2 编码和严格版本拒绝已有局部实现及 focused tests；FactRecord/type/实例键字节向量和部分控制状态有测试。FACT consumer、FactStore/RouteView接线、完整端到端数据帧及最终集成复核仍未验收，不能据局部codec结果称网络交换已完成。


**CAPABILITY 初建 v1（历史实现观察）**：旧记录中的 `internal/link.Handshake` 以version:u8=1、mask:u64be=0x3f交换并消耗两方向counter0，后续同root发送从1开始。该描述仅保留历史语境，不表示当前契约允许v1。当前实现报告显示CAPABILITY v2严格拒绝v1；最终正式Network认证入口和全链路仍待复核。Network CONTROL已有ProtectedControlIO/controlPump、PING/PONG与EOF实例移除；FACT语义consumer/RouteView依然没有接线。初建capability成功或payload可解密不等于事实准入。

**ROUTE_CTRL envelope 保留值**：所有 ROUTE_CTRL 的 NetworkID/SrcNodeID/DstNodeID/PathID/PathGeneration 按消息实际值填写，`inner_len` 是 bootstrap payload 字节数；PATH_OPEN/READY/BROKEN 使用 `SessionID=0^16、KeyEpoch=0、MessageNumber=0`；SESSION_CTRL/SESSION_READY 使用真实 SessionID、`KeyEpoch=0、MessageNumber=0`。

**ROUTE_CTRL 计数与方向**：每个已建立 Link direction 由一个串行 writer 在实际 wire emission 时分配 RouteCtrlCounter，从 0 开始递增；LinkGeneration 是 HANDSHAKE 生成的非零 CSPRNG u32，每个新的 LinkID/authentication generation 重新生成，旧 Link/Counter 不复用；u64 溢出关闭 Link 并建立新 generation。PATH_OPEN 的 envelope Src/Dst 是逻辑路径端点，PATH_READY/PATH_BROKEN 反向交换 Src/Dst；SESSION_CTRL 的 envelope SessionID 必须与 payload SessionID 相等，Src/Dst 与所选握手的 initiator/responder 相等。

ROUTE_CTRL redundant fields are protocol invariants and must be checked before any Path/Session state mutation: hop-header PathID/Generation equal the envelope copies; PATH_OPEN/READY/BROKEN payload PathID/Generation equal both copies, payload Lane matches the installed data Path, PathDigest matches the canonical ordered node/link list, and envelope Src/Dst match the logical Path endpoints (READY/BROKEN are reversed). SESSION_CTRL/SESSION_READY payload SessionID equals envelope SessionID; class/data lane/attempt/target_epoch and PathID/Generation match the pending Path/selected handshake record, with Src/Dst matching selected-handshake initiator/responder. For E2E CIRCUIT_OPEN, the source/target endpoints compare payload PathID/Generation/PathDigest with the authenticated envelope and installed Path. Any mismatch is `FrameMalformed`/`InvalidPath` and MUST NOT partially mutate route/session/circuit state.

**SESSION_CTRL payload status (approved)**: the current high-entropy Noise/PSK branch uses `SessionID:16B|class:u8|lane:u8|attempt:u32be|target_epoch:u32be|noise_len:u16be|noise_message`; the schema and READY commit semantics are approved by (see [安全握手与密钥](security.md) 3.5.3), while the exact HKDF salt/info field bytes are an implementation refinement within that approval and external interoperability is not claimed. SessionID/Class/Lane/attempt/target_epoch binding and READY commit semantics are mode-independent. Human passwords are out of P1; any future PAKE scope must reopen these payloads before version freeze.


| MessageType | 最小载荷字段 |
|---|---|
| `IP_PACKET` | 完整 IPv4 包；PacketEnvelope 的 MessageType 固定为 0x01 |
| `UDP_DATAGRAM` | `AssociationID:16B | flags:u8(REQUEST=0x00/REPLY=0x01) | DatagramID:u64be | fragment_index:u8(0/1) | fragment_count:u8(1/2) | total_payload_len:u16be(0..65507) | source IPv4:4B | source port:u16be | destination IPv4:4B | destination port:u16be | fragment_payload`；每个 UDP socket datagram 用一个或两个 E2E UDP_DATAGRAM frame 表示，编码规则见下文。 |
| `STREAM_DATA` | `CircuitID:16B | flags:u8(DATA=0x01/FIN=0x02) | stream_seq:u64 | payload`；stream_seq 是每方向字节偏移，首个 DATA 从 0 开始并按 payload 字节数递增；DATA payload 非空；FIN 是独立空载荷帧，stream_seq 等于最终字节数、不占序号 |
| `CONTROL_RPC` | `rpc_code:u16 | request_id:u64 | payload`；`CIRCUIT_OPEN=0x0001` payload=`CircuitID:16B|open_attempt:u32|target_port:u16|PathID:u64|PathGeneration:u32|RouteViewVersion:u64|PathDigest:32B|source_initial_window:u64(65536 initial bytes)`；`CIRCUIT_READY=0x0002` payload=`CircuitID:16B|open_attempt:u32|status:u8(READY=0x01/REFUSED=0x02/EXPIRED=0x03)|error_code:u16(NO_ROUTE=0x0001/LINK_DOWN=0x0002/PERMISSION=0x0003/TARGET_REFUSED=0x0004/RESOURCE=0x0005/OUTCOME_UNKNOWN=0x0006/CANCELED=0x0007)|initial_window:u64(65536 initial bytes)`；READY 必须 `error_code=0`，REFUSED 使用对应拒绝码，EXPIRED 必须映射 `ErrOutcomeUnknown` 并使用 `OUTCOME_UNKNOWN`；`STREAM_RESET=0x0003` payload=`CircuitID:16B|open_attempt:u32|reason:u32(NO_ROUTE=0x0001/LINK_DOWN=0x0002/RESOURCE=0x0003/PROTOCOL=0x0004/CANCELED=0x0005)`；CANCELED 以 `(NetworkID,SrcNodeID,CircuitID)` 为全 Path/全 attempt 终态；open_attempt 仅用于关联与诊断，并与 Listener.Accept 串行决胜；`RESOURCE_ERROR=0x0004` payload=`CircuitID:16B|resource:u8|retry_after_ms:u32`；`WINDOW_UPDATE=0x0005` payload=`CircuitID:16B|window:u64`（绝对 next-byte credit）。
| `SESSION_CTRL` | `SessionID:16B | SessionClass:u8(PACKET=0x01/STREAM=0x02) | data_lane_id:u8(PACKET=0x01/STREAM=0x02) | attempt:u32 | target_epoch:u32 | noise_len:u16 | noise_message`；data_lane_id 必须等于 SessionClass 和 PATH Lane；消息本身在 CONTROL Link 上以 ROUTE_CTRL 发送 |
| `SESSION_READY` | `SessionID:16B | SessionClass:u8 | data_lane_id:u8 | attempt:u32 | target_epoch:u32 | PathID:u64 | PathGeneration:u32`；data_lane_id 必须等于 SessionClass 与 Path Lane；仅 ROUTE_CTRL，完成当前 Security-selected session handshake 后发送，初建时提交 ReadyPending Path，重钥匙时提交 Active Path 上的 pending target_epoch |
| `PATH_OPEN` | `PathID:u64 | Generation:u32 | LaneID:u8(PACKET=0x01/STREAM=0x02) | ViewVersion:u64 | node_count:u8 | node_ids[16B] | link_count:u8 | (LinkID:u64,LinkEpoch:u64)* | PathDigest:32B` |
| `PATH_READY` | `PathID:u64 | Generation:u32 | LaneID:u8 | PathDigest:32B | status:u8(READY=0x01/REJECT=0x02/ALREADY=0x03/ROLLED_BACK=0x04) | error_code:u16(NO_ROUTE=0x0001/LINK_DOWN=0x0002/RESOURCE=0x0003/PROTOCOL=0x0004)` |
| `PATH_BROKEN` | `PathID:u64 | Generation:u32 | LaneID:u8 | PathDigest:32B | reason:u16 | failed_cursor:u8` |

Flow `UDP_DATAGRAM` segmentation v1：IPv4 UDP 用户载荷最大为 65,507 bytes。E2E 明文 payload 上限为 65,386 bytes；本 record 的固定元数据为 41 bytes，故每 fragment payload 最大 65,345 bytes。`total_payload_len≤65,345` 使用 `fragment_count=1, fragment_index=0` 且 fragment 长度等于 total；`65,346..65,507` 必须 `fragment_count=2`，index 0 长 65,345，index 1 长 `total-65,345`（1..162）；空 UDP payload 合法且使用单 fragment。flags must be REQUEST=0x00 or REPLY=0x01; unknown values reject the datagram. Direction, endpoints, AssociationID, DatagramID, fragment_count and total length在同一 datagram 所有 fragment 中必须一致。`AssociationID` 是本地 Flow/Proxy 为每个 UDP association 生成的 CSPRNG 16-byte ID；在 `(NetworkID,SrcNodeID)` 内对 active/120-second recently-closed IDs 做 collision check 并禁止复用。`DatagramID` 是每 `(NetworkID,SrcNodeID,AssociationID,direction)` 从 1 单调递增的 u64，不回绕/不复用；每逻辑 datagram 的所有 fragments 固定在同一 Path/Session，Path 故障导致缺片时丢弃整个 datagram，不在新 Path 重放。接收端仅在目标 UDP Endpoint 重组，Relay 逐 frame 转发而不缓存完整 datagram。目标端 assembly/replay key 分别是 `(NetworkID,authenticated envelope SrcNodeID,AssociationID,direction,DatagramID)` 与其不含 DatagramID 的前缀；每 key 使用 1024-bit duplicate window。E2E AEAD/Association owner 校验完成后，成功交付或任何 terminal discard（schema/conflict/resource/timeout/superseded）都标记该 DatagramID consumed；tag 失败不修改 ID window；乱序片段可先暂存；相同 index/bytes 的重复片幂等，冲突元数据或不同 bytes 使该 assembly 失效并诊断。每 `(NetworkID,SrcNodeID,AssociationID,direction,DatagramID)` 未完成 assembly 最长 120 秒（不随后续包延长，沿用 UDP association idle 上限）。每 `(NetworkID,authenticated SrcNodeID,AssociationID,direction)` 最多保留一个 incomplete assembly，payload≤65,507 bytes；该 association 收到更高 DatagramID 时先终态丢弃并消费旧 incomplete ID，再接纳新 ID。MESH 每 Network≤256个 UDP Associations，因此 reassembly payload 理论上≤256*2*65,507=33,539,584 bytes；所有 allocation 仍计入 Network 64MiB data-buffer / 256MiB heap-state shared budgets，超过任一上限时拒绝当前片、消费该 DatagramID 并计数，不做业务 ACK/重试。该 Flow framing 与 SOCKS5 UDP 请求头的 RFC `FRAG` 字段无关；P1 仍拒绝客户端 `FRAG!=0`，也不对 L3 `IP_PACKET` 分片/重组。

`CONTROL_RPC.request_id` 为每个 `(SessionID, direction)` 单调分配且不复用的 u64 RPC 标识，request/response 必须原值回显；相同逻辑 Open 重传保留原 request_id，新 attempt 和 CANCEL 使用新 request_id。`CIRCUIT_READY` 只有在 request_id、CircuitID、open_attempt 均与源端当前待决请求相同才可接受; 目标若因 CircuitID cancel tombstone 拒绝迟到 Open，返回 REFUSED/CANCELED；源端已取消或已推进 attempt 后的迟到响应忽略。计数即将回绕时关闭 Session，不回绕。

`STREAM_RESET(CANCELED)` is terminal for `(NetworkID, envelope SrcNodeID, CircuitID)` across all Path/Session/open_attempt values, not keyed by its request_id; receiver records a bounded tombstone even if CIRCUIT_OPEN has not arrived, and rejects any later Open for 30 seconds from tombstone creation; overflow sets an independent per-Peer `CircuitOpenBlockedUntil=now+30s` fence, which is not cleared by unrelated reservation expiry. A lost CANCEL frame still follows the public best-effort cancellation rule.

接收端每 Circuit/方向维护 `next_byte`；`stream_seq == next_byte` 的 DATA 按 payload 交付并递增；`stream_seq < next_byte` 且 `stream_seq+payload_len ≤ next_byte` 作为完整重复帧丢弃计数；若旧帧与 next_byte 部分重叠，发送 STREAM_RESET(PROTOCOL)；`stream_seq > next_byte` 是可靠有序 lane 的协议错误，发送 STREAM_RESET(PROTOCOL)。FIN 必须 payload 为空且 `stream_seq == next_byte`，随后该方向不再接受 DATA。CIRCUIT_READY 的 `initial_window` 初值为 64 KiB；window 是绝对允许的最大 next-byte offset，发送端不得超过；credit 最大前沿不超过 receiver next_byte+256 KiB。应用读取释放缓冲后，接收端发送单调递增 WINDOW_UPDATE；旧 window 值忽略，u64 溢出关闭 Circuit。

PATH_OPEN 约束：`2 ≤ node_count ≤ 16`、`link_count = node_count-1`；LaneID 必须与 SessionClass 相等，PATH 中每个 `(LinkID,LinkEpoch)` 必须引用同一 LaneID 的 LinkFact；`cursor=0` 表示源节点，目标节点收到 cursor=node_count-1 后返回 PATH_READY，failed_cursor 必须在 `[0,node_count-1]`。

覆盖 hop_limit 初值固定为 16（Path 最大跳数），源端写入 16；每个中继在转发前递减一次，递减结果为 0 时不得再转发并判 `BudgetExhausted`；目标节点可在收到最后一跳的正值后交付。

P1 撤销没有独立 ControlType；撤销只能编码为 `Kind=REVOCATION` 的 Fact，随 FACT_PAGE 进入同一 snapshot/digest/ACK/high-watermark 流程。任一认证成员可创建 REVOCATION fact，创建时立即触发新的 FACT_SUMMARY/snapshot；目标版本以上的事实可恢复。

**FACT v2（已确认目标与局部实现观察）**：SUMMARY/PAGE/ACK 的 `protocol_version:u8` 必须为2，并与CAPABILITY v2的fact-sync.v2门禁一致，v1输入拒绝且无降级。固定SUMMARY65B/PAGE header67B/ACK36B字段宽度不变。LINK Record的Payload末尾追加 `TypeLen:u16be|Type`，target为From16|To16|Lane1|LinkID8（41B）；REVOCATION target≤74、FactKey≤93、encoded record≤4253，Type仍计入4096-byte Payload。page/snapshot digest域统一 `simpletier-fact-page-v2` / `simpletier-fact-snapshot-v2`，不能复用v1 canonical/digest并静默改变内容。解析先校验版本/长度/Kind，再从Payload重算完整实例key；同Peer/Lane其他Link不被该实例撤销。当前报告已有v2 codec、实例键算术/向量及strict-version测试；FACT control consumer和FactStore/RouteView生产接线仍缺，最终集成验证pending。除实例键对应的record算术外，原页/snapshot/资源配额不变。

LINK_CTRL fact synchronization payloads（目标v2，以下每个protocol_version值均为2；全部限制在 `length` 上限内；FACT_PAGE facts 编码部分 ≤48 KiB 且最多 128 facts）：`FACT_SUMMARY = protocol_version:u8 | sender_incarnation:u64 | NetworkID:u64 | snapshot_version:u64 | fact_count:u32 | page_count:u32 | digest:32B`；`FACT_PAGE = protocol_version:u8 | sender_incarnation:u64 | NetworkID:u64 | snapshot_version:u64 | page_no:u32 | page_count:u32 | fact_count:u16 | page_digest:32B | facts`；`FACT_ACK = protocol_version:u8 | sender_incarnation:u64 | NetworkID:u64 | snapshot_version:u64 | page_no:u32 | status:u8(OK=0x01/NEED_PAGE=0x02/COMPLETE=0x03/REJECT=0x04/NEED_SUMMARY=0x05) | reason:u16 | missing_page:u32`。FACT_PAGE 的 `facts` 是固定 header 之后的 remainder 字节流，长度由已解码 payload 总长减去固定字段推导（无单独 `facts_len` 字段）；其中 records 是 Topology 定义的 `FactRecord` 串接（包含 `key_len|FactKey|FactEnvelope|Payload`，不可只发送 Envelope/Payload）。remainder size、page/snapshot counts 和 digest 按这些实际 Record bytes 校验，规则见拓扑模块 3.3.1。接收方先 staging，所有页齐全且每页 digest/整体 digest 校验通过后原子提交 sender-known facts；重复页幂等，缺页由 NEED_PAGE 重传，NEED_SUMMARY 明确请求新的 SUMMARY，REJECT 携带 reason（过期、版本、摘要、资源或语义错误），COMPLETE 只在原子提交后发送；OK=单页已接收，NEED_PAGE=请求 missing_page，NEED_SUMMARY=清理当前 staging 并请求 SUMMARY，REJECT=清理 staging 并按 reason 终止当前 snapshot。未知 snapshot 先丢弃并发送 NEED_SUMMARY。FACT_ACK 的 sender_incarnation 回显 FACT_SUMMARY/PAGE 的发布者 incarnation，不使用接收者本地 incarnation；sender_incarnation 由发布节点在进程内递增（重启后从 1 开始），snapshot_version 在该 incarnation 内单调递增；接收方按 sender+incarnation+snapshot_version 去旧，撤销在 staging 提交前合并且 tombstone 优先。`SESSION_CTRL` 只在 PATH_READY 后建立端到端会话；PATH_OPEN/PATH_READY/PATH_BROKEN 本身使用 ROUTE_CTRL 的逐跳保护。


### 3.2 安全会话与密钥代际

```text
[Init]
  |
  v
[Handshaking] --认证失败/超时--> [Closed]
  |
  v
[Active: KeyEpoch=1, 消息号递增]
  |
  +--换钥匙条件--> [Rekeying: Epoch+1, 消息号归零] --> [Active: KeyEpoch=N]
  +--持续违规(按归属阈值)--> [Closing] --> [Closed]
  +--TCP 断开/显式关闭--> [Closed]
```

状态由每条 Session 方向独立维护。换 KeyEpoch 时新旧钥匙不得共用随机数空间：新代际第一条校验通过的消息启动 30 秒 grace，接收端正常推进、不判违规。PathGeneration 变化本身不进入 nonce；Path 失效时关闭绑定该 Path 的 Session，后续消息在新 Path 上使用新 SessionID/所选握手新派生的 root key，不复用旧 nonce/replay 域。

### 3.3 关键实现机制与失败语义

1. **切帧**：累积读取到 4 字节头即校验 `固定最小值 ≤ length ≤ 65536`，越界立即失败；随后按 length 读满再解密；TCP EOF/半帧判 `TruncatedFrame`（链路故障，非攻击）。
2. **逐跳处理**：中继解密成功后只允许改 cursor、剩余预算、OverlayHopLimit；改动 PathID/Generation 或其他字段会导致下一跳/目的端校验失败。
3. **防重放及提交顺序**：E2E 作用域为 `(SessionID,KeyEpoch,direction)`，逐跳数据为 `(LinkID,SessionID,KeyEpoch,direction)`，ROUTE_CTRL 为 `(LinkID,LinkGeneration,direction)`；LINK_CTRL 使用 `(LinkID,LinkGeneration,direction)` 的严格递增 ControlCounter。对 E2E：envelope 的 MessageNumber/KeyEpoch 在端到端认证前不可信；允许先做只读 replay precheck，但必须先验证 E2E AEAD tag，再原子地复查并提交 bitmap/window/epoch 状态。并发重复只有一个可提交；失败 tag 不能移动高水位、滑窗或启动旧 epoch grace，防止相邻中继伪造大 MessageNumber 投毒。逐跳及 ROUTE_CTRL 计数器只在该层 AEAD 验证成功后提交；LINK_CTRL writer 在同一串行发送锁内分配 ControlCounter 并写帧，接收端认证后才更新 last counter。
4. **失败分类**（不得混成一个“网络错误”）：

| 类别 | 触发 | 计入违规阈值 |
|---|---|---|
| `FrameTooLarge` | length > 65536 | 是 |
| `FrameMalformed` | length 低于固定最小值、FrameKind 非法、FrameKind↔MessageType 不一致、解密后结构非法 | 是 |
| `TruncatedFrame` | TCP EOF/半帧 | 否（链路故障） |
| `TamperDetected` | 任一层 AEAD 校验失败（含伪造来源注入） | 计数但不因单类事件自动关闭端到端会话；按 ingress Link 隔离 |
| `ReplaySuspected` | 窗口内重复/过旧 | 是 |
| `EpochMismatch` | 未知旧代际/超出 grace（新代际提前到达不计） | 是 |
| `BudgetExhausted` | 中继 cursor/OverlayHopLimit/剩余预算耗尽 | 否（正常转发失败） |
| `QueueFull` | 见上表按 MessageType 处置 | 否（按各自策略） |

5. **违规归属（防借伪造帧关掉受害会话）**：`TamperDetected`、FrameMalformed、ReplaySuspected、EpochMismatch 等在端到端认证完成前只丢弃、计数并按 ingress Link 隔离，不能凭可伪造的 SessionID 关闭会话；只有通过端到端认证的状态错误，或明确的本地资源策略，才可关闭对应 E2E Session。共享 Link/连接池不因单一会话错误关闭；Link/连接池仅由链路层失败（`TruncatedFrame`、读写错误、失活探测）关闭。
6. **性能路径**：发送侧从缓冲池取帧缓冲，小帧在极短窗口内合并为一次 TCP 写（聚合 I/O 或拷贝）；控制帧可插队但不得重排同一 STREAM Session；Packet/Datagram 和 Stream Session 分别固定到各自 lane/数据连接；入队后不得改写发送缓冲。

### 3.4 可自主部分与已冻结取舍

Handshake-independent outer wire fields are the current v1 contract: TCP frame length, FrameKind, hop header, optional envelope, assigned endian rules, and fixed numeric codes. The pre-frame Noise `HANDSHAKE` message kinds/payload and the Noise-specific `SESSION_CTRL` body are the approved high-entropy Noise/PSK branch (see [安全握手与密钥](security.md) 3.5.3); exact KDF field bytes are an implementation refinement within that approval and external interoperability is not claimed; any future PAKE scope requires a new decision and revised schemas. Implementers may choose internal memory objects/buffer pools/goroutine structure, but must preserve the confirmed outer-frame offsets.

历史冻结（2026-09-22，推荐整包确认）的外层字段/安全约束包括：原 TCP framing 字节布局、双层 ChaCha20-Poly1305、随机数代际32位+消息号64位、重放窗口1024位、单帧 length≤65536、控制/数据池隔离。后来用户批准 Connector/Connection 上统一的可靠字节流，TCP/WS/WSS/宿主输入复用这些 framing 字段，不能再将旧“只允许 TCP 载体”当作当前 SDK 提供者限制。独立物理池与共享 WS 下的隔离取舍仍不擅自等同。

当前提案中不依赖认证握手模式的 Wire 约束包括：逐跳子钥匙按 (Link,方向,用途) 隔离；会话按 SessionClass 分为 Packet/Stream lane；SessionID 不跨 lane/连接复用；换钥接收推进语义与 30 秒 grace；E2E/逐跳/ROUTE_CTRL 窗口域分离；PathID/Generation 在 85B envelope 与 hop header 双绑定；Fact sync 使用 LINK_CTRL 固定 opcode；按 MessageType 的超限处置；`length ≤ 65536`；FrameKind/MessageType 数值与握手无关的 payload schema。Noise Split 与 HKDF 应用域（`simpletier/v2/session-root`、`simpletier/v2/session-traffic`）已由 批准；精确 salt/info 字段顺序是实现细化，见 [安全握手与密钥](security.md) 3.5.3。跨实现互操作仍未验证；未来如新增 PAKE scope 须另立决策并重审相关 schema。本文仍为 proposed，设计评审门禁未通过。

### 3.4.1 原 Link 内换钥（ControlType 0x09）

人工确认（seq1875/seq1885）：不新增明文握手；使用现有加密 `LINK_CTRL` 的 `ControlType 0x09 = LINK_KEY_UPDATE` 与 capability bit6；三消息 Noise XX 更新 transcript；旧钥下 REQUEST/XX/READY/COMMIT/ARMED，目标数据 Link 上各方向 FENCE 后以新钥 CONFIRM，DONE 双向确认；任一 FENCE 后禁止回滚，FENCE 前取消必须 ABORT/ABORT_ACK/ABORT_REJECT；每 Link 至多一个 pending，旧/新两代并存；E2E nonce 仍为 envelope `KeyEpoch|MessageNumber`。

Wire 影响：CAPABILITY v2 的 required mask 由 0x3f 变为 0x7f（bit6 必需），bits7..63 保留；`ControlType` 新增 0x09；未协商 bit6 时收到 0x09 判 `FrameMalformed`/拒绝，不降级。payload 具体字段与 phase 编码是在该批准内的实现细化，见 `internal/link/key_update.go`。

实现与验收边界（observed）：`internal/link/key_update.go` 已有 opcode/状态机；link 内 same-stream FENCE 路径测试未绿，本文不宣称换钥实现已验收。数值 key-use 预算仍属 Security 未批准边界。

## 4. 实现状态

帧编解码与逐跳 AEAD 已实现，入口 `internal/wire/frame.go`。单元测试覆盖帧往返、
超长/非法类型、篡改与重放拒绝。


## 5. 偏差、未知和继续入口

- 外层frame.v1长度/kind/hop/envelope/nonce偏移保持不变；FACT/CAPABILITY已确认统一v2并strict拒绝v1 peer：bit1=fact-sync.v2、fullmask0x7f、bits6..63继续保留。LINK尾部Type及完整实例key/record4253目标见Topology。当前已有v2 codec/局部测试报告，文档批准不等于FACT consumer/RouteView或业务路径已运行。Noise-specific SESSION/再换钥具体控制协议和key-use数值仍未由两项批准自动冻结。
- 所选 Noise/PSK branch 的 Noise Split/KDF 与 `noise_message` 载荷属于当前 proposed 协议详设，须在独立设计评审和互操作验证后冻结；SessionClass、Path routing、Fact sync 和其余握手无关 Frame layout 仍是当前 proposed 机制，均未做实现/互操作验证。
- 性能没有实测数据；“保证性能”当前落实为机制 + 基准测试交付门槛，数值目标待基准后冻结。
- 术语对照：KeyEpoch（端到端代际）/LinkGeneration（链路控制代际）/PathGeneration（路径代际）/LinkEpoch（连接重建标识）含义不同；配置字段 `network.token` 与行文“name+secret”指同一入网凭据。
- 初建 Noise/CAPABILITY 与 CONTROL 生命周期已接入认证后帧泵/拓扑消费者，再完成 Session/Path/Circuit/双层业务AEAD、持续writer/replay资源和不断长流换钥。当前除outer framing已有raw codec、FrameProtector和初建认证能力gate；新代码的同库双端测试不替代独立项目互操作、平台或端到端性能，历史条目不改hash冒充新验证。
