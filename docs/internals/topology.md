# 拓扑与路由


## 摘要

本模块负责把认证邻接和节点地址/能力事实转换为本地可查询的 RouteView，并为新 Circuit 返回经过策略过滤、排序和版本检查的候选路径。它不负责拨号、握手密钥、业务端口监听、应用重试或宿主机路由。

本模块是 SimpleTier 的 proposed 契约。它参考 `docs/references/TCP虚拟组网设计方案_v0.1.md` 的链路状态思路，并对照父目录 EasyTier 当前源码的 `RoutePeerInfo + conn_info + 本地 Dijkstra + 最终目标转发` 结构。EasyTier 的行为在本文中用 `observed` 标明，不自动变成 SimpleTier 的已批准协议。

## 1. 需求与模块约束


### 1.1 上层需求与边界

上层功能需求见 [TCP 虚拟覆盖网络](../tcp-overlay-network.md) 。本模块承担：

- 保存通过认证来源得到的节点、地址、邻接边和能力事实；
- 处理事实版本、启动世代、序列、有效期、撤销和重复；
- 从当前一致快照构建本地图，计算目标 NodeID 的候选路径；
- 为 Circuit 建路提供稳定的路径版本和排除原因；
- 在拓扑或链路健康变化时使旧 RouteView 失效，但不替业务层迁移已有 Stream。

本模块不承担：

- 认证或判断收到消息的远端是否可信；调用方必须先提供已认证 ingress、StaticPublicKey/NodeID 绑定和 NetworkID 校验结果；P1 不要求 origin signature；
- 直接建立/关闭 Link 或执行 NAT 穿透；
- 逐数据块转发或维护 Stream/Circuit 的字节偏移；
- 解释 HTTP、WebSocket、私有协议或应用层重试；
- 将一个中心节点变成全网唯一的下一跳下发器。

### 版本化事实到一致视图

对同一事实来源，模块只接受符合 NetworkID、身份、版本和有效期规则的最新声明。旧声明、重复声明和已失效声明不能覆盖新状态；拓扑快照重建期间，查询不能返回混合版本的路径和地址映射。

### 路径查询的可解释性

给定目标 NodeID、请求的 data Lane、策略和起始 RouteView 版本，查询返回有序候选路径或带类别的失败原因。data Lane 只能为 PACKET 或 STREAM；PacketRoute 固定请求 PACKET，TCP Circuit 固定请求 STREAM。候选中每条 LinkFact 必须与请求 Lane 相同，且沿每条边存在 active CONTROL Link 供 PATH/SESSION bootstrap；先按 Lane/可达/策略/能力/无重复节点/跳数/预算过滤，再最多保留 3 条候选。排序相同的结果使用稳定决胜规则。

### 变化只影响新建流

RouteView 更新不能直接修改已 Ready Circuit。若快照重建失败，服务对象显式标记 `Stale`，仍可为未受影响的目标提供新建路候选；但每次查询必须按当前 FactStore high-watermark/tombstone、绝对有效期、AddressFact 冲突态和 active LinkEpoch 过滤旧快照。发生更高版本/撤销/冲突而其新快照尚未发布的 key 立即列入 invalidation mask，不得再从 stale 视图选中。受影响目标返回 `RouteStale` 或 `RouteConflict`，不返回旧 NodeID；现有 Circuit 生命周期由上层负责。

### 有界同步和计算资源

通告大小、每个 Origin 保留的事实量、版本缓存、候选路径数量和图计算资源必须有上限。当前 P1 硬初值为：FactKind PayloadLength≤4 KiB；v2 `FactRecord = 2B key_len + FactKey + 62B FactEnvelope + Payload`，LINK target=41B=`16+16+1+8`，最大 REVOCATION target=74B=`16+16+1+41`，FactKey最大93B=`1+16+2+74`，故 encoded FactRecord≤4,253 bytes。Type追加在LINK payload末尾且仍占原4096-byte Payload；Signature/Provenance不在线上。这里只忠实更新实例键增长后的 record 算术，以下 count/page/snapshot/内存配额不变；单 FACT_PAGE≤128 records 且 facts Record bytes≤48 KiB；每 sender snapshot≤8192 records/64页/3 MiB；每 Fact Origin≤4096 live records；每 authenticated ingress sender staging≤8 MiB/2 snapshots；RouteView≤3 候选/目标/lane、最多16跳；单网络≤1024 NodeFact、4096 LinkFact、1024 AddressFact、1024 RevocationFact；FactStore≤32 MiB（含 records/provenance），FACT staging≤64 MiB；图重建并发≤2。count/byte 上限是同时约束，不承诺所有子限额同时可满；超限输入拒绝或淘汰并诊断，提升上限需修订和基准证据。

### L3 目标地址和包路径

对 L3 packet plane，模块按本网络已确认且唯一的 VirtualIP/32 将目标 IPv4 地址解析为 NodeID，并返回 LaneID=PACKET 的候选路径及 `AddressFactVersion`。源端将该版本 pin 到单个 packet attempt；在 PATH activation/提交转发前重查当前 address owner，若已变更/冲突则返回 `RouteStale`/`RouteConflict` 并丢弃，不把这个 IP packet 静默改投到新 NodeID。目标节点在写 Host Adapter 前还必须确认内层 destination IPv4 等于自身当前拥有的 VirtualIP/32；不再拥有该 IP 时丢弃并计数。RouteView 更新只影响后续新 packet attempt。TCP Circuit 仍独立请求 LaneID=STREAM；PacketRoute 和 TCP Circuit 的 path/session 生命周期、预算与失败处理不得混用。


| 场景 | 期望结果 | 关联 |
|---|---|---|
| A-B-C 链式拓扑 | A 的 RouteView 能得到 C 的下一跳/完整候选路径是 B |
| 两条等价路径 | 选择遵循明确成本和稳定 NodeID/LinkID 决胜，不在每次重算间随机切换 |
| 旧版本晚到 | 旧 incarnation/sequence 不覆盖新事实，也不延长有效期 |
| 边断开 | 受影响目标从当前可达候选中排除；其他可达路径仍可查询 |
| 策略禁止中继 | 含被禁止节点/边的路径先被过滤，不以更低成本绕过策略 |
| 环路输入 | 计算结果不含重复 NodeID，Circuit 建路不会无限转发 |
| 同步超限/畸形 | 返回可区分的协议/资源错误，不写入部分不一致快照 |
| RouteView 更新中建路 | Circuit 绑定一个可识别的视图版本；更新不修改已有 Circuit |
| L3 目标地址查询 | VirtualIP/32 解析得到唯一目标 NodeID 和 PACKET 路径，不依赖 TCP Stream 端口 |
| Packet Route 与 TCP Circuit 并存 | 两者共享事实但分别请求 PACKET/STREAM Lane；生命周期/失败/预算不混用 |
| Lane 过滤早于候选上限 | 三条低成本混合/错误 Lane 路径存在且另有合法 PACKET 路径时，PacketCandidates 仍返回 PACKET 候选；控制边只作为 bootstrap 可达性校验 |
| 地址冲突 | 同一 VirtualIP 有两个仍有效 owner 时返回 RouteConflict 且无候选；低 NodeID 决胜只用于 allocator，冲突解除前不发包 |
| stale view 与新撤销 | RouteView 重建失败后，未受影响路由可带 Stale 使用；已撤销/过期/冲突的 key 不得从旧视图返回 |
| PacketRoute 地址版本失效 | FactVersion 查询后、Path activation 前撤销/改址则源端 RouteStale 丢弃；若已发出，旧目标在 HostAdapter 写入前的 /32 owner check 必须失败，不能 retarget |
| 事实时间边界 | 超过45秒有效期、未来 issued 超过30秒容差、已过 expires+30秒的 Fact 被拒；重复/转发不延长时限 |
| provenance 饱和 | 第9个 ingress source 导致 provenance Saturated 但完整 FACT snapshot 仍原子提交；后续 source 关闭不提前删除事实，最终按原始 expiry/tombstone 清理 |
| 同版本 equivocation | 同一 key/version canonical bytes 不同，以确定性 canonical 字节序决胜并记录诊断；所有实现最终看到同一 winner |
| FACT v2/CAPABILITY v2协调升级 | version1拒绝且不发送FACT；version2/mask0x7f、bit1=fact-sync.v2、bits6..63=0，LINK Type与完整实例key/digest一致；未执行 |
| 健康并行Link独立撤销 | epoch10已准入L1，再准入epoch11的L2时两条都可见；EOF/撤销L1的完整实例版本只排除L1，L2继续；Type不作唯一key |
| 并发新尝试不能放宽floor | 11 先提高 floor 时尚未准入的 10 迟到必须拒绝；序列化epoch分配到admission完成，仍须实际证明；同epoch transcript持久绑定缺口不隐瞒 |
| LinkEpoch 网络域 | 同 initiator/Lane 的 Network A 高 epoch 不拒绝 Network B 的较低 epoch；同 Network 重启后仍拒绝回退 epoch |
| 地址派生重启 | 相同 NodeID/Network/attempt 在冷启动实现同一 IPv4 地址；/31、/32、池耗尽边界结果确定 |
| FactRecord bytes/digest | 两份独立 encoder 生成相同 `key_len|FactKey|Envelope|Payload` 字节；FactKey 与 payload 推导值不符时拒绝 |
| Snapshot page canonicality | FactKey 跨页重复/乱序、pageNo/count sum 与 summary 不符时整份 staging snapshot 拒绝且不部分提交 |

## 2. 概要设计


### 2.1 内部职责与依赖

```text
[已认证 Link]
      |
      | VerifiedFact: peer/address/link advertisements
      v
[Fact Store] --版本/寿命/语义结果--> [Snapshot Builder]
                                          |
                                          v
                                      [Peer Graph]
                                          |
                              cost + policy + constraints
                                          v
                                     [RouteView]
                                          |
                              target -> ordered candidates
                                          v
                           [TCP Circuit Open / Packet Route]
```

- **Fact Store**：按 NetworkID 和来源 NodeID 保存节点、地址、邻接、服务能力和健康摘要；不执行 Socket I/O；
- **Snapshot Builder**：在一致性边界内读取事实，过滤不完整/过期数据，生成不可变快照；
- **Peer Graph**：节点是 NodeID，边是认证 Link/邻接事实，边携带可计算成本和策略标签；
- **RouteView**：保存从本节点到目标的候选结果、版本和排除原因；可从快照重建，不是新的事实来源；
- **Circuit**：消费一个 RouteView 版本并自己记录已选路径，不能反向修改 Fact Store；
- **PacketRoute**：消费同一事实/视图得到 IP/Prefix 到目标 NodeID 的包候选，不拥有 TCP/UDP/ICMP 连接状态或应用重试。

### 2.2 处理流程

```text
[Link / Identity Admission]
      |
      +--未认证/NetworkID/NodeID 绑定不符--> [Admission reject；不进入本模块]
      |
      v
[VerifiedFact]
      |
      +--编码/语义/版本非法--> [Fact Store reject，不改变当前快照]
      |
      v
[比较 origin + incarnation + sequence]
      |
      +--旧或重复--> [忽略；不刷新寿命]
      |
      v
[写入有界 Fact Store]
      |
      +--达到批处理窗口/触发事件--> [构建一致 Snapshot]
                                         |
                                         v
                                  [过滤节点和边]
                                         |
                                         v
                                  [计算候选路径]
                                         |
                                         +--无可达路径--> [RouteView: NoRoute]
                                         |
                                         v
                                  [发布新 RouteView]
```

事实接收、快照构建和路径查询可以异步，但版本发布必须是原子的：查询要么看见旧的完整 RouteView，要么看见新的完整 RouteView，不应看见只有地址更新而邻接图未更新的中间状态。

### 2.3 数据流

```text
[Link Admission]
    | verified Advertisement
    v
[Fact Store]
    | latest facts by origin/version
    v
[Topology Snapshot]
    | nodes + edges + addresses + capabilities
    v
[Graph / Cost Calculator]
    | policy-filtered candidates
    v
[RouteView]
    | query result + view version + exclusion reason
    v
[Circuit Builder]
```

事实的来源是认证 Link；Routing 只拥有事实的版本化副本和派生视图。VirtualIP -> NodeID、代理 CIDR（若未来支持）和 NodeID -> Link/路径都必须带事实版本，避免旧映射在新拓扑上继续生效。当前 P1 只需要单个 VirtualIP 到 NodeID，EasyTier 的 proxy CIDR 是参考能力而非本模块必需契约。

## 3. 详细设计


### 3.1 接口和数据结构

以下为 Go 侧的接口方向，字段和并发模型仍是候选：

```go
type FactVersion struct {
    Incarnation uint64
    Sequence    uint64
}

type FactKind uint8

type Revocation struct {
    TargetOrigin  NodeID
    TargetKind    FactKind
    TargetKey     []byte
    TargetVersion FactVersion
}

type FactEnvelope struct {
    NetworkID   NetworkID
    Kind        FactKind
    Origin      NodeID
    Version     FactVersion
    IssuedAt    time.Time
    ExpiresAt   time.Time
    Revocation  *Revocation
    Signature   []byte // P1 provenance 不要求 origin signature；字段保留给未来更强隔离方案
}

type FactSource struct {
    AuthenticatedPeer NodeID
    IngressLink       LinkRef
}

type FactProvenance struct {
    Sources   []FactSource // at most 8 exact ingress sources
    Saturated bool         // local marker; true means additional sources were observed but not retained
}

type VerifiedFact struct {
    Envelope   FactEnvelope
    Provenance FactProvenance
    Payload    any
}

type NodeFact struct {
    Envelope        FactEnvelope
    NodeID          NodeID
    StaticPublicKey []byte
    Capabilities    CapabilitySet
}

type AddressFact struct {
    Envelope   FactEnvelope
    NodeID     NodeID
    VirtualIP  netip.Addr // sole P1 source for VirtualIP -> NodeID
    PrefixLen  uint8      // exactly 32 in P1
}

type LinkFact struct {
    Envelope    FactEnvelope
    LinkID      LinkID
    LinkEpoch   uint64
    LaneID      uint8
    From        NodeID // Link initiator / authoritative origin
    To          NodeID
    Cost        LinkCost
    Capabilities CapabilitySet
    ConnectionType string // confirmed transport metadata; revised wire encoding not implemented yet
}

type LinkCost struct {
    RTTMillis         uint32
    JitterMicros      uint32
    LossPPM           uint32
    QueueMicros       uint32
    ReconnectsLast5m  uint32
}

type LinkRef struct {
    ID      LinkID
    Epoch   uint64
    LaneID  uint8 // must match the path's requested PACKET or STREAM lane
    ConnectionType string // display metadata from the same authenticated LinkFact snapshot
}

type CandidatePath struct {
    Nodes       []NodeID
    Links       []LinkRef
    LaneID      uint8
    Cost        PathCost
    ViewVersion uint64
}

type InstalledPath struct {
    PathID       uint64
    Generation   uint32
    LaneID       uint8
    Candidate    CandidatePath
    PathDigest   [32]byte
}

type AddressResolution struct {
    NodeID     NodeID
    Prefix     netip.Prefix // always IPv4 /32 in P1
    FactVersion FactVersion
}

type RouteFreshness uint8

const (
    RouteViewFresh RouteFreshness = iota
    RouteViewStale
)

type PacketRoute struct {
    DestinationNode     NodeID
    Prefix              netip.Prefix // always IPv4 /32 in P1
    AddressFactVersion  FactVersion // mapping pinned by this route result
    LaneID              uint8       // always PACKET
    Candidates          []CandidatePath
    ViewVersion         uint64
    Freshness           RouteFreshness
}

type RouteView interface {
    Version() uint64
    Freshness() RouteFreshness
    ResolveVirtualIP(netip.Addr) (AddressResolution, error) // RouteConflict/RouteStale are explicit
    PacketCandidates(netip.Addr, RoutePolicy) (PacketRoute, error) // filters PACKET before the 3-path cap
    Candidates(NodeID, uint8, RoutePolicy) ([]CandidatePath, error) // explicit data LaneID
}

// FactStore accepts only VerifiedFact values produced by Link/Identity admission.
// It still validates envelope semantics, versions, expiry, and resource limits.
```

LinkFact 的 ConnectionType 与 FACT v2 实例键已有具体确认：从稳定 ConnectionInfo 取得 literal Type，并随认证 v2 通告传播；当前实现报告包含 FACT v2 codec、实例 target/FactKey/record 算术和独立固定向量。FactStore persistence v2 有局部实现/33个测试报告，但 revokedThrough 单调性待修；FACT control consumer、完整快照接入、RouteView 和全网 Type 传播仍未接通。不能把 DTO、持久化 helper 或 codec 测试当作 wire-to-route 运行链。

LinkFact 约束：`Envelope.Origin == From`，From 为该已认证可靠字节流 Link 的 initiator；每个 `(From, To, LaneID, LinkID)` 对应一个 active 物理实例。不同 LinkID 可独立并存，即使类型相同或 epoch 不同；反向图边由同一 initiator LinkFact 派生，引用同一 LinkID/LinkEpoch/Lane/Type。较高 epoch 提高 NEW-attempt floor、拒绝尚未准入的较低新尝试，不自动 drain 已经认证且健康的不同 LinkID。撤销/物理 EOF/明确失败按完整实例 key/version 排除该实例，不撤销同 Peer/Lane 的其他实例；旧业务固定 Path 的真实故障语义不因此改成无损迁移。

**FactKind 与 Payload v2 编码（已确认目标）**：`NODE=0x01`：`NodeID:16B | StaticPublicKey:32B | capability_count:u16 | (cap_len:u16|cap_utf8)*`，TargetKey=`NodeID`；`LINK=0x02`：`LinkID:u64 | LinkEpoch:u64 | LaneID:u8 | From:16B | To:16B | rtt_ms:u32 | jitter_us:u32 | loss_ppm:u32 | queue_us:u32 | reconnects_5m:u32 | capability_count:u16 | (cap_len:u16|cap_utf8)* | TypeLen:u16 | Type:TypeLen bytes`，TargetKey=`From||To||LaneID||LinkID`（41B 独立实例键）；`ADDRESS=0x03`：`NodeID:16B | VirtualIP:4B | prefix_len:u8(32) | flags:u8(0)`，TargetKey=`NodeID||VirtualIP`；`REVOCATION=0x04`：`Revoker:16B | TargetOrigin:16B | TargetKind:u8 | target_key_len:u16 | target_key | target_incarnation:u64 | target_sequence:u64 | tombstone_incarnation:u64 | tombstone_sequence:u64`，TargetKey=`Revoker||TargetOrigin||TargetKind||target_key`（最大74B）。撤销 LINK 必须含原41B实例 target 及目标版本；LINK Type 追加在既有全部字段末尾，TypeLen 按 UTF-8 字节而非字符，计入既有 PayloadLength≤4096。所有整数大端，时间是 Unix milliseconds；capabilities 仍按 UTF-8 字节序排序且不得重复；每个可变字段用 u16 长度并受既有事实/页上限约束。不得把 v2 内容放进声称 v1 的记录。


- `FactVersion.Incarnation`/`Sequence` 与每 sender `snapshot_version` 从 1 开始递增、不可回绕；计数无法安全递增时停止发布。LinkFact `LinkID`/`LinkEpoch` 必须非零、`From != To`、LaneID 只能是 CONTROL/PACKET/STREAM，`loss_ppm≤1000000`；REVOCATION 只允许撤销 NODE/LINK/ADDRESS，不撤销其他 REVOCATION。
- `NodeID` 是身份标识，不以 VirtualIP 或当前 Link 地址替代；`NodeFact.StaticPublicKey` 必须能重新计算出 NodeID 且 `Envelope.Origin == NodeFact.NodeID`；`NodeFact` 不包含地址字段，`AddressFact` 是 VirtualIP→NodeID 的唯一事实来源；
- `FactEnvelope.Revocation` 在 P1 必须为 nil；所有撤销统一使用 `Kind=REVOCATION` 的 canonical Fact，经 FACT_PAGE 同步。REVOCATION payload.Revoker 必须等于 Envelope.Origin；Envelope.Version 必须等于 `tombstone_incarnation/sequence`。目标字段为 TargetOrigin/TargetKind/TargetKey/target_incarnation/target_sequence；任何认证成员均可发起，撤销只压制目标版本及更旧版本，目标 Origin 发布更高版本可恢复；
- `FactKey` 必须由接收方按 `DeriveTargetKey(Kind, Payload)` 重新计算，并与携带的 target key 完全相等；携带 key 只作为一致性检查，不能作为信任输入；
- `FactProvenance` 最多保存 8 个 distinct `(AuthenticatedPeer, IngressLink)`；发现第 9 个来源时设置本地 `Saturated=true` 并继续原子提交完整 sender snapshot，不因单个 Fact 的来源数拒绝整页/整 snapshot。source Link 关闭时删除已记录来源；若 `Saturated=false` 且无来源才转 Withdrawn；若 saturated 且已无可精确列举来源，则保留该版本到原始 `ExpiresAt`（仅按固定 30 秒 skew 规则判断）或明确 tombstone，不延长有效期。高版本替换该 Fact 时重置饱和状态；此上限是 gossip provenance 内存约束，不是信任/签名机制。
- FACT schema v2 uses `protocol_version=2` on SUMMARY/PAGE/ACK; CAPABILITY schema v2 bit1 is `fact-sync.v2`. All peers are coordinated-upgraded and v1 is rejected before any FACT exchange; no mixed-version fallback or v1-labelled v2 records. `RevocationFlag` remains reserved0 because `FactEnvelope.Revocation` is nil; `AddressFact.prefix_len=32`, `flags=0`, other values invalid. P1 Node/LINK capability strings remain exact ASCII `packet.ipv4`, `endpoint.tcp`, `endpoint.udp`, `relay`, sorted unique; IPv6/gateway/resume/unknown capability strings remain rejected. Unknown literal ConnectionType is descriptive metadata, not one of these capability strings or a permission grant.
- `FactStore` 只接受Link/Identity admission产出的 `VerifiedFact`；Provenance由admission注入，不能从转发载荷自称得到；完整ContextID为本地分区根，FactEnvelope.NetworkID只核对预期上下文locator。Routing不拥有信任根或远端公钥验证器；
- `FactVersion` 的比较必须能区分重启世代，单调序列不能在世代回退时继续沿用；
- `ExpiresAt` 来自原始发布者，转发和重复接收不能延长它；所有时间是 Unix milliseconds。接收时要求 `IssuedAt <= now + 30s`、`ExpiresAt > IssuedAt`、`ExpiresAt-IssuedAt <=45s`，且 `now <= ExpiresAt+30s`；effective expiry 固定为原始 `ExpiresAt+30s`，重复/转发不重设计时，过期同版本不能复活。P1 provenance 由已认证 ingress Link + `StaticPublicKey -> NodeID` 绑定提供，`Signature` 不作为 P1 必填校验，保留给未来 origin-signature 扩展；FactStore 仍检查 envelope 与 payload 的语义一致性；
- `CandidatePath.Nodes` 必须包含本节点和目标节点，且不允许重复；`Links` 与相邻节点数量对应；
- `ViewVersion` 属于 CandidatePath 查询快照；`PathDigest` 只在 Path 层分配 PathID/Generation/Lane 后计算，存于 InstalledPath 并随 CircuitOpen 引用，不由 RouteView 预计算；
- `Candidates`/`PacketCandidates` 返回 `NoRoute`、`PolicyDenied`、`RouteConflict`、`RouteStale`、`ResourceLimit`、`InvalidFact`；公共 API 分别映射到 `ErrNoRoute`、`ErrPermissionDenied`、`PacketError(RouteConflict)`、`ErrRouteStale`、`ErrResource`、`ErrProtocol`。

### 3.2 状态转换

主状态对象是一个来源的事实记录集合。单条来源状态如下：

```text
[Absent]
   |
   +--首个合法版本--> [Current]
   |
   +--语义/版本/资源非法--> [Rejected]

[Current]
   |
   +--更高 incarnation--> [Current: replace]
   +--同 incarnation 更高 sequence--> [Current: replace]
   +--同版本且 canonical bytes 相同--> [Current: no-op]
    +--同版本但 canonical bytes 不同--> [Current: equivocation; 选择字节序最小事实并记录诊断]
   +--到期/撤销--> [Expired]
   +--已跟踪来源都关闭且 Saturated=false--> [Withdrawn]
    +--Link关闭且 Saturated=true--> [Current: retain until ExpiresAt/tombstone]

[Expired] --新合法世代--> [Current]
[Withdrawn] --新合法世代--> [Current]
```

状态修改者是 Fact Store 的接收/过期任务；RouteView Builder 只读取事实并发布派生版本，不直接把事实标为 Current。未经过 admission 的输入不能进入 Snapshot。`Rejected` 输入不能半写入 Snapshot。`Expired` 和 `Withdrawn` 的清理时机可以延迟，但不得继续参与新路径计算。

事实优先级规则：

- FactStore 先按已认证的完整 `ContextID` 分区，再按 `Origin + FactKind + TargetKey` 选择事实；Envelope.NetworkID仅核对该预期上下文的u64 locator，不单独建立本地状态命名空间；
- 更高 `Incarnation` 覆盖旧世代，同世代内更高 `Sequence` 覆盖旧版本；世代回退或计数无法递增时，节点拒绝以该身份发布新事实。相同 key/version 的 canonical bytes 相同则 no-op；bytes 不同视为 equivocation，所有接收方选择字典序最小的 canonical bytes 并记录诊断，使后续全量同步可收敛；该规则不提供防恶意成员伪造保证；
- `Revocation` 是带版本的 tombstone，保留 90 秒且优先于 staging 中的旧事实；快照提交前重新合并当前 tombstone/high-watermark；
- 新世代只有在本地确认旧世代撤销/过期不会被重新接受后才能恢复同一事实键。


### 3.3 关键实现机制

#### 3.3.1 事实版本与同步

每个节点维护启动世代（incarnation）并在该世代内递增 sequence；当前为进程内计数，重启从 1 开始。同步会话可维护对端已知版本摘要，优先发送增量，周期发送摘要修复丢失。会话状态丢失后允许重新请求完整快照。

接收顺序：

1. 只接收Link/Identity admission已验证的VerifiedFact，核对预期完整ContextID分区与Envelope.NetworkID locator，再校验版本、大小、kind/payload一致性及资源上限；
2. 读取该来源当前版本；
3. 旧版本丢弃；同版本 canonical bytes 完全相同是 no-op，不能延长寿命；同版本内容不同时选择字典序最小 canonical bytes 并记录 equivocation 诊断；
4. 新版本或明确 tombstone 写入 Fact Store，并使相关 Snapshot 失效；
5. 在有界批处理窗口后构建新快照；
6. 原子发布 RouteView，并通知依赖的建路任务。

**编码冻结**：手工定长二进制 + 每条消息首部版本字节，严格版本匹配——版本不匹配直接拒绝，**不做未知字段保真**。单版本交付意味着全组同一版本运行，跨版本兼容协议属于未来版本升级机制；代价是升级需协调全组，换来的是省掉 protobuf/未知字段往返保留的复杂度（EasyTier 的 route_peer_wire 保真方案是有跨版本需求才付出的代价，本项目暂不需要）。

FACT_PAGE 的 `facts` 字段是按 FactKey 原始字节严格递增排序的 `FactRecord` 字节流；每条 Record 为 `key_len:u16be | FactKey | FactEnvelope固定字段 | Payload`，其中 `FactEnvelope.PayloadLength` 只计 Payload，不含外层 FactKey。`FactKey` 必须由接收端从 Kind/Origin/Payload 重新推导并与这段携带值逐字节比较。每页最多128 records，`facts` 编码部分≤48 KiB（包含每个 key_len、FactKey、Envelope 和 Payload）；每 snapshot 最多8192 records、64页、canonical FactRecord 总字节≤3 MiB。

Control Lane 同步使用 `FACT_SUMMARY/FACT_PAGE/FACT_ACK`；事实撤销仅作为 REVOCATION Fact 包含在 FACT_PAGE，不定义独立 FACT_REVOKE 帧。Link 建立后双方分别发送摘要；页面采用 request/response 逐页传输，接收方在全部页和摘要验证通过后原子更新该 ingress 的 provenance。

`NetworkID = SHA-256("simpletier-v1" || 0x00 || name_utf8_raw || 0x00 || canonical_cidr_utf8)[0:8]`；`name_utf8_raw` 是配置 `network.name` 的原始合法 UTF-8 字节，要求非空且不含 NUL，不 trim、不做 Unicode normalization、不折叠大小写；`canonical_cidr_utf8` 必须是 `a.b.c.d/p` 的 ASCII 十进制形式，a/b/c/d 为 0..255 且无前导零（单独的 0 除外），p 为 1..32（`0.0.0.0/0` 拒绝以避免 SystemNetwork 安装默认路由），地址必须已是网络地址（host bits 非零直接拒绝）。PSK 使用同一 `name_utf8_raw` 作为 HKDF salt，`network.token` 使用配置得到的 UTF-8 原始字节，不 trim、不大小写折叠。FactEnvelope 固定字段顺序为 NetworkID:u64、Kind:u8、Origin:16B、Incarnation:u64、Sequence:u64、IssuedAt:u64、ExpiresAt:u64、RevocationFlag:u8、PayloadLength:u32；Payload 按 FactKind 固定大端字段/长度前缀编码。`VerifiedFact.Envelope` 与具体 Payload 内的 NodeID/LinkID/NetworkID 必须逐字段一致，否则 `InvalidFact`。

**Fact high-watermark**：FactStore 在进程内维护 `(ContextID, FactKey) -> max_fact_version + revoked_through`，容量 16384 条（含 live key/tombstone）；每 Network 最多 8192 live facts（NODE≤1024、LINK≤4096、ADDRESS≤1024、REVOCATION≤1024）。达到 high-watermark 容量时，先回收已过期且无有效 tombstone 的非 live key；tombstone/high-watermark 保留到 `max(target ExpiresAt + 90 秒, tombstone ExpiresAt + 90 秒)` 后才可回收。若无可回收项则拒绝新增唯一 key 并发 ResourceLimit，不降低已有高水位。LINK FactKey 按 `(From, To, LaneID, LinkID)` 区分实例；不同 LinkID 的版本/撤销各自维护，不因同 Peer/Lane 或更高 NEW-attempt epoch替换健康已建立实例。同实例仍按既定 FactVersion/物理LinkEpoch和撤销规则比较，不复活旧连接。更多唯一key消耗原live-facts/high-watermark/staging/内存配额，配额不增。

**事实键与快照提交**：收到 FACT_PAGE/REVOKE 时先与 high-watermark 比较，再进入 staging；快照提交不能降低 high-watermark，tombstone 清理只清理 payload，不清理高水位。`FactKey = Kind:u8 || Origin:16B || target_key_len:u16 || target_key`；撤销按完整 FactKey 定位，不依赖不可反查的 hash。`canonical_fact_bytes = u16be(len(FactKey)) || FactKey || Encode(FactEnvelope_without_Signature_and_Provenance) || Encode(Payload)`；Envelope/Payload 均按本节固定大端布局编码，Signature/Provenance 永不进入 digest。`page_digest = SHA-256("simpletier-fact-page-v2" || sender_incarnation:u64 || snapshot_version:u64 || page_no:u32 || fact_count:u16 || canonical_fact_bytes_sorted_by_FactKey)`；同一页重复 FactKey 直接拒绝。整体 `digest = SHA-256("simpletier-fact-snapshot-v2" || sender_incarnation:u64 || snapshot_version:u64 || page_count:u32 || page_digest[page_no=0] || ... || page_digest[page_no=page_count-1])`；空 snapshot 的 page_count=0，整体 digest 按同一公式包含 `page_count:u32=0` 且无 page_digest 项。每个 sender 的 snapshot 是该 sender 已知的完整事实集合：staging 完成后，原子替换该 ingress sender 先前贡献的 provenance 集合；每个事实保留其精确 ingress source 的至多 8 项 provenance；未饱和时来源集合空才 Withdrawn。若 Saturated=true 且已无可精确列举来源，则保留该版本至原始有效期/明示撤销，不因来源集合暂空提前 Withdrawn，也不延长寿命。staging 中的 Revocation/high-watermark 先合并，tombstone 优先。**撤销/时间**：P1 接受已认证 ingress 传入的 Revocation tombstone；tombstone 至少保留 90 秒（两个 45 秒通告有效期），旧版本不得复活；时间只用于过期判断，且以本节点收到事实的时刻为锚点计算有效期，不与发布方的绝对时间比较（内网互联时两端时钟可能相差数分钟）；启动世代必须单调递增；该计数在进程内存中，重启从 1 开始。跨分区合并先按 Origin+Kind+Key 和 Incarnation/Sequence，再按 tombstone 优先。

FACT_PAGE 的 `facts` 字段必须逐字节等于按严格 FactKey 顺序串接的 `canonical_fact_bytes`（即上述 length-prefixed FactKey + Envelope + Payload Record）；page byte limit、fact_count 和 page_digest 都按这批实际发送的 Record 字节计算。接收端要求 `page_count=0` 当且仅当 `fact_count=0`；非空 snapshot 的 `page_no` 必须覆盖 `[0,page_count-1]`、每页 record 数为 1..128，所有页 fact_count 之和等于 SUMMARY.fact_count；Record keys 在页内及整个页序列严格递增且全局唯一，facts 字节≤48KiB/page、总 canonical bytes≤3MiB/snapshot，page_count≤64、records≤8192。任何计数/顺序/重复/边界不符均拒绝整个 staging snapshot，不部分提交。

**邻接声明冻结**：每条已认证双向 Link 由 initiator 发布一条 LinkFact，RouteView 从该事实派生两向图边；不要求 responder 再发布匹配 LinkFact，但两向边都必须引用同一 LinkID/LinkEpoch/Lane。没有已认证 LinkFact 的方向不进入图；环路安全由路径节点唯一 + OverlayHopLimit 保证。

### 3.3.2 图构建与路径选择

图构建只加入：

- 版本有效且身份可验证的 NodeID；
- 每个已认证 LinkFact 产生两向邻接边；两向边共享 LinkID/LinkEpoch/Lane，连接失效时同时从候选路径排除；
- 未过期、未撤销且满足中继/访问策略的 Link；
- 每个边引用包含不可复用的 LinkEpoch；底层连接重建必须生成新 epoch，旧 Circuit 不能借同一 LinkID 复活。

路径计算顺序：

1. 根据目标地址映射得到 NodeID；
2. 先过滤到请求的 PACKET 或 STREAM Lane，并确认每条相邻边存在可用 CONTROL Link 承载 PATH/SESSION bootstrap；然后过滤不可达、策略禁止、能力不匹配、重复节点、超过 hop limit 或预算的候选；
3. 按 RoutePolicy 计算非负成本；
4. 保留有限数量的候选主/备路径；
5. 用稳定的 NodeID/LinkID 排序作为相同成本的决胜；
6. 返回带 `ViewVersion` 的结果。

**路径与健康冻结**：每个目标和请求的数据 Lane 最多 3 条候选路径、最大 16 跳；相同成本按 NodeID/LinkID 稳定排序。健康只用**本地测量**（不做 PeerCenter 式跨节点汇总）。以下为 P1 硬初值；实现可下调，提升需规格修订和基准证据：

| 项目 | 建议初值 |
|---|---|
| 链路探测周期 | 2 秒 + 随机抖动 |
| Link 判死 | 连续 5 次无响应，或硬读写错误立即 |
| 通告刷新 / 有效期 | 15 秒 / 45 秒 |
| 普通指标发布 | 最多 5 秒一次，变化不足不发布 |
| 性能切路 | 成本改善 ≥20%，连续 3 窗口；30 秒冷却；硬故障不受冷却 |

成本公式沿用 v0.2 初值（1 + rtt/50ms + 0.5×jitter/20ms + 3×探测超时率/0.05 + 排队/20ms + 0.5×近 5 分钟重连数）。`rtt_ms/jitter_us/loss_ppm/queue_us/reconnects_5m` 由 LinkFact Origin 的 Link manager 本地观测并随该 LinkFact 发布；reconnects_5m 统计该 Peer/Lane 滚动 5 分钟内因硬失败而重新拨号的次数，排除首次建链和有意 drain/shutdown。每个 router 使用当前版本化 Origin 指标计算其本地路径成本，不运行中心聚合或重写对端事实。

RouteView 只返回候选节点/Link 路径和版本；Path 层在建路时生成 `PathID`，以当前 Generation 安装每跳转发表，返回 PATH_READY 后才允许 PacketRoute/新 Circuit 使用。PathID/Generation 不由 RouteView 查询结果直接伪造，也不在每个数据包上重新生成。

#### 3.3.3 EasyTier 参考的采用边界

`easytier-core/src/peers/route/peer_ospf_route.rs` 的观察：

- `OspfRouteSnapshot` 将 `peer_infos`、`conn_map`、被抑制 Peer 和 `version` 作为计算输入；
- `build_peer_graph_from_snapshot` 从节点和 connected peers 构建有向图；
- `build_from_snapshot` 可以按 `LeastHop` 或 `LeastCost` 重建下一跳，并同时构建 VirtualIP/CIDR 到 Peer 的映射；
- 过期/不可达节点会从下一跳、Peer 信息和 IP 映射中清理；
- `SyncRouteInfo` 以会话已知版本为依据发送数据，收到后再本地重建路由；
- `PeerCenter` 单独汇总直连延迟，不等于唯一的全网下一跳控制器；
- `PeerOutboundPacketRouter`/`RelayPeerMap` 以最终目标 PeerID 发送，逐跳查询本地 gateway。

对 SimpleTier 的建议：采用“传播基础事实、节点本地计算”的部分；第一阶段不复制 OSPF 名称、三层 IP 数据面或 PeerCenter 角色。已确认默认数据面使用固定 TCP Circuit，因此本模块为 Circuit 提供带 ViewVersion/PathDigest/LinkEpoch 的候选路径；EasyTier 的最终目标逐跳语义不进入 P1 TCP 流契约。

#### 3.3.4 健康和拓扑边

健康测量应区分：

- Link 是否仍可读写；
- 探测 RTT/抖动和超时趋势；
- 排队等待是否来自慢消费者；
- 业务目标拒绝是否只是 Endpoint 问题。

硬故障可以立即使边不可用于新建路；性能变差应使用平滑值、迟滞和冷却，不因单次探测切路。健康结果只能修改本地候选成本/可用性，不能未经版本化就改写对端发布的事实。

当前实现：`LinkCost.RTTMillis` 与 `JitterMicros` 由本 Link 自己的 PING/PONG 往返测得（复用准入探测所用的同一机制，`ProbeID` 关联），在 CONTROL lane 上每 3 秒一次——该 lane 有保留队列，探测不会排在业务数据之后。估计器采用与 TCP 同形的平滑均值加平均偏差，单次抖动只微调。尚未测得往返的 Link 报告 0，成本模型按"未测量"处理而非"零延迟"。

#### 3.3.5 并发、清理和失败恢复

- Fact Store 写入与 Snapshot 发布之间必须有明确一致性边界；
- 查询不能持有全局写锁等待网络 I/O；
- 过期任务、同步任务、重建任务和关闭流程都必须可取消；
- 版本缓存和待同步队列到达上限时使用可诊断的拒绝/淘汰策略；
- Link 关闭后，相关事实可先标记不可用再异步清理，但不能被新 Circuit 选中；
- RouteView 重建失败时保留上一个完整视图并标记 `Stale`（**可用性优先，只服务未受影响的新流）。每次查询仍检查当前 FactStore 的 high-watermark/tombstone、有效期、AddressFact 唯一性和 LinkEpoch/active 状态；更高版本、撤销、过期、地址冲突或 Link 关闭会立即写入 invalidation set，旧视图不得返回对应候选。stale 但未被 invalidated 的结果带 `Freshness=RouteViewStale`；受影响地址返回 `RouteStale`/`RouteConflict`，不回落到旧 NodeID。观测必须暴露 stale 及失效原因。

#### 3.3.6 地址分配与冲突收敛

P1 每个 NodeID 只拥有一个 IPv4 VirtualIP/32；AddressFact 是唯一地址事实来源。确定性初始候选使用：`digest = SHA-256("simpletier-v1/address" || NodeID:16B || attempt:u32be)`，`index = uint64be(digest[0:8]) mod usable_host_count`。对 CIDR `/1` 至 `/30`，可用地址从 network+1 到 broadcast-1；`/31` 两个地址都可用；`/32` 唯一地址可分配给至多一个节点。地址由 network+1+index（/31、/32 使用 network+index）计算，attempt 从 0 开始且为 u32；溢出或无剩余 host 时 `AddressPoolExhausted`。同一进程存活期内优先复用上次分配的 `(VirtualIP, attempt)`；跨进程重启无历史记录；自动冲突时 NodeID 小者保留，其他节点从其已存 attempt+1 递增重派。

1. 发布独立 AddressFact，`Envelope.Origin == payload.NodeID`；NodeFact 不携带 VirtualIP。AddressFact 的 key 为 `(NetworkID, Origin, ADDRESS, NodeID, VirtualIP)`，P1 `prefix_len=32`、`flags=0`；改址时撤销旧 key 并发布新 key。
2. 同一 VirtualIP 若有两个仍有效的不同 owner，RouteView 标记该地址 `Conflict`，所有新 PacketRoute 查询返回 `RouteConflict` 并丢弃/计数，不能按到达顺序选人。低 NodeID 胜出只决定 allocator 哪个节点保留该地址；只有冲突声明被撤销/过期且唯一新 AddressFact 原子提交后才重新路由。
3. 显式 `options.fixed_ip` 必须是 CIDR 内可用的 IPv4 host address，且 P1 仍表示单个 `/32`；与任何另一 live owner 冲突时该固定地址节点启动失败，不静默改址。
4. 地址映射变化只影响未来查找，旧 Circuit 已按 NodeID 绑定，不改投。分区合并使用相同 NodeID 决胜；重复/过期的 AddressFact 不续命。

代价：地址分区合并可能导致冲突期间该 VirtualIP 暂时不可路由，VirtualIP 不是永久身份。P1 不实现租约/DHCP/ARP，也不发布用户 LAN 或其他任意前缀；每节点仅有自己的 VirtualIP/32。

### 3.4 可自主部分与待决事项

实现者可以自主选择图算法库、快照不可变表示、读写锁/原子指针、增量重建与全量重建的内部组织，只要满足该区间。

 已于本修订冻结（见 3.3）。剩余非本模块项：性能数值目标待基准测试；按节点撤销/平滑轮换延期（见 [安全握手与密钥](security.md)）；不授权扩展到代理 CIDR、跨网络身份或三层路由。

## 4. 实现状态

事实存储、增量同步与 RouteView 已实现，入口 `internal/topology/fact_store.go`
与 `route_view.go`。端到端行为由 `tests/network_runtime/` 覆盖。


## 5. 偏差、未知和继续入口

- 现有 `docs/references/easytier-routing-logic.md` 解释的是 EasyTier IP 数据包的最终目标逐跳路由；本模块同时定义 TCP Circuit 候选和 L3 PacketRoute/Prefix 查询，但两种数据路径的生命周期、失败和资源语义不能直接合并。
- EasyTier 目前使用的 `RoutePeerInfo`、protobuf 未知字段保留、PeerCenter 延迟汇总、PeerSession 和 relay handshake 都是参考实现事实；SimpleTier 尚未选择相同编码、加密会话或中心延迟服务。
- 本模块没有实现入口和测试基线；任何“可达/低延迟/故障恢复”的结论目前都只能写成设计目标。
- 下一步优先处理 至 中影响 wire contract 和故障语义的项，再拆出协议/存储模块；不要先写一个只返回下一跳的浅层 wrapper，绕过版本和一致性契约。
