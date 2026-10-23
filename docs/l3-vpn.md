# L3 覆盖 VPN


## 摘要

本功能定义 SimpleTier 产品级 P1 的 L3 packet plane 和系统接入边界。用户已确认需要：

- Linux TUN；
- Windows Wintun；
- macOS utun；
- IP 包中承载 TCP、UDP 和 ICMP。

Host Adapter 拥有操作系统设备、地址/路由、权限和关闭生命周期；可移植核心负责 IP 包解析、目标节点解析、拓扑路由、封装、转发、反压和安全策略。TCP SDK 的 `Dial/Listen` 和固定 Stream Circuit 由 [TCP 覆盖网络](tcp-overlay-network.md) 负责，不与本功能的包转发状态混合。完整的 Packet/Flow/Proxy 组合、三平台后端和阶段路线见 [多协议覆盖网络](multiprotocol-overlay.md)。

本功能是 proposed 设计；当前没有 Packet Plane、SystemNetwork 或平台 Host Adapter 实现/验证。仓库已有 Go module 和 Wire framing 单元切片，但没有 L3 转发或平台接线。用户确认的是 IPv4-only、TCP/UDP/ICMP 和三平台 Host Adapter；不实现 IPv6/ICMPv6，不做子网代理。虚拟设备 MTU 使用内部默认 1380（对齐 EasyTier 默认值），不开放用户配置；外层帧与加密契约见 [线上帧协议与链路安全](internals/wire.md)。

## 1. 需求说明


### 1.1 使用者、目标与范围

参与方：

- **普通宿主机应用**：通过操作系统路由把 IP 包送入虚拟设备，不需要修改应用代码；
- **Host Adapter**：在 Linux、Windows、macOS 上创建/打开虚拟设备，配置必要地址和路由，并把完整 IP 包交给核心；
- **Packet Plane**：根据虚拟地址/前缀找到目标 NodeID，沿覆盖网络转发 IP 包；
- **远端 Host Adapter**：把解封装后的 IP 包写回目标系统网络栈；
- **控制面**：传播节点、地址、前缀、邻接和能力事实，但不解析 TCP/UDP/ICMP 应用语义。

本功能目标是让未修改的系统应用可以通过虚拟网络访问其他节点的 TCP、UDP 和 ICMP 目标。L3 packet plane 必须保留 IP 包边界和 L4 协议语义，不能把 UDP/ICMP 伪装成面向连接的 `net.Conn`。

本功能目前不自动承诺：

- 广播/组播、ARP/NDP 代理；
- 远端物理子网代理、NAT 出口、互联网网关；
- 所有系统发行版、Windows 驱动安装方式、macOS entitlement 或移动平台；
- 任何固定吞吐、故障恢复时延或资源预算（MTU 默认值已定 1380；性能数值待基准测试）。

### 三平台 Host Adapter

P1 必须提供三个明确的 Host Adapter 边界：Linux TUN、Windows Wintun、macOS utun。每个 Adapter 能创建/打开设备、读取完整 IP 包、写回 IP 包、报告 MTU/接口状态并可取消关闭。缺少权限、驱动、entitlement 或设备资源时必须返回可诊断错误，不能静默退化为普通 TCP SDK。

### TCP、UDP、ICMP 包承载

Packet Plane 必须能够转发 IP 包中承载的 TCP、UDP 和 ICMP。TCP 在远端由操作系统 TCP 栈继续处理；UDP 保留独立数据报边界，不由路由层重试或重放；ICMP echo 和相关错误包按 IP 包转发，不由核心伪造为应用层 ping 结果。

### 虚拟地址到目标节点

每个节点只声明并拥有自己的 VirtualIP/32；P1 不发布任意 Prefix/子网代理。RouteView 按目标 IPv4 地址解析唯一 NodeID 并返回 AddressFactVersion；一次 packet attempt 固定到该 NodeID/版本。Path activation/packet egress 前若当前 owner 已变更，返回 `RouteStale` 并丢弃，不重定向到新 NodeID；若变化发生在 packet 已发往旧 NodeID 后，目标在 HostAdapter 写入前再校验本地 current VirtualIP/32 所有权并丢弃旧目的地址包。存在两个仍有效 owner 声明的地址在冲突解决前不可路由：丢弃该地址的包并记录 `RouteConflict`；低 NodeID 保留地址、其他节点重派或固定地址启动失败后，只有冲突消除且新 AddressFact 提交后才恢复路由。

### 多跳包转发和环路保护

包可以经过多个已认证节点到达目标。每一跳必须验证覆盖网络头、目标、同一 PACKET Lane 的 Link/Path 状态、OverlayHopLimit 和剩余资源；Overlay relay 只递减覆盖网络 hop limit，不改写完整 IP_PACKET 内的 IPv4 TTL/头/载荷。失败时丢弃并返回控制面诊断，不把 TCP Stream 的 FIN/RESET/Deadline 语义套到 IP 包上。

### Host 生命周期和系统副作用边界

Host Adapter 的启动、配置、运行、停止和异常清理必须是可观察状态机。Go 核心不得直接打开 `/dev/net/tun`、调用 Wintun/utun API 或修改系统路由；这些动作由平台适配层完成。SystemNetwork 每项系统变更都必须先持久化操作意图/资源指纹，再执行并记录结果；重启只清理仍与本实例指纹完全匹配且此前不存在的资源，外部修改必须保留并进入诊断状态。`packet.ipv4` 只在 PacketDevice 配置完成且读写循环可用后发布，运行中设备不可用时撤销能力并使相关路径失效。Go SDK 默认仍不创建系统设备。

### 安全、反压和资源上限

节点必须校验包来源身份及其 VirtualIP/32 所有权、目标 VirtualIP/32 是否存在唯一 AddressFact、包长度、hop limit、协议能力和资源配额。P1 不接受任意前缀发布或端口 ACL。认证前连接、每设备包队列、每 Peer 包速率、每流/每 Link/全局缓冲和控制帧预算必须有上限。慢端或超限时需要明确丢弃、拒绝或关闭策略，不能无限缓存 IP 包。

### 1.3 其他业务规则与质量约束

- **包和流分离**：L3 包可以携带 TCP，但 Packet Plane 不拥有 TCP 连接状态；TCP SDK 的 Stream 也不能承载任意 L3 包并宣称透明 VPN。
- **来源地址防伪**：节点只能发送自己拥有的 VirtualIP/32；P1 不接受任意源 Prefix；中继不能仅凭外层转发字段相信源地址。
- **TTL/Loop 语义**：包的 IP TTL 和覆盖网络 hop limit 都必须受限；包转发不能因为重试而恢复已消耗的 hop 预算。
- **UDP 失败语义**：UDP 包不因丢包、路径切换或响应缺失而自动重放；需要重试由应用负责。
- **ICMP 失败语义（P1 冻结）**：已存在的 ICMP echo/unreachable/time-exceeded 作为普通 IPv4 包转发；Packet Plane 不合成虚假 Echo Reply 或新的 ICMP 错误。覆盖 hop limit、无路由、策略拒绝和超限只丢弃并计数，端点操作系统负责其本地 PMTU/ICMP 生成；
- **MTU 边界（P1 冻结）**：虚拟设备默认 MTU 为 1380，用户配置不包含 MTU 字段；平台/路径不能承载时 SystemNetwork 可在运行时内部下调并产生事件，不能由用户覆盖。超过当前虚拟 MTU 的读入包判 `PacketTooLarge`、丢弃并计数，隧道层不分片、不重组；
- **系统路由边界**：Agent 可以安装自身虚拟网段所需的系统路由；路由变化必须可回滚，不覆盖用户明确配置的冲突路由。


以下场景是拟定验收，当前尚未执行：

| 场景 | 输入/前提 | 期望结果 | 关联 |
|---|---|---|---|
| Linux TUN 创建 | 具备/不具备 TUN 权限 | 成功时设备可读写 IP 包；失败时返回权限/设备错误并清理部分资源 | R-L3-001 |
| Windows Wintun 创建 | 驱动可用/不可用、管理员权限变化 | 成功时创建和关闭适配器；失败不伪装为 TCP SDK 正常运行 | R-L3-001 |
| macOS utun 创建 | entitlement/权限和系统路由条件不同 | 成功时包能进出 utun；关闭后地址/路由可回滚 | R-L3-001, R-L3-005 |
| TCP IP 包多跳 | 系统应用通过虚拟网段访问远端 TCP 服务 | TCP 三次握手和数据包经覆盖网络到达，核心不终止 TCP | R-L3-002, R-L3-004 |
| UDP 数据报 | 应用发送多个独立 UDP 包 | 每个包保留边界和目标端口；不因结果未知自动重放 | R-L3-002 |
| ICMP echo/error | 系统发送 ICMP echo 或收到路径错误 | 包按允许策略转发；失败行为和 TTL 超限可诊断 | R-L3-002, R-L3-004 |
| 无路由/地址冲突 | 目标地址没有唯一 RouteView owner，或有两个仍有效的 AddressFact | 包有限丢弃并记录 `NoRoute`/`RouteConflict`；冲突消除并原子提交唯一地址映射后才恢复路由 | R-L3-003 |
| 环路/TTL | 拓扑暂时环路或 hop limit 耗尽 | 包被丢弃或生成已定义错误，不增加覆盖预算 | R-L3-004 |
| 慢端/队列超限 | 接收设备不读、持续大包进入 | 反压或按策略丢弃/拒绝，控制面仍可工作 | R-L3-006 |
| AddressFact invalidation during PacketPath | Route lookup pinned to owner A, then its AddressFact is revoked/reassigned before target write | in-flight packet is never retargeted to B; A's final `/32` owner check drops it, and subsequent packets use the refreshed unique RouteView | R-L3-003, R-L3-004 |
| PacketDevice readiness | Agent 启动设备并配置系统路由后 | `packet.ipv4` 仅在 PacketDevice 读写循环可用后发布；运行中设备错误时撤销能力并使相关路径失效 | R-L3-001, R-L3-005 |
| IPv4 TTL 与分片 | 多跳转发普通 IPv4 包、合法分片和畸形头 | 中继只递减 OverlayHopLimit，原始 IPv4 TTL/header/payload 不变；不隧道重组；畸形包有限丢弃 | R-L3-002, R-L3-004 |
| SystemNetwork 崩溃恢复 | 在每个平台的设备/地址/MTU/路由应用步骤后注入崩溃并重启；同时模拟外部修改资源 | 只清理 journal 中能证明由本实例创建且指纹未变的资源；保留预先存在/外部修改的资源，不能留下可归属的孤儿。**注：journal 当前只在进程内存中，因此本场景的「崩溃后重启」分支尚不可验收** | R-L3-005 |
| 三平台关闭 | Agent 正常关闭或中途失败 | 设备、地址、系统路由、后台任务和队列都清理 | R-L3-001, R-L3-005 |

## 2. 概要设计


### 2.1 职责、边界和协作

Host Adapter 只处理平台资源，不理解覆盖网络路由；Packet Plane 只处理 IP 包和包级转发，不调用 OS API；Topology/Routing 提供目标地址/前缀到 NodeID 和候选路径；Carrier/Link 提供包帧或可靠双向通道；TCP SDK 的 Endpoint/Circuit 保持独立。

```text
[Linux TUN / Windows Wintun / macOS utun]
                    |
                    | complete IP packet
                    v
              [Packet Plane]
                    |
          destination IP/prefix lookup
                    v
              [RouteView]
                    |
          target NodeID + packet path
                    v
          [Packet Carrier / Relay]
                    |
                    v
              [Remote Packet Plane]
                    |
                    v
            [Remote Host Adapter]
```

Host Adapter 和 Packet Plane 之间的接口是完整 IP 包；Packet Plane 和覆盖网络之间的接口是带目标 NodeID、包路径/下一跳、hop limit 和版本摘要的包帧。任何一层都不能把 UDP/ICMP 包拆成 TCP SDK 的 Stream 操作。

### 2.2 端到端处理流程

```text
[Agent 启动]
   |
   +--平台/权限/驱动失败--> [返回 HostError 并清理]
   |
   v
[创建 Host Adapter]
   |
   v
[配置虚拟地址、MTU 和系统路由]
   |
   +--路由冲突--> [返回 RouteConflict]
   |
   v
[启动 PacketDevice 读写循环]
   |
   v
[解析 IP 包并做来源/长度/协议检查]
   |
   +--非法/未授权--> [Drop + PacketError]
   |
   v
[RouteView 查询目标 NodeID/Prefix]
   |
   +--无路由/策略拒绝--> [Drop + NoRoute/PermissionDenied]
   |
   v
[封装包帧并转发]
   |
   +--路径/资源失败--> [有限候选尝试或 Drop]
   |
   v
[远端解封装并写入 Host Adapter]
```

启动和关闭是 Agent 生命周期；单个 IP 包不需要等待 TCP SDK 的 Endpoint/READY。Packet Plane 的转发成功只代表包交付给下一处理边界，不代表 TCP/UDP/ICMP 上层业务已经成功。

### 2.3 数据流与归属

```text
[OS packet stack]
       |
       v
[Host Adapter PacketDevice]
       | raw IPv4 packet
       v
[Packet Classifier]
       | source/destination/protocol/length
       v
[Packet RouteView]
       | target NodeID + path/policy
       v
[Packet Envelope]
       | authenticated packet frame
       v
[Link / Relay]
       |
       v
[Remote Packet Plane]
       | decapsulated IP packet
       v
[Remote Host Adapter]
       |
       v
[Remote OS packet stack]
```

Host Adapter 拥有设备句柄、系统路由和平台状态；Packet Plane 拥有包解析、封装、转发、丢弃和资源计量；RouteView 拥有唯一 VirtualIP/32 到 NodeID 的派生映射；Link/Carrier 拥有物理连接和包帧通道。Packet Plane 不写 TCP SDK 的 Circuit 状态。

## 3. 详细设计


### 3.1 接口与数据契约

以下接口是跨平台边界草案，不代表具体 Go 包已经存在：

```go
// The L3 Packet Plane consumes the canonical PacketDevice interface from Multi §3.2.
// Host resource operations use the HostResource port owned by Architecture; this feature
// does not define a second PacketDevice/HostAdapter port.
type PacketEnvelope struct {
    NetworkID        NetworkID
    SourceNode       NodeID
    DestinationNode  NodeID
    MessageType      MessageType // 固定为 IP_PACKET
    SessionID        [16]byte
    KeyEpoch         uint32
    PathID           uint64
    PathGeneration   uint32
    OverlayHopLimit  uint8
    MessageNumber     uint64 // assigned by the Wire Session egress serializer after scheduling
    Payload          []byte
}
```

契约候选：

- `ReadPacket`/`WritePacket` 每次处理一个完整 IP 包，不把一次读写等同于 TCP/UDP 应用消息；
- `PacketEnvelope` 的线上字段映射以 [线上帧协议](internals/wire.md) 为准：NetworkID、Source/DestinationNode、MessageType=IP_PACKET、SessionID、KeyEpoch、PathID、PathGeneration、MessageNumber 和 payload 进入对应端到端/逐跳保护；OverlayHopLimit/cursor/剩余预算仅逐跳保护。`RouteViewVersion`、`PathDigest` 只留在本地 RouteView/Path 诊断，不另造未定义 wire 字段；
- `PacketID` 用于诊断、限流和重复检测，不代表允许自动重放 UDP/ICMP；
- `SourceNode` 必须与源地址等于该节点拥有的 VirtualIP/32 匹配，不能由中继任意改写；
- `DestinationNode` 由本地 RouteView 根据目标 IPv4 VirtualIP/32 得到，包帧不依赖 TCP SDK 的远端端口；
- Host Adapter 返回的平台错误、权限错误、路由冲突和设备关闭必须可区分。

### 3.2 平台适配边界

| 平台 | 适配器 | 平台拥有的资源 | 需验证的行为 |
|---|---|---|---|
| Linux | TUN | `/dev/net/tun`、接口地址、系统路由、权限 | 多队列/单队列、MTU、关闭清理、路由冲突 |
| Windows | Wintun | Wintun 驱动/适配器、接口地址、路由、权限 | 驱动可用性、安装/加载边界、读写线程、关闭句柄 |
| macOS | utun | utun socket、接口地址、路由、entitlement | socket 创建、接口索引、路由回滚、权限/签名 |

核心只依赖 `PacketDevice` 和 `HostAdapter`；不能在核心中分支调用 `/dev/net/tun`、Wintun 或 utun。平台适配器不可用时，仍可以启动无 TUN 的 TCP SDK，但不能宣称 L3 Agent 可用。

### 3.3 IP 协议语义

#### TCP

Packet Plane 只转发 IP/TCP 包，端点 TCP 状态机由两侧操作系统维护。核心不解析 TCP 请求、不执行应用重试，也不把 IP/TCP 包映射成 TCP SDK 的 `Stream`。系统 TCP 连接的路径故障表现为包丢失、超时或连接关闭，不能使用 TCP SDK 的 READY/FIN/RESET 语义替代。

#### UDP

每个 UDP 包独立封装、转发和计量，保留源/目的地址与端口。路由层不因为没有响应而重发，也不为 UDP 建立具有业务语义的长期 Stream。若底层 Carrier 为可靠 TCP framing，队头阻塞和延迟影响必须显式记录，不能宣称等价于原生 UDP 传输。

#### ICMP

ICMP echo、destination unreachable、time exceeded 等均作为 IP 包处理。核心不代替操作系统生成新的 ICMP 错误；覆盖 TTL/hop limit 耗尽、无路由、策略拒绝和超限统一丢弃并计数；本版本不实现 IPv6/ICMPv6（已确认）。

### 3.4 包状态和生命周期

Host Adapter 的主状态：

```text
[Created]
    |
    +--权限/设备失败--> [Error]
    |
    v
[Configured]
    |
    +--路由/地址冲突--> [Error]
    |
    v
[Running]
    |
    +--读到 IP 包--> [Classifying]
    |                    |
    |                    +--非法/未授权--> [Dropped]
    |                    |
    |                    v
    |                [Forwarding]
    |                    |
    |                    +--成功--> [Delivered]
    |                    +--无路由/超限--> [Dropped]
    |
    +--关闭/设备断开--> [Stopping] --> [Closed]
```

设备状态由 Host Adapter 修改；包状态由 Packet Plane 修改。`Dropped` 是单包终态，不应让整个 Link 或 Agent 进入失败，除非达到资源/安全策略定义的阈值。`Stopping` 后不能再向设备写入新包，也不能留下系统路由和后台读写任务。

### 3.5 包路由、封装和环路保护

1. 从完整 IP 包解析目标地址、源地址、协议和长度；
2. 校验源地址恰等于本节点已确认的 VirtualIP/32，校验完整 IPv4 包长度和协议能力；
3. 使用当前 RouteView 将目标 IPv4 映射到唯一 AddressFact/NodeID，并携带该 `AddressFactVersion`；冲突返回 `RouteConflict` 丢弃；
4. 过滤策略禁止、过期、不可达、能力不足和超出 hop/资源预算的路径；
5. 若已有 active Packet Path/Session 则复用；否则通过 PATH_OPEN/READY 安装或切换 PathID/PathGeneration，在新 Path 上发送新的 `SESSION_CTRL(PACKET)` 完成已由 批准的 Noise/PSK Session handshake（Schema 与 KDF 域见 [线上帧协议](internals/wire.md) 与 [安全握手与密钥](internals/security.md) 3.5.3；跨实现互操作仍待验证），再发送 `SESSION_READY` 提交 ReadyPending；
6. 生成逻辑 `PacketEnvelope`，绑定已安装 PathID/PathGeneration 和完整 IP 包；Packet Plane 不分配 nonce/counter。Wire Session egress scheduler 决定 wire order 后填写 KeyEpoch/MessageNumber 并执行 E2E AEAD，Link writer 再填写逐跳计数和路由字段；
7. 通过 Packet Carrier/Relay 转发；中继只处理覆盖头，不解析 TCP/UDP/ICMP 载荷；
8. 目标节点验证 envelope、目标 NodeID、路径/Link 状态、源地址授权及内层 destination IPv4 仍等于本节点唯一 current VirtualIP/32；不再拥有该地址时不注入 Host Adapter，丢弃并计数。

IP TTL/Hop Limit 与覆盖 hop limit 是不同约束：Overlay relay 保留完整 IPv4 TTL/header/payload，仅每跳递减 OverlayHopLimit；任一覆盖预算耗尽都不能通过重试恢复。包路径采用源端无重复节点路径：`PATH_OPEN/READY -> SESSION_CTRL(PACKET) -> selected Session handshake -> SESSION_READY`；因控制与数据 TCP Links 独立，ReadyPending 时早到 Packet frame 按[多协议路径状态](multiprotocol-overlay.md)有界暂存，提交后才写 Host Adapter。PathID/Generation 固定每跳转发；路径故障后新消息可改走备用 Path 并新建 Session；中继不改下一跳，保护关系见[线上帧协议](internals/wire.md)。

### 3.6 安全与资源治理

- Host Adapter 设备和系统路由操作必须受权限边界保护，配置错误不能降级为不安全的宿主机全局路由；
- Packet Plane 必须进行源地址防伪、目标前缀授权、NetworkID/NodeID 认证、包长度和 hop limit 校验；
- 包帧认证必须覆盖 payload，不能只认证外层目标；防重放窗口 1024 位已由线上帧协议冻结，结构/重放错误在端到端认证前只隔离 ingress，不关闭受害 Session；阈值数值待压测；
- 每个 Host Adapter 的包队列≤1024包/2MiB；每 Peer Packet rate≤10000pps、burst 2000；Packet Carrier/Path 与全局帧内存受多协议 3.8 的 P1 硬上限约束；
- 控制面握手、拓扑和 teardown 保留每 Link 64 帧/256KiB，不能被大批 UDP/ICMP/TCP 包占满；
- 超限行为必须是明确的丢弃、拒绝、限速或关闭，不能使用无限队列。

### 3.7 实现自由和待决问题

局部平台调用封装、线程/任务组织、缓冲池实现和日志字段可以自主选择，但不得改变 Host Adapter/Core 归属和包边界。以下事项仍需协议/平台评审：

- **D-L3-002：已确认 IPv4-only。** 不实现 IPv6/ICMPv6；扩展头和 IPv6 相关逻辑不进入当前范围。
- **D-L3-003：已冻结。** 外层载体只有加密 TCP framing；包路径采用 PathID/Generation 固定转发（见 [线上帧协议](internals/wire.md)）。
- **D-L3-004：已冻结。** 虚拟 MTU 默认 1380 且不可配置；Host Adapter/SystemNetwork 负责设置和内部下调；隧道层不分片/重组，超过当前 MTU 的读入包 `PacketTooLarge` 丢弃计数；已有 ICMP 错误透传，Packet Plane 不合成新的 ICMP 错误。
- **D-L3-005：已确认不做子网代理。** 广播/组播、ARP/NDP 和 NAT 出口明确不属于本版本；如未来需要另行设计。
- **D-L3-006：范围已确认。** 三平台 SystemNetwork 全部事务属于本版本交付：地址/路由安装与回滚、驱动/权限/entitlement、崩溃重启、睡眠唤醒、网络切换和 underlay 绕行；具体每平台 API 与回滚语义是实现设计细节。
- **D-L3-007：已冻结。** P1 成员默认同网允许 + 源地址防伪，资源初值和观测字段见多协议 3.8；性能数值待基准。
- **代理认证：已确认。** SOCKS5/HTTP Proxy 都强制 Basic 认证，详见 [多协议覆盖网络](multiprotocol-overlay.md)。
- **平台测试主机（人工回答）：** 用户明确回答“当前没有这两类测试主机”。因此 Windows/macOS 的驱动/entitlement 与 native SystemNetwork 只算编译期代码，在真实主机上未验证；Linux TUN 的真实设备 runtime/事务/取消/恢复已通过验收。`internal/host`、`internal/sysnet` 目录不存在；设备/系统网络实际位于 `internal/agent/**`，由 FEAT-MULTIPROTOCOL-OVERLAY primary 拥有，本 feature 只引用该实现位置，不建立第二 primary Owns。

## 4. 实现状态

| 能力 | 状态 | 入口 |
|---|---|---|
| Linux TUN 设备与系统路由 | 已通过真实设备验收 | `internal/agent/device_linux.go` |
| Wintun（Windows）| 仅交叉编译 | `internal/agent/device_windows.go` |
| utun（macOS）| 仅交叉编译 | `internal/agent/device_darwin.go` |
| SystemNetwork 事务 | 已实现，journal 在内存 | `internal/agent` |
| L3 packet 转发 | 已实现 | `internal/packet` |

真实 TUN 验收在 `tests/tun_acceptance/`。崩溃后重启的资源恢复依赖 journal 持久化，
而 journal 当前只在内存中，因此该分支尚不可验收。


## 5. 偏差、未知和继续入口

- L3 packet plane 属于完整产品 P1 范围，超出 [TCP 虚拟覆盖网络](tcp-overlay-network.md) 的子功能边界。
- EasyTier 的 TUN、packet plane、host/core 分层是参考观察；其具体路由、协议载体、加密和平台实现不能直接视为 SimpleTier 契约。
- 三种平台与 TCP/UDP/ICMP 包承载已确认；平台调用与性能基准见 [benchmarks/](benchmarks/)。
- Linux TUN 已通过真实设备验收（`tests/tun_acceptance/`）；Windows Wintun 与 macOS utun 尚无真实主机运行验证。广播/组播、子网代理和 NAT 不在本版本范围。
