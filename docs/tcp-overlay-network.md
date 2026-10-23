# TCP 虚拟覆盖网络


## 摘要

本功能整理一个可嵌入 Go 应用的 TCP 覆盖网络：节点通过少量监听地址和上游地址加入同一逻辑网络，系统为节点分配 NodeID 和尽量稳定的 VirtualIP，传播拓扑事实并为新业务流选择路径。应用使用虚拟 IP + 端口调用 `DialContext` 或 `Listen`，不需要知道中继节点和具体载体。

这是对 `docs/references/TCP虚拟组网设计方案_v0.1.md` 的结构化候选设计，不是已批准的生产协议。父目录 `/usr/local/src/project/easytier` 只作为参考实现和设计资料来源；EasyTier 中的三层 TUN 数据面、UDP/QUIC/WireGuard、NAT 穿透和子网代理不自动进入本 TCP 子功能范围。完整产品的 L3 数据面由 [L3 VPN](l3-vpn.md) 单独定义。

当前实码已有typed SDK/context/PSK、每 Network 独立 IdentityStore（进程内存）、TCP/WS/WSS Connector、provisional地址、CONTROL Noise/Capability admission、epoch门禁与owned Link生命周期；CAPABILITY/FACT v2 codec与strict-version已有实现。ProtectedControlIO/control pump处理认证PING/PONG和实例EOF/error退出，已认证 FACT v2 consumer 与派生 RouteView 已接线并运行（`pkg/simpletier/fact_runtime.go`，由 `Network` 启动、认证准入时喂数据）；跨节点业务数据路径（DialContext/Listen）已有端到端验收（`tests/network_runtime/direct_test.go`，远程 Dial 必须先有路由，即经由 FACT+RouteView）。仍缺的是 Windows 侧的跨节点业务验收与 FACT 同步本身的直接集成证据。性能端到端基准见 [benchmarks/](benchmarks/)。本文拥有TCP SDK Dial/Listen、固定Circuit和Stream语义；L3/Host Adapter/UDP ICMP IP包由FEAT-L3-VPN拥有。name+token为组凭据、canonical CIDR为地址池/完整context的一部分，NodeID由稳定静态身份派生。

## 1. 需求说明


### 1.1 使用者、目标与范围

参与方：

- **Go 库宿主应用**：创建并关闭网络实例，注册虚拟 TCP 服务，主动连接远端服务；
- **覆盖网络节点**：维护自身身份、已认证邻接、拓扑事实和本地路径；
- **可选 Agent**：系统级 TUN/Wintun/utun 接入由 [L3 VPN](l3-vpn.md) 定义，本 feature 只定义其复用的 TCP SDK 语义；
- **中继节点**：转发覆盖网络控制消息和已建立的 Circuit，不需要理解 HTTP、WebSocket 或私有业务协议。

目标是让两个没有直接物理连通的节点，只要存在一条或多条可用的认证连接，就能通过虚拟地址访问对端显式注册的 TCP 端口。节点可以有多个上游；上游只决定初始拨号，不代表固定的父子关系。

本功能明确不包含：

- 原始 IP 包、UDP、ICMP、TUN/Wintun/utun 设备和系统路由；这些属于 [L3 VPN](l3-vpn.md)；
- 把普通 TCP 长连接在路径故障后伪装成无损迁移；
- 路由层替业务层自动重放可能产生副作用的 HTTP 或私有协议请求；
- 未经设计和测试就承诺所有 NAT 环境可直连、固定规模上限或固定故障恢复时延。

### 虚拟 TCP 接入

应用在已启动的网络实例上，可以用标准 Go 风格的 `Listen` 注册虚拟端口，用 `DialContext` 连接 `VirtualIP:port`。成功返回前，目标节点身份、目标端口授权和目标服务连接必须完成；不能只建立到中继的物理连接就返回成功。

### 最小配置可启动

节点只提供监听地址、零到多个上游地址、网络名称、虚拟网段和入网凭据，即可进入监听和连接流程。上游暂时不可达不应被当作配置格式错误；节点应保留监听并执行有界退避重连。未知载体、空凭据、非法网段、地址池耗尽和配置错误必须在启动阶段给出明确错误。空 Token 的拒绝是核心 Runtime/握手不变量，不能只依赖外层配置解析；已构造的内部配置也必须无法用空凭据加入网络。

### 身份、网络和地址分离

NodeID 不依赖 VirtualIP、网络名称或入网凭据，仅在本实例生命周期内稳定；重启后是新 NodeID（无持久身份）。NetworkID 表示逻辑网络命名空间；VirtualIP 是可收敛的寻址结果。地址冲突、网络分区合并、固定地址冲突和状态复制必须有可观察的处理结果，不能静默把旧业务流改投到另一节点。

### 认证的双向邻接

只有通过网络身份、节点身份、版本和能力校验的连接，才能发布拓扑事实或承载业务 Circuit。认证后的邻接双方都可以主动发起逻辑流；认证失败、身份冲突或协议不兼容必须关闭该 Link，不把部分握手结果当作可用成员状态。

### 拓扑传播和主备路径

节点需要能够从已认证邻居获得足以计算路径的拓扑事实，并在本地形成目标节点的可达视图。路径选择应排除不可达、策略禁止、跳数/预算超限和能力不匹配的候选；在存在合法备用时，主路径故障只影响新建流的首选路径，不要求修改已有流。

### 固定 Circuit 的流语义

每条业务流在建路阶段绑定源端、目标端和一条无环路径。中继只执行路径中指定的下一跳并消耗同一剩余预算。流必须支持取消、Deadline、半关闭和明确 RESET；FIN 只关闭一个方向，不能因为一个流半关闭而关闭共享邻接。

### 载体与业务适配器解耦

本版本外层载体**只支持加密 TCP framing**（用户已确认），切分/加密/防重放契约见 [线上帧协议与链路安全](internals/wire.md)；WebSocket、HTTP 隧道和私有载体延期，未来引入需另行设计与验收。载体只负责提供统一的可靠、有序、双向流和帧边界；业务 Adapter 负责 HTTP 请求、WebSocket 消息边界、取消和请求级重试；Routing、Link 和 Circuit 不解析业务报文，也不替 Adapter 决定是否可以重放请求。

按用户新增的“支持已有流连接”请求，SDK 提供独立的 [StreamCarrier](internals/stream-carrier.md) 帧传输原语，接收宿主交接的专用 `io.ReadWriteCloser`（含既有 `net.Conn`），无需额外 listen/dial 或身份目录。它复用同一外层 Wire framing，但不验证身份或 AEAD、不注册 Network 邻接；返回帧均为未认证数据。认证 Link/Session 与 Network.AttachConnection 已接通（AttachConnection 已实现并有测试），不构成明文/弱加密 Network 模式。

### 有界资源和可解释状态

节点必须对 Link、建路、活跃流、同步通告、发送/接收窗口和总缓冲设置可观察的硬上限；当前 P1 数值见 [多协议覆盖网络](multiprotocol-overlay.md) 3.8 与 [线上帧协议](internals/wire.md) 3.3，性能服务目标由实现后的基准测试确定。至少能查询 NodeID、VirtualIP、认证邻居、主备路径、成本/排除原因、活跃 Circuit、错误类别、缓冲占用和切换原因。

### 1.3 其他业务规则与质量约束

- **错误不混层**：`NoRoute`、`LinkDown`、`RouteStale` 可以触发候选路径尝试；`PermissionDenied`、`ProtocolNotSupported` 直接返回；`TargetRefused`、`ServiceUnavailable` 不应默认把整个覆盖链路判死；`OutcomeUnknown`、`SessionLost` 不应被路由层默认重放。
- **时间预算不逐跳重置**：Circuit 建路的总 Deadline/预算由源端定义，中继只能扣减剩余量。
- **来源地址边界**：库模式不承诺目标应用看到原始物理来源 IP；应用可查询远端 NodeID，但该查询不等于网络层源地址伪装。
- **状态复制边界**：可以复制配置，不能复制正在使用的 NodeID 私钥和地址状态来启动两个相同身份的实例；每个实例自动获得独立进程内 scope，无需配置状态目录。
- **安全边界**：只有成功完成当前 network 握手的 peer 才按成员授权；成员默认允许同网虚拟端口访问/转发/ICMP，源地址防伪强制。当前已确认的部署政策要求 token 为 ≥128-bit CSPRNG；配置层只拒绝空值，不能判断熵，因此不对任意非空值承诺抗猜测强度；细粒度 ACL、按节点撤销和凭据轮换延期。
- **性能边界**：原 v0.1 中的 RTT、抖动、超时率、队列等待和重连惩罚公式是候选初值，不是已验证预算或服务等级承诺。


以下是拟定验收场景，当前尚未实现或执行：

| 场景 | 输入/前提 | 期望结果 | 关联 |
|---|---|---|---|
| 非法地址池 | 使用非 canonical CIDR、IPv6 CIDR 或 `0.0.0.0/0` | 在任何网络路由副作用前拒绝；`/0` 不得安装为系统默认路由 |
| 双向多跳访问 | A、B 仅分别连接可中继的 R；B 注册虚拟 TCP 端口 | A 的 Dial 在目标端口准备好后成功，B 可反向 Dial A 的端口 |
| 多路径故障 | A 到 B 存在两条合法路径，主路径断开 | 新建流选择备用；已有流返回明确错误，不被无损迁移 |
| 上游不可达 | upstreams 地址合法但暂时无法连接 | 节点继续监听，按退避重连；不报告为配置解析成功但网络永久可用 |
| 无路由/目标拒绝 | 目标未出现在 RouteView，或目标端口未授权/拒绝 | 分别得到 `NoRoute` 或目标/权限错误，不无限转发 |
| 拓扑环路和过期 | 收到重复、过期或形成环路的通告 | 通告按版本/寿命处理；Circuit 不无限绕圈，预算不逐跳增加 |
| 地址冲突与重启 | 自动地址冲突、网络分区合并、节点重启 | 按确定规则收敛或明确耗尽/固定冲突；旧流不改投他人 |
| 半关闭 | 一侧调用 `CloseWrite` 后仍等待响应 | 写方向结束，读方向仍可用；仅在目标或线路关闭时结束读 |
| 慢端和大流量 | 接收方不读、并发流和大帧持续进入 | 窗口收缩并反压；达到上限后有明确错误或拒绝，不无限积压 |
| 结果未知与重试 | LinkWriter 接受 CIRCUIT_OPEN 前可在同一总预算内换 attempt；接受后只可在同 Session 用原 request_id/内容重发，否则 OutcomeUnknown 且 attempt 固定；新用户 Dial 用新 CircuitID |
| Opening 取消 race | attempt 0 Open 在 Path 0 延迟，源端换 Path/attempt 1 后取消且 CANCEL 先到目标；CircuitID-wide tombstone 拒绝迟到 attempt 0；若 Accept 先胜则 target Reset，远端应用可能已见流 |
| Network.Close 生命周期 | 阻塞 Accept 在 Network.Close 后返回 ErrClosed；active Stream 本地 Read/Write 返回 ErrClosed，远端收到 CANCELED；Done 在异步清理完成后关闭 |
| 错误凭据/网络 | 节点使用错误 Token 或 NetworkID | Link 认证失败，不发布成员和拓扑信息 |

## 2. 概要设计


### 2.1 职责、边界和协作

`Runtime` 将外部 Config 规范化为内部运行计划，生成进程内静态身份并启动监听、上游连接、同步和接入模块。`Carrier` 将不同底层连接转换为统一双向流；`Link` 负责邻接握手、复用、反压和存活；`Topology/Routing` 只消费认证后的事实并产生路径视图；`Endpoint/Circuit` 将虚拟地址和路径映射为业务流；Adapter 只负责边界协议。

推荐的核心协作边界：

- Routing 不直接拨号、读写 Socket 或解析应用报文；
- Carrier 不拥有 NodeID、地址分配或全局路由；
- Circuit 不修改 RouteView，也不在 DATA 阶段重算路径；
- Adapter 不直接绕过 Endpoint 或访问其他节点的 Link；
- Agent 的系统路由和 TUN 只能位于系统接入层，不能改变库的默认监听和 Dial 契约。

### 2.2 端到端处理流程

```text
[创建 Network]
   |
   +--Config 非法--> [返回配置错误]
   |
   v
[生成 Network 身份 / 派生 VirtualIP]
   |
   v
[库-owned TCP Carrier: listen + upstreams]
   |
   +--连接失败--> [保留监听，退避重连]
   |
   v
[Link 握手/能力认证 -> Advertisement -> RouteView]
   |
   v
[Listen 注册 Endpoint]
   |
   v
[Dial 查地址/选路；total budget ≤30s]
   |
   +--NoRoute/参数非法--> [返回分层错误]
   |
   v
[候选 Path: PATH_OPEN/READY]
   |
   +--安装失败--> [下一个候选；同一预算]
   |
   v
[SESSION_CTRL / selected Session handshake / SESSION_READY]
   |
   +--Session setup 未完成--> [下一个候选；同一预算]
   |
   v
[向 STREAM data Link 提交 CIRCUIT_OPEN]
   |
   +--确定尚未提交--> [下一个候选；同一预算]
   |
   +--已提交--> [等待当前 attempt/request_id 的 CIRCUIT_READY]
                      |
                      +--READY--> [目标 Stream 已建；向 Dial 返回 Stream]
                      +--REFUSED--> [返回目标/权限错误]
                      +--结果不确定--> [ErrOutcomeUnknown；不递增 attempt]
```

启动连接和业务 Dial 是异步边界：`Network` 可以在没有上游时完成本地监听，但 `DialContext` 只有在目标路径和端口准备完成后才返回。RouteView 更新可并发发生；一次 CircuitOpen 使用它开始建路时捕获的候选和总预算。

### 2.3 数据流与归属

```text
[宿主构造的 typed Config]
        |
        v
[RuntimePlan] ---> [IdentityStore (per-Network, in-memory)]
        |                  |
        |                  +--> stable static key / NodeID
        v
[NetworkID RuntimeState]
 address attempt / incarnation / LinkEpoch
        |
        v
[Address declaration / conflict convergence]
         |
         +--> confirmed VirtualIP + AddressFact
         v
[Carrier] <--> [LinkSession] <--> [邻居控制面]
                           |
                           +--> [TopologyStore]
                                      |
                                      v
                                  [RouteView]
                                      |
                          target NodeID + candidates
                                      v
[Virtual Endpoint] <--> [Circuit] <--> [Remote Endpoint]
                                      |
                                      v
                               [应用 Stream]
```

`RuntimePlan` 是校验后的派生配置，不是用户配置的第二份事实；`IdentityStore` 只拥有该 Network 的静态密钥/NodeID，每个 Network 独立生成，不跨实例共享；地址尝试、incarnation、LinkEpoch 等状态必须按 NetworkID 隔离保存，不归共享身份对象所有。provisional VirtualIP 可以支持本地 Endpoint，但未完成声明确认前不进入远端 RouteView；`TopologyStore` 只接受已认证、版本可比较且未过期的事实；`RouteView` 可丢弃并重建；`Circuit` 和 Stream 独立拥有流控、半关闭和错误。

### 2.4 关键方案与取舍

根目录 v0.1 明确提出“TCP 服务型覆盖网络、虚拟 IP + 端口、稳定 NodeID、链路状态、固定 Circuit”。本整理稿保留这一方向，但以下选择仍是 proposed：

- **库优先、Agent 可选**：让普通 Go 服务可以无特权接入，减少默认副作用；代价是不能用库本身服务未修改的系统程序。
- **链路状态事实而非中心下发下一跳**：每个节点从邻居获得节点/边事实并本地计算，避免单一路由控制器；代价是需要版本、过期、重复和分区收敛规则。
- **源端固定 Circuit（已确认）**：让 TCP 流的路径、预算和故障归属明确；代价是路径失效要重建，且 Open 需要传输受限路径信息。EasyTier 的最终目标逐跳查路由是对照方案，不直接替代该流语义。
- **载体/业务分离**：一条可靠流可以承载原始 TCP、HTTP 或 WebSocket；代价是每个 Adapter 必须自行处理消息边界、重试和取消。
- **地址可收敛而非永久不变**：地址便于用户使用但不是身份；代价是分区合并可能要求更新地址映射，应用不应把 VirtualIP 当持久主键。

## 3. 详细设计


### 3.1 接口与数据契约

#### 3.1.1 Go 库入口草案

以下公开类型与本地启动已存在；完整远端 Dial/Stream/Circuit 路径仍未实现。已确认并落实的 Connector/Connection 与 ConnectionTarget 详见 [连接提供者与实例](internals/connections.md)。真实 ws/wss 及宿主已升级 WebSocket 的 byte-stream 接入见 [WebSocket 模块](internals/websocket.md)；它遵循相同 Connection 接口，不等于 Link 已认证：

```go
package simpletier

import (
    "context"
    "net"
)

type Config struct {
    Listen    []string
    Upstreams []string
    Targets   []ConnectionTarget // host Connector + opaque physical endpoint
    Network   NetworkConfig
    Options   RuntimeOptions
}

type NetworkConfig struct {
    Name  string
    CIDR  string
    Token string
}

type RuntimeOptions struct {
    FixedIP   string
    Relay     *bool
    LogLevel  string
    RateLimit *bool   // nil = 关闭准入限速
}

// Validate checks core config without side effects; NewNetwork validates again before startup.
func (cfg Config) Validate() error

// NewNetwork validates config and starts the core network. It returns after configured listeners bind.
func NewNetwork(cfg Config) (Network, error)

type NodeID string

type Stream interface {
    net.Conn
    CloseWrite() error
    Reset(code uint32) error
    RemoteNode() NodeID
}

type StreamListener interface {
    Accept() (Stream, error)
    Addr() net.Addr
    Close() error
}

type Network interface {
    DialContext(context.Context, string, string) (Stream, error)
    Listen(string, string) (StreamListener, error)
    ListenPacket(string, string) (net.PacketConn, error)
    NetListener(StreamListener) net.Listener // optional stdlib adapter
    AttachConnection(context.Context, Connection, AttachOptions) (AttachedLink, error)
    LocalVirtualIP() netip.Addr
    Peers() ([]PeerFact, error)
    Close() error
    Done() <-chan struct{} // closed after all background cleanup completes
}
```

约束：

- `DialContext` 的 `network` 第一阶段只接受 `tcp`；address 是虚拟 IPv4 + 端口（IPv6 不在本版本范围）；
- `Listen` 只注册本实例 VirtualIP 上的虚拟端口：`:port` 使用当前本地/临时 VirtualIP；显式 `IPv4:port` 必须与该地址一致。空 host 不是 OS wildcard，也不代理宿主机监听；
- `Stream` 的 Deadline 只影响当前流，不能直接改变共享 Link 或其他流；
- `CloseWrite` 幂等发送 FIN，远端 `Read` 在已读完数据后返回 EOF；`Reset(code)` 幂等发送 `CONTROL_RPC(STREAM_RESET)`，code 只能是 wire 定义的 `NO_ROUTE/LINK_DOWN/RESOURCE/PROTOCOL/CANCELED`，本地未知码返回 `ErrProtocol` 且不发帧；远端未知 RESET reason 同样终止该 Stream 并报告 `ErrProtocol`。`Stream.Close` 等价于 Reset(CANCELED) 并关闭本地两方向；
- `Listener.Close` 幂等停止新连接并解除阻塞中的 Accept，自身返回 nil；阻塞中的 Accept 返回 ErrClosed;
- `RemoteNode` 返回认证后的 NodeID，不等于远端物理地址；
- `Close` 幂等：先停止新建入站/出站 Circuit，关闭全部已注册 Listener 并使阻塞的 `Accept` 返回 `ErrClosed`；取消 pending Circuit 并发送 teardown；主动 reset 当前 Network 的 active Stream（本地后续 Read/Write 返回 `ErrClosed`，远端看到 `CANCELED`），再关闭 Link 并释放有限缓冲。同步等待最多 5 秒，超时返回 `ErrCloseTimeout`，后台清理继续，`Done()` 在所有后台清理完成后关闭；重复调用 Close 可再次等待同一 Done。Link 故障仍映射为 `SessionLost`，不与本地 Close 混淆。

#### 3.1.2 配置与规范化

| 字段 | 规则 | 失败行为 |
|---|---|---|
| `listen` | 每项为 `tcp://host:port`，host 显式、port `1..65535`，wildcard 显式 `0.0.0.0`；`listen` 与 typed `targets` 可同时为空（此时不绑定任何监听，仅可经 `AttachConnection` 接入）| 协议/host/port 非法拒绝；不接受 port `0` |
| `targets` | SDK `[]ConnectionTarget`：非 nil Connector 与非空 opaque Endpoint；共享提供者不可在运行期间并发修改 | nil/typed-nil/空 endpoint 在副作用前拒绝；Targets 值复制；出站通过 Connector.Dial，成功连接自带稳定 Info，尚不代表认证 Link |
| `upstreams` | 可为空；每项为 `tcp://host:port`，host 必须显式、port `1..65535` | 格式或端点字段非法时拒绝；可达性失败时保留监听并重连 |
| `network.name` | 参与 NetworkID/握手一致性校验 | 空值或不一致时拒绝入网 |
| `network.cidr` | canonical IPv4 single subnet, prefix length `1..32`; `/0` is rejected because its system route is the default route | 解析失败、不可分配、`/0` 或冲突时明确报错 |
| `network.token` | Typed SDK value supplied directly by the host; the library performs no file or environment expansion; value must be nonempty | Empty token rejects before authentication; logs never include its value; entropy remains the caller's CSPRNG responsibility |
| `options` | Core typed options: `fixed_ip`, `relay` (true by default), and `log_level` (`debug`/`info`/`warn`/`error`, case-insensitive; default `info`). No `state_dir`: runtime state is process-local and nothing is written to disk | Unknown fields, invalid values or combinations reject before side effects; `fixed_ip` must be a usable VirtualIP in this CIDR |

认证凭据由 `network.name` + `network.token` 构成；`network.cidr` 决定 NetworkID/地址池，同组节点仍须使用相同的 canonical CIDR。用户不需要提供 NodeID、证书/私钥路径或加密算法。Runtime 负责生成进程内节点身份和启动世代（不持久化），空 Token 在配置层和核心握手层都必须拒绝。SDK `Config` 只含核心字段与 `options`；Agent 使用独立 typed `AgentConfig` 扩展 `inbounds`，由宿主通过 SDK 传入。库不读取 YAML/JSON/其他配置文件，不读取 process environment，也不展开 `${VAR}`；所有字符串按调用方给定值校验。`Config.Validate()` 与 `AgentConfig.Validate()` 只做无副作用校验；`NewNetwork(Config)` 不创建 TUN、不修改系统路由，也不接受 Agent inbounds。


`NewNetwork(cfg)` 先完整校验/规范化核心配置，再绑定所有配置的 TCP listen 地址并启动后台 Link/upstream 重连；监听绑定成功后返回运行中的 `Network`。本地配置错误或 listener bind 错误返回构造错误，并回滚本次已创建的 listener、释放本 Network 已取得的 IdentityStore 引用。**没有持久 identity/lock 文件**——状态只在内存，构造失败不留下任何磁盘痕迹。upstream 暂不可达不使构造失败，保留 listener 并退避重连。生命周期由返回的 `Network.Close/Done` 管理；SDK 构造不创建 TUN、不修改系统路由。

#### 3.1.3 控制对象

| 对象 | 必要字段/语义 |
|---|---|
| `NodeIdentity` | NodeID、X25519 公钥/私钥引用、启动世代；进程内存，禁止克隆复用 |
| `NetworkID` | 协议命名空间、规范化网络名和 CIDR；Token 不直接参与身份计算 |
| `AddressAdvertisement` | NetworkID、NodeID、StaticPublicKey、VirtualIP、incarnation/sequence、issued/expiry、撤销信息 |
| `LinkAdvertisement` | 本端/对端 NodeID、LinkID、LinkEpoch、能力、健康摘要、版本 |
| `TopologyAdvertisement` | NetworkID、origin、origin StaticPublicKey、incarnation、sequence、issued/expiry、links、addresses、capabilities、撤销信息 |
| `CircuitOpen` | CircuitID（一次逻辑 Dial 稳定）、open_attempt、目标 NodeID/端口、PathID、PathGeneration、RouteViewVersion、PathDigest、无环 hops、cursor、hop limit、remaining_budget_us、source_initial_window（固定 65,536 bytes） |
| `CircuitReady` | echoed CONTROL_RPC request_id、CircuitID、open_attempt、status/error、target_initial_window（固定 65,536 bytes；不能发 0 credit） |
| `StreamFrame` | CircuitID（DATA/FIN only）、字节偏移、有限载荷；窗口 credit 通过 absolute WINDOW_UPDATE，RESET 通过 CONTROL_RPC STREAM_RESET |

事实编码、FrameKind/MessageType、Path payload、资源初值、API 错误和关闭语义由本版规格冻结；实现和基准测试尚未运行。

### 3.2 业务状态流转

主状态对象是一次 `Circuit`，它与底层 Link 和应用 Stream 分开管理。

```text
[Requested]
    |
    +--参数/策略不通过--> [Failed: Invalid / PermissionDenied]
    |
    v
[Opening: OpenUncommitted]
    |
    +--Path/Session setup failure before CircuitOpen commit--> [Opening: next candidate, same budget]
    |
    +--Wire Session egress accepts CircuitOpen--> [OpenCommitted: attempt fixed]
                                                     |
                                                     +--matching READY--> [Ready]
                                                     +--definitive REFUSED--> [Failed: target error]
                                                     +--same request retry on same usable Session--> [OpenCommitted]
                                                     +--Link failure/deadline/ambiguous result--> [Failed: OutcomeUnknown]
    |
    +--Cancel/Deadline--> [CancelSent] --> [Failed: context error]

[Ready]
    |
    +--本地 CloseWrite--> [LocalWriteClosed]
    |                          |
    |                          +--远端 FIN--> [BothClosed]
    |
    +--远端 FIN--> [RemoteWriteClosed]
    |                    |
    |                    +--本地 CloseWrite--> [BothClosed]
    |
    +--取消/Deadline/Reset--> [Resetting] --> [Closed]
    +--链路硬故障--> [Failed: SessionLost]

[BothClosed] --> [Closed]
```

状态说明：

- `Requested` 只存在于本地 Dial 调用，不能被远端观察为已成功；
- `Opening` 的源端总预算一次设定并递减，最多30秒。更高 `open_attempt` 只允许在 CIRCUIT_OPEN 尚处于 `OpenUncommitted`（尚无成功的 LinkWriter admission；同步 all-or-none admission 进行中仍留在此状态）时递增；`EgressCommitted` 是串行 LinkWriter 成功接纳完整 E2E frame 入队的时刻（不是只选择逻辑帧/分配 MessageNumber）；只有 LinkWriter 同步明确拒绝（且保证该帧不会稍后发送）才可换候选；已分配的 MessageNumber 允许留空洞；若返回结果无法证明拒绝，按可能已接纳处理并返回 OutcomeUnknown，绝不切换候选；接纳后该帧可能到达目标，任何后续写错误都不能证明未交付，此后不得切换 Path 或提高 attempt。commit 前的 Path/Session setup failure 或 LinkWriter 明确 all-or-none reject 可在同一预算下尝试下一个候选；admission 尚未返回时不得启动并行候选。commit 后仅允许在同一仍可用 Session 上以相同 attempt/request_id/内容重发（每个 frame 分配新的 MessageNumber）；若 Session/Link 不可用、Deadline 到或 READY 仍不确定，则返回 `OutcomeUnknown`。源端只接受当前 attempt 的 READY，忽略旧 attempt 的迟到 READY；
- `Ready` 才允许将 Circuit 交给源端调用方；目标未返回当前 attempt 的 READY 时不能向调用方返回成功连接；
- `LocalWriteClosed` 表示本地已发送 FIN，但仍可读取；`RemoteWriteClosed` 表示本地读到 EOF，但仍可写，直到本地 `CloseWrite` 或完整 `Close`；
- `BothClosed` 是两个方向都完成 FIN 后的正常终态；应用 `Close` 关闭两个方向并释放当前流，`Reset` 立即终止当前流并丢弃未交付的流内数据；
- `OutcomeUnknown` 表示目标可能已创建/交付 Stream 但源端未确认 READY；同一 attempt 在 reservation 内可重发缓存结果。目标不得对同一 CircuitID 再创建第二条目标 Stream；EgressCommitted 后源端不发更高 attempt；若非法/旧实现仍将更高 attempt 发到已存在可能有副作用的 OpenRecord，目标只返回 `OutcomeUnknown`，绝不新建 Stream。Active OpenRecord 在 Stream 生命周期内保留；终态 refusal/close/cancel 的 CircuitID record/tombstone 自终态转换起保留固定30秒，用于拒绝晚到 attempt；源端 total Dial budget 最大30秒，预算后不得再提交 Open。新的用户 Dial 必须生成新 CircuitID；
- `CancelSent` 表示源端本地已因 context cancel/deadline 返回错误并发送 `STREAM_RESET(CANCELED)`。在目标端它是 `(source NodeID, CircuitID)` 范围的终态，不限于载荷中的 open_attempt 或某个 Path/Session：即使尚无 OpenRecord 也建立 bounded cancel tombstone，拒绝所有该 CircuitID 的迟到/更早/更高 Open。目标与 `Listener.Accept` 以同一把锁决定 pending-delivery/cancel winner；取消先胜出则删除 pending Stream，Accept 先胜出则立即 Reset，但远端应用可能已观察到它。cancel tombstone 从创建时起固定保留30秒，并计入每 Peer≤64的 pre-READY reservation；若该池满，设置来源 Peer 的 `CircuitOpenBlockedUntil=now+30s` admission fence；deadline 独立于其他 pre-READY reservation 的到期/回收，期间该 Peer 的新 Open 均返回 ResourceLimit。控制取消帧丢失时仍是 best-effort。源端在本地取消后忽略任何迟到 READY；该语义不保证分布式 race 中绝不远端交付；
- `Failed` 表示当前 Circuit 失败，不能把其内部字节缓冲直接接到新 Circuit；`Closed` 是终态，共享 Link 生命周期由 Link 状态单独决定。

Link 的候选状态为 `Connecting -> Handshaking -> Established -> Suspect -> Closed`。硬读写错误可以从 `Established` 直接到 `Closed`；探测超时先进入 `Suspect`，达到实现确定的失活条件后关闭。恢复的 Link 需要重新经过认证和拓扑发布，不直接复活旧 Circuit。

Link/RouteView 与 Circuit 的交互矩阵：

| 事件 | Opening Circuit | Ready Circuit | 新建 Circuit |
|---|---|---|---|
| RouteView 更新 | OpenUncommitted 可用新视图选择候选；EgressCommitted 后固定 Path/attempt，不提升 attempt | 不迁移、不改路径 | 使用新视图 |
| Link 进入 `Suspect` | OpenUncommitted 可等待或改选候选；EgressCommitted 只等当前结果/同 Session 同 request 重试，不递增 attempt | 继续使用，直到真实读写失败 | 排除该 Link |
| Link `Closed` 或数据读写失败 | EgressCommitted 前可下一候选；commit 后无 higher attempt，回复确定缺失则 `OutcomeUnknown` | 返回 `SessionLost`，不自动迁移 | 排除该 Link |
| Link 恢复 | 重新认证并获得新的 `LinkEpoch` | 不复活旧 Circuit | 认证完成后才可作为候选 |

具体确认：已认证且健康的不同LinkID可独立并存，较高epoch的新实例只提高NEW-attempt floor，不自动drain旧健康实例；按完整实例FactKey/version撤销或真实失败只排除该实例。未准入10在11先提高floor后迟到仍拒绝，同域尝试须序列化分配到admission完成或另有经评审的排序证明，不降低/分拆floor。实例并存不改变固定到真实失败L1的旧业务错误，也不承诺跨物理Link无损迁移。FACT/CAPABILITY v2目标见[Wire](internals/wire.md)与[Topology](internals/topology.md)；当前报告已有v2 codec/门禁局部实现，事实消费者和这些场景仍未执行。

### 3.3 关键处理与不变量

#### 3.3.1 启动与身份

1. 接收宿主通过 typed SDK 传入的 `Config`，按调用方原样校验字段；不读取配置文件、不展开环境变量；空 Token 在 Runtime 校验阶段拒绝，不能等待或依赖上游连接失败暴露问题；
2. 规范化 NetworkID、CIDR、监听/上游 URL；
3. 构造本 Network 自己的 IdentityStore，在内存中生成静态密钥/NodeID；
4. 打开完整 ContextID 命名的独立 RuntimeState，保存该网络的 VirtualIP、地址 attempt、incarnation 和 LinkEpoch 高水位；这些状态都在进程内存中，不放入 IdentityStore。
5. 检查固定地址和本地状态复制风险；
6. 按配置顺序绑定所有 TCP listen 地址；任一绑定失败时关闭本次已创建的全部 listener，并释放本 Network 的 IdentityStore 引用，构造失败不留下磁盘痕迹；NodeID 为进程内生成，重启即变；
7. listener 全部就绪后启动后台 upstream/Link 尝试；上游暂不可达不使构造失败，保留监听并退避重连；
8. 每个 TCP 连接先升级为 Carrier/Link，再做身份、网络、版本和能力认证；
9. 只有身份认证和必需 Capability 校验完成的 Link 才能进入 TopologyStore。

成功构造后，`Network.Close` 先停止 listener 和后台 worker，再释放该 Network 的 IdentityStore 引用，随后在所有清理完成时关闭 `Done`。**运行态状态不写磁盘，因此没有跨 Network 共享的 identity 文件或 OS 锁需要保留**；一个 Network 关闭只影响它自己内存中的状态。

不变量：

- NodeID 不因 VirtualIP、网络名或 Token 改变；
- 认证失败的连接不能发布拓扑或接收业务 Open；
- 上游暂时不可达不破坏本地监听；
- `Close` 后后台重连任务不能重新创建 Link。

#### 3.3.2 地址声明和冲突

启动时优先读取历史 VirtualIP，并向可达邻居查询声明。历史地址没有有效冲突时复用；否则按 NodeID + attempt 得到确定性候选并逐个尝试。收到声明时先验证 NetworkID、NodeID/StaticPublicKey 绑定、版本/有效期和认证 ingress，再更新本地映射；P1 不要求 origin signature。

两个自动声明冲突时按稳定 NodeID 顺序决定保留者，另一方递增 attempt 换候选；候选耗尽明确失败。固定地址冲突不静默改址。地址映射变化只影响未来 Endpoint 查找，已经绑定 NodeID 的旧 Circuit 不改投其他节点。P1 不做租约/DHCP/ARP 和 origin signature；撤销/轮换由信任组换 secret 处理。

当前本地启动切片在未配置 `fixed_ip` 时，使用本实例 NodeID 和 attempt=0 公式计算 provisional VirtualIP，供 `Listen(":port")` 解析；此候选不会发布为 AddressFact，也不进入 RouteView，直到对应 Link/Topology 事实完成认证。非零 attempt 仅进程内记录、跨重启不保留；冲突重派已实现（见 TestAutoLoserReallocation）；跨进程历史地址复用未实现。

#### 3.3.3 拓扑同步和路由视图

问答具体选择parallel_link_epoch“独立并存和撤销（Recommended）”、fact_protocol_upgrade“统一升级并拒绝 v1（Recommended）”：目标全组FACT v2/CAPABILITY schema v2，version:u8/mask:u64be宽度不变，bit1=fact-sync.v2、其余bit0/2..5保持frame/path/session/packet/stream v1语义，fullmask0x3f、bits6..63保留。LINK payload末尾追加TypeLen:u16+Type，target包含LinkID；不能把版本1peer当作兼容消费者或向其发送v1-labelled v2数据。类型展示旧批准不重问；新rekeyopcode/bit、use quotas、KDF具体未决项不获追认。当前报告已有v2 codec/门禁局部实现；FACT consumer/RouteView生产链仍未接通，场景未执行。

TopologyStore 维护认证节点、地址声明、邻接边和可选服务能力。每条通告包含 origin、origin StaticPublicKey、incarnation、sequence、issued/expiry 和认证 ingress。incarnation 为进程内计数，重启从 1 重新开始；跨重启不再保证递增，因此不提供跨重启的新旧判定。P1 的事实 provenance 由已认证成员互信和 StaticPublicKey/NodeID 绑定提供，origin signature 为未来增强，不作为当前必填。

同步流程：

1. 邻接建立后交换版本摘要和能力；
2. 根据摘要发送分页的完整缺口或增量事实；
3. 周期核对摘要，修复丢失；
4. 接收方按 origin + incarnation + sequence 丢弃旧版本，重复版本不能延长原始有效期；
5. 失效边本地立即从候选路径排除，再等待其他节点收敛；
6. RouteView 从一致快照重建，旧版本不能覆盖较新的视图。

推荐的 RouteView 结果是 `target NodeID -> ordered candidate paths`，而不是让业务层直接操作下一跳。路径过滤在排序之前，至少检查可达性、策略、中继能力、跳数上限和预算；候选决胜使用稳定的 NodeID/LinkID 顺序，减少相同成本下的抖动。

详细路由契约和 EasyTier 对照见 [拓扑与路由模块](internals/topology.md)。

#### 3.3.4 Circuit 建立和转发

源端从当前 RouteView 选择同一 STREAM Lane 的无重复节点路径，先通过 `PATH_OPEN/READY` 安装 PathID/PathGeneration，再在该 Path 上发送 `SESSION_CTRL(STREAM)` 完成当前选定的 Noise/PSK Session handshake（具体帧细节待评审）。SESSION_READY 在 CONTROL TCP Link 上提交 ReadyPending；各 hop 对 READY 前到达的匹配 E2E 数据只入有界队列，不提前交付。源端随后在 STREAM data Link 上发送 `CONTROL_RPC(CIRCUIT_OPEN)`。CircuitOpen 携带稳定的 CircuitID、open_attempt、PathID、PathGeneration、RouteViewVersion、PathDigest、预算和窗口；每 attempt 有一个 RPC request_id，同 attempt 重传使用相同 request_id/内容。每个中继检查：

- 当前节点是否出现在预期 hops/cursor；
- LinkID + LinkEpoch 是否仍对应已认证邻接，且未被关闭/撤销；
- PathID/PathGeneration 是否已安装且与 PATH_OPEN 的 nodes/links/digest 一致；
- RouteViewVersion 作为源端选择视图和诊断信息保留；中继不要求本地视图版本数值完全相同，但必须验证收到的路径和当前策略仍可执行；
- PATH_OPEN 安装时已由每跳校验 PathDigest 与公开 nodes/LinkID/LinkEpoch 顺序；当前 CIRCUIT_OPEN 的 E2E PathDigest 不可由中继读取，不在中继阶段重复校验；
- hop limit、`remaining_budget_us` 和帧大小是否有效；
- 本地中继策略是否允许转发；

`CircuitID` 在一次用户 Dial 内稳定，`open_attempt` 仅能在该 CircuitID 的 CIRCUIT_OPEN 尚未 EgressCommitted 时因换候选路径递增；Wire `CONTROL_RPC.request_id` 对每个 attempt 固定，并由 READY 响应原样回显。目标端以 `(source NodeID, CircuitID)` 建立单一 `OpenRecord`，串行化 reservation 与 `Listener.Accept`，至多创建一个本地 Stream。相同 attempt/request_id/内容的重传只返回缓存结果；同一 attempt 的冲突内容判协议错误。若 OpenRecord 已可能创建或交付 Stream，后续更高 attempt 必须返回 `OutcomeUnknown`（若已缓存无副作用的拒绝则返回该拒绝），不得重新打开第二个目标连接。目标一旦进入 Active Stream，Circuit 记录保留到该 Stream 关闭并计入每节点活跃流上限；尚未交付/确认结果的 pre-READY reservation/tombstone 保留到首个请求携带的剩余预算耗尽（源端总预算最大 30 秒），预算耗尽后该 Dial 不得再发送 Open。新用户 Dial 必须生成新 CircuitID.

Opening 期间的取消通过 `CONTROL_RPC(STREAM_RESET(CANCELED))` 表达，可在 READY 前使用；目标与 `Listener.Accept` 以同一把锁决定 pending-delivery/cancel winner。取消先胜出则删除 pending Stream；Accept 先胜出则 Reset 已交付 Stream。源端已返回 context error 后忽略任何迟到 READY。

`remaining_budget_us` 是固定单位的相对预算，不依赖跨节点墙上时钟；每一跳扣除本地观测的处理、排队和转发耗时，不能重新获得完整预算或发生无符号溢出。`OpenUncommitted` 候选 Path 与此时递增的 attempt 共享该总预算；`EgressCommitted` 后不切换 candidate/attempt，Link 失败按 `OutcomeUnknown` 处理。

校验通过后，中继推进 Path cursor 并绑定入站/出站逻辑流，不能改用 PATH_OPEN 之外的替代路径。目标节点执行端口授权并至多打开一个本地 Stream，CircuitReady 才能使源端的当前 attempt 成功。当前 request_id/attempt 必须同时匹配；目标对同 attempt 的精确重复返回缓存结果，若源端违反 `EgressCommitted` fence 仍发送更高 attempt，且目标记录表明旧 attempt 可能已有副作用，目标返回 `OutcomeUnknown`，绝不重复打开服务连接。目标服务拒绝可缓存并返回拒绝，不污染整条 Link。

DATA 在已建立 Circuit 上按帧转发，不为每个数据块查全局 RouteView。FIN 只关闭方向；RESET 只关闭当前流；所有路径都共享源端剩余预算。慢端导致窗口收缩时必须反压，达到缓冲上限时返回可区分的资源错误。

#### 3.3.5 故障、重试和结果未知

- Link 的明确读写错误立即使依赖该 Link 的候选失效；探测连续失败也必须有实现定义的上限；
- Path/Session setup failures before `EgressCommitted` may select a backup candidate within the same `remaining_budget_us`; every retry shares the original 30s total budget and never starts a new full timeout.
- 已经 `Ready` 的流若线路断开，P1 返回 `SessionLost`，不自动迁移；
- `EgressCommitted` 后任何 timeout/link error/READY 回程丢失都不得提升 attempt；若原 Session 仍可用，只允许相同 attempt/request_id/内容的幂等重发（Wire 分配新的 MessageNumber）读取目标缓存。Session 不可用或总预算到期时返回 `OutcomeUnknown`，交给调用方；新用户 Dial 必须生成新 CircuitID。
- HTTP/业务 Adapter 可以依据幂等性、请求状态和去重能力决定请求重试；Routing 不默认重放；
- “目标可能已处理但响应丢失”归类为 `OutcomeUnknown`，不能仅凭底层连接关闭推断业务未执行。

#### 3.3.6 观测和资源治理

至少保留以下关联信息：NodeID、LinkID + LinkEpoch、CircuitID、open_attempt、目标 NodeID、RouteView 版本和错误类别。观测输出不得包含 Token、私钥或完整敏感握手材料。计数器和状态快照需要区分控制面、转发数据和本地业务，避免把目标端口拒绝误计为全链路故障。

资源上限需要覆盖：

- **认证前 admission**：每个监听器的未认证连接数、待读字节、握手并发、每来源速率和认证 Deadline；超限时在认证前关闭/拒绝，不进入拓扑或无限排队；
- **拓扑与建路**：每来源通告大小/频率、每 Peer 邻接数、并发 CircuitOpen、pre-READY reservation 和待同步队列；
- **数据面**：每流窗口、每流/每 Link/全局缓冲、帧长度、活跃流和后台任务；慢端必须反压，达到上限后用明确资源错误、拒绝新流或 RESET 处理；
- **控制优先级**：控制握手、拓扑、健康和 teardown 帧必须有保留预算或独立队列，不能被业务数据队列完全占满；数据侧仍需按流公平计量，不能只限制共享物理连接。

控制/数据连接池分离与满载按 MessageType 的处置（STREAM 反压→超时 RESET、包/报丢弃+计数、控制不丢）已由 [线上帧协议](internals/wire.md) 冻结；资源表初值见多协议 3.8，实际分配必须计入 Link/流/全局上限；性能目标仍待基准测试，不影响当前字段互操作。

### 3.4 实现自由和待决问题

在没有改变上述外部行为和安全边界的前提下，包内私有函数拆分、goroutine/task 组织、锁/频道实现、编码库选择和日志字段命名可由实现者自主决定。以下项目仍需要确认或实验：

- **SDK 范围：已确认。** 本 feature 的公开 SDK 只承诺 TCP 字节流；产品级 UDP/ICMP/TUN/Wintun/utun 由 [L3 VPN](l3-vpn.md) 定义。
- **路径模型：已确认。** TCP SDK 采用固定源端 Circuit；L3 packet forwarding 使用独立 PathID/Generation 包路径，不能把 L3 包状态混入 TCP Stream。
- **token 策略：已确认。** P1 handshake branch 为 X25519/NodeID、HKDF PSK、Noise_XXpsk3/Noise_IKpsk2，原 Link 内换钥为 ControlType 0x09 + capability bit6（seq1875/seq1885）；安全强度只适用于实际满足 ≥128-bit CSPRNG 生成政策的 token，非空校验不证明熵。人类口令不属于 P1；Session IK/Split/应用域与换钥事务已批准，精确 KDF 字节是实现细化（[安全握手与密钥](internals/security.md) 3.5.3），跨实现互操作仍待验证；按节点撤销/平滑轮换延期。
- **地址分配：已冻结。** VirtualIP 确定性派生与冲突收敛见 [拓扑与路由](internals/topology.md) 3.3.6。
- **健康测量：已冻结。** 本地健康测量和 v0.2 初值见拓扑模块 3.3.2；性能目标待基准测试。
- **传输范围：历史约束已被修订。** 旧“只有加密 TCP、WebSocket 延期”不再是限制：当前 Connector/Connection 共用可靠字节流，TCP/WS/WSS 提供者已存在；HTTP CONNECT 载体仍非实现。物理 CONTROL/data 隔离、共享 WS 队头阻塞与 Link更新进度不因类型抽象自动等价，见 Wire 与连接模块。
- **错误类别：已冻结。** 公开错误类别为 `ErrClosed`、`ErrDeadline`、`ErrNoRoute`、`ErrLinkDown`、`ErrRouteStale`、`ErrPermissionDenied`、`ErrTargetRefused`、`ErrSessionLost`、`ErrResource`、`ErrOutcomeUnknown`、`ErrProtocol`、`ErrCloseTimeout`；公开 Listener 是 `StreamListener.Accept() (Stream,error)`，`NetListener` 提供标准库适配；Network.Close 幂等最多等待 5 秒，超时返回 ErrCloseTimeout，Done 在后台清理完成后关闭。

除安全握手外，上述 API/Circuit 行为是本 Revision 的 proposed contract；Noise/PSK 的强度仅适用于实际符合已选 ≥128-bit CSPRNG token policy 的 secret；配置层非空校验不能证明熵。实现接线、平台互操作和性能基准仍未完成。

## 4. 当前实现状态

| 能力 | 状态 | 入口 |
|---|---|---|
| Config/AgentConfig 校验 | 完成 | `pkg/simpletier/config.go` |
| Network 启动与监听 | 完成 | `pkg/simpletier/network.go` |
| CONTROL Link 认证准入 | 完成 | `network.go` `admitConnectionLink` |
| ListenPacket / DialContext | 完成 | `udp_socket.go` / `stream_runtime.go` |
| 公开 AttachConnection | 完成 | `attach.go` |
| FACT v2 同步与 RouteView | 完成 | `fact_runtime.go` |
| TUN / Wintun / utun | Linux 已验收；Windows/macOS 仅交叉编译 | `internal/agent` |
| 主动 probe owner | 未实现 | — |
| 完整 per-source 速率治理 | 部分 | `rate_enforce.go` |

端到端验收在 `tests/network_runtime/`（跨节点业务数据）和 `tests/tun_acceptance/`
（真实 TUN 设备）。性能数据见 [benchmarks/](benchmarks/)。

## 5. 偏差、未知和继续入口

- `docs/references/TCP虚拟组网设计方案_v0.1.md` 保留为原始设计资料；本文件是 `docs/` 下的 proposed 整理稿，尚未替代原文件。
- `docs/references/easytier-routing-logic.md` 描述 EasyTier 的当前路由观察；它不是 SimpleTier 的实现说明，也未覆盖 EasyTier 全部安全、连接和数据面行为。
- TCP implementation remains partial: typed Config/context/PSK、IdentityStore、provisional attempt0地址和transactional listener/Close既有；CONTROL初建认证、加密CAPABILITY、ContextID sender/receiver epoch与activeLinks已接线。它不读取库内配置文件。失败连接关闭、成功连接由Link生命周期拥有；已有CONTROL保护帧泵与实例EOF退出，没有主动probe owner。FACT v2 consumer、FactStore、AddressFact 与 RouteView 已接线并运行（`pkg/simpletier/fact_runtime.go`），已确认的v2门禁/事实实例/健康Link并存目标已有实现。远端 Dial 已通（`tests/network_runtime/direct_test.go` 的端到端业务数据验收）。仍未完成：主动 probe owner、Windows 侧跨节点业务验收、FACT 同步的直接集成证据、完整 per-source 速率/accountant、不断长流换钥。
- 原 v0.1 中的 15 秒/45 秒通告寿命、20% 切路优势、3 个评估窗口、30 秒冷却、成本公式等仍是建议值，未写入本整理稿的强制契约。
- TCP 固定 Circuit 与 EasyTier 逐跳下一跳转发的差异已明确处理；TCP Stream 与 L3 PacketRoute 的生命周期保持分离，不混用。
- Topology/Path/Circuit/resource contracts remain proposed;高熵token与不断长流正常换钥要求已确认。Noise XXpsk3初建调用和同库双端加密能力互认已经有代码，不是独立互操作或完整长期安全验证；数值使用策略/原Link内更新事务仍未冻结。旧startup微基准和crosscompile记录原样保留，不能冒称当前Link/Session数据平面、Windows/macOS运行或端到端性能。最终当前源码验证与独立复核需主agent收集并绑定，不能沿用旧raw-close的历史记录。
