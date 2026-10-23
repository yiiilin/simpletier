# SimpleTier 系统概要设计


## 摘要与范围

SimpleTier 的目标是一个可复用的 Go 覆盖网络核心，以及面向宿主机的可选 Agent。核心负责身份、认证邻接、拓扑、路由和包/流转发；TCP SDK 提供虚拟 `IP:port` 的 `Dial/Listen`；Agent 负责把同一核心接入系统网络。

P1 的宿主机接入范围已确认为 Linux TUN、Windows Wintun、macOS utun。L3 数据面承载 IPv4 包中的 TCP、UDP 和 ICMP，不实现 IPv6/ICMPv6；TCP SDK 的固定 Circuit 与 L3 packet forwarding 是两种不同的数据路径。SOCKS5/HTTP Proxy 归入 Flow/Proxy 平面且都强制 Basic 认证。外层载体只有加密 TCP framing（帧契约见 [线上帧协议与链路安全](internals/wire.md)）；虚拟设备 MTU 使用内部默认 1380（对齐 EasyTier 默认值）且不开放用户配置；全部已确认范围同一版本交付，实施前完成全量设计冻结。

本概要是对 `docs/references/TCP虚拟组网设计方案_v0.1.md` 的扩展整理稿。核心 SDK 不读取配置文件、不从进程环境补充或展开配置字段；运行态状态全部在进程内存中，不写磁盘，因此重启后 NodeID 与虚拟 IP 都会重新生成——需要稳定地址的部署用 `FixedIP` 钉住。Linux TUN 通过真实设备验收；Windows Wintun 与 macOS utun 只做了交叉编译，未在真实主机验证。

范围：

- P1 包含跨平台 Host Adapter：Linux TUN、Windows Wintun、macOS utun，其地址/路由/驱动/生命周期事务全部属于交付范围；
- IPv4-only packet plane 传输 TCP、UDP、ICMP；虚拟设备 MTU 默认 1380，不开放用户配置；
- 外层载体只有加密 TCP framing；切分/双层加密/防重放/性能契约见 [线上帧协议与链路安全](internals/wire.md)；
- P1 同时保留 TCP SDK 的虚拟 `Dial/Listen` 和源端固定 Circuit；
- SOCKS5（CONNECT/UDP ASSOCIATE）与 HTTP Proxy（HTTP/CONNECT/流式/WebSocket）均强制 Basic 认证；
- 核心不直接调用操作系统网络 API，宿主适配器拥有设备、系统路由、权限和生命周期；
- 不做子网代理；广播/组播、ARP/NDP、Gateway/NAT 不是当前已确认范围；
- 全部已确认范围在同一版本一次性交付；实施前完成全量设计冻结（用户要求“提前将所有内容都设计好再实施”）。
## 1. 领域与文档落点

| 领域 | 稳定职责/边界 | 功能规格目录 | 模块契约目录 | 现有资料与未分析部分 |
|---|---|---|---|---|
| overlay | 节点身份、认证邻接、拓扑、路由、Packet/Flow 双平面、三平台 Host Adapter、TCP SDK 和代理边界 | [多协议覆盖网络](multiprotocol-overlay.md)、[L3 VPN](l3-vpn.md)、[TCP 覆盖网络](tcp-overlay-network.md) | [拓扑与路由](internals/topology.md)、[安全握手与密钥](internals/security.md)、[线上帧协议与链路安全](internals/wire.md) | `../TCP虚拟组网设计方案_v0.1.md`；`../easytier-routing-logic.md`；`../references/多协议虚拟组网设计方案_v0.2.md`；当前仅有 Wire frame 编解码/单元测试切片；完整 Core/Runtime/SDK/Agent 实现仍缺 |

目录中的 feature 描述端到端用户行为；Topology/Routing、Security、Wire Protocol 已有共享模块契约。Config/Runtime、Carrier/Link、Packet Plane、Endpoint/Circuit/Stream、Host Adapter、SystemNetwork 与 Adapter 的责任目前由本概要和相关 feature 划界，后续若形成稳定共享契约再拆分模块文档。

## 2. 模块与职责

| 模块 | 职责 | 对外接口 | 依赖 | 主要文档 |
|---|---|---|---|---|
| Config / Runtime | 读取、校验和规范化配置，初始化进程内状态，管理启动与关闭 | `Config`、`Network`/`Agent` 生命周期 | 标准库、Identity、Host Adapter | [多协议覆盖网络](multiprotocol-overlay.md)、[L3 VPN](l3-vpn.md)、[TCP 覆盖网络](tcp-overlay-network.md) |
| Identity / Security | 生成进程内 NodeID，区分 NetworkID、凭据和节点身份，执行邻接/端到端认证与密钥派生 | 握手与密钥契约 | Core identity/state ports、crypto/storage primitives（不依赖 Runtime 或 Carrier） | [安全握手与密钥](internals/security.md) |
| Carrier / Link | 库拥有 TCP 监听、拨号、退避重连及连接池；Link 负责邻接握手、复用、反压和存活 | `CarrierDialer`、`CarrierAcceptor`、Link 内部接口 | Security key port、Wire 的字节流接口 | [安全握手与密钥](internals/security.md)、[线上帧协议](internals/wire.md) |
| Wire Protocol | 帧定界与上限、双层 AEAD、消息编号/防重放、性能机制 | 独立 byte-stream codec / scheduler | 抽象字节流 port、Security 提供的 key material | [线上帧协议](internals/wire.md) |
| Topology / Routing | 保存从已认证/校验端口接收的版本化节点、地址、邻接事实，构图并计算候选路径 | `RouteView`、IPv4 VirtualIP/32 与 Lane-aware 路径查询 | Core Fact/Identity types、Policy port（不依赖 Link 实现） | [拓扑与路由](internals/topology.md) |
| Packet Plane | 解析/封装 IP 包，按本机 `PacketDevice` 与 RouteView 查目标 VirtualIP/32，逐跳转发 TCP/UDP/ICMP 包 | `PacketRoute`、`PacketDevice` port | Topology/RouteView、Link port、`PacketDevice` port | [多协议覆盖网络](multiprotocol-overlay.md)、[L3 VPN](l3-vpn.md) |
| Flow / Proxy | TCP Stream、UDP Datagram、SOCKS5（强制用户名/密码）、HTTP Proxy（强制 Basic）和 SocketEndpoint 语义 | `Stream`、internal `DatagramSession` Flow port、代理入口 | Routing/Link/Policy ports | [多协议覆盖网络](multiprotocol-overlay.md)、[TCP 覆盖网络](tcp-overlay-network.md) |
| Endpoint / Circuit / Stream | 解析虚拟地址，注册 TCP 服务，按 Path 建立 Circuit，承载半关闭、取消和资源释放 | `Network.DialContext`、`Network.Listen`、`Stream` | Routing、Link/Session | [TCP 覆盖网络](tcp-overlay-network.md) |
| Host Adapter | 拥有 Linux TUN、Windows Wintun、macOS utun、系统地址/路由、权限及生命周期；实现 Core ports | `PacketDevice`、`HostResource` adapter | OS APIs、Core port types | [多协议覆盖网络](multiprotocol-overlay.md) |
| SystemNetwork | 通过 HostResource port 管理地址、MTU、系统路由/DNS 的可回滚事务和所有权 | `RoutePlan`、设备事件 | HostResource/Policy ports | 多协议 feature |
| Adapter | 将 TCP SDK、L3 Agent、SOCKS5/HTTP 接入映射到公开 Core interfaces | `net.Listener`、`net.Conn`、Agent lifecycle | Public Core APIs only | 多协议与两个子功能 |
| Policy | 提供同网默认访问/中继规则、资源 admission 的稳定实现；P1 不包含端口/节点 ACL | `PolicyProvider`、`ResourceAccountant` 实现 | Core value types / ports only；core consumers 仅依赖 `Policy` port | 本 architecture |
| Observability | 收集 status snapshot、metrics、diagnostics 和 structured logs | `EventSink`、query snapshots | Core event/query ports + standard sinks；作为叶子 consumer，不被 core modules import | 本 architecture |

编译期依赖通过单向 ports 组织：Host Adapter 实现 Core 定义的 `PacketDevice`/`HostResource`；Packet Plane 消费这些接口，不依赖平台实现；TCP/HTTP/SOCKS Adapter 只调用公开 Core API，不由 Endpoint 反向导入；Carrier 提供双向字节流 port，Wire Protocol 消费该抽象 port 而不依赖 Carrier 实现。Runtime/Agent 是组合根，负责装配具体 adapter、Carrier、Wire、Route、Endpoint、Policy provider 和 Observability sinks；Policy implementation 实现 Core `Policy` port，Observability 只消费 Core event/query ports，Core packages 不导入其具体实现。Routing 与 Packet Plane 不依赖 `net/http`、WebSocket 或业务 Codec；中继只处理覆盖网络协议和包/流，不解析应用层业务。

## 3. 运行时协作与处理流程

### 3.1 节点启动、入网和收敛

```text
[Config]
   |
   +--校验失败--> [拒绝启动并返回字段错误]
   |
   v
[加载 NodeID / 地址状态]
   |
   v
[启动监听器 + 尝试连接 upstreams]
   |
   +--上游暂不可达--> [保留监听并按退避重连]
   |
   v
[Carrier 建立双向 Link]
   |
   v
[网络身份 / 节点身份 / 能力认证]
   |
   +--认证失败--> [关闭 Link，不发布拓扑和业务能力]
   |
   v
[同步邻接与地址事实]
   |
   v
[本地构建 RouteView]
   |
   v
[节点进入可提供虚拟服务的运行态]
```

上游地址只决定初始拨号，不在逻辑上形成父子关系。零上游节点仍可监听并接受入站连接；没有任何可用 Link 时保留孤立状态。上游故障不是配置错误，但没有可达路径时业务 Dial 必须明确失败。

### 3.2 虚拟 TCP 流建立

```text
[应用调用 DialContext(virtual-ip:port)]
   |
   +--地址/端口/策略非法--> [返回参数或权限错误]
   |
   v
[Endpoint 将 VirtualIP 映射为目标 NodeID]
   |
   +--没有 RouteView--> [返回 NoRoute]
   |
   v
[Routing 过滤候选并选择主路径]
   |
   +--主路径 PATH_OPEN/READY 失败--> [在同一预算内尝试合法备用]
   |
   +--全部失败--> [返回 LinkDown / RouteStale]
   |
   v
[PATH_READY -> SESSION_CTRL(STREAM) -> 所选会话握手完成 -> SESSION_READY]
   |
   v
[Path Active -> E2E CONTROL_RPC(CIRCUIT_OPEN)]
   |
   v
[中继逐跳校验路径位置和预算]
   |
   v
[目标节点端点校验端口授权并打开本地 Listener]
   |
   +--目标拒绝--> [返回 PermissionDenied / TargetRefused]
   |
   v
[返回 CircuitReady]
   |
   v
[固定 Circuit 承载 Stream DATA]
```

路径选择只发生在建路阶段。Circuit 建立后，数据块不重新查全局路由；RouteView 更新也不把已有 `net.Conn` 迁移到另一条线路。断线时已有流返回明确错误，新流再读取当前 RouteView。

### 3.3 L3 packet flow

```text
[OS 应用]
   |
   v
[系统路由 -> TUN/Wintun/utun]
   |
   +--权限/设备失败--> [Agent 启动失败]
   |
   v
[Host Adapter 读取完整 IP 包]
   |
   +--畸形/不支持--> [丢弃并记录 PacketError]
   |
   v
[Packet Plane 解析目标地址和协议]
   |
   +--无 owner--> [NoRoute]
   +--多 owner AddressFact--> [RouteConflict + drop]
   |
   v
[按目标 VirtualIP/32 解析 NodeID，按 PACKET Lane 选择包路径]
   |
   +--PATH_OPEN/READY 失败--> [尝试候选或丢弃并记录]
   |
   v
[PATH_READY -> SESSION_CTRL(PACKET) -> 所选会话握手完成 -> SESSION_READY]
   |
   v
[IP_PACKET Packet Relay 转发]
   |
   v
[远端 Host Adapter 写回系统网络栈]
```

TCP、UDP、ICMP 在 L3 数据面都作为 IP 包传输。Packet Plane 不终止 TCP/UDP，也不替应用重放；TCP SDK 的 `CircuitOpen/StreamFrame` 只用于显式的虚拟 TCP `Dial/Listen`。主机权限、系统地址/路由、MTU 和设备生命周期由 Host Adapter 拥有，不能由可移植核心直接调用。

### 3.4 数据流与归属

```text
[应用 Config]
   | network.name/cidr/token/options
   v
[Runtime 校验与身份状态]
   | NodeID / NetworkID / provisional VirtualIP
   v
[地址声明与冲突收敛]
   |
   +--冲突/撤销--> [换候选或明确失败]
   |
   v confirmed VirtualIP + AddressFact
[已认证 Link]
   | LinkID / capabilities / topology facts
   v
[Topology Store]
   | versioned advertisements
   v
[RouteView]
   | target NodeID -> candidate paths
   v
[Endpoint / Circuit]
   | open / data / fin / reset
   v
[目标 Listener 与应用 Stream]
```

配置输入由 Runtime 拥有；身份密钥和启动世代保存在进程内存；Topology Store 拥有经过认证的节点、邻接、地址和能力事实；RouteView 是由快照计算出的派生数据，不接受业务适配器直接写入；Circuit/Stream 拥有自己的取消、半关闭、窗口和错误状态。无上游时可以保留本地监听和 Endpoint，但 provisional VirtualIP 不进入远端 RouteView，只有声明确认后才能被其他节点解析。Token 不应进入日志或诊断输出。

## 4. 数据流与状态归属

| 对象 | 创建者 | 修改者 | 可见性与清理 |
|---|---|---|---|
| `NodeIdentity` | 首次启动的 Runtime | Identity；静态密钥按本地身份生命周期管理 | 进程内记录；NodeID 不随 VirtualIP 或 Token 改变；`network.token` 属于全组凭据，不提供按节点/无缝轮换 |
| `AddressFact` | 地址分配器 | 地址同步/冲突收敛流程 | 以独立版本事实传播；失效声明不能继续映射新流 |
| `Link` | Carrier/Link | 握手、健康检测、关闭流程 | 邻接双方可见；关闭后从可用拓扑移除 |
| `Advertisement` | 节点本地事实发布器 | 本节点事件和启动世代 | 按版本/有效期传播；接收方不得因转发延长原始寿命 |
| `RouteView` | Routing | 快照重建任务 | 本地派生；版本落后时不得覆盖较新的查询结果 |
| `Endpoint` | `Network.Listen` | Endpoint 注册/关闭 | 只对目标节点的虚拟端口可见；不自动映射宿主机监听端口 |
| `Circuit` | Dial 源端 | 建路、关闭、超时和线路失败 | 单流拥有；失败后不可复用为新流 |
| `Stream` | Circuit | 读写、FIN、RESET、Deadline | 应用可见；不改变共享 Link 的生命周期 |

## 5. 依赖边界与公共约束

- **库与 Agent 分离。** Go 库默认只拥有用户态虚拟 TCP 入口；Agent 才能在获得系统权限后创建 TUN、安装系统路由或接入普通应用。TUN 是 IP 分组接口，不直接等于字节流 API。
- **认证与寻址分离。** NetworkID 用于协议命名空间，NodeID 来自长期节点身份，VirtualIP 属于地址分配；Token 只能作为入网凭据，不能承担 NodeID 或端到端身份语义。
- **控制面与数据面分离。** 控制面传播拓扑和策略，Circuit 在建路时消费路径；数据面沿已建立 Circuit 传输，不逐块重算路径。
- **错误分层。** NoRoute、LinkDown、RouteStale 允许尝试其他合法候选；权限/协议错误直接返回；目标服务拒绝不自动污染整条链路；结果未知不默认重放。
- **有界资源。** 每 Network core 拥有的 heap/state/byte-buffer 总计≤256 MiB；其中全局数据/帧/流缓冲≤64 MiB、FACT Store≤32 MiB、FACT staging≤64 MiB，其余链路/Path/session/统计对象共享剩余额度。每 Peer active Link≤6（3 Lane×2 initiator），replacement drain≤6；每 Link 数据队列≤4 MiB、控制保留≤64帧/256 KiB；认证前连接/握手/每来源速率及 Path/Session/Fact 限额见对应模块。单帧 `length ≤ 65536`、防重放窗口 1024 位是协议硬约束；实现可下调各上限，不得上调而不递增规格修订和基准证据。
- **控制面优先。** 握手、拓扑、健康和 teardown 控制帧需要保留预算或独立队列，不能被业务数据占满；数据按流、Link 和全局层级计量。
- **版本和兼容性。** 通告、握手、Circuit 帧和错误码需要显式版本/能力协商；未知协议不静默降级。

## 6. 部署与运行边界

### 6.1 Go 库

库由宿主应用创建 `Network` 实例并负责其进程级生命周期。库拥有基于标准 TCP socket 的 Carrier：按 `listen`/`upstreams` 监听、拨号和重连，并建立控制/数据连接池；宿主不需要注入 framing Carrier。库不自动读取全局配置、不安装系统服务、不修改宿主路由。只有显式创建 Agent 且 `AgentConfig.inbounds.tun=true` 并具备平台权限时，才会创建 TUN/Wintun/utun 或改系统路由；显式开启后的权限错误不得静默降级。外层载体只有加密 TCP framing。

### 6.2 可选 Agent

Agent 复用 Core，拥有 Linux TUN、Windows Wintun 或 macOS utun 的设备接入、系统地址/路由、权限和生命周期；L3 packet plane 负责 TCP/UDP/ICMP IP 包。权限不足时明确报错；不能只启动核心并宣称普通宿主机应用已经透明互访。Go 库默认不创建这些系统资源，Agent 是 P1 的独立宿主适配层。

## 7. 关键取舍、未知与风险

### 7.1 参考事实与本项目候选方案

父目录 EasyTier 的当前源码观察到：

- `peer_ospf_route.rs` 将 `RoutePeerInfo` 和 `conn_info` 组织成带版本的快照，在节点本地构图并计算下一跳；
- `peer_manager.rs` 转发时以最终目标 PeerID 为目标，中继增加转发计数并再次查询本地下一跳；
- `direct/mod.rs` 将直连成功作为拓扑新增边，而不是另建一套路由表；
- `peer_conn.rs` 将握手、收包循环、Ping/Pong 和 liveness feature 分开；
- `relay_peer_map.rs` 为跨中继的目标节点建立独立会话，并在握手期间对有限数量的待发包做缓冲；
- `config/mod.rs` 的默认 NetworkIdentity 使用空 secret，secret digest 和 `tunnel/encrypt/mod.rs` 的部分密钥派生使用 `DefaultHasher`，同时保留 `NullCipher`/XOR 等可选路径；这些只能作为 SimpleTier 的反例，不能作为强认证或密码学基线。

这些是 EasyTier 的 `observed` 参考，不是 SimpleTier 的批准契约。EasyTier 的 TUN/IP 数据面可作为 L3 参考；其 UDP/QUIC/WireGuard、子网代理和 NAT 穿透能力不能自动等同于本项目 P1 已确认范围。SimpleTier P1 目前只确认 TCP/UDP/ICMP IP 包和三种 Host Adapter。

### 7.2 已确认取舍与待验证风险

- **P1 L3 范围：已确认。** Linux TUN、Windows Wintun、macOS utun 承载 IPv4 包中的 TCP/UDP/ICMP；不实现 IPv6/ICMPv6。
- **MTU：已冻结。** 虚拟设备 MTU 默认 1380（对齐 EasyTier 默认值），不开放用户配置；路径/平台下调由内部处理。
- **子网代理：已确认不做。** 广播/组播、ARP/NDP、Gateway/NAT 需要明确禁用或另行设计。
- **代理认证：已冻结。** SOCKS5 用用户名/密码（RFC 1929），HTTP Proxy 用 Basic（RFC 7617），均为强制项、无 NO AUTH。
- **外层帧约束：已确认。** 用户确认的外层 TCP framing、双层 ChaCha20-Poly1305、代际/消息号 nonce、1024 位重放窗口、64 KiB 单帧上限与控制/数据连接池分离继续适用；Noise-specific HANDSHAKE/SESSION_CTRL payload、Split/KDF 与 IK rekey 属于已选高熵 token 分支的 proposed 详设，完整 v1 布局仍须通过当前独立设计评审/互操作后冻结；若未来新增 PAKE scope，须重新设计对应 schema/key schedule，见 [线上帧协议](internals/wire.md)。
- **TCP SDK 路径模型：已确认。** TCP SDK 源端选择无环路径，每个中继严格执行固定 Circuit；L3 packet forwarding 使用独立的 PathID/Generation 包路径，不复用 TCP 流 Circuit。
- **握手分支与 token 策略：已确认。** P1 握手分支为 X25519 静态身份、HKDF PSK、Noise_XXpsk3/Noise_IKpsk2 与 IK rekey；安全强度只适用于实际按 CSPRNG≥128 bits 生成的 token，非空校验不证明熵或强度。人类口令不属于 P1；完整 Noise/PSK 详设仍须通过当前独立设计评审/互操作后冻结，见 [安全握手与密钥](internals/security.md)。
- **地址分配：已冻结。** 地址由 NodeID 确定性派生 + 历史复用；冲突时低 NodeID 保留、败者递增 attempt 重派；固定地址冲突启动失败；无租约/DHCP/ARP，见 [拓扑与路由](internals/topology.md) 3.3.6。
- **健康测量：已冻结。** 本地健康测量 + v0.2 建议初值（探测 2s、连续 5 次判死、通告 15/45s、每目标/数据 Lane 3 候选、16 跳、性能切路 20%/3 窗口/30s 冷却），见拓扑模块 3.3.2。

## 8. 怎么验证

```bash
go build ./... && go vet ./...
go test ./internal/... ./pkg/...        # 单元与集成
go test ./tests/...                     # 端到端
go test ./tests/tun_acceptance/         # 真实 TUN，需要 root
go test -race ./pkg/simpletier/         # 竞态检测
```

`tests/` 下是端到端验收，跑真实进程和真实网络：

| 目录 | 覆盖 |
|---|---|
| `tests/network_runtime/` | 跨节点业务数据（TCP/UDP 实际收发校验）|
| `tests/tun_acceptance/` | 真实 TUN 设备、系统路由、崩溃清理 |
| `tests/benchmarks/` | 吞吐、延迟、CPU、内存 |
| `tests/roomscale/` | 房间中继的规模与吞吐 |

性能数据见 [benchmarks/](benchmarks/)。

