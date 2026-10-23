# 多协议覆盖网络


## 摘要

本功能把《多协议虚拟组网设计方案 v0.2》落入 SimpleTier 的受管设计。v0.2 的核心结论是：一套控制平面、两类数据平面、独立系统后端。

- **Packet 平面**：转发完整 IPv4 IP 包（TCP/UDP/ICMP），端点操作系统处理协议语义；不实现 IPv6/ICMPv6；虚拟设备 MTU 使用内部默认 1380（对齐 EasyTier 默认值），不开放用户配置；
- **Flow 平面**：TCP 字节流、UDP 数据报以及 SOCKS5/HTTP 本地代理入口；两种代理都强制 Basic 认证；
- **系统后端**：Linux TUN、Windows Wintun、macOS utun 归一化为 `PacketDevice`；
- **共同控制面**：身份、地址、拓扑、路由、健康、认证和安全由两类数据平面共享；
- **外层载体**：只有加密 TCP framing 一种；切分、双层加密、防重放和性能机制见 [线上帧协议与链路安全](internals/wire.md)。

用户已确认：三平台 Host Adapter、IPv4-only、TCP/UDP/ICMP、MTU 默认 1380 且隐藏、不做子网代理、SOCKS5/HTTP 均 Basic 认证、外层仅加密 TCP framing、全部范围同一版本交付（设计冻结前不实施）。本文件把 v0.2 其余能力作为 proposed 目标，不把源文档中的阶段、数值、协议字段或代理行为写成已经批准或已实现的事实。

逐字来源副本：[多协议虚拟组网设计方案_v0.2.md](references/多协议虚拟组网设计方案_v0.2.md)。该副本 SHA-256 为 `3ef7e0b9259f7693a95c966fd6c8aafaea53225749580e04c90efbe19b636fa8`。

现有 TCP SDK 细节见 [TCP 覆盖网络](tcp-overlay-network.md)；拓扑事实和 PacketRoute/Path 查询见 [拓扑与路由](internals/topology.md)。本功能不把 `IP_PACKET`、`UDP_DATAGRAM` 和 `STREAM_DATA` 混成同一种消息或接口。

## 1. 需求说明


### 1.1 使用者、目标与范围

参与方：

- **系统应用**：通过系统地址和路由把 TCP、UDP、ICMP 流量送入虚拟网卡；
- **嵌入式 Go 应用**：使用 TCP SDK，或显式挂载 `PacketDevice`/数据报接口；
- **Host Adapter**：拥有 Linux TUN、Windows Wintun、macOS utun 的设备、权限、地址、路由和事件生命周期；
- **PacketRouter**：以目标 IP/Prefix 找到目标 NodeID，转发完整 IP 包；
- **FlowRouter / Proxy Adapter**：提供 TCP Stream、UDP Datagram、SOCKS5 和 HTTP Proxy 的协议语义；
- **纯中继节点**：只转发加密覆盖消息，不创建 TUN，不把过境包注入自身系统网络。

本功能目标是让节点之间可以只使用 TCP 作为外层载体，同时在内层承载 TCP、UDP 和 ICMP。外层 TCP 的可靠有序传输和队头阻塞不会因为内层是 UDP/ICMP 而消失；载体能力必须在设计和观测中单独表达。

### 两类数据平面

Packet 平面传输完整 IP 包，最终交给远端 `PacketDevice`；Flow 平面传输 TCP 字节流或 UDP 数据报，最终交给 SocketEndpoint、SDK Endpoint 或代理 Adapter。三类载荷使用独立的解析、边界、错误和资源语义。

### 三平台系统接入

P1 目标平台是 Linux TUN、Windows Wintun、macOS utun。平台差异封装在 Host Adapter 中，核心只依赖完整 IP 包的 `PacketDevice` 契约。权限、驱动、entitlement、设备创建和系统路由失败必须明确报告并回滚已创建资源。

### 最小配置与接入开关

保留 `listen`、`upstreams`、`network.name`、`network.cidr`、`network.token` 五类核心字段；兼容 URL carrier scheme 只接受 `tcp`，地址与 canonical IPv4 CIDR 规则见 TCP feature。新增 SDK typed `Targets []ConnectionTarget`，通过宿主 Connector 与 opaque physical endpoint 提供出站连接；Endpoint 仅由提供者解释，Connectors 不读取库内配置文件，连接模块见 [连接提供者与实例](internals/connections.md)。Go SDK 通过 typed `Config` 接收核心值；Agent 通过独立 typed `AgentConfig` 接收相同核心字段与可选 `inbounds`。所有配置值由宿主应用构造并传入 SDK；库不读取 YAML/JSON/其他配置文件，不读取 process environment，也不展开 `${VAR}`，所有字符串均按字面校验。`Config.Validate`/`AgentConfig.Validate` 在任何网络或系统副作用前执行。核心 `Network` 不接受 `inbounds`，也不创建系统资源；Agent 接入必须显式创建。代理入口必须携带非空认证凭据；部署必须提供至少 128-bit CSPRNG bearer token，该校验不能证明熵，不对任意非空输入承诺强认证。

```go
// Values are supplied by the host application.
enableTUN := true
agentConfig := simpletier.AgentConfig{
	Config: simpletier.Config{
		Listen: []string{"tcp://0.0.0.0:7000"},
		Network: simpletier.NetworkConfig{
			Name: "mesh-a", CIDR: "10.30.0.0/24", Token: networkToken,
		},
	},
	Inbounds: simpletier.AgentInbounds{
		TUN: &enableTUN,
		SOCKS5: &simpletier.ProxyConfig{
			Listen: "127.0.0.1:1080", Username: proxyUser, Password: proxyPass,
		},
	},
}
if err := agentConfig.Validate(); err != nil {
	return err
}
```

Go 配置类型分离：`Network` 只接受核心 `Config`；Agent 接入由独立 `AgentConfig` 扩展 `inbounds`。宿主应用必须构造 typed 值并传给 SDK；库不解析配置文件、不读取 process environment，也不展开环境变量。`Config.Validate()` 与 `AgentConfig.Validate()` 在副作用前校验核心字段和已配置 inbounds；`inbounds.tun` 未设置或为 false 时不创建系统设备，只有显式 true 才启动 Host Adapter。代理配置仅存在于 AgentConfig；SDK Core 不忽略 Agent 字段或隐式创建系统资源。

AgentConfig 是与 SDK `Config` 分离的公共 typed DTO，位于 `pkg/simpletier/agent_config.go`；Agent 运行器仍由 `internal/agent/**` 所有。SDK/Agent API 接收结构化值，不提供库内文件读取或 YAML decoder。

```go
package simpletier

type AgentConfig struct {
	Config
	Inbounds AgentInbounds
}

type AgentInbounds struct {
	TUN       *bool
	SOCKS5    *ProxyConfig
	HTTPProxy *ProxyConfig
}

type ProxyConfig struct {
	Listen   string
	Username string
	Password string
}

func (cfg AgentConfig) Validate() error
```

SDK 与 Agent 共用 `network.name`/`cidr`/`token` 和核心选项校验，但 SDK 的 `Config` 不含 `inbounds`，也不会隐式启动系统或代理接入。

Agent 默认不创建系统网卡；只有 `AgentConfig.inbounds.tun: true` 才开启，未配置等同 false。显式开启后权限/驱动不足必须明确失败，不静默降级。SOCKS5 和 HTTP Proxy 默认关闭，只有显式配置监听地址和凭据才开启。嵌入式 Go SDK 默认不创建系统网卡、不修改系统路由。

### PacketDevice 完整包契约

`PacketDevice` 每次读写一个完整 IP 包，不是 TAP 以太网帧，也不携带平台私有的地址族/环元数据。Linux TUN 的 `IFF_NO_PI`、Windows Wintun 的 ring 所有权、macOS utun 的 4 字节地址族前缀都由后端剥离或转换。缓冲不足、包截断、设备关闭和事件错误必须可区分。

### L3 协议承载

Packet 平面支持 IPv4 包中的 TCP、UDP 和 ICMP，不实现 IPv6/ICMPv6。TCP/UDP/ICMP 由远端系统协议栈处理，核心不为每个 TUN TCP 连接创建用户态 TCP 代理，也不把 UDP/ICMP 转成 `net.Conn`。

### 本地代理入口

SOCKS5 支持 CONNECT 和 UDP ASSOCIATE，认证使用用户名/密码（RFC 1929 USERNAME/PASSWORD 子协商）；BIND 可明确返回“不支持”。HTTP Proxy 支持普通 HTTP、CONNECT、流式请求/响应和经 CONNECT 的 WebSocket，认证使用 `Proxy-Authorization: Basic`（RFC 7617）；不默认做 HTTPS 中间人解密。两种代理都强制认证，不提供 NO AUTH 路径；凭据校验失败返回各自协议的标准认证失败响应并限速计数。每入口一组代理用户名/密码，与 `network.token` 分离；多用户与每用户 ACL 不在本次范围。代理可绑定任意可配置地址，包括非 loopback；客户端到代理入口不启用 TLS，监听仅以该入口凭据认证，所有能够到达监听 socket 的客户端均可尝试登录，没有 NodeID/overlay-membership 来源校验或入口来源 ACL。RFC 1929 用户名/密码及 HTTP Basic 凭据可能被链路旁观者捕获并复用。该认证只认证代理客户端，不提供机密性。

代理入口只用其各自配置的用户名/密码认证客户端；客户端可以是非覆盖网络成员，socket 对端 IP 不作为身份或 ACL 输入。通过代理发起的覆盖网络流量使用运行该代理的节点身份和现有策略。默认仅允许目标为本虚拟网络地址，不开放公网/LAN 网关或 DNS 改写；这项目标/出站限制不约束客户端来源。

### 路由、MTU 与系统生命周期

`SystemNetwork` 以可回滚事务管理系统地址、虚拟前缀、MTU、路由和可选 DNS，并为每项副作用维护 write-ahead journal。每次设备/地址/MTU/路由变更前，先记录操作意图及原资源指纹；应用后再记录观测到的结果。**当前 journal 只在进程内存中**（`JournalPath` 恒为空），所以断电/强杀后的恢复路径尚未实现；正常关闭与错误回滚不受影响。崩溃恢复仅撤销此前不存在且当前仍与本实例记录的应用后指纹完全一致的资源；预先存在的资源或被外部改动的资源不得删除/覆盖，冲突进入 `Degraded`。默认只安装虚拟前缀路由，不接管默认路由、不关闭防火墙、不覆盖其他 VPN/容器/虚拟机配置。不做子网代理；MTU 默认 1380 且不可配置；超过当前 MTU 的读入包由 L3 Packet Plane 判 `PacketTooLarge` 丢弃计数，隧道层不分片/重组/合成 ICMP。

### 安全、恢复与资源边界

覆盖信封、端到端消息头和受认证载荷分层；KeyEpoch/MessageNumber 与 PathGeneration 分离，换路径不能复用 AEAD nonce。包源地址、目标地址、通告、代理入口、IPv4 分片基本合法性、重复密文和资源队列都需要有界校验；P1 只发布节点自身 VirtualIP/32，不做任意前缀代理或端口 ACL。Packet/UDP 默认不做业务级 ACK、重放、去重或可靠恢复。**P1 授权模型（最简，完成当前握手后适用）**：被当前 handshake 接受的成员默认允许同网虚拟端口访问、转发和 ICMP；源地址防伪强制。抗猜测强度仅在实际 token 符合已确认的 ≥128-bit CSPRNG policy 时成立；Runtime 的非空校验不能证明熵，本文不对任意非空 `network.token` 保证安全；按端口/节点 ACL、按节点撤销延期。

### 加密外层与性能

外层载体只有加密 TCP framing 一种，不存在明文或弱加密降级路径；切分、双层加密、认证覆盖、防重放和单帧上限由 [线上帧协议与链路安全](internals/wire.md) 拥有。加密不得以关闭安全为代价换性能；性能通过缓冲池、小帧合并写、控制帧优先和控制/数据连接池分离保障，并以基准测试（吞吐、RTT、p95/p99 排队时延、CPU、内存）作为发布门槛，数值目标在基准后冻结。

### Flow UDP 最大 IPv4 datagram

FlowRouter 的 `UDP_DATAGRAM` transport（供 SOCKS5 UDP ASSOCIATE 和本地 UDP SocketEndpoint 使用）必须保留并支持 0..65,507 字节的完整 IPv4 UDP socket payload。固定 Wire frame 上限下使用不超过两片的显式 Flow-fragment schema，并在目的 UDP Endpoint 重组后恰好交付一个 datagram；每片使用独立 E2E MessageNumber，复用同一 AssociationID/DatagramID。每 AssociationID/direction 最多一个 incomplete assembly（payload≤65,507B）；收到更高 DatagramID 时将旧 assembly terminal discard 并标记 consumed 后再接受新 ID。缺片 assembly 120 秒超时、fragment conflict 或 Network shared budget 不足时丢弃整个 datagram并计数，且将 DatagramID 标为 consumed；不做业务 ACK/重试。每 Network≤256 UDP Associations 因而最大重组 payload bound 是 256*2*65,507=33,539,584 bytes，仍计入64MiB/256MiB shared allocator。其他 Flow adapter 输入超过 65,507 时返回 `DatagramTooLarge`。SOCKS5 的 `FRAG!=0` 仍拒绝；FRAG=0 payload 还受 SOCKS 地址头和单个 IPv4 UDP packet 上限约束，回复无法装入时丢弃并计数。该 Flow framing 不改变 L3 IP_PACKET 的分片/MTU规则。

### 1.3 交付边界

用户已确认：**全部已确认范围在同一版本一次性交付**——三平台 Host Adapter、IPv4 TCP/UDP/ICMP 互通、SOCKS5（CONNECT/UDP ASSOCIATE）、HTTP Proxy（HTTP/CONNECT/流式/WebSocket）、加密 TCP 外层、认证组网、地址/拓扑/主备路由、SystemNetwork 生命周期、观测与资源治理。v0.2 的 P1-P4 划分仅作为**实现内部里程碑顺序**（先核心与 Linux，再 Windows/macOS 一致性，再代理与载体细节），不构成分期发布。

同一批准还要求：**实施前完成全部内容的设计冻结**。设计未收敛的条目（握手/密钥交换细节、VirtualIP 冲突、健康阈值、拓扑编码、ACL 数值等）必须先补齐设计并评审，才能开始写业务代码。


以下是拟定验收条件，尚未执行：

| 场景 | 期望结果 | 关联 |
|---|---|---|
| 默认路由 CIDR 拒绝 | AgentConfig 使用 `network.cidr=0.0.0.0/0` | 核心配置在任何系统网络副作用前拒绝，且不得安装 IPv4 默认路由 |
| TUN/Wintun/utun | 三平台设备创建、读写完整包、权限/驱动/entitlement 失败明确 |
| TUN 到 TUN TCP | 两端系统 TCP 栈建立连接，核心不终止内层 TCP |
| TUN 到 TUN UDP | 多个独立 UDP 包保留边界，丢包/重排/迟到不被隐藏重放 |
| TUN 到 TUN ICMP | Echo 和相关错误包按定义转发，TTL/MTU 错误可诊断 |
| SOCKS5 UDP | TCP 关联控制、UDP relay、多目的地、FRAG=0、来源校验和出口端口语义正确；BND.ADDR 不得为 unspecified，BND.ADDR/BND.PORT 必须对应 relay 实际绑定且对该客户端可路由的端点 |
| HTTP Proxy | HTTP、CONNECT、流式响应、WebSocket 101、取消和非幂等请求不盲重试 |
| 外层 TCP 承载 UDP/ICMP | 包可承载但记录可靠有序外层带来的队头阻塞和排队代价 |
| MTU/分片 | 配置无 MTU 字段，设备默认 MTU=1380（平台/路径不支持时可由实现内部下调）；大 UDP、IPv4 DF、PMTU 和分片转发遵守规则，隧道不重组且 P1 无端口 ACL/分片 ACL |
| 代理认证与远程绑定 | 无凭据/错误凭据访问 SOCKS5/HTTP Proxy 被标准方式拒绝；非 loopback 明文监听对任何可达客户端可用且仍强制认证；代理入口不要求客户端属于覆盖网络 |
| 代理出站策略 | 代理客户端使用有效凭据后只可访问本虚拟网络目标；不因此获得公网/LAN 网关能力 |
| SOCKS5 UDP BND | UDP ASSOCIATE 返回实际绑定且对该客户端可达的 IPv4 BND.ADDR/BND.PORT；通配地址不回报 0.0.0.0；不承诺 NAT 穿透 |
| SystemNetwork 崩溃恢复 | 在设备/地址/MTU/路由每个副作用后注入崩溃并重启；只回滚可证明由本实例新建且未被外部修改的资源，保留外部变更 |
| PacketIO 能力就绪 | `packet.ipv4` 只在设备配置完成且读写循环可用后发布；运行中设备读写失效时撤销能力并使相关 Path 不再接收新包 |
| Pending Session 数据 | 在 CONTROL 的 SESSION_READY 与 PACKET/STREAM 独立 TCP Link 上人为制造乱序；ReadyPending 数据只缓冲、不提前交付，提交后按序释放，超限依 MessageType 策略处理 |
| 完整 Flow UDP 最大 datagram | 65,507-byte payload 在 UDP_DATAGRAM 层拆为两帧、目的端重组后逐字节一致；片段乱序/重复/缺失/超时与 shared budget 用例遵守固定规则；Flow 超上限在分帧前返回 DatagramTooLarge |
| 加密外层 | 线路无可读明文；篡改/重放/伪造来源被拒；超长帧在分配内存前拒绝 |
| 单版本交付 | 三平台、TCP/UDP/ICMP、两种代理、生命周期、观测在同一版本全部可验收 | 至 |
| 纯中继 | 中继只转发加密覆盖消息，不创建 TUN、不启用本地 IP forwarding |
| 生命周期 | 启动、睡眠/唤醒、网络切换、崩溃重启和退出只清理本实例资源 |

## 2. 概要设计


### 2.1 控制面、数据面和平台边界

```text
系统应用 -> PacketDevice -> PacketRouter -> IP_PACKET
本地应用 -> SOCKS5/HTTP -> FlowRouter -> STREAM / UDP_DATAGRAM
                                      |
                 Identity / Address / Topology / Policy
                                      |
                 RoutePlanner -> Path / Circuit -> SecureLink
                                      |
                         加密 TCP framing Carrier（控制/数据池）
```

- `PacketDevice` 归一化系统 IP 包读写、MTU 和设备事件；
- `SystemNetwork` 配置地址、路由和可选 DNS，并记录可回滚所有权；
- `Proxy Adapter` 拥有 SOCKS5、HTTP 和私有业务协议语义；
- `PacketRouter` 以目的 IP/Prefix 解析目标 NodeID，转发完整 IP 包；
- `FlowRouter / Endpoint` 以目的 IP + 端口解析 TCP/UDP 出口；
- `Path` 负责可独立交付消息，`Circuit` 负责有状态字节流；
- `SecureLink / Carrier` 负责认证邻接、多路复用、载体和物理连接。

中继只需要理解覆盖网络信封和受认证消息，不需要理解 HTTP 方法、WebSocket 消息、目标系统网卡类型或 TCP/UDP/ICMP 内层内容。

### 2.2 TUN 到 TUN

```text
[宿主 A 应用/内核]
   |
   v
[A PacketDevice ReadPacket]
   |
   v
[按目标 IP 找到 B NodeID]
   |
   v
[认证 IP_PACKET + Path/Generation]
   |
   +--R1/R2 中继--> [B PacketRouter 校验源地址/策略]
                              |
                              v
                     [B PacketDevice WritePacket]
                              |
                              v
                       [宿主 B 内核/应用]
```

TUN 读取方向是宿主待发送包，写入方向是从覆盖网络接收并注入宿主。源/目的虚拟 IP 和端口不默认 NAT；宿主内核处理 TCP 重传、UDP 投递和 ICMP 响应。纯中继不创建 TUN，也不要求启用操作系统 IP forwarding。

### 2.3 Flow 代理路径

```text
[本地应用]
   |
   +--SOCKS5 CONNECT / HTTP CONNECT--> [FlowRouter]
   |                                      |
   +--SOCKS5 UDP ASSOCIATE-------------> [UDP Association]
                                          |
                                          v
                               [目标 IP -> NodeID]
                                          |
                                          v
                                [Stream / UDP_DATAGRAM]
                                          |
                                          v
                                  [远端 Endpoint]
```

代理通常不保留客户端原始物理来源 IP。入口客户端只用每入口配置的 SOCKS5/HTTP 凭据认证；不要求客户端属于覆盖网络，也不使用客户端 NodeID/来源 IP ACL。代理发出的覆盖流量以运行代理的本地节点身份执行，目标默认限制为本虚拟网络地址；目标应用看到的 socket peer 不是原始客户端，失败的请求不自动重试。

### 2.4 数据流

```text
[Config + inbounds]
       |
       +--> [Identity / Address / SystemNetwork]
       |                 |
       |                 +--> PacketDevice / routes / MTU
       v
[Topology + RoutePlanner]
       |
       +--> PacketRoute -> IP_PACKET -> SecureLink
       |
       +--> FlowRoute -> STREAM / UDP_DATAGRAM -> Endpoint
                                      |
                                      v
                              [TCP/UDP socket]
```

`IP_PACKET`、`UDP_DATAGRAM`、`STREAM_DATA` 的载荷边界和失败语义不同。所有数据平面共享身份、地址、拓扑、策略和认证，但不共享错误重试、消息解析或状态对象。

## 3. 详细设计


### 3.1 核心对象和状态所有权

| 对象 | 主要字段/责任 | 所有者 |
|---|---|---|
| `NodeID` | 稳定身份公钥派生值 | Identity |
| `VirtualIP` | 可变地址声明/版本/有效期 | Address/SystemNetwork |
| `LinkID` | 同邻居并行物理连接区分 | SecureLink |
| `PathID/Generation` | 已安装路径和代际 | RoutePlanner/Path |
| `CircuitID` | 一次有状态字节流线路 | TCP SDK/FlowRouter |
| `AssociationID` | SOCKS5 UDP 关联 | Proxy Adapter/UDP Endpoint |
| `SessionID` | 绑定 SessionClass、LaneID、PathID/Generation 和选定 data Link 的端到端状态 | Secure session |
| `PacketDevice` | 完整 IP 包读写、MTU、设备事件 | Host Adapter |
| `IP_PACKET` | 完整 IPv4 分组 | PacketRouter |
| `UDP_DATAGRAM` | 逻辑目的/来源地址和 UDP 载荷 | FlowRouter/UDP Endpoint |
| `STREAM_DATA` | Circuit 上的连续字节、FIN/RESET | FlowRouter/Circuit |

### 3.2 PacketDevice 与 SystemNetwork

统一接口的候选形式：

```go
type PacketDevice interface {
    ReadPacket(context.Context, []byte) (int, error)
    WritePacket(context.Context, []byte) error
    MTU() int
    Events() <-chan DeviceEvent
    Close() error
}

type DeviceEvent struct {
    Kind string
    MTU  int
    Err  error
}
```

一次 `ReadPacket`/`WritePacket` 对应一个完整 IP 包。后端处理平台专属前缀和所有权：Linux 使用 TUN 无附加 PI 头，Windows 处理 Wintun ring 的接收释放/发送分配，macOS 处理 utun 地址族前缀。核心不泄露这些平台细节。

`SystemNetwork` 是可回滚事务：校验权限/网段冲突 -> 保存变更计划 -> 创建设备/分配地址 -> 设置 MTU/虚拟路由 -> 宣布能力就绪 -> 处理设备事件 -> 逆序清理。默认不修改默认路由、不接管全局 DNS、不关闭防火墙、不覆盖其他软件创建的对象。

```text
[Created]
    |
    +--权限/驱动/设备失败--> [Error]
    |
    v
[Configured]
    |
    +--地址/路由/MTU 冲突--> [Error]
    |
    v
[Ready]
    |
    v
[Running]
    |
    +--设备事件/网络切换--> [Running: reconcile]
    +--停止/崩溃恢复--> [Stopping] --> [Closed]
```

设备状态由 Host Adapter/SystemNetwork 修改；Packet/Flow 消息状态由对应 Router/Endpoint 修改。停止后不能留下设备、路由、DNS、防火墙变更或后台读写任务。
### 3.3 Packet、Flow 和 Carrier

逻辑消息类型：

| 类型 | 交付目标 | 可重放/恢复边界 |
|---|---|---|
| `IP_PACKET` | 目标 `PacketDevice` | 不做业务级 ACK/重放；包级重复检测另行定义 |
| `UDP_DATAGRAM` | 目标 UDP socket/Association | 保留 0..65,507-byte datagram 边界；大于单 frame 时最多两片并在目的 Endpoint 重组，不业务重传 |
| `STREAM_DATA` | 目标 Stream/Circuit | FIN/RESET、窗口、取消和结果未知由 Flow 处理 |

覆盖信封和端到端消息头的字段及保护关系已冻结在 [线上帧协议与链路安全](internals/wire.md)：cursor、OverlayHopLimit、剩余预算仅逐跳保护、中继可改；PathID/PathGeneration 双重绑定（逐跳+端到端），任何跳不可改；NetworkID、Src/DstNodeID、MessageType、SessionID、KeyEpoch、MessageNumber、内层长度为端到端认证的不可变字段。二进制偏移布局在实现时冻结为协议 v1，不得改变保护关系。

外层载体**只有加密 TCP framing 一种**（用户已确认）：WS/WSS、HTTP 隧道、私有载体和原生数据报 Carrier 均不在本版本。TCP 外层封装 UDP/ICMP 时继承可靠、有序交付和队头阻塞，这一代价必须在观测中体现；不能把 TCP framing 宣称为原生 UDP 传输。

### 3.4 Linux / Windows / macOS 后端

- **Linux TUN**：使用 `IFF_TUN | IFF_NO_PI`，不启用 TAP；首版单读单写，权限由 Agent/helper 管理；地址、MTU、路由使用系统网络 API，不在核心拼接 shell 命令。
- **Windows Wintun**：区分 Adapter/LUID、Session、Receive/Release 和 Allocate/Send；接收包释放后不得被 goroutine 继续引用；地址/路由通过系统 API 单独配置；驱动/签名/许可作为发布边界。
- **macOS utun**：原生后端剥离 4 字节地址族前缀；桌面 Network Extension 作为独立适配层；签名、entitlement、扩展安装和用户授权需要真机验证。

平台设备未就绪时不得发布 `packet.ipv4` 能力。纯中继不需要平台设备能力。

### 3.4.1 SystemNetwork 事务与恢复

`SystemNetwork` 维护本实例 owner id 和 per-resource journal，记录设备名、地址、MTU、路由及其原始/期望指纹。**当前 journal 只在进程内存中**（`JournalPath` 恒为空），因此下面图中的「崩溃/重启扫描」路径尚未实现；正常关闭的回滚不受影响。状态如下：

```text
[Absent] -> [Prepared] -> [Applied] -> [Running]
   |           |            |
   +--冲突/权限失败--> [Rollback] <---崩溃/重启扫描
                                      |
                                      v
                              [Reconcile/Running]
[Running] --睡眠/网络切换--> [Reconcile] --失败--> [Rollback/Degraded]
[Running] --关闭--> [Rollback] --> [Absent]
```

- `Prepared` 在进程内维护 write-ahead journal，逐项记录资源类型/唯一标识、操作前指纹、期望状态及实例 owner id；每次 OS 副作用前先写入该操作意图。**尚无持久化落盘**，因此不提供跨进程崩溃恢复，成功后读取实际资源并持久化精确的应用后指纹。已存在的完全相同资源标记为 borrowed，不归本实例删除；
- 启动扫描未完成 journal 并逐项 compare-before-delete：资源仍为操作前状态或不存在则不删除；此前不存在且仍与本实例期望指纹完全一致的资源才可回滚；与两种记录都不匹配的资源保留并进入 `Degraded`，不得按接口名或系统快照覆盖/删除；
- 网络切换/睡眠唤醒时重新解析物理 underlay，确保 upstream TCP 不被虚拟路由递归捕获，然后重建 Link/Path；
- 正常关闭、崩溃恢复和权限变化都走同一回滚/重concile路径；外部修改检测到冲突时保留用户修改并进入 `Degraded`，不静默覆盖；
- 具体 Linux netlink、Windows IP Helper/Wintun、macOS utun/Network Extension 调用由平台适配器实现，核心只消费 `SystemNetwork` 事件。

#### 3.4.2 事务状态机与平台适配器的 seam

上一条"核心只消费 `SystemNetwork` 事件"在实现上长期没有落地：`internal/agent` 起初为 linux / darwin / windows 各写了一套 `*SystemNetwork`，三者把**同一个事务状态机**各写一遍——`State`/`Prepare`/`Apply`/`Rollback`/`Close`/`DegradedDetail`/`Journal`/`RetargetAddress`/journal 写记录/degraded 标记/retarget 失败恢复，共 14 个方法。逐字比对三平台方法体后确认：这 14 个在三平台**完全一致**，另 8 个（`applyLocked`/`applyAddress`/`applyMTU`/`applyRoute`/`prepareLocked`/`preflightAppliedOwnership`/`rollbackLocked`/`resetTransactionLocked`）确有平台差异。

差异的性质是**平台能力**，不是同一序列的三份拷贝：

| 步骤 | linux | darwin | windows |
|---|---|---|---|
| `instance`（写 alias marker） | 有 | 只读 | 只读（LUID+index） |
| `mtu` | 有 | 有 | 有 |
| `address` | 有 | 有 | 有 |
| `link_up` | 有 | 有 | **无**（Wintun 适配器无 link-up 概念） |
| `route` | 有 | 有 | 有 |

因此 seam 的边界是：**共享判定流程，平台各自负责所有权证明与步骤清单**。

```
                    SystemNetwork 接口（5 个方法）
                              |
                    +---------+---------+
                    |   共享状态机       |   ← 判定：degraded、journal 时序、
                    | systemNetworkOwner |     状态流转、retarget 前后置条件
                    +---------+---------+
                              | systemNetworkHooks（5 个平台钩子 + 2 个取值钩子）
              +---------------+---------------+
              v               v               v
        linuxSystemNetwork  darwinSystemNetwork  windowsSystemNetwork
        (netlink/ioctl)     (route/utun)        (IP Helper)
```

**共享状态**（`systemNetworkState`）持有 `opts`/`mtu`/`current`/`journal`/`degraded`/`degradedDetail` 与**唯一一把 mutex**；平台 struct 以值内嵌它，故 `n.opts`、`n.journal`、`n.mu` 等既有访问方式不变。平台钩子与共享方法**共用同一把锁**：钩子总是在持锁状态下被调用，这与重构前 `n.mu` 的用法一致。

**平台钩子**（`systemNetworkHooks`）是 seam 上唯一通往 OS 的路：

- `prepareLocked` / `applyLocked` / `rollbackLocked` / `resetTransactionLocked` / `preflightAppliedOwnership`——平台的状态迁移、步骤清单与所有权证明；
- `journalInterfaceName` / `platformAddressFingerprint`——两个取值钩子。

**指纹格式保持各平台原样**。journal 是**每节点一份、三平台共用**，记录里存的就是平台特定的指纹串；共享代码只把指纹当作**不透明字符串**透传，不解释它。统一指纹格式会需要迁移既有 journal 记录，且让记录携带无关平台的字段，因此不做。

**状态守卫与状态迁移在平台钩子里，不在共享代码里**：`Prepare` 要求 `Absent`、`Apply` 要求 `Prepared` 并迁移到 `Applied`、`Rollback` 迁移到 `Degraded` 或 `Rollback`（**不是** `Absent`）。同样地，journal 要求**上一个事务有终态检查点**才能开新事务（`beginTransaction` 的前置条件），而终态检查点由平台的 `rollbackLocked` 写出。这两条契约此前只隐含在平台代码里，现由共享层的测试固定。

**可测性**：共享状态机可完全离线测试——测试替身只需实现平台钩子，无需真实内核、无需 root、无需网络命名空间。这补上了此前只有 Windows 拥有可注入 seam（`windowsIPHelperOps` + `fakeIPHelper`）、而 linux/darwin 的事务测试必须打真实内核（darwin 因此有 9 处 skip）的落差。

**本节范围**：只提取 14 个三平台逐字一致的方法。`applyLocked` 的步骤清单、`rollbackLocked`/`preflightAppliedOwnership` 的所有权证明仍按平台实现——它们的差异来自平台能力与平台数据结构（route/address 状态结构、指纹字段），强行统一会引入 opaque 字段并丢失类型检查。是否进一步纳入 seam 待后续评估。

### 3.5 SOCKS5 / HTTP Proxy

SOCKS5：

- CONNECT 建立 TCP Flow，目标是 IPv4 字面量或域名（域名解析到 IPv4；IPv6 不在范围）；
- UDP ASSOCIATE 由 TCP 控制连接持有生命周期，本地 UDP relay 按 Wire 规定为每个 Association 生成并持有唯一 CSPRNG AssociationID，再管理多个目的地址；成功响应返回该 association 实际 UDP socket 的 IPv4 `BND.ADDR/BND.PORT`。若监听地址是 wildcard，按 TCP 控制客户端选择可达的本地 IPv4 地址，禁止回报 `0.0.0.0`；控制连接关闭时释放 relay。代理不执行 NAT 穿透，部署必须确保所回报 UDP endpoint 对客户端可达；
- 认证为强制用户名/密码（RFC 1929），无 NO AUTH 路径，BIND 明确返回不支持；
- SOCKS5 客户端 datagram `FRAG != 0` 拒绝；内部 Flow UDP_DATAGRAM 分片对 SOCKS 应用透明，但本地 SOCKS UDP 报文仍必须满足自己的单包长度。若远端 UDP reply 加上 SOCKS 地址头后不能放进一个本地 IPv4 UDP packet（不实现 SOCKS FRAG），则丢弃并计数；
- Association 换中继时尽量保留出口 socket/端口，出口状态丢失则报告关联丢失。

HTTP Proxy：

- 支持普通 HTTP、CONNECT、流式上传/响应和经 CONNECT 的 WebSocket；
- 认证为强制 `Proxy-Authorization: Basic`（RFC 7617），缺失/错误凭据返回 407 并限速计数；
- 不默认 HTTPS 中间人解密；
- Body、Trailer、Flush、取消、连接池和重试由 HTTP Adapter 负责；
- CONNECT-UDP/CONNECT-IP 属于独立扩展，不算普通 HTTP Proxy 的默认能力。

### 3.6 MTU、分片和 ICMP

虚拟设备 MTU 使用**内部默认 1380**（对齐 EasyTier 默认值，来源：EasyTier `gen_default_flags()`），不开放用户配置（用户确认）；路径或平台需要下调时由内部调整并产生事件。TCP Carrier 以长度帧承载完整 IP 包并由外层 TCP 分段，因此虚拟 MTU 不机械等于“物理 MTU 减隧道头”；单帧上限 64 KiB 由 [线上帧协议](internals/wire.md) 保证内层包无需隧道层分片。

IPv4-only：默认不改写正常 IP 包，端点内核负责其自身分片/重组；Packet Plane 不在隧道层分片或重组，也不合成新的 ICMP 错误。超过当前虚拟 MTU 的读入包按 PacketTooLarge 丢弃计数；已有 ICMP echo/unreachable/time-exceeded 包照常转发。P1 只发布节点 VirtualIP/32，不实现端口 ACL，因而不需按端口重组/跟踪非首片；未来加入端口 ACL 时必须另行设计有界分片状态。ICMPv6/扩展头不进入本版本。

### 3.7 路由、健康与恢复

PacketRouter 先按目标 IP/Prefix 找 NodeID，再依据 RoutePlanner 的候选路径转发；FlowRouter 对 TCP Stream 和 UDP Association 使用自己的路径/出口状态。包/UDP 消息可在故障后把后续消息换到备用，但不对丢失消息做业务重放；TCP SDK Circuit 默认保持原绑定，除非另行协商恢复。

健康指标区分连接健康、包队列、端到端进展、服务拒绝和 ACL 拒绝。v0.2 的探测周期、通告寿命、路径成本、候选数量、性能切路和冷却值已作为简化初值冻结，数值性能目标仍需基准测试。

#### 3.7.1 Path 生命周期

```text
[RouteView 候选]
       |
       v
[PATH_OPEN: PathID + Generation + nodes/links]
       |
       +--任一跳校验失败--> [PATH_BROKEN]
       |
       v
[PATH_READY: 各跳安装转发表项]
       |
       v
[SESSION_CTRL(PACKET/STREAM): 建立 E2E Session]
       |
       +--所选 Session handshake 失败/超时--> [PATH_BROKEN + rollback]
       |
       v
[SESSION_READY: 各 hop 提交 ReadyPending]
       |
       v
[ACTIVE: IP_PACKET/UDP/Stream 可使用]
```

SESSION_READY 走 CONTROL TCP Link，而 E2E 数据走独立 PACKET/STREAM TCP Link，两条连接之间没有传输顺序保证。初建 Session 时，hop 在 `ReadyPending` 收到匹配的逐跳认证 E2E frame 先入有界队列，不交付/转发；匹配 SESSION_READY 提交 Path Active 后按 data-Link 接收顺序释放。对已 Active Path 的 rekey，Path 维持 Active，但对应 Session 建立 `RekeyPending(target_epoch,attempt)`：旧 epoch 继续收发；Session egress 在每个 direction 发送首个 target-epoch frame 前先排空已提交的旧 epoch 队列，此后不再提交旧 epoch frame，保证 Stream 的 stream_seq 顺序跨 epoch 保持；hop 在匹配 SESSION_READY 前只暂存 target-epoch frame，不能将其交付或推进 replay/epoch/grace；SESSION_READY 到达后才切换 epoch、drain 队列并按 E2E AEAD/replay 规则提交。初建与 rekey 共用 per Path/Session/direction 最多65,897 bytes pending wire queue（含一个最大 UDP_DATAGRAM 两片及 prefix；也覆盖单方向一个64KiB Stream credit window）；metadata 另计 Network-owned state；所有 retained bytes 计入每 Link/Network 聚合上限；Packet/UDP 满时丢弃计数，STREAM_DATA/CONTROL_RPC 反压并按策略 RESET。SESSION_CTRL/rekey 未在 30 秒 cache/reservation TTL 内完成时丢弃 pending queue，发送 PATH_BROKEN 并以 SessionLost 结束该 Path 绑定的 Stream；不回滚或跨 Path 重用 epoch/session key。

`PathID` 由源端生成（CSPRNG u64，进程生命周期内不可复用），`PathGeneration` 初始为 1、每次替换递增；每个 Path 是 lane-specific（`LaneID=PACKET/STREAM`），`PathDigest = SHA-256("simpletier-path-v1" || PathID:u64be || Generation:u32be || LaneID:u8 || ViewVersion:u64be || node_count:u8 || node_ids[0..node_count-1]:16B || link_count:u8 || (LinkID:u64be || LinkEpoch:u64be)[0..link_count-1])[0:32]`，字段顺序与 PATH_OPEN 固定载荷一致。PATH_OPEN/READY/BROKEN 是 `FrameKind=ROUTE_CTRL` 的 `MessageType`，不需要端到端钥匙。每一跳表项为 `(PathID, Generation, LaneID, direction) -> expected_node, incoming LinkID+LinkEpoch, next LinkID+LinkEpoch, incoming_cursor, next_cursor, state, expires_at`，正向/反向各一项，状态为 `Opening -> ReadyPending -> Active -> Broken/Expired`；PATH_OPEN 起始 cursor=0，源节点先校验并转给 cursor+1；每个中继只接受自身 NodeID 与 cursor 对应，PATH_READY 从目标 cursor 倒序沿反向表项返回。Opening Path TTL=45 秒；PATH_READY 后源端与每个已安装 hop 都创建 `ReadyPending`，各自期限 30 秒；若匹配的 SESSION_READY 未在期限内到达该 hop，则该 hop 本地回滚并拒绝迟到 SESSION_READY，源端发送 PATH_BROKEN/rollback，所有 hop 幂等清理；pre-READY reservation TTL=30 秒；只有 SESSION_READY 成功才进入 Active。Active Path 不按墙上时间过期，只在 LinkEpoch 失效、PATH_BROKEN 或无绑定 Session 且空闲 30 秒后清理。相同 PathID+Generation+LaneID+Digest 的重复 OPEN/READY/BROKEN 幂等；相同 PathID+Generation+LaneID 但 digest 不同直接拒绝；PATH_BROKEN/rollback 将状态置 Broken，旧 state 不覆盖更高 Generation；PATH_OPEN 部分成功失败时按已安装项逆序幂等回滚，回滚丢失可由后续过期清理完成。ROUTE_CTRL 的 PATH_OPEN/READY/BROKEN 与 SESSION_CTRL/SESSION_READY 逐跳沿同一 node 序列的 CONTROL Lane Link 传输；相邻节点若有两个方向 initiator 的 CONTROL Links，双方选择当前已认证 active 的 LinkID 原始 u64 字典序最小者作为该段 bootstrap Link。PATH payload 中的 LinkID/LinkEpoch 列表只指 PACKET/STREAM data Lane。每个 hop 必须同时存在所选 CONTROL Link 和 Path 指定的 data Link，否则 PATH_OPEN 拒绝；成功安装后 SESSION_CTRL 经 CONTROL Link，到达目标并完成所选 Session handshake 后 SESSION_READY 提交 ReadyPending。

`SessionID` 的所有权范围是 `(NetworkID, SrcNodeID, DstNodeID, PathID, PathGeneration, SessionClass)`：同一 Path/Generation/Class 只建立一个 session，重试复用其 attempt；不同并发 Path 各有独立 SessionID/root key，不进行节点对之间的全局 SessionID 选主。每个 session 仍受 Path 表、ReadyPending 和 Network 聚合资源上限约束。

### 3.8 已冻结决策与测量项

已冻结（用户确认，2026-09-22）：IPv4-only；外层仅加密 TCP framing；MTU 默认 1380 且不可配置；不做子网代理；SOCKS5/HTTP 均强制 Basic 认证；帧/加密/防重放整包见 [线上帧协议](internals/wire.md)；三平台系统事务全部属于交付范围。当前对话另确认：允许非 loopback 代理监听且客户端到代理入口无 TLS（风险已接受）；`inbounds.tun` 为显式 opt-in。SDK/Agent 配置分离；Flow UDP 完整 IPv4 payload 上限按 Fragment 扩展实现分片重组，L3 IP_PACKET 与 SOCKS5 `FRAG` 规则不变。

其余设计项按“最简方案”处理：

- **token 策略：已确认。** 共享信任组采用 name+token；P1 握手分支为 X25519 静态身份、HKDF PSK、Noise_XXpsk3/Noise_IKpsk2，原 Link 内换钥为 ControlType 0x09 + capability bit6（seq1875/seq1885）。安全强度仅适用于实际满足 ≥128-bit CSPRNG 生成政策的 token，非空校验不证明熵；人类口令不属于 P1。Session IK/Split/应用域与换钥事务已批准，精确 KDF 字节是在该批准内的实现细化（[安全握手与密钥](internals/security.md) 3.5.3）；跨实现互操作仍待验证；按节点撤销/平滑轮换仍明确延期。
- **地址分配：已冻结**——确定性地址派生 + 低 NodeID 胜出 + 固定冲突失败，见 [拓扑与路由](internals/topology.md) 3.3.6；
- **健康测量：已冻结**——本地健康测量 + v0.2 建议初值（2 秒探测、5 次判死、15/45 秒通告、每目标/数据 Lane 3 候选、16 跳、20%/3 窗口/30 秒切路），见拓扑模块 3.3.2；
- **帧格式：已冻结**——手工定长二进制+严格版本、有向邻接、每目标/数据 Lane 最多 3 候选、本地成本、Stale 视图仅服务未受影响路线，见拓扑模块 3.3；
- **D-L3-007：已冻结**——P1 授权模型和下表资源硬初值已冻结；实现可下调，不得上调而不递增规格修订；性能数值目标仍待基准。

| 资源项 | P1 硬初值 | 资源项 | P1 硬初值 |
|---|---|---|---|
| 每 Peer active Link 数 | ≤6（3 Lane × 2 initiator）+≤6 replacement drain | 每链路数据队列 | 64 帧且不超过 4 MiB |
| 每链路控制保留 | 64 帧且不超过 256 KiB | 每监听并发握手 | 16 |
| 认证前每监听器连接 | 128 | 每连接待读 | 8 KiB |
| 每来源新连接 | 4/s，burst 8 | 单流 credit | 256 KiB（非预分配） |
| 每节点活跃流 | 4096 个逻辑流 | 单流实际缓冲 | 64 KiB |
| 每 HostAdapter 包队列 | 1024 包且不超过 2 MiB | 每节点 Path 表项 | 1024 |
| PATH_OPEN 并发/Opening TTL | 64 / 45 秒 | ReadyPending/Session_CTRL cache | 30 秒 / 64 条 |
| 每 Peer pre-READY OpenRecord/cancel tombstone | ≤64 / 30 秒；满额时独立设置该 Peer `CircuitOpenBlockedUntil=now+30s` fence，不随无关 reservation 释放而提前解除 | 每来源 FACT staging | 8 MiB、2 个 snapshot |
| FACT_PAGE / snapshot | ≤128 FactRecords/48 KiB page；≤8192 records/64 pages/3 MiB | FactPayload / encoded FactRecord / FactStore | ≤4 KiB / ≤4,245 bytes / ≤32 MiB incl. record/provenance |
| 每 Network FACT staging | 64 MiB | 每 FactKey provenance source | 8 |
| 每 Network live/highwater keys | 8192 / 16384 | 全局数据/帧/流缓冲 | 64 MiB |
| Network-owned heap/state/buffers | 256 MiB | 每 Peer Packet rate | 10000 pps、burst 2000 |
| Per Link control rate | 100 msg/s、burst 200 | Network control rate | 10000 msg/s、burst 20000 |
| 控制面保留预算 | 64 帧/Link、网络总计≤8 MiB | 代理入口连接 | 256 |
| UDP Association/reassembly | ≤256 per Network；≤1 incomplete assembly per direction/Association，payload≤65,507B | UDP 关联/assembly idle TTL | 120 秒 |

上表各项均为上限而非逐 Link/流预留；所有分配先向统一 Network allocator 记账，包含完整线帧字节（含 4-byte length prefix）及拥有的 buffer/state。每 Link 的 256 KiB 控制保留是上限，不保证在每个 Link 同时保留满额；网络共享控制池最多 8 MiB，和全局 64 MiB/256 MiB 上限同时约束。达到聚合上限后，Packet/UDP 丢弃并计数，Stream 反压并在超时后返回资源错误/RESET；控制帧不得静默丢弃，无法进入共享控制池时走有界 Link teardown/资源失败。

当前 token policy 已确认：P1 仅支持 ≥128-bit CSPRNG bearer secret 与选定的 Noise/PSK proposed 分支，人类口令不在范围。剩余发布开放项：**性能数值目标**（由基准测试确定）；当前 handshake/schema 详设仍须通过独立设计评审/互操作后冻结。定期换钥时长、重放违规断链阈值等实现初值压测后调整。按节点撤销、平滑轮换、多用户代理 ACL 为明确延期项，不属于本版本设计缺口。

## 4. 实现状态

| 能力 | 状态 |
|---|---|
| Packet 平面（Linux TUN）| 已通过真实设备验收 |
| Packet 平面（Wintun / utun）| 仅交叉编译，未在真实主机验证 |
| Flow 平面（TCP/UDP/SOCKS5/HTTP）| 已实现 |
| 中继与房间隔离 | 已实现，规模数据见 [benchmarks/12-relay-scale.md](benchmarks/12-relay-scale.md) |


## 5. 偏差、未知和继续入口

- v0.2 原文已逐字保存于 `docs/references/多协议虚拟组网设计方案_v0.2.md`；本文件是当前项目的受管整合稿，不是对原文逐段复制。原文中的 IPv6、MTU=1280、NO AUTH、多载体和 P1-P4 分期建议已被用户决策取代，以本文件为准。
- 用户已确认范围见摘要与 3.8；SOCKS5/HTTP 多用户、CONNECT-UDP/IP、原生数据报、代理流恢复、Gateway/DNS 仍是 v0.2 后续扩展，不在本版本。
- 当前实现：`internal/agent` 已有认证 SOCKS5/HTTP CONNECT adapter、`device.go`/Linux TUN、`sysnet_linux/darwin/windows` 与 native SystemNetwork；Linux TUN 的真实设备 runtime/事务/取消/恢复已通过验收；Windows/macOS 仅有编译期代码与 native SystemNetwork 实现，用户明确回答“当前没有这两类测试主机”，在真实主机上未验证。`internal/flow`、`internal/proxy`、`internal/host` 目录仍不存在，不得宣称 empty 实现。Agent/TUN/Flow/Proxy 到真实 Network 的接线与端到端验收仍未完成。
- 下一步：实现 Agent/TUN、Flow/Proxy runtime 并接线到真实 Network；Noise/PSK interop、三平台 driver/entitlement 与性能仍需各自验收，不能只完成 Linux TUN 就宣称完整交付。
- ** Ownership/当前事实（observed，2026-10-08 晚，docs-only）**：本 feature 作为 MESH natural module 现 primary Owns `internal/flow/**` 与 `internal/budget/**`（shared multiprotocol Network allocator），并持有 Agent runtime/udp 的精确 `pkg/simpletier/agent_*.go`；不建立与 L3 `internal/packet/**` 或 TCP runtime 的二重 primary。
- Flow Reply：private Receipt API 已有真实 UDP max request/reply 组件；公开 UDP `Network.ListenPacket` 的 core SDK tests 由 worker 321 公告，**实际 hash 待收齐后绑定**，尚非完整 SOCKS 业务 E2E。
- 平台能力：native Linux netNS/TUN cap 可用；`9cf` raw-length framing 只是 prototype **capability，不是业务功能**；SDK 真 Agent test writer `0f`（新 `tests/tun_acceptance`、`examples/tun-agent`）使用实际 `NewAgent`，正在运行。按用户明确口径“framing 不当完整验收”，文档不把该 cap prototype 写成已验收。
- L3 native acceptance 引用：L3 新测试 `tests/tun_acceptance/**`、`examples/tun-agent/**` 由 FEAT-L3-VPN primary Owns（E-L3-008）；MESH 的 `internal/agent/**` 只引用该 native acceptance，不重复 Owns，避免二重 primary。SDK core packet 已经由 native TUN 接线（Linux），Windows/macOS host 仍 unverified。
- 新增源码注释约定：`//doc <raw path>` 不追加 requirement 尾部；owner `iphelper_windows.go` 的额外 `` pointer 需由 sole SysNet owner 在未来注释 worker 修复，**不得靠改 Owns 隐藏**。
