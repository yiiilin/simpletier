# EasyTier 路由信息如何在节点间传播

本文基于当前 `upstream/main` 的 `e97230751018c1f929c3aa671321e26f9670adbb`，解释 EasyTier 中每个节点如何学习拓扑、计算下一跳，以及数据包如何完成逐跳转发。

## 一、整体模型

EasyTier 不是由中心服务器统一下发路由的传统 VPN，而是一个去中心化的三层虚拟网络。`easytier-core` 持有组网、Peer、路由和数据面逻辑，`easytier` 负责 TUN、真实 socket、DNS 和平台适配。

整体数据路径如下：

```text
本机应用
   |
   v
TUN 虚拟网卡
   | 原始 IPv4/IPv6 报文
   v
CorePacketPlane
   | 根据目标 IP 找 PeerId
   v
PeerOutboundPacketRouter
   |
   +-- 目标 Peer 有直连: PeerMap -> PeerConn
   |
   +-- 没有直连: 路由表找下一跳 -> RelayPeerMap
                                      |
                                      v
                             中间节点逐跳转发
                                      |
                                      v
                                  目标 Peer
                                      |
                                      v
                             HostPacket -> TUN
```

公共共享节点只是一个普通 EasyTier 节点。它通常具有公网监听地址，可以承担引导发现和中继职责，但不是全网唯一的路由控制器。

## 二、节点先建立少量初始连接

节点启动后，会根据 `initial_peers` 或 `-p` 参数连接一个或多个已知地址。这些地址只是引导节点，不是中心控制器。

连接流程大致是：

```text
initial_peers
    |
    v
ManualConnectorManager
    |
    v
TCP/UDP/其他 Tunnel
    |
    v
PeerConn 握手
    |
    v
PeerMap 接纳连接
```

手工连接器负责地址解析、底层传输、重连和超时处理，代码位于：

- `easytier-core/src/connectivity/manual/mod.rs`
- `easytier-core/src/peers/admission.rs`

监听器收到连接后，会进入统一的 `PeerAcceptedTunnelHandler` 和 `PeerConnectionAdmission`，不会绕过握手和网络身份校验。

例如：

```text
节点 A --------+
               +---- 共享节点 S
节点 B --------+
```

A 和 B 只要都能连接 S，就可以先通过 S 加入同一个虚拟网络。

## 三、节点同步的是拓扑事实

节点之间同步的不是最终的 `next_hop`，而是计算路由所需的基础事实。

### 1. Peer 信息

`RoutePeerInfo` 描述节点自身的信息，包括：

- PeerId；
- 虚拟 IPv4/IPv6；
- 发布的 proxy CIDR；
- UDP/TCP NAT 类型；
- 功能标志和 relay 策略；
- secure mode 的 Noise 公钥；
- 凭据、ACL group 和公共 IPv6 信息。

### 2. 直接连接关系

节点还会公布自己的直接连接关系：

```text
A 直接连接 B
B 直接连接 A、C
C 直接连接 B
```

这些关系保存在 `conn_info` 中，用来构建 Peer 拓扑。

路由同步通过自定义的 `SyncRouteInfo` RPC 完成，主要实现位于：

- `easytier-core/src/peers/route/peer_ospf_route.rs`
- `sync_route_with_peer`
- `do_sync_route_info`

同步信息带有版本号、时间戳和会话状态。每个 session 会记录对端已经收到的版本，因此正常情况下只发送变化部分。

## 四、A 是如何知道 C 的

假设网络拓扑如下：

```text
A ===== B ===== C
```

A 只和 B 有直接连接，A 并没有直接连接 C。

B 会向 A 同步：

```text
B 的 RoutePeerInfo
C 的 RoutePeerInfo
B 的连接关系: B -> A、B -> C
```

A 收到后，在本地保存：

```text
节点: A、B、C
边:   A-B、B-C
```

然后 A 在本地构建图：

```text
A --direct--> B --direct--> C
```

所以 A 得出：

```text
目标 C 的下一跳是 B
```

A 不需要先连接 C，也不需要向中心服务器查询 C 的下一跳。路由信息沿着直连边逐步传播，类似 link-state flooding。

## 五、每个节点独立计算路由

节点收到拓扑信息后，会按照以下流程计算：

```text
RoutePeerInfo + conn_info
          |
          v
本地 PeerGraph
          |
          v
Dijkstra
          |
          v
OspfRouteTable
          |
          v
目标 PeerId -> 下一跳 PeerId
```

相关实现：

- `build_peer_graph_from_snapshot`
- `gen_next_hop_map_with_least_hop`
- `gen_next_hop_map_with_least_cost`
- `build_from_snapshot`

代码位置：

`easytier-core/src/peers/route/peer_ospf_route.rs`

EasyTier 维护两套路由策略：

- `LeastHop`：优先选择跳数最少的路径；
- `LeastCost`：优先选择累计延迟最低的路径。

默认情况下，算法先选择最少跳数路径；如果有多条相同跳数的路径，再比较链路成本。启用 `latency_first` 后，会倾向使用最低延迟路径，即使它需要经过更多中继。

因此，同一个目标在不同节点上的下一跳可能不同：

```text
A 看到: C -> B
D 看到: C -> E
```

这是正常现象，因为每个节点根据自己的路由视图和成本信息独立计算。

## 六、PeerCenter 不是中央路由服务器

EasyTier 中的 `PeerCenter` 主要用于补充直连链路的延迟信息，而不是保存唯一的全网路由表。

它的流程是：

1. 每个节点测量自己与直连 Peer 的延迟；
2. 选择一个可达的普通 Peer 作为临时 center；
3. 向 center 报告直连 Peer 和延迟；
4. center 汇总后返回全局链路成本；
5. 各节点使用这些成本重新计算 `LeastCost` 路由。

center 是动态选择的，通常排除 public server，并倾向选择 PeerId 较小的节点。

因此应区分：

```text
SyncRouteInfo  -> 同步拓扑事实
PeerCenter     -> 汇总直连链路延迟
OspfRouteTable -> 每个节点本地计算下一跳
```

## 七、数据包只携带最终目标

本机 TUN 收到 IP 报文后，native 层把它交给 `CorePacketPlane`。核心先根据目标 IP 找到目标 PeerId，然后生成 EasyTier 包头：

```text
from_peer_id = A
to_peer_id   = C
packet_type  = Data
```

A 查询自己的路由表得到下一跳 B，并把包发送给 B。

B 收到后发现：

```text
to_peer_id != B
```

于是 B 不把报文交给自己的 TUN，而是重新查询本地路由表，再转发给 C。

因此数据包中不需要携带完整路径：

```text
A -> B -> C
```

它只携带最终目标：

```text
目标是 C
```

每个中间节点都根据自己的本地路由表决定下一跳。主要实现位于：

- `easytier-core/src/peers/peer_manager.rs:3021`
- `easytier-core/src/peers/peer_manager.rs:3477`

## 八、路由变化如何传播

以下事件都会触发拓扑或路由更新：

- 新增 PeerConn；
- PeerConn 断开；
- UDP/TCP hole punching 成功；
- Peer 被删除；
- 虚拟 IP 或 proxy CIDR 改变；
- 凭据或 ACL group 改变。

`PeerRoute` 会检测本地直连 Peer 快照变化，更新自己的 `RoutePeerInfo` 和 `conn_info`，随后触发路由同步。

过期或不可达的 Peer 信息会被清理，避免旧拓扑永久留在路由表中。路由维护逻辑位于：

`easytier-core/src/peers/route/peer_ospf_route.rs:3737`

## 九、P2P 直连只是给拓扑增加新边

最初 A、B 可能通过共享节点 S 中继：

```text
A -> S -> B
```

随后 `DirectConnectorManager` 会根据路由表找到“可达但没有直连”的节点，查询对方监听地址，并尝试：

- 局域网直连；
- 公网 TCP/UDP 直连；
- IPv6 直连；
- UDP hole punching；
- TCP hole punching。

如果打洞成功：

```text
A -> S -> B
```

就会变成：

```text
A --------direct-------- B
```

这相当于在 PeerGraph 中增加了一条 A-B 边。拓扑同步完成后，各节点重新计算下一跳，后续数据就可能绕过 S。

NAT 策略和打洞代码位于：

- `easytier-core/src/connectivity/direct/mod.rs`
- `easytier-core/src/connectivity/hole_punch/udp/`
- `easytier-core/src/connectivity/hole_punch/tcp.rs`

## 十、虚拟 IP 和子网代理

路由表还维护两类 IP 映射：

```text
10.144.144.2       -> Peer B
192.168.10.0/24    -> 子网代理 Peer B
```

虚拟网络 IP 会精确映射到某个 Peer；proxy CIDR 则通过最长前缀匹配映射到负责该物理子网的 Peer。

native 层会根据已知 proxy CIDR 动态安装 TUN 系统路由。相关逻辑位于：

- `easytier-core/src/peers/route/peer_ospf_route.rs`
- `easytier/src/instance/virtual_nic.rs`

## 总结

EasyTier 的路由学习过程可以概括为：

```text
种子地址建立初始 Tunnel
  -> Peer 握手和身份确认
  -> PeerMap 记录直接连接
  -> 直连邻居交换 RoutePeerInfo 和 conn_info
  -> 路由事实沿拓扑传播
  -> 每个节点本地构建 PeerGraph
  -> 每个节点独立运行 Dijkstra
  -> 得到自己的 next_hop_peer_id
  -> TUN 报文映射到目标 PeerId
  -> 数据包按每一跳的本地路由逐跳转发
  -> P2P 成功后增加直连边并重新收敛
```

所以，`easytier-cli route` 显示的 `next_hop_peer_id` 是当前节点独立计算出的结果，不是中心服务器下发的固定值。不同节点对同一个目标显示不同下一跳，是分布式路由正常工作的表现。
