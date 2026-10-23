# SimpleTier SDK 使用指南


本文件回答三个问题：**怎么跑起来**、**每种场景怎么写**、**出问题查什么**。

---

## 1. 五分钟跑通两节点

### 节点 A（监听方）

```go
package main

import (
    "fmt"
    "net"
    "github.com/yiiilin/simpletier/pkg/simpletier"
)

func main() {
    n, err := simpletier.NewNetwork(simpletier.Config{
        Listen: []string{"tcp://0.0.0.0:11010"},
        Network: simpletier.NetworkConfig{
            Name:  "demo",
            CIDR:  "10.100.0.0/24",
            Token: "shared-secret-at-least-16-bytes",
        },
        Options: simpletier.RuntimeOptions{FixedIP: "10.100.0.2"},
    })
    if err != nil {
        panic(err)
    }
    defer n.Close()

    // 在虚拟 IP 上监听；对端通过 overlay 连到这里
    ln, err := n.Listen("tcp", ":8080")
    if err != nil {
        panic(err)
    }
    fmt.Println("listening:", ln.Addr())

    for {
        stream, err := ln.Accept()
        if err != nil {
            return
        }
        go func(s simpletier.Stream) {
            defer s.Close()
            s.Write([]byte("hello from A\n"))
        }(stream)
    }
}
```

### 节点 B（连接方）

```go
n, _ := simpletier.NewNetwork(simpletier.Config{
    Upstreams: []string{"tcp://A的IP:11010"},   // 主动连 A
    Network: simpletier.NetworkConfig{
        Name:  "demo",                          // 必须相同
        CIDR:  "10.100.0.0/24",                 // 必须相同
        Token: "shared-secret-at-least-16-bytes", // 必须相同
    },
    Options: simpletier.RuntimeOptions{FixedIP: "10.100.0.3"},
})
defer n.Close()

// 连 A 的虚拟 IP:8080（不是物理 IP）
s, err := n.DialContext(context.Background(), "tcp", "10.100.0.2:8080")
```

### 同一进程内的多个 Network

**优先一个进程跑一个 Network。** 多个 Network 挤在一个进程里会互相争抢 CPU，每对吞吐明显
下降：同一对节点在独立进程里能到 40 MB/s，同进程内只有 11 MB/s。

必须同进程跑多个 Network 时，它们的状态天然隔离，不需要额外配置——只要确保 CPU 够用。

没有任何载体的 Network（既无 `Listen` 也无 `Upstreams`/`Targets`）是合法的：所有连接都可以经 `AttachConnection` 进入。这种情况不需要额外开关。

### 三个必须一致的字段

| 字段 | 作用 | 不一致的后果 |
|---|---|---|
| `Name` | 网络身份的一部分 | 两条互不相干的网络，永远不收敛 |
| `CIDR` | 网络身份的一部分 | 同上 |
| `Token` | 认证凭据 | 握手失败 |

**`Name` + `CIDR` 共同构成网络身份。** 只改其中一个也会导致对端看不见你。这是最容易踩的坑。

---

## 2. 使用场景

### 场景一：把内网服务暴露给远端（TCP 端口转发）

```go
// 远端节点：监听虚拟端口
ln, _ := n.Listen("tcp", ":5432")
for {
    client, _ := ln.Accept()
    go func(c simpletier.Stream) {
        defer c.Close()
        // 连本地真实的 Postgres
        real, err := net.Dial("tcp", "127.0.0.1:5432")
        if err != nil {
            return
        }
        defer real.Close()
        go io.Copy(real, c)
        io.Copy(c, real)
    }(client)
}

// 本地节点：像访问本地端口一样访问远端
conn, _ := n.DialContext(ctx, "tcp", "10.100.0.2:5432")
```

实测性能：**179 MB/s 下载，171 MB/s 上传**（10 MiB 载荷，本机 loopback 载体）。

### 场景二：三节点中继（A 和 B 不直连）

```go
// R（中继）：只监听，不配 upstream
relay, _ := simpletier.NewNetwork(simpletier.Config{
    Listen:  []string{"tcp://0.0.0.0:11010"},
    Network: netCfg,
    // Options.Relay 留空即允许中继（默认 true）
})

// A 和 B 都只连 R
a, _ := simpletier.NewNetwork(simpletier.Config{
    Upstreams: []string{"tcp://R:11010"},
    Network:   netCfg,
})
b, _ := simpletier.NewNetwork(simpletier.Config{
    Upstreams: []string{"tcp://R:11010"},
    Network:   netCfg,
})
```

**关键**：不要显式设 `Options.Relay = false`。那会移除 relay 能力，导致多跳 STREAM 路由失败（`route policy denied`）。

量级参考：本机回环上，经中继的 echo 吞吐比直连低约 8%（三次运行 −1%~16%，落在噪声范围内）。中继只做逐跳加解密、不解端到端密文，所以额外成本是多一跳的跳层开销，而非解密整条载荷。详见 `benchmarks/09-baseline.md`。

### 场景三：一个进程同时服务 WebSocket 与 TCP 对端

```go
// 内置 TCP 载体
n, _ := simpletier.NewNetwork(simpletier.Config{
    Listen:    []string{"tcp://0.0.0.0:11010"},
    Upstreams: []string{"tcp://hub:11010"},
    Network:   netCfg,
})

// 同一 Network 上再挂一个 WebSocket 入口
http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
    ws, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        return
    }
    conn, _ := simpletier.NewWebSocketConnection(ws)
    // Role: Responder 表示这是被动接受的一方
    _, err = n.AttachConnection(r.Context(), conn, simpletier.AttachOptions{
        Role:      simpletier.LinkRoleResponder,
        Negotiate: true,
    })
})
```

完整可运行版本见 `examples/gin-edge/`。

### 场景四：UDP 数据报

```go
pc, err := n.ListenPacket("udp", "10.100.0.2:5353")
if err != nil {
    return
}
buf := make([]byte, 1500)
for {
    n, addr, err := pc.ReadFrom(buf)
    if err != nil {
        return
    }
    pc.WriteTo(buf[:n], addr)
}
```

### 场景五：L3 隧道（TUN，让整台机器走 overlay）

```go
tunEnabled := true
agent, err := simpletier.NewAgent(simpletier.AgentConfig{
    Config: simpletier.Config{
        Upstreams: []string{"tcp://hub:11010"},
        Network:   netCfg,
    },
    Inbounds:   simpletier.AgentInbounds{TUN: &tunEnabled}, // *bool，不是 bool
    DeviceName: "simpletier0", // 必填；同机多 Agent 必须不同
})
```

需要 root/管理员权限。完整示例见 `examples/tun-agent/`。

**`DeviceName` 是必填项**，因为 TUN 会在宿主机上创建网卡和路由，进程被强杀时它们会留下来。
名字是崩溃后唯一还能找到的线索，所以不能交给系统随机分配（`tunN` 重启后可能变成别的）。

下次启动时按名字找到这个网卡，再看它是否带着本节点的虚拟 IP：

| 情况 | 处理 |
|---|---|
| 网卡不存在 | 正常创建 |
| 存在，且带本节点的虚拟 IP | 判定为上次残留，删除后重建 |
| 存在，但带的是别的地址 | **拒绝启动**，返回 `ErrDeviceInUse` 并指出是哪个网卡 |

第三种情况是保护：光凭名字无法证明归属，直接删除会毁掉别的程序的网络配置。
遇到时按错误提示手动确认并删除。

---

### 场景六：一台中继服务多个隔离房间

场景二是「所有人共用一个网络」。如果你要**一台中继同时服务多个互不可见的网络**，用 `relay` + `room` 包。

房间由 Token 区分。同一个 Token 的成员在同一个虚拟网络里，不同 Token 完全隔离——即使它们用同一个 CIDR。

中继侧：

```go
import (
    "github.com/yiiilin/simpletier/pkg/simpletier/relay"
    "github.com/yiiilin/simpletier/pkg/simpletier/room"
)

r := relay.New(relay.Options{Rooms: room.Options{
    Name: "office",              // 所有房间共用
    CIDR: "10.100.0.0/24",       // 所有房间共用；各房间地址空间独立，不冲突
    // 房间状态全部在进程内存中：token 不同即房间不同，重启后房间自然消失，
    // 成员重新加入即可。没有需要指定的目录。
}})
defer r.Close()

// 两个入口各自一个端口，可以只起需要的那个
go r.ServeTCP(ctx, ":22020")        // 内网节点
go r.ServeWebSocket(ctx, ":22021")  // 公网节点（ws://.../ws?room=<token>）
```

两个入口是**独立的监听**，各占一个端口，可以只起一个。地址传空字符串则用默认端口：`relay.DefaultTCPPort`（22020）和 `relay.DefaultWebSocketPort`（22021）。

成员侧：

```go
n, _ := simpletier.NewNetwork(simpletier.Config{
    Network: simpletier.NetworkConfig{Name: "office", CIDR: "10.100.0.0/24", Token: token},
})
link, err := relay.JoinRoom(ctx, n, "relay-host:11010", token)
defer link.Close()

// 之后就像在同一局域网
n.Listen("tcp", ":8080")
n.DialContext(ctx, "tcp", "对端虚拟IP:8080")
```

**中继是本机端口安全的**：中继不开 TUN，虚拟 IP 只存在于应用层，不是系统接口地址。所以中继上监听 `0.0.0.0:22` 的 SSH，房间成员访问 `中继虚拟IP:22` 会被拒绝。实测 `VIP:22 → target refused`。

### 场景七：把中继挂进自己的 HTTP 服务（gin 等）

`Relay.ServeWebSocket` 会自己建 mux 和监听端口，插不进已有路由。要在自己的 gin/net-http 路由里用，改用 `Relay.Attach`：

```go
func (s *Server) wsHandler(c *gin.Context) {
    if !s.authenticate(c) {          // 你自己的认证，中继看不到这一步
        c.AbortWithStatus(401)
        return
    }
    ws, err := s.upgrader.Upgrade(c.Writer, c.Request, nil)
    if err != nil {
        return
    }
    conn, _ := simpletier.NewWebSocketConnection(ws)
    link, err := s.relay.Attach(c.Request.Context(), conn, c.Query("room"))
    if err != nil {
        return                        // 未签发的 Token 在这里被拒
    }
    defer link.Close()
    <-link.Done()
}
```

`Attach` 只接收「已建立的连接 + 房间 Token」，路由、路径、认证都归你。

#### 查看房间与连入者

```go
// 有哪些房间
for _, info := range r.List() {
    fmt.Printf("room=%s carriers=%d vip=%s created=%s\n",
        info.ID[:12], info.Carriers, info.VirtualIP, info.Created.Format(time.RFC3339))

    // 房间里有谁：NodeID、虚拟 IP、物理连入地址
    members, ok := r.Members(info.ID)
    if !ok {
        continue                     // 房间已销毁
    }
    for _, m := range members {
        fmt.Printf("  node=%s vip=%v from=%s\n",
            m.NodeID[:12], m.VirtualIPs, m.PhysicalAddr)
    }
}
```

`room.RoomInfo` 只暴露 Token 的哈希（`ID`），从不返回 Token 本身——日志和监控里不会泄漏房间钥匙。

`info.Carriers` 是**载体连接数**，不是人数：一个成员要开 CONTROL 和 STREAM 两条载体，所以通常是人数的两倍。人数用 `Members()` 返回的切片长度。

`m.PhysicalAddr` 是连入者的真实来源地址。TCP 入口自动填；自己用 `Attach` 挂路由时，改用 `AttachFrom` 并传入你手上的来源地址（例如 `c.Request.RemoteAddr`）。用 `Attach` 则 `PhysicalAddr` 为空。

### 房间 Token 由谁签发

默认任何 Token 都能建房。要只接受自己签发的 Token，开 `RequireIssued`：

```go
r := relay.New(relay.Options{Rooms: room.Options{
    Name: "office", CIDR: "10.100.0.0/24",
    RequireIssued: true,
}})

// 业务层认证通过后签发
token := mintToken()
r.Rooms().Issue(token)     // 记录为已签发

// 之后客户端带这个 token 才能进；自造的 token 被拒（room.ErrNotIssued）且不建房
r.Rooms().Revoke(token)    // 撤销
```

典型流程：业务层认证 → 生成 Token → `Issue` → 交给客户端 → 客户端建 WebSocket 带 Token 加入。

---

### 场景八：TUN 与「是否暴露本机端口」

`AgentInbounds.TUN` 是**双向**的开关，不是单纯「能不能访问对端」：

| TUN | 本机能否用虚拟 IP 访问对端 | 对端能否访问本机所有端口 |
|---|---|---|
| `true` | ✓ 本机所有程序都能用虚拟 IP | ✓ 包括 SSH 等全部物理端口 |
| `false` | ✗ 只能用 `Network.DialContext` | ✗ 只能访问显式 `Listen` 的虚拟端口 |

**中继不要开 TUN**：开了之后虚拟 IP 会成为真实接口地址，监听 `0.0.0.0` 的服务立刻对房间可见。

### 接入已有连接：两种方式，别选错

SDK 有两个入口处理「连接已经由别人建好」的情况，用途完全不同。

**`AttachConnection`——把它变成 overlay 的一条 Link**

```go
conn, err := simpletier.NewConnection(rawTCP, simpletier.ConnectionInfo{Type: "tcp"})
link, err := n.AttachConnection(ctx, conn, simpletier.AttachOptions{
    Role: simpletier.LinkRoleInitiator,   // 或 LinkRoleResponder
    Lane: 0,   // 0=CONTROL，1=PACKET，2=STREAM（SDK 未导出常量，用字面量）
})
```

接入后这条连接会跑完整 Noise 握手、认证对端，成为 overlay 的一条 Link。

**但一条 CONTROL Link 不等于能收发业务流量。** `DialContext` / `Listen` 走的是 STREAM 数据 lane，
只建 CONTROL 的话路由表里没有可用边，`DialContext` 会一直返回 `ErrNoRoute`——这是刻意的：
认证通过只说明对端是谁，不代表这条链路能承载数据。

要让这条 peer 真正可路由，还得再接一条 STREAM Link 并把它钉到上面那条 CONTROL 上：

```go
streamConn, _ := simpletier.NewConnection(raw2, simpletier.ConnectionInfo{Type: "tcp"})
dataLink, err := n.AttachConnection(ctx, streamConn, simpletier.AttachOptions{
    Role:    simpletier.LinkRoleInitiator,
    Lane:    2,             // STREAM
    Control: controlLink,   // 必须指向已建立的同对端 CONTROL Link
})
```

`relay.JoinRoom` 之所以自动开两条连接，就是为了这个。

`AttachOptions` 还有两个字段，接错会失败：

| 字段 | 用途 |
|---|---|
| `Negotiate` | 仅 responder 可用：从握手中取对端的 LaneID，此时 `Lane` 必须是 `0`（CONTROL）|
| `Control` | **initiator 接 PACKET/STREAM 数据 lane 时必填**：指向一条已建立的同对端 CONTROL Link |

`Control` 的作用是钉住对端身份——数据 Link 只允许连到已有 CONTROL 邻接的那个 peer，
避免握手被引到别的节点。漏填会得到 `ErrMissingControlDependency`。

**它要的不是 `io.ReadWriteCloser`，而是一个多一个方法的接口**

```go
type Connection interface {
    io.ReadWriteCloser        // Read / Write / Close
    Info() ConnectionInfo     // 描述这条连接是什么
}

type ConnectionInfo struct {
    Type string   // 必填，如 "tcp"、"websocket"、"custom"
}
```

所以裸连接不能直接传进来：

```go
n.AttachConnection(ctx, tcpConn, opts)   // ✗ 编译不过，*net.TCPConn 没有 Info()
```

`Type` 会写进 Link 元数据并随拓扑传播，路由视图里能看到每条边是什么类型（`Peers()` 不返回它，
那个接口只有 NodeID、虚拟 IP 和两个布尔标记）。
留空、非法 UTF-8 或含 NUL 都会被拒绝。

两种提供方式：

```go
// 1. 用 SDK 的包装（TCP 等任意 io.ReadWriteCloser）
conn, err := simpletier.NewConnection(tcpConn, simpletier.ConnectionInfo{Type: "tcp"})

// WebSocket 有专用包装，Type 自动是 "websocket"
conn, err := simpletier.NewWebSocketConnection(ws)

// 2. 自己实现，比如把已有的多路复用子流接进来
type muxStream struct{ io.ReadWriteCloser }

func (muxStream) Info() simpletier.ConnectionInfo {
    return simpletier.ConnectionInfo{Type: "custom"}
}
```

连接本身还必须满足：**专用**（不能与别的协议复用同一条连接）、可靠有序、全双工、
`Close` 能解除阻塞的读写。HTTP/1.1 的连接复用、UDP 之类不满足这些条件，走不了这条路。

**`NewStreamCarrier`——只借用这条流收发外层帧**

```go
carrier, err := simpletier.NewStreamCarrier(ctx, stream)
```

不做握手、不建 Link、不发布拓扑，只提供有界的帧读写。**帧头和 body 都没有认证**，
对端可能是任何人。`examples/existing-stream/` 演示的是这个。

| | `AttachConnection` | `NewStreamCarrier` |
|---|---|---|
| 握手与认证 | 完整 Noise | 无 |
| 成为 overlay 的一部分 | ✓ | ✗ |
| 能 Dial/Listen | ✓ | ✗ |
| 该用它的场景 | 要把已有连接接进虚拟网络 | 只要在已有流上跑帧协议 |

判断很简单：**需要虚拟 IP、需要和别的节点互通，就用 `AttachConnection`；
只想复用一条流传帧，才用 `NewStreamCarrier`。**

**`relay` 包里的 `Attach` / `AttachFrom` 是它上面的封装**

用 relay 做房间中继时，别直接调 `Network.AttachConnection`——那要你自己管房间的创建和销毁。
不用房间概念（前面几节那种单网络拓扑）时，直接调 `Network.AttachConnection` 才是对的。
relay 在这之上加了两层：

```go
// 接入 + 按 token 找到/创建房间
link, err := r.Attach(ctx, conn, token)

// 同上，并记录对端的物理地址
link, err := r.AttachFrom(ctx, conn, token, remoteAddr)
```

`AttachFrom` 多的那个参数是**对端物理地址**。`ConnectionInfo` 有意只放可公开的传输元数据，
不放远端地址，所以地址由调用方单独给。内置的 TCP / WebSocket 入口用的都是 `AttachFrom`，
这样 `r.Members(roomID)` 才能告诉你每个成员是从哪个物理地址连进来的。

三层关系：

```
Network.AttachConnection   SDK 核心，只管接入，拓扑和房间都由你管
        ↑
   relay.Attach            加房间管理（按 token 找/建房间）
        ↑
   relay.AttachFrom        再加物理地址记录
```

**`relay.Attach` 的 Role 和 Lane 是写死的**：它固定用 `Role: Responder` + `Negotiate: true`，
由对端在握手里决定 LaneID。所以它只能当被动接入方，不能做 initiator，也不能指定接哪条 lane。
需要主动发起、或要指定数据 lane 时，直接用 `Network.AttachConnection`。

它替你做的是房间生命周期：接入前 `rooms.Join(token)`，失败或链路关闭时 `rooms.Leave(token)`。
`AttachFrom` 再额外调 `ObserveCarrier` / `ForgetCarrier`，让 `r.Members()` 能报出物理地址。

## 3. 排障

### 连不上：先看 `Peers()`

```go
peers, err := n.Peers()
for _, p := range peers {
    fmt.Printf("peer=%s vips=%v staticKey=%v relay=%v\n",
        p.NodeID, p.VirtualIPs, p.HasStaticKey, p.AdvertisesRelay)
}
```

| 现象 | 含义 | 检查 |
|---|---|---|
| `peers` 为空 | 完全没看到对端 | `Name`/`CIDR`/`Token` 是否一致；物理网络是否通 |
| 有 peer 但 `HasStaticKey=false` | 学到了但没拿到公钥 | Token 是否一致 |
| 有 peer 且 `HasStaticKey=true` 但 Dial 失败 | 路由不通 | 是否需要 relay；`Options.Relay` 是否被设成 false |

### 跨主机收敛慢或完全不通

**不需要对时。** 节点之间靠周期性广播互相通告，广播的有效期从**收到那一刻**起算，
不比较两台机器的时钟。时钟差几分钟、几小时都不影响收敛。

所以遇到「连不通」不要去查 `date`，那不是原因。按上面的 `Peers()` 表逐项排查。

### 大文件传输慢

| 载荷 | 实测吞吐 | 说明 |
|---|---|---|
| 10 MiB | 179 MB/s | 单对流回环实测 |
| 大载荷持续传输 | 135-152 MB/s 聚合 | CPU 饱和后的总量上限 |

完整数据见 [benchmarks/09-baseline.md](benchmarks/09-baseline.md)。

若远低于此，按这个顺序检查：

1. **一个进程跑了几个 Network**。这是最常见的误判来源。多个 Network 共享同一个 Go
   调度器和堆，争抢会直接压低每对速率：同一个 peer 对作为两个独立进程能到 40 MB/s，
   挤在一个进程里只有 11 MB/s。量带宽时让每个 Network 独占一个进程。
2. **CPU 是否配够**。单对速率的上限首先是 CPU：加密是主要成本，聚合吞吐会在 CPU 饱和
   处封顶，之后增加并发只会摊薄每对速率、不会提高总量。一台 8 核机器实测封顶在
   135–152 MB/s 左右，与并发对数无关。
3. **RTT**：100 ms 链路仍可达 238 MB/s；500 ms 约 250 MB/s
4. **丢包**：1% 丢包会降到 42 MB/s，这是 TCP 队头阻塞的固有代价

判断是「CPU 不够」还是「链路有问题」：并发数翻倍时，若聚合吞吐不变而每对速率减半，
就是 CPU 封顶；若聚合吞吐也下降，那才是链路或协议的问题。

### 空载延迟正常，但大流量时小请求很慢

同一条连接上的多个流会互相排队：大块数据传输期间，同一连接上的小请求要等它前面发完。

实测（300 ms 往返、100 对并发传 50 MB）：

| 测量时机 | p50 | p90 |
|---|---|---|
| 传输前，链路空闲 | 320 ms | 332 ms |
| 传输中，持续探测 | 492 ms | 2.61 s |

中位数只涨 1.5 倍，尾部涨 7 倍——说明小请求偶发地排在大块数据后面，而不是持续排队。

**要测链路延迟就测空载**。要评估用户体验就测满载，两者不是一回事，只报其中一个会得到
相反的结论。若业务对同一条连接上的小请求延迟敏感，让它走独立连接，或别与 bulk 传输
共用一条链路。

---

## 4. 配置速查

```go
type Config struct {
    Listen    []string            // 只接受 tcp:// 前缀
    Upstreams []string            // 主动连的对端，只接受 tcp://
    Targets   []ConnectionTarget  // 自定义 Connector（WebSocket 等）
    Network   NetworkConfig
    Options   RuntimeOptions
}

type NetworkConfig struct {
    Name  string   // 网络身份（与 CIDR 共同决定）
    CIDR  string   // 如 "10.100.0.0/24"
    Token string   // 共享密钥，建议 ≥16 字节随机
}

type RuntimeOptions struct {
    FixedIP   string  // 固定虚拟 IP；空则自动分配
    Relay     *bool   // 留空=允许中继（推荐）；显式 false 会破坏多跳
    LogLevel  string  // "error"/"info"/"debug"
    RateLimit *bool   // 留空=关闭准入限速；true 开启（见下文数值）
}

type AgentConfig struct {
    Config
    DeviceName string        // 开启 TUN 时必填；崩溃恢复靠它找回网卡
    Inbounds   AgentInbounds
}

type AgentInbounds struct {
    TUN       *bool        // 双向开关，见场景八
    SOCKS5    *ProxyConfig // Listen / Username / Password 三者齐全才生效
    HTTPProxy *ProxyConfig
}
```

### `Network` 接口

| 方法 | 用途 |
|---|---|
| `DialContext(ctx, "tcp", "虚拟IP:端口")` | 连远端虚拟端口 |
| `Listen("tcp", ":端口")` | 在虚拟 IP 上监听 |
| `NetListener(ln)` | 转成标准 `net.Listener` |
| `ListenPacket("udp", "虚拟IP:端口")` | UDP 数据报 |
| `AttachConnection(ctx, conn, opts)` | 把已有连接接入为一条 Link（见「接入已有连接」）|
| `LocalVirtualIP()` | 本节点虚拟 IP |
| `Peers()` | 诊断用：看到哪些对端 |
| `Close()` / `Done()` | 关闭 / 关闭信号 |

### `RuntimeOptions` 字段

| 字段 | 默认 | 用途 |
|---|---|---|
| `FixedIP` | 自动分配 | 固定虚拟 IP；与已有节点冲突时**直接拒绝构造**，不自动改址 |
| `Relay` | `nil`（=允许转发）| `false` 移除中继能力，多跳路由会失败 |
| `LogLevel` | — | 日志级别 |
| `RateLimit` | `nil`（=**关闭**）| 连接准入限速。`true` 时：每来源 64 次/秒（突发 256）、并发握手 16、每监听器认证前 128 |

**`RateLimit` 默认关闭**。它防的是单个对端每秒开大量 Link、或耗尽监听器握手槽。如果你是从一个出口 IP 同时接入大量节点（机房批量启动、负载均衡后面、压测），就需要显式关闭，否则会看到：

```
relay: attach control lane: peer link admission was not confirmed
```

需要这个保护时设 `RateLimit: true`；关闭时请由上游（防火墙、网关）承担防洪职责。

### `relay` 与 `room` 包

中继侧：

| 签名 | 用途 |
|---|---|
| `relay.New(relay.Options) *Relay` | 建中继 |
| `ServeTCP(ctx, addr) error` | TCP 入口；`addr` 为空用 22020 |
| `ServeWebSocket(ctx, addr) error` | WebSocket 入口；`addr` 为空用 22021，并暴露 `/ws?room=` 与 `/healthz` |
| `Attach(ctx, conn, token) (AttachedLink, error)` | 接入已建立的连接，用于挂进自己的路由 |
| `AttachFrom(ctx, conn, token, physicalAddr)` | 同上，额外记录连入者的物理地址 |
| `Issue(token) error` | 登记为已签发（配合 `RequireIssued`）|
| `Revoke(token)` | 撤销 |
| `Count() int` | 活跃房间数 |
| `List() []room.RoomInfo` | 房间列表（ID、载体数、虚拟 IP、创建时间）|
| `Members(id) ([]room.Member, bool)` | 房间成员（NodeID、虚拟 IP、物理地址）|
| `Close() error` | 关闭全部 |

房间管理：

| 签名 | 用途 |
|---|---|
| `room.NewManager(room.Options) *Manager` | 单独使用房间管理 |
| `(*Manager).Join(token) (Network, error)` | 首成员建房，同 Token 复用 |
| `(*Manager).Leave(token)` | 末成员离开后延迟销毁 |
| `(*Manager).Issue(token) error` | 登记为已签发（配合 `RequireIssued`）|
| `(*Manager).Revoke(token)` | 撤销 |
| `(*Manager).Rooms() int` | 活跃房间数 |

成员侧：

| 签名 | 用途 |
|---|---|
| `relay.JoinRoom(ctx, network, addr, token) (AttachedLink, error)` | 接入房间；返回的 link 持有到退出房间为止 |
| `relay.WriteToken(w, token) error` | 手工写 TCP 载体前缀 `[4字节长度][token]` |

`room.Options` 字段：`Name`（默认 `DefaultRoom`）、`CIDR`（默认 `10.100.0.0/24`）、`IdleTimeout`（默认 1 分钟）、`LogLevel`、`RequireIssued`、`RateLimit`。

---

## 5. 完整示例索引

| 示例 | 演示什么 |
|---|---|
| `examples/sdk-local` | 最小启动 |
| `examples/network-runtime` | 两节点 TCP/UDP 互通 |
| `examples/tun-chain` | 三节点中继 + TUN |
| `examples/gin-edge` | 一进程双入口（WebSocket + TCP）|
| `examples/tun-agent` | L3 隧道 Agent |
| `examples/existing-stream` | 在已有流上收发外层帧（`NewStreamCarrier`，不接入 overlay）|
| `examples/room-relay` | 一台中继服务多个隔离房间 |

运行方式：

```bash
go run ./examples/sdk-local -listen tcp://127.0.0.1:39751 -virtual-port 8080
```
