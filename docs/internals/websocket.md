# WebSocket 连接与字节流适配


## 摘要

`WebSocketConnector` 用成熟的 gorilla/websocket v1.5.3 建立 ws/wss；`NewWebSocketConnection` 包装宿主已升级的专用 socket。两者返回自带 Type=websocket 的 Connection，兼容原始握手及普通 framing 的可靠字节流契约，不创建另一套组网协议。HTTP/TLS/宿主认证不自动等于 SimpleTier 网络成员认证。

## 1. 需求与约束

### 可靠流与元数据

binary messages 的字节按顺序组成连续流，空消息不产生流 EOF；WebSocket continuation 与控制帧由成熟库处理，读取必须完整消费当前消息再取下一条。一个消息可含多个协议帧，一个协议帧可跨多个消息。每次 Write 发送一个 binary message，不把 text 解释为协议字节。Type 保持 websocket；metadata 不证明身份。

### 建立取消与所有权

Dial context 只控制建立。不能只依赖 gorilla DialContext：其 HTTP upgrade raw I/O 可能不因无 deadline 的取消中断。SDK 跟踪建立 socket，取消时关闭；成功返回前 stop 并与已启动回调同步，再解除 context/socket 绑定。迟到、nil、conn+error 结果均释放，底层 close once。Close 不获取方向 I/O 锁，解除阻塞，不等待 WebSocket close handshake。NewWebSocketConnection 成功后宿主停止 raw I/O，构造拒绝保留其所有权。

### SDK 输入与独立职责

请求头和可选 `*websocket.Dialer` 由宿主传入。Header 克隆、Dialer 私有复制；共享对象不得并发修改。SDK 的私有默认 Dialer.Proxy=nil，不调用 ProxyFromEnvironment。ws/wss URL 与 HTTP/TLS 选项仅由提供者解释，Network 的 Config.Targets 可调用此实现，不读取配置文件、不展开 SDK 值。HTTP 认证失败不能交付 Connection；成功后仍须组网认证。

### 控制与失败

Read/Write 分别串行，不同方向可并行。文本、读写故障失败关闭，未知已发送数据不重试；正常 close code 1000/1001 映射 io.EOF，其余错误保留。只通过 NextReader 流式读取，不以 ReadMessage 聚合整条消息。宿主控制 handler/read limit 保留，但必须在交接前设置；handler 同步执行且应有界、不可重入 raw Read，不得通过普通 raw WriteMessage 绕过锁，自动控制回复可用成熟库 WriteControl。消息级限制不是 Frame length；过小限制可能拒绝合法最大帧或合并消息。宿主压缩/控制回调的资源行为属于受信提供者契约；SDK关闭输出压缩，不偷偷替宿主改输入设置。

### 验收条件

| 场景 | 期望 |
|---|---|
| 真实 ws/wss 与宿主 HTTP auth | binary 双向读写、Type 不丢失；自定义 CA 的 WSS 在取消已完成 Dial context 后仍可 I/O |
| 连续、空、跨消息和 WS continuation | 字节无丢失/重排；单消息多帧和 ping 交错保持 framing 完整 |
| 停滞 HTTP upgrade | 零 handshake timeout、无 deadline 的 context 取消立即关闭建立 socket，而不是等待无限 HTTP response |
| text/close/read | text 失败关闭；正常 close 为 EOF；Close 解除阻塞，不等待读锁 |
| 实际 Config.Targets | 网络调用真实 WebSocketConnector，然后进入统一 CONTROL Noise/加密能力/epoch 门禁；未通过认证不登记；没有路由时远端 Dial 仍 NoRoute |
| 运行案例 | TCP、pipe、websocket 三模式实际双向 synthetic-frame 比对并退出，不声明认证互操作 |

## 2. 概要设计

拨号阶段由 Connector 管理 socket/TLS/HTTP upgrade 和建立取消；只有升级成功且取消回调同步解除绑定后，实例所有权才交给 Connection。失败分支释放 socket，不交付半成品。字节流层只改变 WebSocket 消息边界的呈现方式；Network现在可将此 Connection交给同一初建 CONTROL Link认证模块，适配器本身仍不发布拓扑、不证明身份、不执行业务分派。两个图分别展示提供者生命周期和按序字节映射。

```text
[SDK Header / Dialer / endpoint]
              |
              v
[private Dialer + cancelable establishment socket]
              |
      +-------+--------+
      |                |
      v                v
[fail/cancel]     [HTTP upgrade success]
      |                |
      v                v
[close socket]   [stop/sync/detach cancellation]
                       |
                       v
              [Connection: Type=websocket]
                       |
                       v
      [consumer: CONTROL Link auth; no topology/routes yet]
```

```text
[WS binary messages / continuations] -> [NextReader] -> [ordered bytes]
[ordered Write bytes] -> [WriteMessage binary] -> [peer binary messages]
[HTTP auth header] -> [host admission] != [SimpleTier identity proof]
```

## 3. 详细设计

```go
type WebSocketConnector struct {
    Dialer *websocket.Dialer
    Header http.Header
}
func (*WebSocketConnector) Dial(context.Context, string) (Connection, error)
func NewWebSocketConnection(*websocket.Conn) (Connection, error)
```

```text
[Establishing] --cancel/error--> [Closed]
      |
      +--upgrade + atomic detach--> [Owned byte stream]
                                         |
                             +-----------+----------+
                             |                      |
                             v                      v
                          [Read/Write]     [error/text/Close -> Closed]
```

建立 tracker.mu 只管 context/socket 交接；成熟库进行 socket/TLS/HTTP 协议 I/O，tracker 用 AfterFunc 关闭已注册 socket，不创建失去所有权的 Dial goroutine。成功交接和 callback 共用同步点；Close of established stream 不再依赖这个 context。独立字节流 readMu/writeMu 不参与 Close，保证双向并发和可取消 I/O。保留 socket/control 设置意味着提供者是受信代码，不能强制终止任意恶意回调。

## 4. 实现与验证

[websocket.go](../../pkg/simpletier/websocket.go)、[回归](../../pkg/simpletier/websocket_test.go) 和 [可运行示例](../../examples/existing-stream/main.go) 已实现。Network初建 CONTROL认证消费者现在存在，适配器仍不实现 Noise/拓扑/路由。/002 是旧 revision1 的真实传输结果，原绑定保留；其认证前拒绝/NoRoute观察仅描述旧代码。新消费者测试和最终基线须主 agent 绑定，不能以旧传输证明当前认证或独立互操作。
