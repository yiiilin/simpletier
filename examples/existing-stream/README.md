# 已建立流连接示例

从项目根目录运行：

```sh
go run ./examples/existing-stream
```

程序由宿主使用 SDK 的 TCPConnector 建立出站回环 TCP 连接，将 accept 得到的入站流包装成 `Connection`；每个实例实现 `io.ReadWriteCloser`，并通过 `Info()` 自带稳定的 Type。再交给 StreamCarrier 双向传输并比对帧，关闭后退出。不使用 NewNetwork、身份目录或配置文件。

```go
conn, err := (&simpletier.TCPConnector{}).Dial(dialCtx, "127.0.0.1:7000")
// conn.Info().Type == "tcp"
```

Dial context 只控制建立过程，不能用它绑定成功连接的整个寿命。StreamCarrier 的 context 才是该载体的生命周期。普通宿主字节流可用 `NewConnection(stream, info)` 包装；真正的已有 WebSocket 应用 `NewWebSocketConnection(*websocket.Conn)`，由适配器流式展开 binary 消息，不只是加一个类型标签。HTTP/TLS 认证仍不等于组网认证。

真实 WebSocket 示例由宿主 HTTP handler 校验认证头并 upgrade，SDK 的 WebSocketConnector 拨号后交接两端 Connection：

```sh
go run ./examples/existing-stream -transport websocket
```

预期报告 `A=websocket B=websocket`，完成双向 synthetic-frame 比对后退出；不声称已有认证路由。请求头、可选 Dialer/TLS/proxy 都通过 SDK 对象传入，默认不读取代理环境变量。

Network 现支持 `Config.Targets []ConnectionTarget` 传入自定义 Connector；typed targets 非空时可不配置额外 SDK listener。它目前仍在拨号后执行认证前拒绝/清理，不能据此宣称已有远端路由。

也可以验证无缓冲双向流：

```sh
go run ./examples/existing-stream -transport pipe
```

预期输出（TCP 默认模式）：

```text
Host-established tcp streams handed to StreamCarrier; connection types A=tcp B=tcp.
A -> B: synthetic frame, 32 opaque body bytes
B -> A: synthetic frame, 32 opaque body bytes
Completed framing-only exchange; not authenticated, no Network routes.
```

## 接入自己的连接

```go
// existingConn 是宿主已建立并准备交接的 net.Conn。
carrier, err := simpletier.NewStreamCarrier(ctx, existingConn)
if err != nil {
    // 构造失败，连接仍由宿主管理。
    return err
}
defer carrier.Close()

frame, err := carrier.ReadFrame()
if err != nil {
    return err
}
// frame 仅经过结构校验；不能直接视为认证消息或交给业务路由。
return carrier.WriteFrame(frame)
```

`net.Conn`、已建立的 TLS 连接、专用 mux 子流，以及其他满足条件的 `io.ReadWriteCloser` 均可传入。提供的流必须可靠、有序、全双工，支持并发读写，且 `Close` 能安全地解除阻塞的读写。

## 所有权和错误

- 成功构造后 SDK 拥有底层流，宿主必须停止原始读写；不能让两个协议争抢同一条连接。使用 mux 时交接独立子流，而不是共享原始 TCP 连接。
- 若宿主此前使用 `bufio.Reader` 预读过数据，须将那个 reader 连同底层 writer/closer 一并包装交接，不能丢弃已缓存字节。
- 构造 context 控制整个 carrier 的生命周期；取消或超时将关闭整个流，并非只取消一条帧。需要的 `net.Conn` deadline 应在交接前设置。
- 同一方向调用串行执行，不同方向可以并发。`WriteFrame` 返回前，不得修改传入的 `Body` 或 `Envelope`；读出的切片由调用方持有。
- `length` 最大 65,536 字节，不含 4 字节前缀。坏帧、截断帧、底层读写失败终止 carrier；半帧不会重试或继续解析。发出字节前发现的本地帧格式错误可修正后重新调用。
- `Close` 幂等，原始关闭错误会保留；`Done` 在底层关闭返回后关闭。调用方仍需等待自己启动的 I/O goroutine。

## 当前边界

这是**已有流上的外层帧传输**，不是认证组网示例。示例中的 body 是合成测试字节，不是有效 AEAD 密文或 Noise 握手。

`StreamCarrier` 不加密、不验证身份、AEAD tag 或重放，不发布事实或路由，且尚未接入 `Network` 的 Link/Session。生产协议帧需由后续认证/加密层生成并验证；Noise 初始 HANDSHAKE 是独立格式，应先在原始流上完成，再进入普通帧模式。本次没有更改或绕过这些安全要求。
