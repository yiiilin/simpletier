# 已有双向流的帧载体


## 摘要

宿主已建立专用 TCP 连接或可靠双向子流时，可通过公开 `NewStreamCarrier(ctx, stream)` 交接给 SDK 并收发有界外层帧。本模块复用现有 [Wire 编解码器](../../internal/wire/frame.go)，不再创建 listener、dial、Config 或 IdentityStore。

本文件记录本次已实现的**传输层**，不是生产认证协议的批准。`CarrierFrame` 只通过结构校验，头部和 body 均未认证；本模块不升级 Link、不创建 Network 邻接、不发布拓扑，也不实现远端 Dial/Listen。原有 [安全握手阻塞](security.md) 保持不变。

来源：用户要求“你来实现一下，我想最好能支持已有流连接”，随后再次要求实现，并在帧传输与认证 Link 的边界说明后要求“继续”。

## 1. 需求与模块约束

### 已建立流接入

输入为专用 `io.ReadWriteCloser`；`net.Conn` 是常见实现，可靠 mux 子流也可交接。流必须可靠、有序、全双工，支持并发读写，且其 `Close` 能安全地解除阻塞 I/O。nil、typed-nil、nil context 或已取消 context 在交接前拒绝。构造失败不读取、写入或关闭宿主流；构造成功后由 carrier 独占读写并负责关闭。

### 有界帧与并发顺序

公开 `CarrierFrame`、FrameKind/MessageType 常量和帧错误复用 Wire 定义。`length <= 65536`，不含 4 字节前缀；接收端先校验长度和类型，再分配 body。每方向整帧串行执行，不同方向可并发，写锁在编码前取得。不创建发送队列或后台丢帧循环；单次正在执行的读写只持有有界 frame buffer。调用方持有的历史返回帧或底层流缓冲不属于本对象的预分配承诺。

### 取消与所有权

context 是整个 carrier 的生命周期，不是单条帧的可恢复取消。取消/超时会关闭底层流，可能截断在途帧。`Close` 不获取读写锁、幂等调用底层 Close，并保留其错误。`Done` 在底层 Close 返回后关闭；调用方仍须等待自己启动的 I/O goroutine。通用流若无法由 Close 解除阻塞，则不满足接入前提，不承诺强制终止它。

### 错误与半帧

帧间 EOF 保留 `io.EOF`，半前缀/半 body 保留 `ErrTruncatedFrame` 和底层原因。非法接收帧或底层读写失败终止 carrier，避免未消费字节使后续解析错位；已写出部分帧不重试。正短写由现有 codec 写完，零进度写判 `io.ErrShortWrite`。本地帧校验在任何字节发出前失败时，仅返回格式/大小错误，不破坏连接。关闭后的新操作返回 `net.ErrClosed`；取消原因、I/O 原因和 Close 原因可通过 `errors.Is` 查询。

### 认证边界

carrier 不加密或验证 AEAD、身份、重放、ControlType 或路由事实，返回数据不得直接当作已认证消息。正式 Link 的初始 Noise HANDSHAKE 是不同的原始记录格式，须先在同一专用流上完成，之后才进入普通 frame 模式。示例只交换合成 framing fixture，不是明文 Network 模式或有效 Noise/AEAD 向量。`NewNetwork` 和其已有监听/认证前拒绝行为未改变。

### 验收条件

要求实跑真实回环 TCP 和 `net.Pipe` 双向收发；最大/非法/截断帧、并发写不串帧、分片读取、正短写/零进度/部分失败写、取消阻塞读写、关闭幂等和预读缓存交接均有可执行测试。公开示例应校验收到的完整 frame 并明确提示未认证，不能仅证明构造成功。

## 2. 概要设计

```text
[Host established dedicated stream]
               |
               v
[NewStreamCarrier: validate + take ownership]
               |
       +-------+--------+
       v                v
[serialized read] [serialized write]
       |                |
       v                v
[existing Wire codec: bounds + layout]
       |                |
       +---failure------+----> [Close owned stream]
       |
       v
[complete outer frame / local write completion]
```

宿主在构造前停止 raw 读写并交接全部已缓存字节。成功只代表传输对象可使用，不能代表 Link 认证或远端接受了某条帧。底层 Close 与方向锁分离，才能解除 `net.Pipe`/TCP 的阻塞。

```text
[Caller frame: opaque body]
            |
            v
[wire.WriteFrame] --> [owned stream] --> [wire.ReadFrame]
                                             |
                                             v
                              [Caller-owned UNVERIFIED frame]
```

发送者在 WriteFrame 返回前不能修改 slice；接收返回的 slice 由调用方持有。Wire 编码是唯一布局来源；carrier 不解释业务字节、不触碰 Network/密钥/拓扑状态。

## 3. 详细设计

### API

```go
func NewStreamCarrier(context.Context, io.ReadWriteCloser) (*StreamCarrier, error)
func (*StreamCarrier) ReadFrame() (CarrierFrame, error)
func (*StreamCarrier) WriteFrame(CarrierFrame) error
func (*StreamCarrier) Close() error
func (*StreamCarrier) Done() <-chan struct{}
```

若宿主先用 `bufio.Reader` 预读，则把该 reader、同一底层 writer 和 closer 组合成 `io.ReadWriteCloser` 交接，不可丢弃已缓存字节。已有 TLS 连接/专用 mux 子流在满足关闭与全双工前提时可输入；本次实测对象为 TCP、`net.Pipe`、通用包装流和缓存 reader，未测试特定 TLS/mux 产品。

### 状态与取消

```text
[Host owns stream] --invalid input--> [Host still owns stream]
       |
       +--constructor succeeds--> [Open carrier]
                                      |
              +--local validation-----+  (zero bytes emitted)
              |
              +--Close / context end / I/O failure--> [Closing]
                                                        |
                                                        v
                                      [underlying Close returns -> Closed/Done]
```

`context.AfterFunc` 注册与 stop-function 发布受单独锁保护，避免构造时取消导致发布竞态。`sync.Once` 序列化关闭并保存首个关闭结果；新 I/O 先检查 context 与 closing 信号。底层写入调用是否已发生，由小型 writer 记录，用于区别可恢复的本地校验错误与不可恢复的传输错误。

### 实现边界

没有 Network.AttachCarrier 成功占位接口；普通 FrameKind decoder 也不是 Noise HANDSHAKE decoder。把现有 carrier 纳入认证 Link 仍需完成独立协议/互操作与路由接线。

## 4. 实现与验证

本模块代码入口：[carrier.go](../../pkg/simpletier/carrier.go)；回归用例：[carrier_test.go](../../pkg/simpletier/carrier_test.go)；运行示例：[main.go](../../examples/existing-stream/main.go)、[运行说明](../../examples/existing-stream/README.md)。验证见上文；本次只更新自身证据，其他模块历史验证保持原始绑定。
