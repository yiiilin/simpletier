# 连接提供者与连接实例


## 摘要

Connector 是可复用拨号器；Connection 是本次已建立的专用可靠全双工流，实现 `io.ReadWriteCloser` 并携带稳定的 ConnectionInfo。TCP、自定义提供者和宿主既有流使用同一种实例契约。组网认证和帧加密不由本模块实现；类型标签不是认证证明。

## 1. 需求与约束

### 验收条件

| 场景 | 期望与验证 | 约束 |
|---|---|---|
| TCP 同一提供者拨号两次 | 两个独立实例携带 tcp Type；关闭一个不影响另一个；TestTCPConnectorReturnsFreshConnections |
| 宿主既有流交接 | 描述值副本不能改变实例；Close 解除阻塞 I/O；TestConnectionCarriesInfoAndIndependentIO、TestConnectionCloseUnblocksIO |
| 无 SDK listener 的自定义 Target | callback 确实被调用、Endpoint 保持字面且元数据读取一次；TestNewNetworkUsesCustomConnector |
| nil/迟到/错误返回与凭据日志 | 不 panic、不漏连接、不记录秘密；TestConfigCopiesAndValidatesConnectionTargets、TestNewNetworkClosesLateConnectorResult、TestConnectorResultValidationAndCleanup、TestNetworkConnectorLogsDoNotExposeCredentials |
| 原始连接成功但未认证 | 仍然 ErrNoRoute、示例明确 synthetic/not authenticated；现有 Network 与示例测试 |

### 实例自带元数据

`Connection` 组合 `io.ReadWriteCloser` 和 `Info() ConnectionInfo`，当前描述字段是 `Type string`。描述在实例生命周期内稳定，Info 返回值副本。Type 必须非空、有效 UTF-8 且不含 NUL，不做大小写折叠或字符串展开；它是可公开的类型标识，不能用 endpoint/凭据充当 Type。`NewConnection` 可包装宿主已有流，失败不接管/关闭，成功后独占流；Close 幂等且保留底层关闭错误，不获取 I/O 锁。

### 拨号与连接寿命分离

`Connector.Dial(ctx, endpoint)` 返回新的独立 Connection；同一提供者可服务多次尝试。context 仅约束建立过程，返回的成功连接不能绑定到此短 context 的寿命。失败提供者必须清理资源，合作处理取消；SDK 不以泄漏 goroutine 模拟强制超时。TCPConnector 复用标准库 net.Dialer；ConnectorFunc 支持宿主实现。

### 真实 SDK 接线

`Config.Targets []ConnectionTarget` 包含 Connector 与 opaque Endpoint，Endpoint 语法只由提供者解释。空 endpoint、nil/typed-nil 提供者在 Network 状态创建或 listener 副作用前拒绝。仅有有效 typed Targets 时可省略 SDK Listen；旧空监听且无 Targets 的配置仍非法。Targets slice 和字段复制，提供者对象/闭包共享，宿主不得在运行期间并发修改它们。传统 TCP Upstreams 通过 TCPConnector 创建实例，TCP accept 也包装 Connection，进入同一个认证前处理入口。

### 失败清理与日志

所有非 nil 拨号返回值都须在取消、conn+error、非法描述或握手失败路径上关闭；typed-nil/nil+nil 不能调用 Info 或 Close。Network 将稳定描述包装后调用同一 CONTROL Link admission，成功且 receiver floor 校验通过才交接给 Established Link 并登记，失败不登记。描述只采样一次并保存稳定快照。不在无限重试循环累积 defer。原始 endpoint 和提供者错误可能包含凭据，运行日志只记录安全索引和阶段，不打印其内容；I/O/Close 原因在处理返回错误中保留。

### 未认证不建路由

成功 Dial/NewConnection 本身不建立认证 Link 或路由。当前 Network 对出站/入站 Connection 执行 Noise/双向 encrypted CAPABILITY，并在 epoch 门禁之后登记 CONTROL activeLinks；ConnectionType 仍不授予身份。LinkFact 类型传播、FactStore/RouteView、数据 Lane、远端 Stream 和正常到期不断流换钥仍未实现，不能将局部身份认证当成组网可用。连接类型不是 LaneID，也不是唯一 LinkID。

## 2. 概要设计

```text
[SDK typed Config.Targets / legacy Upstreams]
                    |
                    v
             [Connector.Dial]
                    |
                    v
        [Connection: stream + stable Info]
                    |
                    v
        [shared CONTROL Link admission]
                    |
          +---------+----------+
          |                    |
          v                    v
     [failure -> close] [Noise + encrypted capability + epoch gate]
                               |
                               v
                    [active Link; no route yet]
```

当前统一接线已包括初建 CONTROL Link 身份/PSK/能力门禁；传统 TCP 和自定义提供者不使用不同的核心协议。仍没有事实、路由、远端业务或完整数据 Lane 运行，不能以提供者或 Link 成功代替这些后续步骤。

```text
[Host Type / stream] -> [NewConnection private snapshot]
                                  |
                                  v
                         [Connection.Info value]
                                  |
                                  v
              [future LinkFact -> per-hop route display]
```

未来只传播值元数据，不传播提供者对象、流对象或凭据。Type 进入正式通告的 wire 字段和版本约束由拓扑规格负责，本模块不擅自改编码。

## 3. 详细设计

```go
type ConnectionInfo struct { Type string }
type Connection interface {
    io.ReadWriteCloser
    Info() ConnectionInfo
}
type Connector interface {
    Dial(context.Context, string) (Connection, error)
}
type ConnectionTarget struct {
    Connector Connector
    Endpoint string
}
```

```text
[Connector reusable] --Dial--> [Connecting]
                                  |
                   +--------------+-------------+
                   |                            |
                   v                            v
              [Failure/cancel]             [New Connection]
                   |                            |
             [cleanup returned stream]          v
                                      [Close -> closed instance]
```

每次重拨产生新实例，不覆盖旧实例的 I/O 状态。Close 信号先禁止新读写，再关闭底层流；原始流必须支持全双工及安全解除阻塞。Network 的5秒 Dial context 仅建立，返回后取消；随后另有5秒 Link握手 context，成功同步解除取消回调并交接长期生命周期，失败关闭。当前 CONTROL成功实例保存在 activeLinks，target已有 Ready Link 时跳过再拨；无帧泵时 Ready 只表示生命周期包裹未被显式关闭，不代表已经探测远端仍活或已能处理业务。

## 4. 实现与验证

实现：[connection.go](../../pkg/simpletier/connection.go)；接线：[network.go](../../pkg/simpletier/network.go)；回归：[connection_test.go](../../pkg/simpletier/connection_test.go)、[Link admission](../../pkg/simpletier/link_admission_test.go)；示例：[main.go](../../examples/existing-stream/main.go)。/002 是旧 revision1 的真实结果，原绑定保留，不代表本修订的认证消费者已重审。当前消费者改变的最终验证须主 agent 绑定；下列历史 Detail 中的 pre-auth-close 描述按其旧基线阅读，不是当前路径。
