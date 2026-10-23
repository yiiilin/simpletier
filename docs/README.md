# SimpleTier 文档

SimpleTier 是一个可嵌入 Go 程序的覆盖网络：节点通过加密 TCP 连接组成虚拟网络，
用虚拟 IP + 端口互相访问，不需要知道中间跳了几层。

## 从哪读起

| 你想做什么 | 读这份 |
|---|---|
| 用 SDK 接入 | [SDK 使用指南](sdk-guide.md) |
| 了解系统怎么组成 | [系统架构](architecture.md) |
| 改内部实现 | [internals/](internals/) 下对应模块 |
| 部署中继 | [多协议覆盖网络](multiprotocol-overlay.md) |
| 看性能数据 | [benchmarks/](benchmarks/) |
| 查排障 | [SDK 使用指南 · 排障](sdk-guide.md) |

## 三层文档

**产品层**（面向接入者与部署者）——`sdk-guide.md`、`multiprotocol-overlay.md`、
`l3-vpn.md`、`tcp-overlay-network.md`。讲能做什么、怎么配置、边界在哪。

**内部层**（面向维护者）——`internals/` 下每模块一份。讲协议格式、状态机、失败处理。

**数据层**——`benchmarks/` 下的实测结果。数字都是跑出来的，测量条件随报告记录。

`references/` 存放外部资料和设计来源，不是本项目的契约。

## 验证

```bash
go build ./... && go vet ./...
go test ./internal/... ./pkg/...   # 单元与集成
go test ./tests/...                # 跨节点端到端
```

真实 TUN 设备的验收需要 root、`/dev/net/tun`，以及创建网络命名空间并把
veth 移入其中的权限：

```bash
sudo go test ./tests/tun_acceptance/ -count=1 -v
```

CI 不跑这一项——托管 runner 不给第三种权限，target 命名空间拿不到 carrier
链路，失败反映的是环境限制而不是缺陷。

## 代码入口

| 包 | 作用 |
|---|---|
| `pkg/simpletier` | SDK 主体：Network、Agent、配置 |
| `pkg/simpletier/relay` | 房间中继 |
| `pkg/simpletier/room` | 房间生命周期 |
| `internal/wire` | 帧编解码 |
| `internal/link` | 握手、链路、控制泵 |
| `internal/topology` | 事实存储与路由 |
| `internal/circuit` | 流控 |
| `internal/session` | 端到端会话 |
| `internal/path` | 路径管理 |
| `internal/security` | 身份与密钥 |
| `internal/agent` | TUN 与系统网络 |
| `internal/flow` / `internal/packet` | 数据平面 |

## 示例

`examples/` 下每个目录都是可运行程序：

| 示例 | 演示 |
|---|---|
| `sdk-local` | 最小启动 |
| `network-runtime` | 三节点数据互通 |
| `tun-chain` | TUN + 中继链 |
| `room-relay` | 一台中继服务多个隔离房间 |
| `gin-edge` | 把已有连接接入 overlay |
| `existing-stream` | 复用已有流收发帧（不接入 overlay） |
| `nodeproc` | 多进程压测工具 |

`go run ./examples/<name>` 直接运行；`sdk-guide-check` 用来验证文档里的代码仍然可跑。

## 许可证

MIT，见 [LICENSE](../LICENSE)。可自由用于商业项目，保留版权声明即可。
