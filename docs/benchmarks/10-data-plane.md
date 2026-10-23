# 数据面性能实测与流量控制决策


本文件记录**实测数字**与**由数字得出的判断**。它不替代 `../internals/wire.md` 的冻结契约；凡与契约冲突的结论都标注为不可采纳。

---

## 1. 为什么要有裸 TCP 基线

SDK 基准跑在真实 loopback TCP carrier 上，但叠加了 overlay：Noise 握手、逐帧 E2E AEAD、64 KiB 窗口流控、加密入口锁。没有基线就无法区分「网络慢」与「overlay 慢」。

`BenchmarkRawTCPEcho` / `BenchmarkRawTCPConcurrency` / `BenchmarkRawTCPBandwidth` 用同一 payload、同一并发度、同一 loopback，只保留 `net.Conn`。

单连接 echo，无延迟注入：

| 尺寸 | 裸 TCP | SDK | 倍数 |
|---|---|---|---|
| 80 KiB | 468.15 MB/s | 47.96 MB/s | 9.8x |
| 1 MiB | 811.55 MB/s | 120.60 MB/s | 6.7x |
| 8 MiB | 1151.74 MB/s | 154.41 MB/s | 7.5x |
| 10 MiB | 1590.83 MB/s | 151.29 MB/s | 10.5x |
| 50 MiB | 733.37 MB/s | 159.63 MB/s | 4.6x |

裸 TCP 每次传输只分配 3-4 个对象；SDK 在 80 KiB 分配 160 个、8 MiB 分配 9801 个。分配数随载荷线性增长，是每帧对象开销的体现。

**结论**：loopback 不是瓶颈。1 MiB 处 overlay 成本 26 倍，且随 payload 增大而恶化。

---

## 2. 已消除的瓶颈（按收益排序）

### 2.1 每帧复制 payload 与重建 cipher — 已修

- `circuitAdapter.ProtectPayload` 原返回 `append([]byte(nil), plaintext...)`，而该 adapter 明确不做加密（真正 AEAD 在 `tx.Seal`），这次复制是纯开销。
- `E2EProtector.Seal`/`Open` 每帧 `chacha20poly1305.New(key[:])`，而 key 在整个 epoch 内不变。

改为直接返回调用方字节、按 epoch 缓存 cipher（安装/丢弃/清空三处同步失效）。

效果：80 KiB 38.54 → 50.65 MB/s（+31%）。

### 2.2 帧写缓冲池化与读游标 — 已修

- `wire.WriteFrame` 每帧 `make` 整个帧缓冲；改为 `sync.Pool` 复用（缓冲不逃逸该函数）。
- `circuit.Circuit` 增加 `recvOff` 读游标：读空时只重置游标而不搬移尾部；部分读仍原地压缩，保持 `len(recvBuf)` 等于未读字节数（缓冲预算契约要求）。

效果：8 MiB 吞吐 +34%，分配 139.1 MB → 122.5 MB。

### 2.3 流控补窗阈值 — 已修

`WINDOW_UPDATE` 是 `CONTROL_RPC`，每次消耗一个共享的 per-Link 控制令牌（`rateLinkControlPerSecond = 100`）。原实现每读一次就把信用前沿推到 `已读 + 64 KiB`，于是大传输每帧都要一次更新，**更新速率而非数据速率成为上限**。

现改为只在剩余信用不足一个 `MaxBuffer` 的八分之一（1 MiB，仍大于一个最大帧）时才补窗。

效果（三次运行）：

| 尺寸 | 修复前 | 修复后 |
|---|---|---|
| 1 MiB | 7.06 | 72.13 / 73.17 / 73.29 MB/s |
| 8 MiB | 1.83 | 3.28 MB/s |
| 80 KiB | 38.54 | 50.33 MB/s |

---

## 3. 一度回滚、后经授权重新采纳的两项（重要）

这两项都测出了显著收益，起初因违反 `wire-protocol.md` 被回滚；**契约持有人随后明确授权修改冻结值**，故其中一项已重新采纳。保留这段历史是为了说明代价与边界。

### 3.1 `MaxBuffer` 放大到 256 KiB — 回滚

曾把 `MaxBuffer` 从 65536 改为 `MaxCreditAhead`（256 KiB），8 MiB 达到 84–87 MB/s。

**当时不可采纳的原因**：
- `wire-protocol.md:71` 明确「每流实际缓冲≤64KiB，256KiB 是 credit 上限而非预分配」。
- `reserveRecvLocked` 立即按 `MaxBuffer` 预留内存，256 KiB 会把 64 MiB 数据池可承载的并发流从 1024 降到 256。

**后续结论**：证明确实不需要改它——§6 的流控豁免拿到了更大收益（19.5x），且不牺牲并发流数量。`MaxBuffer` 现在是 8 MiB（`internal/circuit/circuit.go`）。

**一处需要记录的自查失误**：回滚后曾连测三次得到 84–85 MB/s，据此一度认为「64 KiB 也能达到」。`go clean -testcache` 后复测为 **3.28 MB/s**——那是 `go test` 复用旧编译产物的假象。记忆中的「回滚后仍很快」不成立，84 MB/s 完全依赖那个违规缓冲。

### 3.2 AEAD 移出 `p.mu` — 回滚

曾把 `aead.Seal` 移出锁外（锁内只留校验与提交），意图并行加密。

**不可采纳的原因**：`wire-protocol.md:66` 要求「该 Session 的单一 egress writer 在优先级调度确定 wire order 后才分配 MessageNumber、加密并串行写出，**不得在排队前由并发 producer 预留 counter**」。锁外加密正属于该条禁止的行为。

---

## 4. 真实往返延迟下的表现

`BenchmarkStreamLatencyImpact` 在 carrier 两侧注入单向延迟，一次往返等于 2×delay。
payload 60 KiB（恰在一个 64 KiB 窗口内），每写一帧读回一帧：

```bash
go test ./tests/benchmarks/ -run '^$' -bench 'BenchmarkStreamLatencyImpact|BenchmarkRawTCPLatencyImpact' -benchtime=3x
```

| RTT | 裸 TCP | SDK | SDK/裸 TCP |
|---|---|---|---|
| 0 | 714.38 MB/s | 39.52 MB/s | 18.1x |
| 2 ms | 27.22 MB/s | 9.93 MB/s | 2.7x |
| 20 ms | 2.98 MB/s | 1.34 MB/s | 2.2x |

固定成本在高 RTT 下被摊薄：RTT 越大，两者差距越小。这是每字节加密成本与往返等待
的比例变化，不是协议缺陷。

## 5. 真实载荷（5 MiB – 100 MiB）

前面的套件最大到 8 MiB。`BenchmarkBulk` 用 60 KiB/帧的单条 echo 流覆盖真实文件尺寸：

```bash
go test ./tests/benchmarks/ -run '^$' -bench 'BenchmarkBulk$' -benchtime=3x
```

| 载荷 | 吞吐 | 总耗时 |
|---|---|---|
| 5 MiB | 53.67 MB/s | 98 ms |
| 10 MiB | 53.98 MB/s | 194 ms |
| 50 MiB | 53.46 MB/s | 981 ms |
| 100 MiB | 52.90 MB/s | 1982 ms |

吞吐不随载荷增大而衰减——分帧、窗口与背压在大文件下工作正常。

`BenchmarkBulkLatency` 同时报告首字节与每帧往返：

| 载荷 | 吞吐 | TTFB | 每帧往返 |
|---|---|---|---|
| 5 MiB | 52.82 MB/s | 1027 µs | 1167 µs |
| 10 MiB | 52.53 MB/s | 1280 µs | 1174 µs |
| 50 MiB | 50.84 MB/s | 996 µs | 1208 µs |

## 6. 流控反馈与限速解耦（最大收益）

§5 的 3.5 MB/s 上限已解决。根因是**限速器的管辖范围错了**：`WINDOW_UPDATE` 是接收端的信用反馈，由本节点自己的消费速度产生，对端无法放大；但旧实现把它和 open/ready/reset 一样计入 per-Link 控制令牌，双向各扣一次。于是 64 KiB 窗口每帧要一次更新、每次 2 个令牌，100 令牌/秒就锁死 50 帧/秒 = 3.0 MB/s。

修改方式（区分「谁能在链路上被放大」）：

- `circuit.Submission` 新增 `FlowControl`，仅由 `submitFlowControl` 设置，`windowUpdate` 使用它；出站计费读到就豁免。
- 入站改为**先解码 opcode 再计费**，只豁免 `RPCWindowUpdate`。opcode 取自 hop AEAD 已认证的明文，因此无法靠伪造声明骗取豁免；这一改动同时**更严格**——短 WINDOW_UPDATE body 现在是 malformed 而不是超预算。
- 豁免严格限定在一个 opcode。生命周期 CONTROL_RPC 在预算耗尽时**仍然被拒且仍会使该 Session 失败**，测试同时断言了这两面。

效果（`BenchmarkBulk`，单条 echo 流，60 KiB/帧）。以下是当时优化前后的对比记录：

| 载荷 | 修复前 | 修复后 | 提升 |
|---|---|---|---|
| 5 MiB | 66.28 MB/s / 79 ms | 70.34 MB/s / 74 ms | 持平（原本未受限） |
| 10 MiB | 3.54 MB/s / 2959 ms | **68.39 MB/s / 153 ms** | **19.3x** |
| 50 MiB | 3.58 MB/s / 14640 ms | **70.66 MB/s / 742 ms** | **19.7x** |
| 100 MiB | 3.35 MB/s / 31299 ms | **65.29 MB/s / 1606 ms** | **19.5x** |

当前机器上的复现值见 §5（约 53 MB/s）。两次测量在虚拟化 CPU 与物理机上运行，
绝对数值不可直接比较；上表的意义是同一台机器上修复前后的相对变化。

## 6.1 加密缓冲原地化

`chacha20poly1305.sliceForAppend` 曾是 100 MiB 传输中**全部已分配字节的 51%**：`Seal` 用 nil dst，每帧分配一个 body 大小的密文缓冲。

改为在调用方切片有 tag 余量时原地 seal（plaintext 在此后不再读取，且 AEAD 允许 dst 与明文重叠）。`Circuit` 各编码器（STREAM_DATA 与四个控制 opcode）预先保留 `e2eTagHeadroom`；余量不足时仍回落新分配，不在调用方切片下重新分配。

**尝试并回滚**：`Open` 用同一手法。它在线上是正确的，也符合 AEAD 契约，但会话测试会在同一底层数组上 seal 再 open，原地解密破坏了 fixture。为二阶收益削弱测试不值得，`Open` 保留分配。

## 6.2 帧头合并读取

`ReadFrame` 原用两次 `io.ReadFull` 分别读 hop header 与 envelope。二者在线上连续，合并为一次后单帧从 5 次 syscall 降到 3 次。

MessageType 校验仍在读取任何 body 字节之前完成——这正是 `TestReadFrameRejectsMessageTypeMismatchBeforeBody` 所固定的：声称不匹配 kind 的帧必须在不排空攻击者可控 body 的前提下被拒。**曾把 header 与 body 融合成一次读，该测试发现后已放弃该写法。**

效果：50 MiB +24%，100 MiB +5%（syscall 占比高的大尺寸受益）；小尺寸在噪声范围内。

## 6.3 当前状态：已接近本机 AEAD 上限

CPU profile 显示 `chacha20.quarterRound` 占 **32%**、`xorKeyStreamBlocksGeneric` 累计 38.2%，CPU 利用率 113.89%。

echo 基准每帧需要 **4 次 AEAD**（source 加密、target 解密、target 回显加密、source 解密），这是 echo 测试模式的固有形状，不是产品缺陷。100 MiB × 4 = 400 MB 加解密，按本机 chacha20 吞吐约 0.8 s，实测总耗时 1.6 s——**加密已占约一半，继续优化需降低 AEAD 次数而非代码效率**。

最终数据：

| 基准 | 结果 |
|---|---|
| BenchmarkBulk 5 / 10 / 50 / 100 MiB | 70.34 / 68.39 / 70.66 / 65.29 MB/s |
| BenchmarkStreamDirect 80KiB / 1MiB / 8MiB | 44.49 / 77.11 / 84.80 MB/s |
| BenchmarkStreamConcurrency 1 / 2 / 4 流 | 44.30 / 56.27 / 68.79 MB/s |

## 7. 复现方式

```bash
# 裸 TCP 基线
go test ./tests/benchmarks/ -run '^$' -bench 'BenchmarkRawTCP' -benchtime=3x

# SDK 单流
go test ./tests/benchmarks/ -run '^$' -bench 'BenchmarkStreamDirect/echo' -benchtime=3x

# 并发
go test ./tests/benchmarks/ -run '^$' -bench 'BenchmarkStreamConcurrency' -benchtime=3x

# 延迟矩阵（含 1 s，约 10 s）
go test ./tests/benchmarks/ -run '^$' -bench 'BenchmarkStreamLatencyImpact|BenchmarkRawTCPLatencyImpact' -benchtime=1x

# 逐跳累加
go test ./tests/benchmarks/ -run '^$' -bench 'BenchmarkStreamLatencyAccumulation' -benchtime=1x
```

**注意**：改动 SDK 后先 `go clean -testcache`，否则可能复用到旧编译产物并得到假数字（§3.1 已因此误判一次）。
