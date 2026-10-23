# 基准测试标准

Status: accepted
Scope: `tests/benchmarks/`

本文件定义 SimpleTier 数据面基准的**统一口径**。新增或修改基准必须符合本文件。

---

## 1. 六个维度

每个维度都必须在 **direct** 与 **relay** 两种拓扑上各测一次。

| # | 维度 | 基准函数 | 数据方向 |
|---|---|---|---|
| 1 | 下载速率 | `BenchmarkDownloadThroughput` | target → source |
| 2 | 上传速率 | `BenchmarkUploadThroughput` | source → target |
| 3 | 下载延迟 | `BenchmarkDownloadLatency` | target → source |
| 4 | 上传延迟 | `BenchmarkUploadLatency` | source → target |
| 5 | 并发能力 | `BenchmarkConcurrency` | target → source，多流并发 |
| 6 | 正确性 | `BenchmarkEchoCorrectness` | 双向回显 |

延迟维度（3、4）除拓扑外还必须覆盖 RTT 矩阵：`0 / 1 / 10 / 50 / 100 / 200 / 500 ms / 1 s`。真实部署的延迟由往返时间主导，仅测 loopback 无法代表广域网。

定义：

- **下载** = target 发送、source 接收（服务端 → 客户端）
- **上传** = source 发送、target 接收（客户端 → 服务端）

两个方向必须分开测，不可互相代表：AEAD 次数、信用前沿、中继转发方向均不对称。

拓扑：

- `direct`：source --carrier--> target
- `relay`：source --carrier--> relay --carrier--> target

---

## 2. 尺寸与常量

| 常量 | 值 | 用途 |
|---|---|---|
| `benchFrameChunk` | 256 KiB | 每次写入的块大小 |
| `benchSizes` | 1 MiB / 10 MiB / 50 MiB | 吞吐矩阵 |
| `benchSteadySize` | 10 MiB | 吞吐套件载荷 |
| `benchLatencyPayload` | 1 MiB | 延迟套件载荷 |
| 并发级别 | 1 / 4 / 16 / 32 / 64 / 128 流 | 每流 20 MiB |

**块大小**：256 KiB。单次写跨多个信用窗口，接近真实大块写的行为，且不人为放大每帧固定开销。

**吞吐载荷**：10 MiB。首个进入稳态的尺寸；1 MiB 用于观察启动开销占比，50 MiB 用于确认平台期。

**延迟载荷**：1 MiB。延迟是首字节与每块属性，少量块即可测量；小载荷使高 RTT 用例保持可运行。

**内存约束**：基准不得按载荷大小分配源/目标缓冲。写侧复用一块 `benchFrameChunk`，读侧逐块校验，因此 50 MiB 用例只占两块 256 KiB。

---

## 3. 两个必须分开报告的指标

**吞吐**（MB/s）与**延迟**（µs/ms）回答不同问题，不得混为一个数字。

**吞吐**必须以流水线方式测量：连续写、同时并发读。逐帧停等测的是 RTT，不是吞吐。

**延迟**报告两项：

- `ttfb`：首字节到达时间，反映建链与首个窗口。
- `block-us`：稳态下单块成本，反映流控与调度。

停等形状只允许出现在延迟套件中。

---

## 4. 传输形状

| 形状 | 每字节 AEAD 次数 | 用途 |
|---|---|---|
| 单向（download / upload） | 2（1 加密 + 1 解密） | **性能指标** |
| echo | 4（加密+解密 ×2） | **仅正确性验证** |

echo 每字节的加解密成本是单向的两倍，其 MB/s 不得作为吞吐引用。`BenchmarkEchoCorrectness` 只做逐字节校验与 SHA-256 比对。

---

## 5. 数据校验

大载荷不比对整块内容，改用**位置相关模式**（`benchPattern`）：第 n 字节 = `(offset+n)*31`。

偏移量使模式跨块不重复，因此乱序块或重复块会被发现，而不是静默匹配。接收侧逐块重算并比对，可在常数内存下验证任意长度。

---

## 6. 对照组

任何 SDK 吞吐数字必须与**裸 TCP 基线**同形状对比（`raw_tcp_bench_test.go`），否则无法区分"网络慢"与"overlay 慢"。

对照组使用同一 payload、同一并发度、同一 loopback。

延迟维度另有专用对照 `BenchmarkRawTCPLatency`：同一 RTT 矩阵、同一延迟代理、裸 `net.Conn`。延迟数字必须与该对照并列报告。

---

## 7. 延迟注入

高延迟测量通过 `latencyProxy` 在 carrier 两侧注入单向延迟，因此一次往返 = `2 × delay`。

延迟套件必须同时报告 SDK 与裸 TCP，因为高延迟下两者的差距才是 overlay 的真实代价。

---

## 8. 命名约定

```
Benchmark<Dimension>[/<topology>][/<size>|/streams-<n>|/rtt-<rtt>]
```

例：

- `BenchmarkDownloadThroughput/direct`
- `BenchmarkUploadLatency/relay`
- `BenchmarkConcurrency/streams-04/direct`
- `BenchmarkEchoCorrectness/10MiB`

拓扑名固定为 `direct` / `relay`。

---

## 9. 复现要求

改动 SDK 后必须 `go clean -testcache` 再测。复用旧编译产物会产生与源码不符的数字。

每个记录的数值必须注明：维度、拓扑、尺寸、RTT（延迟维度必填）、并发度、运行次数。
