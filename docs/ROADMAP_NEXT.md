# Kyanos GNSS 排障平台 — 后续开发路线图（纸面交付）

> 创建: 2026-06-03
> 分支: `feat/gnss-ntrip-rtcm-support`
> 适用: Phase 5 收尾及之后
> 本文档是对 `HANDOVER.md` 和 `docs/DEVELOPMENT_PLAN.md` 的**任务重排与补充**，
> 不替代它们。冲突时以本文档的优先级判断为准。

---

## 0. 背景：为什么需要这份路线图

`DEVELOPMENT_PLAN.md` 是早期宏观蓝图（Phase 1-10），`HANDOVER.md` 是 2026-06-03
的真实状态快照。两者均准确，但存在以下**需要在继续开发前澄清的事实**：

1. **诊断引擎（session 包，约 6400 行）完全未接入数据流。**
   `SessionTracker.OnRecord` / `NewSessionTracker` / `OnConnectionClose` 在
   `agent/session` 包外（除测试）零引用。它是"已写完、单测编译通过、但从未被调用"
   的状态。`HANDOVER.md` §6.8 已部分提及，本文档进一步确认其严重性。

2. **存在一个潜伏的 nil-pointer panic（Phase 1-4 已提交代码）。**
   详见下方 T0。这是所有 GNSS 功能在真实 Linux 环境下"一捕获到帧就崩溃"的根因，
   因从未实跑而未暴露。

3. **NTRIP 内核态识别名存实亡。**
   `bpf/pktlatency.h` 定义了 `kProtocolNTRIP=15`，但 `bpf/protocol_inference.h`
   的 `infer_protocol()` 链**只接了 RTCM，没有接 NTRIP**。NTRIP 流量实际靠 HTTP
   识别路径进入用户态（符合 DEVELOPMENT_PLAN §6.2「策略 A」），`kProtocolNTRIP`
   目前是预留枚举。**这意味着：要让 NTRIP record 进入 session tracker，不能依赖
   `Connection4.Protocol == NTRIP`，需要按 ParsedMessage 的具体类型路由**（tracker
   现有实现正是按类型断言路由的，方向正确，但 record 的来源 parser 取决于连接被识别
   成什么协议——这点需在 T1 中验证）。

4. **全部 Phase 1-5 从未在真实 eBPF 环境端到端运行过。**
   所有"已完成"= 代码写完 + `GOOS=linux` 交叉编译单测通过。当前用户 WSL 环境不可用，
   故继续纸面交付，但所有标注 ⚠️LINUX 的验证项必须在环境恢复后补做。

---

## 1. 任务总览与依赖关系

```
T0 (nil-panic 修复) ──┬─> T1 (诊断引擎接线) ──┬─> T2 (Correlator 集成)
   [阻塞项, 必做]      │   [解锁后续一切]      ├─> T3 (CLI flags)
                       │                       └─> T4 (S6 多 Pod 负载)
                       │
                       └─> T5 (低优先级清理, 独立)

⚠️LINUX 验证项 (T6/T7): 环境恢复后统一补做
```

| 编号 | 任务 | 优先级 | 依赖 | Windows 可验证 |
|------|------|--------|------|---------------|
| **T0** | 修复 RTCM/NTRIP 单向 Record 的 nil-Resp panic | **P0 阻塞** | 无 | ✅ 编译 |
| **T1** | 诊断引擎接入数据流（wire SessionTracker） | **P0** | T0 | ✅ 编译 |
| **T2** | Tracker ↔ Correlator 集成 | P1 | T1 | ✅ 编译+单测 |
| **T3** | CLI flags 暴露诊断能力 | P1 | T1 | ✅ 编译 |
| **T4** | S6 多 Pod 负载分析（pod_load.go 新建） | P1 | T1 | ✅ 编译+单测 |
| **T5** | 低优先级清理（scoring.go 拆分等） | P2 | 无 | ✅ 编译+单测 |
| **T6** | Linux 真实构建 `make build-bpf && make` | P0(环境后) | T0-T4 | ⚠️LINUX |
| **T7** | NTRIP/RTCM e2e 回放验证 | P1(环境后) | T6 | ⚠️LINUX |

---

## 2. T0：修复单向 Record 的 nil-Resp panic（阻塞项）

### 2.1 问题定位

`agent/conn/record_processor.go`:

```go
func (p *RecordsProcessor) Run(...) {
    // ...
    slices.SortFunc(p.records, func(r1, r2 RecordWithConn) int {
        return cmp.Compare(r1.Request().TimestampNs(), r2.Request().TimestampNs())
    })
    for idx, record := range p.records {
        recordMills := common.NanoToMills(record.Response().TimestampNs()) // ← panic
        // ...
    }
}

func submitRecord(record protocol.Record, c *Connection4) {
    // ...
    duration := record.Response().TimestampNs() - record.Request().TimestampNs() // ← panic
    // ...
}
```

`RTCMStreamParser.Match` 和 `NTRIPStreamParser.Match`（对 RTCM/NMEA 帧）产出的
`protocol.Record` 只设 `Req`，`Resp == nil`。调用 `record.Response().TimestampNs()`
会对 nil 接口解引用 → panic。

对比：DNS 解析器（`dns.go` 的 `Match`）总是同时设置 `Req` 和 `Resp`（TXID 配对），
所以现有所有协议都不触发该路径。RTCM/NTRIP 是**第一个产出 Resp-only Record 的协议**。

### 2.2 修复方案（择一，倾向方案 A）

**方案 A（推荐，改动集中、风险低）**：在消费侧做 nil 兜底。
- `submitRecord`：当 `record.Response() == nil` 时，用 `record.Request()` 的时间戳/尺寸
  代替 Resp 相关计算（duration=0、respSize=0），并跳过 `FilterByResponse` 分支。
- `RecordsProcessor.Run`：排序与"距今是否满 1s"判断改用 `requestTs`，当 Resp 为 nil 时
  以 Request 时间戳为准。
- `analysis/stat.go` 的 `getParsedMessageBySide`：当某一方向消息为 nil 时回退到非 nil 的
  一方（避免 `prepareEvents` 里 `.Seq()` / `.ByteSize()` 解引用 nil）。
- `analysis/analysis.go` 的 `record.Response().(protocol.StatusfulMessage)`：nil 接口
  类型断言本身安全（返回 ok=false），但需复核所有 `.Response().XXX()` 直接调用点。

**方案 B（改动分散）**：让 RTCM/NTRIP 的 `Match` 把 `Resp` 设为 `Req` 同一个对象
（自反 Record）。优点是消费侧零改动；缺点是语义不清晰（一个推流帧既是请求又是响应），
且会让 duration 恒为 0、可能污染 stat 的响应尺寸统计。**不推荐，但作为后备**。

### 2.3 受影响调用点清单（需逐一复核 `.Response()` 解引用）

- `agent/conn/record_processor.go`: `submitRecord`, `RecordsProcessor.Run` ✅必改
- `agent/analysis/stat.go`: `prepareEvents` → `getParsedMessageBySide`，
  `ReceiveRecord` 中 `events.ingressMessage/egressMessage` 的 `.Seq()/.ByteSize()/.TimestampNs()`
- `agent/analysis/analysis.go`: `record.Response().(protocol.StatusfulMessage)`（断言安全，确认即可）

### 2.4 验证

- `GOOS=linux go build ./agent/...`
- 新增单测：构造一个 `Resp == nil` 的 `protocol.Record`，跑通 `submitRecord` 路径
  （需把 `submitRecord` 的可测部分抽出或用接口注入），断言不 panic。

---

## 3. T1：诊断引擎接入数据流

### 3.1 目标

让 `SessionTracker` 真正收到 record 和连接关闭事件，使 session 包从"死代码"变为可用。

### 3.2 接线点（`agent/agent.go` SetupAgent）

现有：
```go
conn.RecordFunc = func(r protocol.Record, c *conn.Connection4) error {
    return statRecorder.ReceiveRecord(r, c, recordsChannel)
}
conn.OnCloseRecordFunc = func(c *conn.Connection4) error {
    statRecorder.RemoveRecord(c.TgidFd)
    return nil
}
```

改造为（仅当诊断开启时叠加，遵循"叠加不替换"）：
```go
var sessionTracker *session.SessionTracker
if options.SessionDiagnosisEnable {
    sessionTracker = session.NewSessionTracker(options.SessionTrackerConfig)
    correlator := session.NewSessionCorrelator(options.SessionTrackerConfig.Correlator)
    sessionTracker.SetCorrelator(correlator) // T2 提供
}

conn.RecordFunc = func(r protocol.Record, c *conn.Connection4) error {
    if sessionTracker != nil {
        sessionTracker.OnRecord(r, connInfoFromConnection4(c))
    }
    return statRecorder.ReceiveRecord(r, c, recordsChannel)
}
conn.OnCloseRecordFunc = func(c *conn.Connection4) error {
    if sessionTracker != nil {
        sessionTracker.OnConnectionClose(connInfoFromConnection4(c), time.Now(), inferCloseDirection(c))
    }
    statRecorder.RemoveRecord(c.TgidFd)
    return nil
}
```

### 3.3 关键设计点

1. **`connInfoFromConnection4` 适配器**：`session.ConnInfo` 故意与 `conn.Connection4`
   解耦（HANDOVER §5.3）。需要一个适配函数：
   ```go
   func connInfoFromConnection4(c *conn.Connection4) *session.ConnInfo {
       return &session.ConnInfo{
           LocalIP:    c.LocalIp,
           RemoteIP:   c.RemoteIp,
           LocalPort:  uint16(c.LocalPort),
           RemotePort: uint16(c.RemotePort),
           IsServer:   c.IsServerSide(),
       }
   }
   ```
   放在 `agent` 包（避免 session 包反向依赖 conn）。

2. **导入环风险**：`session` 包当前依赖 `protocol/ntrip`、`protocol/rtcm`、`protocol`。
   `agent` 包依赖 `conn` 和 `session`。`session` **不能**依赖 `conn`（conn 已依赖
   protocol/mysql 等，且 agent→conn→... 链路长）。适配器放在 agent 包可避免环。
   → 验证：`session` 包的 import 不含 `kyanos/agent/conn`。

3. **CloseDirection 推断**：现有 `Connection4` 有 `TCPHandshakeStatus`（含 CloseTs）但
   **没有区分 FIN 来自哪一侧**。T1 阶段先返回 `CloseDirectionUnknown`，把精确方向判断
   留给后续（需要 BPF 层提供 FIN/RST 方向，属 T6/T7 之后的 BPF 改造）。这会让 S4 的
   `DisconnectClientInitiated`/`DisconnectRTCMAbort` 分类暂时走不到，是已知降级。

4. **NTRIP record 的来源**：因 NTRIP 内核态未识别（见 §0.3），NTRIP 流量会被识别为
   HTTP（`kProtocolHTTP`）还是被 RTCM 抢识别？需在 T6 实跑确认。**纸面阶段先假设：
   连接首包是 HTTP 握手 → 被识别为 HTTP → 但 HTTP parser 不会产出 NTRIPRequest。**
   ⚠️ 这是一个**架构裂缝**：当前 NTRIP parser 只在 `ParsersMap[NTRIP]` 注册，而没有
   任何连接会被标成 NTRIP 协议。
   → 详见 §3.4，这是 T1 必须解决的核心问题，不只是"接个 hook"。

### 3.4 ⚠️ 核心问题：NTRIP 流量如何路由到 NTRIP parser

三种可能的真实情况（待 T6 实跑确认，纸面先列出对策）：

- **情况 1**：RTCM 的 `is_rtcm_protocol` 在 NTRIP 握手后的二进制流上命中，连接被标为
  `kProtocolRTCM`。则 NTRIP 的 HTTP 握手字节会被 RTCM parser 当成垃圾跳过，
  `NTRIPRequest`/认证信息**永远拿不到**，只能拿到裸 RTCM 帧。
  → 对策：可接受降级（RTCM 帧仍能分析，S3 可用），但 S1/S2（登录/GGA）失效。

- **情况 2**：HTTP 握手先被 `is_http_protocol` 命中，连接标为 `kProtocolHTTP`，
  后续二进制 RTCM 流也归到 HTTP parser → HTTP parser 无法解析二进制，数据丢失。
  → 对策：需要在 HTTP parser 检测到 NTRIP 特征后"协议升级"到 NTRIP parser，或在
  BPF 层真正实现 NTRIP 识别（启用 `kProtocolNTRIP`）。

- **情况 3（理想）**：在 BPF `protocol_inference.h` 补一个 `is_ntrip_protocol()`
  （识别 `GET/SOURCE ... ICY`/`Ntrip-Version`），让 NTRIP 握手连接标为
  `kProtocolNTRIP`，则 `ParsersMap[NTRIP]` 的 `NTRIPStreamParser` 接管整条连接，
  自动处理握手→RTCM→NMEA。这正是 NTRIP parser 设计的预期工作方式。
  → **推荐方向**：T1 的完整解应包含「补 BPF `is_ntrip_protocol()` + 重新生成 Go 绑定」，
  但该步骤需 Linux（`make build-bpf`），故 T1 拆为：
    - **T1a（Windows 可做）**：写好 `is_ntrip_protocol()` C 代码、`infer_protocol()` 接线、
      手工同步 `bpf/agent_*_bpfel.go` 的枚举（已存在 NTRIP=15），写适配器和 hook 接线。
    - **T1b（⚠️LINUX）**：`make build-bpf` 重新生成绑定，实跑确认走的是情况 3。

### 3.5 options 扩展（`agent/common/options.go`）

新增字段（默认关闭，不影响现有行为）：
```go
SessionDiagnosisEnable bool
SessionTrackerConfig   session.TrackerConfig
```
⚠️ 注意：`agent/common`（options 所在包）若 import `kyanos/agent/session`，要确认
session 不反向依赖 agent/common，避免环。session 当前只依赖 protocol/*，安全。

---

## 4. T2：Tracker ↔ Correlator 集成

### 4.1 现状

`SessionTracker.getOrCreateSession()` 创建会话时**没有**调用
`correlator.OnSessionCreated()`，重连/IP 切换检测（S4）拿不到数据。

### 4.2 方案

1. `SessionTracker` 持有 `*SessionCorrelator`：
   ```go
   type SessionTracker struct {
       // ...
       correlator *SessionCorrelator
   }
   func (t *SessionTracker) SetCorrelator(c *SessionCorrelator) { t.correlator = c }
   ```
2. `getOrCreateSession()` 在 `notifyCreated(s)` 之后调用：
   ```go
   if t.correlator != nil {
       t.correlator.OnSessionCreated(s)
   }
   ```
3. `OnConnectionClose` 在 `s.Close()` 后调用 `t.correlator.OnSessionClosed(s)`。
4. **锁顺序**：`getOrCreateSession` 持有 `t.mu` 时不要再进 correlator 的锁后又回调
   session.mu。`OnSessionCreated` 内部读 `s.mu`（RLock），而调用它时 t.mu 已释放
   （现有实现是先 `t.mu.Lock()` 存 map 再 `t.mu.Unlock()`，然后 notify）。确认在
   t.mu 释放后再调 correlator。

### 4.3 验证
- 复用/扩展 `correlator` 相关单测：创建两个同 username 会话（前一个先 close），
  断言产生 `ReconnectEvent`。
- `tracker_test.go` 增加"tracker 带 correlator"路径的断言。

---

## 5. T3：CLI flags 暴露诊断能力

### 5.1 新增 flags（`cmd/ntrip.go` / `cmd/rtcm.go`）

按 HANDOVER §7.3 与 DEVELOPMENT_PLAN §5.3/5.4：
```
# ntrip
--diag                 启用会话诊断引擎（总开关，置 options.SessionDiagnosisEnable=true）
--auth-log             仅输出登录/认证事件
--auth-fail-only       仅输出认证失败
--gga-interval-warn    GGA 间隔告警阈值（默认 5s）
--reconnect-detect     启用重连检测
--reconnect-window     重连判定窗口（默认 60s）
--diag-score           会话关闭时输出诊断评分

# rtcm
--interruption-warn    RTCM 中断告警阈值（默认 2s）
--fps                  显示每秒帧率
```

### 5.2 stat group-by 扩展
HANDOVER §7.3 提到 `--group-by ntrip-user`、`rtcm-msg-type`（后者已存在）。
需在 `agent/analysis/common/classfier.go` 增加 `NTRIPUser` 分类器类型 + 在
`classfier.go` 注册（仿照已有 `NTRIPMountPoint`）。

### 5.3 注意
- flags 默认关闭，`--diag` 不加时行为与现在完全一致。
- 诊断输出渲染：T3 先用 `logger.Printf` 文本输出（关闭时无影响），TUI 集成留后。

---

## 6. T4：S6 多 Pod 负载分析

### 6.1 新建 `agent/session/pod_load.go`

按 DEVELOPMENT_PLAN §5.8：
```go
type PodLoadAnalyzer struct {
    mu    sync.RWMutex
    pods  map[string]*PodStats // podName → stats
}
type PodStats struct {
    PodName      string
    Connections  int
    ActiveConns  int
    FrameRate    float64 // RTCM fps
    TotalFrames  int64
    TotalBytes   int64
    Sessions     []string // sessionIDs
}
func (p *PodLoadAnalyzer) OnSessionCreated(s *NTRIPSession)
func (p *PodLoadAnalyzer) OnSessionClosed(s *NTRIPSession)
func (p *PodLoadAnalyzer) LoadImbalance() float64 // 变异系数 CV = stddev/mean
func (p *PodLoadAnalyzer) StickySession(clientIP string) bool // 会话粘滞检测
```

### 6.2 依赖与降级
- Pod 信息来自 `NTRIPSession.ServerPod`，当前**始终为空**（K8s 模式未实现，属 Phase 7）。
  → S6 在非 K8s 模式下，可用 `ServerNode` 或退化为「按 server 端 LocalIP 聚合」。
  纸面实现要把"Pod 维度"抽象为可配置的聚合键（podName 优先，回退到 server IP）。
- 作为 `SessionListener` 注册到 tracker（实现 `OnSessionCreated/OnSessionClosed`）。

### 6.3 验证
- `pod_load_test.go`：构造多个不同 ServerPod 的会话，断言 `LoadImbalance` 变异系数计算正确、
  粘滞检测正确。

---

## 7. T5：低优先级清理

| 项 | 说明 | 来源 |
|----|------|------|
| `scoring.go` 拆分 | 把 `NTRIPSession.Score()` 从 types.go 提取到独立 scoring.go | DEVELOPMENT_PLAN §5.10 计划 |
| `recentRetransCount` 时间窗口 | 改为关闭前 N 秒窗口计数（用 TCPHealthAnalyzer.RetransmissionEvents 时间戳） | HANDOVER §6.8/§7.5 |
| `sortDurations` 换 sort.Slice | 大数据集性能（n>1000） | HANDOVER §11 |
| leap second 可配置 | `LeapSecondsGPSUTC=18` 提取为配置项 | HANDOVER §6.2/§11 |

均为纯重构，单测应保持全绿。

---

## 8. ⚠️LINUX 验证项（环境恢复后）

| 编号 | 任务 | 命令 |
|------|------|------|
| T6 | 真实构建 | `make build-bpf && make`，再 `go test ./agent/...`（实跑非交叉编译） |
| T6.1 | 确认 NTRIP 路由情况（§3.4） | 实跑 `sudo kyanos watch ntrip` 对接真实/mock caster，看是否拿到 NTRIPRequest |
| T7 | e2e 回放 | 用录制的 NTRIP 会话 pcap 重放，验证 握手→RTCM→NMEA→断开 全链路 |
| T0 验证 | nil-panic 实证 | 实跑 `sudo kyanos watch rtcm` 对接 RTCM 流，确认不再崩溃 |

---

## 9. 本次纸面交付的执行顺序

```
T0  → T1a → T2 → T3 → T4 → T5
（每步：GOOS=linux 编译 + 相关单测编译/运行 + gofmt）
T1b / T6 / T7 标记为 ⚠️LINUX，待环境恢复
```

每完成一项，更新本文件对应章节的状态标记，并在 HANDOVER.md §3 进度表同步。

---

## 10. 进度记录

### T0 — 修复单向 Record 的 nil-Resp panic ✅ 已完成 (2026-06-03)

- `agent/protocol/protocol.go`：新增 `Record.IsUnidirectional()` 与
  `Record.EffectiveResponse()`，把"单向推流协议"作为一等公民支持。
- `agent/conn/record_processor.go`：`submitRecord` 与 `RecordsProcessor.Run`
  中所有 `record.Response().XXX()` 解引用改用 `EffectiveResponse()`，nil-Resp
  时以 Request 为准（duration=0、respSize=取 Req）。
- `agent/analysis/stat.go`：`getParsedMessageBySide` 在某方向消息为 nil 时回退
  到非 nil 一方，避免 `prepareEvents` 里 `.Seq()/.ByteSize()` 解引用 nil。
- `agent/analysis/analysis.go:63` 的 `record.Response().(StatusfulMessage)`：
  nil 接口类型断言本身安全（ok=false），无需改动，已复核。
- 新增 `agent/protocol/record_test.go`：单向/双向 Record 的回归测试（覆盖
  panic 触发点 `EffectiveResponse().TimestampNs()/ByteSize()`）。
- 验证：`GOOS=linux go build ./agent/conn/... ./agent/analysis/... ./agent/protocol/...`
  通过；`go test -c ./agent/protocol/` 通过；新文件 gofmt 干净。
- ⚠️LINUX 实证待补：实跑 `sudo kyanos watch rtcm` 确认不再崩溃（T6）。

### T1a — 诊断引擎接线（Go 侧 + BPF C 侧，Windows 可做部分）✅ 已完成 (2026-06-03)

- `agent/common/options.go`：新增 `SessionDiagnosisEnable bool` 与
  `SessionTrackerConfig session.TrackerConfig`（默认关闭，import session 无环）。
- `agent/session_wiring.go`（新建）：`connInfoFromConnection4` 适配器
  （agent 包内，保持 session 与 conn 解耦）；`inferCloseDirection` 暂返回
  `CloseDirectionUnknown`（见下方限制）。
- `agent/agent.go`：`SetupAgent` 在 `SessionDiagnosisEnable` 时构造
  `SessionTracker` + `SessionCorrelator`，并通过 `AddListener` 注册 correlator
  （**T2 因此自动完成**：correlator 实现了 SessionListener，tracker 的
  `getOrCreateSession→notifyCreated` 会自动回调，无需在 getOrCreateSession 内
  硬编码调用，否则会重复触发）。`RecordFunc`/`OnCloseRecordFunc` 叠加调用
  `tracker.OnRecord` / `tracker.OnConnectionClose`。
- `bpf/protocol_inference.h`：新增 `is_ntrip_protocol()`（识别无歧义标记
  `ICY `/`SOURCE `/`SOURCETABLE `），插入 `infer_protocol()` 链 **HTTP 之前**。
  这让 NTRIP v1 source-push、ICY 数据流、sourcetable 会话能被标为
  `kProtocolNTRIP` 从而由 NTRIPStreamParser 接管。
- 验证：Go 全量构建仅剩既有 cgo 错误（`GetMachineStartTimeNano`，与本次无关，
  交叉编译丢弃 cgo 文件所致）；用临时 stub 验证 agent 包 `go build`/`go vet`
  通过后已删除 stub。BPF `.h` 改动对 Go 构建无影响（待 `make build-bpf` 生效）。

#### T1a 遗留的已知限制（必须 T1b/⚠️LINUX 处理）

1. **NTRIP v1 客户端 `GET /mount` 数据请求 + 全部 NTRIP v2** 在前缀层面与普通
   HTTP 字节相同，无法仅凭前缀区分。区分需扫描 header 块寻找 `Ntrip-Version`/
   `gnss/data` needle，属有界循环扫描，其 eBPF 验证器开销**必须在真实内核上验证**
   后才能启用。当前这类连接仍被识别为 HTTP。
   → 后果：服务端 NTRIP 连接的**首包是客户端 GET**，会被 HTTP 抢先锁定协议
   （协议只在首次推断时设置一次），导致最常见的"客户端拉流"场景目前 **S1/S2
   （登录/GGA）拿不到 NTRIPRequest**。ICY 响应侧标记只能救"响应先到"的连接。
   → T1b 决策项：是否在 `is_http_protocol` 命中后、于用户态做"HTTP→NTRIP 协议
   升级"，或在 BPF 层加 header-scan。倾向用户态升级（避免 BPF 验证器风险）。

2. **CloseDirection 始终 Unknown**：BPF 层未提供 FIN/RST 来源方向，S4 的
   `DisconnectClientInitiated`/`DisconnectRTCMAbort` 分类暂时走不到。需要 BPF
   改造提供方向信号。

3. **BPF 绑定未重新生成**：`is_ntrip_protocol` 与链路改动需 `make build-bpf`
   （Linux）重新生成 `bpf/agent_*_bpfel.go` 后才真正生效。当前 Go 侧枚举
   `kProtocolNTRIP=15` 已存在（手工同步），但内核态二进制尚未包含新逻辑。

### T2 — Tracker ↔ Correlator 集成 ✅ 已完成（随 T1a） (2026-06-03)

- 经核实，`SessionCorrelator` 已实现 `SessionListener` 接口，且
  `getOrCreateSession` 已调用 `notifyCreated`→全部 listener。因此集成只需在接线
  时 `tracker.AddListener(correlator)` 即可（已在 T1a 完成）。
- HANDOVER §7.2 担心的"getOrCreateSession 未调用 OnSessionCreated"实为多虑：
  通过 listener 机制已贯通，且**不应**在 getOrCreateSession 内再硬编码调用
  （会与 notifyCreated 重复触发）。

### T3 — CLI flags 暴露诊断能力 ✅ 已完成 (2026-06-03)

- `agent/analysis/common/classfier.go`：新增 `NTRIPUser` 分类器类型 + 名称
  `"ntrip-user"`（仿 NTRIPMountPoint）。
- `agent/analysis/classfier.go`：注册 `NTRIPUser` 的 ClassId 与 HumanReadable
  函数（从 `NTRIPRequest.Username` 提取，空用户名归类为 `_anonymous_`）。
- `cmd/common.go`：新增 `addSessionDiagnosisFlags(cmd)`（注册共享 flags）与
  `initSessionDiagnosis(cmd)`（`--diag` 时构造并启用 `TrackerConfig`）。
- `cmd/ntrip.go` / `cmd/rtcm.go`：注册诊断 flags 并在 Run 中调用
  `initSessionDiagnosis`。
- `cmd/stat.go`：`--group-by` 帮助文本补充 `ntrip-user`。
- 新增 flags（默认全关，不影响现有行为）：
  `--diag`、`--gga-interval-warn`、`--rtcm-interruption-warn`、
  `--reconnect-detect`、`--reconnect-window`、`--tcp-health`。
- 新增 `classfier_test.go` 测试：NTRIPUser（正常/匿名/非NTRIP/HumanReadable/
  名称注册）5 个。
- 验证：`GOOS=linux go build ./...` + `go vet ./...`（cgo stub 下）全过；
  `go test -c ./agent/analysis/` 通过；编辑文件 gofmt 干净。

#### T3 已知限制 / 后续

- `--reconnect-detect` 当前仅作为开关占位：correlator 已随 T1a 注册并始终运行
  重连检测，该 flag 暂未单独控制开关（reconnect 检测无副作用）。后续可让它控制
  是否输出 reconnect 事件日志。
- 诊断输出渲染：本阶段诊断结果在 session 包内部聚合，CLI 侧尚未把报告/评分输出
  到终端（TUI/文本报告留待后续渲染集成）。`--diag` 目前可见效果是启用引擎并在
  日志打印 "session diagnosis enabled"。
- `--auth-log` / `--auth-fail-only` / `--diag-score` / `--fps`（DEVELOPMENT_PLAN
  §5.3 提及）尚未实现，依赖诊断结果的输出/渲染通道，归入后续渲染集成任务。

### T4 — S6 多 Pod 负载分析 ✅ 已完成 (2026-06-03)

- `agent/session/pod_load.go`（新建）：`PodLoadAnalyzer`，实现 `SessionListener`，
  按服务端 Pod 聚合会话负载。能力：
  - 每 Pod 连接数（总/活跃）、RTCM 帧数/字节数、聚合帧率、唯一客户端数（`Snapshot`）
  - 负载不均（变异系数 CV）：`LoadImbalance`（按活跃连接数）、`FrameRateImbalance`
    （按帧率）
  - Pod 切换检测 `PodSwitches` + 会话粘滞 `IsSticky`
  - 聚合键：`ServerPod`（K8s 模式）优先，回退到 `ip:<ServerIP>`（非 K8s）
- session 包前置增量（支撑 PodLoadAnalyzer 对活跃会话聚合）：
  - `NTRIPSession` 新增 `ServerIP` 字段
  - `NTRIPSession` 新增导出访问器 `RTCMFrameCount()` / `RTCMTotalBytes()` /
    `RTCMFrameRate()`（live 有效，区别于仅在 close 时计算的 `RTCMStats`）
  - `ConnInfo.ServerIP()`（对称于 `ClientIP()`）
  - `getOrCreateSession` 增加 `serverIP` 参数，创建会话时填充 `ServerIP`
- 接线：`agent/common/options.go` 新增 `SessionPodLoadEnable`；`agent.go` 在
  `--diag` 且 `--pod-load` 时把 `PodLoadAnalyzer` 注册为 tracker listener；
  `cmd/common.go` 新增 `--pod-load` flag。
- 新增 `pod_load_test.go`：8 个测试（按 Pod 聚合、IP 回退、均衡/不均衡 CV、单 Pod
  CV=0、Pod 切换、粘滞、关闭后退出活跃计数、与 tracker 集成）。
- 验证：`GOOS=linux go build ./...`（cgo stub 下）、`go vet ./agent/session/...
  ./cmd/...` 全过；`go test -c ./agent/session/` 通过；新文件 gofmt 干净。

#### T4 已知限制

- `ServerPod`/`ServerNode` 仍始终为空（K8s Pod 解析属 Phase 7），故当前实际聚合键
  是 `ip:<serverIP>`，即"按服务端 IP 聚合"。在腾讯云 LB 后多 Pod 共享 LB VIP 的
  场景下，需 Phase 7 的 PodResolver 才能区分到 Pod 粒度。结构已为 Pod 名预留。
- Snapshot 结果同样尚未渲染到 CLI（与 T3 相同，归入后续渲染集成）。

### T5 — 低优先级清理 ✅ 已完成 (2026-06-03)

四个子项：

1. **`sortDurations` 换 `sort.Slice`**（`agent/session/types.go`）：插入排序 →
   stdlib `sort.Slice`（O(n log n)），适配长会话的大样本集。函数签名/调用点/原测试
   不变。
2. **闰秒可配置**（`agent/protocol/rtcm/epoch.go`）：`LeapSecondsGPSUTC` 保留为
   编译期默认常量（兼容现有测试的 `* time.Second` 算术），新增运行时变量
   `leapSeconds` + `SetLeapSeconds()`/`LeapSeconds()`；三处 epoch→UTC 转换改用
   `leapSecondsDuration()`。CLI 新增 `--leap-seconds`（`cmd/common.go`
   `applyLeapSeconds`，在 ntrip/rtcm 的 Run 中调用，独立于 `--diag`）。
   新增 `leapseconds_test.go`（默认值、覆盖、负值忽略、对 EpochToUTC 的 1s 位移影响）。
3. **`scoring.go` 拆分**（新建 `agent/session/scoring.go`）：`DiagnosticScore`/
   `DiagnosticIssue` 类型、`Score()` 方法、`clampInt` 从 types.go 移出；权重提为
   具名常量 `weightLogin/GGA/RTCM/Network/Stability`。
   **顺带修复一处潜在死锁**：原 `Score()` 持 `s.mu.RLock()` 时调用了同样加读锁的
   `s.Duration()`（RWMutex 读锁不可重入，writer 排队时可能死锁）。新增
   `durationLocked()`（调用方持锁），`Duration()` 委托给它，`Score()` 内改用
   `durationLocked()`。
4. **`recentRetransCount` 时间窗口**（`tcp_health.go` + `tracker.go`）：
   新增 `TCPHealthAnalyzer.RetransmissionsInWindow(end, window)`（按事件时间戳
   计数）；`TrackerConfig` 新增 `RetransAbortWindow`（默认 30s）；
   `OnConnectionClose` 在分析断连前，若挂了 TCPAnalyzer，用窗口计数刷新
   `recentRetransCount`（避免"早期有重传但关闭前平静"的会话被误判为 RTCMAbort）。
   无 TCPAnalyzer 时仍用原递增计数器兜底（现有测试不受影响）。
   新增 `RetransmissionsInWindow` 测试（5s/3s/0/1h 窗口）。
- 验证：`GOOS=linux go build ./...`（cgo stub）、`go vet`（session/rtcm/cmd）、
  `go test -c`（session/rtcm）全过；新文件 gofmt 干净。

至此 Phase 5（T0-T5 + TR）的 Windows 可做部分全部完成。剩余仅 ⚠️LINUX 验证项
（§8：T1b header-scan、T6 真实构建、T7 e2e）。

### TR — 诊断结果渲染 ✅ 已完成 (2026-06-03)

> 插入任务（原计划外）：让 T1-T4 接入的诊断引擎产出可见输出，否则对用户是黑盒。
> 采用纯文本走 logger 的形式，不触碰 Bubble Tea TUI 管道（零风险）。

- `agent/session/report.go`（新建）：
  - `FormatSessionReport(s, ReportConfig)`：把已 close 的会话渲染为多段文本报告
    （身份 / 登录S1 / GGA S2 / RTCM S3 / 网络 S5 / 断连 S4 / 诊断评分 + issues）。
    密码默认隐藏（`ReportConfig.ShowPassword`）。
  - `DiagnosticReporter`（实现 `SessionListener`）：会话关闭时通过 `ReportSink`
    输出报告。`OnSessionClosed` 在 tracker 的 `notifyClosed` 中触发——此时
    `Close()`+`AnalyzeDisconnect()` 已完成，会话已 finalize，字段读取无竞争。
  - `FormatPodLoadSummary(p)`：把 PodLoadAnalyzer 快照渲染为定宽表格
    （每 Pod 活跃/总连接、客户端数、帧数、FPS）+ 负载不均 CV + Pod 切换列表。
- 接线 `agent/agent.go`：
  - `--diag-report` 时注册 `DiagnosticReporter`，sink 写入 `common.AgentLog`。
  - 进程退出（render 函数返回后）若启用 pod-load，打印 `FormatPodLoadSummary`。
- 接线 `agent/common/options.go`：新增 `SessionReportEnable`。
- 接线 `cmd/common.go`：新增 `--diag-report` flag。
- 新增 `report_test.go`：9 个测试（报告含各段、密码隐藏/显示、RTCM 统计与
  msg-type 直方图、reporter 关闭时触发/创建时不触发、nil sink 安全、pod-load
  汇总空/有数据/nil）。
- 验证：`GOOS=linux go build ./...`（cgo stub 下）、`go vet` 我的包、
  `go test -c ./agent/session/` 全过；新文件 gofmt 干净。

#### TR 已知限制

- 报告走 `AgentLog.Info`，在 TUI（watch）模式下日志会被 TUI 接管/重定向；
  当前在 TUI 退出后/非 TUI 模式下输出最清晰。后续若要"实时"在 TUI 内展示，需
  render 层集成（更大改动，未做）。
- 仅文本输出；JSONL/HTML 报告导出属 Phase 6。

### P6-JSONL — 结构化 JSONL 会话导出 ✅ 已完成 (2026-06-03)

> Phase 6 的第一块（DEVELOPMENT_PLAN §6.2）。给诊断引擎补上**机器可读**输出通道
> （TR 是人类可读文本），作为后续 Web Console / 告警 / 看板的数据基础。纯 Go、可测，
> 与 TR 复用同一套会话字段读取约定。

- `agent/session/jsonl.go`（新建）：
  - `SessionSummaryJSON`：扁平、自包含的会话 JSON 视图（snake_case 字段），覆盖
    身份 / 登录 / GGA / RTCM（含 msg-type 直方图） / 网络 / 断连 / 诊断评分 + issues。
  - `SessionSummaryFromSession(s, cfg)` / `MarshalSessionSummaryLine(s, cfg)`：
    构建与单行序列化。
  - `JSONLExporter`：线程安全（`sync.Mutex`）的 JSON Lines 写入器，支持文件
    （`NewJSONLExporter`，拥有并负责 Close）或任意 `io.Writer`
    （`NewJSONLExporterWriter`，用于测试/stdout，Close 不关闭底层）。
  - `JSONLReporter`（实现 `SessionListener`）：会话关闭时写一行，错误吞掉（best-effort）。
- **安全**：JSONL feed **永不包含密码**，即使 `ReportConfig.ShowPassword=true`
  （结构化数据下游可能落库/外传，凭据不应进入）。已用测试固化此约束。
- 接线：`agent/common/options.go` 新增 `SessionJSONLPath`；`agent.go` 在
  `--diag` 且路径非空时创建 exporter、注册 reporter、并在退出时 Close（带错误日志）；
  `cmd/common.go` 新增 `--diag-jsonl <path>` flag。
- 新增 `jsonl_test.go`：8 个测试（字段映射、密码绝不出现、单行合法 JSON、
  exporter 一会话一行、writer-backed Path/Close、reporter 关闭时导出/创建不导出、
  nil exporter 安全）。
- 验证：`GOOS=linux go build ./...`（cgo stub）、`go vet`（session/agent/cmd）、
  `go test -c ./agent/session/` 全过；新文件 gofmt 干净。

#### Phase 6 剩余 ✅ 已完成 (2026-06-05)

- **PCAP 合成导出**: `agent/export/pcap.go` + `rotate.go` 基础设施已有，新增 CLI 接线
  - `--pcap-output <path>`: standalone PCAP-NG 写入（不依赖 gRPC）
  - `--pcap-max-size` / `--pcap-max-duration`: RotateWriter 轮转
  - `agent.go` 中 RecordFunc/OnCloseRecordFunc 回退到 standalone writer
- **COS 上传**: `--cos-bucket/region/prefix/delete-raw` flags，RotateWriter OnRotate 回调自动上传
- **WSL2 验证**: 2392 字节有效 pcapng 文件，file 命令确认格式正确

完整用法：
```bash
sudo kyanos watch ntrip --diag --diag-jsonl sessions.jsonl
sudo kyanos watch ntrip --diag --diag-report --diag-jsonl out.jsonl --pod-load
```

### Bug Fix — Auth Tracking + Format String ✅ 已完成 (2026-06-05)

- `agent/metadata/process.go`: `stopPID` 格式化字符串缺少 `netns` 参数，修复为从缓存加载
- `agent/session/tracker.go`: 请求含认证信息时标记 `AuthChecked=true`（解决 loopback 双向捕获导致 Auth 丢失）
- `agent/session/scoring.go` + `types.go`: 仅在 `HTTPStatusCode > 0` 时判定认证失败扣分
- `agent/session/report.go`: 区分"已观察但响应未捕获"与"认证失败"
- `test_ntrip_diag.sh`: 移除 `set -e`，添加 5 点显式验证
- WSL2 验证: 诊断测试 ALL PASS，auth_checked=true，score 99/100

### TUI Diagnostic Rendering ✅ 已完成 (2026-06-05)

- `agent/render/watch/diag_view.go`（新建）: DiagProvider 接口、DiagSessionSnapshot、Lipgloss 样式表格/详情渲染
- `agent/render/watch/watch_render.go`: model 添加 diagMode/diagTable/diagViewport，`d` 键切换，enter 查看详情
- `agent/render/watch/option.go`: DiagTracker 字段
- `agent/session/types.go`: GGAEventCount() 访问器
- `agent/session_wiring.go`: sessionTrackerDiagAdapter
- `agent/agent.go`: --diag 启用时注入 tracker 到 TUI options

### Standalone PCAP-NG Export ✅ 已完成 (2026-06-05)

- `agent/common/options.go`: PcapOutputPath/PcapMaxSize/PcapMaxDuration + COS 字段
- `cmd/common.go`: --pcap-output/--pcap-max-size/--pcap-max-duration/--cos-bucket/region/prefix/delete-raw
- `cmd/ntrip.go` / `cmd/rtcm.go`: 调用 applyPcapOptions
- `agent/agent.go`: 创建 standalone RotateWriter + PcapNgWriter + COS OnRotate 回调
- WSL2 验证: 2392 字节有效 pcapng 文件

### WebSocket Real-time Push ✅ 已完成 (2026-06-05)

- `console/websocket.go`: BroadcastSessionListChange 全局 "sessions" 主题
- `console/api.go`: GET /api/v1/ws/sessions 端点
- `console/grpc_server.go`: session 生命周期广播
- `console/frontend/src/composables/useWebSocket.js`（新建）: 可复用 composable
- `SessionExplorer.vue`: WebSocket 实时会话列表
- `App.vue`: 10s 健康状态轮询

### SessionDetail + All Views Real-time Enhancement ✅ 已完成 (2026-06-05)

- `SessionDetail.vue`: 实时时长计时器、连接状态指示器、RTCM 吞吐量、事件过滤
- `EventTimeline.vue`: 事件类型过滤按钮 + 自动滚动
- `Topology.vue`: 10s 轮询 + "Updated" 时间戳
- `Alerts.vue`: 15s 轮询 + 新告警脉冲提示 + 摘要栏
- `Report.vue`: WebSocket 活跃会话自动刷新 + "Live — updating" 指示器


---

## 11. Phase 7 — Deferred-Verification Items (Linux/TKE Backlog)

> 来源: Phase 7 设计文档 (agent-grpc-control-plane spec), Requirement 9.4
> 状态: 待验证 — 需要真实 Linux 内核、gRPC 对端、K8s 集群环境

Phase 7 将独立 CLI Agent 升级为可远程控制的节点 Agent（gRPC 双向流、任务下发、
事件上报、Pod 身份解析、连接容灾）。设计将所有 live 依赖隔离在接口后面，
使纯逻辑核心（事件投影、凭据脱敏、环形缓冲、退避、集合调和、proto 往返、命令路由）
在当前开发工作站上可编译、可测试。

以下验收标准**无法在当前环境验证**，需在 Linux/TKE 环境可用后补做：

### 11.1 Live gRPC Stream (Requirement 2.2)

| 项 | 说明 |
|----|------|
| 验收标准 | Registration 成功后建立双向 gRPC_Stream，接收 ControlCommand 并上报 SessionEvent |
| 依赖 | 活跃的 gRPC Console 对端 |
| 验证方式 | 启动 Agent（`--grpc-server`）对接真实/mock Console，确认 Connect RPC 成功、command 流畅通、event 流到达 Console |
| 当前状态 | `Client.Run` 逻辑完成，in-process 单元测试通过；live 对端验证待补 |

### 11.2 eBPF Map Push / Kernel-Side Filtering (Requirement 6.4)

| 项 | 说明 |
|----|------|
| 验收标准 | PodResolver 解析出目标 cgroup ID 后，将 Cgroup_Whitelist 推送到 `filter_cgroup_map` BPF map，内核侧仅放行白名单内的 cgroup 事件 |
| 依赖 | Linux 内核 eBPF 运行时、`make build-bpf` 重新生成 Go 绑定 |
| 验证方式 | (1) `make build-bpf && make` 成功编译带新 map 的 BPF 程序；(2) 实跑 Agent，写入 cgroup ID 到 map 并确认非白名单事件被丢弃 |
| 当前状态 | `filter_cgroup_map` 已定义在 `bpf/pktlatency.bpf.c`；`CgroupWhitelist` 接口 + 纯集合调和逻辑已实现并测试；concrete map-backed binding (`cgroup_whitelist_bpf.go`) 已编写但需 Linux 环境验证 |

### 11.3 Live K8s API / CRI / `/proc` Cgroup Traversal (Requirements 6.1–6.3)

| 项 | 说明 |
|----|------|
| 验收标准 6.1 | PodResolver 通过 K8s API 列出目标 namespace + label selector 匹配的 Pods |
| 验收标准 6.2 | PodResolver 通过容器运行时（CRI/containerd/docker）获取 Pod 的容器 ID |
| 验收标准 6.3 | PodResolver 通过 `/proc` cgroup 遍历将容器 ID 映射为 cgroup ID |
| 依赖 | 活跃的 K8s 集群（TKE）、容器运行时 socket、Linux `/proc` 文件系统 |
| 验证方式 | 在 TKE 节点上运行 Agent（`--grpc-pod-resolve --grpc-namespace=<ns> --grpc-selector=<labels>`），确认 PodResolver 能端到端解析出 PodInfo（Pod name、IP、namespace、node、container IDs、cgroup IDs） |
| 当前状态 | `PodLister`/`ContainerLister`/`CgroupMapper` 接口已定义；`PodResolver` 纯逻辑（缓存、容错、回退）已实现并用 fake 测试通过；live K8s/CRI/proc 实现待补 |

### 11.4 TLS Handshake / Unauthenticated-Peer Rejection (Requirements 8.5, 8.7)

| 项 | 说明 |
|----|------|
| 验收标准 8.5 | 当配置的凭据无效时，Agent 允许底层传输连接建立，但拒绝在其上建立 gRPC_Stream |
| 验收标准 8.7 | Agent 仅接受已认证 gRPC_Stream 上的 ControlCommand，未认证对端的命令被拒绝 |
| 依赖 | 真实 TLS 对端（Console 或 mock server with TLS） |
| 验证方式 | (1) 使用无效证书启动 Agent，确认 transport 连接成功但 stream 被拒；(2) 用未认证客户端发送 ControlCommand，确认 Agent 拒绝处理 |
| 当前状态 | `buildTransport` 逻辑实现了三模式选择（authenticated-encrypted / encrypted-only / error-on-missing）；属性测试覆盖模式选择逻辑；live TLS 握手验证待补 |

### 11.5 20+ Node DaemonSet Rollout (Requirement 9.1)

| 项 | 说明 |
|----|------|
| 验收标准 | Agent 作为节点级进程，适合 DaemonSet 部署跨 20+ 节点，每个 Agent 以 node name 寻址 |
| 依赖 | 腾讯云 TKE 集群（20+ worker 节点）、Cloud LB、DaemonSet manifest |
| 验证方式 | (1) 部署 DaemonSet（含 `--grpc-server` 配置）到 20+ 节点 TKE 集群；(2) 确认所有 Agent 注册到 Console 并可独立寻址；(3) 验证滚动更新不丢失事件（利用 Local_Event_Buffer replay） |
| 当前状态 | Agent 设计为节点级进程（registration 携带 node_name 作为唯一标识）；Local_Event_Buffer + replay 机制已实现；规模化部署验证待补 |

### 11.6 验证执行计划

```
环境恢复后执行顺序:

1. make build-bpf && make              → 确认 Phase 7 代码 + BPF map 编译通过
2. 单节点 Agent + mock Console         → 验证 11.1 (live stream) + 11.4 (TLS)
3. 单节点 Agent + 真实 K8s             → 验证 11.3 (Pod 解析) + 11.2 (BPF map push)
4. 多节点 TKE + Cloud LB + Console     → 验证 11.5 (DaemonSet rollout)
```

> **注意**: 以上所有验证项的纯逻辑部分（退避算法、环形缓冲、集合调和、事件投影、
> 凭据脱敏、命令路由、任务状态机）已通过属性测试 + 单元测试在当前环境验证通过。
> deferred 的仅是 live 基础设施交互层。

---

## 12. Phase 8: Web Console Backend ✅ 已完成 (2026-06-04)

### 12.1 交付物

| 文件 | 说明 |
|------|------|
| `console/types.go` | 领域类型 (Agent, Task, SessionRecord, SessionEventRecord) + protobuf 转换 |
| `console/store.go` | `SessionStore` 接口 + `MemoryStore` 实现 (多维过滤/分页) |
| `console/grpc_server.go` | `AgentServiceHandler` 实现 `AgentServiceServer` (5 RPCs) |
| `console/api.go` | REST API (15 端点: tasks, sessions, agents, topology, WebSocket, health) |
| `console/websocket.go` | `WSHub` 主题发布/订阅 + `channelSubscriber` 参考实现 |
| `console/report.go` | `DiagnosticReporter` 五维度诊断报告 (HTML + JSON) |
| `console/console.go` | `Console` 主编排器 (gRPC + HTTP 统一启停, graceful shutdown) |
| `cmd/console.go` | CLI 命令 `kyanos console --grpc-addr :50051 --http-addr :8080` |

### 12.2 测试覆盖

78 个测试函数，覆盖:
- Store CRUD / 过滤 / 分页 / 时间范围
- gRPC stream mock (Connect/ReportEvents/StartCapture/StopCapture/ReportStatus)
- REST API 集成测试 (httptest)
- WebSocket hub (subscribe/unsubscribe/broadcast/concurrent)
- Protobuf 转换 (所有事件类型 + nil 安全)
- 报告生成 (HTML/JSON, HEALTHY/DEGRADED/CRITICAL verdicts)

### 12.3 技术决策

1. **纯标准库 HTTP**: 使用 Go 1.22+ `net/http` 路由 (`{param}` 语法)，不引入 Gin/chi 外部依赖
2. **WebSocket 自实现**: 使用 `net/http.Hijacker` 做 WebSocket 握手，无 gorilla 依赖；生产环境可替换
3. **MemoryStore 优先**: 接口化存储，先用内存实现快速交付，后续可换 ClickHouse/TimescaleDB
4. **凭证安全不变量**: Console 侧类型严格无密码字段，与 Agent 侧 `redactor.go` 双重保障

---

## 13. Phase 9: Web Console Frontend ✅ 已完成 (2026-06-04)

### 13.1 技术栈

Vue 3 + Vite + Element Plus + Axios + Vue Router

### 13.2 交付物

| 文件 | 说明 |
|------|------|
| `src/App.vue` | 主布局: 侧边栏导航 + 健康状态显示 |
| `src/router/index.js` | 7 路由 (topology, tasks, sessions, session detail, report, alerts) |
| `src/api/index.js` | Axios API 客户端 (tasks/sessions/agents/topology/health) |
| `src/views/Topology.vue` | 集群拓扑: 节点卡片 + Pod 列表 + 在线/离线状态 |
| `src/views/Tasks.vue` | 任务管理: 表格列表 + 创建对话框 + 停止确认 |
| `src/views/SessionExplorer.vue` | 会话浏览器: 过滤栏 + 可点击表格 + 评分标签 |
| `src/views/SessionDetail.vue` | 会话详情: 元信息 + 6 项统计卡 + 事件时间线 |
| `src/views/Report.vue` | 诊断报告: 五维度展示 + metrics + findings + issues |
| `src/views/Alerts.vue` | 告警面板: 异常事件聚合 + 严重程度标签 |
| `src/components/EventTimeline.vue` | **核心组件**: 双列上行/下行时间线 + 异常高亮 |

### 13.3 构建与运行

```bash
cd console/frontend
npm install
npm run dev    # 开发模式 (Vite HMR, 自动代理到 :8080)
npm run build  # 生产构建 → dist/
```

### 13.4 已知限制

1. **WebSocket 前端集成**: ✅ 已完成。`composables/useWebSocket.js` 提供可复用 composable；SessionExplorer、SessionDetail、Report 均已接入 WebSocket 实时更新。
2. **虚拟滚动**: Session 列表和 Timeline 未实现虚拟滚动（Element Plus `el-table-v2` 可后续集成）
3. **国际化**: 当前全英文 UI，后续可加 i18n
