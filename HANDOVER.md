# Kyanos GNSS 专项开发 — 交接文档

> 最后更新: 2026-06-03  
> 分支: `feat/gnss-ntrip-rtcm-support`  
> 仓库: `https://github.com/naonaoyh/kyanos.git`  
> 上游: `https://github.com/hengyoush/kyanos` (原始 Kyanos 项目)

---

## 1. 项目概况

### 1.1 目标

基于 Kyanos (eBPF 网络分析工具) 二次开发，构建面向 GNSS 高精度定位服务的网络排障平台。核心能力包括：

- NTRIP v1/v2 协议解析与会话追踪
- RTCM 3.2 二进制帧解析与连续性分析
- 会话级诊断引擎（登录、GGA、RTCM、网络质量、连接稳定性）
- TCP 重传/拥塞与 RTCM 延迟关联分析
- 未来规划：PCAP 导出、Web Console、K8s 部署

### 1.2 技术栈

- **语言**: Go 1.24
- **模块名**: `kyanos` (go.mod)
- **项目路径**: `E:/Work/kyanos`
- **eBPF**: Kyanos 原始 BPF 层 (C + CO-RE)
- **TUI**: Bubble Tea (终端渲染)
- **测试**: 标准 `testing` 包，无外部测试框架依赖

### 1.3 开发环境注意

- 当前开发在 **Windows** 机器上进行
- Kyanos 依赖 Linux eBPF，因此编译验证使用 `GOOS=linux`
- 测试无法在 Windows 上直接运行（sysinfo 等 Linux-only 依赖），使用 `GOOS=linux go test -c` 编译验证
- 推荐验证命令序列:
  ```bash
  GOOS=linux go vet ./agent/session/...
  GOOS=linux go build ./agent/session/...
  GOOS=linux go test -c -o /dev/null ./agent/session/
  gofmt -l agent/session/*.go
  ```

---

## 2. 开发计划总览

完整开发计划文档: `docs/DEVELOPMENT_PLAN.md` (已扩展至约1200行)

| Phase | 名称 | 状态 |
|-------|------|------|
| 1 | RTCM 3.2 协议支持 | **已完成** (已提交 bc0c174) |
| 2 | NTRIP 协议支持 | **已完成** (已提交 bc0c174) |
| 3 | GNSS 综合视图与统计增强 | **已完成** (已提交 bc0c174) |
| 4 | 工程化与生产就绪 | **已完成** (已提交 bc0c174) |
| 5 | NTRIP 诊断引擎 | **进行中** (S1-S5 已完成, S6 + CLI 待做) |
| 6 | PCAP 导出与对象存储 | 未开始 |
| 7 | gRPC 通信层与 Agent 改造 | 未开始 |
| 8 | Web Console 后端 | 未开始 |
| 9 | Web Console 前端 | 未开始 |
| 10 | K8s 部署与集成测试 | 未开始 |

---

## 3. Phase 5 详细进度

Phase 5 包含 6 个排障场景 (S1-S6) + 诊断评分 + CLI 集成:

| 编号 | 场景 | 状态 | 核心文件 |
|------|------|------|---------|
| S1 | NTRIP 登录/认证分析 | **已完成** | `session/tracker.go`, `session/types.go` |
| S2 | GGA 上报时序分析 | **已完成** | `session/types.go` (GGAEvent, GGASummary) |
| S3 | RTCM 播发连续性分析 | **已完成** | `session/types.go` (RTCMEvent, RTCMDeliveryStats) |
| S4 | 网络切换与断连分析 | **已完成** | `session/correlator.go`, `session/types.go` (DisconnectReason) |
| S5 | TCP 重传/拥塞分析 | **已完成** | `session/tcp_health.go` |
| S6 | 多 Pod 负载分析 | **基础已完成** | `session/pod_load.go` (PodLoadAnalyzer, 见 ROADMAP_NEXT §10 T4) |
| — | 诊断评分引擎 | **基础已完成** | `session/types.go` (DiagnosticScore, Score()) |
| — | CLI flags 集成 | **基础已完成** | `--diag` 等开关 + `ntrip-user` group-by (见 ROADMAP_NEXT §10 T3); 报告渲染待做 |
| — | Tracker-Correlator 完整集成 | **已完成** | 通过 `tracker.AddListener(correlator)` 贯通 (见 ROADMAP_NEXT §10 T2) |
| — | 诊断引擎接入数据流 | **已完成(Go侧+BPF C侧)** | `agent/agent.go` + `agent/session_wiring.go` + BPF `is_ntrip_protocol` (见 ROADMAP_NEXT §10 T0/T1a) |

> **2026-06-03 增补**：继续开发的详细任务重排见 `docs/ROADMAP_NEXT.md`。本轮已完成
> T0（修复单向 Record 的 nil-Resp panic，Phase 1-4 潜伏崩溃）、T1a（诊断引擎接线 +
> BPF NTRIP 识别）、T2（Correlator 集成）、T3（CLI flags `--diag` 等 + `ntrip-user`
> group-by）、T4（S6 多 Pod 负载分析 `pod_load.go` + `--pod-load`）、TR（诊断结果
> 渲染 `report.go`：`--diag-report` 逐会话报告 + 退出时 Pod 负载汇总）、T5（清理：
> sort.Slice、闰秒可配置 `--leap-seconds`、scoring.go 拆分+死锁修复、recentRetrans
> 时间窗口）。Phase 5 的 Windows 可做部分全部完成；剩余仅 ⚠️LINUX 验证项
> （T1b header-scan、T6 真实构建、T7 e2e）。

### 3.1 Phase 5 §5.10 交付物清单 (对照)

| 文件 | 计划 | 实际状态 |
|------|------|---------|
| `agent/session/tracker.go` | 新建 | **已完成** (592行) |
| `agent/session/types.go` | 新建 | **已完成** (1147行) |
| `agent/session/correlator.go` | 新建 | **已完成** (254行) |
| `agent/session/tcp_health.go` | 新建 | **已完成** (785行) |
| `agent/session/scoring.go` | 新建 | **未独立** (Score() 在 types.go 中实现) |
| `agent/session/tracker_test.go` | 新建 | **已完成** (1118行) |
| `cmd/watch.go` | 修改 | **未开始** |
| `cmd/stat.go` | 修改 | **未开始** |

---

## 4. 当前代码状态

### 4.1 Git 状态

- **分支**: `feat/gnss-ntrip-rtcm-support`
- **最近提交**: `bc0c174 feat: add NTRIP v1/v2 and RTCM 3.2 GNSS protocol support` (Phase 1-4)
- **未提交变更**: Phase 5 所有新增代码均未提交 (用户要求 "暂时不用提交")

### 4.2 未提交的文件变更

**已修改 (Modified):**
- `agent/protocol/ntrip/ntrip.go` — GGA 解析增加 DiffAge/DiffStationID
- `agent/protocol/ntrip/ntrip_test.go` — 对应测试
- `docs/DEVELOPMENT_PLAN.md` — 扩展了 Phase 5-10 详细规划

**新增 (Untracked):**
- `agent/protocol/rtcm/epoch.go` — RTCM 历元时间提取 (241行)
- `agent/protocol/rtcm/epoch_test.go` — 历元提取测试 (200行)
- `agent/session/correlator.go` — 跨会话关联器 (254行)
- `agent/session/tcp_health.go` — TCP 健康分析器 (785行)
- `agent/session/tcp_health_test.go` — TCP 分析测试 (825行)
- `agent/session/tracker.go` — 会话追踪器核心 (592行)
- `agent/session/tracker_test.go` — 追踪器测试 (1118行)
- `agent/session/types.go` — 核心数据类型 (1147行)
- `agent/session/types_test.go` — 类型测试 (1173行)

### 4.3 测试统计

| 包 | 测试数 | 文件 |
|----|--------|------|
| `agent/session` | **130** | types_test(58) + tracker_test(37) + tcp_health_test(35) |
| `agent/protocol/ntrip` | **73** | ntrip_test.go |
| `agent/protocol/rtcm` | **48** | rtcm_test(38) + epoch_test(10) |
| **总计** | **251** | |

### 4.4 代码规模

| 类别 | 行数 |
|------|------|
| session 包 (生产代码) | ~2,778 行 |
| session 包 (测试代码) | ~3,116 行 |
| rtcm/epoch (生产+测试) | ~441 行 |
| ntrip 修改 | ~38 行 |
| **Phase 5 新增总计** | **~6,373 行** |

---

## 5. 核心架构与数据结构

### 5.1 数据流

```
eBPF kernel events
        │
        ▼
protocol.Record (Request/Response ParsedMessage)
        │
        ▼
SessionTracker.OnRecord(record, connInfo)
        │
        ├── *ntrip.NTRIPRequest → handleNTRIPRequest (S1: 认证)
        ├── *ntrip.NTRIPNMEASentence → handleNMEASentence (S2: GGA)
        ├── *ntrip.NTRIPRTCMFrame → handleRTCMFrame (S3: RTCM)
        └── *rtcm.RTCMFrame → handleRTCMFrame (S3: RTCM direct)

BPF TCP events (future hook)
        │
        ▼
SessionTracker.OnTCPRetransmission / OnTCPRoundTripTime / ... (S5)
        │
        ▼
NTRIPSession.TCPAnalyzer (TCPHealthAnalyzer)

Connection close events
        │
        ▼
SessionTracker.OnConnectionClose → disconnect analysis (S4)
```

### 5.2 关键类型关系

```
NTRIPSession
├── AuthMethod, AuthSuccess, HTTPStatusCode, ServerResponse (S1)
├── Password, NTRIPVersion, UserAgent (identity, configurable visibility)
├── GGAEvents []GGAEvent (S2)
│   └── Timestamp, GGAUtcTime, Latency, Lat/Lon, FixQuality, NumSatellites, DiffAge, Interval, Distance
├── RTCMEvents []RTCMEvent (S3)
│   └── Timestamp, EpochTime, Latency, MessageType, Size, CRCValid, Interval
├── RTCMDeliveryStats (computed on close)
├── NetworkQuality NetworkQualityStats (S5)
│   └── TotalRetransmissions, RetransmissionRate, AvgRTT, P95RTT, RTTJitter, ...
├── TCPAnalyzer *TCPHealthAnalyzer (S5, optional)
│   └── RetransmissionEvents, RTTSamples, WindowShrinks, DetectBursts, CorrelateWithRTCM
├── DisconnectReason, DisconnectDetail, CloseDirection (S4)
├── FieldVisibility (config: 13 boolean switches)
├── DiagnosticScore (Score() method)
└── LatencyStats (RTCMLatencyStats, GGALatencyStats)

SessionCorrelator
├── byUser map[string][]*NTRIPSession
├── OnSessionCreated → detect reconnection, IP change
├── ReconnectEvents, AccountSummary
└── SummarizeAccount
```

### 5.3 类型断言模式

处理 `protocol.Record` 时使用类型断言：

```go
switch msg := record.Request().(type) {
case *ntrip.NTRIPRequest:     // HTTP auth request
case *ntrip.NTRIPNMEASentence: // GGA/NMEA upload
case *ntrip.NTRIPRTCMFrame:   // RTCM wrapped in NTRIP
case *rtcm.RTCMFrame:         // Direct RTCM stream
}
```

`conn.Connection4` 字段: `LocalIp`, `RemoteIp`, `LocalPort`, `RemotePort`, `IsServerSide()`

### 5.4 关键包依赖

```
kyanos/agent/protocol          → Record, ParsedMessage, FrameBase 接口
kyanos/agent/protocol/ntrip    → NTRIPRequest, NTRIPResponse, NTRIPNMEASentence, NTRIPRTCMFrame
kyanos/agent/protocol/rtcm     → RTCMFrame, ExtractEpochMs, EpochToUTC
kyanos/agent/session           → NTRIPSession, SessionTracker, SessionCorrelator, TCPHealthAnalyzer
```

---

## 6. 重要技术决策与注意事项

### 6.1 GOOS=linux 交叉编译

- 项目在 Windows 上开发，但 Kyanos 是 Linux eBPF 程序
- **必须**用 `GOOS=linux` 编译验证
- 不能直接在 Windows 上运行测试 (`go test` 会因 `sysinfo` 等包失败)
- 验证命令: `GOOS=linux go test -c -o /dev/null ./agent/session/`

### 6.2 RTCM 历元时间提取

- MSM 消息 (1071-1137): 30-bit epoch, GPS 周内毫秒 (mod 604,800,000)
- GPS legacy (1001-1004): 24-bit epoch, GPS 小时内毫秒 (mod 3,600,000)
- GLONASS legacy (1009-1012): 27-bit epoch, GLONASS 天内毫秒 (mod 86,400,000)
- GPS 历元: 1980-01-06 UTC, 闰秒 GPS-UTC = 18 (可能需要随时间更新!)
- 位级解析: payload 从第 3 字节开始 (跳过 D3+10bit len+6bit filler)

### 6.3 GGA UTC 时间解析

- GGA 只有时间 (hhmmss.ss), 没有日期
- 借用 capture timestamp 的日期部分
- 午夜翻转处理: 如果 GGA TOD 比 capture TOD 超前 >12h, 假设是前一天

### 6.4 延迟计算

- `Latency = capture_time (系统时钟) - content_time (GNSS 时钟)`
- 包含网络延迟 + 系统时钟偏差
- 长期统计 (P50/P95/Jitter) 可分离系统性偏移和网络抖动

### 6.5 字段可见性配置

- `FieldVisibility` 结构体控制哪些字段被提取/显示
- 默认隐藏密码 (`ShowPassword = false`)
- Tracker 在填充字段时检查对应 visibility flag

### 6.6 断连原因分类优先级

1. Auth failure (最强信号)
2. Account kick-out (correlator 提供)
3. Client-initiated close (CloseClient 方向)
4. RTCM retransmission abort (server close + 高重传数)
5. GGA timeout (server close + GGA 停报超时)
6. Unknown

### 6.7 内存保护

- RTCMEvents 上限 100,000 条 (防内存爆炸)
- sortDurations 使用插入排序 (小数据集 OK, 大数据集考虑换 sort.Slice)
- TCPHealthAnalyzer 有独立的 mutex (不嵌套 session mutex)

### 6.8 已知限制

- `recentRetransCount` 目前是简单计数器，未按时间窗口衰减 (DisconnectRTCMAbort 判断依赖此值)
- `DiagnosticScore` 实现在 types.go 而非独立的 scoring.go
- Tracker 与 Correlator 未完全集成 (Correlator.OnSessionCreated 需要被 Tracker 调用)
- TCP 事件入口方法已定义但尚未从 BPF 层实际调用 (需要 wire up)

---

## 7. Phase 5 剩余工作

### 7.1 S6: 多 Pod 负载分析 (优先级高)

需要实现:
- 每 Pod 连接数/帧率聚合
- 会话粘滞检测
- Pod 切换事件 (扩展 SessionCorrelator)
- 负载不均告警 (变异系数)

建议新建 `agent/session/pod_load.go`，包含:
```go
type PodLoadAnalyzer struct { ... }
type PodStats struct { PodName string; Connections int; FrameRate float64; ... }
func (p *PodLoadAnalyzer) LoadImbalance() float64  // 变异系数
```

### 7.2 Tracker-Correlator 集成 (优先级高)

当前 `SessionTracker.getOrCreateSession()` 创建新会话时没有调用 `correlator.OnSessionCreated()`。需要:
```go
// In tracker.go getOrCreateSession():
if t.correlator != nil {
    t.correlator.OnSessionCreated(s)
}
```
同时需要在 TrackerConfig 中添加 Correlator 实例或让 Tracker 内部持有。

### 7.3 CLI flags 集成 (优先级中)

计划的 flags:
```
kyanos watch ntrip --auth-log            # 仅输出登录事件
kyanos watch ntrip --auth-fail-only      # 仅输出认证失败
kyanos watch ntrip --gga-interval-warn 5s
kyanos watch ntrip --reconnect-detect
kyanos watch ntrip --reconnect-window 60s
kyanos watch rtcm --interruption-warn 2s
kyanos watch rtcm --fps
kyanos stat ntrip --group-by ntrip-user
kyanos stat rtcm --group-by rtcm-msg-type
```

需要修改: `cmd/watch.go`, `cmd/stat.go`

### 7.4 DiagnosticScore 增强 (优先级低)

- 提取到独立 `scoring.go` 文件
- 增加 NetworkScore 中的 TCP 健康分析器数据
- 增加 StabilityScore 中的 Pod 切换事件

### 7.5 recentRetransCount 时间窗口 (优先级低)

当前 `recentRetransCount` 是简单递增计数器。理想实现应该是时间窗口内的计数 (例如关闭前 30 秒内的重传数)。可以用 TCPHealthAnalyzer 的 `RetransmissionEvents` 时间戳来实现精确窗口。

---

## 8. 文件速查表

### 8.1 新增文件 (session 包)

| 文件 | 行数 | 说明 |
|------|------|------|
| `agent/session/types.go` | 1147 | NTRIPSession 核心类型、GGA/RTCM 事件、延迟统计、评分 |
| `agent/session/tracker.go` | 592 | SessionTracker 中央聚合器、Record 处理、TCP 事件入口 |
| `agent/session/correlator.go` | 254 | SessionCorrelator 跨会话关联、重连检测、账户摘要 |
| `agent/session/tcp_health.go` | 785 | TCPHealthAnalyzer 重传/RTT/窗口/burst/关联分析 |
| `agent/session/types_test.go` | 1173 | 核心类型测试 (58 个) |
| `agent/session/tracker_test.go` | 1118 | 追踪器集成测试 (37 个) |
| `agent/session/tcp_health_test.go` | 825 | TCP 分析器测试 (35 个) |

### 8.2 新增文件 (rtcm 包)

| 文件 | 行数 | 说明 |
|------|------|------|
| `agent/protocol/rtcm/epoch.go` | 241 | RTCM 历元提取、GPS 周数计算、UTC 转换 |
| `agent/protocol/rtcm/epoch_test.go` | 200 | 历元提取测试 (10 个) |

### 8.3 修改文件

| 文件 | 变更 | 说明 |
|------|------|------|
| `agent/protocol/ntrip/ntrip.go` | +23 行 | GGA DiffAge/DiffStationID 解析 |
| `agent/protocol/ntrip/ntrip_test.go` | +15 行 | DiffAge 测试断言 |
| `docs/DEVELOPMENT_PLAN.md` | +988 行 | Phase 5-10 详细规划 |

### 8.4 Phase 1-4 已提交文件 (参考)

已包含在 commit `bc0c174` 中:
- `agent/protocol/ntrip/` — NTRIP v1/v2 解析器 (ntrip.go, types.go, filter.go, sourcetable.go)
- `agent/protocol/rtcm/` — RTCM 3.2 解析器 (rtcm.go, types.go, crc24q.go, filter.go, export.go)
- `cmd/ntrip.go`, `cmd/rtcm.go` — CLI 子命令
- BPF 层修改 (协议枚举、识别函数)

---

## 9. 编码约定

1. **命名**: Go 标准风格 (CamelCase exported, camelCase unexported)
2. **注释**: 每个 exported 类型/函数必须有 godoc 注释
3. **测试**: `TestXxx` 函数，不使用 testify 等外部框架
4. **Mutex**: 每个聚合器 (Session, Tracker, Correlator, TCPHealthAnalyzer) 有独立的 `sync.RWMutex`，避免嵌套锁
5. **时间**: 统一使用 `time.Time` (UTC), 间隔使用 `time.Duration`
6. **错误处理**: 协议解析容错 (不 panic, 返回 zero value), 分析器方法不返回 error
7. **格式化**: `gofmt` 标准格式

---

## 10. 快速恢复指南

给下一个 AI 助手的 prompt 模板:

```
我在继续开发 Kyanos GNSS 排障平台项目。项目路径是 E:/Work/kyanos，
分支是 feat/gnss-ntrip-rtcm-support。

关键背景:
- Go 1.24 项目，模块名 "kyanos"
- 必须用 GOOS=linux 编译验证 (Windows 开发环境)
- Phase 1-4 已提交 (RTCM + NTRIP 协议支持)
- Phase 5 进行中 (诊断引擎)，S1-S5 已完成，代码未提交
- 详细开发计划: docs/DEVELOPMENT_PLAN.md
- 交接文档: HANDOVER.md (本文件)

请先阅读:
1. docs/DEVELOPMENT_PLAN.md (开发计划)
2. agent/session/types.go (核心数据结构)
3. agent/session/tracker.go (会话追踪器)
4. agent/session/tcp_health.go (TCP 分析器)

下一步待做:
1. S6: 多 Pod 负载分析 (agent/session/pod_load.go 新建)
2. Tracker-Correlator 完整集成
3. CLI flags 集成 (cmd/watch.go, cmd/stat.go)
4. 提交当前未提交的代码
```

---

## 11. 常见陷阱

| 陷阱 | 说明 | 解决方案 |
|------|------|---------|
| `go test` 在 Windows 失败 | sysinfo 等 Linux-only 依赖 | 用 `GOOS=linux go test -c` |
| Edit 工具字符串匹配失败 | 文件中有 tab/space 差异 | 先 Read 确认精确内容再 Edit |
| 签名变更级联 | 修改 AddGGAEvent 等函数签名需更新所有调用点 | 使用 replace_all 批量更新 |
| byte 常量溢出 | `byte(0xEC<<4)` = 3776 超范围 | 手动计算目标 byte 值 |
| RTCM payload 偏移 | RawBytes 含 3 字节 header, payload 从 [3:] 开始 | 位解析时 offset 要加上 24 (header bits) |
| GPS 闰秒变化 | 当前 LeapSecondsGPSUTC=18, 未来可能更新 | 需要时可配置化 |
| 插入排序性能 | sortDurations 用插入排序, n>1000 时慢 | 可换 sort.Slice |
