# Kyanos NTRIP 专项排障平台 — 开发规划

## 一、项目背景与目标

### 1.1 初始目标（Phase 1-4，已完成）

基于 Kyanos (eBPF 网络分析工具) 进行二次开发，新增对以下协议的原生支持：

- **NTRIP v1/v2**：GNSS 差分改正数据传输协议，基于 HTTP 长连接推流
- **RTCM 3.2**：GNSS 改正数二进制帧格式，通过 TCP 直连或 NTRIP 隧道传输

已交付：可独立运行的 kyanos 二进制，通过 `kyanos watch ntrip` / `kyanos watch rtcm` 等命令实现对上述协议的精准捕获、协议级解析和可视化展示。包含认证凭据提取、GGA 位置解析、RTCM 数据导出等能力。

### 1.2 扩展目标（Phase 5-10，进行中）

将 Kyanos 从单机抓包工具升级为**面向 GNSS 高精度定位服务的网络排障平台**，面向以下核心场景：

- NTRIP 客户端登录异常检测与认证分析
- GGA 上报时序监控与定位质量追踪
- RTCM 播发连续性监控与中断检测
- 设备端 WiFi↔4G 网络切换的业务影响分析
- TCP 重传/拥塞与 RTCM 数据延迟关联分析
- 多 Pod 负载均衡与会话路由分析

交付物：

- **NTRIP 诊断引擎**：会话级追踪、时序分析、异常检测
- **Web Console**：统一控制面，支持集群抓包调度、会话浏览器、诊断报告
- **K8s 部署方案**：DaemonSet Agent + 集中控制面，适配腾讯云 TKE 环境（20+ Pod DS 微服务）

---

## 二、现有架构分析

### 2.1 Kyanos 数据流

```
┌─────────────────────────────────────────────────────────────────────┐
│ eBPF Kernel Layer                                                   │
│  pktlatency.bpf.c                                                   │
│  ├── syscall hook (read/write/send/recv enter/exit)                 │
│  ├── TCP/IP stack hook (tcp_sendmsg, tcp_recvmsg, ip_rcv, etc.)    │
│  ├── Device layer hook (dev_hard_start_xmit, napi_gro_receive)      │
│  ├── XDP hook (optional, for raw packet capture)                    │
│  └── protocol_inference.h (内核态协议初步识别)                        │
│       ├── is_http_protocol()                                        │
│       ├── is_redis_protocol()                                       │
│       ├── is_mysql_protocol()                                       │
│       ├── is_kafka_protocol()                                       │
│       ├── is_mongo_protocol()                                       │
│       ├── is_rocketmq_protocol()                                    │
│       └── is_dns_protocol()                                         │
│                                                                     │
│  perf_event / ring_buffer → 用户态                                  │
└───────────────────────┬─────────────────────────────────────────────┘
                        │ kern_evt_data (含 payload)
                        ▼
┌─────────────────────────────────────────────────────────────────────┐
│ User-space Agent Layer                                              │
│  agent/conn/processor.go     → 接收 eBPF 事件，管理连接状态           │
│  agent/conn/conntrack.go     → 连接跟踪（五元组、容器元数据关联）       │
│  agent/buffer/               → StreamBuffer 流式数据缓冲             │
│  agent/protocol/             → 协议解析器（核心扩展点）                │
│       ├── protocol.go        → ProtocolStreamParser 接口定义         │
│       ├── ParsersMap         → 全局注册表 (protocol enum → parser)   │
│       ├── http.go / redis..go / mysql/ / kafka/ / mongodb/ / dns/   │
│       └── rocketmq/                                                  │
│  agent/conn/record_processor.go → 请求/响应配对，生成 Record          │
│  agent/analysis/             → 流量聚合分析                          │
│  agent/render/               → TUI 渲染 (Bubble Tea)                │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 协议扩展的 5 个触点

添加新协议需要修改以下 5 个位置：

| # | 触点 | 文件位置 | 说明 |
|---|------|---------|------|
| 1 | 协议枚举 | `bpf/pktlatency.h` + 自动生成的 `bpf/agent_*_bpfel.go` | 在 `traffic_protocol_t` 中新增枚举值 |
| 2 | 内核态协议识别 | `bpf/protocol_inference.h` | 新增 `is_xxx_protocol()` 函数，加入 `infer_protocol()` 链 |
| 3 | 用户态协议解析器 | `agent/protocol/xxx/` | 实现 `ProtocolStreamParser` + `ParsedMessage` + `ProtocolFilter` 接口 |
| 4 | 解析器注册 | `agent/protocol/xxx/xxx.go` 的 `init()` | 向 `ParsersMap` 注册解析器 |
| 5 | CLI 子命令 | `cmd/xxx.go` | 新增 Cobra 命令，注册到 `watchCmd` 和 `statCmd` |

### 2.3 核心接口定义

```go
// 协议解析器接口 (agent/protocol/protocol.go)
type ProtocolStreamParser interface {
    ParseStream(streamBuffer *buffer.StreamBuffer, messageType MessageType) ParseResult
    FindBoundary(streamBuffer *buffer.StreamBuffer, messageType MessageType, startPos int) int
    Match(reqStreams map[StreamId]*ParsedMessageQueue,
          respStreams map[StreamId]*ParsedMessageQueue) []Record
}

// 已解析消息接口
type ParsedMessage interface {
    FormatToString() string
    TimestampNs() uint64
    ByteSize() int
    IsReq() bool
    Seq() uint64
    StreamId() StreamId
}

// 协议过滤器接口
type ProtocolFilter interface {
    Filter(req ParsedMessage, resp ParsedMessage) bool
    FilterByProtocol(bpf.AgentTrafficProtocolT) bool
    FilterByRequest() bool
    FilterByResponse() bool
    Protocol() bpf.AgentTrafficProtocolT
}
```

---

## 三、协议分析与设计

### 3.1 RTCM 3.2 帧结构

```
┌──────────┬───────────┬──────────┬───────────────────┬───────────┐
│ Preamble │ Reserved  │  Length  │      Payload      │  CRC-24Q  │
│  8 bits  │  6 bits   │ 10 bits  │  Length * 8 bits  │  24 bits  │
│  0xD3    │  0b000000 │ 0-1023   │  (含 Message Type) │           │
└──────────┴───────────┴──────────┴───────────────────┴───────────┘
  Byte 0     Byte 1-2 (前6位保留,后10位长度)  Byte 3 ~ 3+Len-1    最后3字节
```

关键特征：
- **Preamble**: 固定 `0xD3`
- **Length**: 10-bit，最大 1023 字节
- **Message Type**: Payload 前 12 bits (bit 0-11)，范围 0-4095
- **CRC-24Q**: Qualcomm CRC-24 校验，多项式 `0x1864CFB`
- **常见消息类型**: 1005 (站坐标), 1074-1077 (GPS 观测), 1124-1127 (BDS 观测), 1044 (QZSS)

### 3.2 NTRIP v1 协议特征

```
请求示例:
GET /MOUNT01 HTTP/1.1\r\n
User-Agent: NTRIP client\r\n
Authorization: Basic dXNlcjpwYXNz\r\n
\r\n

响应:
ICY 200 OK\r\n
\r\n
[RTCM 3.2 binary frames...]
```

注意：v1 使用非标准 `ICY 200 OK` 响应头（不是 `HTTP/1.1 200 OK`），这是 NTRIP v1 的显著特征。

### 3.3 NTRIP v2 协议特征

```
请求示例:
GET /MOUNT01 HTTP/1.1\r\n
Host: ntrip.example.com:2101\r\n
User-Agent: NTRIP client/2.0\r\n
Authorization: Basic dXNlcjpwYXNz\r\n
Ntrip-Version: Ntrip/2.0\r\n
\r\n

响应:
HTTP/1.1 200 OK\r\n
Ntrip-Version: Ntrip/2.0\r\n
Content-Type: gnss/data\r\n
Transfer-Encoding: chunked\r\n
\r\n
[chunked RTCM 3.2 binary frames...]
```

v2 使用标准 HTTP/1.1 + `Ntrip-Version` header + chunked encoding。

### 3.4 NTRIP SOURCETABLE（目录服务）

```
GET / HTTP/1.1\r\n
User-Agent: NTRIP client\r\n
\r\n

响应 (SOURCETABLE):
SOURCETABLE 200 OK\r\n
Content-Type: text/plain\r\n
\r\n
STR;MOUNT01;Station 01;RTCM 3.2;1005(10),1074(1),1124(1);0;GPS+GLO+BDS;...
STR;MOUNT02;Station 02;RTCM 3.0;1004(1),1012(1);...
ENDSOURCETABLE
```

---

## 四、分阶段开发计划

### Phase 1：RTCM 3.2 协议支持（核心基础）

> **目标**: 实现对 TCP 直连 RTCM 数据流的精准捕获和帧级解析
> **预计工作量**: 1.5-2 周
> **优先级**: P0 (Phase 2 的 NTRIP 依赖此阶段)

#### 1.1 eBPF 层：协议识别

**文件**: `bpf/pktlatency.h`

在 `traffic_protocol_t` 枚举中新增：

```c
enum traffic_protocol_t {
  // ... 现有协议 ...
  kProtocolRocketMQ,    // = 14
  kProtocolNTRIP,       // = 15  ← 新增
  kProtocolRTCM,        // = 16  ← 新增
  kNumProtocols         // = 17  (自动递增)
};
```

**文件**: `bpf/protocol_inference.h`

新增 RTCM 识别函数。核心启发式逻辑：

```c
static __always_inline enum message_type_t is_rtcm_protocol(const char *old_buf, size_t count) {
  // RTCM 最小帧: preamble(1) + length+reserved(2) + CRC(3) = 6 bytes
  if (count < 6) {
    return kUnknown;
  }

  char buf[3] = {};
  bpf_probe_read_user(buf, 3, old_buf);

  // 检查 preamble: 必须是 0xD3
  if ((uint8_t)buf[0] != 0xD3) {
    return kUnknown;
  }

  // 检查保留位: byte1 的高 6 位必须为 0
  if ((buf[1] & 0xFC) != 0x00) {
    return kUnknown;
  }

  // 提取 length (10 bits): byte1 低 2 位 + byte2
  uint16_t length = ((uint16_t)(buf[1] & 0x03) << 8) | (uint8_t)buf[2];

  // length 合理性检查: 0-1023, 且不超过 count
  if (length > 1023) {
    return kUnknown;
  }

  // 总帧长 = preamble(1) + length_header(2) + payload(length) + CRC(3)
  // 注意: eBPF 层看到的是 syscall 级别的数据，可能包含多个帧或帧的一部分
  // 这里只做基本合理性判断，完整解析交给用户态

  return kRequest;  // RTCM 是单向推流，不区分 req/resp
}
```

在 `infer_protocol()` 链中添加（注意放在 HTTP 之后，因为 RTCM 数据也可能通过 HTTP/NTRIP 传输）：

```c
  // ... 现有协议检测 ...
  } else if (TRACE_PROTOCOL(kProtocolRTCM) &&
             (protocol_message.type = is_rtcm_protocol(buf, count)) != kUnknown) {
    protocol_message.protocol = kProtocolRTCM;
  }
```

**注意事项**:
- RTCM preamble `0xD3` 虽然辨识度较高，但需配合 reserved bits 和 length 范围做联合判断，降低误报率
- 在 `infer_protocol()` 链中，RTCM 检测应放在 HTTP 检测之后（因为 NTRIP 场景下，HTTP 层会先被识别）
- RTCM 是单向推流，没有请求/响应配对，message type 统一设为 `kRequest` 或新增一个 `kStream` 类型

#### 1.2 用户态：RTCM 解析器

**目录结构**:

```
agent/protocol/rtcm/
├── rtcm.go          # 主解析器: RTCMStreamParser + RTCMFrame
├── crc24q.go        # CRC-24Q 校验实现
├── types.go         # RTCM 消息类型常量和定义
└── filter.go        # RTCMFilter 实现
```

**核心类型设计**:

```go
// types.go
package rtcm

// RTCM 3.2 消息类型
const (
    MsgStationCoords    = 1005  // 基站坐标
    MsgStationAntenna   = 1006  // 基站天线信息
    MsgGPSObservations  = 1074  // GPS MSM4 观测值
    MsgGPSObservations7 = 1077  // GPS MSM7 观测值
    MsgGLObservations   = 1124  // BDS MSM4
    MsgGLObservations7  = 1127  // BDS MSM7
    // ... 更多消息类型
)

var MessageTypeNames = map[int]string{
    1005: "Station ARP Coordinates",
    1006: "Station ARP with Antenna Height",
    1074: "GPS MSM4",
    1077: "GPS MSM7",
    1124: "BDS MSM4",
    1127: "BDS MSM7",
    // ...
}
```

```go
// rtcm.go
package rtcm

import (
    "kyanos/agent/buffer"
    "kyanos/agent/protocol"
    "kyanos/bpf"
)

var _ protocol.ProtocolStreamParser = &RTCMStreamParser{}
var _ protocol.ParsedMessage = &RTCMFrame{}

// RTCMFrame 表示一个完整的 RTCM 3.2 帧
type RTCMFrame struct {
    protocol.FrameBase
    Preamble    uint8
    Length      uint16    // payload 长度
    MessageType int       // RTCM 消息类型 (12 bits)
    Payload     []byte    // 原始 payload
    CRCValid    bool      // CRC 校验结果
    CRCExpected uint32    // 期望的 CRC
    CRCActual   uint32    // 实际的 CRC
}

func (f *RTCMFrame) IsReq() bool       { return true }  // RTCM 是单向推流
func (f *RTCMFrame) StreamId() protocol.StreamId { return 0 }
func (f *RTCMFrame) FormatToString() string {
    name, ok := MessageTypeNames[f.MessageType]
    if !ok {
        name = "Unknown"
    }
    return fmt.Sprintf(
        "RTCM Frame: type=%d(%s) length=%d crc_valid=%v",
        f.MessageType, name, f.Length, f.CRCValid,
    )
}

// RTCMStreamParser 实现 ProtocolStreamParser
type RTCMStreamParser struct{}

func (p *RTCMStreamParser) FindBoundary(
    sb *buffer.StreamBuffer, mt protocol.MessageType, startPos int,
) int {
    // 扫描 0xD3 preamble
    head := sb.Head().Buffer()
    for i := startPos; i < len(head); i++ {
        if head[i] == 0xD3 {
            // 验证 reserved bits
            if i+2 < len(head) && (head[i+1]&0xFC) == 0x00 {
                return i
            }
        }
    }
    return -1
}

func (p *RTCMStreamParser) ParseStream(
    sb *buffer.StreamBuffer, mt protocol.MessageType,
) protocol.ParseResult {
    head := sb.Head().Buffer()
    if len(head) < 6 {
        return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
    }

    // 1. 检查 preamble
    if head[0] != 0xD3 {
        return protocol.ParseResult{ParseState: protocol.Invalid}
    }

    // 2. 提取 length
    length := uint16(head[1]&0x03)<<8 | uint16(head[2])
    totalFrameLen := int(length) + 6  // preamble(1) + header(2) + payload + CRC(3)

    if len(head) < totalFrameLen {
        return protocol.ParseResult{ParseState: protocol.NeedsMoreData}
    }

    // 3. 提取 message type (payload 前 12 bits)
    if length < 2 {
        return protocol.ParseResult{ParseState: protocol.Invalid}
    }
    msgType := int(head[3])<<4 | int(head[4])>>4
    msgType &= 0x0FFF  // 12 bits

    // 4. CRC-24Q 校验
    frameData := head[:totalFrameLen]
    crcValid := VerifyCRC24Q(frameData)

    // 5. 构造 RTCMFrame
    seq := sb.Head().LeftBoundary()
    ts, ok := sb.FindTimestampBySeq(seq)
    if !ok {
        return protocol.ParseResult{ParseState: protocol.Ignore}
    }

    frame := &RTCMFrame{
        FrameBase:   protocol.NewFrameBase(ts, totalFrameLen, seq),
        Preamble:    0xD3,
        Length:      length,
        MessageType: msgType,
        Payload:     frameData[3 : 3+length],
        CRCValid:    crcValid,
    }

    return protocol.ParseResult{
        ParseState:     protocol.Success,
        ParsedMessages: []protocol.ParsedMessage{frame},
        ReadBytes:      totalFrameLen,
    }
}

func (p *RTCMStreamParser) Match(
    reqStreams map[protocol.StreamId]*protocol.ParsedMessageQueue,
    respStreams map[protocol.StreamId]*protocol.ParsedMessageQueue,
) []protocol.Record {
    // RTCM 是单向推流，不需要 req/resp 配对
    // 每个帧直接作为独立的 Record 返回
    records := make([]protocol.Record, 0)
    if reqStream, ok := reqStreams[0]; ok {
        for _, msg := range *reqStream {
            records = append(records, protocol.Record{Req: msg})
        }
    }
    return records
}

func init() {
    protocol.ParsersMap[bpf.AgentTrafficProtocolTKProtocolRTCM] = func() protocol.ProtocolStreamParser {
        return &RTCMStreamParser{}
    }
}
```

```go
// filter.go
package rtcm

import (
    "kyanos/agent/protocol"
    "kyanos/bpf"
)

// RTCMFilter 支持按消息类型过滤
type RTCMFilter struct {
    TargetMessageTypes []int    // 只关注特定消息类型
    CRCErrorsOnly      bool     // 只看 CRC 校验失败的帧
}

func (f RTCMFilter) Filter(req, resp protocol.ParsedMessage) bool {
    frame, ok := req.(*RTCMFrame)
    if !ok {
        return false
    }
    if f.CRCErrorsOnly && frame.CRCValid {
        return false
    }
    if len(f.TargetMessageTypes) > 0 {
        found := false
        for _, t := range f.TargetMessageTypes {
            if frame.MessageType == t {
                found = true
                break
            }
        }
        if !found {
            return false
        }
    }
    return true
}

func (f RTCMFilter) FilterByProtocol(p bpf.AgentTrafficProtocolT) bool {
    return p == bpf.AgentTrafficProtocolTKProtocolRTCM
}
func (f RTCMFilter) FilterByRequest() bool { return true }
func (f RTCMFilter) FilterByResponse() bool { return false }
func (f RTCMFilter) Protocol() bpf.AgentTrafficProtocolT {
    return bpf.AgentTrafficProtocolTKProtocolRTCM
}
```

#### 1.3 CLI 命令

**文件**: `cmd/rtcm.go`

```go
package cmd

import (
    "kyanos/agent/protocol/rtcm"
    "github.com/spf13/cobra"
)

var rtcmCmd = &cobra.Command{
    Use:   "rtcm [--msg-type TYPES]",
    Short: "Watch RTCM 3.2 GNSS correction frames",
    Run: func(cmd *cobra.Command, args []string) {
        msgTypes, _ := cmd.Flags().GetIntSlice("msg-type")
        crcErrors, _ := cmd.Flags().GetBool("crc-errors")

        options.MessageFilter = rtcm.RTCMFilter{
            TargetMessageTypes: msgTypes,
            CRCErrorsOnly:      crcErrors,
        }
        options.LatencyFilter = initLatencyFilter(cmd)
        options.SizeFilter = initSizeFilter(cmd)
        startAgent()
    },
}

func init() {
    rtcmCmd.Flags().IntSlice("msg-type", []string{},
        "Filter by RTCM message types (e.g. 1005,1074,1127)")
    rtcmCmd.Flags().Bool("crc-errors", false,
        "Only show frames with CRC-24Q validation errors")
    copy := *rtcmCmd
    watchCmd.AddCommand(&copy)
    copy2 := *rtcmCmd
    statCmd.AddCommand(&copy2)
}
```

#### 1.4 Phase 1 交付物清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `bpf/pktlatency.h` | 修改 | 新增 `kProtocolRTCM` 和 `kProtocolNTRIP` 枚举值 |
| `bpf/protocol_inference.h` | 修改 | 新增 `is_rtcm_protocol()` + 加入 `infer_protocol()` |
| `agent/protocol/rtcm/rtcm.go` | 新建 | RTCMStreamParser + RTCMFrame |
| `agent/protocol/rtcm/crc24q.go` | 新建 | CRC-24Q 校验算法 |
| `agent/protocol/rtcm/types.go` | 新建 | RTCM 消息类型常量 |
| `agent/protocol/rtcm/filter.go` | 新建 | RTCMFilter |
| `agent/protocol/rtcm/rtcm_test.go` | 新建 | 单元测试 |
| `cmd/rtcm.go` | 新建 | CLI 子命令 |
| `cmd/watch.go` | 修改 | `supportedProtocols` 中添加 "rtcm" |
| `bpf/common.go` | 修改 | `ProtocolNamesMap` 中添加 RTCM 条目 |

---

### Phase 2：NTRIP 协议支持

> **目标**: 识别 NTRIP v1/v2 会话，解析 mountpoint、认证、流状态
> **预计工作量**: 1.5-2 周
> **依赖**: Phase 1 (RTCM 解析器)
> **优先级**: P0

#### 2.1 设计思路

NTRIP 本质上运行在 HTTP 之上。有两种实现策略：

**策略 A（推荐）：作为 HTTP 协议的扩展**

不新增独立的 eBPF 协议识别，而是利用现有的 `is_http_protocol()` 识别 HTTP 流量，然后在用户态的 HTTP 解析器中检测 NTRIP 特征（ICY 响应、Ntrip-Version header、gnss/data content-type）。当检测到 NTRIP 会话时，将后续的二进制数据流交给 RTCM 解析器处理。

优势：不需要修改 eBPF 代码，实现简单，且能自动支持 HTTP/1.1 chunked encoding。

**策略 B：独立的 NTRIP 协议识别**

在 eBPF 层新增 `is_ntrip_protocol()`，检测 NTRIP 特有的 header 模式（如 `ICY ` 开头、`Ntrip-Version`、`SOURCETABLE`）。

劣势：NTRIP v2 就是标准 HTTP，在内核态区分两者价值不大，且增加 eBPF 指令数。

**推荐策略 A**，具体实现：

#### 2.2 NTRIP 解析器设计

**目录结构**:

```
agent/protocol/ntrip/
├── ntrip.go         # NTRIPSession + NTRIPStreamParser
├── types.go         # NTRIP 相关常量
├── filter.go        # NTRIPFilter
└── sourcetable.go   # SOURCETABLE 解析
```

**核心类型**:

```go
// types.go
type NTRIPVersion int
const (
    NTRIPv1 NTRIPVersion = 1
    NTRIPv2 NTRIPVersion = 2
)

// NTRIPRequest 表示 NTRIP 客户端请求
type NTRIPRequest struct {
    protocol.FrameBase
    Method      string           // GET, POST, SOURCE
    Path        string           // 请求路径
    Version     NTRIPVersion     // 检测到的 NTRIP 版本
    SessionType NTRIPSessionType // DataStream, SourcePush, Sourcetable
    MountPoint  string           // 提取的挂载点名称
    HasAuth     bool             // 是否有 Authorization 头
    Username    string           // 提取的用户名（Basic Auth 或 SOURCE 方法）
    Password    string           // 提取的密码（Basic Auth 或 SOURCE 方法）
    UserAgent   string           // 客户端 User-Agent
    ContentType string           // Content-Type 头
}

// NTRIPNMEASentence 表示客户端上传的 NMEA 句子（通常为 GGA）
type NTRIPNMEASentence struct {
    protocol.FrameBase
    SentenceType  string   // "GGA", "RMC" 等
    Raw           string   // 完整的 NMEA 句子
    GGAParsed     bool     // 是否成功解析了 GGA 字段
    UTCTime       string   // UTC 时间 (hhmmss.ss)
    Latitude      float64  // 纬度（十进制度，南纬为负）
    Longitude     float64  // 经度（十进制度，西经为负）
    FixQuality    int      // 定位质量: 0=无效,1=GPS,2=DGPS,4=RTK固定,5=RTK浮动
    NumSatellites int      // 使用卫星数
    HDOP          float64  // 水平精度因子
    Altitude      float64  // 天线海拔高度（米）
}
```

**认证凭据提取**（用户态）:

NTRIP 客户端的认证信息从两个来源提取：

1. **Basic Auth 头**: 解析 `Authorization: Basic base64(user:pass)` 头部，base64 解码后按 `:` 分隔得到用户名和密码。支持特殊字符和 Unicode 用户名。

```go
func parseBasicAuth(header string) (username, password string, ok bool) {
    // "Basic dXNlcjpwYXNz" → ("user", "pass", true)
}
```

2. **SOURCE 方法**: NTRIP v1 的 `SOURCE <password> /mountpoint` 格式中，密码直接出现在请求行。此时只有密码，没有用户名。

当同时存在 SOURCE 密码和 Authorization 头时，Basic Auth 的用户名优先（SOURCE 密码不覆盖 Basic Auth 解析的用户名）。

**GGA 位置上传解析**:

NTRIP 客户端（流动站）在使用 VRS（虚拟参考站）服务时，会周期性地向 Caster 上传 NMEA GGA 句子，告知自身位置。解析器从 GGA 句子中提取：

- UTC 时间
- 经纬度（`ddmm.mmmm` 格式转十进制度，自动处理 N/S/E/W 半球符号）
- 定位质量（0=无效, 1=GPS, 2=DGPS, 4=RTK-Fixed, 5=RTK-Float）
- 使用卫星数
- HDOP（水平精度因子）
- 天线海拔高度

```go
func parseGGASentence(sentence string, nmea *NTRIPNMEASentence) {
    // 解析 GGA 逗号分隔字段，填充 GGA 专用字段
}

func parseNMEACoord(coord, dir string) (float64, error) {
    // "5000.0000", "N" → 50.0
    // "12130.0000", "E" → 121.5
}
```

**NTRIP 检测逻辑**（用户态，策略 A 实现）:

NTRIPStreamParser 通过 `detectMode()` 自动检测流量方向，然后在 `parseRequest()` 中：

1. 解析 HTTP 请求行（GET/POST/SOURCE）和请求路径
2. 解析 MIME 头，检测 `Ntrip-Version: Ntrip/2.0` 判断版本
3. 从 `Authorization` 头提取 Basic Auth 凭据（`parseBasicAuth()`）
4. 对 SOURCE 方法从请求行提取密码
5. 根据方法和路径判断会话类型（DataStream/SourcePush/Sourcetable）

握手完成后，解析器自动切换模式：
- 响应侧：RTCM 二进制帧解析（委托给 `RTCMStreamParser`）
- 请求侧：NMEA 句子解析（`parseNMEA()` + `parseGGASentence()`）

#### 2.3 CLI 命令

**文件**: `cmd/ntrip.go`

```go
var ntripCmd = &cobra.Command{
    Use:   "ntrip [--mount MOUNTPOINTS] [--version v1|v2] [--user USERNAMES] [--gga] [--errors]",
    Short: "Watch NTRIP v1/v2 sessions and RTCM data streams",
    Run: func(cmd *cobra.Command, args []string) {
        mounts, _ := cmd.Flags().GetStringSlice("mount")
        users, _ := cmd.Flags().GetStringSlice("user")
        ggaOnly, _ := cmd.Flags().GetBool("gga")
        // ...

        options.MessageFilter = ntrip.NTRIPFilter{
            TargetMountPoints:  mounts,
            TargetUsernames:    users,
            GGAOnly:            ggaOnly,
            // ...
        }
        options.LatencyFilter = initLatencyFilter(cmd)
        options.SizeFilter = initSizeFilter(cmd)
        startAgent()
    },
}

func init() {
    ntripCmd.Flags().StringSlice("mount", []string{},
        "Filter by NTRIP mountpoint names")
    ntripCmd.Flags().StringSlice("user", []string{},
        "Filter by username in auth credentials (e.g. admin,operator)")
    ntripCmd.Flags().Bool("gga", false,
        "Only show client GGA position uploads (NMEA backchannel)")
    // ...
}
```

**CLI flag 完整列表**:

| Flag | 类型 | 说明 |
|------|------|------|
| `--mount` | string slice | 按挂载点名称过滤 |
| `--version` | string slice | 按 NTRIP 版本过滤 (v1, v2) |
| `--method` | string slice | 按 HTTP 方法过滤 (GET, POST, SOURCE) |
| `--session` | string slice | 按会话类型过滤 (data, source, sourcetable) |
| `--user` | string slice | 按用户名过滤认证凭据 |
| `--errors` | bool | 只显示错误响应 |
| `--crc-errors` | bool | 只显示 CRC 校验失败的 RTCM 帧 |
| `--gga` | bool | 只显示客户端上传的 GGA 位置句子 |

#### 2.4 Phase 2 交付物清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `agent/protocol/ntrip/ntrip.go` | 新建 | NTRIP 会话检测、请求解析、认证凭据提取、GGA 位置解析 |
| `agent/protocol/ntrip/types.go` | 新建 | NTRIP 类型定义（NTRIPVersion, NTRIPSessionType） |
| `agent/protocol/ntrip/filter.go` | 新建 | NTRIPFilter（含 TargetUsernames、GGAOnly 过滤） |
| `agent/protocol/ntrip/sourcetable.go` | 新建 | SOURCETABLE 格式解析 |
| `agent/protocol/ntrip/ntrip_test.go` | 新建 | 单元测试（含认证提取、GGA 解析、坐标转换测试） |
| `cmd/ntrip.go` | 新建 | CLI 子命令（含 --user、--gga flag） |
| `cmd/watch.go` | 修改 | supportedProtocols 添加 "ntrip" |

---

### Phase 3：GNSS 综合视图与统计增强

> **目标**: 提供 GNSS 场景专用的分析视图和统计能力
> **预计工作量**: 1-1.5 周
> **依赖**: Phase 1 + Phase 2
> **优先级**: P1

#### 3.1 RTCM 帧统计面板

在 `kyanos stat` 模式下，为 RTCM/GNSS 协议提供专用统计维度：

- **消息类型分布**: 各 RTCM 消息类型的帧数占比和字节数占比
- **数据流速率**: 每秒接收的 RTCM 帧数和字节数（反映数据链路质量）
- **CRC 错误率**: CRC-24Q 校验失败的帧占比（反映传输质量）
- **消息更新率**: 各消息类型的更新周期（如 MSM4 通常 1Hz，即每秒 1 帧）
- **NTRIP 会话状态**: mountpoint、连接时长、累计传输量

#### 3.2 TUI 渲染定制

在 `agent/render/watch/` 和 `agent/render/stat/` 中为 RTCM/NTRIP 定制展示列：

watch 模式下的 RTCM 帧展示：
```
┌────────┬──────────────┬──────────────┬────────┬───────┬───────────┐
│ Time   │ Src          │ Msg Type     │ Length │ CRC   │ Details   │
├────────┼──────────────┼──────────────┼────────┼───────┼───────────┤
│ 14:32  │ 10.0.1.5     │ 1074(GPS M4) │ 298    │ ✓     │ 12 sats   │
│ 14:32  │ 10.0.1.5     │ 1124(BDS M4) │ 312    │ ✓     │ 14 sats   │
│ 14:32  │ 10.0.1.5     │ 1005(Coord)  │ 36     │ ✓     │ E:116.39  │
│ 14:32  │ 10.0.1.5     │ 1077(GPS M7) │ 498    │ ✗     │ CRC error │
└────────┴──────────────┴──────────────┴────────┴───────┴───────────┘
```

watch 模式下的 NTRIP 会话展示：
```
┌────────┬──────────┬─────────┬──────────┬──────────┬──────────────┐
│ Time   │ Client   │ Mount   │ Version  │ Duration │ Data Rate    │
├────────┼──────────┼─────────┼──────────┼──────────┼──────────────┤
│ 14:30  │ 10.0.2.3 │ MOUNT01 │ NTRIPv2  │ 2m 15s   │ 1.2 KB/s     │
│ 14:31  │ 10.0.2.7 │ MOUNT02 │ NTRIPv1  │ 1m 05s   │ 856 B/s      │
└────────┴──────────┴─────────┴──────────┴──────────┴──────────────┘
```

#### 3.3 Phase 3 交付物清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `agent/protocol/rtcm/types.go` | 修改 | 补充 MSM 消息的卫星数提取逻辑 |
| `agent/render/watch/rtcm.go` | 新建 | RTCM 帧的 watch TUI 渲染 |
| `agent/render/watch/ntrip.go` | 新建 | NTRIP 会话的 watch TUI 渲染 |
| `agent/render/stat/rtcm.go` | 新建 | RTCM 统计面板 |
| `agent/analysis/rtcm.go` | 新建 | RTCM 专用统计聚合 |
| `cmd/stat.go` | 修改 | 添加 rtcm/ntrip 到 stat 支持的协议列表 |

---

### Phase 4：工程化与生产就绪

> **预计工作量**: 1 周
> **优先级**: P1

#### 4.1 构建与测试

- 补充完整的单元测试，特别是 RTCM CRC-24Q 校验、帧解析边界条件
- 准备 RTCM 测试数据集（录制的 TCP 流量 pcap 文件）
- 验证 NTRIP v1/v2 的 e2e 场景（连接→推流→断开）
- 确保 `make build-bpf && make` 构建链正常工作

#### 4.2 文档

- 更新 README_CN.md，新增 NTRIP/RTCM 使用说明和示例
- 编写 `docs/gnss-protocols.md`，记录协议分析过程和设计决策

#### 4.3 NTRIP 认证与位置提取（已完成）

> **优先级**: P0（高于其他可选增强）

- **用户名/密码提取**: 从 `Authorization: Basic` 头解码用户名和密码，从 SOURCE 方法的请求行提取密码。CLI 通过 `--user` flag 支持按用户名过滤。
- **客户端 GGA 位置上传提取**: 解析 NTRIP 客户端上传的 NMEA GGA 句子，提取经纬度（十进制度）、定位质量、卫星数、HDOP、海拔高度。CLI 通过 `--gga` flag 只显示 GGA 上传。

**实现要点**:

- `parseBasicAuth()`: base64 解码 `Basic` 认证头，按 `:` 分隔用户名和密码，支持特殊字符和 Unicode
- SOURCE 方法: `SOURCE <password> /mountpoint` 格式中密码在请求行第二位，Basic Auth 用户名优先
- `parseGGASentence()`: 解析 GGA 14 个逗号分隔字段，填充 `GGAParsed`/`UTCTime`/`Latitude`/`Longitude`/`FixQuality`/`NumSatellites`/`HDOP`/`Altitude`
- `parseNMEACoord()`: `ddmm.mmmm` → 十进制度转换，自动处理 N/S/E/W 半球符号
- `fixQualityName()`: 定位质量指标数字映射（0=Invalid, 1=GPS, 2=DGPS, 4=RTK-Fixed, 5=RTK-Float）
- NTRIPFilter 新增 `TargetUsernames []string` 和 `GGAOnly bool` 过滤条件

**测试覆盖**: parseBasicAuth（6 个边界场景）、auth 提取（4 个场景含中文用户名）、GGA 解析（3 个场景含南半球/无定位）、parseNMEACoord（7 个坐标转换）、fixQualityName、FormatToString/SummaryString（GGA/非GGA）、Filter Usernames、Filter GGAOnly

#### 4.4 RTCM 数据导出（已完成）

- **RTCM 数据导出**: 通过 `--export` flag 将所有 CRC 校验通过的 RTCM 帧写入 `.rtcm` 二进制文件。输出格式为标准 RTCM 3.x 帧流，可直接用 RTKLIB 的 rtkrcv、convbin 等工具回放分析。
- 同时支持 rtcm 和 ntrip 命令：`kyanos watch rtcm --export output.rtcm` 或 `kyanos watch ntrip --export output.rtcm`
- 实现要点：`RTCMExporter`（线程安全的文件写入器）、`RTCMFrame.RawBytes`（解析时保存原始帧字节）、`conn.RecordExportFunc`（包级 hook，在过滤前调用）
- 导出逻辑只写 CRC 校验通过的帧，NTRIP 流中的 RTCM 帧也会被导出（通过 `NTRIPRTCMFrame.Inner` 访问）

#### 4.5 可选增强（待实现）

- NTRIP Caster 健康监控：基于 RTCM 帧更新率和 CRC 错误率判断 caster 质量
- 告警集成：当 CRC 错误率超过阈值时触发告警
- RTCM 测试数据集：准备录制的 TCP 流量 pcap 文件作为集成测试数据
- NTRIP e2e 测试：完整的连接→推流→断开端到端测试（需 Linux 环境搭建 mock Caster）

---

### Phase 5：NTRIP 诊断引擎

> **目标**: 构建以"NTRIP Session"为核心的会话级诊断体系，覆盖登录分析、GGA 时序、RTCM 连续性、网络切换影响、TCP 重传拥塞、多 Pod 负载等六大排障场景
> **预计工作量**: 4 周
> **依赖**: Phase 1-4（协议解析基础）
> **优先级**: P0

#### 5.1 排障场景矩阵

| 编号 | 场景 | 核心问题 | 关键指标 |
|------|------|---------|---------|
| S1 | NTRIP 登录异常 | 客户端是否成功登录？认证是否被拒绝？ | 登录时间戳、HTTP 状态码、认证凭据 |
| S2 | GGA 上报异常 | 客户端是否按时上报位置？上报频率是否合理？ | GGA 间隔、坐标有效性、fix quality |
| S3 | RTCM 播发中断 | 服务端是否持续下发差分数据？是否有异常间隔？ | RTCM 帧间隔、帧率、中断时长 |
| S4 | 网络切换影响 | WiFi↔4G 切换是否导致业务中断？中断持续多久？ | TCP 重连时间、会话恢复延迟、IP 变化 |
| S5 | 网络拥塞/重传 | RTCM 数据是否因网络拥塞导致延迟或丢失？ | TCP 重传率、RTT 抖动、窗口大小变化 |
| S6 | 多 Pod 路由不均 | 负载均衡是否导致会话粘滞或 Pod 间负载不均？ | 每 Pod 连接数、每 Pod 帧率、Pod 切换 |

#### 5.2 NTRIP 会话追踪器（Session Tracker）

在现有 Kyanos `RecordFunc` 回调管道之上，新增会话级抽象层。一个 NTRIP Session 涵盖从客户端登录到断开连接的完整生命周期：

```
Client                              DS Server
  │                                     │
  │── GET /MOUNTPOINT ─────────────────>│  ← 登录事件
  │   Authorization: Basic xxx          │
  │<────── 200 OK (ICY-OK) ────────────│  ← 认证成功
  │                                     │
  │── $GPGGA,...*xx\r\n ───────────────>│  ← GGA 上报
  │<────── RTCM Frame #1 ──────────────│  ← RTCM 下发
  │<────── RTCM Frame #2 ──────────────│
  │── $GPGGA,...*xx\r\n ───────────────>│  ← GGA 上报
  │<────── RTCM Frame #3 ──────────────│
  │   ...                               │
  │── TCP RST / FIN ──────────────────>│  ← 断开事件
```

**核心数据结构**:

```go
type NTRIPSession struct {
    SessionID      string           // podName_srcIP_srcPort_mountpoint_startTime
    MountPoint     string
    Username       string
    ClientIP       string
    ClientPort     uint16
    ServerPod      string           // 处理该连接的 DS Pod 名称
    ServerNode     string           // DS Pod 所在节点
    ConnStartTime  time.Time
    ConnCloseTime  *time.Time

    // 登录分析
    AuthMethod     string           // "basic_auth" | "source_method" | "none"
    AuthSuccess    bool
    HTTPStatusCode int
    LoginLatency   time.Duration

    // GGA 上报分析
    GGAEvents      []GGAEvent
    GGAFrequency   float64          // 平均上报频率 (次/秒)
    GGALastFix     *GGAFix

    // RTCM 下发分析
    RTCMStats      RTCMDeliveryStats
    RTCMEvents     []RTCMEvent

    // 网络质量分析
    NetworkQuality NetworkQualityStats
}
```

**子结构定义**:

```go
type GGAEvent struct {
    Timestamp      time.Time
    Latitude       float64
    Longitude      float64
    FixQuality     int
    NumSatellites  int
    HDOP           float64
    Interval       time.Duration    // 距上一次 GGA 的时间间隔
}

type RTCMDeliveryStats struct {
    TotalFrames    int
    AvgInterval    time.Duration    // 平均帧间隔
    MaxInterval    time.Duration    // 最大帧间隔（可能是中断）
    P95Interval    time.Duration
    Interruptions  []RTCMInterruption
    TotalBytes     int64
    AvgThroughput  float64          // bytes/sec
    MessageTypes   map[int]int
}

type RTCMInterruption struct {
    StartTime      time.Time
    EndTime        time.Time
    Duration       time.Duration
}

type NetworkQualityStats struct {
    TotalRetransmissions  int
    RetransmissionRate    float64
    AvgRTT                time.Duration
    MaxRTT                time.Duration
    P95RTT                time.Duration
    RTTJitter             time.Duration
    WindowSizeMin         int
    TCPResetEvents        []TCPResetEvent
    ConnectionMigrations  int         // IP 变化次数
}
```

**实现架构**: Session Tracker 作为 `RecordFunc` 的中间层叠加：

```
现有管道: submitRecord() → RecordFunc(record, conn)
                                    │
新增中间层:               SessionTracker.OnRecord(record, conn)
                                    │
                          ┌─────────┴──────────┐
                          │ 按 mountpoint +     │
                          │ clientIP + pod 聚合  │
                          │ 为 Session          │
                          └─────────┬──────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
              GGA 事件提取    RTCM 帧统计     网络质量统计
```

#### 5.3 登录与认证分析（S1）

基于已实现的 NTRIP 认证提取功能（Phase 4 § 4.3），扩展为完整的登录分析：

| 能力 | 说明 | 实现方式 |
|------|------|---------|
| 登录事件检测 | 记录每次 NTRIP GET/SOURCE 请求 | 已有 NTRIPRequest 解析 |
| 认证失败告警 | HTTP 401/403 响应 | 需在 Match 阶段关联 req-resp |
| 重复登录检测 | 同一用户短时间内多次登录 | Session Tracker 按 username 索引 |
| 异常凭据告警 | 空密码、格式错误的 Auth Header | parseBasicAuth 已有容错 |
| 登录延迟监控 | 从 TCP 建连到认证成功的时间 | ConnStartTime 与 Auth 响应时间戳差 |

新增 CLI flags:

```
kyanos watch ntrip --auth-log            # 仅输出登录事件
kyanos watch ntrip --auth-fail-only      # 仅输出认证失败
kyanos stat ntrip --group-by ntrip-user   # 按用户统计登录次数和成功率
```

#### 5.4 GGA 上报时序分析（S2）

| 能力 | 说明 | 实现方式 |
|------|------|---------|
| GGA 间隔统计 | 相邻两次 GGA 的时间差 | GGAEvent.Interval |
| 频率异常检测 | 间隔超过阈值（默认 5s）| 可配置阈值 |
| 定位质量追踪 | FixQuality 和 NumSatellites 变化趋势 | GGA 解析字段 |
| 坐标漂移检测 | 相邻坐标 Haversine 距离超阈值 | 计算距离 |
| 停报检测 | 会话期间完全无 GGA 上报 | Session Tracker 记录首次 GGA 时间 |

新增 CLI flags:

```
kyanos watch ntrip --gga-interval-warn 5s
kyanos stat ntrip --group-by ntrip-user --metric gga-interval
```

#### 5.5 RTCM 播发连续性分析（S3）

| 能力 | 说明 | 实现方式 |
|------|------|---------|
| 帧间隔统计 | 相邻帧时间差分布 | RTCMDeliveryStats |
| 中断检测 | 帧间隔超过可配置阈值 | RTCMInterruption 事件 |
| 帧率监控 | 每秒帧数（FPS）滑动窗口 | 实时计算 |
| 消息类型分布 | 各 RTCM 消息类型计数和占比 | MessageType 聚合 |
| 吞吐量趋势 | 每秒字节数时间序列 | 滑动窗口 |
| CRC 错误率 | CRC 校验失败的帧占比 | CRCValid 字段 |

新增 CLI flags:

```
kyanos watch rtcm --interruption-warn 2s
kyanos watch rtcm --fps
kyanos stat rtcm --group-by rtcm-msg-type
kyanos stat rtcm --metric interval
```

#### 5.6 网络切换与业务影响检测（S4）

WiFi↔4G 切换在服务端的表现是 TCP 连接断开 + 新 IP 重连。通过跨 Session 关联检测业务影响：

| 能力 | 说明 | 实现方式 |
|------|------|---------|
| 连接断开检测 | TCP RST/FIN 事件 | 已有 ConnClose 事件 |
| 快速重连检测 | 同一用户短时间内断开+重连 | Session Tracker 按 username 关联 |
| 中断时长计算 | 旧连接关闭到新连接建立的时间差 | 跨 Session 关联 |
| IP 变化追踪 | 同一用户从不同 IP 连接 | Session Tracker 记录 ClientIP 变化 |
| 恢复时间分析 | 重连后到首次 RTCM 帧的时间 | 新 Session LoginLatency + 首帧延迟 |

**SessionCorrelator** 跨 Session 关联器:

```go
type SessionCorrelator struct {
    byUser   map[string][]*NTRIPSession  // 按 username 聚合
    config   CorrelatorConfig
}

type CorrelatorConfig struct {
    ReconnectWindow   time.Duration  // 判定为"重连"的时间窗口，默认 60s
    IPChangeThreshold time.Duration  // IP 变化关联窗口，默认 120s
}

func (sc *SessionCorrelator) OnNewSession(s *NTRIPSession) *ReconnectEvent {
    // 查找同一 username 最近关闭的 Session
    // 如果时间差 < ReconnectWindow → 判定为重连
    // 如果 ClientIP 变化 → 标记为疑似网络切换
}
```

新增 CLI flags:

```
kyanos watch ntrip --reconnect-detect
kyanos watch ntrip --reconnect-window 60s
```

#### 5.7 TCP 重传与拥塞分析（S5）

Kyanos BPF 层已捕获 TCP 内核事件（`KernEvent`），包含 16 步内核包处理流程。需要新增分析器从中提取 TCP 层指标：

| 能力 | 说明 | 实现方式 |
|------|------|---------|
| 重传计数 | 每连接 TCP 重传总数 | 从 BPF kern_events 提取 |
| 重传率 | 重传数 / 总包数 | 计算比率 |
| RTT 估算 | 基于内核时间戳的往返延迟 | NIC→ACK 时间差 |
| RTT 抖动 | RTT 标准差 / P95 | 滑动窗口 |
| 窗口收缩 | TCP 接收窗口缩小事件 | TCP header window size |
| 拥塞事件关联 | 重传突增是否与 RTCM 中断时间重合 | 时间线交叉分析 |

```go
type TCPHealthAnalyzer struct {
    // 从 KernEventStream 提取:
    // - 重传: 同一 seq 号出现多次 NIC-Out 事件
    // - RTT: NIC-Out 到对应 ACK (NIC-In) 的时间差
    // - 窗口: TCP header window size
}
```

#### 5.8 多 Pod 负载分析（S6）

| 能力 | 说明 | 实现方式 |
|------|------|---------|
| 每 Pod 连接数 | 各 DS Pod 当前活跃 NTRIP 会话数 | Session Tracker 按 Pod 聚合 |
| 每 Pod 帧率 | 各 Pod 的 RTCM 播发帧率 | RTCMDeliveryStats per Pod |
| 会话粘滞检测 | 同一客户端是否始终连到同一 Pod | Session Tracker 跨 Pod 查询 |
| Pod 切换事件 | 客户端从 Pod A 切换到 Pod B | SessionCorrelator 扩展 |
| 负载不均告警 | 连接数/帧率偏差超过阈值 | 变异系数 |

#### 5.9 诊断评分引擎

为每个 Session 生成 0-100 的健康评分，综合各维度：

| 维度 | 权重 | 扣分规则 |
|------|------|---------|
| 登录认证 | 15% | 认证失败 -15，登录延迟>5s -5 |
| GGA 上报 | 20% | 间隔异常每次 -3，停报>30s -10 |
| RTCM 播发 | 35% | 中断每次 -5，CRC 错误率>1% -10 |
| 网络质量 | 20% | 重传率>1% -5，RTT P95>50ms -5 |
| 连接稳定性 | 10% | 非预期断开 -10，重连失败 -10 |

#### 5.10 Phase 5 交付物清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `agent/session/tracker.go` | 新建 | SessionTracker 核心实现 |
| `agent/session/types.go` | 新建 | NTRIPSession, GGAEvent, RTCMDeliveryStats 等类型 |
| `agent/session/correlator.go` | 新建 | SessionCorrelator 跨 Session 关联 |
| `agent/session/tcp_health.go` | 新建 | TCPHealthAnalyzer |
| `agent/session/scoring.go` | 新建 | 诊断评分引擎 |
| `agent/session/tracker_test.go` | 新建 | 单元测试 |
| `cmd/watch.go` | 修改 | 新增 --auth-log, --gga-interval-warn, --reconnect-detect 等 flags |
| `cmd/stat.go` | 修改 | 新增 --metric gga-interval, --metric interval 等 |

---

### Phase 6：PCAP 导出与对象存储

> **目标**: 实现 Wireshark 兼容的 PCAP 导出、JSONL 结构化数据导出，以及腾讯云 COS 对象存储集成
> **预计工作量**: 2 周
> **依赖**: Phase 5
> **优先级**: P1

#### 6.1 PCAP 导出（Wireshark 兼容）

用户要求原始数据可以用 Wireshark 打开。需实现标准 PCAP/PCAP-NG 格式导出。

**方案**: 从 BPF 事件的 syscall payload 重建 PCAP，合成 TCP/IP/ETH 头部写入标准 PCAP 格式。

```go
type PcapWriter struct {
    file     *os.File
    mu       sync.Mutex
    linkType uint32  // LINKTYPE_RAW (101) 或 LINKTYPE_ETHERNET (1)
}

func NewPcapWriter(path string) (*PcapWriter, error)
func (w *PcapWriter) WritePacket(ts time.Time, srcIP, dstIP net.IP,
    srcPort, dstPort uint16, payload []byte) error
func (w *PcapWriter) Close() error
```

**注意**: 合成头部的 PCAP 在 Wireshark 中 TCP 序列号分析可能不完整。如需精确 PCAP，后续可切换为旁路 libpcap 方案。

#### 6.2 JSONL 结构化数据导出

每行一个事件的 JSON Lines 格式，用于后续分析和报告生成：

```jsonl
{"ts":"2026-06-03T14:22:01.000Z","type":"auth","event":"login","user":"user001","mount":"MOUNT-A","pod":"ds-pod-7","status":"success","latency_ms":23}
{"ts":"2026-06-03T14:22:01.500Z","type":"gga","lat":31.242797,"lon":121.481687,"fix":1,"sats":12,"interval_s":1.0}
{"ts":"2026-06-03T14:22:01.523Z","type":"rtcm","msg_type":1005,"size":156,"crc_valid":true,"interval_ms":0.8}
{"ts":"2026-06-03T14:55:12.300Z","type":"network","event":"retransmission","seq":12345,"retrans_count":1}
```

#### 6.3 腾讯云 COS 集成

```go
type COSUploader struct {
    client *cos.Client
    bucket string
    prefix string
}

func NewCOSUploader(secretID, secretKey, bucket, region, prefix string) *COSUploader
func (u *COSUploader) Upload(localPath string) (cosURL string, err error)
```

COS 目录结构:

```
captures/
├── 2026/06/03/
│   ├── task-20260603-142201-pod7.pcap          # 原始 PCAP
│   ├── task-20260603-142201-pod7.parsed.jsonl   # 解析数据
│   └── task-20260603-142201-pod7.report.html    # 诊断报告
```

#### 6.4 文件轮转与大小限制

抓包文件需要自动轮转：按文件大小（如 100MB）或时间（如 1 小时）切割，防止磁盘占满。

#### 6.5 Phase 6 交付物清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `agent/export/pcap.go` | 新建 | PcapWriter 实现 |
| `agent/export/jsonl.go` | 新建 | JSONL 结构化数据导出 |
| `agent/export/cos.go` | 新建 | 腾讯云 COS 上传 |
| `agent/export/rotate.go` | 新建 | 文件轮转 |
| `agent/export/export_test.go` | 新建 | 单元测试 |

---

### Phase 7：gRPC 通信层与 Agent 改造

> **目标**: 实现 Agent 与控制面之间的 gRPC 双向流通信，支持任务下发、事件上报、状态同步；改造 Agent 支持运行时动态修改过滤规则和 Pod 身份解析
> **预计工作量**: 3 周
> **依赖**: Phase 5, 6
> **优先级**: P1

#### 7.1 gRPC Protobuf 定义

```protobuf
syntax = "proto3";
package kyanos.agent.v1;

// Agent 与控制面的双向流服务
service AgentService {
    // Agent 注册并建立事件流
    rpc Connect(AgentInfo) returns (stream ControlCommand);
    // Agent 上报事件流
    rpc ReportEvents(stream SessionEvent) returns (EventAck);
    // Agent 上报状态
    rpc ReportStatus(AgentStatus) returns (StatusAck);
    // 控制面下发抓包任务
    rpc StartCapture(CaptureTask) returns (TaskResponse);
    rpc StopCapture(StopRequest) returns (TaskResponse);
}

message AgentInfo {
    string node_name = 1;
    string agent_version = 2;
    repeated PodInfo managed_pods = 3;  // 本节点管理的 DS Pod 列表
}

message ControlCommand {
    oneof command {
        CaptureTask start_capture = 1;
        StopRequest stop_capture = 2;
        FilterUpdate update_filter = 3;
    }
}

message CaptureTask {
    string task_id = 1;
    string target_pod = 2;
    string target_namespace = 3;
    map<string, string> pod_labels = 4;
    NTRIPFilterConfig ntrip_filter = 10;
    RTCMFilterConfig rtcm_filter = 11;
    int64 duration_seconds = 20;
    bool export_pcap = 21;
    bool export_parsed = 22;
    string cos_bucket = 23;
}

message SessionEvent {
    string task_id = 1;
    string session_id = 2;
    int64 timestamp_ns = 3;
    oneof event {
        AuthEvent auth = 10;
        GGAEvent gga = 11;
        RTCMEvent rtcm = 12;
        NetworkEvent network = 13;
        SessionCloseEvent close = 14;
    }
}
```

#### 7.2 Agent gRPC Server

Agent 新增 gRPC 模块，启动时：
1. 加载 eBPF 程序并附着探针
2. 发现本节点上所有目标 Pod（通过 K8s API + cgroup 解析）
3. 将 cgroup 白名单推送到 BPF map（内核侧过滤）
4. 通过 gRPC 向 Console 注册
5. 进入事件处理循环，将 Session 事件流式上报

#### 7.3 动态过滤规则

Agent 支持运行时修改过滤规则，无需重启：
- 修改 BPF map 中的 cgroup 白名单（增删目标 Pod）
- 修改用户态 MessageFilter（按 mountpoint、username 等过滤）
- 修改 CaptureTask 参数（持续时间、导出选项等）

#### 7.4 Pod 身份解析器（PodResolver）

eBPF 捕获的是内核级事件（PID, cgroup ID），需要解析为 K8s Pod 信息：

```go
type PodResolver struct {
    client    kubernetes.Interface  // K8s API client
    cache     map[uint64]*PodInfo   // cgroup ID → Pod 信息
    namespace string
    labels    map[string]string
}

type PodInfo struct {
    PodName      string
    PodIP        string
    Namespace    string
    NodeName     string
    ContainerIDs []string
    CgroupIDs    []uint64
}
```

解析流程:
1. K8s API 列出目标 namespace + labels 的所有 Pod
2. Container runtime API 获取 container ID
3. `/proc` 遍历 cgroup 建立 container ID → cgroup ID 映射
4. 推送 cgroup ID 列表到 BPF map（内核侧过滤）

#### 7.5 Phase 7 交付物清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `proto/agent.proto` | 新建 | gRPC 接口定义 |
| `agent/grpc/server.go` | 新建 | Agent gRPC Server |
| `agent/grpc/pod_resolver.go` | 新建 | Pod 身份解析器 |
| `agent/grpc/dynamic_filter.go` | 新建 | 运行时动态过滤 |
| `cmd/watch.go` | 修改 | 新增 --grpc-server flag |
| `deploy/daemonset.yaml` | 新建 | K8s DaemonSet 部署清单 |

---

### Phase 8：Web Console 后端

> **目标**: 实现 NTRIP 排障平台的控制面后端，包括任务管理、会话存储、诊断报告、WebSocket 实时推送
> **预计工作量**: 3 周
> **依赖**: Phase 7
> **优先级**: P1

#### 8.1 技术选型

| 组件 | 选型 | 理由 |
|------|------|------|
| 后端框架 | Go + Gin | 与 Kyanos 同语言，可复用协议解析代码 |
| gRPC | google.golang.org/grpc | Agent ↔ Console 双向流式通信 |
| 实时推送 | WebSocket (gorilla/websocket) | 实时会话数据推送到前端 |
| 指标存储 | ClickHouse 或 PostgreSQL+TimescaleDB | 会话指标时序存储 |
| 对象存储 | 腾讯云 COS SDK | 用户指定 |
| 容器编排 | K8s Deployment (1-2 replicas) | 控制面本身不需要太多实例 |

#### 8.2 系统架构

```
┌──────────────────────────────────────────────────┐
│              NTRIP Web Console                    │
│                                                   │
│  ┌────────────┐     ┌────────────────────────┐   │
│  │ REST API   │     │ gRPC Client             │   │
│  │ (Gin)      │     │ (下发指令/接收事件)       │   │
│  └─────┬──────┘     └───────────┬────────────┘   │
│        │                        │                 │
│  ┌─────┴────────────────────────┴────────────┐   │
│  │            Service Layer                   │   │
│  │  TaskManager / SessionStore / ReportEngine │   │
│  └─────┬───────────────────────┬─────────────┘   │
│        │                       │                  │
│  ┌─────┴──────┐     ┌─────────┴──────────┐      │
│  │ COS Client  │     │ WebSocket Server   │      │
│  └────────────┘     └────────────────────┘      │
└──────────────────────────────────────────────────┘
```

#### 8.3 核心 API

**任务管理**:

```
POST   /api/v1/tasks              创建抓包任务
GET    /api/v1/tasks              列表查询
GET    /api/v1/tasks/:id          任务详情
DELETE /api/v1/tasks/:id          停止任务
```

**会话查询**:

```
GET    /api/v1/sessions                    会话列表（支持分页、过滤）
GET    /api/v1/sessions/:id                会话详情
GET    /api/v1/sessions/:id/events         事件时间线（上行下行双列）
GET    /api/v1/sessions/:id/report         诊断报告（HTML/PDF）
```

**集群状态**:

```
GET    /api/v1/agents                Agent 列表（节点、管理的 Pod）
GET    /api/v1/agents/:node/status   Agent 状态
GET    /api/v1/topology              集群拓扑（节点-Pod 映射）
```

**WebSocket**:

```
WS     /api/v1/ws/sessions/:id      实时订阅会话事件
WS     /api/v1/ws/tasks/:id         实时订阅任务状态
```

#### 8.4 诊断报告生成器

生成包含以下内容的 HTML/PDF 报告：

- 会话概要（用户、接入点、持续时间、DS Pod、健康评分）
- 登录分析（认证方式、延迟、重连次数）
- GGA 上报分析（总数、平均间隔、最大间隔、定位质量、异常事件）
- RTCM 播发分析（总帧数、帧率、中断事件、消息类型分布、CRC 错误率）
- 网络质量分析（重传、RTT、抖动、连接重置）
- 诊断结论（各维度是否达标的判定结果）

#### 8.5 Phase 8 交付物清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `console/` | 新建目录 | Web Console 项目 |
| `console/main.go` | 新建 | 入口 |
| `console/api/` | 新建 | REST API handlers |
| `console/grpc/` | 新建 | gRPC Client |
| `console/store/` | 新建 | SessionStore 实现 |
| `console/report/` | 新建 | 诊断报告生成器 |
| `console/ws/` | 新建 | WebSocket handler |
| `console/cos/` | 新建 | COS 管理 |

---

### Phase 9：Web Console 前端

> **目标**: 实现面向运维人员的前端界面，核心功能为集群拓扑视图、任务管理、NTRIP 会话浏览器（上行与下行按时间戳双列排序展示）
> **预计工作量**: 4 周
> **依赖**: Phase 8
> **优先级**: P1

#### 9.1 技术选型

Vue 3 + Vite + 组件库（如 Element Plus 或 Ant Design Vue），轻量适合运维工具。

#### 9.2 核心页面

**集群拓扑视图**: 可视化展示节点/Pod 分布，各 Agent 状态，当前活跃抓包任务。

**任务管理页面**: 创建/停止/查询抓包任务，选择目标 Pod/Node/Label，配置过滤规则，设置持续时间。

**NTRIP 会话浏览器（核心视图）**: 以 NTRIP 会话为单位，上行与下行按时间戳双列排序展示：

```
┌────────────────────────────────────────────────────────────────────┐
│  Session: user001@MOUNT-A → ds-pod-7 (Node-3)                     │
│  Started: 2026-06-03 14:22:01 | Duration: 02:35:12 | ● Active     │
├────────────────────────────────────────────────────────────────────┤
│  Timeline (UTC)          ▲ Uplink (Client→Server)    ▼ Downlink   │
│  ────────────────────────────────────────────────────────────────── │
│  14:22:01.000  ▲ GET /MOUNT-A (Basic Auth: user001:****)          │
│  14:22:01.023                                           ▼ 200 OK   │
│  14:22:01.500  ▲ $GPGGA,... (fix=1, sats=12)                     │
│  14:22:01.523                                           ▼ RTCM 1005│
│  14:22:01.623                                           ▼ RTCM 1074│
│  14:22:02.500  ▲ $GPGGA,... (fix=1, sats=12)                     │
│  ...                                                               │
│  14:55:12.300  ▲ TCP FIN                               ▼ TCP FIN  │
│                                                                    │
│  ─── Statistics ────────────────────────────────────────────────── │
│  GGA: 2012 events, avg 1.00s interval, 0 anomalies               │
│  RTCM: 180,720 frames, avg 1200 fps, 0 interruptions              │
│  Network: 3 retransmissions, avg RTT 2.1ms, 0 resets             │
└────────────────────────────────────────────────────────────────────┘
```

前端要点：虚拟滚动列表（大量事件场景）、上行/下行双色区分、异常事件高亮（红色）、时间范围缩放平移、点击展开完整报文。

**诊断报告查看页**: 展示生成的诊断报告，支持下载 HTML/PDF。

**告警与异常事件面板**: 汇总所有抓包任务中检测到的异常事件。

#### 9.3 Phase 9 交付物清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `console/frontend/` | 新建目录 | Vue 3 前端项目 |
| `src/views/Topology.vue` | 新建 | 集群拓扑视图 |
| `src/views/Tasks.vue` | 新建 | 任务管理 |
| `src/views/SessionExplorer.vue` | 新建 | 会话浏览器（核心） |
| `src/views/Report.vue` | 新建 | 诊断报告 |
| `src/views/Alerts.vue` | 新建 | 告警面板 |
| `src/components/Timeline.vue` | 新建 | 双列时间线组件 |

---

### Phase 10：K8s 部署与集成测试

> **目标**: 完成 K8s DaemonSet 部署方案、Helm Chart、RBAC 配置，适配腾讯云 TKE 环境，端到端集成测试
> **预计工作量**: 2 周
> **依赖**: Phase 7, 8, 9
> **优先级**: P1

#### 10.1 部署拓扑

```
腾讯云 K8s 集群 (TKE)
│
├── namespace: gnss-monitoring
│   ├── DaemonSet: kyanos-agent              # 每节点一个 eBPF 采集器
│   ├── Deployment: ntrip-console             # 控制面 (1-2 replicas)
│   ├── StatefulSet: clickhouse               # 指标存储 (可选)
│   └── ConfigMap: kyanos-config              # 全局配置
│
├── namespace: gnss-production                 # DS 微服务所在命名空间
│   ├── Deployment: ds-access                  # DS 数据播发服务 (20+ Pods)
│   └── Service: ds-access-svc (LoadBalancer)  # 对接腾讯云 LB
│
└── RBAC:
    ├── ServiceAccount: kyanos-agent-sa
    ├── ClusterRole: kyanos-agent-role         # 读 Pod/Node 元数据
    └── ClusterRoleBinding
```

#### 10.2 DaemonSet 部署要点

eBPF Agent 需要以下特权配置：

```yaml
spec:
  template:
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: kyanos-agent
        securityContext:
          privileged: true    # 生产环境可收窄为最小 capabilities
        volumeMounts:
        - name: sys-kernel-debug
          mountPath: /sys/kernel/debug
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: sys
          mountPath: /sys
          readOnly: true
        - name: modules
          mountPath: /lib/modules
          readOnly: true
        - name: cgroup
          mountPath: /sys/fs/cgroup
          readOnly: true
        resources:
          requests:
            cpu: 200m
            memory: 256Mi
          limits:
            cpu: "1"
            memory: 512Mi
```

使用 `nodeAffinity` 将 Agent 只调度到运行 DS Pod 的节点：

```yaml
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: node-role
                operator: In
                values: ["ds-pool"]
```

#### 10.3 腾讯云 LB 环境特殊处理

1. **客户端真实 IP**: 腾讯云 LB 通过 Proxy Protocol 或 X-Forwarded-For 传递客户端 IP，eBPF 抓到的是 LB 内部 IP，需从 HTTP 头提取真实客户端 IP
2. **NTRIP 会话关联**: LB 轮询分发可能导致同一客户端重连落到不同 Pod，Session Tracker 通过 mountpoint + username 跨 Pod 关联
3. **LB 健康检查过滤**: 排除 LB 健康检查流量（按源 IP 或路径过滤）

#### 10.4 Helm Chart

提供完整的 Helm Chart 用于一键部署：

```
chart/
├── Chart.yaml
├── values.yaml
├── templates/
│   ├── daemonset.yaml
│   ├── console-deployment.yaml
│   ├── console-service.yaml
│   ├── console-ingress.yaml
│   ├── configmap.yaml
│   ├── serviceaccount.yaml
│   ├── clusterrole.yaml
│   ├── clusterrolebinding.yaml
│   └── _helpers.tpl
```

#### 10.5 Phase 10 交付物清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `deploy/daemonset.yaml` | 新建 | Agent DaemonSet |
| `deploy/console-deployment.yaml` | 新建 | Console Deployment |
| `deploy/console-service.yaml` | 新建 | Console Service |
| `deploy/console-ingress.yaml` | 新建 | Console Ingress |
| `deploy/rbac.yaml` | 新建 | RBAC 配置 |
| `deploy/configmap.yaml` | 新建 | 全局配置 |
| `chart/` | 新建目录 | Helm Chart |

---

## 五、系统架构设计

### 5.1 整体架构

```
                        ┌──────────────────────────────────────┐
                        │           NTRIP Web Console           │
                        │   (统一控制面 · 独立微服务部署)          │
                        │                                      │
                        │  ┌──────────┐  ┌───────────────────┐ │
                        │  │ 任务调度  │  │ 会话浏览器         │ │
                        │  │ Capture   │  │ Session Explorer  │ │
                        │  │ Task Mgr  │  │ (时间线双列视图)    │ │
                        │  └──────────┘  └───────────────────┘ │
                        │  ┌──────────┐  ┌───────────────────┐ │
                        │  │ 诊断报告  │  │ COS 对象存储管理    │ │
                        │  │ Report    │  │ (PCAP + 解析数据)   │ │
                        │  └──────────┘  └───────────────────┘ │
                        └────────────┬─────────────────────────┘
                                     │ gRPC (控制指令下发 / 事件上报)
                    ┌────────────────┼────────────────┐
                    │                │                │
              ┌─────┴─────┐   ┌─────┴─────┐   ┌─────┴─────┐
              │  Node 1    │   │  Node 2    │   │  Node M    │
              │ ┌────────┐ │   │ ┌────────┐ │   │ ┌────────┐ │
              │ │ Kyanos  │ │   │ │ Kyanos  │ │   │ │ Kyanos  │ │
              │ │ Agent   │ │   │ │ Agent   │ │   │ │ Agent   │ │
              │ │(DaemonSet│ │   │ │(DaemonSet│ │   │ │(DaemonSet│ │
              │ │  Pod)    │ │   │ │  Pod)    │ │   │ │  Pod)    │ │
              │ └────────┘ │   │ └────────┘ │   │ └────────┘ │
              │  Pod1 Pod2  │   │  Pod3 Pod4  │   │  PodN ...   │
              │  (DS) (DS)  │   │  (DS) (DS)  │   │  (DS)       │
              └────────────┘   └────────────┘   └────────────┘
                    │
          ┌─────────┴──────────┐
          │  Tencent Cloud LB   │
          │  (外部流量入口)       │
          └─────────┬──────────┘
                    │
          NTRIP Clients (测量设备 / 物联网终端)
```

三层架构：

1. **Kyanos Agent（DaemonSet）**: 每节点一个特权 Pod，负责 eBPF 挂载、流量捕获、协议解析、初步聚合
2. **NTRIP Web Console（控制面）**: 独立微服务，负责任务调度、会话浏览、诊断报告、COS 存储管理
3. **存储层**: 腾讯云 COS 存放原始 PCAP + 解析后结构化数据，可选 ClickHouse/PostgreSQL 存放指标时序数据

### 5.2 Agent 与控制面通信流程

```
Agent 启动:
  1. 加载 eBPF 程序并附着探针
  2. 通过 K8s API 发现本节点 DS Pod，解析 cgroup ID
  3. 推送 cgroup 白名单到 BPF map (内核侧过滤)
  4. gRPC 向 Console 注册: "Node-3, 管理 Pod7/Pod8/Pod12"
  5. 进入事件处理循环

控制面下发任务:
  Console → Agent (gRPC Stream):
    CaptureTask { target_pod: "ds-pod-7", filter: {...}, duration: 300s }

Agent 执行:
  → 动态调整过滤规则 → 开始采集
  Agent → Console (gRPC Stream):
    SessionEvent { session_id, timestamp, events... }  // 实时流式上报
  任务结束 → 生成 PCAP → 上传 COS → 上报完成
```

### 5.3 与现有 Kyanos 的兼容性

所有改动遵循"叠加不替换"原则：

| 模块 | 改动方式 | 对原有功能的影响 |
|------|---------|----------------|
| NTRIP/RTCM 解析器 | 新增 | 无 |
| Session Tracker | 新增中间层，可选启用 | 不启用时行为不变 |
| CLI flags | 新增 flag | 原有 flag 不变 |
| gRPC Server | 新增模块，通过 `--grpc-server` 启用 | 不启用时纯 CLI 模式 |
| PCAP 导出 | 新增 `--pcap-export` flag | 不启用时无影响 |
| BPF map 动态更新 | 新增运行时接口 | 不影响现有 BPF 程序加载 |
| Pod 身份解析 | 新增模块，通过 `--k8s-mode` 启用 | 不启用时使用原有 container-id 过滤 |
| Web Console | 完全独立的微服务 | 不影响 Kyanos 主程序 |

---

## 六、实施注意事项

### 6.1 eBPF 指令数限制

eBPF 程序有严格的指令数限制（内核验证器限制，较新内核约 100 万条指令，旧内核 4096 条）。`protocol_inference.h` 中的 `is_rtcm_protocol()` 应尽量轻量，只做 preamble + reserved bits + length 的基本检查，将复杂的 CRC 校验留给用户态。

### 6.2 NTRIP 与 HTTP 的协议冲突

NTRIP v2 是合法的 HTTP/1.1 流量。在 `infer_protocol()` 链中，HTTP 检测会先于 RTCM 命中。这是预期行为——用户态解析器应在 HTTP 解析器检测到 NTRIP 特征后，切换为 NTRIP 模式，并将后续的 binary stream 交给 RTCM 解析器。

### 6.3 RTCM 帧边界问题

TCP 是字节流协议，RTCM 帧可能跨越多次 read syscall。Kyanos 的 `StreamBuffer` 机制天然处理了这个问题——`ParseStream` 返回 `NeedsMoreData` 时，框架会等待更多数据后再调用解析器。`FindBoundary` 中的 `0xD3` 扫描确保在乱序数据中也能重新同步到帧边界。

### 6.4 重新生成 BPF 代码

修改 `bpf/pktlatency.h` 后，必须重新生成 Go 绑定代码：

```bash
make build-bpf    # 内部调用 clang + bpf2go
```

这会重新生成 `bpf/agent_x86_bpfel.go` 和 `bpf/agent_arm64_bpfel.go` 中的枚举常量。新增的 `kProtocolNTRIP` 和 `kProtocolRTCM` 会自动映射为 Go 的 `AgentTrafficProtocolTKProtocolNTRIP` 和 `AgentTrafficProtocolTKProtocolRTCM`。

### 6.5 构建环境要求

- Go 1.23+
- Clang 10.0+ / LLVM 10.0+
- Linux headers
- 构建必须在 Linux 环境下执行（eBPF 编译依赖 Linux 内核头文件）
- 如果在 Windows 上开发，建议使用 WSL2 或 Docker 容器进行构建

### 6.6 eBPF 特权容器安全

DaemonSet 需要 privileged 权限，需与集群安全策略协调。建议使用专用 namespace + RBAC 隔离。生产环境可将 `privileged: true` 收窄为最小 capability 集合：`SYS_ADMIN`, `SYS_PTRACE`, `NET_ADMIN`, `NET_RAW`, `BPF`, `PERFMON`（Linux 5.8+）。

### 6.7 腾讯云 TKE 环境适配

1. **内核版本**: 需确认 TKE 节点内核版本是否支持 Kyanos 的 BPF 程序（最低 3.10，推荐 5.x）
2. **BTF 文件**: TKE 自定义镜像可能不带 BTF，需要准备对应的 BTF 文件或使用 Kyanos 的 legacy kernel 模式
3. **节点标签**: 使用 nodeAffinity 将 Agent 只调度到 DS Pod 运行的节点，避免资源浪费

### 6.8 数据量与性能评估

20+ Pod × 1200 RTCM fps × 200 bytes ≈ 4.8 MB/s 原始数据。长时间抓包需要考虑：
- Agent 侧内存缓冲大小（建议不超过 512MB）
- gRPC 传输带宽（压缩后约 1-2 MB/s）
- COS 存储空间（按天估算约 400GB）
- 建议按需抓包（指定 Pod、指定时间段），避免全量持续抓取

### 6.9 PCAP 精度

从 BPF 事件重建的 PCAP 头部是合成的，Wireshark 的 TCP 序列号分析功能可能不完整。如需精确 PCAP，考虑旁路 libpcap 方案（在 Agent 中嵌入 libpcap 捕获线程）。

### 6.10 gRPC 连接稳定性

节点 Agent 与控制面之间的网络可能因节点调度而中断，需要实现：
- 断线自动重连（指数退避）
- 事件本地缓冲（断连期间暂存到本地文件，恢复后补发）
- 心跳检测（30s 间隔）

---

## 七、里程碑时间线

```
Week 1-2:   Phase 1 - RTCM 3.2 协议支持 ✅ 已完成
            ├── eBPF 协议识别 (2d)
            ├── RTCM 解析器 + CRC-24Q (3d)
            ├── CLI 命令 + 注册 (1d)
            └── 测试验证 (2d)

Week 3-4:   Phase 2 - NTRIP v1/v2 支持 ✅ 已完成
            ├── NTRIP 会话检测逻辑 (2d)
            ├── NTRIP 解析器 + SOURCETABLE (3d)
            ├── CLI 命令 + 与 HTTP 解析器集成 (2d)
            └── 测试验证 (1d)

Week 5:     Phase 3 - GNSS 综合视图 ✅ 已完成
            ├── TUI 渲染定制 (2d)
            ├── 统计聚合 (2d)
            └── 集成测试 (1d)

Week 6:     Phase 4 - 工程化 ✅ 已完成
            ├── 补充测试 + 文档 (2d)
            ├── NTRIP 认证提取 + GGA 解析 (P0)
            ├── RTCM 数据导出 (--export)
            └── Classifier 单元测试

Week 7-10:  Phase 5 - NTRIP 诊断引擎 (4 周)
            ├── Session Tracker 核心 (3d)
            ├── GGA 间隔分析 (2d)
            ├── RTCM 帧间隔/中断检测 (2d)
            ├── 登录事件完整追踪 (2d)
            ├── TCP 重传/RTT 分析器 (3d)
            ├── SessionCorrelator 重连检测 (2d)
            ├── 多 Pod 负载分析 (2d)
            ├── 诊断评分引擎 (2d)
            └── CLI 新 flags + 测试 (6d)

Week 11-12: Phase 6 - PCAP 导出与对象存储 (2 周)
            ├── PcapWriter (3d)
            ├── 腾讯云 COS SDK 集成 (2d)
            ├── JSONL 导出器 (1d)
            ├── 文件轮转 (1d)
            └── 测试 (3d)

Week 13-15: Phase 7 - gRPC 通信层与 Agent 改造 (3 周)
            ├── Protobuf 定义 (2d)
            ├── Agent gRPC Server (3d)
            ├── 动态过滤规则 (3d)
            ├── Pod 身份解析器 (3d)
            ├── Agent 注册/心跳/状态上报 (2d)
            └── 测试 (2d)

Week 16-18: Phase 8 - Web Console 后端 (3 周)
            ├── 项目脚手架 + REST API (4d)
            ├── SessionStore 实现 (3d)
            ├── 会话查询 API (2d)
            ├── 诊断报告生成器 (3d)
            ├── WebSocket 实时推送 (2d)
            └── COS 管理 API (1d)

Week 19-22: Phase 9 - Web Console 前端 (4 周)
            ├── 项目脚手架 (1d)
            ├── 集群拓扑视图 (3d)
            ├── 任务管理页面 (3d)
            ├── Session Explorer 双列时间线 (5d)
            ├── RTCM/GGA 图表 (4d)
            ├── 诊断报告 + 告警面板 (4d)

Week 23-24: Phase 10 - K8s 部署与集成测试 (2 周)
            ├── DaemonSet YAML + Helm Chart (2d)
            ├── Console Deployment + Ingress (1d)
            ├── RBAC 配置 (1d)
            ├── 腾讯云 TKE 环境适配 (2d)
            ├── 端到端集成测试 (3d)
            └── 性能测试 (1d)

Total: ~24 周 (Phase 1-4 已完成 6 周，Phase 5-10 预计 18 周)
```
