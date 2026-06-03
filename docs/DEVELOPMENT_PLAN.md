# Kyanos 二次开发规划：NTRIP & GNSS (RTCM 3.2) 协议支持

## 一、项目背景与目标

基于 Kyanos (eBPF 网络分析工具) 进行二次开发，新增对以下协议的原生支持：

- **NTRIP v1/v2**：GNSS 差分改正数据传输协议，基于 HTTP 长连接推流
- **RTCM 3.2**：GNSS 改正数二进制帧格式，通过 TCP 直连或 NTRIP 隧道传输

最终交付物：可独立运行的 kyanos 二进制，通过 `kyanos watch ntrip` / `kyanos watch gnss` 等命令实现对上述协议的精准捕获、协议级解析和可视化展示。

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

## 五、实施注意事项

### 5.1 eBPF 指令数限制

eBPF 程序有严格的指令数限制（内核验证器限制，较新内核约 100 万条指令，旧内核 4096 条）。`protocol_inference.h` 中的 `is_rtcm_protocol()` 应尽量轻量，只做 preamble + reserved bits + length 的基本检查，将复杂的 CRC 校验留给用户态。

### 5.2 NTRIP 与 HTTP 的协议冲突

NTRIP v2 是合法的 HTTP/1.1 流量。在 `infer_protocol()` 链中，HTTP 检测会先于 RTCM 命中。这是预期行为——用户态解析器应在 HTTP 解析器检测到 NTRIP 特征后，切换为 NTRIP 模式，并将后续的 binary stream 交给 RTCM 解析器。

### 5.3 RTCM 帧边界问题

TCP 是字节流协议，RTCM 帧可能跨越多次 read syscall。Kyanos 的 `StreamBuffer` 机制天然处理了这个问题——`ParseStream` 返回 `NeedsMoreData` 时，框架会等待更多数据后再调用解析器。`FindBoundary` 中的 `0xD3` 扫描确保在乱序数据中也能重新同步到帧边界。

### 5.4 重新生成 BPF 代码

修改 `bpf/pktlatency.h` 后，必须重新生成 Go 绑定代码：

```bash
make build-bpf    # 内部调用 clang + bpf2go
```

这会重新生成 `bpf/agent_x86_bpfel.go` 和 `bpf/agent_arm64_bpfel.go` 中的枚举常量。新增的 `kProtocolNTRIP` 和 `kProtocolRTCM` 会自动映射为 Go 的 `AgentTrafficProtocolTKProtocolNTRIP` 和 `AgentTrafficProtocolTKProtocolRTCM`。

### 5.5 构建环境要求

- Go 1.23+
- Clang 10.0+ / LLVM 10.0+
- Linux headers
- 构建必须在 Linux 环境下执行（eBPF 编译依赖 Linux 内核头文件）
- 如果在 Windows 上开发，建议使用 WSL2 或 Docker 容器进行构建

---

## 六、里程碑时间线

```
Week 1-2:   Phase 1 - RTCM 3.2 协议支持
            ├── eBPF 协议识别 (2d)
            ├── RTCM 解析器 + CRC-24Q (3d)
            ├── CLI 命令 + 注册 (1d)
            └── 测试验证 (2d)

Week 3-4:   Phase 2 - NTRIP v1/v2 支持
            ├── NTRIP 会话检测逻辑 (2d)
            ├── NTRIP 解析器 + SOURCETABLE (3d)
            ├── CLI 命令 + 与 HTTP 解析器集成 (2d)
            └── 测试验证 (1d)

Week 5:     Phase 3 - GNSS 综合视图
            ├── TUI 渲染定制 (2d)
            ├── 统计聚合 (2d)
            └── 集成测试 (1d)

Week 6:     Phase 4 - 工程化
            ├── 补充测试 + 文档 (2d)
            └── 性能验证 + 发布准备 (3d)
```
