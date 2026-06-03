# GNSS 协议分析：NTRIP v1/v2 与 RTCM 3.2

本文档记录了在 Kyanos (eBPF 网络分析工具) 中新增 NTRIP 和 RTCM 协议支持的协议分析过程、设计决策和实现细节。

## 1. 协议概述

### 1.1 RTCM 3.2 (Radio Technical Commission for Maritime Services)

RTCM 3.2 是 GNSS（全球导航卫星系统）领域最常用的差分改正数据帧格式，由国际海事无线电技术委员会制定。它定义了参考站向流动站发送的改正数二进制编码规范。

帧结构如下：

```
┌──────────┬──────────────────┬───────────────────────────┬──────────┐
│ Preamble │ Reserved + Length│ Payload (0-1023 bytes)    │ CRC-24Q  │
│ 1 byte   │ 2 bytes          │                           │ 3 bytes  │
│ 0xD3     │ 6-bit + 10-bit   │ 首12-bit 为 Message Type  │ Qualcomm │
└──────────┴──────────────────┴───────────────────────────┴──────────┘
```

关键特征：

- **Preamble**: 固定 `0xD3`，用于帧同步。
- **Reserved bits**: 6 bits，必须为 `000000`。这是一个重要的合法性检查点。
- **Length**: 10 bits，表示 payload 长度（0-1023 bytes）。
- **Message Type**: payload 前 12 bits，标识消息类型（如 1077 = GPS MSM7）。
- **CRC-24Q**: 使用 Qualcomm 多项式 `0x1864CFB` 的 24-bit CRC 校验，覆盖 preamble + header + payload。

RTCM 消息类型按 GNSS 星座分组：GPS 使用 1001-1004（legacy）、1019（ephemeris）、1071-1077（MSM）；GLONASS 使用 1009-1012、1020、1081-1087、1230；Galileo 使用 1045/1046、1091-1097；BeiDou 使用 1042、1121-1127。

MSM（Multiple Signal Messages）是新一代观测数据消息，分为 MSM1（粗伪距）到 MSM7（全分辨率 + CNR + 多普勒）七个等级。

### 1.2 NTRIP v1/v2 (Networked Transport of RTCM via Internet Protocol)

NTRIP 是在互联网上传输 RTCM 改正数据的应用层协议。它本质上是一个特殊的 HTTP 长连接推流协议，分为两个版本：

**NTRIP v1** 使用非标准 HTTP 变体：

- 客户端请求使用标准 HTTP GET 或自定义 SOURCE 方法
- 服务端响应使用 `ICY 200 OK`（而非 `HTTP/1.0 200 OK`）表示数据流开始
- Sourcetable 响应使用 `SOURCETABLE 200 OK` 状态行
- 无 `Content-Length` 或 `Transfer-Encoding`，数据流持续到连接关闭

**NTRIP v2** 是标准 HTTP/1.1 的扩展：

- 通过 `Ntrip-Version: Ntrip/2.0` 头进行版本协商
- 响应使用标准 HTTP/1.1 状态行
- Content-Type 为 `gnss/data`
- 支持 chunked transfer encoding

典型的 NTRIP 会话流程：

```
Client                              Caster
  │                                    │
  │ GET /RTK_DATA HTTP/1.1             │
  │ Ntrip-Version: Ntrip/2.0           │
  │ Authorization: Basic xxx           │
  ├───────────────────────────────────>│
  │                                    │
  │ HTTP/1.1 200 OK                    │
  │ Content-Type: gnss/data            │
  │<───────────────────────────────────┤
  │                                    │
  │    ◄─── RTCM binary stream ───►    │
  │    (continuous push, long-lived)   │
  │                                    │
```

NTRIP 还定义了三种会话类型：DataStream（客户端拉取改正数据）、SourcePush（参考站推送数据到 Caster，使用 SOURCE 方法）、Sourcetable（客户端请求 Caster 的可用挂载点列表）。

## 2. 设计决策

### 2.1 NTRIP 协议识别策略：用户态扩展（Strategy A）

在 eBPF 内核态的 `protocol_inference.h` 中，我们没有将 NTRIP 作为独立协议进行识别，而是采用了"HTTP 扩展"策略：

1. eBPF 层的 HTTP 检测逻辑会命中 NTRIP v1/v2 的初始 HTTP 握手
2. 用户态的 NTRIP 解析器接收 HTTP 握手数据，通过检测 `Ntrip-Version` 头、`ICY`/`SOURCETABLE` 响应、`gnss/data` Content-Type 等特征判断是否为 NTRIP 会话
3. 一旦确认为 NTRIP，后续的 RTCM 二进制流由 NTRIP 解析器委托给 RTCM 解析器处理

选择此策略的原因：

- NTRIP v2 是合法的 HTTP/1.1，在内核态无法仅通过几个字节区分
- NTRIP v1 的 `ICY` 响应虽然是独特的，但只在响应侧可见，请求侧看起来就像标准 HTTP
- 在内核态增加更多检测逻辑会增加 eBPF 程序复杂度，触及指令数限制
- 用户态解析器有完整的上下文（请求 + 响应），可以更准确地判断

### 2.2 RTCM eBPF 识别：轻量级三点检查

对于直连 TCP 的 RTCM 流（不经过 NTRIP），在内核态使用三点轻量检查：

1. 首字节是否为 preamble `0xD3`
2. 接下来 2 字节中的 reserved bits（高 6 bits）是否全零
3. Length 字段是否在合理范围内（≤ 1023）

CRC-24Q 校验留给用户态处理，避免在内核态执行复杂的位运算。

### 2.3 RTCM 单向流处理

RTCM 是单向推送协议（参考站 → 流动站），没有请求/响应的概念。在 Kyanos 框架中，所有 RTCM 帧都被标记为"请求"（`IsReq() = true`），`Match()` 方法将同一连接上的帧按顺序配对。这种设计复用了框架的 Record 机制，同时保持了语义的正确性。

### 2.4 NTRIP-RTCM 组合：委托模式

NTRIP 解析器在检测到 HTTP 握手完成后的 RTCM 数据流时，不自行解析 RTCM 帧，而是委托给 `RTCMStreamParser`。解析结果被包装为 `NTRIPRTCMFrame`，保留 NTRIP 会话上下文的同时复用 RTCM 解析能力。

### 2.5 NTRIP 认证凭据提取

NTRIP 客户端的认证信息是排查接入问题的关键线索，解析器从两个来源自动提取用户名和密码：

**Basic Auth 头**：NTRIP v1/v2 通用的标准 HTTP 认证方式。`Authorization: Basic base64(user:pass)` 头部被解码后按 `:` 分隔为用户名和密码。实现中的 `parseBasicAuth()` 函数处理了各种边界情况：无效 base64 编码、缺失冒号分隔符、非 Basic scheme、以及包含特殊字符或 Unicode 的凭据。

**SOURCE 方法**：NTRIP v1 特有的 `SOURCE <password> /mountpoint` 格式中，密码直接出现在请求行的第二个字段。这种方式没有用户名（只有密码），常见于参考站向 Caster 推送数据的场景。

当两者同时存在时（SOURCE 方法 + Authorization 头），Basic Auth 解析的用户名优先保留。

### 2.6 客户端 GGA 位置上传解析

在使用 VRS（虚拟参考站）服务时，NTRIP 客户端（流动站）会周期性地向 Caster 上传 NMEA GGA 句子，告知自身近似位置。Caster 根据此位置生成虚拟参考站的改正数据。

解析器在请求侧（client→server）检测到 `$` 前缀的 NMEA 句子时，对 GGA 类型进行完整字段解析：

- 经纬度：从 NMEA 的 `ddmm.mmmm` 格式转换为十进制度，`parseNMEACoord()` 自动处理 N/S/E/W 半球符号（南纬和西经取负值）
- 定位质量：0（无效）到 8（仿真），其中 4（RTK-Fixed）和 5（RTK-Float）是 GNSS RTK 场景中最常见的值
- 使用卫星数、HDOP（水平精度因子）、天线海拔高度

这些信息在 watch 详情界面中以结构化方式展示，在 `--gga` 模式下只过滤显示 GGA 上传，便于监控流动站的位置上报状态。

### 2.7 渲染与统计：复用通用框架

Kyanos 的 TUI 渲染使用通用表格组件，通过 `FormatToString()` 方法提供协议自定义的详情展示。统计模式通过 `ClassfierType` 分类器系统实现协议特定的分组维度：

- `RTCMMessageType`: 按 RTCM 消息类型分组（如 1074、1077、1005）
- `RTCMConstellation`: 按 GNSS 星座分组（GPS、GLONASS、Galileo 等）
- `NTRIPMountPoint`: 按 NTRIP 挂载点分组
- `NTRIPSessionType`: 按 NTRIP 会话类型分组（DataStream、SourcePush、Sourcetable）

在 `stat` 模式下，`ProtocolAdaptive` 分类器会根据协议类型自动选择对应的分组维度。

### 2.8 RTCM 数据导出

通过 `--export` flag 可将捕获的 RTCM 帧实时写入 `.rtcm` 二进制文件，便于用 RTKLIB 等工具进行离线分析或回放。

实现架构：

1. `RTCMFrame` 在解析时保存 `RawBytes`（原始帧字节的副本），这是导出的数据来源
2. `RTCMExporter` 是线程安全的文件写入器（`sync.Mutex` 保护），接受来自多个连接的并发写入
3. `conn.RecordExportFunc` 是包级 hook 变量，在 `submitRecord()` 中的过滤逻辑之前被调用，确保导出所有帧而非仅通过过滤的帧
4. 只导出 CRC 校验通过的帧（`frame.CRCValid == true`），NTRIP 流中的 RTCM 帧通过 `NTRIPRTCMFrame.Inner` 间接访问

当 `RecordExportFunc` 不为 nil 时，`submitRecord()` 会强制解析消息（即使过滤条件不需要解析），确保每条记录都能被导出。

## 3. 实现架构

### 3.1 文件组织

```
agent/protocol/rtcm/
├── types.go          # 常量、枚举（Constellation, MSMClass, MessageTypeNames）
├── crc24q.go         # CRC-24Q 校验算法实现
├── rtcm.go           # RTCMStreamParser, RTCMFrame（含 RawBytes）, 解析逻辑
├── filter.go         # RTCMFilter (按消息类型/星座/CRC状态过滤)
├── export.go         # RTCMExporter (线程安全的 .rtcm 文件写入器)
└── rtcm_test.go      # 单元测试（含导出测试）

agent/protocol/ntrip/
├── types.go          # 常量、枚举（NTRIPVersion, NTRIPSessionType）
├── sourcetable.go    # SOURCETABLE 解析器
├── ntrip.go          # NTRIPStreamParser, 消息类型, 解析逻辑
├── filter.go         # NTRIPFilter (按版本/会话/挂载点/状态码过滤)
└── ntrip_test.go     # 单元测试

agent/analysis/
├── classfier.go      # 分类器注册（含 RTCM/NTRIP 分类器）
└── classfier_test.go # 分类器单元测试

cmd/
├── rtcm.go           # kyanos watch rtcm / kyanos stat rtcm 子命令
├── ntrip.go          # kyanos watch ntrip / kyanos stat ntrip 子命令
├── watch.go          # 注册 RTCM/NTRIP 到支持的协议列表
└── stat.go           # 注册协议特定分类器到 ProtocolSpecificClassfiers
```

### 3.2 协议扩展五触点

在 Kyanos 中新增一个协议需要修改五个位置：

1. **BPF 枚举** (`bpf/pktlatency.h`): 在 `kProtocol` 枚举中添加新协议标识
2. **BPF 推断** (`bpf/protocol_inference.h`): 在内核态的 `infer_protocol()` 中添加协议检测函数
3. **Go 解析器** (`agent/protocol/<proto>/`): 实现 `ProtocolStreamParser` 接口并在 `ParsersMap` 中注册
4. **CLI 命令** (`cmd/<proto>.go`): 注册子命令到 watch/stat
5. **注册** (`cmd/watch.go`, `cmd/stat.go`): 将协议添加到支持列表，配置分类器

### 3.3 StreamBuffer 与字节流重组

TCP 是字节流协议，RTCM 帧可能跨越多次 `read` 系统调用。Kyanos 的 `StreamBuffer` 机制通过 `Add(seq, data, timestamp)` 方法按序重组数据。解析器返回 `NeedsMoreData` 时，框架会等待更多数据到达后再次调用解析器，天然处理了分帧问题。

`FindBoundary` 方法扫描 `0xD3` preamble 实现帧同步，即使在数据乱序或中间丢失的情况下也能重新对齐到下一个有效帧边界。reserved bits 检查进一步防止了 `0xD3` 在 payload 中的误匹配。

## 4. 使用示例

### 4.1 监听 RTCM 直连流量

```bash
# 监听所有 RTCM 帧
sudo kyanos watch rtcm

# 只看 GPS MSM7 消息
sudo kyanos watch rtcm --msg-type 1077

# 只看 Galileo 星座
sudo kyanos watch rtcm --constellation galileo

# 只看 CRC 校验失败的帧
sudo kyanos watch rtcm --crc-errors

# 导出所有有效 RTCM 帧到 .rtcm 文件（可用 RTKLIB 回放分析）
sudo kyanos watch rtcm --export output.rtcm
```

### 4.2 监听 NTRIP 会话

```bash
# 监听所有 NTRIP 会话
sudo kyanos watch ntrip

# 只看特定挂载点
sudo kyanos watch ntrip --mount RTK_DATA

# 只看 NTRIP v2
sudo kyanos watch ntrip --version v2

# 只看 Source Push 会话
sudo kyanos watch ntrip --session source-push

# 按用户名过滤认证凭据
sudo kyanos watch ntrip --user admin,operator

# 只看客户端上传的 GGA 位置（VRS 场景）
sudo kyanos watch ntrip --gga

# 只看有错误的会话
sudo kyanos watch ntrip --errors

# 从 NTRIP 流中导出 RTCM 数据到文件
sudo kyanos watch ntrip --export output.rtcm
```

### 4.3 统计分析

```bash
# 按 RTCM 消息类型统计
sudo kyanos stat rtcm --group-by rtcm-msg-type

# 按星座统计
sudo kyanos stat rtcm --group-by rtcm-constellation

# 按挂载点统计 NTRIP
sudo kyanos stat ntrip --group-by ntrip-mount

# 按会话类型统计
sudo kyanos stat ntrip --group-by ntrip-session
```

## 5. 测试覆盖

### 5.1 RTCM 测试

- CRC-24Q 算法正确性（标准向量、空输入、单字节）
- ParseStream: 有效帧、CRC 失败、数据不足、不完整帧、无效 preamble、无效 reserved bits、空缓冲区、多帧缓冲区
- FindBoundary: preamble 在起始位置、偏移位置、跳过无效 reserved bits、无 preamble、空缓冲区
- Match: 单向流匹配、空流
- RTCMFilter: 消息类型过滤、星座过滤、CRC 错误过滤、非 RTCM 输入、FilterByProtocol/Request/Response
- MSMDescription 和 FormatToSummaryString
- RTCMExporter: 帧写入、nil/空帧处理、路径返回、无效路径错误
- RTCMFrame.RawBytes: 解析后原始字节正确存储
- ParsersMap 注册验证

### 5.2 NTRIP 测试

- 请求解析: GET、SOURCE、sourcetable 请求、数据不足场景
- ICY 响应解析: 标准 ICY、无空行的 ICY
- SOURCETABLE 响应解析: 完整/不完整
- HTTP 响应解析: NTRIP v2 标准响应、401 认证响应
- NMEA 句子解析: 有效/无效
- RTCM 帧委托解析
- Match: HTTP 握手配对、ICY 状态码配对、未配对的 RTCM 帧、空队列
- NTRIPFilter: 版本、会话类型、方法、挂载点、状态码、CRC 错误、NMEA、用户名、GGAOnly 过滤
- 认证凭据提取: parseBasicAuth（有效/空密码/特殊字符/非Basic/无效base64/无冒号）、Basic Auth 提取（含中文用户名）、SOURCE 方法密码提取、无认证场景
- GGA 解析: 北半球标准坐标、南半球/西半球坐标、无定位/零卫星、非GGA句子不触发解析、parseNMEACoord 坐标转换（7 个测试向量）、fixQualityName 映射
- FormatToString/FormatToSummaryString: GGA 结构化输出、非GGA 输出、GGA 摘要字符串

### 5.3 分类器测试

- RTCMMessageType: 直接 RTCM 帧、NTRIP 包装帧、非 RTCM 消息
- RTCMConstellation: 直接帧、包装帧、非 RTCM 消息、所有星座类型
- NTRIPMountPoint: 正常请求、非 NTRIP 消息
- NTRIPSessionType: DataStream、SourcePush、Sourcetable、非 NTRIP 消息
- 人类可读输出: 所有分类器的 HumanReadable 版本
- GetClassfierType: ProtocolAdaptive 模式的 RTCM/NTRIP/回退场景
- getClassfier: ProtocolAdaptive 模式的端到端分类
- getClassIdHumanReadableFunc: ProtocolAdaptive 模式的可读输出
- ClassfierTypeNames 注册验证

## 6. 已知限制与后续工作

- **e2e 测试**: 目前缺少完整的端到端测试（连接→推流→断开），需要用录制的 pcap 数据补充
- **NTRIP Caster 健康监控**: 基于 RTCM 帧更新率和 CRC 错误率判断 caster 质量
- **告警集成**: CRC 错误率超阈值时触发告警
- **BPF 代码重新生成**: 修改 `pktlatency.h` 后需在 Linux 环境执行 `make build-bpf` 重新生成 Go 绑定
