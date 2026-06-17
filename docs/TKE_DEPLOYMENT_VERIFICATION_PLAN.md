# Kyanos GNSS 诊断 Agent — TKE 部署验证规划

> **文档状态**: DRAFT — 待审批后方可执行
> **创建日期**: 2026-06-17
> **风险等级**: 🔴 高危 — 涉及生产 TKE 集群（76 节点，103+ Pod）

---

## 1. 当前状态快照

### 1.1 项目开发状态

| Phase | 名称 | 代码状态 |
|-------|------|---------|
| 1-9 | RTCM/NTRIP/诊断引擎/gRPC/Console/TUI | ✅ 全部完成，已推送 |
| 10 | K8s 部署（Helm + Dockerfile） | 🔧 配置就绪，未实际部署验证 |

**跳板机编译验证结果**（43.157.72.201 / TencentOS 4.4 / Kernel 6.6.110）:
- `make build-bpf && make kyanos` ✅ 成功
- 冒烟测试 `kyanos watch --pids 1` ✅ eBPF 程序加载成功（417ms）
- 二进制: 66MB 静态链接 ELF

### 1.2 TKE 集群现状（只读收集）

| 指标 | 值 |
|------|-----|
| 集群版本 | v1.34.1-tke.4/5 |
| 节点总数 | **76** |
| 节点 OS | TencentOS Server 3.1 |
| 节点内核 | **5.4.241**（多种子版本） |
| 容器运行时 | containerd://1.6.9-tke.8 |
| 节点 Taints | `<none>`（所有节点无污点） |
| 节点 Labels | 含 `team=positioning`(18节点), `node-type=high-performance`(32), `node-type=standard`(10) |
| 典型节点规格 | SA5.2XLARGE16(8C16G), SA5.4XLARGE32(16C32G) |
| 集群地域 | eu-frankfurt-1 (de) / zone 170001 |
| 资源配额 | pods: 103/14053, services: 102/19849, configmaps: 2/3985 |

**关键 namespace**:
- `position-precision` — GNSS 高精度定位业务（103+ Pod，含多个 CrashLoopBackOff）
- `ssr2osr-position-precision` — SSR2OSR 定位业务
- `apps`, `middleware`, `monitoring` — 基础设施

**已有 DaemonSet**:
- kube-system: csi-cbs-node, csi-cni, ip-masq-agent, kube-proxy, tke-cni-agent, tke-eni-agent, tke-monitor-agent, tke-node-exporter（各 76 实例）
- tcss: yunjing-agent（安全 Agent，76 实例）

**⚠️ 关键发现**:
1. 节点内核 **5.4.241** — 跳板机测试用的是 6.6.110，两者差距较大
2. 集群已有 **9 个 DaemonSet** 在所有 76 节点上运行，再加 kyanos-agent 是第 10 个
3. position-precision namespace 有多个 Pod 处于 CrashLoopBackOff 状态
4. 当前 root 用户拥有 cluster-admin 权限（`*.* [*]`）— 安全风险

---

## 2. 风险评估

### 2.1 高危风险 (P0)

| # | 风险 | 影响 | 缓解策略 |
|---|------|------|---------|
| R1 | **内核 5.4.241 eBPF 兼容性** — 代码已有 v5d4 profile（kprobe fallback、perf_buffer 替代 ringbuf、ip_rcv_core.isra backup），理论兼容。但 6.6→5.4 跨度大，perf_buffer 在高频场景可能有性能差异 | Agent 启动失败或功能受限 | **必须在隔离 5.4 内核 CVM 上验证**（A2 步骤），不接受跳板机 6.6 结果作为替代 |
| R1b | **btfgen BTF archive 不含 TencentOS** — 当前 btf archive 仅覆盖 CentOS 7/8、Ubuntu 18/20。TKE 节点内置 BTF (`CONFIG_DEBUG_INFO_BTF=y`)，但如果某节点 BTF 文件损坏/缺失，Agent 无法回退到 btfgen 数据 | 特定节点 Agent 启动失败 | A7 步骤全量检查 76 节点 BTF 完整性；备选：从 TKE 节点提取 BTF 补充 archive |
| R2 | **privileged + hostNetwork + hostPID** — kyanos-agent 以特权模式运行，能访问所有节点网络和进程 | 对 76 个生产节点的安全威胁极大 | 评估是否可降级为具体 capabilities；先在独立测试 namespace 验证 |
| R3 | **76 节点同时部署 DaemonSet** — maxUnavailable=1 滚动更新仍需较长时间，且每个节点额外消耗资源 | 可能影响生产 Pod 调度 | 建议先用 nodeSelector 限制到少量测试节点 |

### 2.2 中危风险 (P1)

| # | 集群 | 影响 | 缓解策略 |
|---|------|------|---------|
| R4 | **gRPC stream 网络稳定性** — Agent → Console 的长连接在 TKE VPC-CNI 网络下可能受 NAT/超时影响 | Agent 断连，丢失诊断数据 | 需测试长连接稳定性 |
| R5 | **containerd 运行时** — Pod 身份解析依赖 containerd API，需验证 containerd://1.6.9-tke.8 兼容性 | Pod 解析失败 | 测试 `--grpc-pod-resolve` 在 containerd 环境 |
| R6 | **镜像仓库命名空间** — values-tke.yaml 中 `<YOUR_CCR_NAMESPACE>` 未填写 | 部署失败 | 需确认 CCR 命名空间路径 |

### 2.3 低危风险 (P2)

| # | 集群 | 影响 | 缓解策略 |
|---|------|------|---------|
| R7 | **BTF 文件回退** — 内核 5.4.241 应自带 BTF，但部分子版本可能缺失 | Agent 使用内置 BTFgen 数据，可能有微小兼容差异 | 检查每个子版本 BTF 可用性 |
| R8 | **Console PVC 持久化** — ReadWriteOnce + 2 副本 = 第二副本无法挂载 | Console 数据丢失 | 设 replicaCount=1 或使用 ReadWriteMany (CFS) |

---

## 3. 验证策略：分阶段、可回滚

> **核心原则**: 永远不在全量生产节点上直接部署。先单节点 → 小范围 → 全量。

### Phase A — 离线预检（零生产影响）

> **核心原则**: 全程不接触生产节点。所有验证在隔离环境中完成，验证失败只影响测试资源，零生产风险。

#### A0. 前置知识确认（已完成 ✅）

通过 `kubectl debug node` 对生产节点执行的**只读查询**已确认：

| 检查项 | 结果 | 影响 |
|--------|------|------|
| TKE 节点内核 | 5.4.241-19-0023.2_plus | 与跳板机 6.6.110 差距大 |
| CONFIG_DEBUG_INFO_BTF | =y ✅ | BTF 内置，不需要 btfgen 回退 |
| CONFIG_BPF_SYSCALL | =y ✅ | eBPF 可用 |
| CONFIG_BPF_JIT_ALWAYS_ON | =y ✅ | JIT 编译 |
| CONFIG_BPF_LSM | =y ✅ | LSM BPF 可用 |
| CONFIG_HAVE_FENTRY | =y | 编译器支持 fentry，但无 BPF trampoline |
| CONFIG_BPF_TRAMP | 未启用 | **fentry/fexit 不可用**，必须走 kprobe fallback |
| /sys/kernel/btf/vmlinux | 存在 ✅ | CO-RE BTF 数据可用 |

**代码兼容性分析**（`agent/compatible/type.go` v5d4 profile）:
- `SupportFentry: false` → 走 kprobe fallback ✅
- `SupportRingBuffer: false` → 走 perf_buffer fallback ✅
- `SupportBTF: true` → CO-RE 可用 ✅
- 有 `ip_rcv_core.isra.0` / `.isra.20` backup kprobe ✅

**⚠️ 已识别风险**: btfgen BTF archive 仅含 CentOS/Ubuntu，**不含 TencentOS**。但因 TKE 节点内置 BTF，影响为：如果某节点 BTF 文件损坏或缺失，Agent 无法回退到 btfgen 数据。

---

#### A1. 创建隔离测试 CVM（核心改进 🔑）

**为什么这是最安全的做法？**
- 在真实 5.4 内核上验证，但**完全隔离于生产集群**
- 如果 eBPF 加载导致内核问题（极低概率），只影响一次性测试 CVM
- 可重复、可销毁、可快照

**操作步骤**:
1. 在腾讯云控制台创建 CVM：
   - 镜像：**TencentOS Server 3.1**（与 TKE 节点相同 OS）
   - 规格：2C4G 即可（SA5.MEDIUM4）
   - 地域：与 TKE 集群相同（eu-frankfurt）
   - 网络：**不要加入 TKE 集群 VPC**，使用独立子网
   - 安全组：仅开放 SSH 入站
2. 从跳板机 scp 编译好的二进制到测试 CVM
3. 运行验证（详见 A2）
4. 验证完毕后销毁 CVM

**成本**: 约 ¥0.2/小时，验证完毕即销毁

---

#### A2. 5.4 内核冒烟测试（在隔离 CVM 上）

**验证项**（按风险从高到低排列）:

| # | 测试 | 命令 | 预期 | 风险 |
|---|------|------|------|------|
| A2.1 | eBPF 加载 | `./kyanos watch --pids 1 --no-tui 2>&1 \| head -20` | 含 "Loaded eBPF maps & programs" | 🔴 最高 |
| A2.2 | kprobe attach 验证 | `./kyanos watch --pids 1 --no-tui --debug 2>&1 \| grep -i kprobe` | 看到 kprobe attach 成功（不是 fentry） | 🔴 高 |
| A2.3 | perf_buffer fallback | `./kyanos watch --pids 1 --no-tui --debug 2>&1 \| grep -iE 'perf|ringbuf'` | 确认走 perf_buffer 而非 ringbuf | 🟡 中 |
| A2.4 | ip_rcv_core symbol 解析 | `cat /proc/kallsyms \| grep ip_rcv_core` | 能找到 ip_rcv_core 或 .isra 变体 | 🟡 中 |
| A2.5 | BTF CO-RE 重定位 | `./kyanos watch --pids 1 --no-tui --debug 2>&1 \| grep -iE 'reloc\|CO-RE\|core'` | CO-RE 重定位成功 | 🟡 中 |
| A2.6 | 生成 HTTP 流量验证 | `curl -s http://example.com & ./kyanos watch --pids $(pgrep curl) --no-tui` | 捕获到 HTTP 请求 | 🟢 低 |
| A2.7 | 资源占用基线 | `top -b -n1 \| grep kyanos` | CPU < 5%, MEM < 200MB | 🟢 低 |
| A2.8 | 优雅退出 | `./kyanos watch --pids 1 & sleep 3 && kill $!` | eBPF 程序正确卸载，无残留 | 🟢 低 |

**A2.1 失败时的降级路径**:
```
A2.1 失败 → 检查 dmesg | grep -i bpf
  → "Operation not permitted" → 检查 capabilities
  → "Invalid argument" → BTF 版本不兼容，需要 btfgen 补丁
  → "Kernel panic" → 记录问题，放弃 5.4 原生支持，考虑升级节点内核
```

---

#### A3. 内核符号兼容性预检（只读，可在跳板机执行）

**目的**: 在不部署 Agent 的情况下，提前确认 5.4 内核符号可用性。

**操作**: 通过 `kubectl debug node` 对 2-3 个不同子版本的节点执行只读命令：

```bash
# 选择不同子版本节点
for node in 10.152.0.102 10.152.0.11 10.152.0.12; do
  echo "=== Node $node ==="
  kubectl debug node/$node -it --image=ubuntu:22.04 -- \
    bash -c 'cat /proc/kallsyms | grep -E "ip_rcv_core|__ip_queue_xmit|dev_queue_xmit|dev_hard_start_xmit|tcp_v4_do_rcv|tcp_v6_do_rcv" | head -20'
  echo ""
done
```

**验证点**:
- 所有 kprobe 目标函数符号存在
- `ip_rcv_core` 的 `.isra.*` 变体名称（5.4 可能是 `.isra.0` 或 `.isra.20`）
- 无 `T` (text) 段缺失

**注意**: `kubectl debug` 创建的调试 Pod 在退出后需手动清理：
```bash
kubectl delete pod node-debugger-10.152.0.102-xxxxx
```

---

#### A4. Docker 镜像构建与扫描

**分步操作**:

| 步骤 | 操作 | 验证点 |
|------|------|--------|
| A4.1 | Docker build Agent 镜像 | 多阶段构建成功，镜像 < 200MB |
| A4.2 | Docker build Console 镜像 | 构建成功 |
| A4.3 | **漏洞扫描** `docker scout` 或 `trivy` | 无 Critical/High CVE |
| A4.4 | 本地运行 Agent 容器 | `docker run --rm --privileged kyanos-agent:local version` 正常 |
| A4.5 | 确认 CCR 命名空间 | 镜像仓库路径正确（替换 `<YOUR_CCR_NAMESPACE>`） |
| A4.6 | Docker push 到 CCR | 镜像可拉取 |

**A4.3 漏洞扫描命令**（在跳板机上）:
```bash
# 安装 trivy（如未装）
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# 扫描 Agent 镜像
trivy image --severity HIGH,CRITICAL image-apps.tencentcloudcr.com/kyanos/kyanos-agent:v0.1.0
```

**关键风险**: Dockerfile 中 `make btfgen` 的 BTF archive 不含 TencentOS。如果 TKE 某节点 BTF 损坏，Agent 无法回退。
- **缓解**: 验证所有 76 节点的 BTF 文件完整性（A3 步骤中一并检查）
- **备选方案**: 从 TKE 节点提取 BTF 文件，添加到 btfgen archive

---

#### A5. Helm 渲染与服务端验证

**分步操作**:

| 步骤 | 操作 | 验证点 |
|------|------|--------|
| A5.1 | `helm lint` | 无 Error/Warning |
| A5.2 | `helm template` 本地渲染 | YAML 语法正确 |
| A5.3 | **`helm install --dry-run=server`** | 服务端验证：API 兼容性、资源配额、admission webhook 均通过 |
| A5.4 | 单节点 values 文件验证 | `values-single-node.yaml` 渲染后 nodeSelector 生效 |
| A5.5 | RBAC 最小权限审查 | ClusterRole 仅含必需权限 |

**A5.3 是关键改进** 🔑: `--dry-run=server` 会将请求发送到 K8s API Server 进行真实验证（但不实际创建资源），能提前发现：
- Admission webhook 拒绝（如 TKE 的安全策略）
- 资源配额不足
- API 版本不兼容
- PodSecurityPolicy / PodSecurityStandard 违规

```bash
# 服务端干跑验证（零影响，不创建任何资源）
helm install kyanos-agent deploy/helm/kyanos-agent \
  --namespace kyanos-system \
  --create-namespace \
  -f deploy/values-tke.yaml \
  --dry-run=server
```

---

#### A6. 安全权限审计

**目的**: 确认 `privileged: true` 是否真的必要，尝试最小权限集。

**分步操作**:

| 步骤 | 操作 | 验证点 |
|------|------|--------|
| A6.1 | 列出所有声明的 capabilities | SYS_ADMIN, BPF, NET_ADMIN, SYS_PTRACE, NET_RAW, PERFMON |
| A6.2 | 在隔离 CVM 上逐一测试 | 删除每个 capability 后 Agent 是否仍能加载 eBPF |
| A6.3 | 测试 `privileged: false` + capabilities | 确认最小权限集 |
| A6.4 | 记录每个 capability 的实际用途 | 形成文档 |

**A6.2 测试矩阵**（在隔离 CVM 上用 Docker 模拟）:
```bash
# Full privileged（基线）
docker run --rm --privileged kyanos-agent:local watch --pids 1 --no-tui

# 逐个移除 capability
docker run --rm --cap-add SYS_ADMIN --cap-add BPF --cap-add NET_ADMIN \
  --cap-add SYS_PTRACE --cap-add NET_RAW --cap-add PERFMON \
  --pid=host --network=host kyanos-agent:local watch --pids 1 --no-tui

# 测试去掉 SYS_ADMIN（仅用 BPF + PERFMON）
docker run --rm --cap-add BPF --cap-add PERFMON --cap-add NET_ADMIN \
  --cap-add SYS_PTRACE --cap-add NET_RAW \
  --pid=host --network=host kyanos-agent:local watch --pids 1 --no-tui
```

---

#### A7. BTF 覆盖性全量检查

**目的**: 确认所有 76 个节点的 BTF 文件完整可用，避免 btfgen 回退问题。

**操作**（只读，通过 kubectl debug）:
```bash
# 在跳板机上批量检查所有节点 BTF
for node in $(kubectl get nodes -o name); do
  name=${node#node/}
  result=$(kubectl debug node/$name -it --image=ubuntu:22.04 -- \
    bash -c 'ls -la /sys/kernel/btf/vmlinux && md5sum /sys/kernel/btf/vmlinux' 2>/dev/null)
  echo "$name: $result"
  # 清理调试 Pod
  kubectl delete pod -l app=debug 2>/dev/null
done
```

**验证点**:
- 所有 76 节点 `/sys/kernel/btf/vmlinux` 存在
- 相同内核子版本的 BTF md5 一致
- 如果发现 BTF 缺失的节点，需标记为不可调度或补充 btfgen 数据

---

#### Phase A 执行顺序与决策门

```
A0 (已确认) ──→ A1 (创建隔离 CVM) ──→ A2 (5.4 冒烟测试)
                                         │
                                    A2 全部通过？
                                    ├── YES → A3 + A4 + A5 + A6 + A7 (可并行)
                                    └── NO  → 停止，修复 eBPF 兼容性问题
                                              │
                                         修复后重新 A2
                                              │
                                         仍失败？→ 评估节点内核升级方案
```

**Phase A 完成标准**:
- [x] A0: TKE 节点内核配置已确认
- [ ] A1: 隔离 CVM 已创建
- [ ] A2: 所有 8 项 5.4 冒烟测试通过
- [ ] A3: 内核符号兼容性确认
- [ ] A4: 镜像构建 + 扫描通过，已推送到 CCR
- [ ] A5: Helm 服务端 dry-run 通过
- [ ] A6: 最小权限集已确定
- [ ] A7: 76 节点 BTF 完整性确认

**只有全部 ✅ 后，才进入 Phase B。**

---

### Phase B — 单节点验证（最小影响）

**目标**: 在 1 个生产节点上验证 Agent 运行，不影响其他节点。

| 步骤 | 操作 | 验证点 | 回滚 |
|------|------|--------|------|
| B1 | 创建 `kyanos-system` namespace | namespace 创建成功 | `kubectl delete ns kyanos-system` |
| B2 | 部署 Console（Deployment, replicaCount=1） | Pod Running, /healthz 返回 ok | `helm uninstall kyanos-console -n kyanos-system` |
| B3 | 用 nodeSelector 部署 Agent 到 **1 个指定节点** | 仅 1 个 Pod Running | `helm uninstall kyanos-agent -n kyanos-system` |
| B4 | 检查 Agent eBPF 加载 | 日志中看到 `Loaded eBPF maps & programs` | 查看 `kubectl logs` |
| B5 | 检查 Agent → Console gRPC 连接 | Console 日志收到 Agent 注册事件 | 检查网络连通性 |
| B6 | 部署 fake-ntrip-caster 测试 Pod | Pod Running, 产生 RTCM 流量 | `kubectl delete -f deploy/test-ntrip-pod.yaml` |
| B7 | 检查 Agent 捕获 NTRIP/RTCM 流量 | Agent 日志有 NTRIP 协议识别 | 查看 Agent 日志 |
| B8 | 检查 Pod 身份解析 | Agent 能将 containerd Pod IP 解析为 Pod 名称 | 查看 Agent 日志 |
| B9 | 检查对生产负载的影响 | 目标节点上原有 Pod 无异常 | `kubectl get pods -n position-precision -o wide` |

**B3 的关键配置**:
```yaml
# values-single-node.yaml — 单节点测试专用
nodeSelector:
  kubernetes.io/hostname: "10.152.0.102"  # 选择 1 个测试节点

tolerations: []  # 不容忍所有污点，仅调度到无污点的指定节点

resources:
  requests:
    cpu: 200m
    memory: 256Mi
  limits:
    cpu: "1"
    memory: 1Gi
```

### Phase C — 小范围验证（positioning 节点）

**目标**: 在 `team=positioning` 标签的 18 个节点上验证。

| 步骤 | 操作 | 验证点 | 回滚 |
|------|------|--------|------|
| C1 | 升级 nodeSelector 到 `team=positioning` | 18 个 Agent Pod Running | `helm uninstall` |
| C2 | 检查所有 18 节点的 Agent 健康 | 0 CrashLoopBackOff | 逐节点排查 |
| C3 | 验证真实 NTRIP 流量捕获 | Agent 捕获 position-precision namespace 的 NTRIP 流量 | 检查日志 |
| C4 | 验证诊断引擎输出 | 诊断会话数据到达 Console | 查看 Console 面板 |
| C5 | 监控 24h 稳定性 | 无重启、无 OOM、无断连 | 检查 metrics |
| C6 | 资源影响评估 | Agent CPU < 500m, 内存 < 512Mi | 调整 resources |

**C1 的关键配置**:
```yaml
# values-positioning.yaml — positioning 节点测试
nodeSelector:
  team: positioning

tolerations: []  # positioning 节点无污点

updateStrategy:
  type: RollingUpdate
  rollingUpdate:
    maxUnavailable: 2  # 每次最多更新 2 个节点
```

### Phase D — 全量部署（76 节点）

**前提**: Phase C 验证全部通过，24h 稳定运行无异常。

| 步骤 | 操作 | 验证点 | 回滚 |
|------|------|--------|------|
| D1 | 移除 nodeSelector, tolerations 改为 Exists | 76 个 Agent Pod 全部 Running | `helm uninstall` |
| D2 | Console replicaCount 升至 2 | 2 个 Console Pod Running | `helm upgrade --set replicaCount=1` |
| D3 | 启用 TLS（生产建议） | gRPC mTLS 连接成功 | 回退 `grpc.tls.enabled=false` |
| D4 | 启用 Ingress（可选） | Web 面板可访问 | `helm upgrade --set ingress.enabled=false` |
| D5 | 启用 PVC 持久化 | Console 数据持久化 | `helm upgrade --set persistence.enabled=false` |

---

## 4. 回滚策略

### 4.1 快速回滚（< 2 分钟）

```bash
# 完全移除 kyanos 部署
helm uninstall kyanos-agent --namespace kyanos-system
helm uninstall kyanos-console --namespace kyanos-system
kubectl delete namespace kyanos-system

# 移除 ClusterRole 和 ClusterRoleBinding（helm uninstall 会自动清理）
# 移除测试 Pod
kubectl delete -f deploy/test-ntrip-pod.yaml
```

### 4.2 部分回滚

```bash
# 仅回滚 Agent，保留 Console
helm uninstall kyanos-agent --namespace kyanos-system

# 仅回滚到单节点模式
helm upgrade kyanos-agent deploy/helm/kyanos-agent \
  --namespace kyanos-system \
  --set nodeSelector.kubernetes\\.io/hostname=10.152.0.102
```

### 4.3 影响评估

- **卸载 kyanos-agent**: DaemonSet 删除后，所有节点上的 Agent Pod 立即终止，eBPF 程序自动卸载
- **卸载 kyanos-console**: Console Pod 终止，所有 Agent 的 gRPC 连接断开（Agent 会持续重试但不影响业务）
- **对 position-precision 业务的影响**: kyanos-agent 使用 hostNetwork 但**仅监听/捕获，不注入或修改任何流量**，卸载后业务完全恢复

---

## 5. 验证检查清单

### 5.1 每阶段通用检查

| # | 检查项 | 命令 | 预期 |
|---|--------|------|------|
| CK1 | Pod Running | `kubectl get pods -n kyanos-system` | 0 CrashLoop |
| CK2 | eBPF 加载 | `kubectl logs <agent> -n kyanos-system --tail=50` | 含 "Loaded eBPF" |
| CK3 | gRPC 连接 | `kubectl logs <console> -n kyanos-system --tail=50` | 含 Agent 注册 |
| CK4 | 资源消耗 | `kubectl top pods -n kyanos-system` | CPU < limits |
| CK5 | 业务 Pod 健康 | `kubectl get pods -n position-precision` | 无新增异常 |
| CK6 | 节点负载 | `kubectl top nodes` | 无显著上升 |

### 5.2 关键技术验证

| # | 验证项 | 阶段 | 重要性 |
|---|--------|------|---------|
| TV1 | 5.4.241 内核 eBPF 加载（kprobe fallback） | A2 | 🔴 必须 |
| TV2 | 5.4.241 perf_buffer 替代 ringbuf | A2 | 🔴 必须 |
| TV3 | 5.4.241 ip_rcv_core symbol 解析 | A2/A3 | 🔴 必须 |
| TV4 | 76 节点 BTF 完整性 | A7 | 🔴 必须 |
| TV5 | 容器镜像漏洞扫描 | A4 | 🔴 必须 |
| TV6 | Helm 服务端 dry-run | A5 | 🔴 必须 |
| TV7 | 最小权限集确认 | A6 | 🟡 重要 |
| TV8 | containerd Pod 解析 | B8 | 🔴 必须 |
| TV9 | NTRIP 协议识别 | B7 | 🔴 必须 |
| TV10 | gRPC 长连接稳定性 | C5 | 🟡 重要 |
| TV11 | RTCM 诊断引擎输出 | C4 | 🟡 重要 |
| TV12 | TLS mTLS 连接 | D3 | 🟢 可选 |
| TV13 | Console 持久化 | D5 | 🟢 可选 |

---

## 6. 前置条件与依赖

### 6.1 必须提前解决

| # | 项 | 当前状态 | 需要的操作 |
|---|-----|---------|-----------|
| P1 | **5.4 内核隔离测试环境** | 跳板机是 6.6.110 | **创建 TencentOS 3.1 CVM**（约 ¥0.2/h），与 TKE 节点 OS/内核完全一致，验证完毕即销毁 |
| P2 | **CCR 命名空间** | 跳板机已登录 `image-apps.tencentcloudcr.com` | 确认实际使用的 CCR 地址和命名空间（values-tke.yaml 中的 `<YOUR_CCR_NAMESPACE>`） |
| P3 | **Console Dockerfile** | 本地 `console/Dockerfile` 存在 | 需要构建 Console 镜像 |
| P4 | **测试节点选择** | 无污点，18 个 positioning 节点可选 | 指定 B3 步骤的测试节点 IP |

### 6.2 建议提前准备

| # | 项 | 说明 |
|---|-----|------|
| S1 | **TLS 证书** | 生产环境 gRPC 应启用 mTLS，需提前生成 CA + 服务器/客户端证书 |
| S2 | **监控集成** | Agent 和 Console 应接入 TKE 已有的 Prometheus (monitoring namespace) |
| S3 | **日志收集** | 确认 TKE 日志收集机制能采集 kyanos-system namespace 的日志 |

---

## 7. 时间预估

| Phase | 步骤数 | 预估时间 | 前置 |
|-------|--------|---------|------|
| A0 (已确认) | 1 | 已完成 | 无 |
| A1 (创建 CVM) | 1 | 15-30 分钟 | A0 |
| A2 (5.4 冒烟) | 8 | 1-2 小时 | A1 |
| A3 (内核符号) | 1 | 30 分钟 | A0（可与 A2 并行） |
| A4 (镜像构建) | 6 | 2-3 小时 | A2 通过后 |
| A5 (Helm 验证) | 5 | 30 分钟 | A0（可与 A4 并行） |
| A6 (权限审计) | 4 | 1-2 小时 | A2 通过后（可与 A4 并行） |
| A7 (BTF 全量) | 1 | 30-60 分钟 | A0（可与 A2-A6 并行） |
| **A 合计** | | **4-6 小时** | |
| B (单节点) | 9 | 1-2 小时 | A 全通过 |
| C (小范围) | 6 | 24-48 小时（含稳定性观察） | B 全通过 |
| D (全量) | 5 | 2-4 小时 + 7 天观察 | C 全通过 |

**总计**: 约 8-14 天（含稳定性观察周期）

---

## 8. 决策审批点

> 以下每个节点需要 yuanhong 确认后方可推进：

1. **A1 之前**: 是否批准创建隔离 TencentOS 3.1 测试 CVM？预估成本 ¥0.2/小时。
2. **A2 之后**: 5.4 内核冒烟测试是否全部通过？如有失败项，如何修复？
3. **A6 之后**: 最小权限集确认后，是否接受该权限配置？
4. **A7 之后**: 76 节点 BTF 完整性是否全部确认？如有缺失节点如何处理？
5. **A 全部完成后**: 是否批准进入 Phase B（单节点验证）？
6. **B1 之前**: 是否允许在 TKE 集群创建 `kyanos-system` namespace？
7. **B3 之前**: 指定哪个节点作为单节点测试目标？
8. **C1 之前**: Phase B 全部通过后，是否扩展到 positioning 节点？
9. **D1 之前**: Phase C 24h 稳定后，是否全量部署？

---

## 附录 A: TKE 集群详情

```
Cluster: v1.34.1-tke.4/5
Control Plane: https://10.152.64.48
Nodes: 76 (all Ready, no taints)
Kernel: 5.4.241-19-0017/0023 (multiple sub-versions)
OS: TencentOS Server 3.1
Runtime: containerd://1.6.9-tke.8
Region: de (eu-frankfurt-1) / zone 170001

Node types:
  - team=positioning: 18 nodes (GNSS 业务节点)
  - node-type=high-performance: 32 nodes
  - node-type=standard: 10 nodes
  - other/ unlabeled: 16 nodes

Existing DaemonSets (76 instances each):
  - kube-system: csi-cbs-node, csi-nodeplugin-cfsplugin, ip-masq-agent,
    kube-proxy, tke-cni-agent, tke-eni-agent, tke-monitor-agent, tke-node-exporter
  - tcss: yunjing-agent (security agent)

Key namespaces:
  - position-precision: ~103 Running pods + multiple CrashLoopBackOff
  - ssr2osr-position-precision: ~13 Running pods
  - apps, middleware, monitoring, kuboard, tcss

Resource quota (position-precision):
  - pods: 103/14053
  - services: 102/19849
  - configmaps: 2/3985
```

## 附录 B: Helm Chart 结构

```
deploy/helm/kyanos-agent/
  Chart.yaml         — v0.1.0, appVersion 0.1.0
  values.yaml        — 默认值 (CCR, gRPC, resources, tolerations)
  templates/
    daemonset.yaml   — hostPID+hostNetwork+privileged, BPF volumes
    rbac.yaml        — ClusterRole (pods/nodes/services/watch) + Binding
    configmap.yaml   — kyanos.yaml 配置文件

deploy/helm/kyanos-console/
  Chart.yaml         — v0.1.0
  values.yaml        — 默认值 (CCR, gRPC:9090, http:8080, replicas:2)
  templates/
    deployment.yaml  — Console 服务, health probes, TLS/PVC support
    service.yaml     — ClusterIP (gRPC + HTTP)
    ingress.yaml     — 可选 Ingress
    pvc.yaml         — 可选持久化
    serviceaccount.yaml
```

## 附录 C: Dockerfile 分析

**Agent Dockerfile** (`deploy/Dockerfile`):
- Stage 1: golang:1.24-bookworm → 安装 clang/llvm/libelf-dev → build-bpf + btfgen → 静态编译 kyanos
- Stage 2: ubuntu:22.04 → 仅 libelf1 + ca-certificates → 66MB 二进制 + BTF 回退数据
- 关键问题: `make btfgen BUILD_ARCH=x86_64 ARCH_BPF_NAME=x86` 是否能覆盖 5.4.241 所有子版本？

**Console Dockerfile** (`console/Dockerfile`):
- 未在此次检查中读取，需确认是否已构建

## 附录 D: 安全权限需求

kyanos-agent DaemonSet 要求:
```yaml
securityContext:
  privileged: true
  capabilities:
    add: [SYS_ADMIN, BPF, NET_ADMIN, SYS_PTRACE, NET_RAW, PERFMON]

hostPID: true
hostNetwork: true
dnsPolicy: ClusterFirstWithHostNet
```

**建议降级方案**（Phase B/C 测试时评估）:
- 先用 `privileged: true` 验证功能
- 确认功能后，尝试替换为具体 capabilities
- 记录每个 capability 的实际使用情况

---

> **下一步行动**: yuanhong 审批此规划后，按 Phase A → B → C → D 顺序执行。
> 每个阶段完成后需确认后方可进入下一阶段。