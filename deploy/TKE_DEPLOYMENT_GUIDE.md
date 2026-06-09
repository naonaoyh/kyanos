# Kyanos GNSS 诊断系统 — 腾讯云 TKE 部署说明书

版本: 0.2.0 | 日期: 2026-06-09

---

## 一、系统概述

Kyanos 是一套基于 eBPF 技术的 GNSS（全球导航卫星系统）网络诊断平台，专用于 NTRIP/RTCM 协议的实时捕获、分析和故障排查。系统由两个核心组件构成：

**Kyanos Agent** — 以 DaemonSet 方式运行在每个节点上的 eBPF 探针。它以内核态零拷贝方式捕获 NTRIP/RTCM 流量，解析协议细节（包括 RTCM3 帧结构、CRC-24Q 校验、GPS-UTC 闰秒偏差等），并通过 gRPC 将诊断事件上报给 Console。

**Kyanos Console** — 中心化后端服务，以 Deployment 方式运行。它接收所有 Agent 上报的事件，提供 REST API、WebSocket 实时推送和 Web 管理面板，支持会话查询、诊断报告生成和历史数据回溯。

### 架构拓扑

```
                       ┌─────────────────────────────────┐
                       │    腾讯云 TKE 集群               │
                       │                                  │
                       │  ┌─────────────────────────────┐ │
                       │  │ kyanos-console (Deployment) │ │
                       │  │  gRPC :9090  HTTP :8080     │ │
                       │  │  2 副本，可水平扩展          │ │
                       │  └────────────┬────────────────┘ │
                       │               │ gRPC              │
          ┌────────────┼───────────────┼───────────────┐  │
          ▼            ▼               ▼               ▼  │
    ┌──────────┐ ┌──────────┐   ┌──────────┐   ┌──────────┐
    │ Agent    │ │ Agent    │   │ Agent    │   │ Agent    │
    │ (DS Pod) │ │ (DS Pod) │   │ (DS Pod) │   │ (DS Pod) │
    │ Node-1   │ │ Node-2   │   │ Node-3   │   │ Node-N   │
    │ eBPF     │ │ eBPF     │   │ eBPF     │   │ eBPF     │
    └──────────┘ └──────────┘   └──────────┘   └──────────┘
                       │                                  │
                       │  ┌─────────────────────────────┐ │
                       │  │ 测试 Pod (可选)              │ │
                       │  │ fake-ntrip-caster :2101     │ │
                       │  │ ntrip-test-client           │ │
                       │  └─────────────────────────────┘ │
                       └─────────────────────────────────┘
```

### 数据流

```
NTRIP Client/Server ──(网络流量)──> 节点网卡
                                      │
                                  eBPF kprobe/tracepoint
                                      │
                                      ▼
                                 Agent Pod
                                  │ 协议解析
                                  │ RTCM3 帧校验
                                  │ 会话诊断
                                  ▼
                             gRPC Stream
                                  │
                                  ▼
                              Console
                              │ 存储/索引
                              │ 诊断报告
                              ▼
                         Web 面板 / REST API
```

---

## 二、前置条件

### 2.1 TKE 集群要求

| 项目 | 要求 |
|------|------|
| TKE 版本 | 1.24+ |
| 节点操作系统 | Ubuntu 22.04 / TencentOS Server 3.1 / CentOS 8+ |
| 节点内核版本 | ≥ 5.4（推荐 5.15+） |
| BTF 支持 | `CONFIG_DEBUG_INFO_BTF=y`（TKE 标准镜像默认启用） |
| 节点规格 | Agent: ≥ 1C/2G；Console: ≥ 2C/4G |
| 网络插件 | Global-Router 或 VPC-CNI 均可 |

### 2.2 本地工具

部署前请确保本地已安装以下工具：

```bash
# kubectl（与 TKE 集群版本匹配）
kubectl version --client

# Helm v3.x
helm version

# Docker（用于构建镜像）
docker version

# 已配置 kubectl 连接到目标 TKE 集群
kubectl cluster-info
```

如果尚未配置 kubectl，可在 TKE 控制台获取 kubeconfig：TKE 控制台 → 集群 → 基本信息 → Kubeconfig → 复制并保存到 `~/.kube/config`。

### 2.3 腾讯云 CCR（容器镜像服务）

你需要在腾讯云容器镜像服务中创建一个命名空间和两个镜像仓库：

1. 登录腾讯云控制台，进入「容器镜像服务」
2. 创建命名空间（如 `kyanos`）
3. 创建两个镜像仓库：`kyanos-agent` 和 `kyanos-console`
4. 记录下你的 CCR 地址（通常为 `ccr.ccs.tencentyun.com`）和命名空间名称

### 2.4 节点 BPF 兼容性预检

在部署前，建议在目标节点上运行预检脚本验证 eBPF 兼容性。脚本会自动提权到 root（因为需要读取 `/sys/kernel/debug` 等内核路径）：

```bash
# 将预检脚本传到 TKE 节点上执行（脚本会自动 sudo 提权）
chmod +x deploy/scripts/preflight-check.sh
./deploy/scripts/preflight-check.sh
```

或通过临时 Pod 在集群内检查：

```bash
kubectl run preflight --rm -it --image=ubuntu:22.04 --privileged -- bash
# 在 Pod 内:
apt-get update && apt-get install -y curl
curl -sSL https://raw.githubusercontent.com/your-repo/kyanos/main/deploy/scripts/preflight-check.sh | bash
```

预检项目包括：内核版本、BTF 支持、BPF 系统调用、cgroup 挂载、tracefs 可用性和容器运行时检测。脚本输出通过（✓）、警告（⚠）、失败（✗）三级标记，任何一项失败将返回非零退出码。

---

## 三、构建和推送镜像

### 3.1 使用构建脚本（推荐）

项目提供了统一的构建脚本，支持一键构建并推送 Agent 和 Console 镜像：

```bash
# 从项目根目录执行
chmod +x deploy/scripts/build-and-push.sh

# 构建全部镜像并推送
./deploy/scripts/build-and-push.sh \
  --registry ccr.ccs.tencentyun.com \
  --namespace kyanos \
  --tag v0.1.0

# 仅构建 Agent
./deploy/scripts/build-and-push.sh --agent-only --tag v0.1.0

# 仅构建 Console
./deploy/scripts/build-and-push.sh --console-only --tag v0.1.0

# 构建但不推送（本地验证）
./deploy/scripts/build-and-push.sh --no-push --tag v0.1.0
```

### 3.2 手动构建

如需手动控制构建过程：

**Agent 镜像：**

```bash
# 项目根目录
docker build -f deploy/Dockerfile \
  --build-arg VERSION=$(git describe --tags --always) \
  --build-arg COMMIT_ID=$(git rev-parse HEAD) \
  --build-arg BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t ccr.ccs.tencentyun.com/kyanos/kyanos-agent:v0.1.0 \
  .

docker push ccr.ccs.tencentyun.com/kyanos/kyanos-agent:v0.1.0
```

**Console 镜像：**

Console 使用多阶段构建，包含 Vue.js 前端编译和 Go 后端编译：

```bash
# 项目根目录
docker build -f console/Dockerfile \
  --build-arg VERSION=$(git describe --tags --always) \
  --build-arg COMMIT_ID=$(git rev-parse HEAD) \
  --build-arg BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t ccr.ccs.tencentyun.com/kyanos/kyanos-console:v0.1.0 \
  .

docker push ccr.ccs.tencentyun.com/kyanos/kyanos-console:v0.1.0
```

### 3.3 镜像结构说明

| 镜像 | 基础镜像 | 内容 | 默认入口 |
|------|---------|------|---------|
| kyanos-agent | ubuntu:22.04 | kyanos 二进制 + BTF 回退文件 | `./kyanos watch ntrip --diag` |
| kyanos-console | ubuntu:22.04 | kyanos 二进制 + Vue 前端 dist | `./kyanos console --grpc-addr :9090 --http-addr :8080` |

---

## 四、部署步骤

### 4.1 一键部署（推荐）

使用提供的快速部署脚本。脚本会在部署前自动验证 kubectl/helm/docker 工具可用性和集群连接状态，并可选运行节点预检：

```bash
chmod +x deploy/scripts/quick-deploy.sh

# 完整部署（构建 + 部署，含预检）
./deploy/scripts/quick-deploy.sh \
  --ccr-namespace kyanos \
  --tag v0.1.0

# 使用已有镜像部署（跳过构建）
./deploy/scripts/quick-deploy.sh \
  --ccr-namespace kyanos \
  --tag v0.1.0 \
  --skip-build

# 跳过预检（已在之前验证过）
./deploy/scripts/quick-deploy.sh \
  --ccr-namespace kyanos \
  --tag v0.1.0 \
  --skip-build \
  --skip-preflight

# 带 CCR 认证部署
./deploy/scripts/quick-deploy.sh \
  --ccr-namespace kyanos \
  --tag v0.1.0 \
  --skip-build \
  --ccr-user <用户名> \
  --ccr-pass <密码>
```

### 4.2 手动分步部署

#### 4.2.1 创建命名空间

```bash
kubectl create namespace kyanos-system
```

#### 4.2.2 创建镜像拉取凭证（如 CCR 为私有仓库）

```bash
kubectl create secret docker-registry ccr-secret \
  --namespace kyanos-system \
  --docker-server=ccr.ccs.tencentyun.com \
  --docker-username=<用户名> \
  --docker-password=<密码>
```

#### 4.2.3 部署 Console

```bash
helm install kyanos-console deploy/helm/kyanos-console \
  --namespace kyanos-system \
  --set image.registry=ccr.ccs.tencentyun.com \
  --set image.repository=kyanos/kyanos-console \
  --set image.tag=v0.1.0 \
  --set replicaCount=2 \
  --wait --timeout 120s
```

或使用 TKE 专用 values 文件：

```bash
# 先编辑 deploy/values-tke-console.yaml 填入实际参数
helm install kyanos-console deploy/helm/kyanos-console \
  --namespace kyanos-system \
  -f deploy/values-tke-console.yaml \
  --wait --timeout 120s
```

#### 4.2.4 部署 Agent DaemonSet

```bash
helm install kyanos-agent deploy/helm/kyanos-agent \
  --namespace kyanos-system \
  --set image.registry=ccr.ccs.tencentyun.com \
  --set image.repository=kyanos/kyanos-agent \
  --set image.tag=v0.1.0 \
  --set grpc.server="kyanos-console.kyanos-system.svc.cluster.local:9090" \
  --wait --timeout 120s
```

或使用 TKE 专用 values 文件：

```bash
# 先编辑 deploy/values-tke.yaml 填入实际参数
helm install kyanos-agent deploy/helm/kyanos-agent \
  --namespace kyanos-system \
  -f deploy/values-tke.yaml \
  --wait --timeout 120s
```

### 4.3 验证部署

```bash
# 1. 检查所有 Pod 状态
kubectl get pods -n kyanos-system -o wide

# 预期输出:
# NAME                                 READY   STATUS    RESTARTS   AGE
# kyanos-console-xxx-xxx               1/1     Running   0          2m
# kyanos-console-xxx-yyy               1/1     Running   0          2m
# kyanos-agent-xxxxx                   1/1     Running   0          1m
# kyanos-agent-yyyyy                   1/1     Running   0          1m

# 2. 检查 DaemonSet 覆盖率
kubectl get ds -n kyanos-system
# DESIRED 应等于 CURRENT 且等于 READY

# 3. 检查 Console Service
kubectl get svc -n kyanos-system

# 4. 查看 Agent 启动日志
kubectl logs -n kyanos-system -l app.kubernetes.io/name=kyanos-agent --tail=30

# 5. 查看 Console 启动日志
kubectl logs -n kyanos-system -l app.kubernetes.io/name=kyanos-console --tail=20
```

---

## 五、配置参考

### 5.1 Agent 配置项

Agent 通过 Helm values 和 kyanos CLI 参数进行配置。主要配置项：

| Helm 路径 | 说明 | 默认值 |
|-----------|------|--------|
| `image.registry` | 镜像仓库地址 | `ccr.ccs.tencentyun.com` |
| `image.repository` | 镜像名称 | `kyanos/kyanos-agent` |
| `image.tag` | 镜像版本 | Chart appVersion |
| `grpc.server` | Console gRPC 地址 | `kyanos-console.kyanos-system.svc.cluster.local:9090` |
| `grpc.tls.enabled` | 启用 TLS | `false` |
| `diagnostics.enabled` | 启用 NTRIP 诊断 | `true` |
| `diagnostics.protocol` | 监控协议 | `ntrip` |
| `diagnostics.tcpHealth` | TCP 健康分析 | `true` |
| `diagnostics.extraArgs` | 额外 CLI 参数 | `[]` |
| `resources.requests.cpu` | CPU 请求 | `100m` |
| `resources.requests.memory` | 内存请求 | `128Mi` |
| `resources.limits.cpu` | CPU 限制 | `500m` |
| `resources.limits.memory` | 内存限制 | `512Mi` |
| `nodeSelector` | 节点选择器 | `{}` |
| `tolerations` | 容忍规则 | `[operator: Exists]` |

**常用 extraArgs：**

| 参数 | 说明 |
|------|------|
| `--remote-port=2101` | 仅捕获 NTRIP 标准端口流量 |
| `--grpc-pod-resolve` | 启用 Pod 身份解析 |
| `--grpc-namespace=default` | 仅监控特定命名空间的 Pod |
| `--gga-interval-warn=10s` | GGA 上报间隔告警阈值 |
| `--rtcm-interruption-warn=3s` | RTCM 中断告警阈值 |
| `--diag-report` | 会话关闭时打印诊断报告 |
| `--pcap-output=/tmp/capture.pcap` | 启用 PCAP 抓包 |
| `--cos-bucket=my-bucket` | 自动上传 PCAP 到 COS |

### 5.2 Console 配置项

| Helm 路径 | 说明 | 默认值 |
|-----------|------|--------|
| `image.registry` | 镜像仓库地址 | `ccr.ccs.tencentyun.com` |
| `image.repository` | 镜像名称 | `kyanos/kyanos-console` |
| `replicaCount` | 副本数 | `2` |
| `grpc.port` | gRPC 监听端口 | `9090` |
| `http.port` | HTTP 监听端口 | `8080` |
| `persistence.enabled` | 启用持久化存储 | `false` |
| `persistence.storageClass` | 存储类（TKE 推荐 `cbs-ssd`） | `""` |
| `persistence.size` | 存储大小 | `10Gi` |
| `storageRetention` | 数据保留天数 | `7` |
| `ingress.enabled` | 启用 Ingress | `false` |
| `service.type` | Service 类型 | `ClusterIP` |

> **持久化 + 多副本注意事项：** 当 `persistence.enabled=true` 且 `accessModes` 为 `ReadWriteOnce`（默认值）时，`replicaCount` 应设为 `1`。因为 `ReadWriteOnce` 只允许一个节点挂载该卷，多副本调度到不同节点时第二个 Pod 会卡在 `ContainerCreating` 状态。如需多副本 + 持久化，请将 `accessModes` 改为 `ReadWriteMany` 并使用支持此模式的存储类（如 CFS 或 NFS）。

### 5.3 TKE 环境专用配置示例

以下是一个典型的 TKE 生产环境 Agent 配置（`values-tke.yaml` 模板已提供在 `deploy/values-tke.yaml`）：

```yaml
image:
  registry: ccr.ccs.tencentyun.com
  repository: your-ns/kyanos-agent
  tag: "v0.1.0"

grpc:
  server: "kyanos-console.kyanos-system.svc.cluster.local:9090"

diagnostics:
  enabled: true
  protocol: "ntrip"
  tcpHealth: true
  extraArgs:
    - "--grpc-pod-resolve"
    - "--remote-port=2101"

resources:
  requests:
    cpu: 200m
    memory: 256Mi
  limits:
    cpu: "1"
    memory: 1Gi
```

---

## 六、TLS 安全配置

生产环境建议启用 Agent 与 Console 之间的 TLS 加密通信。

### 6.1 生成证书

```bash
# 使用 openssl 生成自签名 CA 和证书
# （生产环境建议使用腾讯云 SSL 证书服务）

# 1. 生成 CA
openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
  -keyout ca.key -out ca.crt \
  -subj "/CN=Kyanos CA"

# 2. 生成 Console 服务端证书
openssl req -newkey rsa:4096 -nodes \
  -keyout tls.key -out tls.csr \
  -subj "/CN=kyanos-console.kyanos-system.svc.cluster.local"

openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out tls.crt -days 365 \
  -extfile <(printf "subjectAltName=DNS:kyanos-console.kyanos-system.svc.cluster.local,DNS:kyanos-console.kyanos-system,DNS:localhost")
```

### 6.2 创建 K8s Secret

```bash
# Console TLS 证书
kubectl create secret tls kyanos-console-tls \
  --namespace kyanos-system \
  --cert=tls.crt \
  --key=tls.key

# Agent CA 证书（用于验证 Console 身份）
kubectl create secret generic kyanos-agent-tls \
  --namespace kyanos-system \
  --from-file=ca.crt=ca.crt
```

### 6.3 启用 TLS 部署

```bash
# 升级 Console 启用 TLS
helm upgrade kyanos-console deploy/helm/kyanos-console \
  --namespace kyanos-system \
  --set grpc.tls.enabled=true \
  --set grpc.tls.secretName=kyanos-console-tls

# 升级 Agent 启用 TLS
helm upgrade kyanos-agent deploy/helm/kyanos-agent \
  --namespace kyanos-system \
  --set grpc.tls.enabled=true \
  --set grpc.tls.caCert=/etc/kyanos/tls/ca.crt
```

---

## 七、Ingress 配置

如需通过域名访问 Console Web 面板，可启用 Ingress。TKE 支持 CLB Ingress Controller。

### 7.1 使用 TKE CLB Ingress

```yaml
# values-tke-console.yaml 中启用 Ingress
ingress:
  enabled: true
  className: "qcloud"
  annotations:
    kubernetes.io/ingress.class: qcloud
    # 使用已有的 CLB 实例（可选）
    kubernetes.io/ingress.existLbId: "lb-xxxxxxxx"
    # HTTPS 配置（可选）
    kubernetes.io/ingress.http-rules: '[{"host":"console.kyanos.example.com","path":"/","backend":{"serviceName":"kyanos-console","servicePort":8080}}]'
  hosts:
    - host: console.kyanos.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: kyanos-console-ingress-tls
      hosts:
        - console.kyanos.example.com
```

### 7.2 使用 port-forward 临时访问

不配置 Ingress 时，可通过 port-forward 临时访问 Web 面板：

```bash
kubectl port-forward -n kyanos-system svc/kyanos-console 8080:8080
# 浏览器打开 http://localhost:8080
```

---

## 八、功能验证

### 8.1 部署测试 NTRIP 流量

项目提供了模拟 NTRIP Caster 和 Client，用于生成测试流量验证系统功能：

```bash
# 部署模拟 NTRIP 源站和测试客户端
kubectl apply -f deploy/test-ntrip-pod.yaml

# 等待 Pod 就绪
kubectl wait --for=condition=Ready pod/fake-ntrip-caster --timeout=60s
kubectl wait --for=condition=Ready pod/ntrip-test-client --timeout=60s

# 验证流量正在产生
kubectl logs fake-ntrip-caster
# 预期: Fake NTRIP Caster running on port 2101

kubectl logs ntrip-test-client
# 预期: Connecting to http://fake-ntrip-caster:2101/RTCM3...

# 检查 Agent 是否捕获了 NTRIP 流量
kubectl logs -n kyanos-system -l app.kubernetes.io/name=kyanos-agent --tail=50
# 预期: 看到 NTRIP/RTCM 事件日志
```

### 8.2 访问 Console Web 面板

```bash
# port-forward 方式
kubectl port-forward -n kyanos-system svc/kyanos-console 8080:8080
# 打开浏览器访问 http://localhost:8080
```

Web 面板提供以下功能：在线 Agent 列表、实时会话监控、历史会话查询、诊断报告查看、WebSocket 实时推送。

### 8.3 REST API 验证

```bash
# 获取集群拓扑
curl http://localhost:8080/api/v1/topology

# 列出所有 Agent
curl http://localhost:8080/api/v1/agents

# 列出活跃会话
curl http://localhost:8080/api/v1/sessions

# 获取特定会话详情
curl http://localhost:8080/api/v1/sessions/<session-id>

# 获取会话诊断报告
curl http://localhost:8080/api/v1/sessions/<session-id>/report
```

### 8.4 完整验证清单

| 步骤 | 验证项 | 命令 | 预期结果 |
|------|--------|------|---------|
| 1 | Agent DaemonSet | `kubectl get ds -n kyanos-system` | DESIRED = READY |
| 2 | Console Deployment | `kubectl get deploy -n kyanos-system` | AVAILABLE = 期望副本数 |
| 3 | Console 健康检查 | `curl localhost:8080/healthz` | `ok`（纯文本） |
| 4 | Console 就绪检查 | `curl localhost:8080/readyz` | `ok`（纯文本） |
| 5 | 测试流量 | `kubectl apply -f deploy/test-ntrip-pod.yaml` | Pod Running |
| 6 | Agent 捕获 | Agent 日志 | 看到 NTRIP/RTCM 事件 |
| 7 | Console 接收 | Console 日志或 Web 面板 | 看到在线 Agent + 会话数据 |
| 8 | REST API | `curl localhost:8080/api/v1/sessions` | JSON 会话列表 |

---

## 九、运维操作

### 9.1 升级

```bash
# 构建新版本镜像
./deploy/scripts/build-and-push.sh --tag v0.2.0

# 升级 Agent（滚动更新，maxUnavailable=1）
helm upgrade kyanos-agent deploy/helm/kyanos-agent \
  --namespace kyanos-system \
  --set image.tag=v0.2.0

# 升级 Console
helm upgrade kyanos-console deploy/helm/kyanos-console \
  --namespace kyanos-system \
  --set image.tag=v0.2.0
```

### 9.2 回滚

```bash
# 回滚 Agent 到上一个版本
helm rollback kyanos-agent --namespace kyanos-system

# 回滚到指定版本
helm rollback kyanos-agent 2 --namespace kyanos-system

# 查看发布历史
helm history kyanos-agent --namespace kyanos-system
```

### 9.3 扩缩容

Console 支持水平扩展以应对大量 Agent 连接：

```bash
# 增加 Console 副本数
helm upgrade kyanos-console deploy/helm/kyanos-console \
  --namespace kyanos-system \
  --set replicaCount=4

# 或直接用 kubectl
kubectl scale deployment kyanos-console -n kyanos-system --replicas=4
```

Agent 以 DaemonSet 运行，自动随节点数量扩缩。如需仅在特定节点运行，配置 `nodeSelector`。

### 9.4 日志查看

```bash
# Agent 日志
kubectl logs -n kyanos-system -l app.kubernetes.io/name=kyanos-agent --tail=100 -f

# Console 日志
kubectl logs -n kyanos-system -l app.kubernetes.io/name=kyanos-console --tail=100 -f

# 特定 Pod 的前一次崩溃日志
kubectl logs -n kyanos-system <pod-name> --previous
```

### 9.5 卸载

```bash
# 卸载 Agent
helm uninstall kyanos-agent --namespace kyanos-system

# 卸载 Console
helm uninstall kyanos-console --namespace kyanos-system

# 清理测试 Pod
kubectl delete -f deploy/test-ntrip-pod.yaml

# 删除命名空间（清除所有资源，包括 PVC）
kubectl delete namespace kyanos-system
```

---

## 十、故障排查

### 10.1 Agent Pod 处于 CrashLoopBackOff

```bash
# 查看崩溃前的日志
kubectl logs -n kyanos-system <agent-pod> --previous

# 常见原因和解决方案:
#
# 1. "failed to load BPF object" — 内核版本过低或缺少 BTF
#    → 升级节点内核到 5.4+，或确认 Agent 镜像包含 BTF 回退文件
#
# 2. "permission denied" — 权限不足
#    → 确认 DaemonSet securityContext 包含 privileged: true
#
# 3. "failed to connect to console" — Console 地址错误
#    → 检查 grpc.server 配置是否正确指向 Console Service
#    → 验证 DNS 解析: kubectl exec <agent-pod> -- nslookup kyanos-console.kyanos-system.svc.cluster.local
```

### 10.2 Agent 未捕获 NTRIP 流量

```bash
# 1. 验证 hostNetwork 和 hostPID 已启用
kubectl get pod -n kyanos-system <agent-pod> \
  -o jsonpath='{.spec.hostNetwork} {.spec.hostPID}'
# 预期: true true

# 2. 验证目标 NTRIP 服务可达
kubectl exec -n kyanos-system <agent-pod> -- \
  curl -s http://fake-ntrip-caster.default:2101/

# 3. 确认没有 --remote-port 过滤（或端口设置正确）
kubectl get pod -n kyanos-system <agent-pod> -o yaml | grep -A 20 args

# 4. 启用 debug 日志排查
helm upgrade kyanos-agent deploy/helm/kyanos-agent \
  --namespace kyanos-system \
  --set extraEnv[0].name=KYANOS_LOG_LEVEL \
  --set extraEnv[0].value=debug
```

### 10.3 Console 未收到事件

```bash
# 1. 检查 Agent 到 Console 的 gRPC 连通性
kubectl exec -n kyanos-system <agent-pod> -- \
  nc -zv kyanos-console.kyanos-system.svc.cluster.local 9090

# 2. 检查 Console 的 gRPC 端口是否正常监听
kubectl exec -n kyanos-system <console-pod> -- \
  ss -tlnp | grep 9090

# 3. 查看 Console 日志中的 Agent 注册事件
kubectl logs -n kyanos-system -l app.kubernetes.io/name=kyanos-console | grep -i register

# 4. 确认 Service 端点正常
kubectl get endpoints -n kyanos-system kyanos-console
```

### 10.4 Console Web 面板无法访问

```bash
# 1. 检查 Service 和 Endpoints
kubectl get svc kyanos-console -n kyanos-system
kubectl get endpoints kyanos-console -n kyanos-system

# 2. 确认健康检查通过
kubectl exec -n kyanos-system <console-pod> -- curl -s localhost:8080/healthz

# 3. 如使用 Ingress，检查 Ingress 状态
kubectl get ingress -n kyanos-system
kubectl describe ingress -n kyanos-system
```

### 10.5 节点 eBPF 不兼容

```bash
# 在问题节点上运行预检脚本
kubectl run preflight --rm -it --privileged \
  --overrides='{"spec":{"nodeSelector":{"kubernetes.io/hostname":"<问题节点IP>"}}}' \
  --image=ubuntu:22.04 -- bash

# 在 Pod 内:
apt-get update && apt-get install -y kmod
uname -r
ls /sys/kernel/btf/vmlinux
ls /sys/fs/bpf
cat /proc/config.gz | gunzip | grep BPF
```

### 10.6 Console 第二个副本卡在 ContainerCreating

启用持久化存储后，如果 PVC 使用 `ReadWriteOnce` 访问模式，第二个副本将无法挂载卷：

```bash
# 检查 PVC 状态
kubectl get pvc -n kyanos-system

# 确认 accessModes
kubectl get pvc -n kyanos-system -o jsonpath='{.items[*].spec.accessModes}'

# 解决方案（选其一）：
# 方案 A: 将副本数降为 1
helm upgrade kyanos-console deploy/helm/kyanos-console \
  --namespace kyanos-system --set replicaCount=1

# 方案 B: 改用 ReadWriteMany 存储类
helm upgrade kyanos-console deploy/helm/kyanos-console \
  --namespace kyanos-system \
  --set persistence.accessModes[0]=ReadWriteMany \
  --set persistence.storageClass="cfs-nfs"
```

### 10.7 Helm 升级后 Agent 无法连接 Console

升级时如果修改了 Console Service 名称或端口，Agent 可能无法重连：

```bash
# 检查 Agent 使用的 Console 地址
kubectl get pod -n kyanos-system <agent-pod> -o jsonpath='{.spec.containers[0].args}' | tr ',' '\n'

# 检查 Service 端点
kubectl get svc -n kyanos-system kyanos-console
kubectl get endpoints -n kyanos-system kyanos-console

# 修复: 更新 Agent 的 grpc.server 配置
helm upgrade kyanos-agent deploy/helm/kyanos-agent \
  --namespace kyanos-system \
  --set grpc.server="kyanos-console.kyanos-system.svc.cluster.local:9090"
```

---

## 十一、TKE 平台特别说明

### 11.1 节点安全组

TKE 节点的安全组需要确保以下端口不被阻断：

| 方向 | 端口 | 协议 | 说明 |
|------|------|------|------|
| 入站 | 9090 | TCP | Agent → Console gRPC |
| 入站 | 8080 | TCP | Console HTTP/WebSocket |
| 出站 | 2101 | TCP | NTRIP 标准端口（被监控流量） |

注意：由于 Agent 使用 `hostNetwork: true`，安全组直接影响 Agent 的网络可见性。

### 11.2 存储类

TKE 提供 CBS（云硬盘）存储类，Console 持久化存储推荐使用：

| 存储类 | 适用场景 |
|--------|---------|
| `cbs-ssd` | 推荐，SSD 云硬盘，适合频繁读写 |
| `cbs-premium` | 高性能 SSD，适合大量历史数据 |
| `cbs-basic` | 普通云硬盘，适合低频访问归档 |

### 11.3 节点标签

TKE 节点通常具有以下标签，可用于 Agent 调度策略：

```bash
# 查看节点标签
kubectl get nodes --show-labels

# 常用标签:
# node.kubernetes.io/instance-type    — 机型
# topology.kubernetes.io/zone         — 可用区
# kubernetes.io/os                    — 操作系统
# kubernetes.io/arch                  — CPU 架构
```

### 11.4 COS 集成

Agent 支持将 PCAP 抓包文件自动上传到腾讯云 COS（对象存储），便于长期存储和分析：

```yaml
diagnostics:
  extraArgs:
    - "--pcap-output=/tmp/capture.pcap"
    - "--pcap-max-size=104857600"        # 100MB 轮转
    - "--pcap-max-duration=1h"           # 1小时轮转
    - "--cos-bucket=my-cos-bucket"
    - "--cos-region=ap-guangzhou"
    - "--cos-prefix=kyanos-captures/"
    - "--cos-delete-raw"                 # 上传后删除本地文件
```

---

## 十二、部署文件清单

项目 `deploy/` 目录下与 TKE 部署相关的完整文件清单：

```
deploy/
├── Dockerfile                          # Agent 多阶段构建文件
├── README.md                           # 英文部署说明（简版）
├── README_CN.md                        # 中文部署说明（简版）
├── test-ntrip-pod.yaml                 # 测试 NTRIP 流量 Pod
├── values-tke.yaml                     # TKE Agent 专用 values 覆盖
├── values-tke-console.yaml             # TKE Console 专用 values 覆盖
├── TKE_DEPLOYMENT_GUIDE.md             # 本部署说明书
├── scripts/
│   ├── build-and-push.sh               # 镜像构建和推送脚本
│   ├── preflight-check.sh              # 节点 eBPF 预检脚本
│   └── quick-deploy.sh                 # TKE 一键部署脚本
└── helm/
    ├── kyanos-agent/
    │   ├── Chart.yaml                  # Agent Helm Chart 元数据
    │   ├── values.yaml                 # Agent 默认 values
    │   └── templates/
    │       ├── _helpers.tpl            # Helm 模板函数
    │       ├── daemonset.yaml          # Agent DaemonSet
    │       ├── rbac.yaml               # ClusterRole/ClusterRoleBinding
    │       └── configmap.yaml          # Agent 配置
    └── kyanos-console/
        ├── Chart.yaml                  # Console Helm Chart 元数据
        ├── values.yaml                 # Console 默认 values
        └── templates/
            ├── _helpers.tpl            # Helm 模板函数
            ├── deployment.yaml         # Console Deployment
            ├── service.yaml            # Console Service (gRPC + HTTP)
            ├── serviceaccount.yaml     # ServiceAccount
            ├── ingress.yaml            # Ingress (可选)
            └── pvc.yaml                # PersistentVolumeClaim (可选)
```
