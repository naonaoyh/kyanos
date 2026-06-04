# Kyanos GNSS 诊断 Agent — 腾讯云 TKE 部署指南

本目录包含 Kyanos GNSS 诊断 Agent 在**腾讯云容器服务 (TKE)** 上的完整 Kubernetes 部署配置。

## 架构概览

```
┌─────────────────────────────────────────────────────────────┐
│  TKE 集群                                                   │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  kyanos-console (Deployment, 2 副本)                   │  │
│  │  - gRPC 服务端 :9090 (Agent 连接端口)                  │  │
│  │  - HTTP 管理面板 :8080                                 │  │
│  └────────────────────────┬──────────────────────────────┘  │
│                           │ gRPC                             │
│          ┌────────────────┼────────────────┐                │
│          ▼                ▼                ▼                 │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐        │
│  │ kyanos-agent │ │ kyanos-agent │ │ kyanos-agent │        │
│  │ (DaemonSet)  │ │ (DaemonSet)  │ │ (DaemonSet)  │        │
│  │  节点 1      │ │  节点 2      │ │  节点 3      │        │
│  │  eBPF 探针   │ │  eBPF 探针   │ │  eBPF 探针   │        │
│  └──────────────┘ └──────────────┘ └──────────────┘        │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  测试 Pod (可选)                                       │  │
│  │  - fake-ntrip-caster: RTCM3 模拟源站                  │  │
│  │  - ntrip-test-client: 流量生成客户端                   │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 前置条件

- TKE 集群，节点内核 5.4+（Ubuntu 22.04 或 TencentOS Server 3.1）
- 已配置 `kubectl` 连接到你的 TKE 集群
- 安装 `helm` v3.x
- 容器镜像已推送至腾讯云容器镜像服务 (CCR)
- 节点必须支持 BTF（`CONFIG_DEBUG_INFO_BTF=y`）

### 验证节点 BPF 支持

```bash
# 登录节点或运行特权 Pod 检查
kubectl run btf-check --rm -it --image=ubuntu:22.04 --privileged -- bash -c \
  "ls /sys/kernel/btf/vmlinux && echo 'BTF 正常' || echo 'BTF 不可用'"
```

## 构建和推送镜像

### Kyanos Agent 镜像

```bash
# 在项目根目录执行
docker build -f deploy/Dockerfile \
  --build-arg VERSION=$(git describe --tags --always) \
  --build-arg COMMIT_ID=$(git rev-parse HEAD) \
  --build-arg BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t ccr.ccs.tencentyun.com/kyanos/kyanos-agent:latest .

# 推送到腾讯云 CCR
docker push ccr.ccs.tencentyun.com/kyanos/kyanos-agent:latest
```

### Kyanos Console 镜像

```bash
# 构建 Console（Phase 8 Web 后端）
docker build -f console/Dockerfile \
  -t ccr.ccs.tencentyun.com/kyanos/kyanos-console:latest ./console/

docker push ccr.ccs.tencentyun.com/kyanos/kyanos-console:latest
```

## 部署步骤

### 1. 创建命名空间

```bash
kubectl create namespace kyanos-system
```

### 2. 部署 Console

```bash
helm install kyanos-console deploy/helm/kyanos-console \
  --namespace kyanos-system \
  --set image.registry=ccr.ccs.tencentyun.com \
  --set image.repository=kyanos/kyanos-console
```

### 3. 部署 Agent DaemonSet

```bash
helm install kyanos-agent deploy/helm/kyanos-agent \
  --namespace kyanos-system \
  --set image.registry=ccr.ccs.tencentyun.com \
  --set image.repository=kyanos/kyanos-agent \
  --set grpc.server="kyanos-console.kyanos-system.svc.cluster.local:9090"
```

### 4. 验证部署

```bash
# 检查 Agent Pod 在所有节点上运行
kubectl get pods -n kyanos-system -l app.kubernetes.io/name=kyanos-agent -o wide

# 检查 Console 健康状态
kubectl get pods -n kyanos-system -l app.kubernetes.io/name=kyanos-console

# 查看 Agent 日志
kubectl logs -n kyanos-system -l app.kubernetes.io/name=kyanos-agent --tail=50
```

## 使用模拟 NTRIP 流量测试

部署测试用的 NTRIP 模拟源站和客户端来生成流量：

```bash
# 部署模拟 NTRIP 源站 + 测试客户端
kubectl apply -f deploy/test-ntrip-pod.yaml

# 等待 Pod 就绪
kubectl wait --for=condition=Ready pod/fake-ntrip-caster --timeout=60s
kubectl wait --for=condition=Ready pod/ntrip-test-client --timeout=60s

# 验证流量正在产生
kubectl logs fake-ntrip-caster
kubectl logs ntrip-test-client

# 检查 kyanos-agent 是否捕获了 NTRIP 流量
kubectl logs -n kyanos-system -l app.kubernetes.io/name=kyanos-agent --tail=20
```

## 配置说明

### Agent 参数覆盖（TKE 环境）

创建 `values-tke.yaml` 适配你的环境：

```yaml
# values-tke.yaml
image:
  registry: ccr.ccs.tencentyun.com
  repository: kyanos/kyanos-agent
  tag: "0.1.0"

grpc:
  server: "kyanos-console.kyanos-system.svc.cluster.local:9090"
  tls:
    enabled: true
    caCert: "/etc/kyanos/tls/ca.crt"

diagnostics:
  enabled: true
  protocol: "ntrip"
  tcpHealth: true
  extraArgs:
    - "--remote-port=2101"

resources:
  requests:
    cpu: 200m
    memory: 256Mi
  limits:
    cpu: "1"
    memory: 1Gi

# 仅调度到 GNSS 处理节点
nodeSelector:
  node-role.kubernetes.io/gnss: ""

tolerations:
  - key: "dedicated"
    operator: "Equal"
    value: "gnss"
    effect: "NoSchedule"
```

使用自定义配置部署：

```bash
helm install kyanos-agent deploy/helm/kyanos-agent \
  --namespace kyanos-system \
  -f values-tke.yaml
```

### TLS 配置

生产环境建议启用 Agent 与 Console 之间的 TLS 加密：

```bash
# 为 Console 创建 TLS Secret
kubectl create secret tls kyanos-console-tls \
  --namespace kyanos-system \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key

# 为 Agent 创建 CA 证书 Secret
kubectl create secret generic kyanos-agent-tls \
  --namespace kyanos-system \
  --from-file=ca.crt=path/to/ca.crt

# 启用 TLS 部署
helm upgrade kyanos-console deploy/helm/kyanos-console \
  --namespace kyanos-system \
  --set grpc.tls.enabled=true \
  --set grpc.tls.secretName=kyanos-console-tls

helm upgrade kyanos-agent deploy/helm/kyanos-agent \
  --namespace kyanos-system \
  --set grpc.tls.enabled=true
```

## TKE 特别说明

### 内核与 BPF 兼容性

TKE 节点通常运行以下系统：
- **Ubuntu 22.04**，内核 5.15+ — 完整 BPF/BTF 支持
- **TencentOS Server 3.1**，内核 5.4+ — 完整 BPF 支持

两者均支持 CO-RE（一次编译，到处运行），Agent 内置的 BTF 文件为没有 `/sys/kernel/btf/vmlinux` 的节点提供回退支持。

### 安全权限

Agent 需要特权访问以执行 eBPF 操作。最低所需 capabilities：
- `CAP_BPF` — 加载和管理 BPF 程序
- `CAP_SYS_ADMIN` — 访问内核数据结构
- `CAP_NET_ADMIN` — 附加到网络接口
- `CAP_SYS_PTRACE` — 读取进程内存（SSL 密钥提取）
- `CAP_PERFMON` — 附加 perf 事件
- `CAP_NET_RAW` — 原始套接字访问

DaemonSet 模板默认使用 `privileged: true` 以保证最大兼容性。如需细粒度控制，可替换为上述具体 capabilities。

### 网络配置

- `hostNetwork: true` — 必需，使 Agent 能看到所有主机网络流量
- `hostPID: true` — 必需，用于进程级别的流量归属
- `dnsPolicy: ClusterFirstWithHostNet` — 确保使用 hostNetwork 时集群内 DNS 正常

### 容器镜像仓库认证

如果你的 CCR 需要认证：

```bash
kubectl create secret docker-registry ccr-secret \
  --namespace kyanos-system \
  --docker-server=ccr.ccs.tencentyun.com \
  --docker-username=<用户名> \
  --docker-password=<密码>

# 在 values.yaml 中引用：
# imagePullSecrets:
#   - name: ccr-secret
```

## 升级

```bash
# 升级 Agent
helm upgrade kyanos-agent deploy/helm/kyanos-agent \
  --namespace kyanos-system \
  --set image.tag="0.2.0"

# 升级 Console
helm upgrade kyanos-console deploy/helm/kyanos-console \
  --namespace kyanos-system \
  --set image.tag="0.2.0"
```

## 卸载

```bash
helm uninstall kyanos-agent --namespace kyanos-system
helm uninstall kyanos-console --namespace kyanos-system
kubectl delete namespace kyanos-system

# 清理测试 Pod
kubectl delete -f deploy/test-ntrip-pod.yaml
```

## 故障排查

### Agent Pod 处于 CrashLoopBackOff

```bash
# 查看 BPF 加载错误日志
kubectl logs -n kyanos-system <agent-pod名> --previous

# 常见问题：
# - 内核版本过低：需要 5.4+ 以支持完整 eBPF
# - BTF 不可用：检查节点上是否存在 /sys/kernel/btf/vmlinux
# - 权限不足：确保 Pod 以特权模式运行或拥有正确的 capabilities
```

### Agent 未捕获 NTRIP 流量

```bash
# 验证 hostNetwork 和 hostPID 已生效
kubectl get pod -n kyanos-system <agent-pod名> -o jsonpath='{.spec.hostNetwork}'

# 验证目标 NTRIP 服务可达
kubectl exec -n kyanos-system <agent-pod名> -- curl -s http://fake-ntrip-caster.default:2101/
```

### Console 未收到事件

```bash
# 检查 Agent 到 Console 的网络连通性
kubectl exec -n kyanos-system <agent-pod名> -- \
  nc -zv kyanos-console.kyanos-system.svc.cluster.local 9090

# 查看 Console 日志中的注册事件
kubectl logs -n kyanos-system -l app.kubernetes.io/name=kyanos-console
```

## 快速验证清单

部署完成后，按以下顺序验证：

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1. Agent 运行 | `kubectl get ds -n kyanos-system` | DESIRED = READY |
| 2. Console 运行 | `kubectl get deploy -n kyanos-system` | AVAILABLE = 2 |
| 3. 测试流量 | `kubectl apply -f deploy/test-ntrip-pod.yaml` | Pod Running |
| 4. 流量捕获 | `kubectl logs -n kyanos-system -l app.kubernetes.io/name=kyanos-agent` | 看到 NTRIP/RTCM 事件 |
| 5. Console 接收 | Console HTTP :8080 面板 | 看到在线 Agent + 会话数据 |
