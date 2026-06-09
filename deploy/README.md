# Kyanos GNSS Diagnostic Agent — TKE Deployment Guide

This directory contains the complete Kubernetes deployment configuration for the Kyanos GNSS diagnostic agent, targeting **Tencent Kubernetes Engine (TKE)**.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  TKE Cluster                                                │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  kyanos-console (Deployment, 2 replicas)              │  │
│  │  - gRPC server :9090 (agents connect here)            │  │
│  │  - HTTP dashboard :8080                               │  │
│  └────────────────────────┬──────────────────────────────┘  │
│                           │ gRPC                             │
│          ┌────────────────┼────────────────┐                │
│          ▼                ▼                ▼                 │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐        │
│  │ kyanos-agent │ │ kyanos-agent │ │ kyanos-agent │        │
│  │ (DaemonSet)  │ │ (DaemonSet)  │ │ (DaemonSet)  │        │
│  │  Node 1      │ │  Node 2      │ │  Node 3      │        │
│  │  eBPF probes │ │  eBPF probes │ │  eBPF probes │        │
│  └──────────────┘ └──────────────┘ └──────────────┘        │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Test Pods (optional)                                 │  │
│  │  - fake-ntrip-caster: RTCM3 source                   │  │
│  │  - ntrip-test-client: traffic generator               │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

- TKE cluster with kernel 5.4+ (Ubuntu 22.04 or TencentOS Server 3.1)
- `kubectl` configured for your TKE cluster
- `helm` v3.x installed
- Container images pushed to Tencent Cloud Container Registry (CCR)
- Nodes must have BTF support enabled (`CONFIG_DEBUG_INFO_BTF=y`)

### Verify BPF support on TKE nodes

```bash
# SSH into a node or run a privileged pod
kubectl run btf-check --rm -it --image=ubuntu:22.04 --privileged -- bash -c \
  "ls /sys/kernel/btf/vmlinux && echo 'BTF OK' || echo 'BTF not available'"
```

## Build & Push Images

### Kyanos Agent

```bash
# From the project root
docker build -f deploy/Dockerfile \
  --build-arg VERSION=$(git describe --tags --always) \
  --build-arg COMMIT_ID=$(git rev-parse HEAD) \
  --build-arg BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t ccr.ccs.tencentyun.com/kyanos/kyanos-agent:latest .

# Push to Tencent CCR
docker push ccr.ccs.tencentyun.com/kyanos/kyanos-agent:latest
```

### Kyanos Console

```bash
# Build from the console directory (Phase 8 implementation)
docker build -f console/Dockerfile \
  -t ccr.ccs.tencentyun.com/kyanos/kyanos-console:latest ./console/

docker push ccr.ccs.tencentyun.com/kyanos/kyanos-console:latest
```

## Deployment

### 1. Create Namespace

```bash
kubectl create namespace kyanos-system
```

### 2. Deploy Console

```bash
helm install kyanos-console deploy/helm/kyanos-console \
  --namespace kyanos-system \
  --set image.registry=ccr.ccs.tencentyun.com \
  --set image.repository=kyanos/kyanos-console
```

### 3. Deploy Agent DaemonSet

```bash
helm install kyanos-agent deploy/helm/kyanos-agent \
  --namespace kyanos-system \
  --set image.registry=ccr.ccs.tencentyun.com \
  --set image.repository=kyanos/kyanos-agent \
  --set grpc.server="kyanos-console.kyanos-system.svc.cluster.local:9090"
```

### 4. Verify Deployment

```bash
# Check agent pods are running on all nodes
kubectl get pods -n kyanos-system -l app.kubernetes.io/name=kyanos-agent -o wide

# Check console is healthy
kubectl get pods -n kyanos-system -l app.kubernetes.io/name=kyanos-console

# View agent logs
kubectl logs -n kyanos-system -l app.kubernetes.io/name=kyanos-agent --tail=50
```

## Testing with Fake NTRIP Traffic

Deploy the test NTRIP caster and client to generate traffic:

```bash
# Deploy fake NTRIP caster + test client
kubectl apply -f deploy/test-ntrip-pod.yaml

# Wait for pods to start
kubectl wait --for=condition=Ready pod/fake-ntrip-caster --timeout=60s
kubectl wait --for=condition=Ready pod/ntrip-test-client --timeout=60s

# Verify traffic is flowing
kubectl logs fake-ntrip-caster
kubectl logs ntrip-test-client

# Check that kyanos-agent is capturing the NTRIP traffic
kubectl logs -n kyanos-system -l app.kubernetes.io/name=kyanos-agent --tail=20
```

## Configuration

### Agent Values Override (TKE-specific)

Create a `values-tke.yaml` for your environment:

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

# Target only GNSS processing nodes
nodeSelector:
  node-role.kubernetes.io/gnss: ""

tolerations:
  - key: "dedicated"
    operator: "Equal"
    value: "gnss"
    effect: "NoSchedule"
```

Then deploy:

```bash
helm install kyanos-agent deploy/helm/kyanos-agent \
  --namespace kyanos-system \
  -f values-tke.yaml
```

### TLS Configuration

For production, enable TLS between agent and console:

```bash
# Create TLS secret for the console
kubectl create secret tls kyanos-console-tls \
  --namespace kyanos-system \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key

# Create TLS secret for the agent (CA cert)
kubectl create secret generic kyanos-agent-tls \
  --namespace kyanos-system \
  --from-file=ca.crt=path/to/ca.crt

# Deploy with TLS enabled
helm upgrade kyanos-console deploy/helm/kyanos-console \
  --namespace kyanos-system \
  --set grpc.tls.enabled=true \
  --set grpc.tls.secretName=kyanos-console-tls

helm upgrade kyanos-agent deploy/helm/kyanos-agent \
  --namespace kyanos-system \
  --set grpc.tls.enabled=true
```

## TKE-Specific Notes

### Kernel & BPF Compatibility

TKE nodes typically run:
- **Ubuntu 22.04** with kernel 5.15+ — full BPF/BTF support
- **TencentOS Server 3.1** with kernel 5.4+ — full BPF support

Both support CO-RE (Compile Once – Run Everywhere) via BTF, so the agent's embedded BTF files handle fallback for nodes without `/sys/kernel/btf/vmlinux`.

### Security

The agent requires privileged access for eBPF operations. Minimum capabilities:
- `CAP_BPF` — load and manage BPF programs
- `CAP_SYS_ADMIN` — access kernel data structures
- `CAP_NET_ADMIN` — attach to network interfaces
- `CAP_SYS_PTRACE` — read process memory (SSL key extraction)
- `CAP_PERFMON` — attach perf events
- `CAP_NET_RAW` — raw socket access

The DaemonSet template uses `privileged: true` for maximum compatibility. In environments requiring fine-grained control, replace with the specific capabilities listed above.

### Networking

- `hostNetwork: true` — required so the agent sees all host network traffic
- `hostPID: true` — required for process-level attribution
- `dnsPolicy: ClusterFirstWithHostNet` — ensures in-cluster DNS works with hostNetwork

### Container Registry Authentication

If your CCR requires authentication:

```bash
kubectl create secret docker-registry ccr-secret \
  --namespace kyanos-system \
  --docker-server=ccr.ccs.tencentyun.com \
  --docker-username=<username> \
  --docker-password=<password>

# Reference in values:
# imagePullSecrets:
#   - name: ccr-secret
```

## Upgrading

```bash
# Update agent
helm upgrade kyanos-agent deploy/helm/kyanos-agent \
  --namespace kyanos-system \
  --set image.tag="0.2.0"

# Update console
helm upgrade kyanos-console deploy/helm/kyanos-console \
  --namespace kyanos-system \
  --set image.tag="0.2.0"
```

## Uninstall

```bash
helm uninstall kyanos-agent --namespace kyanos-system
helm uninstall kyanos-console --namespace kyanos-system
kubectl delete namespace kyanos-system

# Clean up test pods
kubectl delete -f deploy/test-ntrip-pod.yaml
```

## Troubleshooting

### Agent pod CrashLoopBackOff

```bash
# Check logs for BPF loading errors
kubectl logs -n kyanos-system <agent-pod> --previous

# Common issues:
# - Kernel too old: need 5.4+ for full eBPF support
# - BTF not available: check /sys/kernel/btf/vmlinux exists on node
# - Insufficient capabilities: ensure privileged or correct caps
```

### Agent not capturing NTRIP traffic

```bash
# Verify hostNetwork and hostPID are active
kubectl get pod -n kyanos-system <agent-pod> -o jsonpath='{.spec.hostNetwork}'

# Verify the target NTRIP service is reachable
kubectl exec -n kyanos-system <agent-pod> -- curl -s http://fake-ntrip-caster.default:2101/
```

### Console not receiving events

```bash
# Check agent-to-console connectivity
kubectl exec -n kyanos-system <agent-pod> -- \
  nc -zv kyanos-console.kyanos-system.svc.cluster.local 9090

# Check console logs for registration events
kubectl logs -n kyanos-system -l app.kubernetes.io/name=kyanos-console
```

## Additional Resources

For a comprehensive deployment guide, automation scripts, and preflight checks:

- [TKE Deployment Guide](./TKE_DEPLOYMENT_GUIDE.md) — Full guide for Tencent Kubernetes Engine
- `scripts/build-and-push.sh` — Build and push container images
- `scripts/quick-deploy.sh` — One-command TKE deployment
- `scripts/preflight-check.sh` — Node eBPF compatibility checker
- `values-tke.yaml` / `values-tke-console.yaml` — TKE-specific Helm value overrides
