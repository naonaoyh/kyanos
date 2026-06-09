#!/usr/bin/env bash
# quick-deploy.sh — TKE 一键部署脚本
#
# 用法:
#   ./deploy/scripts/quick-deploy.sh --registry ccr.ccs.tencentyun.com --namespace kyanos --tag v0.1.0
#
# 此脚本自动执行:
#   1. 创建 kyanos-system 命名空间
#   2. 创建 CCR 镜像拉取 Secret（可选）
#   3. 部署 Console (Helm)
#   4. 部署 Agent DaemonSet (Helm)
#   5. 验证部署状态
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Defaults
REGISTRY="ccr.ccs.tencentyun.com"
CCR_NAMESPACE="kyanos"
TAG="latest"
K8S_NAMESPACE="kyanos-system"
CCR_USER=""
CCR_PASS=""
SKIP_BUILD=false
CONSOLE_REPLICAS=2

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

一键部署 Kyanos GNSS 诊断系统到 TKE 集群。

Required:
  --registry REGISTRY       容器镜像仓库 (default: ccr.ccs.tencentyun.com)
  --ccr-namespace NS        CCR 命名空间
  --tag TAG                 镜像 tag

Optional:
  --k8s-namespace NS        K8s 命名空间 (default: kyanos-system)
  --ccr-user USER           CCR 用户名（创建 imagePullSecret）
  --ccr-pass PASS           CCR 密码
  --skip-build              跳过镜像构建（使用已推送的镜像）
  --console-replicas N      Console 副本数 (default: 2)
  -h, --help                显示帮助

Examples:
  # 构建并部署
  $(basename "$0") --ccr-namespace myteam --tag v0.1.0

  # 使用已有镜像部署
  $(basename "$0") --ccr-namespace myteam --tag v0.1.0 --skip-build

  # 带认证部署
  $(basename "$0") --ccr-namespace myteam --tag v0.1.0 --ccr-user admin --ccr-pass xxx
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --registry)         REGISTRY="$2"; shift 2 ;;
        --ccr-namespace)    CCR_NAMESPACE="$2"; shift 2 ;;
        --tag)              TAG="$2"; shift 2 ;;
        --k8s-namespace)    K8S_NAMESPACE="$2"; shift 2 ;;
        --ccr-user)         CCR_USER="$2"; shift 2 ;;
        --ccr-pass)         CCR_PASS="$2"; shift 2 ;;
        --skip-build)       SKIP_BUILD=true; shift ;;
        --console-replicas) CONSOLE_REPLICAS="$2"; shift 2 ;;
        -h|--help)          usage ;;
        *)                  echo "Unknown option: $1"; usage ;;
    esac
done

AGENT_IMAGE="${REGISTRY}/${CCR_NAMESPACE}/kyanos-agent:${TAG}"
CONSOLE_IMAGE="${REGISTRY}/${CCR_NAMESPACE}/kyanos-console:${TAG}"

echo "=========================================="
echo "  Kyanos TKE 一键部署"
echo "=========================================="
echo "  镜像仓库:     ${REGISTRY}/${CCR_NAMESPACE}"
echo "  镜像 Tag:     ${TAG}"
echo "  K8s 命名空间: ${K8S_NAMESPACE}"
echo "  Console 副本: ${CONSOLE_REPLICAS}"
echo "=========================================="
echo ""

# ── Step 1: Build & Push images ─────────────────────────────────
if [ "$SKIP_BUILD" = false ]; then
    echo "[Step 1/5] 构建并推送镜像..."
    "${SCRIPT_DIR}/build-and-push.sh" \
        --registry "${REGISTRY}" \
        --namespace "${CCR_NAMESPACE}" \
        --tag "${TAG}"
    echo ""
else
    echo "[Step 1/5] 跳过镜像构建（使用已有镜像）"
    echo ""
fi

# ── Step 2: Create namespace ─────────────────────────────────────
echo "[Step 2/5] 创建 K8s 命名空间..."
if kubectl get namespace "${K8S_NAMESPACE}" &>/dev/null; then
    echo "  命名空间 ${K8S_NAMESPACE} 已存在，跳过创建。"
else
    kubectl create namespace "${K8S_NAMESPACE}"
    echo "  命名空间 ${K8S_NAMESPACE} 已创建。"
fi
echo ""

# ── Step 3: Create imagePullSecret (if credentials provided) ────
echo "[Step 3/5] 配置镜像拉取凭证..."
if [ -n "$CCR_USER" ] && [ -n "$CCR_PASS" ]; then
    kubectl create secret docker-registry ccr-secret \
        --namespace "${K8S_NAMESPACE}" \
        --docker-server="${REGISTRY}" \
        --docker-username="${CCR_USER}" \
        --docker-password="${CCR_PASS}" \
        --dry-run=client -o yaml | kubectl apply -f -
    echo "  imagePullSecret 'ccr-secret' 已创建。"
    PULL_SECRET="--set imagePullSecrets[0].name=ccr-secret"
else
    echo "  未提供 CCR 认证信息，跳过 imagePullSecret 创建。"
    PULL_SECRET=""
fi
echo ""

# ── Step 4: Deploy Console ───────────────────────────────────────
echo "[Step 4/5] 部署 Kyanos Console..."

# Uninstall existing release if present
if helm status kyanos-console --namespace "${K8S_NAMESPACE}" &>/dev/null; then
    echo "  检测到已有 kyanos-console release，执行升级..."
    helm upgrade kyanos-console "${PROJECT_ROOT}/deploy/helm/kyanos-console" \
        --namespace "${K8S_NAMESPACE}" \
        --set image.registry="${REGISTRY}" \
        --set image.repository="${CCR_NAMESPACE}/kyanos-console" \
        --set image.tag="${TAG}" \
        --set replicaCount="${CONSOLE_REPLICAS}" \
        ${PULL_SECRET} \
        --wait --timeout 120s
else
    helm install kyanos-console "${PROJECT_ROOT}/deploy/helm/kyanos-console" \
        --namespace "${K8S_NAMESPACE}" \
        --set image.registry="${REGISTRY}" \
        --set image.repository="${CCR_NAMESPACE}/kyanos-console" \
        --set image.tag="${TAG}" \
        --set replicaCount="${CONSOLE_REPLICAS}" \
        ${PULL_SECRET} \
        --wait --timeout 120s
fi
echo "  Console 部署完成。"
echo ""

# ── Step 5: Deploy Agent ────────────────────────────────────────
echo "[Step 5/5] 部署 Kyanos Agent DaemonSet..."

CONSOLE_ADDR="kyanos-console.${K8S_NAMESPACE}.svc.cluster.local:9090"

if helm status kyanos-agent --namespace "${K8S_NAMESPACE}" &>/dev/null; then
    echo "  检测到已有 kyanos-agent release，执行升级..."
    helm upgrade kyanos-agent "${PROJECT_ROOT}/deploy/helm/kyanos-agent" \
        --namespace "${K8S_NAMESPACE}" \
        --set image.registry="${REGISTRY}" \
        --set image.repository="${CCR_NAMESPACE}/kyanos-agent" \
        --set image.tag="${TAG}" \
        --set grpc.server="${CONSOLE_ADDR}" \
        ${PULL_SECRET} \
        --wait --timeout 120s
else
    helm install kyanos-agent "${PROJECT_ROOT}/deploy/helm/kyanos-agent" \
        --namespace "${K8S_NAMESPACE}" \
        --set image.registry="${REGISTRY}" \
        --set image.repository="${CCR_NAMESPACE}/kyanos-agent" \
        --set image.tag="${TAG}" \
        --set grpc.server="${CONSOLE_ADDR}" \
        ${PULL_SECRET} \
        --wait --timeout 120s
fi
echo "  Agent 部署完成。"
echo ""

# ── Verification ─────────────────────────────────────────────────
echo "=========================================="
echo "  部署验证"
echo "=========================================="
echo ""
echo "Console 状态:"
kubectl get pods -n "${K8S_NAMESPACE}" -l app.kubernetes.io/name=kyanos-console -o wide
echo ""
echo "Agent 状态:"
kubectl get pods -n "${K8S_NAMESPACE}" -l app.kubernetes.io/name=kyanos-agent -o wide
echo ""
echo "DaemonSet 状态:"
kubectl get ds -n "${K8S_NAMESPACE}"
echo ""
echo "Service 状态:"
kubectl get svc -n "${K8S_NAMESPACE}"
echo ""

echo "=========================================="
echo "  部署完成！"
echo "=========================================="
echo ""
echo "下一步:"
echo "  1. 查看 Agent 日志:"
echo "     kubectl logs -n ${K8S_NAMESPACE} -l app.kubernetes.io/name=kyanos-agent --tail=50"
echo ""
echo "  2. 访问 Console Web 面板:"
echo "     kubectl port-forward -n ${K8S_NAMESPACE} svc/kyanos-console 8080:8080"
echo "     然后打开浏览器访问 http://localhost:8080"
echo ""
echo "  3. 部署测试 NTRIP 流量:"
echo "     kubectl apply -f ${PROJECT_ROOT}/deploy/test-ntrip-pod.yaml"
echo ""
echo "  4. 卸载:"
echo "     helm uninstall kyanos-agent --namespace ${K8S_NAMESPACE}"
echo "     helm uninstall kyanos-console --namespace ${K8S_NAMESPACE}"
