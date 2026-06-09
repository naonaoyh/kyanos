#!/usr/bin/env bash
# build-and-push.sh — 构建并推送 Kyanos Agent 和 Console 镜像到腾讯云 CCR
#
# 用法:
#   ./deploy/scripts/build-and-push.sh [OPTIONS]
#
# 示例:
#   ./deploy/scripts/build-and-push.sh --registry ccr.ccs.tencentyun.com --namespace kyanos --tag v0.1.0
#   ./deploy/scripts/build-and-push.sh --agent-only --tag v0.1.0-hotfix
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Defaults
REGISTRY="ccr.ccs.tencentyun.com"
NAMESPACE="kyanos"
TAG="latest"
AGENT_ONLY=false
CONSOLE_ONLY=false
PUSH=true
PLATFORM="linux/amd64"

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Build and push Kyanos images to Tencent Cloud Container Registry (CCR).

Options:
  --registry REGISTRY   Container registry (default: ccr.ccs.tencentyun.com)
  --namespace NS        Registry namespace (default: kyanos)
  --tag TAG             Image tag (default: latest)
  --agent-only          Build only the agent image
  --console-only        Build only the console image
  --no-push             Build only, do not push
  --platform PLATFORM   Target platform (default: linux/amd64)
  -h, --help            Show this help

Examples:
  $(basename "$0") --namespace myteam --tag v0.1.0
  $(basename "$0") --agent-only --tag v0.1.0-hotfix
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --registry)   REGISTRY="$2"; shift 2 ;;
        --namespace)  NAMESPACE="$2"; shift 2 ;;
        --tag)        TAG="$2"; shift 2 ;;
        --agent-only) AGENT_ONLY=true; shift ;;
        --console-only) CONSOLE_ONLY=true; shift ;;
        --no-push)    PUSH=false; shift ;;
        --platform)   PLATFORM="$2"; shift 2 ;;
        -h|--help)    usage ;;
        *)            echo "Unknown option: $1"; usage ;;
    esac
done

# Auto-detect version info
VERSION="${TAG}"
COMMIT_ID="$(cd "$PROJECT_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

AGENT_IMAGE="${REGISTRY}/${NAMESPACE}/kyanos-agent:${TAG}"
CONSOLE_IMAGE="${REGISTRY}/${NAMESPACE}/kyanos-console:${TAG}"

echo "=========================================="
echo "  Kyanos Image Builder"
echo "=========================================="
echo "  Registry:   ${REGISTRY}"
echo "  Namespace:  ${NAMESPACE}"
echo "  Tag:        ${TAG}"
echo "  Commit:     ${COMMIT_ID}"
echo "  Build time: ${BUILD_TIME}"
echo "  Platform:   ${PLATFORM}"
echo "=========================================="

build_agent() {
    echo ""
    echo "[1/2] Building Kyanos Agent image..."
    echo "  Image: ${AGENT_IMAGE}"
    
    docker build \
        --platform "${PLATFORM}" \
        -f "${PROJECT_ROOT}/deploy/Dockerfile" \
        --build-arg VERSION="${VERSION}" \
        --build-arg COMMIT_ID="${COMMIT_ID}" \
        --build-arg BUILD_TIME="${BUILD_TIME}" \
        -t "${AGENT_IMAGE}" \
        "${PROJECT_ROOT}"
    
    echo "  Agent image built successfully."
    
    if [ "$PUSH" = true ]; then
        echo "  Pushing ${AGENT_IMAGE}..."
        docker push "${AGENT_IMAGE}"
        echo "  Agent image pushed."
    fi
}

build_console() {
    echo ""
    echo "[2/2] Building Kyanos Console image..."
    echo "  Image: ${CONSOLE_IMAGE}"
    
    docker build \
        --platform "${PLATFORM}" \
        -f "${PROJECT_ROOT}/console/Dockerfile" \
        --build-arg VERSION="${VERSION}" \
        --build-arg COMMIT_ID="${COMMIT_ID}" \
        --build-arg BUILD_TIME="${BUILD_TIME}" \
        -t "${CONSOLE_IMAGE}" \
        "${PROJECT_ROOT}"
    
    echo "  Console image built successfully."
    
    if [ "$PUSH" = true ]; then
        echo "  Pushing ${CONSOLE_IMAGE}..."
        docker push "${CONSOLE_IMAGE}"
        echo "  Console image pushed."
    fi
}

# Execute builds
if [ "$AGENT_ONLY" = true ]; then
    build_agent
elif [ "$CONSOLE_ONLY" = true ]; then
    build_console
else
    build_agent
    build_console
fi

echo ""
echo "=========================================="
echo "  Build complete!"
if [ "$PUSH" = true ]; then
    echo "  Images pushed to ${REGISTRY}/${NAMESPACE}/"
else
    echo "  Images built locally (push skipped)."
fi
echo "=========================================="
