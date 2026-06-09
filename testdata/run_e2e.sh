#!/usr/bin/env bash
# E2E test orchestrator for Kyanos.
# Requires root (auto-elevates if not root).

# ── Root auto-elevation ─────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "[INFO] This script requires root privileges (kyanos uses eBPF). Re-executing with sudo..."
    exec sudo -E env "PATH=$PATH" "$0" "$@"
fi



DOCKER_REGISTRY=$1

has_files() {  
    local path="$1"  
  
    # 检查路径是否存在  
    if [ ! -d "$path" ]; then  
        echo "Error: The path '$path' does not exist."  
        return 1  
    fi  
  
    # 使用 find 命令查找路径下的文件（不包括目录）  
    files=$(find "$path" -maxdepth 1 -type f)  
  
    # 检查是否找到文件  
    if [ -z "$files" ]; then  
        echo "No files found in the path '$path'."  
        return 1  
    else  
        echo "Files found in the path '$path':"  
        echo "$files"  
        return 0  
    fi  
}  


function main() {
  rm -rf /tmp/kyanos_* || true
  # kubectl delete pod test-ptcpdump | true
  CMD="./kyanos"
  has_files "/var/lib/kyanos/btf"
  if [ -f "/var/lib/kyanos/btf/current.btf" ]; then  
    CMD="./kyanos --btf /var/lib/kyanos/btf/current.btf "
  fi
  set -ex
  # bash testdata/test_base.sh "$CMD"
  # bash testdata/test_filter_by_l4.sh "$CMD"
  # bash testdata/test_kern_evt.sh "$CMD"
  # bash testdata/test_docker_filter_by_container_id.sh "$CMD" "$DOCKER_REGISTRY"
  # bash testdata/test_docker_filter_by_container_name.sh "$CMD" "$DOCKER_REGISTRY"
  # bash testdata/test_docker_filter_by_pid.sh "$CMD"
  # bash testdata/test_containerd_filter_by_container_id.sh "$CMD" "$DOCKER_REGISTRY"
  # bash testdata/test_containerd_filter_by_container_name.sh "$CMD" "$DOCKER_REGISTRY"
  # bash testdata/test_redis.sh "$CMD" "$DOCKER_REGISTRY"
  # bash testdata/test_mysql.sh "$CMD" "$DOCKER_REGISTRY"
  bash testdata/test_rocketmq.sh "$CMD" "$DOCKER_REGISTRY"
  # bash testdata/test_https.sh "$CMD"
  # bash testdata/test_side.sh "$CMD" "$DOCKER_REGISTRY"
  # bash testdata/test_gotls.sh "$CMD"
  echo "success!"
}

main
