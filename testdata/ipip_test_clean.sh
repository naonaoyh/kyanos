#!/bin/bash
# Cleanup IPIP tunnel namespaces created by ipip_test.sh
# Requires root (auto-elevates if not root).

set -ex

# ── Root auto-elevation ─────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "[INFO] This script requires root privileges. Re-executing with sudo..."
    exec sudo -E env "PATH=$PATH" "$0" "$@"
fi

ip netns del host1
ip netns del host2
ip netns del internet