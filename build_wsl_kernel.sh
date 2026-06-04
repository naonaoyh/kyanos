#!/bin/bash
# =============================================================================
# Build a custom WSL2 kernel with CONFIG_FPROBE=y for Kyanos eBPF tracing
# =============================================================================
#
# Current kernel: 6.18.26.1-microsoft-standard-WSL2
# Only CONFIG_FPROBE is missing — all other BPF/FTRACE prereqs are enabled.
#
# Strategy: clone Microsoft's WSL2 kernel source (matching version), enable
# CONFIG_FPROBE in the config, and rebuild. The resulting bzImage replaces
# the default WSL2 kernel.
#
# Run time: ~10-20 minutes on a modern machine
# =============================================================================

set -e
export PATH=/usr/local/go/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH

BUILD_DIR="$HOME/wsl-kernel-build"
NCPU=$(nproc)

echo "=============================================="
echo "  Custom WSL2 Kernel Build (CONFIG_FPROBE=y)"
echo "=============================================="
echo ""
echo "Current kernel: $(uname -r)"
echo "Build CPUs: $NCPU"
echo ""

# --- Step 1: Check build dependencies ---
echo "=== Step 1: Checking build dependencies ==="
MISSING=""
for dep in gcc make flex bison bc python3; do
    if ! which $dep > /dev/null 2>&1; then
        MISSING="$MISSING $dep"
    fi
done

if [ -n "$MISSING" ]; then
    echo "Installing missing deps:$MISSING"
    sudo apt-get update -qq 2>/dev/null || true
    sudo apt-get install -y -qq build-essential flex bison \
        libssl-dev libelf-dev bc python3 dwarves cpio pahole 2>/dev/null || {
        echo "ERROR: Cannot install deps. Please install manually:$MISSING"
        exit 1
    }
fi

# Check for critical headers
if [ ! -f /usr/include/openssl/opensslv.h ] 2>/dev/null; then
    echo "NOTE: libssl-dev may be missing (needed for kernel signing)"
fi
echo "Build deps OK."

# --- Step 2: Get kernel source ---
echo ""
echo "=== Step 2: Getting kernel source ==="
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Microsoft's WSL2-Linux-Kernel repo on GitHub
# Try to match the running kernel version tag
REPO_URL="https://github.com/microsoft/WSL2-Linux-Kernel.git"

if [ ! -d "WSL2-Linux-Kernel" ]; then
    echo "Cloning WSL2 kernel source (shallow, latest branch)..."
    # Try the rolling-lts branch which tracks newer kernels
    git clone --depth 1 "$REPO_URL" 2>&1 || {
        echo "ERROR: Cannot clone kernel source (network issue?)."
        echo "Alternative: download from https://github.com/microsoft/WSL2-Linux-Kernel/releases"
        exit 1
    }
else
    echo "Kernel source already exists at $BUILD_DIR/WSL2-Linux-Kernel"
    echo "To update: cd $BUILD_DIR/WSL2-Linux-Kernel && git pull"
fi

cd WSL2-Linux-Kernel
echo "Source version: $(head -5 Makefile | grep -E 'VERSION|PATCHLEVEL|SUBLEVEL' | tr '\n' ' ')"

# --- Step 3: Configure with CONFIG_FPROBE ---
echo ""
echo "=== Step 3: Configuring kernel ==="

# Use the existing Microsoft WSL2 config as base
if [ -f Microsoft/config-wsl ]; then
    cp Microsoft/config-wsl .config
    echo "Base config: Microsoft/config-wsl"
elif [ -f arch/x86/configs/config-wsl ]; then
    cp arch/x86/configs/config-wsl .config
    echo "Base config: arch/x86/configs/config-wsl"
else
    echo "No WSL config found. Extracting from running kernel..."
    zcat /proc/config.gz > .config
    echo "Base config: /proc/config.gz (running kernel)"
fi

# Enable CONFIG_FPROBE and its event interface
echo ""
echo "Enabling CONFIG_FPROBE..."
./scripts/config --enable CONFIG_FPROBE
./scripts/config --enable CONFIG_FPROBE_EVENTS

# Also ensure these are set (should already be, but be explicit)
./scripts/config --enable CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS
./scripts/config --enable CONFIG_BPF_EVENTS
./scripts/config --enable CONFIG_DEBUG_INFO_BTF

# Resolve dependencies
make olddefconfig 2>&1 | tail -3

# Verify the critical setting
echo ""
echo "CONFIG_FPROBE status after olddefconfig:"
grep CONFIG_FPROBE .config
echo ""
if grep -q "CONFIG_FPROBE=y" .config; then
    echo "✅ CONFIG_FPROBE=y confirmed!"
else
    echo "❌ CONFIG_FPROBE was not set! Checking dependencies..."
    grep -E "FPROBE|FTRACE|DYNAMIC_FTRACE_WITH_DIRECT" .config
    echo "You may need to enable CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS first."
    exit 1
fi

# --- Step 4: Build ---
echo ""
echo "=== Step 4: Building kernel (-j$NCPU) ==="
echo "This will take 10-20 minutes..."
echo ""

make -j$NCPU bzImage 2>&1 | tail -10

if [ ! -f arch/x86/boot/bzImage ]; then
    echo "ERROR: Build failed! Check the full output above."
    exit 1
fi

echo ""
echo "✅ Kernel built successfully!"
ls -la arch/x86/boot/bzImage

# --- Step 5: Install ---
echo ""
echo "=== Step 5: Installing kernel ==="

# Determine Windows username (for the .wslconfig path)
WIN_USER=$(cmd.exe /C "echo %USERNAME%" 2>/dev/null | tr -d '\r' || echo "")
if [ -z "$WIN_USER" ]; then
    # Fallback: check /mnt/c/Users for single user
    WIN_USER=$(ls /mnt/c/Users/ | grep -v -E 'Public|Default|All' | head -1)
fi

INSTALL_DIR="/mnt/c/Users/$WIN_USER/wsl-kernel"
mkdir -p "$INSTALL_DIR"
cp arch/x86/boot/bzImage "$INSTALL_DIR/bzImage"

echo "Kernel installed to: $INSTALL_DIR/bzImage"
echo ""

# Create .wslconfig if it doesn't exist
WSLCONFIG="/mnt/c/Users/$WIN_USER/.wslconfig"
if [ ! -f "$WSLCONFIG" ]; then
    cat > "$WSLCONFIG" << EOF
[wsl2]
kernel=C:\\\\Users\\\\$WIN_USER\\\\wsl-kernel\\\\bzImage
EOF
    echo "Created $WSLCONFIG"
else
    echo "NOTE: $WSLCONFIG already exists."
    echo "Please add/update the following line under [wsl2]:"
    echo "  kernel=C:\\\\Users\\\\$WIN_USER\\\\wsl-kernel\\\\bzImage"
fi

echo ""
echo "=============================================="
echo "  BUILD COMPLETE!"
echo "=============================================="
echo ""
echo "Next steps:"
echo "  1. From Windows PowerShell: wsl --shutdown"
echo "  2. Start WSL again: wsl"
echo "  3. Verify: uname -r"
echo "  4. Verify: zcat /proc/config.gz | grep CONFIG_FPROBE"
echo "     (should show CONFIG_FPROBE=y)"
echo "  5. Test Kyanos: sudo ./kyanos watch http --debug-output"
echo ""
echo "To revert to the default kernel:"
echo "  Remove or comment out the 'kernel=' line in $WSLCONFIG"
echo "  Then: wsl --shutdown && wsl"
