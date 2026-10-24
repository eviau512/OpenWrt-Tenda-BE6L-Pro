#!/usr/bin/env bash
# Package only the already-built AArch64 kernel/modules for the ARM32 root ABI.
# Dependency recipes may also emit packages; only kernel/kmod outputs may be
# admitted to the hybrid repository after an independent ELF/ABI audit.
set -euo pipefail
base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
logs="$base/logs/p5-hybrid-kernel-apks"
out=/root/be6l-openwrt/compat-kernel-apks
export PATH=/root/be6l-openwrt/host/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export FORCE_UNSAFE_CONFIGURE=1
export CONFIG_SHELL=/root/be6l-openwrt/host/bin/bash
mkdir -p "$logs" "$out"
if test ! -e "$out/.be6l-hybrid-apks"; then
    test -z "$(find "$out" -mindepth 1 -maxdepth 1 -print -quit)"
    touch "$out/.be6l-hybrid-apks"
fi
cd /root/be6l-openwrt/arm64-source
trap 'rc=$?; echo "$rc" > "$logs/build.exit"' EXIT
make -j4 SHELL="$CONFIG_SHELL" ARCH_PACKAGES=arm_cortex-a7 \
    CONFIG_PER_FEED_REPO= PACKAGE_DIR="$out" PACKAGE_DIR_ALL="$out" \
    package/kernel/linux/compile package/kernel/mac80211/compile \
    package/kernel/mt76/compile package/kernel/gpio-button-hotplug/compile \
    > "$logs/build.log" 2>&1
echo HYBRID_KERNEL_PACKAGE_RECIPES_FINISHED
