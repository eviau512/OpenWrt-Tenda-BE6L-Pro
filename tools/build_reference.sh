#!/usr/bin/env bash
# Reference two-SDK build. Never transport, boot, flash or alter host routing.
set -euo pipefail
base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work=/root/be6l-openwrt
export PATH="$work/host/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export CONFIG_SHELL="$work/host/bin/bash"
export FORCE_UNSAFE_CONFIGURE=1
jobs=${JOBS:-4}
python3 "$base/tools/prepare_sources.py" --check
mkdir -p "$base/logs/proxy-build-1213" "$base/logs/arm64-compat-build" \
    "$base/logs/p5-hybrid-kernel-apks" "$base/artifacts/arm64-compat"

python3 "$base/tools/configure_proxy_packages.py"
python3 "$base/tools/fix_passwall_compat_arch.py"
python3 "$base/tools/prepare_user_files.py"
cd "$work/source"
make SHELL="$CONFIG_SHELL" defconfig
grep -qx 'CONFIG_PACKAGE_wpad-mbedtls=y' .config
grep -qx 'CONFIG_TARGET_ROOTFS_INITRAMFS=y' .config
grep -qx '# CONFIG_TARGET_ROOTFS_SQUASHFS is not set' .config
make -j"$jobs" SHELL="$CONFIG_SHELL" V=s > "$base/logs/proxy-build-1213/build.log" 2>&1
echo 0 > "$base/logs/proxy-build-1213/build.exit"

# Bootstrap kernel/module payloads without requiring a pre-existing external
# CPIO. The native AArch64 userspace generated here must never be booted.
python3 - "$work/arm64-source/.config" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);lines=p.read_text().splitlines()
lines=[s for s in lines if not s.startswith('CONFIG_EXTERNAL_CPIO=')]
p.write_text('\n'.join(lines+['CONFIG_EXTERNAL_CPIO=""'])+'\n')
PY
cd "$work/arm64-source"
make SHELL="$CONFIG_SHELL" defconfig
grep -qx 'CONFIG_TARGET_ROOTFS_INITRAMFS=y' .config
grep -qx '# CONFIG_TARGET_ROOTFS_SQUASHFS is not set' .config
make -j"$jobs" SHELL="$CONFIG_SHELL" V=s > "$base/logs/arm64-compat-build/kernel.log" 2>&1
echo 0 > "$base/logs/arm64-compat-build/kernel.exit"

python3 "$base/tools/assemble_compat_rootfs.py"
bash "$base/tools/build_hybrid_kernel_apks.sh"
python3 "$base/tools/audit_hybrid_kernel_apks.py"
python3 "$base/tools/prepare_hybrid_apk_root.py"
python3 "$base/tools/prepare_hybrid_apk_root.py" --commit
python3 "$base/tools/assemble_hybrid_apk_cpio.py"
python3 - "$work/arm64-source/.config" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]);lines=p.read_text().splitlines()
lines=[s for s in lines if not s.startswith('CONFIG_EXTERNAL_CPIO=')]
p.write_text('\n'.join(lines+['CONFIG_EXTERNAL_CPIO="/root/be6l-openwrt/compat-rootfs/rootfs.cpio"'])+'\n')
PY
make SHELL="$CONFIG_SHELL" defconfig
make -j"$jobs" SHELL="$CONFIG_SHELL" V=s target/linux/install > "$base/logs/arm64-compat-build/image.log" 2>&1
python3 "$base/tools/validate_compat_image.py"
echo 'INITRAMFS_BUILT_AND_STATICALLY_VALIDATED; HARDWARE_ACCEPTANCE_STILL_REQUIRED'
