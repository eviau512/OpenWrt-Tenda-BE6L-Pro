# SPDX-License-Identifier: MIT
"""Admit only the normal ARM32 handoff image; no target or flash operation."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess
import sys

BASE=Path(__file__).resolve().parents[1]
SDK=Path('/root/be6l-openwrt/source')
KERNEL=SDK/'build_dir/target-arm_cortex-a7_musl_eabi/linux-airoha_an7563/linux-6.18.55'
ROOT=SDK/'build_dir/target-arm_cortex-a7_musl_eabi/root-airoha'
ART=BASE/'artifacts/arm32-wdt-handoff-v1'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work',type=Path,required=True)
    args=parser.parse_args()
    result=json.loads((args.work/'build-result.json').read_text())
    assert result['build_completed'] and result['owned_build_finished']
    assert str(args.work.resolve())==result['work']
    assert sha(KERNEL/'drivers/watchdog/airoha_wdt.c')=='e98c5a4f09bfffc596d2e3914e69da9c0511137ba15f11b65f56c3c1cb3fefce'
    config=(KERNEL/'.config').read_text().splitlines()
    for line in ('CONFIG_KEXEC=y','CONFIG_AIROHA_WATCHDOG=y','# CONFIG_WATCHDOG_NOWAYOUT is not set'):
        assert line in config,line
    package_manifest=ART/'openwrt-airoha-an7563-tenda_be6l-pro.manifest'
    packages=dict(line.split(' - ',1) for line in package_manifest.read_text().splitlines())
    required=('luci','luci-theme-argon','luci-i18n-base-zh-cn','curl','lua','luci-lib-nixio','btop','wpad-mbedtls',
              'tailscale','sing-box','luci-app-passwall')
    assert all(name in packages for name in required)
    assert 'luci-app-argon-config' not in packages and 'xray-core' not in packages
    for name in ('portal_autologin.sh','portal_autologin_BE6L.sh'):
        assert not (ROOT/'usr/bin'/name).exists()
    for name in ('etc/config/wireless','etc/crontabs/root'):
        p=ROOT/name
        if p.exists():
            data=p.read_text()
            assert not re.search(r'(?m)^\s*option\s+(?:key|sae_password|wpa_passphrase)\s',data), 'Stored wireless key found; no values printed'
            assert 'portal_autologin' not in data, 'Retired portal cron entry'
    default=ROOT/'etc/uci-defaults/98-be6l-proxy-packages'
    assert default.is_file() and 'disable' in default.read_text() and 'tailscale sing-box passwall' in default.read_text()
    assert (ROOT/'usr/lib/lua/nixio.so').is_file()
    cross,=SDK.glob('staging_dir/toolchain-arm_cortex-a7_*/bin/arm-openwrt-linux-muslgnueabi-gcc')
    subprocess.run([sys.executable,str(BASE/'tools/audit_module_layout.py'),'--kernel',str(KERNEL),
                    '--root',str(ROOT),'--arch','arm','--cross-compile',str(cross)[:-3],
                    '--output',str(args.work/'module-layout-admission.json')],check=True)
    image=ART/'openwrt-airoha-an7563-tenda_be6l-pro-initramfs-kernel.bin'
    assert sha(image)==result['image_sha256']
    subprocess.run([sys.executable,str(BASE/'tools/prepare_ramboot.py'),str(image),
                    '--output-dir',str(ART/'ramboot'),'--require-watchdog-handoff'],check=True)
    payload=json.loads((ART/'ramboot/manifest.json').read_text())
    admission=dict(schema=1,image_sha256=sha(image),image_bytes=image.stat().st_size,
        watchdog_source_sha256=sha(KERNEL/'drivers/watchdog/airoha_wdt.c'),
        kernel_config_sha256=sha(KERNEL/'.config'),normal_openwrt_build=True,
        normal_package_manifest=True,required_packages={x:packages[x] for x in required},
        compiled_watchdog_handoff_markers=True,matching_arm32_modules=True,
        kernel_bytes=payload['kernel_bytes'],kernel_end=hex(0x80088000+payload['kernel_bytes']),
        kernel_reserved_boundary='0x84000000',kernel_headroom_bytes=0x84000000-0x80088000-payload['kernel_bytes'],
        flash_guards_verified=True,stored_credentials_included=False,
        target_executed=False,watchdog_handoff_runtime_qualified=False)
    (ART/'build-validation.json').write_text(json.dumps(admission,indent=2)+'\n')
    print(json.dumps(admission,indent=2))


if __name__=='__main__':main()
