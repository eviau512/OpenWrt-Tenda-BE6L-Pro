"""Compile isolated real kernel API observer and finite epoch tests; no DUT calls."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import time

HERE = Path(__file__).resolve().parent
BASE = HERE.parents[1]
SDK = Path('/root/be6l-openwrt/arm64-source')
KERNEL = SDK / 'build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55'
DRIVER = KERNEL / 'drivers/net/ethernet/airoha'
OUT = BASE / 'logs' / time.strftime('wired-kernel-diag-v1-%Y%m%d-%H%M%S')
WORK = Path('/root/be6l-openwrt') / OUT.name
OUT.mkdir()
WORK.mkdir()
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
protected_paths = [KERNEL / '.config', KERNEL / 'arch/arm64/boot/Image']
protected_paths += sorted(KERNEL.rglob('*.ko'))
protected_paths += sorted(DRIVER.glob('*.c')) + sorted(DRIVER.glob('*.h'))
protected = {str(p): sha(p) for p in protected_paths}
assert sha(DRIVER / 'airoha_ppe.c') == '39b585e3b1f2bc808e19ebdffd5dc53e34feac4558f76336b024b58aae676e35'
for path in DRIVER.glob('*.h'):
    shutil.copyfile(path, WORK / path.name)
for name in ('diag.c', 'diag.h', 'epoch.h', 'test-epoch.c'):
    shutil.copyfile(HERE / name, WORK / name)
(WORK / 'Makefile').write_text('obj-m += diag.o\n')
with (OUT / 'host-compile.txt').open('wb') as log:
    subprocess.run(['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=undefined', '-fno-sanitize-recover=all',
                    str(WORK / 'test-epoch.c'), '-o', str(WORK / 'test-epoch')],
                   stdout=log, stderr=subprocess.STDOUT, check=True)
result = json.loads(subprocess.check_output([str(WORK / 'test-epoch')], text=True))
gcc, = SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
env = dict(os.environ)
env.update(PATH='/root/be6l-openwrt/host/bin:' + env['PATH'],
           STAGING_DIR=str(SDK / 'staging_dir'), KCONFIG_NOSILENTUPDATE='1')
with (OUT / 'kernel-compile.txt').open('wb') as log:
    subprocess.run(['make', '-C', str(KERNEL), 'M=' + str(WORK), 'ARCH=arm64',
                    'CROSS_COMPILE=' + str(gcc)[:-3],
                    'SHELL=/root/be6l-openwrt/host/bin/bash', 'diag.o'], env=env,
                   stdout=log, stderr=subprocess.STDOUT, check=True)
assert {str(p): sha(p) for p in protected_paths} == protected
obj = (WORK / 'diag.o').read_bytes()
assert obj[:6] == b'\x7fELF\x02\x01' and obj[18:20] == b'\xb7\0'
symbols = subprocess.check_output([str(gcc.with_name(gcc.name[:-3] + 'nm')), '-u', str(WORK / 'diag.o')], text=True)
(OUT / 'undefined-symbols.txt').write_text(symbols)
for required in ('dev_get_by_index', 'register_netdevice_notifier',
                 'unregister_netdevice_notifier', 'skb_checksum', 'cancel_delayed_work_sync'):
    assert required in symbols, required
for forbidden in ('airoha_fe_wr', 'airoha_fe_set', 'airoha_fe_clear', 'foe_commit', 'foe_release'):
    assert forbidden not in symbols, forbidden
adapter = (HERE / 'diag.c').read_text()
assert 'dev_hold(d->refs[2]);' in adapter and 'dev_put(put[i]);' in adapter
result.update(kernel_api_object_compiled=True, full_driver_integration=False,
              real_kernel_refs_executed=False, hardware_access=False,
              sdk_driver_config_image_modules_unchanged=True,
              routed_gate_changed=False, bind_images_constructed=False,
              action_encoder_or_software_egress_complete=False,
              source_sha256={p.name: sha(p) for p in HERE.iterdir() if p.is_file()},
              kernel_header_sha256=sha(DRIVER / 'airoha_eth.h'),
              object_sha256=sha(WORK / 'diag.o'), isolated_work=str(WORK),
              protected_file_count=len(protected), ubsan=True)
(OUT / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
(BASE / 'logs/wired-kernel-diag-v1-latest.json').write_text(json.dumps({'directory': str(OUT)}) + '\n')
print(json.dumps({'directory': str(OUT), **result}, indent=2))
