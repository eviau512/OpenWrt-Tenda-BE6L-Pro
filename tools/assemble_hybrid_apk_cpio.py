"""Build native external CPIO from the independently audited APK-managed root."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess

base = Path(__file__).resolve().parents[1]
src32 = Path('/root/be6l-openwrt/source')
src64 = Path('/root/be6l-openwrt/arm64-source')
work = Path('/root/be6l-openwrt/compat-rootfs')
root_report = json.loads((base / 'artifacts/arm64-compat/hybrid-apk-root.json').read_text())
assert root_report['offline_transaction_passed'] and root_report['normal_apk_solver_and_signatures']
root = Path(root_report['root'])
assert root.resolve() == Path('/root/be6l-openwrt/compat-apk-root/root')
audit = json.loads((base / 'artifacts/arm64-compat/hybrid-kernel-apk-audit.json').read_text())
for file, sha in audit['verified_module_files'].items():
    assert hashlib.sha256((root / file).read_bytes()).hexdigest() == sha
assert root_report['kernel_pin'] in (root / 'etc/apk/world').read_text().splitlines()
assert not list((root / 'usr/bin').glob('portal_autologin*'))
assert (root / 'etc/uci-defaults/zz-be6l-proxy-packages').is_file()
assert hashlib.sha256((root / 'lib/firmware/airoha/an7552.bin').read_bytes()).hexdigest() == '934d85a5949ec622cdf853b8442aeb3c5cdd92a81866a843963f4fbf26a3a867'
logs = base / 'logs/arm64-compat-build'
report = json.loads((logs / 'rootfs-validation.json').read_text())
for key in ('external_cpio_sha256', 'external_cpio_bytes', 'image', 'image_sha256',
            'runtime_evidence', 'qualification', 'runtime_failure'):
    report.pop(key, None)
report.update({'ramboot_validated': False,
    'elf32_userspace_verified': root_report['elf32_userspace'],
    'elf64_modules_verified': audit['verified_module_files'],
    'module_payloads': sorted(item['info']['name'] for item in audit['packages']),
    'kernel_apk_pin': root_report['kernel_pin'],
    'package_metadata_qualification': 'APK-managed mixed root: signed kernel/kmod packages resolved normally, exact AArch64 kernel ABI pinned; kernel changes require matching RAM boot.',
    'hybrid_apk_offline_validation': root_report,
    'config32_sha256': hashlib.sha256((src32 / '.config').read_bytes()).hexdigest(),
    'config64_sha256': hashlib.sha256((src64 / '.config').read_bytes()).hexdigest()})
(root / 'etc/be6l-compat-build.json').write_text(json.dumps({k: v for k, v in report.items()
    if k != 'elf64_modules_verified'}, indent=2) + '\n')
epoch = int(subprocess.check_output(['git', 'show', '-s', '--format=%ct', 'HEAD'], cwd=src32, text=True))
paths = ['.'] + sorted(str(p.relative_to(root)) for p in root.rglob('*'))
for name in paths:
    os.utime(root / name, (epoch, epoch), follow_symlinks=False)
cpio = work / 'rootfs.cpio'
with cpio.open('wb') as output:
    subprocess.run([str(src32 / 'staging_dir/host/bin/cpio'), '--null', '--reproducible',
                    '-o', '-H', 'newc', '-R', '0:0'], cwd=root,
                   input=('\0'.join(paths) + '\0').encode(), stdout=output, check=True)
kernel = src64 / 'build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55'
device_list = work / 'device-nodes.list'
device_list.write_text('nod /dev/console 0600 0 0 c 5 1\nnod /dev/null 0666 0 0 c 1 3\n')
with cpio.open('ab') as output:
    subprocess.run([str(kernel / 'usr/gen_init_cpio'), '-t', str(epoch), str(device_list)], stdout=output, check=True)
report['external_cpio_sha256'] = hashlib.sha256(cpio.read_bytes()).hexdigest()
report['external_cpio_bytes'] = cpio.stat().st_size
(logs / 'rootfs-validation.json').write_text(json.dumps(report, indent=2) + '\n')
print('APK_MANAGED_MIXED_CPIO_VALIDATED', report['external_cpio_bytes'])
