"""Admit only verified kernel/kmod APKs, never the dependency userspace outputs."""
from pathlib import Path
import hashlib
import json
import shutil
import struct
import subprocess
import tempfile

base = Path(__file__).resolve().parents[1]
src = Path('/root/be6l-openwrt/arm64-source')
apk = src / 'staging_dir/host/bin/apk'
raw = Path('/root/be6l-openwrt/compat-kernel-apks')
repo = Path('/root/be6l-openwrt/compat-kernel-repo')
scratch = Path('/root/be6l-openwrt/compat-kernel-audit')
prior = Path('/root/be6l-openwrt/compat-rootfs/root')
keys = src / 'build_dir/target-aarch64_cortex-a53_musl/root-airoha/etc/apk/keys'
assert keys.is_dir() and (raw / '.be6l-hybrid-apks').exists()
repo.mkdir(exist_ok=True)
scratch.mkdir(exist_ok=True)
assert repo.resolve().parent == Path('/root/be6l-openwrt')
metadata = []
all_modules = {}
for package in sorted(raw.glob('*.apk')):
    # This positive allowlist excludes all AArch64 userspace dependencies
    # automatically repackaged by the outer OpenWrt dependency graph.
    if not (package.name.startswith('kernel-') or package.name.startswith('kmod-')):
        continue
    data = json.loads(subprocess.check_output([str(apk), 'adbdump', '--format', 'json', str(package)], text=True))
    info = data['info']
    assert info['name'] == 'kernel' or info['name'].startswith('kmod-')
    assert info['arch'] == 'arm_cortex-a7', info
    subprocess.run([str(apk), '--keys-dir', str(keys), 'verify', str(package)],
                   check=True, stdout=subprocess.DEVNULL)
    count = 0
    with tempfile.TemporaryDirectory(prefix='apk-', dir=scratch) as directory:
        unpacked = Path(directory)
        assert unpacked.resolve().parent == scratch.resolve()
        subprocess.run([str(apk), '--keys-dir', str(keys), 'extract', '--no-chown',
                        '--destination', str(unpacked), str(package)], check=True,
                       stdout=subprocess.DEVNULL)
        for file in unpacked.rglob('*'):
            if not file.is_file() or file.is_symlink():
                continue
            relative = file.relative_to(unpacked)
            header = file.read_bytes()[:20]
            if header[:4] != b'\x7fELF':
                continue
            if file.suffix == '.ko':
                assert header[4] == 2 and struct.unpack_from('<H', header, 18)[0] == 183, str(relative)
                digest = hashlib.sha256(file.read_bytes()).hexdigest()
                old = prior / relative
                assert old.is_file(), 'Unexpected added module: ' + str(relative)
                assert hashlib.sha256(old.read_bytes()).hexdigest() == digest, 'Changed module binary: ' + str(relative)
                assert str(relative) not in all_modules
                all_modules[str(relative)] = digest
                count += 1
            else:
                # Firmware for a different processor is allowed only when
                # byte-identical to the previously qualified root filesystem.
                assert str(relative).startswith('lib/firmware/')
                assert (prior / relative).is_file()
                assert file.read_bytes() == (prior / relative).read_bytes()
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    existing = repo / package.name
    if existing.exists():
        assert hashlib.sha256(existing.read_bytes()).hexdigest() == digest
    else:
        shutil.copyfile(package, existing)
    metadata.append({'file': package.name, 'sha256': digest, 'info': info, 'elf64_module_count': count})
kernel, = [item for item in metadata if item['info']['name'] == 'kernel']
expected = 'kernel=' + kernel['info']['version']
for item in metadata:
    if item['info']['name'].startswith('kmod-'):
        assert expected in item['info']['depends'], item['info']
old_modules = {str(p.relative_to(prior)) for p in (prior / 'lib/modules').rglob('*.ko')}
assert set(all_modules) == old_modules, {'missing': sorted(old_modules - set(all_modules)), 'extra': sorted(set(all_modules) - old_modules)}
report = {'scope': 'offline_kernel_module_package_metadata_only', 'kernel_pin': expected,
          'userspace_package_arch': 'arm_cortex-a7', 'module_elf_machine': 'aarch64',
          'packages': metadata, 'verified_module_files': all_modules,
          'module_bytes_unchanged': True, 'userspace_dependencies_excluded': True,
          'installed_into_router': False}
(base / 'artifacts/arm64-compat/hybrid-kernel-apk-audit.json').write_text(json.dumps(report, indent=2) + '\n')
print('AUDITED_KERNEL_PACKAGES', len(metadata), 'UNCHANGED_ARM64_MODULES', len(all_modules), expected)
