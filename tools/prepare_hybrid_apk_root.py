"""Resolve the mixed root's kernel ABI with normal APK transactions, offline."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import struct
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--commit', action='store_true')
parser.add_argument('--verify-only', action='store_true')
args = parser.parse_args()
base = Path(__file__).resolve().parents[1]
src = Path('/root/be6l-openwrt/arm64-source')
prior = Path('/root/be6l-openwrt/compat-rootfs/root')
parent = Path('/root/be6l-openwrt/compat-apk-root')
root = parent / 'root'
repo = Path('/root/be6l-openwrt/compat-kernel-repo')
logs = base / 'logs/p5-hybrid-kernel-apks'
audit_path = base / 'artifacts/arm64-compat/hybrid-kernel-apk-audit.json'
audit = json.loads(audit_path.read_text())
marker = {'owner': 'be6l-offline-hybrid-apk', 'audit_sha256': hashlib.sha256(audit_path.read_bytes()).hexdigest()}
parent.mkdir(exist_ok=True)
if not root.exists():
    (parent / '.owner.json').write_text(json.dumps(marker) + '\n')
    shutil.copytree(prior, root, symlinks=True)
assert json.loads((parent / '.owner.json').read_text()) == marker
assert root.resolve() == Path('/root/be6l-openwrt/compat-apk-root/root')
keys = root / 'etc/apk/keys'
keys.mkdir(exist_ok=True)
build_keys = src / 'build_dir/target-aarch64_cortex-a53_musl/root-airoha/etc/apk/keys'
for key in build_keys.iterdir():
    assert key.name in ('public-key.pem', 'openwrt-snapshots.pem')
    data = key.read_bytes()  # APK public verification keys only.
    assert data.startswith(b'-----BEGIN PUBLIC KEY-----') and b'PRIVATE' not in data
    target = keys / key.name
    if target.exists() and target.read_bytes() != data:
        target = keys / ('be6l-kernel-' + hashlib.sha256(data).hexdigest()[:20] + '.pem')
    if not target.exists():
        target.write_bytes(data)
apk = src / 'staging_dir/host/bin/apk'
common = [str(apk), '--root', str(root), '--arch', 'arm_cortex-a7', '--network=no',
          '--scripts=no', '--cache=no', '--repositories-file', '/dev/null']
packages = []
for item in audit['packages']:
    package = repo / item['file']
    assert hashlib.sha256(package.read_bytes()).hexdigest() == item['sha256']
    packages.append(str(package))
command = common + ['add']
if not args.commit:
    command.append('--simulate')
command += [audit['kernel_pin']] + packages
log = logs / ('offline-install.txt' if args.commit else 'offline-simulation.txt')
if log.exists() and not args.commit:
    previous = logs / 'offline-simulation-before-key-merge.txt'
    if not previous.exists():
        shutil.copyfile(log, previous)
if not args.verify_only:
    with log.open('w') as output:
        subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, check=True)
if not args.commit and not args.verify_only:
    print('OFFLINE_TRANSACTION_SIMULATION_PASSED', root)
    raise SystemExit(0)
# Local APK file arguments create checksum constraints in WORLD. Replace
# those through the normal solver with package names plus an exact kernel ABI.
if args.commit:
    with (logs / 'offline-world-pin.txt').open('w') as output:
        subprocess.run(common + ['add', audit['kernel_pin']] +
            [item['info']['name'] for item in audit['packages'] if item['info']['name'] != 'kernel'],
            stdout=output, stderr=subprocess.STDOUT, check=True)
assert 'OK:' in (logs / 'offline-install.txt').read_text()
assert 'OK:' in (logs / 'offline-world-pin.txt').read_text()
world = (root / 'etc/apk/world').read_text().splitlines()
assert audit['kernel_pin'] in world
for file, digest in audit['verified_module_files'].items():
    assert hashlib.sha256((root / file).read_bytes()).hexdigest() == digest
elf32, modules = 0, 0
for directory in ('bin', 'sbin', 'usr/bin', 'usr/sbin', 'usr/lib', 'usr/libexec', 'lib'):
    for file in (root / directory).rglob('*'):
        if not file.is_file() or file.is_symlink():
            continue
        relative = file.relative_to(root)
        if str(relative).startswith('lib/firmware/'):
            continue
        with file.open('rb') as stream:
            header = stream.read(20)
        if header[:4] != b'\x7fELF':
            continue
        machine = struct.unpack_from('<H', header, 18)[0]
        if file.suffix == '.ko':
            assert header[4] == 2 and machine == 183, str(relative)
            modules += 1
        else:
            assert header[4] == 1 and machine == 40, str(relative)
            elf32 += 1
assert modules == len(audit['verified_module_files']) and elf32 >= 100
query = subprocess.check_output([arg for arg in common if arg != '--scripts=no'] + ['query', '--installed', '--format', 'json',
    '--fields', 'name,version,arch,depends', 'kernel', 'kmod-*'], text=True)
(logs / 'installed-kernel-packages.json').write_text(query)
report = {'root': str(root), 'audit_sha256': marker['audit_sha256'],
          'kernel_pin': audit['kernel_pin'], 'elf32_userspace': elf32,
          'unchanged_elf64_modules': modules, 'normal_apk_solver_and_signatures': True,
          'userspace_arch': 'arm_cortex-a7', 'kernel_module_arch': 'aarch64',
          'offline_transaction_passed': True, 'runtime_qualified': False,
          'kernel_upgrade_requires_matching_ramboot': True}
(base / 'artifacts/arm64-compat/hybrid-apk-root.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
