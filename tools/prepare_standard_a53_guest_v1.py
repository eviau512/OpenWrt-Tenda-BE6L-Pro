# SPDX-License-Identifier: MIT
"""Install a small signed, unmodified standard A53 package fixture offline.

This is an isolated guest runtime for later binfmt tests, not a compatibility
claim. Target package scripts are disabled; no host or router root is changed.
"""
from pathlib import Path
import argparse
import json
import shutil
import struct
import subprocess
from package_native_netifd_v3 import records, root_digest, sha
from plan_integer_binfmt_v1 import matches

NAMES = ('libc', 'libgcc1', 'libstdcpp6', 'busybox', 'ucode',
         'libucode20261009', 'libjson-c5', 'btop')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('cached-packages', 'keys', 'apk', 'work'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not w.name.startswith('be6l-standard-a53-guest-') or w.exists():
        p.error('Use a fresh /root/be6l-standard-a53-guest-* directory')
    w.mkdir(mode=0o700)
    trust = w/'trust'
    shutil.copytree(a.keys, trust)
    if any(b'PRIVATE' in path.read_bytes() for path in trust.iterdir() if path.is_file()):
        raise ValueError('Only public verification keys may be copied')

    def run(label, command):
        r = subprocess.run(list(map(str, command)), capture_output=True, timeout=180)
        (w/(label+'.log')).write_bytes(r.stdout+r.stderr)
        if r.returncode:
            raise RuntimeError(label+' failed; retained log is authoritative')
        return r.stdout

    candidates = list(a.cached_packages.rglob('*.apk'))
    packages, expected, metadata = [], {}, []
    for name in NAMES:
        found = [path for path in candidates if path.name.startswith(name+'-')
                 and path.name[len(name)+1:len(name)+2].isdigit()]
        if len(found) != 1:
            raise ValueError('Expected one cached package for '+name)
        package = found[0]
        info = json.loads(run('metadata-'+name, [a.apk, 'adbdump', '--format', 'json', package]))['info']
        if info['name'] != name or info['arch'] != 'aarch64_cortex-a53':
            raise ValueError('Not a standard A53 package: '+name)
        run('verify-'+name, [a.apk, '--network=no', '--keys-dir', trust, 'verify', package])
        unpacked = w/'extracted'/name
        unpacked.mkdir(parents=True)
        run('extract-'+name, [a.apk, '--network=no', '--keys-dir', trust,
            'extract', '--no-chown', '--destination', unpacked, package])
        for relative, record in records(unpacked).items():
            if relative in expected and expected[relative] != record:
                raise ValueError('Conflicting package payload: '+relative)
            expected[relative] = record
        packages.append(package)
        metadata.append(dict(info=info, file=package.name, sha256=sha(package)))
    root = w/'root'
    root.mkdir()
    common = [a.apk, '--root', root, '--arch', 'aarch64_cortex-a53', '--keys-dir', trust,
              '--network=no', '--cache=no', '--logfile=no',
              '--repositories-file', '/dev/null']
    run('initialize-database', common+['--scripts=no', 'add', '--initdb'])
    run('simulate', common+['--scripts=no', 'add', '--simulate']+packages)
    run('install', common+['--scripts=no', 'add']+packages)
    installed = json.loads(run('installed', common+['query', '--installed', '--format', 'json',
        '--fields', 'name,version,arch,depends', '*']))
    if {item['name']: item['version'] for item in installed} != {
            item['info']['name']: item['info']['version'] for item in metadata}:
        raise ValueError('Installed package inventory mismatch')
    actual = records(root)
    for relative, record in expected.items():
        if actual.get(relative) != record:
            raise ValueError('Standard package payload changed: '+relative)
    elf = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open('rb') as incoming:
            header = incoming.read(64)
        if len(header) < 64 or header[:4] != b'\x7fELF':
            continue
        if not matches(header) or struct.unpack_from('<I', header, 48)[0] != 0:
            raise ValueError('Unexpected standard guest ELF: '+str(path))
        elf[path.relative_to(root).as_posix()] = sha(path)
    if not elf or not (root/'lib/ld-musl-aarch64.so.1').exists():
        raise ValueError('Incomplete standard guest dynamic runtime')
    report = dict(normal_signed_standard_package_transaction=True,
        architecture='aarch64_cortex-a53', packages=metadata, installed_packages=len(installed),
        package_payload_paths_verified=len(expected), standard_elf_sha256=elf,
        root_records_sha256=root_digest(root), standard_payloads_unmodified=True,
        target_package_scripts_executed=False, target_executed=False,
        binfmt_registered=False, standard_a53_package_compatibility_qualified=False)
    (w/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print('SIGNED_STANDARD_A53_GUEST_PREPARED', len(installed), len(elf), flush=True)


if __name__ == '__main__':
    main()
