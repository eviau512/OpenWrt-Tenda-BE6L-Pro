# SPDX-License-Identifier: MIT
"""Compose signed RAM-only SSH identity/recovery packages in a new root.

Each work directory contains a fresh private client key and an image-specific
server key. Keep the work and all derived binaries private. Only public key
fingerprints and hashes belong in published evidence. No device is contacted.
"""
from pathlib import Path, PurePosixPath
import argparse
import json
import os
import shutil
import subprocess
from package_native_netifd_v3 import records, root_digest, sha, copy_path
from prepare_ramboot import tree, image, text
from verify_embedded_compat_cpio import verify
import lzma

BASE = Path(__file__).resolve().parents[1]
ARM32_FIT = '4f1d61e6ddfa92181655156f2d1bc91bc32b956b69d519e5e345b7a9af195cd1'
ARM32_CPIO = 'df66e812543ef9bb1ec62354098aaf621f29e042ae898ed12d3892b434d4941d'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    origin = p.add_mutually_exclusive_group(required=True)
    origin.add_argument('--arm32-fit', type=Path)
    origin.add_argument('--composition', type=Path)
    p.add_argument('--arm32-kernel', type=Path)
    for name in ('apk', 'cpio-tool', 'host-keygen', 'host-keygen-libs', 'work'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    work = a.work.resolve()
    if work.parent != Path('/root') or not work.name.startswith('be6l-unattended-root-'):
        p.error('Use a fresh /root/be6l-unattended-root-* directory')
    inherited = None
    if a.composition:
        inherited = json.loads((a.composition / 'result.json').read_text())
        if root_digest(a.composition / 'root') != inherited['installed_root_records_sha256']:
            raise ValueError('Input sealed root changed')
    else:
        if sha(a.arm32_fit) != ARM32_FIT or a.arm32_kernel is None:
            raise ValueError('Wrong qualified ARM32 intermediate')
        n = tree(a.arm32_fit.read_bytes())
        c = n['/configurations/' + text(n['/configurations']['default'])]
        packed, _ = image(n, text(c['kernel']))
        data = lzma.decompress(packed, format=lzma.FORMAT_ALONE)
        archive = a.arm32_kernel / 'usr/initramfs_data.cpio'
        if sha(archive) != ARM32_CPIO:
            raise ValueError('Wrong intermediate root archive')
        verify(a.arm32_kernel, data, archive)
    work.mkdir(mode=0o700)

    def run(label, command, env=None):
        result = subprocess.run(list(map(str, command)), capture_output=True, timeout=180, env=env)
        (work / (label + '.log')).write_bytes(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(label + ' failed; inspect retained private log')
        return result.stdout

    original = work / 'baseline-root'
    if inherited:
        shutil.copytree(a.composition / 'root', original, symlinks=True)
    else:
        original.mkdir()
        listing = run('archive-list', [a.cpio_tool, '-it', '--quiet', '-F', archive]).decode().splitlines()
        for name in listing:
            if '..' in PurePosixPath(name).parts:
                raise ValueError('Archive traversal')
        # Device nodes remain supplied by the unchanged embedded archive.
        command = [str(a.cpio_tool), '-idm', '--quiet', '--no-preserve-owner', '--no-absolute-filenames',
                   '-F', str(archive), '-f', 'dev/*']
        result = subprocess.run(command, cwd=original, capture_output=True)
        (work / 'archive-extract.log').write_bytes(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError('Trusted baseline archive extraction failed')
    before = records(original)
    baseline_digest = root_digest(original)
    for name in ('etc/dropbear/authorized_keys', 'etc/dropbear/dropbear_ed25519_host_key'):
        if (original / name).exists():
            raise ValueError('Do not overwrite an existing SSH identity')
    ro = [a.apk, '--root', original, '--network=no', '--cache=no', '--logfile=no', '--repositories-file', '/dev/null']
    query = ['query', '--installed', '--format', 'json', '--fields', 'name,version,arch', '*']
    packages = json.loads(run('baseline-packages', ro + query))
    package_names = {i['name'] for i in packages}
    if 'be6l-ram-access' in package_names:
        raise ValueError('Access package already present')
    access = work / 'access-files'
    target_key = access / 'etc/dropbear/dropbear_ed25519_host_key'
    target_key.parent.mkdir(parents=True)
    env = dict(os.environ, LD_LIBRARY_PATH=str(a.host_keygen_libs))
    run('server-key-generate', [a.host_keygen, '-t', 'ed25519', '-f', target_key], env=env)
    public_lines = run('server-public', [a.host_keygen, '-y', '-f', target_key], env=env).decode().splitlines()
    host_public, = [line for line in public_lines if line.startswith('ssh-ed25519 ')]
    target_key.chmod(0o600)
    client = work / 'client-ed25519'
    run('client-key-generate', ['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'be6l-private-ram-test', '-f', client])
    copy_path(work / 'client-ed25519.pub', access / 'etc/dropbear/authorized_keys')
    (access / 'etc/dropbear/authorized_keys').chmod(0o600)
    (work / 'known-hosts').write_text('192.168.0.1,192.168.1.1,192.168.15.1 ' + host_public + '\n')
    stages = [('be6l-ram-access', access, ['dropbear'], '1.0.0-r1')]
    installed_guard = next((i['version'] for i in packages if i['name'] == 'be6l-recovery-guard'), None)
    if installed_guard != '1.0.0-r2':
        guard = work / 'guard-files'
        for src, dst, mode in (
            ('be6l-recovery.config', 'etc/config/be6l-recovery', 0o600),
            ('be6l-recovery.init', 'etc/init.d/be6l-recovery', 0o755),
            ('be6l-recovery-guard', 'usr/sbin/be6l-recovery-guard', 0o755),
            ('state.sh', 'usr/lib/be6l-recovery-guard/state.sh', 0o644)):
            copy_path(BASE / 'packages/be6l-recovery-guard/files' / src, guard / dst)
            (guard / dst).chmod(mode)
        stages.append(('be6l-recovery-guard', guard, ['busybox', 'procd', 'uci', 'dropbear'], '1.0.0-r2'))
    key, public, trust = work / 'fixture-signing.key', work / 'fixture-public.pem', work / 'trust'
    trust.mkdir()
    for path in (original / 'etc/apk/keys').iterdir():
        if path.is_file():
            if b'PRIVATE' in path.read_bytes():
                raise ValueError('Verification directory contains a private key')
            copy_path(path, trust / path.name)
    approved, expected = [], {}
    try:
        run('signing-key-generate', ['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', key])
        key.chmod(0o600)
        run('signing-public', ['openssl', 'pkey', '-in', key, '-pubout', '-out', public])
        copy_path(public, trust / 'be6l-unattended.pem')
        for name, files, depends, version in stages:
            package = work / (name + '.apk')
            cmd = [a.apk, 'mkpkg', '--sign-key', key, '--files', files, '--output', package]
            for field, value in dict(name=name, version=version, arch='noarch', license='MIT',
                    description='Private BE6L unattended RAM test', depends=' '.join(depends)).items():
                cmd += ['--info', field + ':' + value]
            run('package-' + name, cmd)
            run('verify-' + name, [a.apk, '--keys-dir', trust, '--network=no', 'verify', package])
            approved.append(package)
            expected.update(records(files))
        root = work / 'root'
        shutil.copytree(original, root, symlinks=True)
        transaction = [a.apk, '--root', root, '--keys-dir', trust, '--network=no', '--cache=no',
                       '--logfile=no', '--scripts=no', '--repositories-file', '/dev/null']
        run('simulate', transaction + ['add', '--simulate', *approved])
        if root_digest(root) != baseline_digest:
            raise ValueError('Simulation changed root')
        run('install', transaction + ['add', *approved])
        lock = root / 'var/lock'
        if not lock.resolve().is_relative_to(root):
            raise ValueError('Offline lock escapes root')
        lock.mkdir(parents=True, exist_ok=True)
        run('enable-recovery', ['/bin/bash', root / 'etc/rc.common', root / 'etc/init.d/be6l-recovery', 'enable'],
            env=dict(os.environ, IPKG_INSTROOT=str(root)))
        (lock / 'procd_be6l-recovery.lock').unlink(missing_ok=True)
        if not (root / 'etc/rc.d/S95be6l-recovery').is_symlink():
            raise ValueError('Guard is not enabled')
        after = records(root)
        root_ro = [a.apk, '--root', root, '--network=no', '--cache=no', '--logfile=no', '--repositories-file', '/dev/null']
        for name, files, _, version in stages:
            for path, value in records(files).items():
                if after.get(path) != value:
                    raise ValueError('Installed bytes or modes differ: ' + path)
                owner = run('owner-' + path.replace('/', '_'), root_ro + ['info', '--who-owns', '/' + path]).decode().strip()
                if not owner.endswith(' is owned by ' + name + '-' + version):
                    raise ValueError('Wrong package owner')
        changed = {n for n in before.keys() | after.keys() if before.get(n) != after.get(n)}
        allowed = set(expected) | {'etc/rc.d/S95be6l-recovery', 'etc/rc.d/K01be6l-recovery'}
        if any(n not in allowed and not n.startswith(('etc/apk/', 'lib/apk/')) for n in changed):
            raise ValueError('Unrelated payload changes')
        if set(before) - set(after) or root_digest(original) != baseline_digest:
            raise ValueError('Deleted path or baseline changed')
        installed = json.loads(run('installed-packages', root_ro + query))
        if len(installed) != len(packages) + sum(name not in package_names for name, _, _, _ in stages):
            raise ValueError('Unexpected package count')
    finally:
        key.unlink(missing_ok=True)
    report = dict(inherited or {}, normal_signed_component_transaction=True,
        original_root_records_sha256=baseline_digest, installed_root_records_sha256=root_digest(root),
        baseline_packages=len(packages), installed_packages=len(installed), changed_root_paths=sorted(changed),
        private_signing_key_removed=True, original_root_unchanged=True,
        private_image_identity=True, strict_known_hosts_prepared=True,
        recovery_enabled_in_offline_root=True, target_package_scripts_executed=False,
        matching_root_composed=True, image_built=False, target_executed=False)
    # Never publish a server/client private key, raw log or this work directory.
    (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print('UNATTENDED_SIGNED_RAM_ROOT_COMPOSED', len(installed), flush=True)


if __name__ == '__main__':
    main()
