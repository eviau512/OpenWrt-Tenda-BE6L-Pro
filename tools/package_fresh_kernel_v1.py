# SPDX-License-Identifier: MIT
"""Normally transact fresh kernel/kmod packages in a NEW sealed mixed RAM root.

Rebuilds installed in-tree module payloads, retains seven external modules only
with unchanged source/configuration and a fresh layout probe, and records that
CONFIG_MODVERSIONS is disabled. Does not claim live module or ASIC acceptance.
"""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from package_native_netifd_v3 import records, root_digest, copy_path, sha

FIELDS = 'name,version,arch,license,description,depends,provides,install-if,provider-priority,origin,tags,replaces'
KERNEL = 'arm64-source/build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55'
TOOLCHAIN = 'arm64-source/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.4.0_musl'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--composition', type=Path, required=True)
    parser.add_argument('--kernel-build', type=Path, required=True)
    parser.add_argument('--prepared', type=Path, required=True)
    parser.add_argument('--kernel-cache', type=Path, required=True)
    parser.add_argument('--bootstrap', type=Path, required=True)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    if work.parent != Path('/root') or not work.name.startswith('be6l-kernel-apk-'):
        parser.error('Use a fresh /root/be6l-kernel-apk-* directory')
    original = args.composition / 'root'
    prior = json.loads((args.composition / 'result.json').read_text())
    if root_digest(original) != prior['installed_root_records_sha256']:
        raise ValueError('Sealed component root changed')
    built = json.loads((args.kernel_build / 'result.json').read_text())
    layout = json.loads((args.kernel_build / 'module-layout.json').read_text())
    build = args.kernel_build / 'build'
    if not built['full_kernel_built'] or not layout['passed'] or layout['module_count'] != 84:
        raise ValueError('Fresh kernel/layout evidence missing')
    if sha(build / 'Module.symvers') != built['module_symvers_sha256']:
        raise ValueError('Kernel symbol table changed')
    if sha(args.bootstrap / KERNEL / '.config') != built['baseline_config_sha256'] or sha(build / '.config') != built['effective_config_sha256']:
        raise ValueError('Kernel configuration bytes changed after build')
    old_config = (args.bootstrap / KERNEL / '.config').read_text()
    new_config = (build / '.config').read_text()
    from build_fresh_arm64_kernel_v1 import config_values
    old_values, new_values = config_values(old_config), config_values(new_config)
    assert {k for k in old_values.keys() | new_values.keys()
            if old_values.get(k) != new_values.get(k)} == {'CONFIG_INITRAMFS_SOURCE'}
    source = args.prepared / 'kernel-source/linux-6.18.55'
    header_hashes = {}
    for name in ('drivers/net/ethernet/airoha/airoha_eth.h',
                 'drivers/net/ethernet/airoha/airoha_regs.h',
                 'include/linux/soc/airoha/airoha_offload.h'):
        relative = Path(name)
        if sha(source / relative) != sha(args.bootstrap / KERNEL / relative):
            raise ValueError('External Airoha header changed: ' + name)
        header_hashes[name] = sha(source / relative)
    config_set = args.kernel_cache / KERNEL / '.config.set'
    lines = sorted(line for line in config_set.read_text().splitlines() if re.search('=[ym]', line))
    abi = hashlib.md5(('\n'.join(lines) + '\n').encode()).hexdigest()
    if abi != 'ebdb6ef0fb8a643c0a13573c2d8c2337':
        raise ValueError('Wrong OpenWrt pre-initramfs ABI configuration')
    work.mkdir(mode=0o700)
    before = records(original)
    original_digest = root_digest(original)
    readonly = [args.apk, '--root', original, '--network=no', '--cache=no', '--logfile=no',
                '--repositories-file', '/dev/null']

    def run(label, command, good=True, env=None):
        result = subprocess.run(list(map(str, command)), capture_output=True, timeout=240, env=env)
        (work / (label + '.log')).write_bytes(result.stdout + result.stderr)
        if (result.returncode == 0) != good:
            raise RuntimeError(label + ' returned ' + str(result.returncode))
        return result.stdout

    query = ['query', '--installed', '--format', 'json', '--fields', FIELDS]
    packages = json.loads(run('old-kernel-packages', readonly + query + ['kernel', 'kmod-*']))
    old_kernel, = [p for p in packages if p['name'] == 'kernel']
    if old_kernel['version'] != '6.18.55~' + abi + '-r1':
        raise ValueError('Installed kernel ABI pin differs')
    new_kernel_version = '6.18.55~' + abi + '-r100'
    new_kernel_pin = 'kernel=' + new_kernel_version
    cross = str(args.bootstrap / TOOLCHAIN / 'bin/aarch64-openwrt-linux-musl-')
    env = dict(os.environ, CROSS=cross, NO_RENAME='1', SOURCE_DATE_EPOCH='1792420077')
    env.pop('KEEP_SYMBOLS', None)
    env.pop('KEEP_BUILD_ID', None)
    strip_script = args.prepared / 'openwrt/scripts/strip-kmod.sh'
    fresh = {Path(name).name: build / name for name in built['in_tree_module_sha256']}
    old_modules = {p.name: p for p in (original / 'lib/modules').rglob('*.ko')}
    if len(fresh) != len(built['in_tree_module_sha256']) or len(old_modules) != 84:
        raise ValueError('Duplicate or unexpected module names')
    external = sorted(set(old_modules) - fresh.keys())
    expected_external = ['cfg80211.ko', 'compat.ko', 'gpio-button-hotplug.ko', 'mac80211.ko',
                         'mt76-connac-lib.ko', 'mt76.ko', 'mt7996e.ko']
    if external != expected_external:
        raise ValueError('Unexpected external module set')
    stage, expected, replacements, retained = {}, {}, {}, {}
    for package in packages:
        name = package['name']
        if package['arch'] != 'arm_cortex-a7':
            raise ValueError('Unexpected mixed-root module package label')
        files = work / 'files' / name
        files.mkdir(parents=True)
        listing = run('contents-' + name, readonly + ['info', '--contents', name]).decode()
        for line in listing.splitlines():
            if not line or line.endswith('contains:'):
                continue
            relative = line.lstrip('/')
            if '..' in PurePosixPath(relative).parts:
                raise ValueError('Invalid package path')
            origin, destination = original / relative, files / relative
            copy_path(origin, destination)
            if origin.suffix == '.ko':
                if origin.name in fresh:
                    path = fresh[origin.name]
                    if sha(path) != built['in_tree_module_sha256'][path.relative_to(build).as_posix()]:
                        raise ValueError('New module changed')
                    shutil.copyfile(path, destination)
                    destination.chmod(origin.stat().st_mode & 0o7777)
                    run('strip-' + origin.name, ['/bin/sh', strip_script, destination], env=env)
                    replacements[relative] = dict(before=sha(origin), after=sha(destination))
                else:
                    retained[relative] = sha(origin)
        if name == 'kernel':
            directory = files / 'lib/modules/6.18.55'
            (directory / 'modules.builtin').write_text(''.join(
                Path(line).name + '\n' for line in (build / 'modules.builtin').read_text().splitlines()))
            strings = run('builtin-modinfo-strings', ['strings', build / 'modules.builtin.modinfo']).splitlines()
            filtered = [line for line in strings if not re.search(rb'\.(file|parmtype)=', line)]
            (directory / 'modules.builtin.modinfo').write_bytes(b'\0'.join(filtered) + b'\0')
        stage[name] = files
        for path, value in records(files).items():
            if path in expected:
                raise ValueError('Two packages own the same file')
            expected[path] = value
    if len(replacements) != 77 or len(retained) != 7:
        raise ValueError('Missing rebuilt or retained module payloads')
    key, public, trust = work / 'fixture-signing.key', work / 'public-key.pem', work / 'trust'
    trust.mkdir()
    for path in (original / 'etc/apk/keys').iterdir():
        if path.is_file():
            if b'PRIVATE' in path.read_bytes():
                raise ValueError('Not a public verification key')
            copy_path(path, trust / path.name)
    approved = []
    versions = {}
    try:
        run('key-generate', ['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', key])
        key.chmod(0o600)
        run('key-public', ['openssl', 'pkey', '-in', key, '-pubout', '-out', public])
        copy_path(public, trust / 'be6l-fresh-kernel.pem')
        for package in packages:
            name = package['name']
            version = new_kernel_version if name == 'kernel' else package['version'].rsplit('-r', 1)[0] + '-r100'
            versions[name] = version
            depends = [new_kernel_pin if item.startswith('kernel=') else item for item in package.get('depends', [])]
            command = [args.apk, 'mkpkg', '--sign-key', key, '--files', stage[name],
                       '--output', work / (name + '.apk')]
            info = dict(name=name, version=version, arch=package['arch'], license=package['license'],
                        description=package['description'], depends=depends)
            for field in ('provides', 'install-if', 'provider-priority', 'origin', 'tags', 'replaces'):
                if field in package:info[field] = package[field]
            for field, value in info.items():
                command += ['--info', field + ':' + (' '.join(value) if isinstance(value, list) else str(value))]
            run('mkpkg-' + name, command, env=env)
            approved.append(work / (name + '.apk'))
            run('verify-' + name, [args.apk, '--keys-dir', trust, '--network=no', 'verify', approved[-1]])
        root = work / 'root'
        shutil.copytree(original, root, symlinks=True)
        transaction = [args.apk, '--root', root, '--keys-dir', trust, '--network=no', '--cache=no',
                       '--logfile=no', '--scripts=no', '--repositories-file', '/dev/null']
        run('simulate', transaction + ['add', '--simulate', *approved])
        if root_digest(root) != original_digest:
            raise ValueError('Simulation changed root')
        run('normal-install', transaction + ['add', *approved])
        query_root = [args.apk, '--root', root, '--network=no', '--cache=no', '--logfile=no', '--repositories-file', '/dev/null']
        after = records(root)
        for name, value in expected.items():
            if after.get(name) != value:
                raise ValueError('Installed kernel package payload differs: ' + name)
        for package in packages:
            name = package['name']
            for path in records(stage[name]):
                owner = run('owner-' + path.replace('/', '_'), query_root + ['info', '--who-owns', '/' + path]).decode().strip()
                if not owner.endswith(' is owned by ' + name + '-' + versions[name]):
                    raise ValueError('Wrong installed owner: ' + path)
        installed = json.loads(run('installed', query_root + ['query', '--installed', '--format', 'json', '--fields', 'name,version', '*']))
        if len(installed) != 218 or root_digest(original) != original_digest:
            raise ValueError('Package count or original root changed')
        changed = {name for name in before.keys() | after.keys() if before.get(name) != after.get(name)}
        unexpected = changed - set(expected) - {name for name in changed if name.startswith(('lib/apk/', 'etc/apk/'))}
        if unexpected:
            raise ValueError('Unrelated root files changed: ' + str(sorted(unexpected)))
    finally:
        if key.exists():key.unlink()
    report = dict(normal_signed_component_transaction=True, kernel_package_version=new_kernel_version,
        package_count_rebuilt=len(approved), installed_packages=218, rebuilt_module_count=77,
        retained_external_module_count=7, replacements=replacements, retained_external_modules=retained,
        baseline_packages=218, original_root_unchanged=True, private_signing_key_removed=not key.exists(),
        original_root_records_sha256=original_digest, installed_root_records_sha256=root_digest(work / 'root'),
        source_kernel_build_receipt_sha256=sha(args.kernel_build / 'result.json'),
        openwrt_preinitramfs_abi=abi, module_layout_probe_passed=True, module_crc_enforcement=False,
        unchanged_external_interface_headers=header_hashes,
        target_package_scripts_executed=False,
        matching_root_composed=True, image_built=False, target_executed=False)
    (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print('FRESH_KERNEL_MODULES_NORMAL_SIGNED_ROOT', len(approved), 'PACKAGES; 84 MODULES', flush=True)


if __name__ == '__main__':
    main()
