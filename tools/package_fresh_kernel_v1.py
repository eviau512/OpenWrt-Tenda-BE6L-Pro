# SPDX-License-Identifier: MIT
"""Normally transact fresh kernel/kmod packages in a NEW sealed mixed RAM root.

Rebuilds installed in-tree module payloads, retains seven external modules only
with unchanged source/configuration and a fresh layout probe, and records that
CONFIG_MODVERSIONS is disabled. Does not claim live module or ASIC acceptance.
The opt-in binfmt build instead requires all seven external modules rebuilt.
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
    parser.add_argument('--external-build', type=Path,
                        help='Required complete fresh external-module receipt for a binfmt kernel')
    args = parser.parse_args()
    work = args.work.resolve()
    if work.parent != Path('/root') or not work.name.startswith('be6l-kernel-apk-'):
        parser.error('Use a fresh /root/be6l-kernel-apk-* directory')
    original = args.composition / 'root'
    prior = json.loads((args.composition / 'result.json').read_text())
    if root_digest(original) != prior['installed_root_records_sha256']:
        raise ValueError('Sealed component root changed')
    built = json.loads((args.kernel_build / 'result.json').read_text())
    binfmt = bool(built.get('integer_binfmt_builtin'))
    base_count = 219 if binfmt else 218
    if binfmt and (not args.external_build or prior.get('private_native_files_marked') != 61 or prior['installed_packages'] != 219):
        raise ValueError('Binfmt composition requires the admitted signed private-marker root and fresh external modules')
    if not binfmt and args.external_build:
        raise ValueError('External rebuild input is only admitted for the explicit binfmt profile')
    layout = json.loads((args.kernel_build / 'module-layout.json').read_text())
    build = args.kernel_build / 'build'
    if not built['full_kernel_built'] or not layout['passed'] or layout['module_count'] != (85 if binfmt else 84):
        raise ValueError('Fresh kernel/layout evidence missing')
    if sha(build / 'Module.symvers') != built['module_symvers_sha256']:
        raise ValueError('Kernel symbol table changed')
    if sha(args.bootstrap / KERNEL / '.config') != built['baseline_config_sha256'] or sha(build / '.config') != built['effective_config_sha256']:
        raise ValueError('Kernel configuration bytes changed after build')
    old_config = (args.bootstrap / KERNEL / '.config').read_text()
    new_config = (build / '.config').read_text()
    from build_fresh_arm64_kernel_v1 import config_values
    old_values, new_values = config_values(old_config), config_values(new_config)
    expected_delta = {'CONFIG_INITRAMFS_SOURCE'} | ({'CONFIG_BINFMT_MISC'} if binfmt else set())
    assert {k for k in old_values.keys() | new_values.keys()
            if old_values.get(k) != new_values.get(k)} == expected_delta
    if binfmt and (old_values['CONFIG_BINFMT_MISC'] != 'n' or new_values['CONFIG_BINFMT_MISC'] != 'y'):
        raise ValueError('Unexpected binfmt kernel configuration')
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
    preinit = config_set.read_text()
    def preinit_abi(text):
        lines = sorted(line for line in text.splitlines() if re.search('=[ym]', line))
        return hashlib.md5(('\n'.join(lines) + '\n').encode()).hexdigest()
    old_abi = preinit_abi(preinit)
    if old_abi != 'ebdb6ef0fb8a643c0a13573c2d8c2337':
        raise ValueError('Wrong OpenWrt pre-initramfs ABI configuration')
    if binfmt:
        if preinit.count('# CONFIG_BINFMT_MISC is not set') != 1:
            raise ValueError('Unexpected pre-initramfs binfmt profile')
        preinit = preinit.replace('# CONFIG_BINFMT_MISC is not set', 'CONFIG_BINFMT_MISC=y')
    abi = preinit_abi(preinit)
    work.mkdir(mode=0o700)
    (work / 'kernel-preinitramfs.config.set').write_text(preinit)
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
    if old_kernel['version'] != '6.18.55~' + old_abi + ('-r100' if binfmt else '-r1'):
        raise ValueError('Installed kernel ABI pin differs')
    new_kernel_version = '6.18.55~' + abi + ('-r101' if binfmt else '-r100')
    new_kernel_pin = 'kernel=' + new_kernel_version
    cross = str(args.bootstrap / TOOLCHAIN / 'bin/aarch64-openwrt-linux-musl-')
    env = dict(os.environ, CROSS=cross, NO_RENAME='1', SOURCE_DATE_EPOCH='1792420077')
    env.pop('KEEP_SYMBOLS', None)
    env.pop('KEEP_BUILD_ID', None)
    strip_script = args.prepared / 'openwrt/scripts/strip-kmod.sh'
    fresh = {Path(name).name: build / name for name in built['in_tree_module_sha256']}
    fresh_hashes = {Path(name).name: digest for name,digest in built['in_tree_module_sha256'].items()}
    old_modules = {p.name: p for p in (original / 'lib/modules').rglob('*.ko')}
    if len(fresh) != len(built['in_tree_module_sha256']) or len(old_modules) != 84:
        raise ValueError('Duplicate or unexpected module names')
    external = sorted(set(old_modules) - fresh.keys())
    expected_external = ['cfg80211.ko', 'compat.ko', 'gpio-button-hotplug.ko', 'mac80211.ko',
                         'mt76-connac-lib.ko', 'mt76.ko', 'mt7996e.ko']
    if external != expected_external:
        raise ValueError('Unexpected external module set')
    external_receipt_sha = None
    if binfmt:
        external_built = json.loads((args.external_build / 'result.json').read_text())
        if (not external_built['all_external_modules_rebuilt'] or
            external_built['kernel_build_receipt_sha256'] != sha(args.kernel_build / 'result.json') or
            external_built['kernel_effective_config_sha256'] != built['effective_config_sha256'] or
            external_built['kernel_module_symvers_sha256'] != built['module_symvers_sha256'] or
            sorted(external_built['modules']) != expected_external):
            raise ValueError('External modules do not match this new kernel/configuration')
        for name,item in external_built['modules'].items():
            fresh[name] = args.external_build / item['path']
            fresh_hashes[name] = item['sha256']
        external_receipt_sha = sha(args.external_build / 'result.json')
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
                    if sha(path) != fresh_hashes[origin.name]:
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
    if len(replacements) != (84 if binfmt else 77) or len(retained) != (0 if binfmt else 7):
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
            old_base, old_release = package['version'].rsplit('-r', 1)
            version = new_kernel_version if name == 'kernel' else old_base + '-r' + (str(int(old_release)+1) if binfmt else '100')
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
        if len(installed) != base_count or root_digest(original) != original_digest:
            raise ValueError('Package count or original root changed')
        changed = {name for name in before.keys() | after.keys() if before.get(name) != after.get(name)}
        unexpected = changed - set(expected) - {name for name in changed if name.startswith(('lib/apk/', 'etc/apk/'))}
        if unexpected:
            raise ValueError('Unrelated root files changed: ' + str(sorted(unexpected)))
    finally:
        if key.exists():key.unlink()
    report = dict(normal_signed_component_transaction=True, kernel_package_version=new_kernel_version,
        package_count_rebuilt=len(approved), installed_packages=base_count, rebuilt_module_count=77,
        rebuilt_in_tree_module_count=77, rebuilt_external_module_count=7 if binfmt else 0,
        total_rebuilt_module_count=len(replacements),
        retained_external_module_count=len(retained), replacements=replacements, retained_external_modules=retained,
        baseline_packages=base_count, original_root_unchanged=True, private_signing_key_removed=not key.exists(),
        original_root_records_sha256=original_digest, installed_root_records_sha256=root_digest(work / 'root'),
        source_kernel_build_receipt_sha256=sha(args.kernel_build / 'result.json'),
        openwrt_preinitramfs_abi=abi, module_layout_probe_passed=True, module_crc_enforcement=False,
        unchanged_external_interface_headers=header_hashes,
        external_build_receipt_sha256=external_receipt_sha, integer_binfmt_builtin=binfmt,
        preinitramfs_config_set_sha256=sha(work / 'kernel-preinitramfs.config.set'),
        target_package_scripts_executed=False,
        matching_root_composed=True, image_built=False, target_executed=False)
    (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print('FRESH_KERNEL_MODULES_NORMAL_SIGNED_ROOT', len(approved), 'PACKAGES; 84 MODULES', flush=True)


if __name__ == '__main__':
    main()
