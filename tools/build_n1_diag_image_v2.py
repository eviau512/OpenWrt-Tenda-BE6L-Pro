# SPDX-License-Identifier: MIT
"""Versioned offline build/audit/compose driver; never contact or boot a DUT.

Each stage is explicit. Legacy artifacts/checkers are read-only inputs. The
build stage requires an exact reviewed source lock and rebuilds all modules.
"""
from pathlib import Path
import argparse
import hashlib
import json
import lzma
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from a64_soft_context import BASE, SDK, EPOCH
from migrate_network_defaults_root import migrate
from prepare_ramboot import tree, image, text
from soft_abi_admission import file_records
from verify_embedded_compat_cpio import verify
from ppe_module_abi_v2 import probe as abi_probe, module_record

PIN = '30b833ae5b8a6ba94149268c47a8493308a0ee04'
FIRMWARE = '934d85a5949ec622cdf853b8442aeb3c5cdd92a81866a843963f4fbf26a3a867'
LIBC = '143100b85695d93b77a8b79b518f17cb48134ab38c828a07b0a9d171811dcddb'
WORKROOT = Path('/root/be6l-openwrt')
KERNEL = SDK / 'build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55'
APK = SDK / 'staging_dir/host/bin/apk'
ARTIFACT = BASE / 'artifacts/arm64-n1-diag-v2'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('stage', choices=('prepare', 'source-lock', 'build', 'finalize-build', 'resume-finalize', 'audit', 'compose', 'finish-compose', 'image'))
parser.add_argument('--work', type=Path, required=True)
parser.add_argument('--expected-source-lock')
parser.add_argument('--diagnostic-proof', type=Path, required=True)
args = parser.parse_args()
work = args.work.resolve()
assert work.parent == WORKROOT and work.name.startswith('n1-image-v2-')
env = dict(os.environ, FORCE_UNSAFE_CONFIGURE='1', SOURCE_DATE_EPOCH=EPOCH,
           CONFIG_SHELL=str(WORKROOT / 'host/bin/bash'))
env['PATH'] = str(WORKROOT / 'host/bin') + ':/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
n1_proof = json.loads(args.diagnostic_proof.read_text())
assert n1_proof['cases'] >= 58 and n1_proof['complete_airoha_translation_units_and_link']
assert n1_proof['can_publish'] is False and n1_proof['context_bytes'] == 56
assert n1_proof['userspace_arming_interface'] and not n1_proof['automatic_unb_classification_change']
n1_patch = SDK / 'target/linux/airoha/patches-6.18/977-n1-identity-and-inert-driver-taps.patch'
assert sha(n1_patch) == n1_proof['source_patch_sha256']



def save(name, data):
    (work / name).write_text(json.dumps(data, indent=2) + '\n')


def read(name):
    return json.loads((work / name).read_text())


def run(label, command, cwd=None, local_env=None):
    with (work / (label + '.log')).open('wb') as output:
        result = subprocess.run([str(x) for x in command], cwd=cwd,
                                env=local_env or env, stdout=output, stderr=subprocess.STDOUT)
    assert result.returncode == 0, (label, result.returncode)


def metadata(package):
    return json.loads(subprocess.check_output([str(APK), 'adbdump', '--format', 'json', str(package)]))['info']


def source_lock():
    assert subprocess.check_output(['git', '-C', str(SDK), 'rev-parse', 'HEAD'], text=True).strip() == PIN
    patches = SDK / 'target/linux/airoha/patches-6.18'
    assert len(list(patches.glob('973*.patch'))) == 1
    assert len(list(patches.glob('974*.patch'))) == 1, 'Reviewed 974 must exist before locking/building'
    selected = sorted(patches.glob('*.patch'))
    selected += sorted((SDK / 'package/kernel/mt76/patches').glob('*.patch'))
    selected += [SDK / x for x in ('target/linux/airoha/an7563a64/config-6.18',
                  'package/kernel/bpf-headers/Makefile', 'package/kernel/linux/Makefile',
                  'package/kernel/mac80211/Makefile', 'package/kernel/mt76/Makefile')]
    records = {p.relative_to(SDK).as_posix(): sha(p) for p in selected}
    lock = dict(version=1, openwrt_commit=PIN, files=records)
    digest = hashlib.sha256(json.dumps(lock, sort_keys=True).encode()).hexdigest()
    return lock, digest


def native_check(root):
    bundle = WORKROOT / 'soft-bundle-v2'
    baseline = read('baseline.json')
    receipt_path = BASE / 'logs/soft-bundle-soft-bundle-v2/result.json'
    assert sha(receipt_path) == baseline['bundle_receipt_sha256']
    receipt = json.loads(receipt_path.read_text())
    assert receipt['passed'] and receipt['normal_solver_signatures'] and receipt['pid1_owned_by_native_procd_package']
    assert receipt['profile_lock_sha256'] == baseline['soft_profile_lock_sha256']
    trust = work / 'native-public-keys'
    trust.mkdir(exist_ok=True)
    public = (bundle / 'fixture-public.pem').read_bytes()
    assert public.startswith(b'-----BEGIN PUBLIC KEY-----') and b'PRIVATE' not in public
    (trust / 'fixture-public.pem').write_bytes(public)
    for group in ('runtime', 'tools', 'procd', 'compat'):
        package_info = receipt['approved_packages'][group]
        package = bundle / package_info['file']
        assert sha(package) == package_info['sha256']
        run('verify-native-' + group, [APK, '--keys-dir', trust, '--network=no', 'verify', package])
        with tempfile.TemporaryDirectory(prefix='native-approved-' + group + '-', dir=work) as temporary:
            extracted = Path(temporary)
            run('extract-native-' + group, [APK, '--keys-dir', trust, '--network=no',
                'extract', '--no-chown', '--destination', extracted, package])
            for name, record in file_records(extracted).items():
                file = root / name
                if 'symlink' in record:
                    assert file.is_symlink() and str(file.readlink()) == record['symlink'], name
                else:
                    assert sha(file) == record['sha256'], name
                    assert file.stat().st_mode & 0o7777 == (extracted / name).stat().st_mode & 0o7777, name
    assert sha(root / 'lib/aarch64-soft/libc.so') == LIBC
    assert sha(root / 'lib/firmware/airoha/an7552.bin') == FIRMWARE
    assert not list((root / 'usr/bin').glob('portal_autologin*'))
    ownership = [APK, '--root', root, '--network=no', '--cache=no', 'info', '--who-owns']
    for name, owner in (('/sbin/init', 'procd'), ('/sbin/procd', 'procd'),
                        ('/lib/aarch64-soft/libc.so', 'runtime'), ('/lib/libsetlbf.so', 'compat')):
        output = subprocess.check_output([str(x) for x in ownership + [name]], text=True)
        expected = metadata(bundle / receipt['approved_packages'][owner]['file'])
        assert expected['name'] + '-' + expected['version'] in output
    assert (root / 'sbin/init').read_bytes()[:6] == b'\x7fELF\x02\x01'
    save('native-owner-proof.json', dict(original_bundle_receipt_sha256=sha(receipt_path),
        profile_lock_sha256=receipt['profile_lock_sha256'], approved_native_packages=receipt['approved_packages'],
        actual_pid1_libc_ownership_verified=True, original_native_payloads_unchanged=True))


def verify_build_abi(label):
    build = read('build-lock.json')
    assert source_lock()[1] == build['source_lock_sha256']
    assert sha(KERNEL / 'include/net/flow_offload.h') == build['flow_rule_header_sha256']
    assert sha(KERNEL / 'Module.symvers') == build['module_symvers_sha256']
    actual = abi_probe(KERNEL, work / label)
    keys = ('module_struct_bytes', 'flow_rule_bytes', 'flow_rule_action_offset', 'ct_context_bytes',
            'ct_context_offset', 'ct_context_version', 'flow_action_entry_bytes', 'vermagic')
    assert all(actual[key] == build['numeric_flow_rule_layout'][key] for key in keys)
    return actual


def finalize_matching_packages(label, install_baseline=True):
    """Finish normal gzip-initramfs config before rebuilding/package metadata."""
    sdk_config = (SDK / '.config').read_text()
    match = re.search(r'^CONFIG_EXTERNAL_CPIO="([^"]+)"$', sdk_config, re.M)
    assert match, 'The trusted baseline external CPIO must remain selected'
    external = Path(match.group(1))
    trusted = json.loads((BASE / 'artifacts/arm64-compat/build-validation.json').read_text())
    assert sha(external) == trusted['external_cpio_sha256']
    if install_baseline:
        run(label + '-baseline-image-install', ['make', '-j4', 'SHELL=' + env['CONFIG_SHELL'],
            'V=s', 'target/linux/install'], SDK)
    final_config = (KERNEL / '.config').read_text()
    assert '\nCONFIG_INITRAMFS_COMPRESSION_GZIP=y\n' in final_config
    assert '\nCONFIG_RD_GZIP=y\n' in final_config
    for name in ('mt76', 'mac80211', 'gpio-button-hotplug'):
        run(label + '-clean-' + name, ['make', 'SHELL=' + env['CONFIG_SHELL'],
            'package/kernel/' + name + '/clean'], SDK)
    targets = ['package/kernel/' + name + '/compile' for name in ('mac80211', 'mt76', 'gpio-button-hotplug')]
    run(label + '-external-modules', ['make', '-j4', 'SHELL=' + env['CONFIG_SHELL'], 'V=s', *targets], SDK)
    raw = work / (label + '-apks')
    assert not raw.exists()
    raw.mkdir()
    run(label + '-kernel-apks', ['make', '-j4', 'SHELL=' + env['CONFIG_SHELL'], 'ARCH_PACKAGES=arm_cortex-a7',
        'CONFIG_PER_FEED_REPO=', 'PACKAGE_DIR=' + str(raw), 'PACKAGE_DIR_ALL=' + str(raw),
        'package/kernel/linux/compile', *targets], SDK)
    numeric = abi_probe(KERNEL, work / (label + '-flow-abi'))
    shutil.copyfile(KERNEL / '.config', work / 'packaged-kernel.config')
    assert numeric['ct_context_version'] == 2 and numeric['ct_context_bytes'] == 56
    return raw, numeric


if args.stage == 'prepare':
    assert not work.exists()
    work.mkdir()
    baseline = json.loads((BASE / 'artifacts/arm64-rxhash/build-validation.json').read_text())
    assert baseline['image_sha256'] == 'd5a2bc21a9fa7072b982bfa1a734adc40c37412ea1ea9c2728d04ed21090d6fb'
    save('owner.json', dict(driver_version=2, work=str(work), source_baseline=baseline['image_sha256']))
    save('baseline.json', baseline)
    inputs = work / 'userspace-apks'
    inputs.mkdir()
    files = {}
    for folder in ('bridger-arm32', 'network-defaults'):
        receipt = json.loads((BASE / 'artifacts' / folder / 'build-validation.json').read_text())
        assert receipt['apk_signature_verified'] if folder == 'network-defaults' else receipt['normal_apk_signature_verified']
        package = BASE / 'artifacts' / folder / receipt['package_name']
        expected = receipt['package_sha256'] if folder == 'network-defaults' else receipt['artifacts'][package.name]['sha256']
        assert sha(package) == expected
        shutil.copyfile(package, inputs / package.name)
        files[package.name] = expected
    save('userspace-inputs.json', files)
    print('N1_V2_INPUTS_PREPARED_NO_BUILD', work)
    raise SystemExit(0)

assert read('owner.json') == dict(driver_version=2, work=str(work), source_baseline=
    'd5a2bc21a9fa7072b982bfa1a734adc40c37412ea1ea9c2728d04ed21090d6fb')
if args.stage == 'source-lock':
    lock, digest = source_lock()
    save('source-lock-candidate.json', dict(lock=lock, sha256=digest))
    print('REVIEWED_SOURCE_LOCK_REQUIRED', digest)
elif args.stage == 'build':
    lock, digest = source_lock()
    assert args.expected_source_lock == digest, 'Pass the exact reviewed source-lock digest'
    assert not (work / 'raw-apks').exists()
    shutil.copyfile(SDK / '.config', work / 'sdk-config-before')
    shutil.copyfile(KERNEL / '.config', work / 'kernel-config-before')
    save('reviewed-build-inputs.json', dict(lock=lock, source_lock_sha256=digest))
    lines = (SDK / '.config').read_text().splitlines()
    lines = [line for line in lines if not re.match(r'(?:# )?CONFIG_PACKAGE_wpad', line)]
    lines = [line for line in lines if not re.match(r'(?:# )?CONFIG_TARGET_INITRAMFS_COMPRESSION_', line)]
    lines.append('CONFIG_TARGET_INITRAMFS_COMPRESSION_GZIP=y')
    (SDK / '.config').write_text('\n'.join(lines + ['CONFIG_PACKAGE_wpad-mbedtls=y']) + '\n')
    run('bridger-inputs', [sys.executable, BASE / 'tools/prepare_bridger.py', SDK, '--apply'])
    run('defconfig', ['make', 'SHELL=' + env['CONFIG_SHELL'], 'defconfig'], SDK)
    # The internal flow_rule ABI changed. Rebuild from a normal clean target,
    # not just a set of objects whose old vermagic happens to match.
    run('kernel-clean', ['make', 'SHELL=' + env['CONFIG_SHELL'], 'target/linux/clean'], SDK)
    run('kernel-build', ['make', '-j4', 'SHELL=' + env['CONFIG_SHELL'], 'V=s', 'target/linux/compile'], SDK)
    raw, numeric = finalize_matching_packages('matching')
    config = (KERNEL / '.config').read_text()
    for option in ('CONFIG_NET_CLS_BPF=m', 'CONFIG_NET_ACT_BPF=m', 'CONFIG_NET_ACT_VLAN=m'):
        assert '\n' + option + '\n' in config
    assert source_lock()[1] == digest
    save('build-lock.json', dict(source_lock=lock, source_lock_sha256=digest,
        kernel_config_sha256=sha(KERNEL / '.config'),
        config_without_cpio_sha256=hashlib.sha256('\n'.join(x for x in config.splitlines()
            if not x.startswith('CONFIG_INITRAMFS_SOURCE=')).encode()).hexdigest(),
        flow_rule_header_sha256=sha(KERNEL / 'include/net/flow_offload.h'),
        module_symvers_sha256=sha(KERNEL / 'Module.symvers'),
        numeric_flow_rule_layout=numeric, expected_vermagic=numeric['vermagic'],
        raw_apks=str(raw), final_kernel_config_before_packaging=True,
        clean_full_kernel_and_external_modules_rebuilt=True))
    print('N1_V2_MATCHING_KERNEL_AND_MODULES_BUILT', work)
elif args.stage in ('finalize-build', 'resume-finalize'):
    # Resume a build launched by the initial driver revision, without reusing
    # its pre-install configuration or intermediate APK repository as admission.
    if args.stage == 'resume-finalize':
        checkpoint = json.loads((BASE / 'logs/ppe-bridger-build-checkpoint-latest.json').read_text())
        assert Path(checkpoint['work']) == work and not checkpoint['active_owned_build_processes']
        assert sha(SDK / '.config') == checkpoint['sdk_config_sha256']
        assert sha(KERNEL / '.config') == checkpoint['kernel_config_sha256']
        build = read('intermediate-build-lock.json')
        assert source_lock()[1] == checkpoint['source_lock_sha256'] == build['source_lock_sha256']
    elif (work / 'build-lock.json').exists():
        build = read('build-lock.json')
    else:
        reviewed = read('reviewed-build-inputs.json')
        assert source_lock()[1] == reviewed['source_lock_sha256']
        assert (work / 'matching-apks').is_dir() and (KERNEL / 'vmlinux').is_file()
        # A prior controller can fail after the successful build at its probe.
        # Re-run the normal incremental target to obtain an actual success,
        # then regenerate the complete final configuration/package receipt.
        run('resume-kernel-compile', ['make', '-j4', 'SHELL=' + env['CONFIG_SHELL'],
            'V=s', 'target/linux/compile'], SDK)
        build = dict(source_lock=reviewed['lock'], source_lock_sha256=reviewed['source_lock_sha256'],
            clean_full_kernel_and_external_modules_rebuilt=True,
            recovered_after_post_build_probe_parser_failure=True)
    assert source_lock()[1] == build['source_lock_sha256']
    assert not build.get('final_kernel_config_before_packaging', False)
    if args.stage != 'resume-finalize':
        save('intermediate-build-lock.json', build)
    raw, numeric = finalize_matching_packages('resume-final-1' if args.stage == 'resume-finalize' else 'final',
        install_baseline=args.stage != 'resume-finalize')
    config = (KERNEL / '.config').read_text()
    build.update(kernel_config_sha256=sha(KERNEL / '.config'),
        config_without_cpio_sha256=hashlib.sha256('\n'.join(x for x in config.splitlines()
            if not x.startswith('CONFIG_INITRAMFS_SOURCE=')).encode()).hexdigest(),
        flow_rule_header_sha256=sha(KERNEL / 'include/net/flow_offload.h'),
        module_symvers_sha256=sha(KERNEL / 'Module.symvers'), numeric_flow_rule_layout=numeric,
        expected_vermagic=numeric['vermagic'], raw_apks=str(raw),
        final_kernel_config_before_packaging=True)
    save('build-lock.json', build)
    print('N1_V2_FINAL_KERNEL_CONFIG_AND_PACKAGES_MATCH', work)
elif args.stage == 'audit':
    build = read('build-lock.json')
    assert build['final_kernel_config_before_packaging']
    assert source_lock()[1] == build['source_lock_sha256']
    assert sha(KERNEL / 'include/net/flow_offload.h') == build['flow_rule_header_sha256']
    assert sha(KERNEL / 'Module.symvers') == build['module_symvers_sha256']
    repo, unpack = work / 'kernel-repo', work / 'extracted-kmods'
    assert not repo.exists() and not unpack.exists()
    repo.mkdir(); unpack.mkdir()
    keys = SDK / 'build_dir/target-aarch64_cortex-a53_musl/root-airoha/etc/apk/keys'
    modules, module_abi, packages = {}, {}, []
    raw = Path(build['raw_apks'])
    assert raw.parent == work
    for package in sorted(raw.glob('*.apk')):
        info = metadata(package)
        if info['name'] != 'kernel' and not info['name'].startswith('kmod-'):
            continue
        assert re.fullmatch(r'[a-z0-9+_.-]+', info['name']) and info['arch'] == 'arm_cortex-a7'
        run('verify-' + info['name'], [APK, '--keys-dir', keys, '--network=no', 'verify', package])
        root = unpack / info['name']; root.mkdir()
        run('extract-' + info['name'], [APK, '--keys-dir', keys, '--network=no', 'extract',
            '--no-chown', '--destination', root, package])
        for file in root.rglob('*'):
            if not file.is_file() or file.is_symlink():
                continue
            name = file.relative_to(root).as_posix()
            data = file.read_bytes()
            if data[:4] != b'\x7fELF':
                continue
            if file.suffix == '.ko':
                assert data[4:6] == b'\x02\x01' and struct.unpack_from('<H', data, 18)[0] == 183
                assert name not in modules
                modules[name] = sha(file)
                module_abi[name] = module_record(file, build['numeric_flow_rule_layout'])
            else:
                baseline_file = WORKROOT / 'soft-bundle-v2/rootfs' / name
                assert name.startswith('lib/firmware/') and baseline_file.is_file() and sha(file) == sha(baseline_file)
        shutil.copyfile(package, repo / package.name)
        packages.append(dict(file=package.name, sha256=sha(package), info=info))
    kernel, = [x for x in packages if x['info']['name'] == 'kernel']
    pin = 'kernel=' + kernel['info']['version']
    for item in packages:
        if item['info']['name'].startswith('kmod-'):
            assert pin in item['info']['depends']
    assert set(read('baseline.json')['elf64_modules_verified']) <= set(modules)
    for name in ('cls_bpf.ko', 'act_bpf.ko', 'act_vlan.ko'):
        assert 'lib/modules/6.18.55/' + name in modules
    save('kernel-audit.json', dict(kernel_pin=pin, packages=packages, module_files=modules,
                                  module_abi=module_abi, source_build_lock=build,
                                  stale_modules_allowed=False))
    print('N1_V2_KERNEL_APKS_AUDITED', len(modules), pin)
elif args.stage in ('compose', 'finish-compose'):
    audit = read('kernel-audit.json')
    root = work / 'root'
    if args.stage == 'compose':
        assert not root.exists()
        shutil.copytree(WORKROOT / 'soft-bundle-v2/rootfs', root, symlinks=True)
        native_check(root)
        save('managed-migration.json', migrate(root, APK))
        keys = root / 'etc/apk/keys'
        for i, key in enumerate((WORKROOT / 'source/public-key.pem', SDK / 'public-key.pem')):
            data = key.read_bytes(); assert data.startswith(b'-----BEGIN PUBLIC KEY-----') and b'PRIVATE' not in data
            (keys / ('be6l-v1-build-' + str(i) + '.pem')).write_bytes(data)
    else:
        assert root.is_dir() and not (work / 'composition.json').exists()
        assert 'OK:' in (work / 'transact-root.log').read_text()
        assert 'OK:' in (work / 'normalize-world.log').read_text()
    packages = []
    for item in audit['packages']:
        p = work / 'kernel-repo' / item['file']; assert sha(p) == item['sha256']; packages.append(p)
    for name, digest in read('userspace-inputs.json').items():
        p = work / 'userspace-apks' / name; assert sha(p) == digest; packages.append(p)
    common = [APK, '--root', root, '--network=no', '--cache=no', '--scripts=no', '--repositories-file', '/dev/null']
    if args.stage == 'compose':
        run('simulate-root', common + ['add', '--simulate', audit['kernel_pin'], *packages])
        run('transact-root', common + ['add', audit['kernel_pin'], *packages])
        names = [item['info']['name'] for item in audit['packages'] if item['info']['name'] != 'kernel']
        run('normalize-world', common + ['add', audit['kernel_pin'], *names, 'bridger', 'be6l-network-defaults'])
    assert audit['kernel_pin'] in (root / 'etc/apk/world').read_text().splitlines()
    for name, digest in audit['module_files'].items():
        assert sha(root / name) == digest
    assert {p.relative_to(root).as_posix() for p in (root / 'lib/modules').rglob('*.ko')} == set(audit['module_files'])
    native_check(root)
    local_env = dict(env, IPKG_INSTROOT=str(root))
    run('enable-bridger', [env['CONFIG_SHELL'], root / 'etc/rc.common', root / 'etc/init.d/bridger', 'enable'], root, local_env)
    assert (root / 'etc/rc.d/S19bridger').is_symlink()
    for name in ('tailscale', 'passwall'):
        run('disable-' + name, [env['CONFIG_SHELL'], root / 'etc/rc.common', root / 'etc/init.d' / name, 'disable'], root, local_env)
        assert not list((root / 'etc/rc.d').glob('S??' + name))
    readonly = [x for x in common if x != '--scripts=no']
    run('policy-ownership', readonly + ['info', '--who-owns', '/usr/libexec/platform/packet-steering.sh', '/etc/uci-defaults/99-be6l-ram-ui'])
    for name, digest in json.loads((BASE / 'artifacts/network-defaults/build-validation.json').read_text())['owned_script_sha256'].items():
        assert sha(root / name) == digest and (root / name).stat().st_mode & 0o777 == 0o755
    assert not list((root / 'etc/uci-defaults').glob('*.apk-new'))
    run('package-manifest', readonly + ['query', '--installed', '--format', 'json', '--fields', 'name,version,arch,depends', '*'])
    manifest = json.loads((work / 'package-manifest.log').read_text())
    assert len(manifest) >= read('baseline.json')['actual_packages']
    assert all(item['arch'] in ('arm_cortex-a7', 'noarch', 'aarch64_be6l_soft_experimental') for item in manifest)
    state = dict(driver_version=2, native_c_elfs=58, fully_native_userspace=False,
        native_init_procd=True, corrected_fma_libc=True, ramboot_validated=False,
        runtime_abi='aarch64_kernel_soft64_native_c_arm32_remaining_apps',
        package_metadata='Normal offline APK transaction; matching rebuilt ARM64 kernel/modules; policy scripts owned.',
        kernel_changes_require_matching_ramboot=True, bridger_installed=True, bridger_hardware_qualified=False,
        soft_profile_lock_sha256=read('baseline.json')['soft_profile_lock_sha256'])
    state.update(n1_diagnostic_only=True, diagnostic_default_enabled=False, can_publish=False,
                 routed_bind_supported=False, normal_native_apk_transaction=True, preserved_normal_native_ownership=True,
                 native_packages_replaced_this_round=False)
    for name in ('be6l-soft-init.json', 'be6l-compat-build.json'):
        (root / 'etc' / name).write_text(json.dumps(state, indent=2) + '\n')
    save('composition.json', dict(metadata=state, root=str(root), kernel_audit_sha256=sha(work / 'kernel-audit.json'),
        package_manifest_sha256=sha(work / 'package-manifest.log'), actual_packages=len(manifest),
        userspace_profile_unchanged=True))
    print('N1_V2_FRESH_PACKAGE_ROOT_COMPOSED_NO_IMAGE', root)
elif args.stage == 'image':
    composition, audit, build = read('composition.json'), read('kernel-audit.json'), read('build-lock.json')
    root = Path(composition['root']); native_check(root)
    assert composition['kernel_audit_sha256'] == sha(work / 'kernel-audit.json')
    assert source_lock()[1] == build['source_lock_sha256']
    before_image_abi = verify_build_abi('image-entry-abi')
    paths = ['.'] + sorted(str(p.relative_to(root)) for p in root.rglob('*'))
    for name in paths:
        os.utime(root / name, (int(EPOCH), int(EPOCH)), follow_symlinks=False)
    cpio = work / 'rootfs.cpio'
    with cpio.open('wb') as output:
        subprocess.run([str(SDK / 'staging_dir/host/bin/cpio'), '--null', '--reproducible', '-o', '-H', 'newc', '-R', '0:0'],
            cwd=root, input=('\0'.join(paths) + '\0').encode(), stdout=output, check=True)
    nodes = work / 'device-nodes.list'; nodes.write_text('nod /dev/console 0600 0 0 c 5 1\nnod /dev/null 0666 0 0 c 1 3\n')
    with cpio.open('ab') as output:
        subprocess.run([str(KERNEL / 'usr/gen_init_cpio'), '-t', EPOCH, str(nodes)], stdout=output, check=True)
    saved = (SDK / '.config').read_bytes()
    try:
        lines = saved.decode().splitlines(); lines = [x for x in lines if not x.startswith('CONFIG_EXTERNAL_CPIO=')]
        (SDK / '.config').write_text('\n'.join(lines + ['CONFIG_EXTERNAL_CPIO="' + str(cpio) + '"']) + '\n')
        run('image-defconfig', ['make', 'SHELL=' + env['CONFIG_SHELL'], 'defconfig'], SDK)
        run('image-install', ['make', '-j4', 'SHELL=' + env['CONFIG_SHELL'], 'V=s', 'target/linux/install'], SDK)
        config = (KERNEL / '.config').read_text()
        normalized = hashlib.sha256('\n'.join(x for x in config.splitlines() if not x.startswith('CONFIG_INITRAMFS_SOURCE=')).encode()).hexdigest()
        assert normalized == build['config_without_cpio_sha256'], 'Unexpected kernel ABI/config change at image stage'
        after_image_abi = verify_build_abi('image-exit-abi')
        fit, = (SDK / 'bin/targets/airoha/an7563a64').glob('*tenda_be6l-pro-initramfs-kernel.bin')
        dt = tree(fit.read_bytes()); conf = dt['/configurations/' + text(dt['/configurations']['default'])]
        packed, props = image(dt, text(conf['kernel'])); dtb, _ = image(dt, text(conf['fdt']))
        assert text(props['arch']) == 'arm64' and text(props['compression']) == 'lzma'
        assert int.from_bytes(props['load'], 'big') == 0x80200000
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        data = decoder.decompress(packed, max_length=0x3e00000)
        assert decoder.eof and not decoder.unused_data and data[0x38:0x3c] == b'ARMd'
        _, effective, _ = struct.unpack_from('<QQQ', data, 8)
        assert effective >= len(data) and 0x80200000 + effective <= 0x84000000
        board = tree(dtb)
        assert b'tenda,be6l-pro\0' in board['/']['compatible']
        assert sum('read-only' in x for x in board.values()) == 10
        assert any('airoha,bmt-read-only' in x for x in board.values())
        embedded = verify(KERNEL, data, cpio)
        compiler, = SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
        run('module-layout', [sys.executable, BASE / 'tools/audit_module_layout.py', '--kernel', KERNEL,
            '--root', root, '--arch', 'arm64', '--cross-compile', str(compiler)[:-3], '--output', work / 'module-layout.json'])
        for name, digest in audit['module_files'].items():
            assert sha(root / name) == digest
            assert module_record(root / name, build['numeric_flow_rule_layout']) == audit['module_abi'][name]
        report = dict(**composition['metadata'], **embedded, image=fit.name, image_sha256=sha(fit),
            external_cpio_sha256=sha(cpio), external_cpio_bytes=cpio.stat().st_size,
            kernel_config_sha256=sha(KERNEL / '.config'), kernel_effective_bytes=effective,
            kernel_headroom_bytes=0x84000000 - 0x80200000 - effective,
            elf64_modules_verified=audit['module_files'], module_layout_audit=read('module-layout.json'),
            source_abi_build_lock=build, kernel_apk_pin=audit['kernel_pin'],
            source_abi_numeric_layout=build['numeric_flow_rule_layout'], expected_module_vermagic=build['expected_vermagic'],
            image_entry_abi=before_image_abi, image_exit_abi=after_image_abi,
            native_owner_proof=read('native-owner-proof.json'),
            actual_package_manifest_sha256=composition['package_manifest_sha256'],
            actual_package_manifest_verified=True, actual_packages=composition['actual_packages'],
            root=str(root), dtb_readonly_partitions=10, standard_kernel_make=True,
            normal_kernel_module_package_transaction=True, default_loader_chroot_tested=False,
            static_admission_only=True, hardware_qualified=False)
        assert report['module_layout_audit']['passed']
        ARTIFACT.mkdir(exist_ok=True)
        assert not (ARTIFACT / 'build-validation.json').exists(), 'Never overwrite an existing candidate'
        shutil.copyfile(fit, ARTIFACT / fit.name)
        (ARTIFACT / 'build-validation.json').write_text(json.dumps(report, indent=2) + '\n')
        save('image-result.json', report)
        print('N1_V2_STATIC_IMAGE_ADMITTED_NO_RAMBOOT', report['image_sha256'])
    finally:
        (SDK / '.config').write_bytes(saved)
        assert (SDK / '.config').read_bytes() == saved
