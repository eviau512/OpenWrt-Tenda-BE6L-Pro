# SPDX-License-Identifier: MIT
"""Build a fresh ARM64 kernel and in-tree modules with a sealed RAM archive.

The resulting vmlinux embeds the component archive's old module packages.
Matching rebuilt module packaging and final CPIO/Image admission are mandatory
later stages. No target operation or standard-A53 compatibility is claimed.
"""
from pathlib import Path
from datetime import datetime, timezone
import argparse
import hashlib
import json
import os
import re
import subprocess

BASE = Path(__file__).resolve().parents[1]
KERNEL = 'arm64-source/build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55'
TOOLCHAIN = 'arm64-source/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.4.0_musl'
CONFIG_SHA = '6da2430a71f780d28e554810936df142a4427df22f8e31fe07f80e581a36e215'
DRIVER_SHA = 'de1f3299891eef4d987a4e9222eedc535ead18bf0d100c996eea2c0f8d5bb2f1'
EPOCH = 1792420077


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def config_values(text):
    result = {}
    for line in text.splitlines():
        if line.startswith('CONFIG_'):
            key, value = line.split('=', 1)
            result[key] = value
        elif match := re.fullmatch(r'# (CONFIG_\w+) is not set', line):
            result[match[1]] = 'n'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared', type=Path, required=True)
    parser.add_argument('--bootstrap', type=Path, required=True)
    parser.add_argument('--host-prefix', type=Path, required=True)
    parser.add_argument('--cpio', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--integer-binfmt', action='store_true',
                        help='Build in binfmt_misc for a separately admitted instruction-emulation candidate')
    args = parser.parse_args()
    work = args.work.resolve()
    if work.parent != Path('/root') or not work.name.startswith('be6l-kernel-build-'):
        parser.error('Use a fresh /root/be6l-kernel-build-* directory')
    kernel = args.prepared / 'kernel-source/linux-6.18.55'
    prepared = json.loads((args.prepared / 'result.json').read_text())
    if not prepared['pristine_case_sensitive_source'] or sha(kernel / 'drivers/net/ethernet/airoha/airoha_ppe.c') != DRIVER_SHA:
        raise ValueError('Wrong fresh kernel preparation')
    baseline = args.bootstrap / KERNEL / '.config'
    if sha(baseline) != CONFIG_SHA:
        raise ValueError('Wrong qualified kernel configuration')
    evidence = json.loads((BASE / 'docs/evidence/continuation-20261105.json').read_text())
    cpio_sha = evidence['root_archive_measurement']['roots']['native']['cpio_sha256']
    if sha(args.cpio) != cpio_sha:
        raise ValueError('RAM archive differs from reviewed component evidence')
    work.mkdir(mode=0o700)
    build = work / 'build'
    build.mkdir()
    old_config = baseline.read_text()
    values = config_values(old_config)
    changed = old_config.replace('CONFIG_INITRAMFS_SOURCE=' + values['CONFIG_INITRAMFS_SOURCE'],
                                'CONFIG_INITRAMFS_SOURCE="' + str(args.cpio.resolve()) + '"')
    if args.integer_binfmt:
        if changed.count('# CONFIG_BINFMT_MISC is not set') != 1:
            raise ValueError('Unexpected baseline binfmt configuration')
        changed = changed.replace('# CONFIG_BINFMT_MISC is not set', 'CONFIG_BINFMT_MISC=y')
    (build / '.config').write_text(changed)
    toolchain = args.bootstrap / TOOLCHAIN
    compiler_prefix = str(toolchain / 'bin/aarch64-openwrt-linux-musl-')
    wrappers = {}
    for name, program in [('hostcc', 'gcc'), ('hostcxx', 'g++')]:
        wrapper = work / name
        command = [str(args.host_prefix / 'usr/bin' / program), '--sysroot=' + str(args.host_prefix),
                   '-isystem', str(args.host_prefix / 'usr/include/x86_64-linux-gnu')]
        wrapper.write_text('#!/usr/bin/python3\nimport os,sys\ncommand=' + repr(command) +
                           '\nos.execv(command[0], command + sys.argv[1:])\n')
        wrapper.chmod(0o755)
        wrappers[name] = wrapper
    env = dict(os.environ, PATH=str(toolchain / 'bin') + ':' + str(args.host_prefix / 'usr/bin') + ':/usr/bin:/bin',
        LD_LIBRARY_PATH=str(args.host_prefix / 'usr/lib/x86_64-linux-gnu'),
        STAGING_DIR=str(args.bootstrap / 'arm64-source/staging_dir'), SOURCE_DATE_EPOCH=str(EPOCH),
        KBUILD_BUILD_USER='builder', KBUILD_BUILD_HOST='buildhost', KBUILD_BUILD_VERSION='1',
        KBUILD_BUILD_TIMESTAMP=datetime.fromtimestamp(EPOCH, timezone.utc).strftime('%a %b %d %H:%M:%S UTC %Y'),
        PKG_CONFIG_SYSROOT_DIR=str(args.host_prefix),
        PKG_CONFIG_LIBDIR=str(args.host_prefix / 'usr/lib/x86_64-linux-gnu/pkgconfig'),
        BISON_PKGDATADIR=str(args.host_prefix / 'usr/share/bison'),
        M4=str(args.host_prefix / 'usr/bin/m4'))
    make = [str(args.host_prefix / 'usr/bin/make'), '-C', str(kernel), 'O=' + str(build),
        'ARCH=arm64', 'CROSS_COMPILE=' + compiler_prefix,
        'HOSTCC=' + str(wrappers['hostcc']), 'HOSTCXX=' + str(wrappers['hostcxx']),
        'HOSTPKGCONFIG=' + str(args.host_prefix / 'usr/bin/pkg-config')]

    def run(label, command):
        with (work / (label + '.log')).open('wb') as output:
            result = subprocess.run(command, env=env, stdout=output, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(label + ' failed; inspect its retained log')

    run('olddefconfig', make + ['olddefconfig'])
    actual = config_values((build / '.config').read_text())
    delta = {key: dict(before=values.get(key), after=actual.get(key))
             for key in values.keys() | actual.keys() if values.get(key) != actual.get(key)}
    (work / 'config-delta.json').write_text(json.dumps(delta, indent=2) + '\n')
    allowed = {'CONFIG_INITRAMFS_SOURCE'}
    if args.integer_binfmt:
        allowed.add('CONFIG_BINFMT_MISC')
        if delta.get('CONFIG_BINFMT_MISC') != dict(before='n', after='y'):
            raise ValueError('Requested built-in binfmt configuration differs')
    if set(delta) != allowed:
        raise ValueError('Unexpected configuration drift; do not build or admit')
    print('FRESH_CONFIGURATION_ADMITTED', json.dumps(delta), flush=True)
    run('compile', make + ['-j4', 'vmlinux', 'modules'])
    vmlinux = build / 'vmlinux'
    header = vmlinux.read_bytes()[:20]
    if header[:6] != b'\x7fELF\x02\x01' or header[18:20] != b'\xb7\0':
        raise ValueError('Wrong kernel ELF architecture')
    release = (build / 'include/config/kernel.release').read_text().strip()
    if release != '6.18.55':
        raise ValueError('Unexpected kernel release')
    modules = {p.relative_to(build).as_posix(): sha(p) for p in build.rglob('*.ko')}
    report = dict(kernel_release=release, baseline_config_sha256=CONFIG_SHA,
        effective_config_sha256=sha(build / '.config'), configuration_delta=delta,
        cpio_sha256=cpio_sha, source_preparation_receipt_sha256=sha(args.prepared / 'result.json'),
        driver_source_sha256=DRIVER_SHA, compiler_sha256=sha(Path(compiler_prefix + 'gcc')),
        vmlinux_sha256=sha(vmlinux), module_symvers_sha256=sha(build / 'Module.symvers'),
        in_tree_module_count=len(modules), in_tree_module_sha256=modules,
        build_command=make + ['-j4', 'vmlinux', 'modules'], full_kernel_built=True,
        matching_module_packages_built=False, matching_root_composed=False,
        final_image_admitted=False, target_executed=False,
        standard_a53_package_compatibility_qualified=False)
    report['integer_binfmt_builtin'] = args.integer_binfmt
    report['external_modules_require_fresh_build'] = args.integer_binfmt
    (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print('FRESH_ARM64_KERNEL_AND_IN_TREE_MODULES_BUILT', len(modules), flush=True)


if __name__ == '__main__':
    main()
