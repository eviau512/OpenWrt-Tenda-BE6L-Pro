# SPDX-License-Identifier: MIT
"""Finish an owned kernel build with its signed module root and a RAM-only FIT.

This updates only the explicitly supplied fresh build directory. Its earlier
receipt is preserved as a predecessor; the final receipt describes the updated
Image. External wireless modules are retained, not described as freshly built.
No target connection or boot operation is performed.
"""
from pathlib import Path
from datetime import datetime, timezone
import argparse
import json
import lzma
import os
import shutil
import struct
import subprocess
from build_fresh_arm64_kernel_v1 import config_values, sha, TOOLCHAIN, EPOCH
from package_native_netifd_v3 import root_digest
from prepare_ramboot import tree, text, image
from verify_embedded_compat_cpio import verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('prepared', 'kernel-build', 'composition', 'archive', 'bootstrap',
                 'host-prefix', 'dtc', 'mkimage', 'lzma', 'work'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--previous-image', type=Path,
                        help='Prior final receipt for a subsequent owned CPIO-only rebuild')
    args = parser.parse_args()
    work = args.work.resolve()
    if work.parent != Path('/root') or not work.name.startswith('be6l-final-image-'):
        parser.error('Use a fresh /root/be6l-final-image-* directory')
    build = args.kernel_build / 'build'
    prior_path = args.kernel_build / 'result.json'
    prior = json.loads(prior_path.read_text())
    component = json.loads((args.composition / 'result.json').read_text())
    archive = json.loads((args.archive / 'result.json').read_text())
    layout = json.loads((args.composition / 'module-layout.json').read_text())
    root = args.composition / 'root'
    cpio = args.archive / 'native.cpio'
    if not prior['full_kernel_built'] or not component['matching_root_composed']:
        raise ValueError('Incomplete source/build/package admission')
    if component['source_kernel_build_receipt_sha256'] != sha(prior_path):
        raise ValueError('Package root is for another kernel build')
    if args.previous_image:
        previous = json.loads((args.previous_image / 'result.json').read_text())
        if sha(build / '.config') != previous['kernel_config_sha256'] or sha(build / 'arch/arm64/boot/Image') != previous['kernel_sha256']:
            raise ValueError('Owned build changed since the previous Image')
    elif sha(build / '.config') != prior['effective_config_sha256'] or sha(build / 'vmlinux') != prior['vmlinux_sha256']:
        raise ValueError('Owned build changed since initial compilation')
    if not layout['passed'] or layout['module_count'] != 84 or layout['kernel_config_sha256'] != sha(build / '.config'):
        raise ValueError('Final module layout admission missing or stale')
    root_pin = component['installed_root_records_sha256']
    if root_digest(root) != root_pin or archive['roots']['native']['root_records_sha256'] != root_pin:
        raise ValueError('Root changed since signed composition')
    if sha(cpio) != archive['roots']['native']['cpio_sha256']:
        raise ValueError('Final CPIO changed')
    for name in ('dtc', 'mkimage', 'lzma'):
        path = getattr(args, name)
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError('Missing executable image tool: ' + name)
    before_modules = {p.relative_to(build).as_posix(): sha(p) for p in build.rglob('*.ko')}
    if before_modules != prior['in_tree_module_sha256']:
        raise ValueError('Compiled modules changed since packaging')
    work.mkdir(mode=0o700)
    shutil.copyfile(prior_path, work / 'predecessor-build.json')
    shutil.copyfile(build / '.config', work / 'predecessor.config')
    old = (build / '.config').read_text()
    values = config_values(old)
    (build / '.config').write_text(old.replace('CONFIG_INITRAMFS_SOURCE=' + values['CONFIG_INITRAMFS_SOURCE'],
        'CONFIG_INITRAMFS_SOURCE="' + str(cpio.resolve()) + '"'))
    sdk = args.prepared / 'openwrt'
    kernel = args.prepared / 'kernel-source/linux-6.18.55'
    cross = str(args.bootstrap / TOOLCHAIN / 'bin/aarch64-openwrt-linux-musl-')
    env = dict(os.environ, PATH=str(args.dtc.parent) + ':' + str(args.host_prefix / 'usr/bin') + ':/usr/bin:/bin',
        LD_LIBRARY_PATH=str(args.host_prefix / 'usr/lib/x86_64-linux-gnu'),
        STAGING_DIR=str(args.bootstrap / 'arm64-source/staging_dir'), SOURCE_DATE_EPOCH=str(EPOCH),
        KBUILD_BUILD_USER='builder', KBUILD_BUILD_HOST='buildhost', KBUILD_BUILD_VERSION='1',
        KBUILD_BUILD_TIMESTAMP=datetime.fromtimestamp(EPOCH, timezone.utc).strftime('%a %b %d %H:%M:%S UTC %Y'),
        BISON_PKGDATADIR=str(args.host_prefix / 'usr/share/bison'), M4=str(args.host_prefix / 'usr/bin/m4'))
    make = [str(args.host_prefix / 'usr/bin/make'), '-C', str(kernel), 'O=' + str(build),
        'ARCH=arm64', 'CROSS_COMPILE=' + cross, 'HOSTCC=' + str(args.kernel_build / 'hostcc'),
        'HOSTCXX=' + str(args.kernel_build / 'hostcxx'),
        'HOSTPKGCONFIG=' + str(args.host_prefix / 'usr/bin/pkg-config')]

    def run(label, command):
        with (work / (label + '.log')).open('wb') as output:
            result = subprocess.run([str(x) for x in command], env=env, stdout=output, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(label + ' failed; retained log is authoritative')

    run('olddefconfig', make + ['olddefconfig'])
    actual = config_values((build / '.config').read_text())
    delta = {key: dict(before=values.get(key), after=actual.get(key))
             for key in values.keys() | actual.keys() if values.get(key) != actual.get(key)}
    if set(delta) != {'CONFIG_INITRAMFS_SOURCE'}:
        raise ValueError('Unexpected final-image configuration change')
    run('image', make + ['-j4', 'Image'])
    data = (build / 'arch/arm64/boot/Image').read_bytes()
    if data[0x38:0x3c] != b'ARMd':
        raise ValueError('Not an ARM64 Image')
    _, effective, _ = struct.unpack_from('<QQQ', data, 8)
    if not effective >= len(data) or not 0x80200000 + effective <= 0x84000000:
        raise ValueError('Effective Image overlaps the unchanged NPU reservation')
    embedded = verify(build, data, cpio)
    if before_modules != {p.relative_to(build).as_posix(): sha(p) for p in build.rglob('*.ko')}:
        raise ValueError('Module objects changed during final image build')
    if sha(build / 'Module.symvers') != prior['module_symvers_sha256']:
        raise ValueError('Exported symbol table changed')
    shutil.copyfile(build / 'arch/arm64/boot/Image', work / 'Image')
    dts_dir = sdk / 'target/linux/airoha/dts'
    dts = dts_dir / 'an7563-tenda-be6l-pro.dts'
    dtb = work / 'openwrt.dtb'
    run('dts-preprocess', [cross + 'cpp', '-nostdinc', '-x', 'assembler-with-cpp',
        '-I' + str(dts_dir), '-I' + str(dts_dir / 'include'), '-I' + str(kernel / 'include'),
        '-I' + str(kernel / 'scripts/dtc/include-prefixes'), '-undef', '-D__DTS__',
        '-o', work / 'board.tmp', dts])
    run('dtb', [args.dtc, '-O', 'dtb', '-i' + str(dts_dir), '-o', dtb, work / 'board.tmp'])
    board = tree(dtb.read_bytes())
    if b'tenda,be6l-pro\0' not in board['/']['compatible'] or sum('read-only' in p for p in board.values()) != 10:
        raise ValueError('Board or ten MTD guards differ')
    if not any('airoha,bmt-read-only' in p for p in board.values()):
        raise ValueError('BMT read-only guard missing')
    run('lzma', [args.lzma, 'e', work / 'Image', '-lc1', '-lp2', '-pb2', work / 'Image.lzma'])
    run('mkits', ['/bin/sh', sdk / 'scripts/mkits.sh', '-D', 'tenda_be6l-pro',
        '-o', work / 'kernel.its', '-k', work / 'Image.lzma', '-C', 'lzma', '-d', dtb,
        '-a', '0x80200000', '-e', '0x80200000', '-c', 'config-1', '-A', 'arm64', '-v', '6.18.55'])
    fit = work / 'openwrt-airoha-an7563a64-tenda_be6l-pro-initramfs-kernel.bin'
    run('mkimage', [args.mkimage, '-f', work / 'kernel.its', fit])
    nodes = tree(fit.read_bytes())
    refs = nodes['/configurations/' + text(nodes['/configurations']['default'])]
    packed, props = image(nodes, text(refs['kernel']))
    final_dtb, _ = image(nodes, text(refs['fdt']))
    if text(props['arch']) != 'arm64' or text(props['compression']) != 'lzma' or any(
            int.from_bytes(props[key], 'big') != 0x80200000 for key in ('load', 'entry')):
        raise ValueError('FIT architecture/compression/addresses differ')
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    decoded = decoder.decompress(packed, max_length=0x3e00000)
    if not decoder.eof or decoder.unused_data or decoded != data or final_dtb != dtb.read_bytes():
        raise ValueError('Actual FIT payloads differ')
    if root_digest(root) != root_pin:
        raise ValueError('Package root changed during image creation')
    report = dict(image=fit.name, image_sha256=sha(fit), image_bytes=fit.stat().st_size,
        kernel_sha256=sha(work / 'Image'), kernel_bytes=len(data), kernel_effective_bytes=effective,
        vmlinux_sha256=sha(build / 'vmlinux'),
        kernel_headroom_bytes=0x84000000 - 0x80200000 - effective,
        kernel_config_sha256=sha(build / '.config'), configuration_delta=delta,
        external_cpio_sha256=sha(cpio), **embedded,
        composition_receipt_sha256=sha(args.composition / 'result.json'),
        root_records_sha256=root_pin, installed_packages=component['installed_packages'],
        rebuilt_in_tree_modules=component['rebuilt_module_count'],
        retained_external_modules=component['retained_external_module_count'],
        unchanged_compiled_module_objects=True, module_layout_audit=layout,
        image_tool_sha256={name: sha(getattr(args, name)) for name in ('dtc', 'mkimage', 'lzma')},
        dtb_sha256=sha(dtb), dtb_readonly_partitions=10, bmt_readonly=True,
        openwrt_image_recipe_commands=True, full_sdk_admitted=False,
        static_image_admission=True, candidate_loader_fixture_executed=False,
        recovery_daemon_target_qualified=False, target_executed=False,
        standard_a53_package_compatibility_qualified=False, routed_nat_qualified=False)
    (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print('MATCHING_ARM64_FIT_STATIC_ADMISSION_PASSED', report['image_sha256'], flush=True)


if __name__ == '__main__':
    main()
