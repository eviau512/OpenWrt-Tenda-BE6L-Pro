# SPDX-License-Identifier: MIT
"""Prepare a private ARM32 intermediate using a separate, signed-root delta initrd.

The old FIT, embedded archive and kernel bytes remain unchanged. A new RAM DTB
supplies the external initrd and disables the wireless module for this handoff.
This is an independent candidate, not inherited runtime qualification.
"""
from pathlib import Path
import argparse
import json
import os
import shutil
import struct
import subprocess
from package_native_netifd_v3 import records, root_digest, sha
from prepare_ramboot import tree
from cpio_selected_files import selected_files
from compose_unattended_ram_v1 import ARM32_FIT

BASE = Path(__file__).resolve().parents[1]


def encode_dtb(blob, nodes):
    start = struct.unpack_from('>I', blob, 8)[0]
    names, strings, body = {}, bytearray(), bytearray()
    def propname(name):
        if name not in names:
            names[name] = len(strings)
            strings.extend(name.encode() + b'\0')
        return names[name]
    def node(path):
        body.extend(struct.pack('>I', 1))
        body.extend((path.rsplit('/', 1)[-1] if path != '/' else '').encode() + b'\0')
        body.extend(bytes(-len(body) % 4))
        for name, value in nodes[path].items():
            body.extend(struct.pack('>III', 3, len(value), propname(name)))
            body.extend(value); body.extend(bytes(-len(body) % 4))
        for child in nodes:
            if child != '/' and (child.rsplit('/', 1)[0] or '/') == path:
                node(child)
        body.extend(struct.pack('>I', 2))
    node('/')
    body.extend(struct.pack('>I', 9))
    result = bytearray(blob[:start]) + body + strings
    for offset, value in ((4, len(result)), (12, start + len(body)), (32, len(strings)), (36, len(body))):
        struct.pack_into('>I', result, offset, value)
    if tree(result) != nodes:
        raise ValueError('Serialized DTB differs')
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('composition', 'baseline-artifact', 'cpio-tool', 'cross-compile', 'work'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    work = a.work.resolve()
    if work.parent != Path('/root') or not work.name.startswith('be6l-arm32-bootstrap-'):
        p.error('Use a fresh /root/be6l-arm32-bootstrap-* directory')
    receipt = json.loads((a.composition / 'result.json').read_text())
    root, baseline = a.composition / 'root', a.composition / 'baseline-root'
    if receipt['installed_packages'] != 215 or not receipt['private_image_identity']:
        raise ValueError('Wrong protected intermediate root')
    if root_digest(root) != receipt['installed_root_records_sha256'] or root_digest(baseline) != receipt['original_root_records_sha256']:
        raise ValueError('Sealed root changed')
    fit, = a.baseline_artifact.glob('*initramfs-kernel.bin')
    if sha(fit) != ARM32_FIT:
        raise ValueError('Wrong original protected FIT')
    old_manifest = json.loads((a.baseline_artifact / 'ramboot/manifest.json').read_text())
    for item in old_manifest['files']:
        if sha(a.baseline_artifact / 'ramboot' / item['name']) != item['sha256']:
            raise ValueError('Original RAM payload changed')
    work.mkdir(mode=0o700)
    before, after = records(baseline), records(root)
    changed = {n for n in before.keys() | after.keys() if before.get(n) != after.get(n)}
    if set(before) - set(after) or changed != set(receipt['changed_root_paths']):
        raise ValueError('Unexpected archive delta')
    paths = set(changed)
    for name in list(paths):
        parent = Path(name).parent
        while str(parent) != '.':
            if (root / parent).is_symlink():
                raise ValueError('Delta path traverses a symlink')
            paths.add(parent.as_posix()); parent = parent.parent
    for path in root.rglob('*'):
        if path.is_dir() and not path.is_symlink():
            old = baseline / path.relative_to(root)
            if not old.is_dir() or old.stat().st_mode & 0o7777 != path.stat().st_mode & 0o7777:
                paths.add(path.relative_to(root).as_posix())
    overlay = work / 'extra.cpio'
    with overlay.open('wb') as output:
        result = subprocess.run([str(a.cpio_tool), '--null', '--reproducible', '-o', '-H', 'newc', '-R', '0:0'],
            cwd=root, input=('\0'.join(sorted(paths)) + '\0').encode(), stdout=output, stderr=subprocess.PIPE)
    (work / 'cpio.log').write_bytes(result.stderr)
    if result.returncode:
        raise RuntimeError('Delta archive creation failed')
    extracted = selected_files(overlay.read_bytes(), changed)
    import hashlib, stat
    for name in changed:
        value, actual = after[name], extracted[name]
        if 'symlink' in value:
            assert stat.S_ISLNK(actual['mode']) and actual['data'].decode() == value['symlink']
        else:
            assert actual['mode'] & 0o7777 == value['mode'] and hashlib.sha256(actual['data']).hexdigest() == value['sha256']
    # Apply the actual delta with the host extractor and compare the entire root.
    validation = work / 'overlay-validation-root'
    shutil.copytree(baseline, validation, symlinks=True)
    result = subprocess.run([str(a.cpio_tool), '-idmu', '--quiet', '--no-preserve-owner', '-F', str(overlay)],
        cwd=validation, capture_output=True)
    (work / 'overlay-validation.log').write_bytes(result.stdout + result.stderr)
    if result.returncode or root_digest(validation) != receipt['installed_root_records_sha256']:
        raise ValueError('Applied delta does not reproduce the entire signed root')
    for name in ('openwrt-kernel', 'kexec', 'ld-musl-arm.so.1', 'libz.so.1'):
        shutil.copyfile(a.baseline_artifact / 'ramboot' / name, work / name)
    raw_dtb = (a.baseline_artifact / 'ramboot/openwrt-ramonly.dtb').read_bytes()
    nodes = tree(raw_dtb)
    nodes['/chosen']['bootargs'] = b'console=ttyS0,115200 earlycon panic=10 module_blacklist=mt7996e\0'
    if 'bootargs-override' in nodes['/chosen']:
        nodes['/chosen']['bootargs-override'] = nodes['/chosen']['bootargs']
    nodes['/chosen']['linux,initrd-start'] = struct.pack('>I', 0x94000000)
    nodes['/chosen']['linux,initrd-end'] = struct.pack('>I', 0x94000000 + overlay.stat().st_size)
    (work / 'board.dtb').write_bytes(encode_dtb(raw_dtb, nodes))
    assert sum('read-only' in props for props in nodes.values()) == 10
    assert any('airoha,bmt-read-only' in props for props in nodes.values())
    compiler = str(a.cross_compile) + 'gcc'
    source = BASE / 'tools/arm64/ram32_initrd_loader.c'
    result = subprocess.run([compiler, '-static', '-Os', '-Wall', '-Wextra', '-Werror',
        '-DKSIZE=' + str((work / 'openwrt-kernel').stat().st_size),
        '-DDSIZE=' + str((work / 'board.dtb').stat().st_size), '-DISIZE=' + str(overlay.stat().st_size),
        str(source), '-o', str(work / 'ram32-initrd-loader')], capture_output=True)
    (work / 'loader-build.log').write_bytes(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError('ARM32 loader compile failed')
    names = ['openwrt-kernel', 'board.dtb', 'extra.cpio', 'ram32-initrd-loader', 'kexec', 'ld-musl-arm.so.1', 'libz.so.1']
    report = dict(original_fit_sha256=ARM32_FIT, composition_receipt_sha256=sha(a.composition / 'result.json'),
        root_records_sha256=receipt['installed_root_records_sha256'], overlay_sha256=sha(overlay),
        overlay_reproduces_entire_signed_root=True, overlay_payload_paths_verified=len(changed),
        installed_packages=215, original_kernel_unchanged=True, kernel_bytes=(work / 'openwrt-kernel').stat().st_size,
        dtb_readonly_partitions=10, bmt_readonly=True, wireless_module_blacklisted=True,
        segments=[[0x80088000, 0x178000], [0x80200000, ((work / 'openwrt-kernel').stat().st_size - 0x178000 + 4095) & ~4095],
                  [0x86ee3000, ((work / 'board.dtb').stat().st_size + 4095) & ~4095],
                  [0x94000000, (overlay.stat().st_size + 4095) & ~4095]],
        files=[dict(name=n, size=(work/n).stat().st_size, sha256=sha(work/n),
                    md5=hashlib.md5((work/n).read_bytes()).hexdigest()) for n in names],
        kernel_load_address='0x80088000', private_server_identity=True,
        booted=False, reset_recovery_qualified=False, flash_operations=False)
    (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print('UNATTENDED_ARM32_INTERMEDIATE_STATIC_CHECKED', overlay.stat().st_size, flush=True)


if __name__ == '__main__':
    main()
