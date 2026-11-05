# SPDX-License-Identifier: MIT
"""Bind a fresh matched ARM64 FIT to its exact root and tested handoff inputs.

Creates a new private RAM payload, without any device call. The established
BL31 entry trampoline, fallback and kexec executor bytes remain unchanged.
Only the allowlisted RAM boot arguments and size-compiled loader are new.
"""
from pathlib import Path
import argparse
import hashlib
import json
import lzma
import shutil
import stat
import struct
import subprocess
import tarfile
from package_native_netifd_v3 import root_digest, sha
from prepare_ramboot import tree, image, text
from prepare_unattended_intermediate_v1 import encode_dtb
from verify_embedded_compat_cpio import verify

BASE = Path(__file__).resolve().parents[1]
PINS = {
    'entry.bin': '8d9ca98a6b6d6710654c45f01d6f0acbb6af6391b09b22872ce5b720243969ae',
    'arm32-fallback': 'baba295f687c384de15fe080d0f3cbd6c6761327ad0b6a7542f88c8744de9917',
    'kexec': '77c7f3177a8455f787bf4972217388ed6ec48be971e19b43e4edab7b4beeb028',
    'ld-musl-arm.so.1': '195a3353cbbbb1b586e62aa1b6dd4a746eb774219636a5fb847a622fd548b8c9',
}
FIXTURE_SHA = '2e4b0d6721134893c2a7256c0d3d4d4473b91a8a403534550dfd96664df24bcd'


def admit_image(data, props, dtb):
    if data[0x38:0x3c] != b'ARMd' or text(props['arch']) != 'arm64':
        raise ValueError('Wrong architecture')
    if any(int.from_bytes(props[key], 'big') != 0x80200000 for key in ('load', 'entry')):
        raise ValueError('Changed FIT load/entry address')
    offset, size, flags = struct.unpack_from('<QQQ', data, 8)
    if not size >= len(data) or flags & 1 or (0x80200000 - offset) % 0x200000:
        raise ValueError('Invalid ARM64 Image header')
    if 0x80200000 + size > 0x84000000:
        raise ValueError('Effective allocation overlaps NPU reservation')
    nodes = tree(dtb)
    if b'tenda,be6l-pro\0' not in nodes['/']['compatible']:
        raise ValueError('Wrong board')
    if sum('read-only' in p for p in nodes.values()) != 10 or not any('airoha,bmt-read-only' in p for p in nodes.values()):
        raise ValueError('Missing MTD/BMT guard')
    if nodes['/reserved-memory/npu-firmware@84000000']['reg'] != struct.pack('>II', 0x84000000, 0x400000):
        raise ValueError('Changed NPU reservation')
    return dict(text_offset=offset, effective_size=size, flags=flags)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('candidate', 'composition', 'archive', 'kernel', 'runtime-test',
                 'baseline-payload', 'prior-loader-fixture', 'cross-compile', 'work'):
        parser.add_argument('--' + name, type=Path, required=True)
    a = parser.parse_args()
    work = a.work.resolve()
    if work.parent != Path('/root') or not work.name.startswith('be6l-candidate-ramboot-'):
        parser.error('Use a fresh /root/be6l-candidate-ramboot-* directory')
    report = json.loads((a.candidate / 'result.json').read_text())
    composition = json.loads((a.composition / 'result.json').read_text())
    tested = json.loads((a.runtime_test / 'result.json').read_text())
    root = a.composition / 'root'
    root_pin = root_digest(root)
    if root_pin != report['root_records_sha256'] or root_pin != composition['installed_root_records_sha256']:
        raise ValueError('Candidate root seal changed')
    if tested['source_root_records_sha256'] != root_pin or not all(tested['native_vm_modules_mapped'].values()):
        raise ValueError('Wrong real native netifd runtime fixture')
    if not all(tested[k] for k in ('actual_aarch64_runtime', 'separate_network_namespace',
                                  'host_netns_unchanged', 'ubus_network_objects_registered')):
        raise ValueError('Incomplete real runtime evidence')
    if sha(a.prior_loader_fixture) != FIXTURE_SHA:
        raise ValueError('Wrong previously qualified loader fixture')
    prior_paths = 0
    with tarfile.open(a.prior_loader_fixture) as stream:
        for member in stream:
            if member.name == 'opt/be6l-curl-init-probe':
                continue  # Test-only executable, never an image payload.
            path = Path(member.name)
            if path.is_absolute() or '..' in path.parts:
                raise ValueError('Unsafe prior fixture path')
            actual = root / path
            if stat.S_IMODE(actual.lstat().st_mode) != member.mode:
                raise ValueError('Changed prior loader mode: ' + member.name)
            if member.issym():
                if not actual.is_symlink() or str(actual.readlink()) != member.linkname:
                    raise ValueError('Changed prior loader symlink')
            elif member.isfile():
                if sha(actual) != hashlib.sha256(stream.extractfile(member).read()).hexdigest():
                    raise ValueError('Changed qualified loader bytes: ' + member.name)
            else:
                raise ValueError('Unexpected fixture node')
            prior_paths += 1
    fit = a.candidate / report['image']
    if sha(fit) != report['image_sha256'] or not report['embedded_cpio_verified']:
        raise ValueError('Candidate FIT changed')
    nodes = tree(fit.read_bytes())
    refs = nodes['/configurations/' + text(nodes['/configurations']['default'])]
    packed, props = image(nodes, text(refs['kernel']))
    dtb, _ = image(nodes, text(refs['fdt']))
    if text(props['compression']) != 'lzma':
        raise ValueError('Wrong FIT compression')
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    data = decoder.decompress(packed, max_length=0x3e00000)
    if not decoder.eof or decoder.unused_data or hashlib.sha256(data).hexdigest() != report['kernel_sha256']:
        raise ValueError('Decoded FIT kernel differs')
    header = admit_image(data, props, dtb)
    cpio = a.archive / 'native.cpio'
    if sha(cpio) != report['external_cpio_sha256'] or sha(a.kernel / '.config') != report['kernel_config_sha256']:
        raise ValueError('CPIO or current kernel build changed')
    embedded = verify(a.kernel, data, cpio)
    for name, pin in PINS.items():
        if sha(a.baseline_payload / name) != pin:
            raise ValueError('Proven handoff input changed: ' + name)
    work.mkdir(mode=0o700)
    (work / 'Image').write_bytes(data)
    for name in PINS:
        shutil.copyfile(a.baseline_payload / name, work / name)
    board = tree(dtb)
    changed = []
    for key in ('bootargs', 'bootargs-override'):
        if key in board['/chosen']:
            board['/chosen'][key] = b'console=ttyS0,115200 earlycon panic=10\0'
            changed.append(key)
    if 'bootargs' not in changed:
        raise ValueError('Missing established console boot arguments')
    (work / 'board.dtb').write_bytes(encode_dtb(dtb, board))
    source = BASE / 'tools/arm64/linux64_kexec_loader.c'
    command = [str(a.cross_compile) + 'gcc', '-static', '-Os', '-Wall', '-Wextra', '-Werror',
        '-DKSIZE64=' + str(len(data)), '-DMEMSIZE64=' + str(header['effective_size']),
        '-DDSIZE=' + str((work / 'board.dtb').stat().st_size), str(source), '-o', str(work / 'linux64-kexec-loader')]
    result = subprocess.run(command, capture_output=True)
    (work / 'loader-build.log').write_bytes(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError('Size-compiled ARM32 loader failed')
    elf = (work / 'linux64-kexec-loader').read_bytes()
    if elf[:6] != b'\x7fELF\x01\x01' or struct.unpack_from('<HH', elf, 16) != (2, 40):
        raise ValueError('Wrong loader ELF')
    phoff = struct.unpack_from('<I', elf, 28)[0]
    stride, count = struct.unpack_from('<HH', elf, 42)
    if any(struct.unpack_from('<I', elf, phoff + i * stride)[0] == 3 for i in range(count)):
        raise ValueError('Loader is not static')
    sizes = [(0x80200000, header['effective_size']), (0x86ee3000, (work / 'board.dtb').stat().st_size),
             (0x90000000, 34657408), (0x87f00000, 4096)]
    segments = [(address, (size + 4095) & ~4095) for address, size in sizes]
    for i, (address, size) in enumerate(segments):
        for other, length in segments[i + 1:]:
            if not (address + size <= other or other + length <= address):
                raise ValueError('Overlapping RAM segments')
    names = ['Image', 'board.dtb', 'entry.bin', 'linux64-kexec-loader', 'arm32-fallback', 'kexec', 'ld-musl-arm.so.1']
    output = dict(board='tenda,be6l-pro', flash='read-only', fit_sha256=report['image_sha256'],
        kernel_header=header, entry='0x87f00000', linux_entry='0x80200000', segments=segments,
        root_records_sha256=root_pin, prior_loader_paths_unchanged=prior_paths,
        native_netifd_real_isolated_runtime=True, full_default_service_qualified=False,
        embedded_cpio=embedded, dtb_changed_properties=['/chosen/' + key for key in changed],
        loader_source_sha256=sha(source), candidate_receipt_sha256=sha(a.candidate / 'result.json'),
        runtime_test_receipt_sha256=sha(a.runtime_test / 'result.json'),
        files=[dict(name=n, size=(work/n).stat().st_size, sha256=sha(work/n),
                    md5=hashlib.md5((work/n).read_bytes()).hexdigest()) for n in names], executed=False)
    (work / 'manifest.json').write_text(json.dumps(output, indent=2) + '\n')
    print('MATCHED_ARM64_CANDIDATE_PAYLOAD_PREPARED', output['fit_sha256'], flush=True)


if __name__ == '__main__':
    main()
