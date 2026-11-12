# SPDX-License-Identifier: MIT
"""Decode the exact 42-block CPIO stream with actual Linux XZ Embedded C.

Host-only codec/wrapper evidence. Uses the supported userspace configuration
hook and private static GCC; never changes a source tree, package installation,
kernel configuration, image or device. It cannot qualify target RAM or boot.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import time
import zlib

EXPECTED_BYTES = 130342912
EXPECTED_CPIO = '99284164b4f338608c61b8130424625797ff1f28e993a60831a351c5ca61d472'


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as incoming:
        for block in iter(lambda: incoming.read(1024*1024), b''):
            digest.update(block)
    return digest.hexdigest()


def vli(data, offset):
    value = 0
    for shift in range(0, 63, 7):
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise ValueError('Invalid bounded XZ VLI')


def stream_layout(data):
    if data[:8] != b'\xfd7zXZ\x00\x00\x01' or data[-2:] != b'YZ':
        raise ValueError('Need the exact single CRC32 XZ stream')
    index_size = (struct.unpack_from('<I', data, len(data)-8)[0]+1)*4
    index_start = len(data)-12-index_size
    if data[index_start] != 0:
        raise ValueError('Missing XZ Index marker')
    count, position = vli(data, index_start+1)
    records = []
    for _ in range(count):
        unpadded, position = vli(data, position)
        uncompressed, position = vli(data, position)
        records.append((unpadded, uncompressed))
    if count != 42 or sum(x[1] for x in records) != EXPECTED_BYTES or 12+sum((x[0]+3)&~3 for x in records) != index_start:
        raise ValueError('Not the admitted 42-block, 130342912-byte stream')
    header_size = (data[12]+1)*4
    flags = data[13]
    if flags & 3:
        raise ValueError('Need exactly one filter in the first Block')
    position = 14
    for flag in (0x40, 0x80):
        if flags & flag:
            _, position = vli(data, position)
    filter_id, position = vli(data, position)
    properties_size, position = vli(data, position)
    if filter_id != 0x21 or properties_size != 1 or data[position] != 16 or position >= 12+header_size-4:
        raise ValueError('Need the admitted 1MiB LZMA2 dictionary property')
    return dict(blocks=count, first_uncompressed=records[0][1],
        first_check_offset=12+((records[0][0]+3)&~3)-4,
        first_header_size=header_size, dictionary_property_offset=position)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel-source', type=Path, required=True)
    p.add_argument('--compression', type=Path, required=True)
    p.add_argument('--host-prefix', type=Path, required=True)
    p.add_argument('--work', type=Path, required=True)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not re.fullmatch('be6l-xz-decoder-host-20261113-[a-z0-9-]+', w.name) or w.exists():
        p.error('Use a fresh /root/be6l-xz-decoder-host-20261113-* directory')
    source = Path(__file__).resolve().parents[1]/'experiments/xz-decoder-host'
    receipt = json.loads((a.compression/'result.json').read_text())
    cpio = Path(receipt['input_cpio']['path'])
    compressed = a.compression/'native.xz'
    if (receipt['input_cpio']['bytes'] != EXPECTED_BYTES or cpio.stat().st_size != EXPECTED_BYTES or
            receipt['input_cpio']['sha256'] != EXPECTED_CPIO or sha(cpio) != EXPECTED_CPIO or
            sha(compressed) != receipt['streams']['native.xz']['sha256']):
        raise ValueError('Exact CPIO or compressor receipt binding differs')
    data = compressed.read_bytes()
    layout = stream_layout(data)
    with cpio.open('rb') as incoming:
        original_first_check = zlib.crc32(incoming.read(layout['first_uncompressed']))
    if struct.unpack_from('<I', data, layout['first_check_offset'])[0] != original_first_check:
        raise ValueError('First Block CRC offset does not match the original CPIO')
    files = ['lib/decompress_unxz.c', 'include/linux/xz.h', 'lib/xz/xz_private.h',
             'lib/xz/xz_stream.h', 'lib/xz/xz_lzma2.h', 'lib/xz/xz_crc32.c',
             'lib/xz/xz_dec_stream.c', 'lib/xz/xz_dec_lzma2.c', 'lib/xz/xz_dec_bcj.c']
    pins = {name: sha(a.kernel_source/name) for name in files}
    w.mkdir(mode=0o700)
    (w/'include/linux').mkdir(parents=True)
    shutil.copyfile(a.kernel_source/'include/linux/xz.h', w/'include/linux/xz.h')
    env = dict(os.environ, PATH=str(a.host_prefix/'usr/bin')+':/usr/bin:/bin',
               LD_LIBRARY_PATH=str(a.host_prefix/'usr/lib/x86_64-linux-gnu'))
    binary = w/'kernel-xz-host'
    command = [str(a.host_prefix/'usr/bin/gcc'), '--sysroot='+str(a.host_prefix), '-static',
        '-isystem', str(a.host_prefix/'usr/include/x86_64-linux-gnu'),
        '-L'+str(a.host_prefix/'usr/lib/x86_64-linux-gnu'),
        '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-unused-parameter',
        '-I'+str(source), '-I'+str(w/'include'),
        '-DBE6L_UNXZ_SOURCE="'+str(a.kernel_source/'lib/decompress_unxz.c')+'"',
        str(source/'kernel-xz-host.c'), '-o', str(binary)]
    compiled = subprocess.run(command, env=env, capture_output=True)
    (w/'compile.log').write_bytes(compiled.stdout+compiled.stderr)
    if compiled.returncode:
        raise RuntimeError('Exact Linux userspace XZ harness compilation failed; inspect compile.log')
    elf = binary.read_bytes()
    if elf[:6] != b'\x7fELF\x02\x01' or elf[18:20] != b'\x3e\0':
        raise ValueError('Host harness is not x86-64 ELF')
    phoff = struct.unpack_from('<Q', elf, 32)[0]
    stride, count = struct.unpack_from('<HH', elf, 54)
    if stride < 56 or not count or phoff+stride*count > len(elf) or any(
            struct.unpack_from('<I', elf, phoff+i*stride)[0] in (2, 3) for i in range(count)):
        raise ValueError('Host harness is not statically linked')
    crc_bad = bytearray(data)
    crc_bad[layout['first_check_offset']] ^= 1
    crc_path = w/'bad-first-block-crc.xz'
    crc_path.write_bytes(crc_bad)
    dictionary_bad = bytearray(data)
    dictionary_bad[layout['dictionary_property_offset']] = 18  # 2MiB, no payload alteration.
    header_end = 12+layout['first_header_size']
    struct.pack_into('<I', dictionary_bad, header_end-4, zlib.crc32(dictionary_bad[12:header_end-4]))
    dictionary_path = w/'declared-dictionary-2m.xz'
    dictionary_path.write_bytes(dictionary_bad)
    cap = 1024*1024+128*1024
    cases = {}

    def run(label, mode, input_path, expected_return, output_name=None, limit=0, allocation_cap=cap):
        output = w/output_name if output_name else None
        argv = [str(binary), mode, str(input_path), str(output) if output else '-',
                str(1024*1024), str(allocation_cap), str(limit)]
        start = time.monotonic()
        result = subprocess.run(argv, env=env, capture_output=True, timeout=120)
        elapsed = time.monotonic()-start
        (w/(label+'.stdout')).write_bytes(result.stdout)
        (w/(label+'.stderr')).write_bytes(result.stderr)
        if result.returncode:
            raise RuntimeError(label+' host harness failed; inspect private logs')
        observed = json.loads(result.stdout)
        passed = (observed['return_code'] == expected_return and not observed['output_error'] and
                  observed['live_payload'] == observed['live_total'] == observed['live_blocks'] == 0 and
                  observed['peak_with_adapter_headers'] <= allocation_cap)
        if output:
            observed['decoded_sha256'] = sha(output)
            observed['decoded_file_bytes'] = output.stat().st_size
            passed = (passed and observed['output_bytes'] == observed['decoded_file_bytes'] == EXPECTED_BYTES and
                      observed['decoded_sha256'] == EXPECTED_CPIO and
                      observed['consumed'] == input_path.stat().st_size)
            observed['output_retained'] = label == 'actual-wrapper-valid'
            if not observed['output_retained']:
                output.unlink()  # Explicit newly created private output, never a source path.
        observed.update(passed=passed, expected_return_code=expected_return, elapsed_host_seconds=elapsed,
                        mode=mode, input=str(input_path), input_limit=limit, command=argv)
        cases[label] = observed
        return observed

    run('actual-wrapper-valid', 'wrapper', compressed, 0, 'decoded.cpio')
    run('codec-dict-limit-1m-valid', 'codec', compressed, 1, 'decoded-codec.cpio')
    run('actual-wrapper-fill-valid', 'wrapper-fill', compressed, 0, 'decoded-fill.cpio')
    run('codec-truncated-footer', 'codec', compressed, 8, limit=len(data)-1)
    run('codec-wrong-block-crc', 'codec', crc_path, 7)
    truncated_wrapper = run('actual-wrapper-truncated-footer', 'wrapper', compressed, -1, limit=len(data)-1)
    crc_wrapper = run('actual-wrapper-wrong-block-crc', 'wrapper', crc_path, -1)
    truncated_wrapper['passed'] = truncated_wrapper['passed'] and truncated_wrapper['wrapper_error'] == 1
    crc_wrapper['passed'] = crc_wrapper['passed'] and crc_wrapper['wrapper_error'] == 1
    oversized = run('codec-over-dict-limit', 'codec', dictionary_path, 4)
    oversized['passed'] = oversized['passed'] and oversized['output_bytes'] == 0 and oversized['max_request'] < 1024*1024
    # The unchanged wrapper deliberately permits larger dictionaries: this is
    # a policy contrast, not a claim that the kernel wrapper rejects >1MiB.
    wrapper_large = run('actual-wrapper-allows-dict-2m', 'wrapper', dictionary_path, 0,
                        'decoded-dict-2m.cpio', allocation_cap=3*1024*1024)
    wrapper_large['passed'] = wrapper_large['passed'] and wrapper_large['max_request'] == 2*1024*1024
    failed_codec = run('codec-allocation-cap', 'codec', compressed, 3, allocation_cap=65536)
    failed_wrapper = run('actual-wrapper-allocation-cap', 'wrapper', compressed, -1, allocation_cap=65536)
    failed_codec['passed'] = failed_codec['passed'] and failed_codec['denied'] > 0
    failed_wrapper['passed'] = failed_wrapper['passed'] and failed_wrapper['denied'] > 0 and failed_wrapper['wrapper_error'] == 1
    unchanged = all(sha(a.kernel_source/name) == digest for name, digest in pins.items())
    report = dict(scope='Host exact Linux XZ Embedded decoder and unchanged unxz body, with supported userspace services',
        kernel_source=str(a.kernel_source), source_files_sha256=pins, kernel_sources_unchanged=unchanged,
        harness_sha256=sha(source/'kernel-xz-host.c'), adaptation_header_sha256=sha(source/'xz_config.h'),
        compile_command=command, host_binary_sha256=sha(binary), static_host_binary=True,
        source_compression_receipt_sha256=sha(a.compression/'result.json'), input_xz_sha256=sha(compressed),
        expected_cpio_sha256=EXPECTED_CPIO, expected_cpio_bytes=EXPECTED_BYTES, stream_layout=layout,
        cases=cases, passed=sum(item['passed'] for item in cases.values()), total=len(cases),
        actual_wrapper_dictionary_max='UINT32_MAX in multi-call mode; no 1MiB policy cap',
        configured_codec_dictionary_max=1024*1024,
        memory_scope='Tracked host decoder/wrapper allocation payload plus adapter headers; excludes mmap input, stack, libc, code and kernel allocator overhead',
        valid_stream_peak_allocation_bytes=cases['actual-wrapper-valid']['peak_with_adapter_headers'],
        valid_stream_allocation_bound_bytes=cap, target_decompression_memory_measured=False,
        target_executed=False, boot_qualified=False, kernel_configuration_qualified=False,
        kernel_built=False, all_modules_qualified=False, cpio_Image_admission_qualified=False)
    (w/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print('HOST_ACTUAL_KERNEL_XZ_DECODER_RESULTS', report['passed'], '/', report['total'],
          'decoded_sha256='+cases['actual-wrapper-valid'].get('decoded_sha256', ''), flush=True)
    if not unchanged or report['passed'] != report['total']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
