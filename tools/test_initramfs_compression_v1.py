# SPDX-License-Identifier: MIT
"""Bounded host regressions for the explicit initramfs codec/config gates.

Verifies one existing real gzip Image and an independent measured XZ stream.
Small malformed codec fixtures are unit inputs, never fabricated firmware.
No new kernel, package, root, candidate or target acceptance is produced.
"""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import lzma
import struct
import zlib
from build_fresh_arm64_kernel_v1 import (config_values, set_config_values, XZ_CONFIG_UPDATES,
    compression_fields, receipt_compression, admit_build_config, admit_compression_config,
    recipe_hashes, require_raw_cpio, sha)
from package_fresh_kernel_v1 import preinitramfs_compression_config, kernel_package_revision, preinit_abi
from verify_embedded_compat_cpio import (decode_initramfs, admit_xz_blocks, verify, vli,
    MAX_XZ_BLOCKS, MAX_CPIO_BYTES, admit_cpio_size)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('kernel-build', 'cpio', 'xz-stream', 'baseline-config', 'preinit-config', 'source', 'work'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    work = a.work.resolve()
    if work.parent != Path('/root') or not work.name.startswith('be6l-initramfs-xz-host-tests-'):
        p.error('Use a fresh /root/be6l-initramfs-xz-host-tests-* directory')
    work.mkdir(mode=0o700)
    tests = {}

    def check(name, operation, reject=False):
        try:
            operation()
        except ValueError as error:
            tests[name] = dict(passed=reject, rejected=True, error=str(error))
        else:
            tests[name] = dict(passed=not reject, rejected=False)

    def equal(actual, expected):
        if actual != expected:
            raise ValueError('Result differs from expectation')

    build = a.kernel_build / 'build'
    expected = a.cpio.read_bytes()
    actual_image = (build / 'arch/arm64/boot/Image').read_bytes()
    check('actual-existing-gzip-object-Image-CPIO', lambda: equal(
        verify(build, actual_image, a.cpio)['embedded_cpio_sha256'], sha(a.cpio)))
    check('actual-measured-XZ-stream-all-blocks', lambda: equal(
        decode_initramfs(a.xz_stream.read_bytes(), expected, 'xz')[0], expected))
    actual_xz_metadata = admit_xz_blocks(a.xz_stream.read_bytes(), len(expected))
    del expected, actual_image

    # The codec unit inputs intentionally exercise arbitrary bytes, not ELF/Image.
    unit = b'070701' + bytes(range(256)) * 128
    gz = gzip.compress(unit, compresslevel=9, mtime=0)
    filters = [dict(id=lzma.FILTER_LZMA2, dict_size=1024 * 1024)]
    xz = lzma.compress(unit, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32, filters=filters)
    for codec, packed in [('gzip', gz), ('xz', xz)]:
        check(codec + '-unit-positive', lambda packed=packed, codec=codec: equal(decode_initramfs(packed, unit, codec)[0], unit))
        for label, malformed in [('truncated', packed[:-1]), ('zero-tail', packed + b'\0' * 4),
                                 ('junk-tail', packed + b'junk'), ('multiple-streams', packed + packed)]:
            check(codec + '-' + label, lambda malformed=malformed, codec=codec: decode_initramfs(malformed, unit, codec), True)
        check(codec + '-wrong-CPIO', lambda packed=packed, codec=codec: decode_initramfs(packed, unit[:-1] + b'x', codec), True)
        check(codec + '-oversized-output', lambda packed=packed, codec=codec: decode_initramfs(packed, unit[:100], codec), True)
        check(codec + '-wrong-receipt-codec', lambda packed=packed, codec=codec: decode_initramfs(packed, unit, 'xz' if codec == 'gzip' else 'gzip'), True)
    bad = bytearray(gz); bad[-8] ^= 1
    check('gzip-bad-data-CRC', lambda: decode_initramfs(bytes(bad), unit, 'gzip'), True)
    for label, position in [('header-CRC', 8), ('footer-CRC', -12), ('block-data-CRC', len(xz) // 2)]:
        bad = bytearray(xz); bad[position] ^= 1
        check('xz-bad-' + label, lambda bad=bad: decode_initramfs(bytes(bad), unit, 'xz'), True)
    crc64 = lzma.compress(unit, check=lzma.CHECK_CRC64, filters=filters)
    check('xz-reject-CRC64', lambda: decode_initramfs(crc64, unit, 'xz'), True)
    wrong_dict = lzma.compress(unit, check=lzma.CHECK_CRC32, filters=[dict(id=lzma.FILTER_LZMA2, dict_size=2 * 1024 * 1024)])
    check('xz-reject-2MiB-dictionary', lambda: decode_initramfs(wrong_dict, unit, 'xz'), True)
    delta_filter = lzma.compress(unit, check=lzma.CHECK_CRC32, filters=[dict(id=lzma.FILTER_DELTA, dist=1)] + filters)
    check('xz-reject-extra-filter', lambda: decode_initramfs(delta_filter, unit, 'xz'), True)
    check('xz-reject-noncanonical-VLI', lambda: vli(b'\x80\0', 0, 2), True)
    check('xz-reject-oversized-VLI', lambda: vli(b'\xff' * 9, 0, 9), True)

    def encoded_vli(value):
        result = bytearray()
        while value >= 128:
            result.append((value & 127) | 128)
            value >>= 7
        result.append(value)
        return bytes(result)

    def index_only(count, uncompressed):
        flags = b'\0\1'
        header = b'\xfd7zXZ\0' + flags + struct.pack('<I', zlib.crc32(flags))
        index = b'\0' + encoded_vli(count) + (b'\x0d' + encoded_vli(uncompressed)) * count
        index += b'\0' * (-len(index) & 3)
        index += struct.pack('<I', zlib.crc32(index))
        footer = struct.pack('<I', len(index) // 4 - 1) + flags
        return header + index + struct.pack('<I', zlib.crc32(footer)) + footer + b'YZ'

    excessive = index_only(MAX_XZ_BLOCKS + 1, 1)
    check('xz-reject-forged-Index-excessive-block-count', lambda: admit_xz_blocks(excessive, MAX_XZ_BLOCKS + 1), True)
    empty_block = index_only(1, 0)
    check('xz-reject-forged-Index-empty-block', lambda: admit_xz_blocks(empty_block, len(unit)), True)
    check('reject-host-admission-oversized-CPIO', lambda: admit_cpio_size(MAX_CPIO_BYTES + 1), True)

    # Alter the second block's filter property and repair its header CRC only.
    # This proves the admission inspects every block, not only the first one.
    multi = bytearray(a.xz_stream.read_bytes())
    footer = multi[-12:]; index_start = len(multi) - 12 - (struct.unpack_from('<I', footer, 4)[0] + 1) * 4
    count, pos = vli(multi, index_start + 1, len(multi) - 16)
    first, pos = vli(multi, pos, len(multi) - 16)
    require_multiple = count > 1
    if not require_multiple:
        raise ValueError('The supplied real XZ fixture must have multiple blocks')
    cursor = 12 + ((first + 3) & ~3); hsize = (multi[cursor] + 1) * 4; pos = cursor + 2
    for mask in (0x40, 0x80):
        if multi[cursor + 1] & mask:
            _, pos = vli(multi, pos, cursor + hsize - 4)
    _, pos = vli(multi, pos, cursor + hsize - 4)
    _, pos = vli(multi, pos, cursor + hsize - 4)
    multi[pos] = 18
    struct.pack_into('<I', multi, cursor + hsize - 4, zlib.crc32(multi[cursor:cursor + hsize - 4]) & 0xffffffff)
    check('xz-reject-second-block-dictionary', lambda: admit_xz_blocks(bytes(multi), a.cpio.stat().st_size), True)
    del multi

    before = config_values(a.baseline_config.read_text())
    source_name = '"' + str(a.cpio.resolve()) + '"'
    legacy = dict(before, CONFIG_INITRAMFS_SOURCE=source_name, CONFIG_BINFMT_MISC='y')
    current = dict(legacy, **XZ_CONFIG_UPDATES)
    check('legacy-gzip-config', lambda: admit_build_config(before, legacy, True, 'gzip'))
    check('explicit-xz-config', lambda: admit_build_config(before, current, True, 'xz'))
    for key in XZ_CONFIG_UPDATES:
        wrong = dict(current); wrong[key] = before.get(key, 'n')
        check('reject-missing-' + key, lambda wrong=wrong: admit_build_config(before, wrong, True, 'xz'), True)
    drift = dict(current); drift['CONFIG_MTD'] = 'n'
    check('reject-unrelated-config-drift', lambda: admit_build_config(before, drift, True, 'xz'), True)
    check('reject-xz-with-gzip-receipt', lambda: admit_compression_config(current, receipt_compression({})), True)
    check('reject-gzip-with-xz-receipt', lambda: admit_compression_config(legacy, receipt_compression(compression_fields('xz'))), True)
    check('legacy-missing-fields-remains-gzip', lambda: equal(receipt_compression({}), 'gzip'))
    check('reject-half-receipt', lambda: receipt_compression({'initramfs_compression': 'xz'}), True)
    check('reject-unknown-profile', lambda: receipt_compression(dict(initramfs_compression='xz', initramfs_compression_profile='unknown')), True)
    check('legacy-kernel-remains-r104', lambda: equal(kernel_package_revision(True, True, True, 'gzip'), '104'))
    check('xz-kernel-is-r105', lambda: equal(kernel_package_revision(True, True, True, 'xz'), '105'))
    check('reject-xz-incomplete-V2', lambda: kernel_package_revision(True, False, False, 'xz'), True)
    preinit = a.preinit_config.read_text()
    check('real-empty-source-preinit-no-phantom-choice', lambda: equal(preinitramfs_compression_config(preinit, 'xz'), (preinit, {})))
    check('actual-OpenWrt-baseline-ABI', lambda: equal(preinit_abi(preinit), 'ebdb6ef0fb8a643c0a13573c2d8c2337'))
    binfmt_preinit = set_config_values(preinit, {'CONFIG_BINFMT_MISC': 'y'})
    xz_preinit, _ = preinitramfs_compression_config(binfmt_preinit, 'xz')
    check('actual-post-preinit-XZ-preserves-legitimate-ABI', lambda: equal(preinit_abi(xz_preinit), '7b648602069fdc1d228ca9bad74de7f2'))
    phantom = set_config_values(preinit, {'CONFIG_INITRAMFS_COMPRESSION_XZ': 'y'})
    check('reject-phantom-preinit-choice', lambda: preinitramfs_compression_config(phantom, 'xz'), True)
    check('actual-source-XZ-recipe', lambda: recipe_hashes(a.source, 'xz'))
    raw = work / 'unit.cpio'; raw.write_bytes(unit)
    prepacked = work / 'unit.cpio.xz'; prepacked.write_bytes(xz)
    false_raw = work / 'compressed.cpio'; false_raw.write_bytes(xz)
    check('raw-cpio-input', lambda: require_raw_cpio(raw))
    check('reject-precompressed-source-name', lambda: require_raw_cpio(prepacked), True)
    check('reject-precompressed-source-bytes', lambda: require_raw_cpio(false_raw), True)
    report = dict(tests=tests, passed=sum(x['passed'] for x in tests.values()), total=len(tests),
        actual_xz_stream_metadata=actual_xz_metadata, actual_cpio_sha256=sha(a.cpio), actual_xz_sha256=sha(a.xz_stream),
        unit_codec_fixtures_are_not_firmware=True, actual_existing_gzip_Image_checked=True,
        actual_xz_verified_as_independent_stream_only=True, new_kernel_or_Image_built=False,
        roots_modified=False, target_executed=False, new_candidate_qualified=False)
    (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print('INITRAMFS_HOST_GATES', report['passed'], '/', report['total'], flush=True)
    if report['passed'] != report['total']:
        print(json.dumps({k: v for k, v in tests.items() if not v['passed']}, indent=2))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
