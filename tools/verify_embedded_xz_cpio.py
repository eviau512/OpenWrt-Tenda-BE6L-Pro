# SPDX-License-Identifier: MIT
"""Prove a new XZ candidate embeds exactly its audited external CPIO."""
import hashlib
import lzma
import struct

def verify(kernel, image, cpio):
    obj = (kernel / 'usr/initramfs_data.o').read_bytes()
    assert obj[:6] == b'\x7fELF\x02\x01'
    offset = struct.unpack_from('<Q', obj, 40)[0]
    size, count, names_index = struct.unpack_from('<HHH', obj, 58)
    assert size == 64 and count > 0 and names_index < count
    assert offset + size * count <= len(obj)
    sections = [struct.unpack_from('<IIQQQQIIQQ', obj, offset + i * size) for i in range(count)]
    names_section = sections[names_index]
    assert names_section[4] + names_section[5] <= len(obj)
    names = obj[names_section[4]:names_section[4] + names_section[5]]
    selected = [s for s in sections if names[s[0]:names.index(0, s[0])] == b'.init.ramfs']
    assert len(selected) == 1
    section = selected[0]
    assert section[4] + section[5] <= len(obj)
    packed = obj[section[4]:section[4] + section[5]]
    assert packed.startswith(b'\xfd7zXZ\x00')
    expected = cpio.read_bytes()
    assert expected.startswith(b'070701'), 'Only a valid newc candidate is admitted'
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=16 * 1024 * 1024)
    unpacked = decoder.decompress(packed, max_length=len(expected) + 1)
    assert decoder.eof and decoder.check == lzma.CHECK_CRC32
    assert len(decoder.unused_data) < 64 and not decoder.unused_data.strip(b'\x00')
    assert unpacked == expected, 'Embedded XZ initramfs differs from the audited CPIO'
    stream_size = len(packed) - len(decoder.unused_data)
    at = image.find(packed)
    assert at >= 0 and image.find(packed, at + 1) == -1, 'CPIO is absent or duplicated in actual FIT kernel'
    config = (kernel / '.config').read_text().splitlines()
    for option in ('CONFIG_RD_XZ=y', 'CONFIG_DECOMPRESS_XZ=y', 'CONFIG_INITRAMFS_COMPRESSION_XZ=y'):
        assert option in config, option
    return {'embedded_cpio_sha256': hashlib.sha256(unpacked).hexdigest(),
            'embedded_cpio_verified': True, 'embedded_cpio_offset': at,
            'embedded_cpio_compressed_bytes': stream_size,
            'embedded_cpio_section_bytes': len(packed),
            'embedded_cpio_compression': 'xz', 'embedded_cpio_check': 'CRC32',
            'xz_initramfs_decoder_config_verified': True}
