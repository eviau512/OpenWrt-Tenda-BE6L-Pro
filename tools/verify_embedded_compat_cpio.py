"""Verify the exact raw CPIO under an explicit kernel/receipt codec profile.

XZ block metadata follows https://tukaani.org/xz/xz-file-format.txt (1.2.1).
Only the reviewed CRC32/single-LZMA2-filter/1MiB-dictionary recipe is admitted.
This host bound is not evidence of a target decoder allocation limit.
"""
import hashlib
import lzma
import struct
import zlib
from build_fresh_arm64_kernel_v1 import (receipt_compression, compression_fields,
    config_values, admit_compression_config, require_raw_cpio)

# Explicit host admission bounds, not kernel decoder or target RAM limits.
MAX_XZ_BLOCKS = 4096
MAX_CPIO_BYTES = 512 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def vli(data, offset, end):
    value = 0
    for count in range(9):
        require(offset < end, 'Truncated XZ variable-length integer')
        byte = data[offset]
        offset += 1
        require(not (count and byte == 0), 'Non-canonical XZ variable-length integer')
        value |= (byte & 0x7f) << (7 * count)
        if not byte & 0x80:
            return value, offset
    raise ValueError('Oversized XZ variable-length integer')


def crc32(data, expected):
    require(zlib.crc32(data) & 0xffffffff == struct.unpack('<I', expected)[0], 'XZ metadata CRC32 differs')


def admit_cpio_size(size):
    require(6 <= size <= MAX_CPIO_BYTES, 'External CPIO exceeds the explicit host admission size bound')


def admit_xz_blocks(packed, expected_size):
    admit_cpio_size(expected_size)
    require(len(packed) >= 32 and len(packed) % 4 == 0, 'Truncated or trailing XZ bytes')
    require(packed[:6] == b'\xfd7zXZ\x00' and packed[6:8] == b'\x00\x01', 'Only XZ CRC32 stream flags are admitted')
    crc32(packed[6:8], packed[8:12])
    footer = packed[-12:]
    require(footer[-2:] == b'YZ' and footer[8:10] == packed[6:8], 'XZ footer or stream flags differ')
    crc32(footer[4:10], footer[:4])
    index_size = (struct.unpack_from('<I', footer, 4)[0] + 1) * 4
    start = len(packed) - 12 - index_size
    require(start >= 12 and index_size >= 8, 'Invalid XZ index bounds')
    index = packed[start:-12]
    require(index[0] == 0, 'Missing XZ index indicator')
    crc32(index[:-4], index[-4:])
    count, offset = vli(index, 1, len(index) - 4)
    require(0 < count <= MAX_XZ_BLOCKS, 'XZ exceeds the explicit host admission block count bound')
    require(count <= (len(index) - 5) // 2, 'Invalid XZ block count')
    records = []
    for _ in range(count):
        unpadded, offset = vli(index, offset, len(index) - 4)
        uncompressed, offset = vli(index, offset, len(index) - 4)
        require(unpadded > 0 and uncompressed > 0, 'Empty XZ blocks are outside the admitted host profile')
        records.append((unpadded, uncompressed))
    require(len(index) - 4 - offset < 4 and not any(index[offset:-4]), 'Invalid XZ index padding')
    require(sum(size for _, size in records) == expected_size, 'XZ index differs from external CPIO size')
    cursor = 12
    for unpadded, uncompressed in records:
        require(cursor < start and packed[cursor] != 0, 'Missing XZ block or concatenated stream')
        header_size = (packed[cursor] + 1) * 4
        end = cursor + ((unpadded + 3) & ~3)
        require(header_size >= 8 and unpadded > header_size + 4 and end <= start, 'Invalid XZ block bounds')
        header = packed[cursor:cursor + header_size]
        require(len(header) == header_size and header[1] & 0x3f == 0, 'Unsupported XZ filters or reserved block flags')
        crc32(header[:-4], header[-4:])
        compressed = unpadded - header_size - 4
        offset = 2
        if header[1] & 0x40:
            size, offset = vli(header, offset, header_size - 4)
            require(size == compressed, 'XZ compressed block size differs')
        if header[1] & 0x80:
            size, offset = vli(header, offset, header_size - 4)
            require(size == uncompressed, 'XZ uncompressed block size differs')
        filter_id, offset = vli(header, offset, header_size - 4)
        properties_size, offset = vli(header, offset, header_size - 4)
        require(filter_id == 0x21 and properties_size == 1 and offset < header_size - 4,
                'Only one LZMA2 filter is admitted')
        # LZMA2 property16 encodes exactly (2 << 19) == 1MiB.
        require(header[offset] == 16, 'XZ dictionary differs from the reviewed1MiB recipe')
        require(not any(header[offset + 1:-4]), 'Invalid XZ block header padding')
        padding = packed[cursor + header_size + compressed:end - 4]
        require(len(padding) == (-unpadded & 3) and not any(padding), 'Invalid XZ block padding')
        cursor = end
    require(cursor == start, 'Extra XZ blocks, bytes or concatenated streams')
    return dict(xz_block_count=count, xz_dictionary_bytes=1024 * 1024,
                xz_filters=['LZMA2'], embedded_cpio_check='CRC32',
                host_admission_max_xz_blocks=MAX_XZ_BLOCKS, host_admission_max_cpio_bytes=MAX_CPIO_BYTES)


def decode_initramfs(packed, expected, compression):
    admit_cpio_size(len(expected))
    require(expected.startswith(b'070701'), 'External source must be raw newc CPIO')
    metadata = {}
    try:
        if compression == 'xz':
            metadata = admit_xz_blocks(packed, len(expected))
            decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=16 * 1024 * 1024)
            unpacked = decoder.decompress(packed, max_length=len(expected) + 1)
            require(decoder.check == lzma.CHECK_CRC32, 'Wrong XZ stream check')
        elif compression == 'gzip':
            decoder = zlib.decompressobj(wbits=31)
            unpacked = decoder.decompress(packed, len(expected) + 1)
        else:
            raise ValueError('Unsupported initramfs codec')
    except (lzma.LZMAError, zlib.error) as error:
        raise ValueError('Corrupt compressed initramfs') from error
    require(decoder.eof and not decoder.unused_data, 'Truncated, trailing or multiple initramfs streams')
    require(unpacked == expected, 'Embedded initramfs differs from the audited external CPIO')
    return unpacked, metadata


def ramfs_section(obj):
    require(len(obj) >= 64 and obj[:4] == b'\x7fELF' and obj[4] in (1, 2) and obj[5] == 1,
            'Invalid initramfs object ELF header')
    is64 = obj[4] == 2
    offset = struct.unpack_from('<Q' if is64 else '<I', obj, 40 if is64 else 32)[0]
    size, count, names_index = struct.unpack_from('<HHH', obj, 58 if is64 else 46)
    require(size == (64 if is64 else 40) and count > 0 and names_index < count and
            offset + size * count <= len(obj), 'Invalid initramfs ELF section table')
    sections = [struct.unpack_from('<IIQQQQIIQQ' if is64 else '<IIIIIIIIII',
                                  obj, offset + i * size) for i in range(count)]
    require(all(s[4] + s[5] <= len(obj) for s in sections if s[1] != 8), 'Out-of-bounds initramfs ELF section')
    names_section = sections[names_index]
    names = obj[names_section[4]:names_section[4] + names_section[5]]
    selected = []
    for section in sections:
        require(section[0] < len(names), 'Invalid initramfs ELF section name')
        end = names.find(b'\0', section[0])
        require(end >= 0, 'Unterminated initramfs ELF section name')
        if names[section[0]:end] == b'.init.ramfs':
            selected.append(section)
    require(len(selected) == 1, 'Missing or duplicate .init.ramfs section')
    section = selected[0]
    require(section[1] == 1 and section[5] > 0, 'Invalid .init.ramfs section type or size')
    return obj[section[4]:section[4] + section[5]]


def verify(kernel, image, cpio, receipt=None):
    compression = receipt_compression(receipt or {})
    admit_compression_config(config_values((kernel / '.config').read_text()), compression)
    require_raw_cpio(cpio)
    obj = (kernel / 'usr/initramfs_data.o').read_bytes()
    packed = ramfs_section(obj)
    admit_cpio_size(cpio.stat().st_size)
    expected = cpio.read_bytes()
    unpacked, metadata = decode_initramfs(packed, expected, compression)
    at = image.find(packed)
    require(at >= 0 and image.find(packed, at + 1) == -1, 'CPIO is absent or duplicated in actual FIT kernel')
    return {'embedded_cpio_sha256': hashlib.sha256(unpacked).hexdigest(),
            'embedded_cpio_verified': True, 'embedded_cpio_offset': at,
            'embedded_cpio_compressed_bytes': len(packed), 'embedded_cpio_section_bytes': len(packed),
            'embedded_cpio_compression': compression, **compression_fields(compression), **metadata}
