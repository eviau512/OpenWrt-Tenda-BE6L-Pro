"""Prove the actual FIT kernel contains the exact audited external CPIO."""
import gzip
import hashlib
import struct

def verify(kernel, image, cpio):
    obj = (kernel / 'usr/initramfs_data.o').read_bytes()
    assert obj[:6] == b'\x7fELF\x02\x01'
    offset = struct.unpack_from('<Q', obj, 40)[0]
    size, count, names_index = struct.unpack_from('<HHH', obj, 58)
    sections = [struct.unpack_from('<IIQQQQIIQQ', obj, offset + i * size) for i in range(count)]
    names = obj[sections[names_index][4]:sections[names_index][4] + sections[names_index][5]]
    selected = [s for s in sections if names[s[0]:names.index(0, s[0])] == b'.init.ramfs']
    assert len(selected) == 1
    section = selected[0]
    packed = obj[section[4]:section[4] + section[5]]
    unpacked = gzip.decompress(packed)
    expected = cpio.read_bytes()
    assert unpacked == expected, 'Embedded initramfs differs from the audited external CPIO'
    at = image.find(packed)
    assert at >= 0 and image.find(packed, at + 1) == -1, 'CPIO is absent or duplicated in actual FIT kernel'
    return {'embedded_cpio_sha256': hashlib.sha256(unpacked).hexdigest(),
            'embedded_cpio_verified': True, 'embedded_cpio_offset': at,
            'embedded_cpio_compressed_bytes': len(packed)}
