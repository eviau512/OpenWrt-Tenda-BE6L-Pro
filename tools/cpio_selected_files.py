# SPDX-License-Identifier: MIT
"""Read selected newc payloads from concatenated initramfs archives, without extraction."""
from pathlib import PurePosixPath
import stat


def selected_files(data, selected):
    records = {}
    pos, trailers, inside = 0, 0, False
    while pos < len(data):
        while pos < len(data) and data[pos] == 0:
            pos += 1
        if pos == len(data):
            break
        assert pos % 4 == 0 and pos + 110 <= len(data), 'Truncated/misaligned newc header'
        magic = data[pos:pos + 6]
        assert magic in (b'070701', b'070702'), 'Unsupported CPIO format'
        encoded = [data[pos + 6 + 8*i:pos + 14 + 8*i] for i in range(13)]
        assert all(len(value) == 8 and all(c in b'0123456789abcdefABCDEF' for c in value)
                   for value in encoded), 'Non-hex or signed newc field'
        fields = [int(value, 16) for value in encoded]
        mode, links, size, namesize = fields[1], fields[4], fields[6], fields[11]
        assert 0 < namesize <= 65536 and pos + 110 + namesize <= len(data)
        name_raw = data[pos + 110:pos + 110 + namesize]
        assert name_raw[-1:] == b'\0' and b'\0' not in name_raw[:-1]
        name = name_raw[:-1].decode('utf-8')
        name = name.removeprefix('./').lstrip('/')
        path = PurePosixPath(name)
        assert '..' not in path.parts, 'CPIO traversal path'
        name = str(path)  # Detect aliases such as sbin//procd as duplicates too.
        start = (pos + 110 + namesize + 3) & ~3
        assert start + size <= len(data), 'Truncated newc payload'
        if magic == b'070702':
            assert sum(data[start:start + size]) & 0xffffffff == fields[12], 'CPIO CRC mismatch'
        pos = (start + size + 3) & ~3
        assert pos <= len(data), 'Truncated newc padding'
        if name == 'TRAILER!!!':
            assert size == 0
            trailers += 1
            inside = False
            continue
        inside = True
        if name in selected:
            assert name not in records, 'Duplicate selected CPIO path: ' + name
            assert stat.S_ISREG(mode) or stat.S_ISLNK(mode), 'Unexpected selected CPIO type'
            # Fail explicitly rather than mistake an empty hardlink placeholder
            # for an executable. This fixture uses distinct files or symlinks.
            assert not stat.S_ISREG(mode) or links == 1, 'Selected regular hardlink is unsupported'
            records[name] = dict(mode=mode, data=data[start:start + size])
    assert trailers and not inside, 'Incomplete newc archive'
    assert set(records) == set(selected), 'Missing selected CPIO files'
    return records
