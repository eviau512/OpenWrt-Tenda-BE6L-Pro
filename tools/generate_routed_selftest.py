"""Generate synthetic golden packets independently of the C rewrite routine."""
from pathlib import Path
import ipaddress
import struct

base = Path(__file__).resolve().parents[1]
dest = base / 'experiments/routed-frame/routed-selftest-vectors.h'

def csum(data):
    data += bytes(len(data) & 1)
    value = sum(struct.unpack('!' + str(len(data) // 2) + 'H', data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535

def wire(version, proto, output, zero):
    src = ipaddress.ip_address(('203.0.113.9' if output else '10.11.12.13') if version == 4 else '2001:db8::2').packed
    dst = ipaddress.ip_address(('192.0.2.77' if output else '198.51.100.2') if version == 4 else '2001:db8::3').packed
    sport, dport = (50123, 12345) if output and version == 4 else (33445, 443)
    payload = b'BE6L-NPU-OFFLINE'
    if proto == 6:
        transport = struct.pack('!HHIIBBHHH', sport, dport, 1, 2, 0x50, 0x18, 6000, 0, 0) + payload
        offset = 16
    else:
        transport = struct.pack('!HHHH', sport, dport, len(payload) + 8, 0) + payload
        offset = 6
    pseudo = src + dst + (struct.pack('!BBH', 0, proto, len(transport)) if version == 4 else struct.pack('!I3xB', len(transport), proto))
    checksum = 0 if zero else (csum(pseudo + transport) or (65535 if proto == 17 else 0))
    transport = transport[:offset] + struct.pack('!H', checksum) + transport[offset + 2:]
    ttl = 63 if output else 64
    if version == 4:
        header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(transport), 123, 0x4000, ttl, proto, 0, src, dst)
        header = header[:10] + struct.pack('!H', csum(header)) + header[12:]
    else:
        header = struct.pack('!IHBB16s16s', 0x60012345, len(transport), proto, ttl, src, dst)
    macs = bytes.fromhex('02ffeeddccbb02aabbccddee' if output else '0266778899aa021122334455')
    return macs + struct.pack('!H', 0x0800 if version == 4 else 0x86dd) + header + transport

def array(data):
    return '{' + ','.join('0x%02x' % b for b in data) + '}'

text = '/* SPDX-License-Identifier: MIT */\n/* Generated synthetic golden packets, never captured traffic. */\n'
cases = [(4, 6, False), (4, 17, False), (4, 17, True), (6, 6, False), (6, 17, False)]
for i, (version, proto, zero) in enumerate(cases):
    text += f'static const uint8_t rf_before_{i}[] = ' + array(wire(version, proto, False, zero)) + ';\n'
    text += f'static const uint8_t rf_after_{i}[] = ' + array(wire(version, proto, True, zero)) + ';\n'
text += 'struct rf_vector { const uint8_t *before, *after; uint32_t length, version, protocol; };\n'
text += 'static const struct rf_vector rf_vectors[] = {\n'
for i, (version, proto, _) in enumerate(cases):
    text += f'{{rf_before_{i}, rf_after_{i}, sizeof(rf_before_{i}), {version}, {proto}}},\n'
text += '};\n'
dest.write_text(text)
print('SYNTHETIC_ROUTED_SELFTEST_VECTORS_READY')
