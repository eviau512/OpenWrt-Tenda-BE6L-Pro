"""Property and guarded-buffer tests of the unconnected routing/NAT primitive."""
from pathlib import Path
import ctypes as C
import ipaddress
import json
import mmap
import random
import struct
import subprocess

base = Path(__file__).resolve().parents[1]
(base / "logs").mkdir(parents=True, exist_ok=True)
source = base / 'experiments/routed-frame'
work = Path('/root/be6l-openwrt/routed-frame-tests')
work.mkdir(exist_ok=True)
library = work / 'routed-frame.so'
subprocess.run(['cc', '-std=c11', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=undefined', '-fno-sanitize-recover=undefined', str(source / 'test-wrapper.c'),
    '-o', str(library)], check=True)

class Identity(C.Structure):
    _fields_ = [(name, C.c_uint32) for name in ('port', 'vlan', 'wcid', 'replay_generation', 'ct_zone')]
class Action(C.Structure):
    _fields_ = [('cookie', C.c_uint64), ('ingress', Identity), ('established', C.c_uint32),
        ('version', C.c_uint8), ('protocol', C.c_uint8), ('mtu', C.c_uint16)] + \
        [(name, C.c_uint8 * 6) for name in ('src_mac', 'dst_mac', 'out_src_mac', 'out_dst_mac')] + \
        [(name, C.c_uint8 * 16) for name in ('src_ip', 'dst_ip', 'out_src_ip', 'out_dst_ip')] + \
        [(name, C.c_uint16) for name in ('src_port', 'dst_port', 'out_src_port', 'out_dst_port')]
lib = C.CDLL(str(library))
lib.test_apply.argtypes = [C.c_void_p, C.c_size_t, C.POINTER(Action), C.POINTER(Identity)]
lib.test_apply.restype = C.c_int
rng = random.Random(0x7563)
counts = {'positive': 0, 'negative_identity_and_headers': 0, 'guarded_truncations': 0}

def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!' + str(len(data) // 2) + 'H', data))
    value = (value & 65535) + (value >> 16)
    value = (value & 65535) + (value >> 16)
    return (~value) & 65535

def put(array, value):
    array[:] = value + bytes(len(array) - len(value))

def action(version, protocol):
    a = Action()
    a.cookie = 0x1234567812345678
    a.ingress = Identity(7, 0, 11, 0x45678, 42)
    a.established, a.version, a.protocol, a.mtu = 1, version, protocol, 1500
    for name, value in [('src_mac', '021122334455'), ('dst_mac', '0266778899aa'),
                        ('out_src_mac', '02aabbccddee'), ('out_dst_mac', '02ffeeddccbb')]:
        put(getattr(a, name), bytes.fromhex(value))
    addresses = ('10.11.12.13', '198.51.100.2', '203.0.113.9', '192.0.2.77') if version == 4 else \
                ('2001:db8::2', '2001:db8::3', '2001:db8::2', '2001:db8::3')
    for name, value in zip(('src_ip', 'dst_ip', 'out_src_ip', 'out_dst_ip'), addresses):
        put(getattr(a, name), ipaddress.ip_address(value).packed)
    a.src_port, a.dst_port = 33445, 443
    a.out_src_port, a.out_dst_port = (50123, 12345) if version == 4 else (33445, 443)
    return a

def pseudo(a, length, output=False):
    prefix = 'out_' if output else ''
    n = 4 if a.version == 4 else 16
    addresses = bytes(getattr(a, prefix + 'src_ip'))[:n] + bytes(getattr(a, prefix + 'dst_ip'))[:n]
    return addresses + (struct.pack('!BBH', 0, a.protocol, length) if a.version == 4 else
                        struct.pack('!I3xB', length, a.protocol))

def packet(a, payload, zero_udp=False):
    if a.protocol == 6:
        transport = struct.pack('!HHIIBBHHH', a.src_port, a.dst_port, rng.getrandbits(32),
            rng.getrandbits(32), 0x50, 0x18, 6000, 0, 0) + payload
        offset = 16
    else:
        transport = struct.pack('!HHHH', a.src_port, a.dst_port, len(payload) + 8, 0) + payload
        offset = 6
    value = checksum(pseudo(a, len(transport)) + transport)
    if a.protocol == 17 and not value:
        value = 65535
    if zero_udp:
        value = 0
    transport = transport[:offset] + struct.pack('!H', value) + transport[offset + 2:]
    if a.version == 4:
        header = struct.pack('!BBHHHBBH4s4s', 0x45, rng.randrange(256), 20 + len(transport),
            rng.randrange(65536), 0x4000, 64, a.protocol, 0, bytes(a.src_ip)[:4], bytes(a.dst_ip)[:4])
        header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    else:
        header = struct.pack('!IHBB16s16s', 0x60000000 | rng.getrandbits(28), len(transport),
                             a.protocol, 64, bytes(a.src_ip), bytes(a.dst_ip))
    return bytes(a.dst_mac) + bytes(a.src_mac) + struct.pack('!H', 0x0800 if a.version == 4 else 0x86dd) + header + transport

def apply(data, a, identity=None):
    buf = C.create_string_buffer(data, len(data))
    identity = identity or a.ingress
    result = lib.test_apply(buf, len(data), C.byref(a), C.byref(identity))
    return result, bytes(buf)

def rejected(data, a, identity=None):
    result, after = apply(data, a, identity)
    assert result == 0 and after == data
    counts['negative_identity_and_headers'] += 1

for version in (4, 6):
    for protocol in (6, 17):
        for case in range(512):
            a = action(version, protocol)
            payload = rng.randbytes(rng.randrange(1301))
            zero = version == 4 and protocol == 17 and case % 7 == 0
            before = packet(a, payload, zero)
            result, after = apply(before, a)
            assert result == 1 and len(after) == len(before)
            assert after[:12] == bytes(a.out_dst_mac) + bytes(a.out_src_mac)
            header = 20 if version == 4 else 40
            transport = after[14 + header:]
            if version == 4:
                assert after[22] == 63 and checksum(after[14:34]) == 0
                assert after[26:30] == bytes(a.out_src_ip)[:4] and after[30:34] == bytes(a.out_dst_ip)[:4]
                assert struct.unpack('!HH', transport[:4]) == (a.out_src_port, a.out_dst_port)
                if zero:
                    assert transport[6:8] == b'\0\0'
                else:
                    assert checksum(pseudo(a, len(transport), True) + transport) == 0
            else:
                assert after[21] == 63 and after[54:] == before[54:]
                assert checksum(pseudo(a, len(transport)) + transport) == 0
            assert transport[20 if protocol == 6 else 8:] == payload
            counts['positive'] += 1
            for field in ('port', 'vlan', 'wcid', 'replay_generation', 'ct_zone'):
                wrong = Identity.from_buffer_copy(bytes(a.ingress))
                setattr(wrong, field, getattr(wrong, field) ^ 1)
                rejected(before, a, wrong)
            for field in ('cookie', 'established'):
                wrong = Action.from_buffer_copy(bytes(a))
                setattr(wrong, field, 0)
                rejected(before, wrong)
            bad = bytearray(before); bad[-1] ^= 1
            if not zero: rejected(bytes(bad), a)
        # Exercise every truncated prefix immediately before a protected page.
        a = action(version, protocol); data = packet(a, bytes(range(73)))
        page = mmap.PAGESIZE
        area = mmap.mmap(-1, 2 * page, prot=mmap.PROT_READ | mmap.PROT_WRITE)
        address = C.addressof(C.c_char.from_buffer(area))
        libc = C.CDLL(None)
        libc.mprotect.argtypes = [C.c_void_p, C.c_size_t, C.c_int]
        assert libc.mprotect(address + page, page, 0) == 0
        try:
            for cut in range(len(data)):
                pointer = address + page - cut
                if cut: C.memmove(pointer, data, cut)
                assert lib.test_apply(pointer, cut, C.byref(a), C.byref(a.ingress)) == 0
                assert C.string_at(pointer, cut) == data[:cut]
                counts['guarded_truncations'] += 1
        finally:
            assert libc.mprotect(address + page, page, mmap.PROT_READ | mmap.PROT_WRITE) == 0
            area.close()
        bad = bytearray(data)
        if version == 4:
            for fragment in (0x2000, 1, 0x8000):
                bad = bytearray(data); bad[20:22] = struct.pack('!H', fragment); bad[24:26] = b'\0\0'
                bad[24:26] = struct.pack('!H', checksum(bytes(bad[14:34])))
                rejected(bytes(bad), a)
            bad = bytearray(data); bad[22] = 1; bad[24:26] = b'\0\0'
            bad[24:26] = struct.pack('!H', checksum(bytes(bad[14:34])))
            rejected(bytes(bad), a)
            bad = bytearray(data); bad[14] = 0x46; rejected(bytes(bad), a)
        else:
            bad = bytearray(data); bad[21] = 1; rejected(bytes(bad), a)
            bad = bytearray(data); bad[20] = 44; rejected(bytes(bad), a)
            if protocol == 17:
                bad = bytearray(data); bad[60:62] = b'\0\0'; rejected(bytes(bad), a)
        wrong = Action.from_buffer_copy(bytes(a)); wrong.mtu = 68 if version == 4 else 1280
        rejected(packet(a, bytes(1300)), wrong)
        bad = bytearray(data); bad[12:14] = b'\x81\0'; rejected(bytes(bad), a)
        if protocol == 6:
            start = 34 if version == 4 else 54
            for flag in (1, 2, 4, 32):
                bad = bytearray(data); bad[start + 13] |= flag
                bad[start + 16:start + 18] = b'\0\0'
                bad[start + 16:start + 18] = struct.pack('!H', checksum(pseudo(a, len(bad) - start) + bytes(bad[start:])))
                rejected(bytes(bad), a)
        else:
            start = 34 if version == 4 else 54
            bad = bytearray(data); bad[start + 4:start + 6] = struct.pack('!H', len(data) - start - 1)
            bad[start + 6:start + 8] = b'\0\0'
            value = checksum(pseudo(a, len(bad) - start) + bytes(bad[start:])) or 65535
            bad[start + 6:start + 8] = struct.pack('!H', value)
            rejected(bytes(bad), a)
        group = Action.from_buffer_copy(bytes(a))
        put(group.dst_ip, ipaddress.ip_address('224.1.2.3' if version == 4 else 'ff02::1').packed)
        put(group.out_dst_ip, bytes(group.dst_ip))
        rejected(packet(group, bytes(32)), group)
        if version == 6:
            wrong = Action.from_buffer_copy(bytes(a)); wrong.out_dst_port ^= 1
            rejected(data, wrong)

# UDP's computed zero must be transmitted as 0xffff after IPv4 NAT.
a = action(4, 17)
transport = struct.pack('!HHHHH', a.out_src_port, a.out_dst_port, 10, 0, 0)
payload = struct.pack('!H', checksum(pseudo(a, 10, True) + transport))
result, transformed = apply(packet(a, payload), a)
assert result == 1 and transformed[40:42] == b'\xff\xff'
assert checksum(pseudo(a, 10, True) + transformed[34:]) == 0

cross = Path('/root/be6l-openwrt/arm64-source/staging_dir/hostpkg/riscv32-elf/bin/riscv32-unknown-elf-')
obj = work / 'routed-frame-rv32.o'
subprocess.run([str(cross) + 'gcc', '-std=c11', '-Os', '-Wall', '-Wextra', '-Werror',
    '-march=rv32imc_zicsr_zifencei', '-mabi=ilp32', '-ffreestanding', '-fno-builtin',
    '-c', str(source / 'test-wrapper.c'), '-o', str(obj)], check=True)
undefined = subprocess.check_output([str(cross) + 'nm', '-u', str(obj)], text=True)
assert not undefined.strip(), undefined
report = {'counts': counts, 'udp_zero_checksum_case': True, 'rv32_freestanding_compile': True,
          'ubsan_passed': True, 'hardware_integrated': False, 'nat_offload_qualified': False}
(base / 'logs/p5-routed-frame-offline-tests.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
