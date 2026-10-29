"""CPU-only versioned RX eligibility proposal; no SDK or hardware changes."""
from pathlib import Path
import hashlib
import json
import shutil
import struct
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
BASE = HERE.parents[1]
LOCK = BASE / 'logs/20261028-resume-wired-action-20261028-112220/result.json'
receipt = json.loads(LOCK.read_text())
source_path = Path(receipt['frozen_source_root']) / 'airoha_ppe.c'
source = source_path.read_text()
assert hashlib.sha256(source_path.read_bytes()).hexdigest() == \
    '39b585e3b1f2bc808e19ebdffd5dc53e34feac4558f76336b024b58aae676e35'
marker = 'static bool\nairoha_ppe_wired_l4_packet_match('
start = source.index(marker)
opening = source.index('{', start)
depth = 0
for end in range(opening, len(source)):
    depth += (source[end] == '{') - (source[end] == '}')
    if not depth:
        actual = source[start:end + 1] + '\n'
        break
else:
    raise AssertionError('unclosed actual source function')
assert 'length > e->ingress_dev->mtu' in actual
assert 'e->wired_egress_dev->mtu' not in actual
assert 'if (airoha_is_7563(eth) && addr_type) {' in source
assert 'REG_PPE_PPE_FLOW_CFG(0), PPE_FLOW_CFG_L2_BRIDGE_MASK);' in source


def checksum(data):
    """Independent host network-order oracle, not imported by the C candidate."""
    if len(data) & 1:
        data += b'\0'
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    value = (value & 65535) + (value >> 16)
    value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def packet(*, payload=b'', options=b'', flags=0x10):
    assert len(options) % 4 == 0 and len(options) <= 40
    source_ip, dest_ip = bytes([192, 0, 2, 1]), bytes([198, 51, 100, 2])
    tcp = struct.pack('!HHIIBBHHH', 40000, 5201, 0x12345678, 0xabcdef01,
                      (5 + len(options) // 4) << 4, flags, 32768, 0, 0)
    tcp += options + payload
    pseudo = source_ip + dest_ip + struct.pack('!BBH', 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack('!H', checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(tcp), 0x2345, 0x4000, 64, 6, 0)
    ip += source_ip + dest_ip
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    assert checksum(ip) == 0 and checksum(pseudo + tcp) == 0
    return ip + tcp


vectors = []


def add(name, data, expected, *, original=True, mtu=1500, linear=1600,
        inaccessible=0, state=1, gso=False):
    assert len(data) <= 1500
    vectors.append(dict(name=name, data=data, expected=expected, original=original,
                        mtu=mtu, linear=linear, inaccessible=inaccessible, state=state, gso=gso))


base = packet()
add('valid-ack-unnecessary', base, True)
add('valid-ack-none', base, True, state=0)
add('valid-ack-complete', base, True, state=2)
add('partial-not-a-complete-rx-packet', base, False, state=3)
add('gso-not-a-single-wire-packet', base, False, gso=True)
for size in (1, 37, 64, 65, 333, 1460):
    data = packet(payload=bytes((i * 107 + 31) & 255 for i in range(size)))
    add('payload-' + str(size), data, True)
add('egress-mtu-exact', base, True, mtu=len(base))
add('egress-mtu-one-below', base, False, mtu=len(base) - 1)
add('egress-mtu-zero', base, False, mtu=0)
add('ack-absent', packet(flags=0), False)
add('urgent', packet(flags=0x30), False)
add('timestamp-option-syntax', packet(options=bytes([1, 1, 8, 10]) + bytes(range(8))), True)
add('eol-option', packet(options=bytes(4)), True)
add('nop-options', packet(options=bytes([1, 1, 1, 1])), True)
add('unknown-option-syntax-only', packet(options=bytes([30, 4, 0xaa, 0xbb])), True)
for name, options in (
    ('option-length-zero', bytes([8, 0, 0, 0])),
    ('option-length-one', bytes([8, 1, 0, 0])),
    ('option-overrun', bytes([8, 10, 0, 0])),
    ('option-missing-length', bytes([1, 1, 1, 8])),
):
    add(name, packet(options=options), False)
for name, index in (('bad-ip-checksum', 10), ('bad-tcp-checksum', 36),
                    ('bad-tcp-covered-byte', 27)):
    changed = bytearray(base)
    changed[index] ^= 1
    add(name, bytes(changed), False)
data = bytearray(packet(payload=b'odd payload'))
data[-1] ^= 1
add('bad-odd-payload-with-unnecessary-flag', bytes(data), False)
data = bytearray(base)
data[12] ^= 1
data[10:12] = b'\0\0'
data[10:12] = struct.pack('!H', checksum(bytes(data[:20])))
add('changed-pseudoheader-ip-checksum-repaired', bytes(data), False)
add('nonlinear-ip-and-tcp', packet(payload=bytes(range(99))), True, linear=8)
add('nonlinear-options-and-payload', packet(options=bytes([1] * 12), payload=bytes(range(151))),
    True, linear=40)
add('unreadable-payload-tail', packet(payload=b'four'), False, inaccessible=42)
add('unreadable-option-tail', packet(options=bytes([1] * 12)), False, inaccessible=42)
add('baseline-truncated-ip', base[:19], False, original=False)
add('baseline-truncated-tcp', base[:39], False, original=False)

vector_type = '''struct vector {
 const char *name; const unsigned char *packet; unsigned int length, mtu, linear, inaccessible;
 int checksum_state; bool gso, original, expected;
};\n'''
for index, vector in enumerate(vectors):
    vector_type += 'static const unsigned char packet_' + str(index) + '[] = {'
    vector_type += ','.join(str(value) for value in vector['data']) + '};\n'
vector_type += 'static const struct vector vectors[] = {\n'
for index, vector in enumerate(vectors):
    vector_type += '{"%s",packet_%d,%d,%d,%d,%d,%d,%s,%s,%s},\n' % (
        vector['name'], index, len(vector['data']), vector['mtu'], vector['linear'],
        vector['inaccessible'], vector['state'], str(vector['gso']).lower(),
        str(vector['original']).lower(), str(vector['expected']).lower())
vector_type += '};\n'

out = BASE / 'logs' / time.strftime('wired-rx-contract-v1-%Y%m%d-%H%M%S')
out.mkdir()
with tempfile.TemporaryDirectory(prefix='be6l-rx-contract-v1-') as temporary:
    work = Path(temporary)
    (work / 'real-packet-match.h').write_text(actual)
    (work / 'vectors.h').write_text(vector_type)
    for name in ('test.c', 'rx-extra.c'):
        shutil.copyfile(HERE / name, work / name)
    command = ['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
               '-fsanitize=undefined', '-fno-sanitize-recover=all', str(work / 'test.c'),
               '-o', str(work / 'test')]
    with (out / 'compile.txt').open('wb') as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    result = json.loads(subprocess.check_output([str(work / 'test')], text=True))
    assert result['passed'] and not result['can_publish']
    result.update(ubsan=True, source_function_sha256=hashlib.sha256(actual.encode()).hexdigest(),
                  source_sha256=hashlib.sha256(source_path.read_bytes()).hexdigest(),
                  vector_bytes_sha256=hashlib.sha256(vector_type.encode()).hexdigest(),
                  fixture_sha256={name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                                  for name in ('run.py', 'test.c', 'rx-extra.c')},
                  independent_python_checksum_oracle=True,
                  original_974_function_unchanged=True, sdk_or_driver_modified=False,
                  firmware_or_image_modified=False, routed_gate_changed=False,
                  asic_exception_semantics_proven=False, real_device_adapter=False,
                  previous_108_cases_rerun=False)
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    (BASE / 'logs/wired-rx-contract-v1-latest.json').write_text(
        json.dumps(dict(directory=str(out))) + '\n')
    print(json.dumps(dict(directory=str(out), **result), indent=2), flush=True)
