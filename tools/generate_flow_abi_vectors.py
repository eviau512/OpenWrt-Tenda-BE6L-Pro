"""Encode synthetic action commands independently of the firmware decoder."""
from pathlib import Path
import importlib.util
import struct

base = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('golden', base / 'tools/generate_routed_selftest.py')
g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
rows = []
lengths = []
for index, (version, proto, zero) in enumerate(g.cases):
    before, after = g.wire(version, proto, False, zero), g.wire(version, proto, True, zero)
    n, start = (4, 26) if version == 4 else (16, 22)
    macs = before[6:12] + before[:6] + after[6:12] + after[:6]
    ips = b''.join(x.ljust(16, b'\0') for x in
        (before[start:start+n], before[start+n:start+2*n], after[start:start+n], after[start+n:start+2*n]))
    words = [7, 0, 11, 0x45678, 42, version | proto << 8 | 1500 << 16]
    words += list(struct.unpack('<6I', macs)) + list(struct.unpack('<16I', ips))
    words += [33445 | 443 << 16, (50123 | 12345 << 16) if version == 4 else (33445 | 443 << 16), 1, index]
    assert len(words) == 32
    rows.append(words); lengths.append(len(before))
text = '/* SPDX-License-Identifier: MIT */\n/* Generated synthetic action words; not captured network data. */\n'
text += 'static const fa_u32 fa_actions[5][32] = {\n'
text += ''.join('{' + ','.join('0x%xU' % value for value in row) + '},\n' for row in rows)
text += '};\nstatic const fa_u32 fa_lengths[5] = {' + ','.join(map(str, lengths)) + '};\n'
(base / 'experiments/flow-abi/flow-actions.h').write_text(text)
print('SYNTHETIC_FLOW_ACTION_WIRE_VECTORS_GENERATED')
