# SPDX-License-Identifier: MIT
"""Derive a strict v2 ABI probe; retain the original strict v1 checker."""
from pathlib import Path
import hashlib
from prepare_n1_identity_v2 import once
BASE = Path(__file__).resolve().parents[1]
original = BASE / 'tools/ppe_module_abi.py'
assert hashlib.sha256(original.read_bytes()).hexdigest() == 'e21365846e1fed82a396d0573b56e1566db1aaefd5faa7843387258b2403457a'
destination = BASE / 'tools/ppe_module_abi_v2.py'
assert not destination.exists()
text = original.read_text()
text = once(text, '#include <net/flow_offload.h>', '#include <net/flow_offload.h>\n#include <net/netfilter/nf_flow_table.h>')
text = once(text, '0x42464131, 1, sizeof(struct module)', '0x42464132, 2, sizeof(struct module)')
text = once(text, '  sizeof(struct flow_action_entry)\n', '''  sizeof(struct flow_action_entry),
  offsetof(struct flow_rule_ct_context, generation),
  offsetof(struct flow_rule_ct_context, ct_cookie),
  offsetof(struct flow_rule_ct_context, flow_cookie),
  offsetof(struct flow_rule_ct_context, tuple_cookie),
  sizeof(struct flow_cls_offload), offsetof(struct flow_cls_offload, ct_context),
  offsetof(struct flow_cls_offload, rule), sizeof(struct flow_offload),
  offsetof(struct flow_offload, diag_generation)
''')
text = once(text, "struct.unpack('<9I'", "struct.unpack('<18I'")
text = once(text, '(0x42464131, 1)', '(0x42464132, 2)')
text = once(text, 'report = dict(schema=1,', 'report = dict(schema=2,')
text = once(text, "                  flow_action_entry_bytes=values[8], vermagic=magic[:-1].decode('ascii'),", '''                  flow_action_entry_bytes=values[8],
                  context_generation_offset=values[9], context_ct_cookie_offset=values[10],
                  context_flow_cookie_offset=values[11], context_tuple_cookie_offset=values[12],
                  flow_cls_bytes=values[13], flow_cls_context_offset=values[14], flow_cls_rule_offset=values[15],
                  nf_flow_bytes=values[16], nf_flow_generation_offset=values[17],
                  vermagic=magic[:-1].decode('ascii'),''')
text = once(text, "    assert report['ct_context_version'] == 1 and report['ct_context_bytes'] == 16", '''    assert report['ct_context_version'] == 2 and report['ct_context_bytes'] == 56
    assert values[9:13] == (16, 24, 32, 40)
    assert values[14] + 56 <= values[15] and values[15] + 8 <= values[13]
    assert values[17] + 8 <= values[16]''')
compile(text, str(destination), 'exec')
destination.write_text(text)
print('STRICT_V2_ABI_CHECKER_DERIVED_WITHOUT_CHANGING_V1')
