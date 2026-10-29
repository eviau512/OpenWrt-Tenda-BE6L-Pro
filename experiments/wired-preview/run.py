"""CPU-only lease/action preview using frozen real producer and encoder bodies."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
BASE = HERE.parents[1]
old = json.loads((BASE / 'logs/20261028-resume-wired-action-20261028-112220/result.json').read_text())
frozen = Path(old['frozen_source_root'])
paths = {
    'airoha_ppe.c': frozen / 'airoha_ppe.c',
    'airoha_eth.h': frozen / 'airoha_eth.h',
    'nf_flow_table_offload.c': BASE / 'logs/routed-context-20261027-201759/nf_flow_table_offload.c.before',
}
source = {}
for name, path in paths.items():
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == old['source_sha256'][name], name
    source[name] = data.decode()


def block(text, marker):
    start = text.index(marker)
    begin = text.index('{', start)
    depth = 0
    for pos in range(begin, len(text)):
        depth += (text[pos] == '{') - (text[pos] == '}')
        if not depth:
            return text[start:pos + 1]
    raise AssertionError(marker)


assert 'if (airoha_is_7563(eth) && addr_type) {' in source['airoha_ppe.c']
assert 'REG_PPE_PPE_FLOW_CFG(0), PPE_FLOW_CFG_L2_BRIDGE_MASK);' in source['airoha_ppe.c']
types = '\n'.join(block(source['airoha_eth.h'], 'struct ' + name + ' {') + ';'
                  for name in ('airoha_foe_mac_info_common', 'airoha_foe_mac_info',
                               'airoha_foe_ipv4_tuple', 'airoha_foe_ipv4'))
patch = (BASE / 'overlay/target/linux/airoha/patches-6.18/973-net-flowtable-preserve-explicit-ct-context-for-admission.patch').read_text()
added = '\n'.join(line[1:] for line in patch.splitlines() if line.startswith('+') and not line.startswith('+++'))
context = block(added, 'struct flow_rule_ct_context {') + ';'
for constant in ('FLOW_RULE_CT_CONTEXT_VERSION', 'FLOW_RULE_CT_CONTEXT_NF_FLOWTABLE'):
    assert '#define ' + constant + ' 1' in added
    context = '#define ' + constant + ' 1\n' + context
producers = ['static void flow_offload_mangle(',
             'static inline struct flow_action_entry *\nflow_action_entry_next(',
             'static int flow_offload_ipv4_snat(', 'static int flow_offload_ipv4_dnat(',
             'static int flow_offload_l4proto(', 'static int flow_offload_port_snat(',
             'static int flow_offload_port_dnat(']
consumers = ['static int airoha_ppe_flow_mangle_ports(',
             'static int airoha_ppe_flow_mangle_ipv4(',
             'static int airoha_ppe_foe_entry_set_ipv4_tuple(',
             'static bool\nairoha_ppe_wired_context_valid(']
helpers = '\n\n'.join(block(source['nf_flow_table_offload.c'], name) for name in producers)
helpers += '\n\n' + '\n\n'.join(block(source['airoha_ppe.c'], name) for name in consumers)
# The wrapper is ours; these four MAC assignments are copied byte-for-byte
# from the real constructor. Do not extract its unqualified neutral defaults.
mac_lines = [
    '\tl2->dest_mac_hi = get_unaligned_be32(data->eth.h_dest);',
    '\tl2->dest_mac_lo = get_unaligned_be16(data->eth.h_dest + 4);',
    '\t\tl2->src_mac_hi = get_unaligned_be32(data->eth.h_source);',
    '\t\thwe->ipv4.l2.src_mac_lo =\n\t\t\tget_unaligned_be16(data->eth.h_source + 4);',
]
for line in mac_lines:
    assert source['airoha_ppe.c'].count(line) == 1
helpers += '\n\nstatic void real_mac_fields(struct airoha_foe_entry *hwe, struct airoha_flow_data *data)\n{\n'
helpers += '\tstruct airoha_foe_mac_info_common *l2 = &hwe->ipv4.l2.common;\n'
helpers += '\n'.join(mac_lines) + '\n}\n'

out = BASE / 'logs' / time.strftime('wired-preview-%Y%m%d-%H%M%S')
out.mkdir()
with tempfile.TemporaryDirectory(prefix='be6l-wired-preview-') as temp:
    work = Path(temp)
    generated = {'real-types.h': types + '\n', 'real-context.h': context + '\n',
                 'real-helpers.h': helpers + '\n'}
    for name, text in generated.items():
        (work / name).write_text(text)
    for name in ('shim.h', 'preview.h', 'preview.c', 'test.c'):
        shutil.copyfile(HERE / name, work / name)
    command = ['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
               '-Wno-unused-parameter', '-fsanitize=undefined',
               '-fno-sanitize-recover=all', str(work / 'test.c'), '-o', str(work / 'test')]
    with (out / 'compile.txt').open('wb') as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    result = subprocess.check_output([str(work / 'test')], text=True)
    parsed = json.loads(result)
    assert parsed['passed'] and parsed['can_publish'] is False
    assert parsed['live_device_references'] == 0
    (out / 'plan.json').write_text(json.dumps(parsed, indent=2) + '\n')
    report = dict(
        passed=True, cases=parsed['cases'], ubsan=True, pure_cpu=True,
        source_sha256={name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in paths.items()},
        context_patch_sha256=hashlib.sha256(patch.encode()).hexdigest(),
        extracted_sha256={name: hashlib.sha256(text.encode()).hexdigest() for name, text in generated.items()},
        fixture_sha256={name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                        for name in ('shim.h', 'preview.h', 'preview.c', 'test.c')},
        plan_sha256=hashlib.sha256((out / 'plan.json').read_bytes()).hexdigest(),
        full_bind_image_constructed=False, can_publish=False, hardware_access=False,
        kernel_build=False, sdk_source_modified=False, admission_gate_changed=False,
        firmware_abi_changed=False, previous_4098_matrix_rerun=False,
        kernel_api_shims=True, exact_device_lease_is_software_contract=True,
        complete_domain_or_withdrawal_proven=False,
    )
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    (BASE / 'logs/wired-preview-latest.json').write_text(json.dumps({'directory': str(out)}) + '\n')
    print(json.dumps(dict(directory=str(out), **report), indent=2), flush=True)
