"""Prepare patch974 and compile isolated real source; never touch a DUT/image.

The main cached driver/header are preserved for ongoing diagnostic ABI locks.
All new routed ownership code remains behind the existing routed refusal.
"""
from pathlib import Path
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import time

BASE = Path(__file__).resolve().parents[1]
SDK = Path('/root/be6l-openwrt/arm64-source')
KERNEL = SDK / 'build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55'
DRIVER = KERNEL / 'drivers/net/ethernet/airoha'
FIXTURE = BASE / 'experiments/wired-ownership'
OUT = BASE / 'logs' / time.strftime('wired-ownership-%Y%m%d-%H%M%S')
OUT.mkdir()
WORK = Path('/root/be6l-openwrt') / OUT.name
WORK.mkdir()
NAME = '974-net-airoha-prepare-wired-l4-ownership-without-admission.patch'
sha = lambda data: hashlib.sha256(data).hexdigest()

original = {name: (DRIVER / name).read_text() for name in ('airoha_ppe.c', 'airoha_eth.h')}
assert sha(original['airoha_ppe.c'].encode()) == '7b556e13910012010090678a4f9e30d707320404d0d6b7014323dbd0a99de0e7'
assert 'wired_egress_dev' not in original['airoha_eth.h']
updated = dict(original)

def replace_once(text, old, new):
    assert text.count(old) == 1, (old[:100], text.count(old))
    return text.replace(old, new, 1)

updated['airoha_eth.h'] = replace_once(updated['airoha_eth.h'],
    '\tstruct net_device *ingress_dev;\n',
    '\tstruct net_device *ingress_dev;\n'
    '\t/* Prospective AN7563 wired L4; routed admission remains disabled. */\n'
    '\tstruct net_device *wired_egress_dev;\n'
    '\tbool wired_l4, wired_dead;\n')
s = updated['airoha_ppe.c']
s = replace_once(s, '#include <linux/ip.h>\n', '#include <linux/ip.h>\n#include <linux/tcp.h>\n')
helpers = (FIXTURE / 'helpers.c').read_text()
s = replace_once(s, 'static void airoha_ppe_foe_set_bridge_addrs(', helpers + '\nstatic void airoha_ppe_foe_set_bridge_addrs(')
packet = (FIXTURE / 'packet-match.c').read_text()
s = replace_once(s, 'static int\nairoha_ppe_foe_commit_subflow_entry(', packet + '\nstatic int\nairoha_ppe_foe_commit_subflow_entry(')
s = replace_once(s,
    '\t\tif (!airoha_ppe_foe_compare_entry(e, hwe))\n\t\t\tcontinue;\n',
    '\t\tif (!airoha_ppe_foe_compare_entry(e, hwe))\n\t\t\tcontinue;\n'
    '\t\t/* Future routed parents must prove this packet and live input. */\n'
    '\t\tif (airoha_is_7563(ppe->eth) &&\n'
    '\t\t    !airoha_ppe_wired_l4_packet_match(ppe, e, hwe, skb))\n'
    '\t\t\tcontinue;\n')
s = replace_once(s,
    '\tif ((e->wdma_dev &&\n\t     READ_ONCE(e->wdma_dev->reg_state) != NETREG_REGISTERED) ||',
    '\tif (e->wired_dead ||\n'
    '\t    (e->wired_egress_dev &&\n'
    '\t     READ_ONCE(e->wired_egress_dev->reg_state) != NETREG_REGISTERED) ||\n'
    '\t    (e->wdma_dev &&\n\t     READ_ONCE(e->wdma_dev->reg_state) != NETREG_REGISTERED) ||')
lifecycle = (FIXTURE / 'lifecycle.c').read_text()
s = replace_once(s, 'static int airoha_ppe_netdevice_event(', lifecycle + '\nstatic int airoha_ppe_netdevice_event(')
start = s.index('static int airoha_ppe_netdevice_event(')
end = s.index('static int airoha_ppe_get_entry_idle_time(', start)
event = s[start:end]
event = replace_once(event,
    '\tif (event != NETDEV_UNREGISTER)\n\t\treturn NOTIFY_DONE;\n',
    '\tif (event != NETDEV_UNREGISTER && event != NETDEV_GOING_DOWN &&\n'
    '\t    event != NETDEV_PRECHANGEUPPER && event != NETDEV_CHANGEUPPER &&\n'
    '\t    event != NETDEV_CHANGEADDR && event != NETDEV_CHANGEMTU &&\n'
    '\t    event != NETDEV_CHANGE)\n\t\treturn NOTIFY_DONE;\n')
event = replace_once(event, '\tspin_lock_bh(&ppe_lock);\n',
    '\tspin_lock_bh(&ppe_lock);\n'
    '\thlist_for_each_entry(e, &ppe->ingress_flows, ingress_node)\n'
    '\t\tairoha_ppe_wired_l4_event(ppe, e, netdev,\n'
    '\t\t\t\t\t  event == NETDEV_UNREGISTER);\n'
    '\tif (event != NETDEV_UNREGISTER)\n\t\tgoto unlock;\n')
event = replace_once(event, '\tspin_unlock_bh(&ppe_lock);\n', 'unlock:\n\tspin_unlock_bh(&ppe_lock);\n')
s = s[:start] + event + s[end:]
s = replace_once(s, '\tmemcpy(&e->data, &hwe, sizeof(e->data));\n',
    '\tmemcpy(&e->data, &hwe, sizeof(e->data));\n'
    '\tif (airoha_is_7563(eth) && offload_type != PPE_PKT_TYPE_BRIDGE) {\n'
    '\t\terr = airoha_ppe_wired_l4_get_devs(eth->ppe, e, rule, odev,\n'
    '\t\t\t\t\t\t    offload_type, l4proto);\n'
    '\t\tif (err)\n\t\t\tgoto free_entry;\n\t}\n')
old_put = '\tdev_put(e->ingress_dev);\n\tdev_put(e->wdma_dev);\n'
assert s.count(old_put) == 3
s = s.replace(old_put, '\tairoha_ppe_flow_entry_put_devs(e);\n')
updated['airoha_ppe.c'] = s

# Keep every active safety gate and initialization exactly present.
assert s.count('if (airoha_is_7563(eth) && addr_type) {') == 1
assert '(FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, hwe.ib1) !=\n\t     PPE_PKT_TYPE_BRIDGE ||' in s
assert 'REG_PPE_PPE_FLOW_CFG(0), PPE_FLOW_CFG_L2_BRIDGE_MASK);' in s
assert original['airoha_ppe.c'][original['airoha_ppe.c'].index('static void airoha_ppe_an7563_init'):original['airoha_ppe.c'].index('int airoha_ppe_init(')] == s[s.index('static void airoha_ppe_an7563_init'):s.index('int airoha_ppe_init(')]

patch = '''Subject: [PATCH] net: airoha: prepare wired L4 ownership without admission

Prepare retained real ingress/Ethernet egress references, actual-packet checks
before a future AN7563 L4 bind, and L4 lifetime invalidation. Every AN7563
routed admission and bridge-subflow refusal remains in place; classification
stays L2-only. This patch does not enable NAT or add cache/register writes.
The new ownership path is prospective and unreachable under the current guard.

'''
for name in original:
    patch += ''.join(difflib.unified_diff(original[name].splitlines(True), updated[name].splitlines(True),
        fromfile='a/drivers/net/ethernet/airoha/' + name,
        tofile='b/drivers/net/ethernet/airoha/' + name, n=0))
destination = BASE / 'overlay/target/linux/airoha/patches-6.18' / NAME
if destination.exists():
    assert destination.read_text().startswith('Subject: [PATCH] net: airoha: prepare wired L4 ownership without admission\n')
subprocess.run(['patch', '--dry-run', '--forward', '-p1', '-d', str(KERNEL)], input=patch.encode(), check=True)
destination.write_text(patch)

def protected_files():
    paths = [KERNEL / '.config', KERNEL / 'arch/arm64/boot/Image']
    paths += sorted((SDK / 'build_dir/target-aarch64_cortex-a53_musl').rglob('*.ko'))
    return {str(path): sha(path.read_bytes()) for path in paths if path.is_file()}

protected = protected_files()
for path in DRIVER.glob('*.h'):
    shutil.copyfile(path, WORK / path.name)
for name, content in updated.items():
    (WORK / name).write_text(content)
(WORK / 'Makefile').write_text('obj-m += airoha_ppe.o\n')
for name in ('helpers.c', 'lifecycle.c', 'packet-match.c', 'test.c'):
    shutil.copyfile(FIXTURE / name, WORK / name)
header = (KERNEL / 'include/net/flow_offload.h').read_text()
context = re.search(r'struct flow_rule_ct_context \{.*?\n\};', header, re.S)[0]
defines = '\n'.join(line for line in header.splitlines() if line.startswith('#define FLOW_RULE_CT_CONTEXT_'))
(WORK / 'context.h').write_text(defines + '\n' + context + '\n')
with (OUT / 'unit-compile.txt').open('wb') as log:
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-fsanitize=undefined',
                    '-fno-sanitize-recover=all', '-o', str(WORK / 'test'), str(WORK / 'test.c')],
                   stdout=log, stderr=subprocess.STDOUT, check=True)
result = subprocess.run([str(WORK / 'test')], capture_output=True, text=True, check=True)
(OUT / 'unit.txt').write_text(result.stdout)
gcc, = SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
env = dict(os.environ)
env['PATH'] = '/root/be6l-openwrt/host/bin:' + env['PATH']
env['STAGING_DIR'] = str(SDK / 'staging_dir')
with (OUT / 'object-compile.txt').open('wb') as log:
    subprocess.run(['make', '-C', str(KERNEL), 'M=' + str(WORK), 'ARCH=arm64',
        'CROSS_COMPILE=' + str(gcc)[:-3], 'SHELL=/root/be6l-openwrt/host/bin/bash',
        'airoha_ppe.o'], env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
assert protected_files() == protected
for name in original:
    assert (DRIVER / name).read_text() == original[name]
obj = (WORK / 'airoha_ppe.o').read_bytes()
assert obj[:6] == b'\x7fELF\x02\x01' and obj[18:20] == b'\xb7\0'
report = dict(patch=NAME, patch_sha256=sha(patch.encode()),
    isolated_source_root=str(WORK), object_sha256=sha(obj),
    source_before={name: sha(value.encode()) for name, value in original.items()},
    source_after={name: sha(value.encode()) for name, value in updated.items()},
    real_source_helper_test=result.stdout.strip(), ubsan=True,
    prospective_unreachable_routed_ownership=True, routed_refusals_preserved=True,
    l2_classifier_unchanged=True, no_cache_or_new_register_writes=True,
    main_cached_source_unchanged=True, protected_files_unchanged=protected,
    isolated_actual_ppe_object_compiled=True, full_kernel_build=False,
    image_built=False, modules_installed=False, hardware_access=False)
(OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
(BASE / 'logs/wired-ownership-latest.json').write_text(json.dumps(dict(directory=str(OUT))) + '\n')
print(json.dumps(report, indent=2), flush=True)
