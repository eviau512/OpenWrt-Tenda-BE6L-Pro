# SPDX-License-Identifier: MIT
"""Test actual N1 producer/store and compile cached ABI consumers privately.

Also builds and links the complete Airoha Ethernet driver in an external Kbuild
directory. No SDK object, module, config, image or device is changed. A normal
matched kernel/package/image build and real callback tests remain mandatory.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
BASE = HERE.parents[1]
sys.path.insert(0, str(BASE / 'tools'))
from test_routed_context_functions import function

sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--work', type=Path, required=True)
parser.add_argument('--reuse-consumers', type=Path, help='A prior passed receipt with exactly matching ABI/source overlays')
args = parser.parse_args()
work = args.work.resolve()
assert work.parent == Path('/root/be6l-openwrt') and work.name.startswith('n1-identity-v2-')
receipt = json.loads((work / 'preparation.json').read_text())
SDK = Path(receipt['sdk'])
K = SDK / 'build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55'
tree = work / 'tree'
driver = tree / 'drivers/net/ethernet/airoha'
out = BASE / 'logs' / time.strftime('n1-identity-v2-%Y%m%d-%H%M%S')
out.mkdir()
protected = [K / '.config', K / 'arch/arm64/boot/Image', *K.rglob('*.ko')]
protected += [K / p for p in receipt['source_files']]
before = {str(p): sha(p) for p in protected}
assert all(sha(K / p) == h for p, h in receipt['source_files'].items())
header = (tree / 'include/net/flow_offload.h').read_text()
nf = (tree / 'net/netfilter/nf_flow_table_offload.c').read_text()
assert 'flow_offload_diag_next_generation();' in (tree / 'net/netfilter/nf_flow_table_core.c').read_text()
assert 'static atomic64_t flow_diag_serial' in (tree / 'net/core/flow_offload.c').read_text()
core_make = (K / 'net/core/Makefile').read_text().replace('\\\n', ' ')
assert re.search(r'(?m)^obj-y\s*[:+]?=\s*[^\n]*\bflow_offload\.o\b', core_make)
zones = (K / 'include/net/netfilter/nf_conntrack_zones.h').read_text()
common = (K / 'include/linux/netfilter/nf_conntrack_zones_common.h').read_text()
diag_header = (driver / 'diag.h').read_text()
declarations = '\n'.join(function(text, marker) + ';' for text, marker in [
    (common, 'struct nf_conntrack_zone {'), (header, 'struct flow_rule_ct_context {'),
    (diag_header, 'struct bd_config {'), (diag_header, 'struct bd_action_copy {'),
    (diag_header, 'struct bd_egress {'), (diag_header, 'struct bd_row {')])
functions = '\n'.join([
    function(zones, 'static inline bool nf_ct_zone_matches_dir('),
    function(zones, 'static inline u16 nf_ct_zone_id('),
    function(nf, 'static bool\nnf_flow_rule_set_ct_context('),
    function((driver / 'diag.c').read_text(), 'static int bd_parse_arm(')])
actual = (HERE / 'test-record.c').read_text().replace('/* ACTUAL_DECLARATIONS */', declarations)
actual = actual.replace('/* ACTUAL_FUNCTIONS */', functions)
actual = actual.replace('/* ACTUAL_ADMISSION */', function((driver / 'diag.c').read_text(), 'static bool bd_context('))
(work / 'actual-record.c').write_text(actual)
shutil.copyfile(HERE / 'record.h', work / 'record.h')
with (out / 'host-compile.txt').open('wb') as output:
    subprocess.run(['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
        '-DCONFIG_NF_CONNTRACK_ZONES=1',
        '-fsanitize=undefined,address', '-fno-sanitize-recover=all', str(work / 'actual-record.c'),
        '-o', str(work / 'actual-record')], stdout=output, stderr=subprocess.STDOUT, check=True)
tested = subprocess.check_output([str(work / 'actual-record')], text=True)
(out / 'actual-record.txt').write_text(tested)
result = json.loads(tested.splitlines()[-1])
gcc, = SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
env = dict(os.environ, PATH='/root/be6l-openwrt/host/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
           STAGING_DIR=str(SDK / 'staging_dir'), KCONFIG_NOSILENTUPDATE='1')
objects = work / 'consumer-objects' / out.name
objects.mkdir(parents=True)
compiled = {}
reused_from = None
if args.reuse_consumers:
    prior_path = args.reuse_consumers.resolve()
    assert prior_path.is_relative_to(BASE / 'logs') and prior_path.name == 'result.json'
    prior = json.loads(prior_path.read_text())
    assert prior['complete_airoha_translation_units_and_link'] and prior['sdk_image_config_modules_sources_unchanged']
    old_work = Path(prior['work'])
    old_preparation = json.loads((old_work / 'preparation.json').read_text())
    for name, digest in old_preparation['changed_files'].items():
        if name in ('drivers/net/ethernet/airoha/airoha_eth.c', 'drivers/net/ethernet/airoha/airoha_ppe.c'):
            continue  # These exact members are fully rebuilt and linked below.
        assert sha(tree / name) == digest, 'Changed ABI/producer must be recompiled: ' + name
    for name, digest in old_preparation['source_files'].items():
        assert sha(K / name) == digest
    compiled = dict(prior['compiled_cached_abi_consumers'])
    reused_from = dict(receipt=str(prior_path), sha256=sha(prior_path), consumers=len(compiled))
commands = () if reused_from else sorted(K.rglob('.*.o.cmd'))
for cmd_file in commands:
    text = cmd_file.read_text(errors='replace')
    dependencies = ('include/net/flow_offload.h', 'include/net/netfilter/nf_flow_table.h')
    if not any(name in text for name in dependencies):
        continue
    first = text.splitlines()[0]
    if not first.startswith('savedcmd_') or ' := ' not in first:
        continue
    argv = shlex.split(first.split(' := ', 1)[1])
    if argv and argv[0] == 'ccache':
        argv.pop(0)
    if not argv or Path(argv[0]).name != gcc.name:
        continue
    assert not any(x in argv for x in (';', '&&', '||', '|', '>', '<')), cmd_file
    inputs = [i for i, a in enumerate(argv) if a.endswith('.c')]
    assert len(inputs) == 1 and argv.count('-o') == 1, cmd_file
    src = Path(argv[inputs[0]])
    if src.is_absolute():
        src = src.relative_to(K)
    source = tree / src if (tree / src).is_file() else K / src
    assert source.is_file(), source
    destination = objects / src.with_suffix('.o')
    destination.parent.mkdir(parents=True, exist_ok=True)
    argv[0] = str(gcc)
    argv[inputs[0]] = str(source)
    argv[argv.index('-o') + 1] = str(destination)
    for i, item in enumerate(argv):
        if item.startswith('-Wp,-MMD,'):
            argv[i] = '-Wp,-MMD,' + str(destination.with_suffix('.d'))
    # Resolve the ordinary includes in their original source order. Forced
    # pre-inclusion changes pr_fmt setup and is not equivalent to a real tree.
    argv[1:1] = ['-I' + str(tree / 'include')]
    log = out / (src.as_posix().replace('/', '__') + '.txt')
    with log.open('wb') as output:
        subprocess.run(argv, cwd=K, env=env, stdout=output, stderr=subprocess.STDOUT, check=True)
    compiled[src.as_posix()] = sha(destination)
    print('ABI_CONSUMER_COMPILED', src, flush=True)
assert 'net/netfilter/nf_flow_table_core.c' in compiled
assert 'net/netfilter/nf_flow_table_offload.c' in compiled
assert 'net/core/flow_offload.c' in compiled
assert 'drivers/net/ethernet/airoha/airoha_ppe.c' in compiled
original_makefile = (driver / 'Makefile').read_text()
(driver / 'Makefile.production').write_text(original_makefile)
(driver / 'Makefile').write_text('obj-m += airoha-eth.o\nairoha-eth-y := airoha_eth.o airoha_ppe.o airoha_ppe_debugfs.o diag.o\n')
try:
    with (out / 'complete-airoha-driver.txt').open('wb') as output:
        subprocess.run(['make', '-C', str(K), 'M=' + str(driver), 'ARCH=arm64',
            'CROSS_COMPILE=' + str(gcc)[:-3], 'SHELL=/root/be6l-openwrt/host/bin/bash',
            'NOSTDINC_FLAGS=-nostdinc -I' + str(tree / 'include'),
            'airoha-eth.o'], env=env, stdout=output, stderr=subprocess.STDOUT, check=True)
finally:
    (driver / 'Makefile').write_text(original_makefile)
assert {str(p): sha(p) for p in protected} == before
assert all(sha(K / p) == h for p, h in receipt['source_files'].items())
linked = driver / 'airoha-eth.o'
data = linked.read_bytes()
assert data[:6] == b'\x7fELF\x02\x01' and data[18:20] == b'\xb7\0'
for name in ('airoha_eth', 'airoha_ppe', 'airoha_ppe_debugfs', 'diag'):
    compiled['drivers/net/ethernet/airoha/' + name + '.c'] = sha(driver / (name + '.o'))
result.update(schema=1, complete_airoha_translation_units_and_link=True,
    compiled_cached_abi_consumers=compiled, linked_driver_sha256=sha(linked),
    sdk_image_config_modules_sources_unchanged=True, protected_file_count=len(before),
    work=str(work), target_executed=False, normal_matched_image_built=False,
    rcu_lifetime_executed_on_target=False, userspace_arming_interface=True,
    arming_controls_cpu_observation_only=True, automatic_unb_classification_change=False,
    software_egress_implemented=True, software_egress_complete=False, direct_ct_destroy_notifier=False,
    reused_matching_consumer_evidence=reused_from,
    actual_host_test_source_sha256=sha(work / 'actual-record.c'),
    actual_host_record_header_sha256=sha(work / 'record.h'),
    routed_refusal_preserved=True, source_patch_sha256=sha(work / '977-n1-identity-and-inert-driver-taps.patch'))
(out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
(BASE / 'logs/n1-identity-v2-latest.json').write_text(json.dumps(dict(directory=str(out))) + '\n')
print('N1_V2_OFFLINE_COMPILE_PASS', out)
