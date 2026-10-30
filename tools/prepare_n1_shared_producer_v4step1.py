# SPDX-License-Identifier: MIT
"""Refactor the exact CT copier in isolation; no skb carrier or target change."""
from pathlib import Path
import argparse
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
from test_routed_context_functions import function

b=Path(__file__).resolve().parents[1]
sdk=Path('/root/be6l-openwrt/arm64-source')
k=sdk/'build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55'
p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);a=p.parse_args()
w=a.work.resolve()
assert w.parent==Path('/root/be6l-openwrt') and w.name.startswith('n1-ct-producer-v4step1-') and not w.exists()
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
pins={
 'net/netfilter/nf_flow_table_offload.c':'ec195a87165cd1d61cc27222036cba75960d2c3ba3f8c8e2984f85edd21d6432',
 'net/netfilter/nf_flow_table_core.c':'a4ff5d3cdc069486fcee9099d0f098bec573300bd2fa78688c21b7bfd4603556',
 'include/net/netfilter/nf_flow_table.h':'1e245a800b029553b2bad31d31dbf3d4ddd8d3b22003e20ba74e0fa98527ac99',
}
for name,digest in pins.items():assert sha(k/name)==digest
original={name:(k/name).read_text() for name in pins}
old=function(original['net/netfilter/nf_flow_table_offload.c'],'static bool\nnf_flow_rule_set_ct_context(')
shared=old.replace('static bool\nnf_flow_rule_set_ct_context(', 'bool\nnf_flow_ct_context_copy(',1)
assert shared[shared.index('{'):]==old[old.index('{'):]
offload=original['net/netfilter/nf_flow_table_offload.c'].replace(old+'\n','',1)
assert offload.count('nf_flow_rule_set_ct_context(')==2
offload=offload.replace('nf_flow_rule_set_ct_context(', 'nf_flow_ct_context_copy(')
core=original['net/netfilter/nf_flow_table_core.c']
needle='#include <net/netfilter/nf_conntrack.h>'
assert core.count(needle)==1
core=core.replace(needle,needle+'\n#include <net/netfilter/nf_conntrack_zones.h>')
needle='static DEFINE_MUTEX(flowtable_lock);'
assert core.count(needle)==1
core=core.replace(needle,shared+'\n\n'+needle)
header=original['include/net/netfilter/nf_flow_table.h']
enum=function(header,'enum flow_offload_tuple_dir {')+';'
assert header.count(enum)==1
prototype=shared[:shared.index('{')].strip()+';'
header=header.replace(enum,enum+'\n\n/* Shared by rule and future packet diagnostics inside nf_flow_table. */\n'+prototype)
assert 'EXPORT_SYMBOL' not in shared
changed={'net/netfilter/nf_flow_table_offload.c':offload,
         'net/netfilter/nf_flow_table_core.c':core,
         'include/net/netfilter/nf_flow_table.h':header}
w.mkdir();tree=w/'tree'
for name,text in changed.items():
 path=tree/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
patch=''.join(''.join(difflib.unified_diff(original[name].splitlines(True),text.splitlines(True),
                    fromfile='a/'+name,tofile='b/'+name)) for name,text in changed.items())
(w/'979-n1-share-exact-ct-context-copy-step1.patch').write_text(patch)
# Test the actual moved function with the same actual declarations, admission,
# parser and shared record header used by the previous producer test.
driver=k/'drivers/net/ethernet/airoha'
context=(k/'include/net/flow_offload.h').read_text()
zones=(k/'include/net/netfilter/nf_conntrack_zones.h').read_text()
common=(k/'include/linux/netfilter/nf_conntrack_zones_common.h').read_text()
diag_header=(driver/'diag.h').read_text()
declarations='\n'.join(function(text,marker)+';' for text,marker in [
 (common,'struct nf_conntrack_zone {'),(context,'struct flow_rule_ct_context {'),
 (diag_header,'struct bd_config {'),(diag_header,'struct bd_action_copy {'),
 (diag_header,'struct bd_egress {'),(diag_header,'struct bd_row {')])
functions='\n'.join([function(zones,'static inline bool nf_ct_zone_matches_dir('),
 function(zones,'static inline u16 nf_ct_zone_id('),shared,
 function((driver/'diag.c').read_text(),'static int bd_parse_arm(')])
actual=(b/'experiments/wired-kernel-diag-v2/test-record.c').read_text()
actual=actual.replace('nf_flow_rule_set_ct_context','nf_flow_ct_context_copy')
actual=actual.replace('/* ACTUAL_DECLARATIONS */',declarations).replace('/* ACTUAL_FUNCTIONS */',functions)
actual=actual.replace('/* ACTUAL_ADMISSION */',function((driver/'diag.c').read_text(),'static bool bd_context('))
(w/'actual-shared-producer.c').write_text(actual)
shutil.copyfile(driver/'record.h',w/'record.h')
out=b/'logs'/w.name;out.mkdir()
protected=[k/'.config',k/'arch/arm64/boot/Image',*k.rglob('*.ko'),*[k/name for name in pins]]
before={str(path):sha(path) for path in protected}
with (out/'host-compile.txt').open('wb') as log:
 subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-DCONFIG_NF_CONNTRACK_ZONES=1',
  '-fsanitize=undefined,address','-fno-sanitize-recover=all',str(w/'actual-shared-producer.c'),
  '-o',str(w/'actual-shared-producer')],stdout=log,stderr=subprocess.STDOUT,check=True)
tested=subprocess.check_output([str(w/'actual-shared-producer')],text=True)
(out/'actual-producer.txt').write_text(tested)
result=json.loads(tested.splitlines()[-1]);assert result['cases']==58
# Rebuild every object in the actual configured nf_flow_table composite.
members=(k/'net/netfilter/nf_flow_table.mod').read_text().splitlines()
expected=['nf_flow_table_core','nf_flow_table_ip','nf_flow_table_path','nf_flow_table_offload','nf_flow_table_xdp']
assert [Path(name).stem for name in members]==expected
module=tree/'net/netfilter'
pending=list(expected);copied=set()
for stem in pending:
 source=k/'net/netfilter'/(stem+'.c');dest=module/source.name
 if not dest.exists():shutil.copyfile(source,dest)
 # Only direct local headers are needed; reject path traversal in includes.
 for name in re.findall(r'^#include "([^"]+)"',source.read_text(),re.M):
  assert Path(name).name==name and name.endswith('.h'),name
  if name not in copied:
   shutil.copyfile(source.parent/name,module/name);copied.add(name)
make='obj-m += be6l-nf-context.o\nbe6l-nf-context-y := '+' '.join(stem+'.o' for stem in expected)+'\n'
(module/'Makefile').write_text(make)
gcc,=sdk.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
env=dict(os.environ,PATH='/root/be6l-openwrt/host/bin:'+os.environ['PATH'],
         STAGING_DIR=str(sdk/'staging_dir'),KCONFIG_NOSILENTUPDATE='1')
with (out/'full-flowtable-compile.txt').open('wb') as log:
 subprocess.run(['make','-C',str(k),'M='+str(module),'ARCH=arm64',
   'CROSS_COMPILE='+str(gcc)[:-3],'SHELL=/root/be6l-openwrt/host/bin/bash',
   'NOSTDINC_FLAGS=-nostdinc -I'+str(tree/'include'),'be6l-nf-context.o'],
   env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
linked=module/'be6l-nf-context.o'
symbols=subprocess.check_output([str(gcc)[:-3]+'nm','-g',str(linked)],text=True)
assert len(re.findall(r'^[0-9a-f]+ T nf_flow_ct_context_copy$',symbols,re.M))==1
assert '__ksymtab_nf_flow_ct_context_copy' not in symbols
assert {str(path):sha(path) for path in protected}==before
result.update(work=str(w),source_patch_sha256=sha(w/'979-n1-share-exact-ct-context-copy-step1.patch'),
 complete_configured_flowtable_link=True,configured_members=expected,
 shared_producer_body_identical=True,no_new_module_export=True,
 skb_carrier_implemented=False,packet_path_changed=False,
 target_executed=False,normal_image_built=False,sdk_unchanged=True,
 protected_files=len(protected),linked_sha256=sha(linked),
 actual_shared_producer_source_sha256=sha(w/'actual-shared-producer.c'),
 current_image_not_changed=True)
(out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print('N1_SHARED_PRODUCER_STEP1_ACTUAL_TESTS_AND_FULL_FLOWTABLE_LINK_PASS',out)
