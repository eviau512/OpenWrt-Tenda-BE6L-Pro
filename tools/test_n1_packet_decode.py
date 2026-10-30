# SPDX-License-Identifier: MIT
"""Compile the real decoder with actual CT declarations/predicate; no DUT."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
from test_routed_context_functions import function

b=Path(__file__).resolve().parents[1]
sdk=Path('/root/be6l-openwrt/arm64-source')
k=sdk/'build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55'
p=argparse.ArgumentParser();p.add_argument('--prototype-proof',type=Path,required=True)
p.add_argument('--attempt',type=int,choices=(1,2),default=1);a=p.parse_args()
r=json.loads(a.prototype_proof.read_text())
assert r['sdk_unchanged'] and r['real_skb_extension_implementation_compiled']
w=Path(r['work']);suffix='' if a.attempt==1 else '-retry2'
test=w/('decode-host-test'+suffix);assert not test.exists();test.mkdir()
source=b/'experiments/wired-packet-carrier-v1'
inc=test/'include';(inc/'linux').mkdir(parents=True);(inc/'net').mkdir()
shutil.copyfile(w/'tree/include/linux/flow_diag_packet.h',inc/'linux/flow_diag_packet.h')
shutil.copyfile(source/'decode.h',test/'decode.h')
types='#include <stdint.h>\n#include <stdbool.h>\ntypedef uint64_t u64;\ntypedef uint32_t u32;\ntypedef int32_t s32;\ntypedef uint16_t u16;\ntypedef uint8_t u8;\n'
(inc/'linux/types.h').write_text('#pragma once\n'+types)
(inc/'linux/string.h').write_text('#include <string.h>\n')
(inc/'linux/build_bug.h').write_text('#define BUILD_BUG_ON(c) _Static_assert(!(c), "kernel layout contract")\n')
flow=(k/'include/net/flow_offload.h').read_text()
context=function(flow,'struct flow_rule_ct_context {')+';'
(inc/'net/flow_offload.h').write_text('#include <linux/types.h>\n#define FLOW_RULE_CT_CONTEXT_VERSION 2\n#define FLOW_RULE_CT_CONTEXT_NF_FLOWTABLE 1\n'+context+'\n')
driver=k/'drivers/net/ethernet/airoha'
predicate=function((driver/'record.h').read_text(),'static bool bd_identity_valid(')+'\n'+function((driver/'diag.c').read_text(),'static bool bd_context(')
actual=(source/'test-decode.c').read_text().replace('/* ACTUAL_CONTEXT_PREDICATE */',predicate)
(test/'actual-decode.c').write_text(actual)
out=b/'logs'/(w.name+'-decode'+suffix);out.mkdir()
with (out/'host-compile.txt').open('wb') as log:
 subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror',
  '-fsanitize=undefined,address','-fno-sanitize-recover=all','-I'+str(inc),
  str(test/'actual-decode.c'),'-o',str(test/'actual-decode')],
  stdout=log,stderr=subprocess.STDOUT,check=True)
text=subprocess.check_output([str(test/'actual-decode')],text=True)
(out/'actual-decode.txt').write_text(text)
result=json.loads(text);assert result['decode_checks']>=35
# Compile against real kernel types and actual flags, not the host shim.
tree=w/'tree';real_header=tree/'include/net/flow_diag_decode.h'
real_header.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/'decode.h',real_header)
probe=tree/('net/core/diag_decode_probe'+str(a.attempt)+'.c')
probe.write_text('''#include <net/flow_diag_decode.h>
bool be6l_decode_type_probe(const struct flow_diag_packet *p,
 bool (*valid)(const struct flow_rule_ct_context *), struct flow_rule_ct_context *out);
bool be6l_decode_type_probe(const struct flow_diag_packet *p,
 bool (*valid)(const struct flow_rule_ct_context *), struct flow_rule_ct_context *out)
{ return flow_diag_packet_decode(p, 1, 2, 1, 5, 3, 3, valid, out); }
''')
gcc,=sdk.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
line=(k/'net/core/.flow_offload.o.cmd').read_text().splitlines()[0]
argv=shlex.split(line.split(' := ',1)[1])
if argv[0]=='ccache':argv.pop(0)
assert Path(argv[0]).name==gcc.name and not any(x in argv for x in (';','&&','|','>'))
inputs=[i for i,x in enumerate(argv) if x.endswith('.c')];assert len(inputs)==1
obj=probe.with_suffix('.o');argv[0]=str(gcc);argv[inputs[0]]=str(probe)
argv[argv.index('-o')+1]=str(obj)
for i,value in enumerate(argv):
 if value.startswith('-Wp,-MMD,'):argv[i]='-Wp,-MMD,'+str(obj.with_suffix('.d'))
argv[1:1]=['-I'+str(tree/'include')]
env=dict(os.environ,PATH='/root/be6l-openwrt/host/bin:'+os.environ['PATH'],STAGING_DIR=str(sdk/'staging_dir'))
with (out/'real-kernel-types.txt').open('wb') as log:
 subprocess.run(argv,cwd=k,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
result.update(real_kernel_types_compiled=True,header_sha256=hashlib.sha256(real_header.read_bytes()).hexdigest(),
 actual_predicate_sha256=hashlib.sha256(predicate.encode()).hexdigest(),
 driver_consumer_wired=False,target_executed=False,skb_lifetimes_qualified=False)
(out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print('ACTUAL_PACKET_DECODE_AND_REAL_KERNEL_TYPE_TESTS_PASS_NO_TARGET',out)
