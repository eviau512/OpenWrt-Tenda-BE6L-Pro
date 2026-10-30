# SPDX-License-Identifier: MIT
"""Compile real packet-extension production in isolation; do not arm or deploy."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
from test_routed_context_functions import function

b=Path(__file__).resolve().parents[1]
sdk=Path('/root/be6l-openwrt/arm64-source')
k=sdk/'build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55'
p=argparse.ArgumentParser()
p.add_argument('--shared-proof',type=Path,required=True)
p.add_argument('--work',type=Path,required=True);a=p.parse_args()
proof=json.loads(a.shared_proof.read_text())
assert proof['cases']==58 and proof['sdk_unchanged'] and proof['complete_configured_flowtable_link']
source_work=Path(proof['work']);source_tree=source_work/'tree'
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
assert sha(source_tree/'net/netfilter/be6l-nf-context.o')==proof['linked_sha256']
w=a.work.resolve()
assert w.parent==Path('/root/be6l-openwrt') and w.name.startswith('n1-packet-prototype-') and not w.exists()
w.mkdir();tree=w/'tree'
files=['include/linux/skbuff.h','net/core/skbuff.c','net/core/flow_offload.c',
       'net/netfilter/nf_flow_table_ip.c']
original={name:(k/name).read_text() for name in files}
protected=[k/'.config',k/'arch/arm64/boot/Image',*k.rglob('*.ko'),*[k/name for name in files]]
before={str(path):sha(path) for path in protected}
config=(k/'.config').read_text()
assert '\nCONFIG_SKB_EXTENSIONS=y\n' in config and '\nCONFIG_NF_FLOW_TABLE=m\n' in config
def once(text,old,new):
 assert text.count(old)==1,old[:100]
 return text.replace(old,new)
# Start from the already compiled shared CT producer, not a duplicate copier.
for name in ('include/net/netfilter/nf_flow_table.h','net/netfilter/nf_flow_table_core.c',
             'net/netfilter/nf_flow_table_offload.c'):
 dest=tree/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source_tree/name,dest)
header=tree/'include/linux/flow_diag_packet.h';header.parent.mkdir(parents=True,exist_ok=True)
shutil.copyfile(b/'experiments/wired-packet-carrier-v1/packet.h',header)
skb_header=once(original['include/linux/skbuff.h'],'\tSKB_EXT_NUM, /* must be last */',
 '''#if IS_ENABLED(CONFIG_NF_FLOW_TABLE)
\tSKB_EXT_NF_FLOW_DIAG,
#endif
\tSKB_EXT_NUM, /* must be last */''')
skb=once(original['net/core/skbuff.c'],'#define SKB_EXT_ALIGN_VALUE\t8',
 '#include <linux/flow_diag_packet.h>\n#define SKB_EXT_ALIGN_VALUE\t8')
skb=once(skb,'static const u8 skb_ext_type_len[] = {','''static const u8 skb_ext_type_len[] = {
#if IS_ENABLED(CONFIG_NF_FLOW_TABLE)
\t[SKB_EXT_NF_FLOW_DIAG] = SKB_EXT_CHUNKSIZEOF(struct flow_diag_packet),
#endif''')
flow=once(original['net/core/flow_offload.c'],'#include <linux/kernel.h>',
 '#include <linux/kernel.h>\n#include <linux/ktime.h>\n#include <linux/spinlock.h>\n#include <linux/flow_diag_packet.h>')
lease=(b/'experiments/wired-packet-carrier-v1/lease.c.inc').read_text()
flow=once(flow,'struct flow_rule *flow_rule_alloc(',lease+'\nstruct flow_rule *flow_rule_alloc(')
ip=once(original['net/netfilter/nf_flow_table_ip.c'],'static unsigned int nf_flow_queue_xmit(',
 (b/'experiments/wired-packet-carrier-v1/nf-packet.c.inc').read_text()+'\nstatic unsigned int nf_flow_queue_xmit(')
ip=once(ip,'#include <linux/netfilter.h>','#include <linux/netfilter.h>\n#include <linux/flow_diag_packet.h>')
v4=function(ip,'nf_flow_offload_ip_hook(')
patched=once(v4,'\treturn nf_flow_queue_xmit(state->net, skb, &xmit);',
 '''\tnf_flow_diag_packet_emit(skb, state->net, flow, dir,
\t\t\t\t ctx.in->ifindex, xmit.outdev->ifindex);
\treturn nf_flow_queue_xmit(state->net, skb, &xmit);''')
ip=once(ip,v4,patched)
for name,text in [('include/linux/skbuff.h',skb_header),('net/core/skbuff.c',skb),
                  ('net/core/flow_offload.c',flow),('net/netfilter/nf_flow_table_ip.c',ip)]:
 path=tree/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
module=tree/'net/netfilter'
members=proof['configured_members']
for stem in members:
 path=module/(stem+'.c')
 if not path.exists():shutil.copyfile(k/'net/netfilter'/path.name,path)
 for name in re.findall(r'^#include "([^"]+)"',(k/'net/netfilter'/path.name).read_text(),re.M):
  assert Path(name).name==name and name.endswith('.h')
  shutil.copyfile(k/'net/netfilter'/name,module/name)
(module/'Makefile').write_text('obj-m += be6l-nf-packet.o\nbe6l-nf-packet-y := '+' '.join(x+'.o' for x in members)+'\n')
core=tree/'net/core'
# Built-in sources must retain their real built-in flags, not be compiled
# as artificial external modules. Copy only their recursively needed local
# headers into the isolated source directory.
pending=['skbuff.c','flow_offload.c'];seen=set()
while pending:
 name=pending.pop()
 if name in seen:continue
 seen.add(name)
 source=k/'net/core'/name
 if name.endswith('.h'):shutil.copyfile(source,core/name)
 for local in re.findall(r'^#include "([^"]+)"',source.read_text(),re.M):
  assert Path(local).name==local and local.endswith('.h'),local
  pending.append(local)
gcc,=sdk.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
env=dict(os.environ,PATH='/root/be6l-openwrt/host/bin:'+os.environ['PATH'],
         STAGING_DIR=str(sdk/'staging_dir'),KCONFIG_NOSILENTUPDATE='1')
out=b/'logs'/w.name;out.mkdir()
for label,directory,target in [('flowtable',module,'be6l-nf-packet.o')]:
 with (out/(label+'.txt')).open('wb') as log:
  subprocess.run(['make','-C',str(k),'M='+str(directory),'ARCH=arm64',
   'CROSS_COMPILE='+str(gcc)[:-3],'SHELL=/root/be6l-openwrt/host/bin/bash',
   'NOSTDINC_FLAGS=-nostdinc -I'+str(tree/'include'),target],
   env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
for stem in ('flow_offload','skbuff'):
 cached=(k/'net/core'/('.'+stem+'.o.cmd')).read_text().splitlines()[0]
 assert cached.startswith('savedcmd_') and ' := ' in cached
 argv=shlex.split(cached.split(' := ',1)[1])
 if argv[0]=='ccache':argv.pop(0)
 assert Path(argv[0]).name==gcc.name
 assert not any(x in argv for x in (';','&&','||','|','>','<'))
 inputs=[i for i,value in enumerate(argv) if value.endswith('.c')]
 assert len(inputs)==1 and argv.count('-o')==1
 dest=core/(stem+'.o')
 argv[0]=str(gcc);argv[inputs[0]]=str(core/(stem+'.c'))
 argv[argv.index('-o')+1]=str(dest)
 for i,value in enumerate(argv):
  if value.startswith('-Wp,-MMD,'):argv[i]='-Wp,-MMD,'+str(dest.with_suffix('.d'))
 argv[1:1]=['-I'+str(tree/'include')]
 with (out/(stem+'-actual-builtin.txt')).open('wb') as log:
  subprocess.run(argv,cwd=k,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
assert {str(path):sha(path) for path in protected}==before
report=dict(work=str(w),source_shared_proof_sha256=sha(a.shared_proof),
    real_flowtable_composite_compiled=True,real_skb_extension_implementation_compiled=True,
    real_builtin_lease_implementation_compiled=True,source_context_bytes=56,packet_bytes=88,
    sdk_unchanged=True,protected_files=len(protected),target_executed=False,
    driver_arming_and_consumer_implemented=False,skb_carrier_runtime_qualified=False,
    clone_allocation_failure_drain_target_tests=False,normal_image_built=False,
    hardware_publish_added=False,ct_reference_added=False,skb_cb_used=False,
    objects={label:sha(tree/name) for label,name in [
      ('flowtable','net/netfilter/be6l-nf-packet.o'),
      ('skb','net/core/skbuff.o'),('flow','net/core/flow_offload.o')]},
    real_cached_builtin_flags_preserved=True,local_core_headers=sorted(seen))
(out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print('N1_PACKET_PRODUCER_AND_REAL_SKB_IMPLEMENTATION_COMPILE_PASS_NOT_RUNTIME',out)
