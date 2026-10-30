# SPDX-License-Identifier: MIT
"""Test and compile a full-identity record consumer, without wiring or arming."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
from test_routed_context_functions import function

b=Path(__file__).resolve().parents[1];sdk=Path('/root/be6l-openwrt/arm64-source')
k=sdk/'build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55'
p=argparse.ArgumentParser();p.add_argument('--shared-proof',type=Path,required=True)
p.add_argument('--prototype-proof',type=Path,required=True)
p.add_argument('--work',type=Path,required=True);a=p.parse_args()
shared=json.loads(a.shared_proof.read_text());proto=json.loads(a.prototype_proof.read_text())
assert shared['cases']==58 and shared['shared_producer_body_identical'] and proto['sdk_unchanged']
w=a.work.resolve()
assert w.parent==Path('/root/be6l-openwrt') and w.name.startswith('n1-carried-record-') and not w.exists()
w.mkdir();tree=w/'tree';driver=tree/'drivers/net/ethernet/airoha';driver.mkdir(parents=True)
shutil.copytree(Path(proto['work'])/'tree/include',tree/'include')
for source in (k/'drivers/net/ethernet/airoha').iterdir():
 if source.suffix in ('.c','.h'):shutil.copyfile(source,driver/source.name)
header=(driver/'diag.h').read_text()
old_struct=function(header,'struct bd_egress {')
new_struct=old_struct.replace('\tbool was_gso, format_complete, delivered;',
 '\tbool was_gso, format_complete, delivered;\n\tbool has_producer_context;\n\tstruct flow_rule_ct_context producer_context;')
assert new_struct!=old_struct
(driver/'diag.h').write_text(header.replace(old_struct,new_struct,1))
record=(driver/'record.h').read_text()
needle='\tfor (i = 0; i < BD_SLOTS; i++) {'
start=record.index('static bool bd_record_egress(')
before=record[:start];body=record[start:]
assert body.count(needle)==1
body=body.replace(needle,''' if (sample->has_producer_context &&
     (!bd_identity_valid(&sample->producer_context) ||
      sample->producer_context.direction != sample->direction ||
      sample->producer_context.ct_cookie != sample->ct_cookie))
  return false;
'''+needle)
needle='\t\tfor (j = 0; j < BD_SLOTS; j++) {'
assert body.count(needle)==1
body=body.replace(needle,'''  if (sample->has_producer_context &&
      memcmp(&row->context, &sample->producer_context, sizeof(row->context)))
   continue;
'''+needle)
(driver/'record.h').write_text(before+body)
actual=(Path(shared['work'])/'actual-shared-producer.c').read_text()
assert actual.count(old_struct)==1
actual=actual.replace(old_struct,new_struct)
addition=r'''
 {
  struct bd_egress e={.ct_cookie=c.ct_cookie,.direction=0,
   .logical_output_ifindex=7,.has_producer_context=true,
   .key={30,20,(5555U<<16)|443}}, good;
  e.producer_context=c;
  memset(rows,0,sizeof(rows));
  row=saved;row.output_ifindex=7;
  row.key[0]=10;row.key[1]=20;row.key[2]=(1234U<<16)|443;
  assert(bd_record_replace(rows,&row)==1);
  row.context=pair;row.direction=1;row.output_ifindex=8;
  row.key[0]=20;row.key[1]=30;row.key[2]=(443U<<16)|5555;
  assert(bd_record_replace(rows,&row)==1);
  assert(bd_record_egress(rows,&e));cases++;
  memcpy(&good,&e,sizeof(e));
  for (unsigned int i=0;i<sizeof(e.producer_context);i++) {
   e.producer_context=c;
   ((unsigned char *)&e.producer_context)[i]^=1;
   assert(!bd_record_egress(rows,&e));
   assert(!memcmp(&rows[0].egress,&good,sizeof(good)));cases++;
  }
  e.producer_context=c;
  assert(bd_record_egress(rows,&e));cases++;
 }
'''
needle=' puts("N1_ACTUAL_RECORD_AND_PRODUCER_PASS");'
assert actual.count(needle)==1
actual=actual.replace(needle,addition+'\n'+needle)
(w/'actual-record.c').write_text(actual);shutil.copyfile(driver/'record.h',w/'record.h')
out=b/'logs'/w.name;out.mkdir()
with (out/'host-compile.txt').open('wb') as log:
 subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror',
  '-DCONFIG_NF_CONNTRACK_ZONES=1','-fsanitize=undefined,address','-fno-sanitize-recover=all',
  str(w/'actual-record.c'),'-o',str(w/'actual-record')],stdout=log,stderr=subprocess.STDOUT,check=True)
text=subprocess.check_output([str(w/'actual-record')],text=True)
(out/'actual-record.txt').write_text(text);result=json.loads(text.splitlines()[-1])
assert result['cases']==116
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
protected=[k/'.config',k/'arch/arm64/boot/Image',*k.rglob('*.ko')]
before_hashes={str(path):sha(path) for path in protected}
gcc,=sdk.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
env=dict(os.environ,PATH='/root/be6l-openwrt/host/bin:'+os.environ['PATH'],STAGING_DIR=str(sdk/'staging_dir'))
objects=[]
for stem in ('airoha_eth','airoha_ppe','airoha_ppe_debugfs','diag'):
 cached=(k/'drivers/net/ethernet/airoha'/('.'+stem+'.o.cmd')).read_text().splitlines()[0]
 argv=shlex.split(cached.split(' := ',1)[1])
 if argv[0]=='ccache':argv.pop(0)
 assert Path(argv[0]).name==gcc.name and not any(x in argv for x in (';','&&','|','>'))
 inputs=[i for i,x in enumerate(argv) if x.endswith('.c')];assert len(inputs)==1
 obj=driver/(stem+'.o');objects.append(obj)
 argv[0]=str(gcc);argv[inputs[0]]=str(driver/(stem+'.c'));argv[argv.index('-o')+1]=str(obj)
 for i,value in enumerate(argv):
  if value.startswith('-Wp,-MMD,'):argv[i]='-Wp,-MMD,'+str(obj.with_suffix('.d'))
 argv[1:1]=['-I'+str(tree/'include')]
 with (out/(stem+'.txt')).open('wb') as log:
  subprocess.run(argv,cwd=k,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
linked=driver/'airoha-eth.o'
subprocess.run([str(gcc)[:-3]+'ld','-r','-o',str(linked),*[str(x) for x in objects]],check=True)
assert {str(path):sha(path) for path in protected}==before_hashes
result.update(full_identity_byte_mutations=56,complete_actual_driver_link=True,
 original_cached_builtin_flags=True,linked_sha256=sha(linked),work=str(w),
 decoder_to_driver_wired=False,driver_arming_wired=False,sdk_unchanged=True,
 target_executed=False,normal_image_built=False,skb_lifetimes_qualified=False,
 record_header_sha256=sha(driver/'record.h'),private_header_sha256=sha(driver/'diag.h'))
(out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print('CARRIED_IDENTITY_RECORD_116_CASES_AND_FULL_DRIVER_LINK_PASS_NO_TARGET',out)
