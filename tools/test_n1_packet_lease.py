# SPDX-License-Identifier: MIT
"""Test the actual lease API with a fake clock; not skb-lifetime acceptance."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import subprocess

b=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--prototype-proof',type=Path,required=True);a=p.parse_args()
r=json.loads(a.prototype_proof.read_text())
assert r['sdk_unchanged'] and r['real_cached_builtin_flags_preserved']
assert r['real_flowtable_composite_compiled'] and r['real_skb_extension_implementation_compiled']
w=Path(r['work']);test=w/'lease-host-test';assert not test.exists();test.mkdir()
source=b/'experiments/wired-packet-carrier-v1'
header=w/'tree/include/linux/flow_diag_packet.h'
core=(w/'tree/net/core/flow_offload.c').read_text()
lease=(source/'lease.c.inc').read_text()
assert lease in core
shutil.copyfile(header,test/'packet.h')
shutil.copyfile(source/'lease.c.inc',test/'lease.c.inc')
shutil.copyfile(source/'test-lease.c',test/'test-lease.c')
shim=test/'include/linux';shim.mkdir(parents=True)
(shim/'types.h').write_text('#include <stdint.h>\ntypedef uint64_t u64;\ntypedef uint32_t u32;\ntypedef int32_t s32;\ntypedef uint16_t u16;\n')
out=b/'logs'/(w.name+'-lease');out.mkdir()
with (out/'compile.txt').open('wb') as log:
 subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror',
  '-fsanitize=undefined,address','-fno-sanitize-recover=all','-I'+str(test/'include'),
  str(test/'test-lease.c'),'-o',str(test/'test-lease')],stdout=log,stderr=subprocess.STDOUT,check=True)
text=subprocess.check_output([str(test/'test-lease')],text=True)
(out/'test.txt').write_text(text)
result=json.loads(text)
assert result['checks']>=30 and result['actual_lease_source']
result.update(source_sha256=hashlib.sha256(lease.encode()).hexdigest(),
 packet_header_sha256=hashlib.sha256(header.read_bytes()).hexdigest(),
 fake_clock_and_lock_shim=True,target_executed=False,
 skb_clone_cow_free_tested=False,allocation_failure_tested=False)
(out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print('ACTUAL_PACKET_LEASE_BOUNDARY_TESTS_PASS_NOT_SKB_LIFETIMES',out)
