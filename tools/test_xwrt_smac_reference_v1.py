# SPDX-License-Identifier: MIT
"""Execute pinned941-04 SMAC functions with substituted host transactions.

This tests the reference's resource rules, not a BE6L port, locking or DMA.
Test field encodings/register tokens are symbolic; no MMIO is performed.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
from test_xwrt_sram_policy_v1 import function
from package_native_netifd_v3 import sha

NAMES = ('airoha_ppe_smac_write', 'airoha_ppe_smac_get', 'airoha_ppe_smac_put')
PRELUDE = r'''
/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8; typedef uint32_t u32;
#define BIT(n) (1U << (n))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define FIELD_GET(m,v) (((v)&(m)) >> __builtin_ctz(m))
#define FIELD_PREP(m,v) (((u32)(v) << __builtin_ctz(m)) & (m))
#define AIROHA_FOE_IB1_BIND_PACKET_TYPE 15U
#define AIROHA_FOE_IB1_BIND_TTL BIT(4)
#define AIROHA_FOE_MAC_SMAC_ID 31U
#define PPE_UPDMEM_ADDR_MASK 31U
#define PPE_UPDMEM_OFFSET_MASK (3U<<8)
#define PPE_UPDMEM_WR_MASK BIT(12)
#define PPE_UPDMEM_REQ_MASK BIT(13)
#define PPE_UPDMEM_ACK_MASK BIT(14)
#define REG_UPDMEM_DATA(i) ((i)*2)
#define REG_UPDMEM_CTRL(i) ((i)*2+1)
enum {PPE_PKT_TYPE_IPV6_ROUTE_3T=2,PPE_PKT_TYPE_IPV6_ROUTE_5T=3};
#define lockdep_assert_held(x) do{}while(0)
#define spin_lock_irqsave(x,f) do{(f)=0;}while(0)
#define spin_unlock_irqrestore(x,f) do{(void)(f);}while(0)
#define dev_err_ratelimited(...) do{}while(0)
static int writes, fail_transaction, warnings, banks[64];
#define WARN_ON_ONCE(x) ((x) ? (warnings++,true) : false)
struct airoha_ppe_smac {u8 addr[6]; u32 refs; bool valid;};
struct airoha_eth {struct {int num_ppe;} *soc;};
struct airoha_ppe {struct {struct airoha_eth *eth;} common;
    struct airoha_ppe_smac smac[15]; int smac_lock; bool smac_failed;};
struct airoha_flow_table_entry {bool smac_ref;
    struct {u32 ib1; struct {struct {u32 src_mac_hi;} l2;} ipv6;} data;};
static u32 get_unaligned_be32(const u8 *p) {return (u32)p[0]<<24|(u32)p[1]<<16|(u32)p[2]<<8|p[3];}
static u32 get_unaligned_be16(const u8 *p) {return (u32)p[0]<<8|p[1];}
static bool is_valid_ether_addr(const u8 *p) {u8 v=0;for(int i=0;i<6;i++)v|=p[i];return v&&!(p[0]&1);}
static bool ether_addr_equal(const u8 *a,const u8 *b) {return !memcmp(a,b,6);}
static void ether_addr_copy(u8 *a,const u8 *b) {memcpy(a,b,6);}
static void airoha_fe_wr(struct airoha_eth *eth,int reg,u32 value) {
    if(reg&1){banks[writes]=reg/2;writes++;}
}
#define read_poll_timeout_atomic(op,v,cond,delay,bound,sleep,eth,reg) ({ \
    (v)=fail_transaction==writes ? 0 : PPE_UPDMEM_ACK_MASK; (cond)?0:-ETIMEDOUT;})
'''
MAIN = r'''
int main(void) {
 const char *names[]={"non-ipv6-control","no-ttl-control","invalid-multicast",
 "two-bank-publish","shared-reference","pool-exhaustion","put-idempotent",
 "cached-reacquire","free-slot-reprogram","timeout-bank0-word0","timeout-bank0-word1",
 "timeout-bank1-word0","timeout-bank1-word1","cached-share-after-latched-timeout",
 "invalid-put-retains-reference","invalid-zero-mac"};
 int failures=0;
 for(int t=0;t<16;t++) {
  struct {int num_ppe;} soc={2}; struct airoha_eth eth; eth.soc=(void*)&soc;
  struct airoha_ppe p={.common={.eth=&eth}};
  struct airoha_flow_table_entry e={.data={.ib1=PPE_PKT_TYPE_IPV6_ROUTE_3T|AIROHA_FOE_IB1_BIND_TTL}};
  struct airoha_flow_table_entry other=e; u8 a[6]={2,0,0,0,0,1}, b[6]={2,0,0,0,0,2};
  writes=warnings=fail_transaction=0; memset(banks,0,sizeof(banks)); bool ok=false; int r;
  if(t==0)e.data.ib1=0;
  if(t==1)e.data.ib1=PPE_PKT_TYPE_IPV6_ROUTE_3T;
  if(t==2)a[0]=1;
  if(t==15)memset(a,0,6);
  if(t>=9&&t<=12)fail_transaction=t-8;
  if(t==14){e.smac_ref=true;e.data.ipv6.l2.src_mac_hi=16;airoha_ppe_smac_put(&p,&e);ok=e.smac_ref&&warnings==1&&!writes;}
  else {
   r=airoha_ppe_smac_get(&p,&e,a);
   if(t<=1)ok=!r&&!writes&&!e.smac_ref;
   if(t==2||t==15)ok=r==-EINVAL&&!writes&&!e.smac_ref;
   if(t==3)ok=!r&&writes==4&&p.smac[0].refs==1&&e.smac_ref&&p.smac[0].valid&&banks[0]==0&&banks[1]==0&&banks[2]==1&&banks[3]==1;
   if(t==4){r=airoha_ppe_smac_get(&p,&other,a);ok=!r&&writes==4&&p.smac[0].refs==2&&other.smac_ref;}
   if(t==5){for(int i=2;i<=15;i++){other=e;other.smac_ref=false;a[5]=i;r=airoha_ppe_smac_get(&p,&other,a);if(r)break;}a[5]=250;r=airoha_ppe_smac_get(&p,&other,a);ok=r==-ENOSPC&&writes==60;}
   if(t==6){airoha_ppe_smac_put(&p,&e);airoha_ppe_smac_put(&p,&e);ok=!e.smac_ref&&!p.smac[0].refs&&!warnings;}
   if(t==7){airoha_ppe_smac_put(&p,&e);r=airoha_ppe_smac_get(&p,&e,a);ok=!r&&writes==4&&p.smac[0].refs==1;}
   if(t==8){airoha_ppe_smac_put(&p,&e);r=airoha_ppe_smac_get(&p,&e,b);ok=!r&&writes==8&&p.smac[0].refs==1&&ether_addr_equal(p.smac[0].addr,b);}
   if(t>=9&&t<=12){int saved=writes;int next=airoha_ppe_smac_get(&p,&other,b);ok=r==-ETIMEDOUT&&p.smac_failed&&!e.smac_ref&&!p.smac[0].refs&&!p.smac[0].valid&&next==-EIO&&writes==saved;}
   if(t==13){fail_transaction=5;r=airoha_ppe_smac_get(&p,&other,b);other=e;other.smac_ref=false;int next=airoha_ppe_smac_get(&p,&other,a);ok=r==-ETIMEDOUT&&p.smac_failed&&!next&&writes==5&&p.smac[0].refs==2&&other.smac_ref;}
  }
  failures+=!ok;
  printf("{\"scenario\":\"%s\",\"passed\":%s,\"transaction_count\":%d,\"failed_latch\":%s}\n",names[t],ok?"true":"false",writes,p.smac_failed?"true":"false");
 }
 return failures?1:0;
}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('reference', 'cc', 'host-prefix', 'work'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not w.name.startswith('be6l-xwrt-smac-reference-'):
        p.error('Use a fresh /root/be6l-xwrt-smac-reference-* directory')
    receipt = json.loads((a.reference/'result.json').read_text())
    source = a.reference/'after-94104/airoha_ppe.c'
    if (receipt['reference_revision'] != '5ae8e6912e64682fcad54593467e84c80f170656' or
        not receipt['reference_through_94104'] or
        sha(source) != receipt['driver_snapshot_sha256']['after-94104']['airoha_ppe.c']):
        raise ValueError('Missing pinned complete941-04 reference')
    extracted = {name:function(source.read_text(), name) for name in NAMES}
    w.mkdir(mode=0o700)
    fixture = w/'reference-smac-fixture.c'
    fixture.write_text(PRELUDE+'\n'.join(extracted.values())+MAIN)
    env = dict(os.environ, LD_LIBRARY_PATH=str(a.host_prefix/'usr/lib/x86_64-linux-gnu'))
    r = subprocess.run([str(a.cc), '-O0', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-Wno-sign-compare',
                        str(fixture), '-o', str(w/'fixture')], env=env, capture_output=True)
    (w/'compile.log').write_bytes(r.stdout+r.stderr)
    if r.returncode:
        raise RuntimeError('Reference fixture compile failed; inspect retained log')
    r = subprocess.run([str(w/'fixture')], env=env, capture_output=True, timeout=10)
    (w/'observations.jsonl').write_bytes(r.stdout)
    rows = [json.loads(line) for line in r.stdout.decode().splitlines()]
    passed = r.returncode == 0 and len(rows) == 16 and all(row['passed'] for row in rows)
    report = dict(reference_revision=receipt['reference_revision'], reference_source_sha256=sha(source),
        extracted_function_sha256={name:hashlib.sha256(text.encode()).hexdigest() for name,text in extracted.items()},
        actual_reference_function_bodies_used=True, observations=rows, all_reference_cases_passed=passed,
        substituted_operations=['register tokens/reads/writes', 'spinlocks', 'field encodings', 'logger'],
        xwrt_941_04_be6l_port_complete=False, current_be6l_driver_changed=False,
        hardware_drain_qualified=False, target_executed=False)
    (w/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print('REFERENCE_SMAC_CASES_RECORDED', len(rows), passed, flush=True)
    if not passed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
