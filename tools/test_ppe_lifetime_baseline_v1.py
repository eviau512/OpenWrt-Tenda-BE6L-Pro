# SPDX-License-Identifier: MIT
"""Expose current PPE lifetime failures using the real pinned C call chain.

Only register/list/allocator/netdev operations are substituted. This reproduces
source ownership decisions, not DMA drainage or hardware behavior. The known
baseline is expected to fail safety invariants; no port/image/DUT mutation occurs.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
from test_xwrt_sram_policy_v1 import function

PIN = 'de1f3299891eef4d987a4e9222eedc535ead18bf0d100c996eea2c0f8d5bb2f1'
NAMES = ('airoha_ppe_foe_write_failed', 'airoha_ppe_foe_unbind_flow',
         'airoha_ppe_foe_remove_flow', 'airoha_ppe_foe_release_slot',
         'airoha_ppe_foe_flow_remove_entry', 'airoha_ppe_flow_offload_destroy',
         'airoha_ppe_free_flow')

PRELUDE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;
#define GENMASK(h,l) ((~0U << (l)) & (~0U >> (31-(h))))
#define FIELD_GET(m,v) (((v) & (m)) >> __builtin_ctz(m))
#define AIROHA_FOE_IB1_BIND_STATE GENMASK(29,28)
enum {AIROHA_FOE_STATE_INVALID, AIROHA_FOE_STATE_UNBIND, AIROHA_FOE_STATE_BIND, AIROHA_FOE_STATE_FIN};
enum {FLOW_TYPE_L4, FLOW_TYPE_L2, FLOW_TYPE_L2_SUBFLOW};
#define PPE_GLO_CFG_EN_MASK 1
#define REG_PPE_GLO_CFG(i) (i)
#define lockdep_assert_held(x) do {} while(0)
#define spin_lock_bh(x) do {} while(0)
#define spin_unlock_bh(x) do {} while(0)
#define dev_err(...) do {} while(0)
struct airoha_foe_entry {u32 ib1;};
struct airoha_flow_table_entry {
    u32 hash; int type, list, l2_subflow_node, ingress_node, wlan_node, node;
    int dev_refs;
};
struct airoha_eth_soc_data {int num_ppe;};
struct airoha_eth;
struct airoha_ppe {struct airoha_eth *eth; struct airoha_flow_table_entry **foe_owner;};
struct airoha_eth {struct airoha_ppe *ppe; struct airoha_eth_soc_data *soc; void *dev; int flow_table;};
struct flow_cls_offload {unsigned long cookie;};
static int airoha_flow_table_params;
static struct airoha_flow_table_entry *looked_up;
static struct airoha_foe_entry hardware;
static bool read_failed;
static int commit_error, disabled_banks, freed, dev_puts, cookie_removed;
static void hlist_del_init(int *node) {*node=0;}
static void airoha_fe_clear(struct airoha_eth *eth, int bank, int mask) {disabled_banks++;}
static struct airoha_foe_entry *airoha_ppe_foe_get_entry_locked(struct airoha_ppe *ppe, u32 hash) {
    return read_failed ? NULL : &hardware;
}
static int airoha_ppe_foe_commit_entry(struct airoha_ppe *ppe, struct airoha_foe_entry *entry, u32 hash, bool wlan) {
    return commit_error;
}
static void kfree(void *value) {freed++;}
static void airoha_ppe_foe_remove_l2_flow(struct airoha_ppe *ppe, struct airoha_flow_table_entry *entry) {
    /* Parent-L2 removal is deliberately outside this fixture's admitted paths. */
    __builtin_trap();
}
static void *rhashtable_lookup(int *table, unsigned long *cookie, int params) {return looked_up;}
static int rhashtable_remove_fast(int *table, int *node, int params) {cookie_removed++; return 0;}
static void airoha_ppe_flow_entry_put_devs(struct airoha_flow_table_entry *entry) {
    dev_puts += entry->dev_refs; entry->dev_refs=0;
}
'''

MAIN = r'''
int main(void) {
    const char *names[] = {"normal-unbind-control", "normal-destroy-control",
        "read-failure-unbind", "timeout-unbind", "timeout-remove-l2-child",
        "timeout-slot-replacement", "timeout-tc-destroy", "timeout-table-free-callback"};
    for (int test=0; test<8; test++) {
        struct airoha_eth_soc_data soc={.num_ppe=2};
        struct airoha_eth eth={.soc=&soc};
        struct airoha_flow_table_entry entry={.hash=1,.type=FLOW_TYPE_L4,.dev_refs=2};
        struct airoha_flow_table_entry *owners[4]={NULL,&entry,NULL,NULL};
        struct airoha_ppe ppe={.eth=&eth,.foe_owner=owners};
        struct flow_cls_offload cls={.cookie=1};
        eth.ppe=&ppe; looked_up=&entry;
        hardware.ib1=AIROHA_FOE_STATE_BIND << 28;
        read_failed=test==2; commit_error=test>=3 ? -ETIMEDOUT : 0;
        disabled_banks=freed=dev_puts=cookie_removed=0;
        int error=0;
        if (test==0 || test==2 || test==3) airoha_ppe_foe_unbind_flow(&ppe,&entry);
        else if (test==1 || test==6) error=airoha_ppe_flow_offload_destroy(&eth,&cls);
        else if (test==4) {entry.type=FLOW_TYPE_L2_SUBFLOW; airoha_ppe_foe_remove_flow(&ppe,&entry);}
        else if (test==5) {entry.type=FLOW_TYPE_L2_SUBFLOW; airoha_ppe_foe_release_slot(&ppe,1);}
        else if (test==7) airoha_ppe_free_flow(&entry,&ppe);
        bool passed;
        if (test<2) passed=owners[1]==NULL && entry.hash==0xffff &&
            (test==0 ? freed==0 && dev_puts==0 : freed==1 && dev_puts==2 && cookie_removed==1 && error==0);
        else passed=owners[1]==&entry && entry.hash==1 && !freed && !dev_puts && !cookie_removed;
        printf("{\"scenario\":\"%s\",\"safety_invariant_passed\":%s,\"owner_retained\":%s,"
               "\"hash\":%u,\"free_calls\":%d,\"netdev_refs_put\":%d,\"cookie_removals\":%d,"
               "\"enable_clear_writes\":%d,\"returned_error\":%d}\n",
               names[test],passed?"true":"false",owners[1]==&entry?"true":"false",entry.hash,
               freed,dev_puts,cookie_removed,disabled_banks,error);
    }
    return 0;
}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'cc', 'host-prefix', 'work'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not w.name.startswith('be6l-ppe-lifetime-baseline-') or w.exists():
        p.error('Use a fresh /root/be6l-ppe-lifetime-baseline-* directory')
    raw = a.source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PIN:
        raise ValueError('Only the exact current ARM64 SRAM-policy source is admitted')
    text = raw.decode()
    extracted = {name:function(text,name) for name in NAMES}
    w.mkdir(mode=0o700)
    source = w/'actual-lifetime-fixture.c'
    source.write_text(PRELUDE+'\n'.join(extracted.values())+MAIN)
    env=dict(os.environ, LD_LIBRARY_PATH=str(a.host_prefix/'usr/lib/x86_64-linux-gnu'))
    command=[str(a.cc),'-O0','-g','-Wall','-Wextra','-Wno-unused-parameter','-Werror',str(source),'-o',str(w/'fixture')]
    build=subprocess.run(command,env=env,capture_output=True)
    (w/'build.log').write_bytes(build.stdout+build.stderr)
    if build.returncode:
        raise RuntimeError('Host fixture compile failed; inspect retained log')
    result=subprocess.run([str(w/'fixture')],env=env,capture_output=True,timeout=10,check=True)
    (w/'observations.jsonl').write_bytes(result.stdout)
    observations=[json.loads(line) for line in result.stdout.decode().splitlines()]
    controls=observations[:2]
    failures=observations[2:]
    reproduced=(len(observations)==8 and all(x['safety_invariant_passed'] for x in controls) and
        all(not x['safety_invariant_passed'] for x in failures))
    report=dict(source_sha256=PIN, extracted_function_sha256={name:hashlib.sha256(value.encode()).hexdigest()
        for name,value in extracted.items()}, actual_function_bodies_used=True,
        substituted_operations=['register access','list bookkeeping','allocator','netdev references','hardware transaction','cookie table'],
        excluded_paths=['L2 parent removal','netdevice notifier','full driver deinit','real IRQ/locking','ASIC/DMA drainage'],
        observations=observations, known_unsafe_baseline_reproduced=reproduced,
        xwrt_941_04_port_implemented=False, safety_invariants_passed=False,
        hardware_qualified=False,target_executed=False)
    (w/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PPE_LIFETIME_BASELINE_RECORDED', json.dumps(dict(reproduced=reproduced,controls=len(controls),unsafe_cases=len(failures))),flush=True)
    # Recording the known bad baseline is successful research, not a passing driver test.
    if not reproduced: raise SystemExit(1)


if __name__=='__main__':main()
