# SPDX-License-Identifier: MIT
"""Execute actual isolated draft C functions with faulted software operations.

The model deliberately has no DMA or device. Passing ownership bookkeeping is
not permission to enable native offload. A negative control proves a void hash
free callback cannot restore its removed cookie; preflight must precede it.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
from test_xwrt_sram_policy_v1 import function
import test_xwrt_smac_reference_v1 as smac

NAMES = ('airoha_ppe_foe_write_failed','airoha_ppe_foe_withdraw_complete',
    'airoha_ppe_foe_slot_busy','airoha_ppe_foe_reserve_slot',
    'airoha_ppe_foe_unbind_flow','airoha_ppe_foe_remove_flow',
    'airoha_ppe_foe_release_slot','airoha_ppe_foe_remove_l2_flow',
    'airoha_ppe_foe_flow_remove_entry','airoha_ppe_foe_flow_commit_entry',
    'airoha_ppe_flush_wdma_entry','airoha_ppe_wired_l4_event',
    'airoha_ppe_netdevice_event','airoha_ppe_flow_offload_destroy',
    'airoha_ppe_free_flow','airoha_ppe_lifetime_preflight')

PRELUDE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32; typedef uint16_t u16; typedef uint8_t u8;
#define GENMASK(h,l) ((~0U << (l)) & (~0U >> (31-(h))))
#define FIELD_GET(m,v) (((v)&(m)) >> __builtin_ctz(m))
#define AIROHA_FOE_IB1_BIND_STATE GENMASK(29,28)
#define AIROHA_FOE_IB1_BIND_PACKET_TYPE 15U
#define PPE_GLO_CFG_EN_MASK 1
#define REG_PPE_GLO_CFG(i) (i)
#define READ_ONCE(x) (x)
#define lockdep_assert_held(x) do{}while(0)
#define spin_lock_bh(x) do{}while(0)
#define spin_unlock_bh(x) do{}while(0)
#define dev_err(...) do{}while(0)
#define container_of(p,t,m) ((t*)((char*)(p)-offsetof(t,m)))
#define IS_ERR(p) ((uintptr_t)(p) > (uintptr_t)-4096)
#define PTR_ERR(p) ((int)(intptr_t)(p))
enum {AIROHA_FOE_STATE_INVALID,AIROHA_FOE_STATE_UNBIND,AIROHA_FOE_STATE_BIND};
enum {FLOW_TYPE_L4,FLOW_TYPE_L2,FLOW_TYPE_L2_SUBFLOW};
enum {NETREG_REGISTERED,PPE_PKT_TYPE_BRIDGE=1};
enum {NETDEV_UNREGISTER=1,NETDEV_GOING_DOWN,NETDEV_PRECHANGEUPPER,
      NETDEV_CHANGEUPPER,NETDEV_CHANGEADDR,NETDEV_CHANGEMTU,NETDEV_CHANGE};
#define NOTIFY_DONE 0
struct hlist_node {struct hlist_node *next, **pprev;};
struct hlist_head {struct hlist_node *first;};
static void hlist_add_head(struct hlist_node *n,struct hlist_head *h) {
 n->next=h->first; if(n->next)n->next->pprev=&n->next; h->first=n; n->pprev=&h->first;
}
static void hlist_del_init(struct hlist_node *n) {
 if(!n->pprev)return;
 *n->pprev=n->next;
 if(n->next)n->next->pprev=n->pprev;
 n->pprev=NULL;n->next=NULL;
}
#define hlist_for_each_entry(e,h,m) \
 for(struct hlist_node *_node=(h)->first; \
     _node && ((e)=container_of(_node,__typeof__(*(e)),m),1); _node=_node->next)
#define hlist_for_each_entry_safe(e,n,h,m) \
 for(struct hlist_node *_node=(h)->first; \
     _node && ((n)=_node->next,(e)=container_of(_node,__typeof__(*(e)),m),1); _node=(n))
struct net_device {int reg_state,refs;};
struct notifier_block {int placeholder;};
struct airoha_foe_entry {u32 ib1;};
struct airoha_flow_table_entry {
 u32 hash; int type,dev_refs,node,l2_node; unsigned long cookie;
 struct hlist_node list,l2_subflow_node,ingress_node,wlan_node;
 struct hlist_head l2_flows; struct airoha_foe_entry data;
 struct net_device *ingress_dev,*wired_egress_dev,*wdma_dev;
 bool wired_l4,wired_dead,wdma_dead,lifetime_retired;
 u16 wdma_wcid; u8 wdma_idx;
};
struct airoha_eth_soc_data {int num_ppe;};
struct airoha_eth;
struct airoha_ppe {
 struct airoha_eth *eth; struct airoha_flow_table_entry **foe_owner;
 bool foe_failed,stopping,lifetime_ready;
 struct hlist_head ingress_flows,wlan_flows,*foe_flow;
 int l2_flows; struct notifier_block netdevice_nb;
};
struct airoha_eth {struct airoha_ppe *ppe; struct airoha_eth_soc_data *soc;
 void *dev;int flow_table;bool native;};
struct flow_cls_offload {unsigned long cookie;};
struct rhashtable_iter {int index;};
static const int airoha_flow_table_params=1,airoha_l2_flow_table_params=2;
static struct airoha_flow_table_entry *looked_up,*walk_entries[4];
static struct airoha_foe_entry hardware;
static bool read_failed;
static int commit_error,fail_hash=-1,invalid_error,disabled_banks,freed,dev_puts;
static int cookie_removed,parent_removed,warnings,commits,pending_publications;
#define WARN_ON_ONCE(x) ((x)?(warnings++,true):false)
static bool airoha_is_7563(struct airoha_eth *eth) {return eth->native;}
static u32 airoha_ppe_get_total_num_entries(struct airoha_ppe *p) {return 4;}
static void airoha_fe_clear(struct airoha_eth *e,int bank,int mask){disabled_banks++;}
static struct airoha_foe_entry *airoha_ppe_foe_get_entry_locked(struct airoha_ppe *p,u32 h) {
 return read_failed && (fail_hash<0 || h==(u32)fail_hash)?NULL:&hardware;
}
static int airoha_ppe_foe_commit_entry(struct airoha_ppe *p,struct airoha_foe_entry *e,u32 h,bool w) {
 commits++; return fail_hash<0 || h==(u32)fail_hash?commit_error:0;
}
static void kfree(void *p) {freed++;}
static void *rhashtable_lookup(int *table,unsigned long *cookie,int params){return looked_up;}
static int rhashtable_remove_fast(int *table,int *node,int params) {
 if(params==1)cookie_removed++; else parent_removed++; return 0;
}
static void dev_put(struct net_device *dev){dev->refs--;dev_puts++;}
static void airoha_ppe_flow_entry_put_devs(struct airoha_flow_table_entry *e){dev_puts+=e->dev_refs;e->dev_refs=0;}
static void airoha_ppe_smac_put(struct airoha_ppe *p,struct airoha_flow_table_entry *e){}
static u32 airoha_ppe_foe_get_entry_hash(struct airoha_ppe *p,struct airoha_foe_entry *e){return 0;}
static int airoha_ppe_foe_l2_flow_commit_entry(struct airoha_ppe *p,struct airoha_flow_table_entry *e) {
 pending_publications++;return 0;
}
static int airoha_ppe_foe_invalidate_wdma(struct airoha_ppe *p,u32 hash,u16 w,u8 b){return invalid_error;}
static bool airoha_ppe_wired_depends_on(struct net_device *dev,struct net_device *event){return dev==event;}
static struct net_device *netdev_notifier_info_to_dev(void *p){return p;}
static void airoha_ppe_flush_wdma_failed(struct airoha_ppe *p,int err){p->foe_failed=true;}
static void rhashtable_walk_enter(int *table,struct rhashtable_iter *it){it->index=0;}
static void rhashtable_walk_start(struct rhashtable_iter *it){}
static void *rhashtable_walk_next(struct rhashtable_iter *it){return walk_entries[it->index++];}
static void rhashtable_walk_stop(struct rhashtable_iter *it){}
static void rhashtable_walk_exit(struct rhashtable_iter *it){}
'''

MAIN = r'''
int main(void) {
 const char *names[]={"normal-unbind-control","normal-destroy-control",
  "read-error-retains-owner","write-timeout-retains-owner","child-timeout-retains-parent-link",
  "slot-release-timeout-retains-owner","tc-destroy-timeout-retains-cookie",
  "preflight-timeout-keeps-destructive-teardown-unreached","native-ack-is-not-drain",
  "native-nonbind-is-not-drain","identity-mismatch-retains-hash","slot-collision-does-not-steal",
  "owner-reserved-before-transaction","parent-child-timeout-retains-parent-table",
  "parent-normal-removal-idempotent","wdma-timeout-retains-child",
  "wired-event-timeout-retains-device","ingress-unregister-timeout-retains-device",
  "wdma-unregister-timeout-retains-device","native-cold-gate-rejects-publication",
  "poison-gate-rejects-publication","stopping-gate-rejects-publication",
  "preflight-staged-progress-retains-failed-cookie",
  "negative-control-void-callback-cannot-restore-cookie",
  "child-rejected-by-parent-cleanup-without-use-after-free"};
 int failures=0;
 for(int t=0;t<25;t++) {
  struct airoha_eth_soc_data soc={2};struct airoha_eth eth={.soc=&soc};
  struct net_device dev={.refs=2};
  struct airoha_flow_table_entry e={.hash=1,.type=FLOW_TYPE_L4,.dev_refs=2};
  struct airoha_flow_table_entry parent={.hash=0xffff,.type=FLOW_TYPE_L2};
  struct airoha_flow_table_entry other={.hash=2,.type=FLOW_TYPE_L4};
  struct airoha_flow_table_entry *owners[4]={NULL,&e,NULL,NULL};
  struct hlist_head tuples[4]={0};
  struct airoha_ppe p={.eth=&eth,.foe_owner=owners,.foe_flow=tuples};
  struct flow_cls_offload cls={1};eth.ppe=&p;looked_up=&e;
  memset(walk_entries,0,sizeof(walk_entries));walk_entries[0]=&e;
  hardware.ib1=AIROHA_FOE_STATE_BIND<<28;
  read_failed=false;commit_error=invalid_error=0;fail_hash=-1;
  disabled_banks=freed=dev_puts=cookie_removed=parent_removed=warnings=commits=pending_publications=0;
  hlist_add_head(&e.list,&tuples[0]);
  int error=0;bool ok=false;
  if(t==2)read_failed=true;
  if(t>=3&&t<=7)commit_error=-ETIMEDOUT;
  if(t==0||t==2||t==3||t==8||t==9||t==10) {
   if(t==8||t==9)eth.native=true;
   if(t==9)hardware.ib1=AIROHA_FOE_STATE_UNBIND<<28;
   if(t==10)owners[1]=&other;
   error=airoha_ppe_foe_unbind_flow(&p,&e);
  }
  else if(t==1||t==6)error=airoha_ppe_flow_offload_destroy(&eth,&cls);
  else if(t==4||t==5) {
   e.type=FLOW_TYPE_L2_SUBFLOW;hlist_add_head(&e.l2_subflow_node,&parent.l2_flows);
   error=t==4?airoha_ppe_foe_remove_flow(&p,&e):airoha_ppe_foe_release_slot(&p,1);
  }
  else if(t==7)error=airoha_ppe_lifetime_preflight(&eth);
  else if(t==11)ok=airoha_ppe_foe_slot_busy(&p,&other,1)&&owners[1]==&e&&e.hash==1&&!commits;
  else if(t==12){owners[1]=NULL;e.hash=0xffff;airoha_ppe_foe_reserve_slot(&p,&e,1);ok=owners[1]==&e&&e.hash==1&&!commits;}
  else if(t==13||t==14||t==15) {
   e.type=FLOW_TYPE_L2_SUBFLOW;hlist_add_head(&e.l2_subflow_node,&parent.l2_flows);
   if(t!=14)commit_error=-ETIMEDOUT;
   error=t==15?airoha_ppe_flush_wdma_entry(&p,&parent):airoha_ppe_foe_flow_remove_entry(&p,&parent);
   if(t==14){int again=airoha_ppe_foe_flow_remove_entry(&p,&parent);ok=!error&&!again&&!owners[1]&&!parent.l2_flows.first&&parent_removed==1&&freed==1;}
   else ok=error==-ETIMEDOUT&&owners[1]==&e&&parent.l2_flows.first==&e.l2_subflow_node&&!parent_removed&&!freed;
  }
  else if(t==16) {
   e.wired_l4=true;e.ingress_dev=&dev;e.wired_egress_dev=&dev;commit_error=-ETIMEDOUT;
   error=airoha_ppe_wired_l4_event(&p,&e,&dev,true);
   ok=error==-ETIMEDOUT&&e.ingress_dev==&dev&&e.wired_egress_dev==&dev&&dev.refs==2&&!dev_puts&&e.wired_dead;
  }
  else if(t==17||t==18) {
   commit_error=-ETIMEDOUT;
   if(t==17){parent.ingress_dev=&dev;e.type=FLOW_TYPE_L2_SUBFLOW;
    hlist_add_head(&e.l2_subflow_node,&parent.l2_flows);hlist_add_head(&parent.ingress_node,&p.ingress_flows);}
   else {e.wdma_dev=&dev;hlist_add_head(&e.wlan_node,&p.wlan_flows);}
   error=airoha_ppe_netdevice_event(&p.netdevice_nb,NETDEV_UNREGISTER,&dev);
   ok=owners[1]==&e&&dev.refs==2&&!dev_puts&&!freed&&
      (t==17?parent.ingress_dev==&dev:e.wdma_dev==&dev);
  }
  else if(t>=19&&t<=21) {
   e.hash=0xffff;owners[1]=NULL;hlist_del_init(&e.list);
   if(t==19)eth.native=true;
   if(t==20)p.foe_failed=true;
   if(t==21)p.stopping=true;
   error=airoha_ppe_foe_flow_commit_entry(&p,&e);
   ok=error==-EOPNOTSUPP&&!e.list.pprev&&!pending_publications;
  }
  else if(t==22) {
   owners[2]=&other;walk_entries[1]=&other;commit_error=-ETIMEDOUT;fail_hash=2;
   error=airoha_ppe_lifetime_preflight(&eth);
   ok=error==-ETIMEDOUT&&!owners[1]&&e.lifetime_retired&&owners[2]==&other&&
      other.hash==2&&!freed&&!dev_puts&&!cookie_removed;
  }
  else if(t==23) {
   /* Models the actual rhashtable_free_and_destroy sequencing. The callback
    * cannot undo this unlink. This observation is a known UNSAFE boundary. */
   commit_error=-ETIMEDOUT;cookie_removed=1;airoha_ppe_free_flow(&e,&p);
   ok=owners[1]==&e&&!freed&&!dev_puts&&cookie_removed==1&&warnings==1;
  }
  else if(t==24) {
   e.type=FLOW_TYPE_L2_SUBFLOW;
   error=airoha_ppe_foe_flow_remove_entry(&p,&e);
   ok=error==-EINVAL&&owners[1]==&e&&!freed&&!dev_puts&&warnings==1;
  }
  if(t==0)ok=!error&&!owners[1]&&e.hash==0xffff&&!freed;
  if(t==1)ok=!error&&!owners[1]&&e.hash==0xffff&&freed==1&&dev_puts==2&&cookie_removed==1;
  if(t>=2&&t<=7)ok=error<0&&owners[1]==&e&&e.hash==1&&!freed&&!dev_puts&&!cookie_removed&&e.list.pprev;
  if(t==4||t==5)ok=ok&&parent.l2_flows.first==&e.l2_subflow_node;
  if(t==8||t==9)ok=error==-EOPNOTSUPP&&owners[1]==&e&&e.hash==1&&!freed&&!dev_puts;
  if(t==10)ok=error==-ESTALE&&owners[1]==&other&&e.hash==1&&!commits;
  failures+=!ok;
  printf("{\"scenario\":\"%s\",\"expected_observation_passed\":%s,\"returned_error\":%d,"
   "\"physical_owner_retained\":%s,\"free_calls\":%d,\"netdev_puts\":%d,\"cookie_removals\":%d,"
   "\"hardware_withdrawal_proved\":false}\n",names[t],ok?"true":"false",error,owners[1]==&e?"true":"false",freed,dev_puts,cookie_removed);
 }
 return failures?1:0;
}
'''


def compile_run(a, work, tag, source):
    cfile = work/(tag+'.c')
    cfile.write_text(source)
    env = dict(os.environ,LD_LIBRARY_PATH=str(a.host_prefix/'usr/lib/x86_64-linux-gnu'))
    cmd = [str(a.cc),'-O0','-g','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
           '-Wno-sign-compare',str(cfile),'-o',str(work/tag)]
    r = subprocess.run(cmd,env=env,capture_output=True,timeout=30)
    (work/(tag+'-compile.log')).write_bytes(r.stdout+r.stderr)
    if r.returncode:
        raise RuntimeError('Actual C fixture compile failed: '+tag)
    r = subprocess.run([str(work/tag)],env=env,capture_output=True,timeout=10)
    (work/(tag+'-observations.jsonl')).write_bytes(r.stdout)
    rows = [json.loads(x) for x in r.stdout.decode().splitlines()]
    return r.returncode,rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('draft','cc','host-prefix','work'):
        p.add_argument('--'+name,type=Path,required=True)
    a = p.parse_args()
    work = a.work.resolve()
    if work.parent != a.draft.resolve() or work.exists():
        p.error('Use a fresh test directory immediately below the private draft')
    prep = json.loads((a.draft/'preparation.json').read_text())
    source = Path(prep['source'])/'airoha_ppe.c'
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=prep['modified_sha256']['airoha_ppe.c'] or prep['native_binding_admitted']:
        raise ValueError('Draft mismatch or unexpectedly admitted draft')
    text = raw.decode()
    extracted = {n:function(text,n) for n in NAMES}
    work.mkdir(mode=0o700)
    status,rows = compile_run(a,work,'ownership-fixture',PRELUDE+'\n'.join(extracted.values())+MAIN)
    smac_extracted = {n:function(text,n) for n in smac.NAMES}
    # Only the containing structure changed in this local port. Execute the
    # original reference's same 16 transactions against the local C functions.
    prelude = smac.PRELUDE.replace('struct {struct airoha_eth *eth;} common;', 'struct airoha_eth *eth;')
    smain = smac.MAIN.replace('.common={.eth=&eth}', '.eth=&eth')
    sstatus,srows = compile_run(a,work,'ported-smac-fixture',prelude+'\n'.join(smac_extracted.values())+smain)
    order = dict(
        tc_cookie_before_rx_pending=function(text,'airoha_ppe_flow_offload_replace').index('err = rhashtable_insert_fast') <
            function(text,'airoha_ppe_flow_offload_replace').index('err = airoha_ppe_foe_flow_commit_entry'),
        child_owner_before_hardware_write=function(text,'airoha_ppe_foe_commit_subflow_entry').index('airoha_ppe_foe_reserve_slot') <
            function(text,'airoha_ppe_foe_commit_subflow_entry').index('err = airoha_ppe_foe_commit_entry'),
        child_link_before_hardware_write=function(text,'airoha_ppe_foe_commit_subflow_entry').index('hlist_add_head(&f->l2_subflow_node') <
            function(text,'airoha_ppe_foe_commit_subflow_entry').index('err = airoha_ppe_foe_commit_entry'),
        deinit_preflight_before_destructive_table_free=function(text,'airoha_ppe_deinit').index('airoha_ppe_lifetime_preflight') <
            function(text,'airoha_ppe_deinit').index('rhashtable_free_and_destroy'),
        native_cold_gate_no_enabling_setter='ppe->lifetime_ready = false;' in text and
            'lifetime_ready = true' not in text)
    passed = (not status and not sstatus and len(rows)==25 and len(srows)==16 and
        all(x['expected_observation_passed'] for x in rows) and all(x['passed'] for x in srows) and all(order.values()))
    report = dict(draft_source_sha256=hashlib.sha256(raw).hexdigest(),
        actual_function_sha256={n:hashlib.sha256(t.encode()).hexdigest() for n,t in {**extracted,**smac_extracted}.items()},
        ownership_observations=rows,ported_smac_observations=srows,source_order_checks=order,
        expected_source_observations_passed=passed,
        negative_control_callback_still_cannot_restore_cookie=True,
        substituted_operations=['register reads/writes','transaction success/failure','spinlocks',
            'hash table/list infrastructure','allocator','netdev references','walk synchronization'],
        excluded=['actual DMA/output drain','IRQ/RCU/RTNL concurrency','bounded NETDEV_UNREGISTER',
            'platform devres release','full driver teardown','runtime TC replacement construction'],
        xwrt_94104_complete_port=False,native_binding_admitted=False,
        hardware_withdrawal_qualified=False,target_executed=False)
    (work/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PPE_DRAFT_SOURCE_FAULT_OBSERVATIONS',len(rows),len(srows),passed,flush=True)
    if not passed:
        raise SystemExit(1)


if __name__=='__main__':
    main()
