# SPDX-License-Identifier: MIT
"""Fault controls executing actual newly integrated mt76 source functions.

The actual driver units compile separately. Here only allocation/refcount/RCU,
SKB infrastructure and queue surfaces are substituted. No old standalone lease
model is used, and no concurrency, native reachability or DMA proof is implied.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
from test_xwrt_sram_policy_v1 import function

PRELUDE = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
typedef uint64_t u64;typedef uint16_t u16;typedef uint8_t u8;
typedef struct {unsigned n;} refcount_t;
typedef struct {int n;} atomic_t;
#define U64_MAX UINT64_MAX
#define MT76_N_WCIDS 4
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define GFP_KERNEL 0
#define EXPORT_SYMBOL_GPL(x)
#define lockdep_assert_held(x) do{}while(0)
#define lockdep_is_held(x) 1
#define rcu_access_pointer(x) (x)
#define rcu_dereference(x) (x)
#define rcu_dereference_protected(x,c) (x)
#define rcu_assign_pointer(x,v) do{(x)=(v);}while(0)
#define RCU_INIT_POINTER(x,v) do{(x)=(v);}while(0)
#define rcu_read_lock_held() 1
#define RCU_LOCKDEP_WARN(x,msg) assert(!(x))
static unsigned allocations,frees,warnings,graces;static bool fail_alloc;
#define WARN_ON_ONCE(x) ((x)?(warnings++,true):false)
static void synchronize_rcu(void){graces++;}
static void refcount_set(refcount_t *r,unsigned n){r->n=n;}
static bool refcount_dec_and_test(refcount_t *r){assert(r->n);return !--r->n;}
static bool refcount_inc_not_zero(refcount_t *r){if(!r->n)return false;r->n++;return true;}
static void atomic_set(atomic_t *a,int n){a->n=n;}
static int atomic_read(atomic_t *a){return a->n;}
static void *kzalloc(size_t n,int flags){(void)flags;if(fail_alloc)return NULL;void *p=calloc(1,n);assert(p);allocations++;return p;}
static void kfree(void *p){if(p){frees++;free(p);}}
static void ether_addr_copy(u8 *a,const u8 *b){memcpy(a,b,6);}
/* Exact lease fields are inserted from the private source header below. */
'''

SURFACE = r'''
struct mt76_wcid {struct mt76_rx_lease *rx_lease;u16 idx;bool alive;};
enum mt76_rxq_id {MT_RXQ_MAIN,MT_RXQ_RRO_IND,QUEUES};
enum {MT76_HWRRO_V3=3,RX_FLAG_8023=1,RX_FLAG_DECRYPTED=2,RX_FLAG_IV_STRIPPED=4};
struct mt76_rx_status {struct mt76_wcid *wcid;unsigned flag,seqno;bool amsdu,first_amsdu,last_amsdu;};
struct sk_buff;
struct shared_info {struct sk_buff *frag_list;};
struct sk_buff {unsigned char cb[128] __attribute__((aligned(16)));unsigned char data[64];struct shared_info shared;struct sk_buff *next,*qnext;bool disposed;};
struct sk_buff_head {struct sk_buff *head,**tail;};
struct mt76_queue {bool rro;};
struct mt76_dev;
struct mt76_phy {
 struct mt76_dev *dev;
 struct {struct sk_buff *head,**tail;u16 seqno;struct mt76_rx_lease *lease;} rx_amsdu[QUEUES];
};
struct mt76_dev {
 int mutex;bool rx_lease_enabled;u64 rx_lease_epoch;
 struct mt76_rx_lease *rx_retired[MT76_N_WCIDS];
 struct mt76_wcid *wcid[MT76_N_WCIDS];
 struct mt76_phy phy,*phys[3];struct mt76_queue q_rx[QUEUES];
 struct sk_buff_head rx_skb[QUEUES];int hwrro_mode;
};
static unsigned dropped,delivered,dead_pointer,merged;
static const u8 rfc1042_header[6]={0xaa,0xaa,3,0,0,0};
#define skb_shinfo(s) (&(s)->shared)
static struct mt76_rx_status *status(struct sk_buff *s){return (void*)s->cb;}
static bool ether_addr_equal(const u8 *a,const u8 *b){return !memcmp(a,b,6);}
static int ieee80211_get_hdrlen_from_skb(struct sk_buff *s){(void)s;return 24;}
static bool mt76_queue_is_wed_rro_data(struct mt76_queue *q){return q->rro;}
static void dev_kfree_skb(struct sk_buff *s){
 assert(!s->disposed);s->disposed=true;dropped++;
 for(struct sk_buff *f=s->shared.frag_list;f;){struct sk_buff *n=f->next;dev_kfree_skb(f);f=n;}
}
static void __skb_queue_tail(struct sk_buff_head *q,struct sk_buff *s){s->qnext=NULL;if(!q->head)q->head=s;else *q->tail=s;q->tail=&s->qnext;}
static void sink(struct mt76_dev *d){
 for(unsigned q=0;q<QUEUES;q++){
  struct sk_buff *s=d->rx_skb[q].head;d->rx_skb[q].head=NULL;d->rx_skb[q].tail=NULL;
  while(s){
   struct sk_buff *n=s->qnext;delivered++;if(status(s)->wcid&&!status(s)->wcid->alive)dead_pointer++;
   for(struct sk_buff *f=s->shared.frag_list;f;f=f->next){merged++;delivered++;if(status(f)->wcid&&!status(f)->wcid->alive)dead_pointer++;}
   unsigned before=dropped;dev_kfree_skb(s);dropped=before;s=n;
  }
 }
}
'''

MAIN = r'''
static void prepare(struct mt76_dev *d,struct mt76_wcid *w,u16 idx){
 static const u8 addr[6]={2,1,2,3,4,5};w->idx=idx;w->alive=true;
 assert(!mt76_rx_lease_prepare(d,w,idx,0,addr));d->wcid[idx]=w;
}
static void retire(struct mt76_dev *d,struct mt76_wcid *w){
 mt76_rx_lease_retire(d,w);d->wcid[w->idx]=NULL;w->alive=false;
}
static void finish(struct mt76_dev *d,struct mt76_wcid *a,struct mt76_wcid *b){
 sink(d);if(a->rx_lease)retire(d,a);if(b->rx_lease)retire(d,b);
 mt76_rx_lease_cleanup(d);assert(allocations==frees);
}
int main(void){
 const char *names[]={"baseline-normal-control","negative-baseline-retained-raw-cache-after-sta-retire",
  "draft-cache-is-real-sidecar-and-raw-pointer-erased","draft-retired-cache-dropped-before-new-peer",
  "draft-live-fragment-chain-control","draft-mixed-peer-same-seq-flushed-separately",
  "draft-late-binding-mismatch-dropped","draft-allocation-failure-before-publication",
  "draft-retired-number-reuse-denied-without-all-provider","draft-epoch-overflow-before-publication",
  "draft-header-error-releases-cache-owner-once","draft-rro-cross-poll-queue-rejected",
  "draft-unowned-nonstation-pointer-not-cached","draft-null-station-control",
  "draft-retire-idempotent-before-no-fail-sta-free","draft-cpu-purge-covers-secondary-phy",
  "draft-native-admission-default-remains-closed"};
 unsigned failures=0;
 for(unsigned t=0;t<17;t++){
  struct mt76_dev d={.rx_lease_enabled=true};d.phy.dev=&d;d.phys[0]=&d.phy;
  struct mt76_phy aux={.dev=&d};d.phys[1]=&aux;
  struct mt76_wcid a={0},b={0},fake={.idx=1,.alive=true};
  struct sk_buff first={0},last={0};
  allocations=frees=warnings=graces=dropped=delivered=dead_pointer=merged=0;fail_alloc=false;
  bool ok=false;int error=0;
  if(t==7){fail_alloc=true;error=mt76_rx_lease_prepare(&d,&a,1,0,rfc1042_header);ok=error==-ENOMEM&&!a.rx_lease&&!d.wcid[1]&&!allocations;}
  else if(t==9){d.rx_lease_epoch=U64_MAX;error=mt76_rx_lease_prepare(&d,&a,1,0,rfc1042_header);ok=error==-EOVERFLOW&&!a.rx_lease&&!allocations;}
  else{
   prepare(&d,&a,1);prepare(&d,&b,2);
   *status(&first)=(struct mt76_rx_status){.wcid=&a,.flag=RX_FLAG_8023,.seqno=7,.amsdu=true,.first_amsdu=true};
   *status(&last)=(struct mt76_rx_status){.wcid=&b,.flag=RX_FLAG_8023,.seqno=8};
   if(t==0){status(&first)->amsdu=false;baseline_mt76_rx_release_burst(&d.phy,0,&first);sink(&d);ok=delivered==1&&!dead_pointer;}
   if(t==1){baseline_mt76_rx_release_burst(&d.phy,0,&first);retire(&d,&a);baseline_mt76_rx_release_burst(&d.phy,0,&last);sink(&d);ok=dead_pointer==1&&delivered==2;}
   if(t==2){mt76_rx_release_burst(&d.phy,0,&first);ok=!status(&first)->wcid&&d.phy.rx_amsdu[0].lease==a.rx_lease&&a.rx_lease->refs.n==2;}
   if(t==3){mt76_rx_release_burst(&d.phy,0,&first);retire(&d,&a);mt76_rx_release_burst(&d.phy,0,&last);sink(&d);ok=dropped==1&&delivered==1&&!dead_pointer&&d.rx_retired[1]->refs.n==1;}
   if(t==4||t==5||t==10){
    status(&last)->seqno=7;status(&last)->amsdu=true;status(&last)->last_amsdu=true;
    if(t!=5)status(&last)->wcid=&a;
    if(t==10)memcpy(first.data,rfc1042_header,6);
    mt76_rx_release_burst(&d.phy,0,&first);mt76_rx_release_burst(&d.phy,0,&last);sink(&d);
    ok=t==4?delivered==2&&merged==1&&!dead_pointer:t==5?delivered==2&&!merged&&!dead_pointer:dropped==2&&!delivered&&a.rx_lease->refs.n==1;
   }
   if(t==6){mt76_rx_release_burst(&d.phy,0,&first);d.wcid[1]=&fake;mt76_rx_release_burst(&d.phy,0,&last);sink(&d);ok=dropped==1&&delivered==1&&!dead_pointer;d.wcid[1]=&a;}
   if(t==8){retire(&d,&a);error=mt76_rx_lease_prepare(&d,&fake,1,0,rfc1042_header);ok=error==-EBUSY&&!fake.rx_lease&&d.rx_retired[1]&&!frees;}
   if(t==11){d.q_rx[0].rro=true;d.hwrro_mode=MT76_HWRRO_V3;status(&first)->amsdu=false;mt76_rx_release_burst(&d.phy,0,&first);sink(&d);ok=dropped==1&&!delivered&&a.rx_lease->refs.n==1;}
   if(t==12){status(&first)->wcid=&fake;mt76_rx_release_burst(&d.phy,0,&first);ok=dropped==1&&!d.phy.rx_amsdu[0].head&&!d.phy.rx_amsdu[0].lease;}
   if(t==13){status(&first)->wcid=NULL;status(&first)->amsdu=false;mt76_rx_release_burst(&d.phy,0,&first);sink(&d);ok=delivered==1&&!dead_pointer;}
   if(t==14){retire(&d,&a);struct mt76_rx_lease *held=d.rx_retired[1];mt76_rx_lease_retire(&d,&a);ok=d.rx_retired[1]==held&&held->refs.n==1&&!warnings&&!a.rx_lease;}
   if(t==15){mt76_rx_release_burst(&aux,0,&first);retire(&d,&a);mt76_rx_lease_purge(&d);ok=dropped==1&&!aux.rx_amsdu[0].head&&!aux.rx_amsdu[0].lease&&d.rx_retired[1]->refs.n==1;}
   if(t==16)ok=!mt76_rx_lease_native_ready(&d);
  }
  unsigned before=dropped,observed=dead_pointer,frames=delivered;
  finish(&d,&a,&b);failures+=!ok;
  printf("{\"scenario\":\"%s\",\"expected_observation_passed\":%s,\"errno\":%d,"
    "\"raw_retired_pointer_observed\":%u,\"delivered\":%u,\"dropped\":%u,\"hardware_proved\":false}\n",
    names[t],ok?"true":"false",error,observed,frames,before);
 }
 return failures?1:0;
}
'''


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('draft','cc','host-prefix','work'):
        p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();w=a.work.resolve()
    if w.parent!=a.draft.resolve() or w.exists():p.error('Fresh directory immediately below private draft required')
    prep=json.loads((a.draft/'preparation.json').read_text());src=Path(prep['private_source'])
    text=(src/'mac80211.c').read_text();header=(src/'mt76.h').read_text()
    for n,pin in prep['modified_sha256'].items():
        if hashlib.sha256((src/n).read_bytes()).hexdigest()!=pin:raise ValueError('Draft changed')
    for n,pin in prep['original_sha256'].items():
        if hashlib.sha256((Path(prep['source'])/n).read_bytes()).hexdigest()!=pin:
            raise ValueError('Pinned baseline changed: '+n)
    names=('mt76_rx_lease_native_ready','mt76_rx_lease_put','mt76_rx_lease_prepare',
        'mt76_rx_lease_retire','mt76_rx_lease_capture','mt76_rx_lease_resolve',
        'mt76_rx_lease_purge','mt76_rx_lease_cleanup','mt76_rx_release_amsdu','mt76_rx_release_burst')
    body={n:function(text,n) for n in names}
    lease=header[header.index('struct mt76_rx_lease {'):]
    lease=lease[:lease.index('};')+2].replace('ETH_ALEN','6')
    old=(Path(prep['source'])/'mac80211.c').read_text()
    old_header=(Path(prep['source'])/'mt76.h').read_text()
    baseline='\n'.join(function(old,n) for n in ('mt76_rx_release_amsdu','mt76_rx_release_burst'))
    baseline=baseline.replace('mt76_rx_release_amsdu','baseline_mt76_rx_release_amsdu').replace(
        'mt76_rx_release_burst','baseline_mt76_rx_release_burst')
    w.mkdir(mode=0o700)
    c=w/'actual-draft-cache.c';c.write_text(PRELUDE+lease+'\n'+SURFACE+'\n'+baseline+'\n'+'\n'.join(body.values())+MAIN)
    env=dict(os.environ,LD_LIBRARY_PATH=str(a.host_prefix/'usr/lib/x86_64-linux-gnu'))
    r=subprocess.run([str(a.cc),'-O0','-g','-Wall','-Wextra','-Werror','-Wno-sign-compare','-Wno-unused-parameter',
        str(c),'-o',str(w/'fixture')],env=env,capture_output=True,timeout=30)
    (w/'compile.log').write_bytes(r.stdout+r.stderr)
    if r.returncode:raise RuntimeError('Actual draft function fixture compile failed')
    r=subprocess.run([str(w/'fixture')],env=env,capture_output=True,timeout=10)
    (w/'observations.jsonl').write_bytes(r.stdout);(w/'stderr.log').write_bytes(r.stderr)
    rows=[json.loads(x) for x in r.stdout.decode().splitlines()]
    main=(src/'mt7996/main.c').read_text();npu=(src/'npu.c').read_text();init=(src/'mt7996/init.c').read_text()
    publish=function(main,'mt7996_mac_sta_init_link')
    checks=dict(owner_before_link_publication=publish.index('mt76_rx_lease_prepare')<publish.index('rcu_assign_pointer(msta->link'),
        owner_before_wcid_publication=publish.index('mt76_rx_lease_prepare')<publish.index('rcu_assign_pointer(dev->mt76.wcid'),
        retired_existing_link_cannot_reactivate='dev->mt76.rx_retired[msta_link->wcid.idx]' in function(main,'mt7996_mac_sta_add_links'),
        generic_reset_transfers_owner='mt76_rx_lease_retire(dev, wcid)' in function(text,'mt76_reset_device'),
        native_gate_before_get=function(npu,'mt76_npu_init').index('!mt76_rx_lease_native_ready')<function(npu,'mt76_npu_init').index('an7552_npu_get'),
        purge_after_irq_napi_cpu_sync=function(init,'mt7996_cleanup_device').index('mt76_rx_lease_purge')>function(init,'mt7996_cleanup_device').index('synchronize_net();'),
        target_only='rx_lease_enabled = is_mt7992(mdev)' in init,
        status_layout_unchanged=header[header.index('struct mt76_rx_status {'):header.index('struct mt76_freq_range_power {')]==
            old_header[old_header.index('struct mt76_rx_status {'):old_header.index('struct mt76_freq_range_power {')])
    passed=r.returncode==0 and len(rows)==17 and all(x['expected_observation_passed'] for x in rows) and all(checks.values())
    report=dict(actual_integrated_source_function_sha256={n:hashlib.sha256(t.encode()).hexdigest() for n,t in body.items()},
        observations=rows,source_order_checks=checks,all_expected_observations_passed=passed,
        baseline_negative_control_is_not_a_safety_pass=True,
        actual_queue_sidecar=True,old_standalone_model_used=False,
        substituted_operations=['SKB infrastructure','allocator','reference counter primitives','RCU/locks','queue bookkeeping'],
        excluded=['real IRQ/RCU/RTNL concurrency','native packet reachability','physical DMA/output withdrawal',
            'full module ABI/link','safe full remove/reprobe and cross-device epoch'],
        native_admission_closed=True,hardware_all_provider=False,target_executed=False)
    (w/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print('ACTUAL_MT76_RX_LEASE_SOURCE_CONTROLS',len(rows),passed,flush=True)
    if not passed:raise SystemExit(1)


if __name__=='__main__':main()
