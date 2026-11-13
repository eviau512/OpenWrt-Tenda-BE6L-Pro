# SPDX-License-Identifier: MIT
"""Build an isolated retired-owner prototype and source-bound RX fault fixture.

No driver source, kernel, root, candidate or device is changed. The two actual
mt76 cache functions run with substituted SKB/queue/RCU surfaces. A generated
adapter adds independent lease tags; its storage is modeled, not kernel ABI.
Synthetic provider evidence cannot qualify physical withdrawal or admission.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
from test_xwrt_sram_policy_v1 import function

PIN = '0646b55c7d330b793e216878ef1efe733ecc840f912e6a39b16d6fc0ec5cce61'
NATIVE_PIN = 'c6428b8042fa74316c3a4adddcce9cc836b05cbccef9bafe8b34304577c6af57'
BASE = Path(__file__).resolve().parents[1]

PRELUDE = r'''
#include "retired_lease.h"
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
enum mt76_rxq_id { MT_RXQ_MAIN, MT_RXQ_RRO_IND, QUEUES };
enum { MT76_HWRRO_V3=3, RX_FLAG_8023=1, RX_FLAG_DECRYPTED=2, RX_FLAG_IV_STRIPPED=4 };
struct mt76_wcid { unsigned idx; bool alive; };
struct mt76_rx_status { struct mt76_wcid *wcid; unsigned flag,seqno; bool amsdu,first_amsdu,last_amsdu; };
struct sk_buff;
struct shared_info { struct sk_buff *frag_list; };
struct sk_buff {
 unsigned char cb[128] __attribute__((aligned(16)));
 unsigned char data[64];
 struct shared_info shared;
 struct sk_buff *next,*qnext;
 /* Modeled metadata storage. Real skb extension/per-queue layout is NOT
  * implemented and must not be mistaken for room in current skb->cb. */
 struct be6l_lease *cache_lease;
 bool cache_tagged,disposed;
};
struct sk_buff_head { struct sk_buff *head,**tail; };
struct mt76_queue { bool rro; };
struct mt76_dev {
 struct be6l_manager leases;
 struct mt76_wcid *live[BE6L_LEASE_SLOTS];
 struct be6l_lease *binding[BE6L_LEASE_SLOTS];
 struct mt76_queue q_rx[QUEUES];
 struct sk_buff_head rx_skb[QUEUES];
 int hwrro_mode;
};
struct mt76_phy {
 struct mt76_dev *dev;
 struct { struct sk_buff *head,**tail; unsigned seqno; } rx_amsdu[QUEUES];
};
static unsigned dropped,delivered,dead_pointer_observed,unknown_delivered;
static const unsigned char rfc1042_header[6]={0xaa,0xaa,3,0,0,0};
#define skb_shinfo(s) (&(s)->shared)
static bool ether_addr_equal(const unsigned char *a,const unsigned char *b){return !memcmp(a,b,6);}
static int ieee80211_get_hdrlen_from_skb(struct sk_buff *s){(void)s;return 24;}
static bool mt76_queue_is_wed_rro_data(struct mt76_queue *q){return q->rro;}
static void dev_kfree_skb(struct sk_buff *s) {
 if(!s)return;
 assert(!s->disposed);s->disposed=true;dropped++;
 if(s->cache_lease){be6l_lease_put(s->cache_lease);s->cache_lease=NULL;}
 struct sk_buff *child=s->shared.frag_list;
 while(child){struct sk_buff *next=child->next;dev_kfree_skb(child);child=next;}
}
static void __skb_queue_tail(struct sk_buff_head *q,struct sk_buff *s) {
 s->qnext=NULL;
 if(!q->head)q->head=s;else *q->tail=s;
 q->tail=&s->qnext;
}
static struct mt76_rx_status *status(struct sk_buff *s){return (void*)s->cb;}
static void observe_and_consume(struct sk_buff *s) {
 delivered++;
 /* The retired stack fixture remains allocated. This detects retained raw
  * pointers without dereferencing genuinely freed memory or alleging DUT UAF. */
 if(status(s)->wcid && !status(s)->wcid->alive)dead_pointer_observed++;
 if(!status(s)->wcid)unknown_delivered++;
 for(struct sk_buff *f=s->shared.frag_list;f;f=f->next){
  delivered++;
  if(status(f)->wcid && !status(f)->wcid->alive)dead_pointer_observed++;
 }
 unsigned before=dropped;dev_kfree_skb(s);dropped=before;
}
static void sink(struct mt76_dev *d) {
 for(unsigned q=0;q<QUEUES;q++){
  struct sk_buff *s=d->rx_skb[q].head;
  d->rx_skb[q].head=NULL;d->rx_skb[q].tail=NULL;
  while(s){struct sk_buff *n=s->qnext;observe_and_consume(s);s=n;}
 }
}
'''

ADAPTER = r'''
/* Receive capture runs under the existing RX/RCU protection while the real
 * pointer is valid. It retains a separately owned lease and clears raw WCID
 * before that packet may survive a poll boundary. No station pointer is saved. */
static bool prototype_capture(struct mt76_phy *phy,struct sk_buff *s) {
 struct mt76_wcid *w=status(s)->wcid;
 struct mt76_dev *d=phy->dev;
 if(w){
  struct be6l_lease *l=be6l_lookup_untagged(&d->leases,w->idx);
  if(!l || d->live[w->idx]!=w || d->binding[w->idx]!=l){dev_kfree_skb(s);return false;}
  be6l_lease_get(l);s->cache_lease=l;
 }
 s->cache_tagged=true;status(s)->wcid=NULL;
 return true;
}
static void prototype_release_amsdu(struct mt76_phy *phy,enum mt76_rxq_id q) {
 struct mt76_dev *d=phy->dev;
 struct sk_buff *head=phy->rx_amsdu[q].head;
 struct be6l_lease *l=head->cache_lease;
 bool valid=head->cache_tagged;
 if(l)valid=valid&&be6l_lease_is_current(l)&&d->binding[l->id.wcid]==l&&d->live[l->id.wcid];
 for(struct sk_buff *f=head->shared.frag_list;f;f=f->next)
  valid=valid&&f->cache_tagged&&f->cache_lease==l;
 if(!valid){
  phy->rx_amsdu[q].head=NULL;phy->rx_amsdu[q].tail=NULL;
  dev_kfree_skb(head);return;
 }
 /* The real adapter must keep this resolve + normal packet delivery inside
  * one current RCU span. It cannot restore a raw pointer and queue it forever. */
 for(struct sk_buff *s=head;s;s=s==head?head->shared.frag_list:s->next){
  status(s)->wcid=l?d->live[l->id.wcid]:NULL;
  if(s->cache_lease){be6l_lease_put(s->cache_lease);s->cache_lease=NULL;}
  s->cache_tagged=false;
 }
 mt76_rx_release_amsdu(phy,q);
}
static void prototype_purge_caches(struct mt76_phy *phy) {
 /* A real remove path needs actual RX serialization before this loop. */
 for(unsigned q=0;q<QUEUES;q++)if(phy->rx_amsdu[q].head){
  struct sk_buff *s=phy->rx_amsdu[q].head;
  phy->rx_amsdu[q].head=NULL;phy->rx_amsdu[q].tail=NULL;dev_kfree_skb(s);
 }
}
'''

MAIN = r'''
static int synth_lease(void *context,const struct be6l_identity *id,struct be6l_evidence *e) {
 (void)context;*e=(struct be6l_evidence){id->epoch,id->wcid,id->band,BE6L_COVER_ALL};return 0;
}
static int synth_device(void *context,uint64_t epoch,struct be6l_evidence *e) {
 (void)context;*e=(struct be6l_evidence){.epoch=epoch,.coverage=BE6L_COVER_ALL};return 0;
}
static struct be6l_provider synthetic={synth_lease,synth_device,NULL};
static struct be6l_lease *add_live(struct mt76_dev *d,struct mt76_wcid *w) {
 struct be6l_identity id={.wcid=w->idx,.band=0,.mac={2,0,0,0,0,1}};
 struct be6l_lease *l;assert(!be6l_lease_prepare(&d->leases,&id,&l));
 d->live[w->idx]=w;d->binding[w->idx]=l;assert(!be6l_lease_publish(l));return l;
}
static void retire_sta(struct mt76_dev *d,struct mt76_wcid *w) {
 struct be6l_lease *l=d->binding[w->idx];assert(l);
 assert(!be6l_lease_retire(l));d->live[w->idx]=NULL;d->binding[w->idx]=NULL;
 w->alive=false;assert(!be6l_lease_cpu_detached(l));
 /* Models unpublish/grace only. Does NOT claim hardware has drained. */
}
static void finish(struct mt76_dev *d,struct mt76_phy *p) {
 prototype_purge_caches(p);sink(d);
 for(unsigned i=0;i<BE6L_LEASE_SLOTS;i++)if(d->leases.slot[i]){
  struct be6l_lease *l=d->leases.slot[i];
  if(l->state==BE6L_LIVE){assert(!be6l_lease_retire(l));assert(!be6l_lease_cpu_detached(l));}
  assert(!be6l_lease_finalize(l,&synthetic));
 }
 assert(!d->leases.objects_alive);
}
int main(void) {
 const char *names[]={"baseline-normal-control","negative-baseline-cross-poll-raw-pointer",
  "prototype-retired-cache-dropped-without-old-wcid-deref","prototype-live-fragment-control",
  "prototype-mixed-peer-same-sequence-is-not-merged","prototype-tag-survives-independent-old-epoch-and-reuse",
  "negative-baseline-null-table-and-grace-do-not-rewrite-cache",
  "prototype-mismatching-live-binding-rejected","prototype-null-station-control",
  "actual-header-rejection-releases-all-tags","prototype-remove-purges-independent-cache-before-devres",
  "prototype-capture-without-prepublished-lease-fails-closed"};
 unsigned failed=0;
 for(unsigned t=0;t<12;t++){
  struct mt76_dev d={0};struct mt76_phy p={.dev=&d};
  struct mt76_wcid old={1,true},other={2,true};
  struct be6l_lease *old_lease=add_live(&d,&old);add_live(&d,&other);
  struct sk_buff a={0},b={0};
  *status(&a)=(struct mt76_rx_status){.wcid=&old,.flag=RX_FLAG_8023,.seqno=7,.amsdu=true,.first_amsdu=true};
  *status(&b)=(struct mt76_rx_status){.wcid=&other,.flag=RX_FLAG_8023,.seqno=8};
  dropped=delivered=dead_pointer_observed=unknown_delivered=0;bool ok=false;
  if(t==0){status(&a)->amsdu=false;mt76_rx_release_burst(&p,0,&a);sink(&d);ok=delivered==1&&!dead_pointer_observed;}
  if(t==1||t==6){
   mt76_rx_release_burst(&p,0,&a);bool raw=status(&a)->wcid==&old;
   retire_sta(&d,&old);mt76_rx_release_burst(&p,0,&b);sink(&d);
   ok=raw&&!d.live[1]&&dead_pointer_observed==1&&delivered==2;
  }
  if(t==2){
   prototype_mt76_rx_release_burst(&p,0,&a);bool cleared=!status(&a)->wcid;
   retire_sta(&d,&old);prototype_mt76_rx_release_burst(&p,0,&b);sink(&d);
   ok=cleared&&dropped==1&&delivered==1&&!dead_pointer_observed&&d.leases.slot[1]==old_lease;
  }
  if(t==3||t==4||t==9){
   status(&b)->seqno=7;status(&b)->amsdu=true;status(&b)->last_amsdu=true;
   if(t!=4)status(&b)->wcid=&old;
   if(t==9)memcpy(a.data,rfc1042_header,6);
   prototype_mt76_rx_release_burst(&p,0,&a);prototype_mt76_rx_release_burst(&p,0,&b);sink(&d);
   ok=t==3?delivered==2&&!dropped&&!dead_pointer_observed:delivered==0&&dropped==2;
  }
  if(t==5){
   prototype_mt76_rx_release_burst(&p,0,&a);uint64_t epoch=old_lease->id.epoch;
   retire_sta(&d,&old);assert(!be6l_lease_finalize(old_lease,&synthetic));
   struct mt76_wcid fresh={1,true};struct be6l_lease *current=add_live(&d,&fresh);
   bool independent=d.leases.objects_alive==3&&old_lease->id.epoch==epoch&&current->id.epoch!=epoch;
   status(&b)->wcid=&fresh;prototype_mt76_rx_release_burst(&p,0,&b);sink(&d);
   ok=independent&&dropped==1&&delivered==1&&!dead_pointer_observed;
   /* Finish before the borrowed current table pointer leaves this scope. */
   finish(&d,&p);
  }
  if(t==7){
   prototype_mt76_rx_release_burst(&p,0,&a);d.binding[1]=d.binding[2];
   prototype_mt76_rx_release_burst(&p,0,&b);sink(&d);
   ok=dropped==1&&delivered==1&&!dead_pointer_observed;d.binding[1]=old_lease;
  }
  if(t==8){status(&a)->wcid=NULL;status(&a)->amsdu=false;prototype_mt76_rx_release_burst(&p,0,&a);sink(&d);ok=delivered==1&&unknown_delivered==1;}
  if(t==10){
   prototype_mt76_rx_release_burst(&p,0,&a);retire_sta(&d,&old);be6l_shutdown_begin(&d.leases);
   bool blocked=be6l_devres_release_gate(&d.leases,&synthetic)==-EBUSY;
   prototype_purge_caches(&p);finish(&d,&p);
   ok=blocked&&dropped==1&&!be6l_devres_release_gate(&d.leases,&synthetic);
  }
  if(t==11){d.binding[1]=NULL;prototype_mt76_rx_release_burst(&p,0,&a);ok=a.disposed&&!p.rx_amsdu[0].head&&!delivered;}
  unsigned pre_finish_drops=dropped;
  if(t!=5&&t!=10)finish(&d,&p);
  failed+=!ok;
  printf("{\"scenario\":\"%s\",\"expected_observation_passed\":%s,\"raw_retired_pointer_observations\":%u,"
   "\"delivered_frames\":%u,\"dropped_frames\":%u,\"live_native_reachability_proved\":false}\n",
   names[t],ok?"true":"false",dead_pointer_observed,delivered,pre_finish_drops);
 }
 return failed?1:0;
}
'''


def run(a, work, name, source, extra=()):
    file = work/(name+'.c')
    file.write_text(source)
    env = dict(os.environ,LD_LIBRARY_PATH=str(a.host_prefix/'usr/lib/x86_64-linux-gnu'))
    folder = BASE/'experiments/npu-retired-lease'
    cmd = [str(a.cc),'-std=gnu11','-O0','-g','-Wall','-Wextra','-Werror',
        '-I'+str(folder),str(file),str(folder/'retired_lease.c'),*map(str,extra),'-o',str(work/name)]
    r = subprocess.run(cmd,env=env,capture_output=True,timeout=30)
    (work/(name+'-compile.log')).write_bytes(r.stdout+r.stderr)
    if r.returncode:
        raise RuntimeError('Prototype compile failed: '+name)
    r = subprocess.run([str(work/name)],env=env,capture_output=True,timeout=10)
    (work/(name+'-observations.jsonl')).write_bytes(r.stdout)
    (work/(name+'-stderr.log')).write_bytes(r.stderr)
    rows = [json.loads(x) for x in r.stdout.decode().splitlines()]
    return r.returncode,rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source','native-source','cc','host-prefix','work'):
        p.add_argument('--'+name,type=Path,required=True)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent!=Path('/root') or not w.name.startswith('be6l-retired-lease-prototype-20261113-') or w.exists():
        p.error('Fresh private /root/be6l-retired-lease-prototype-20261113-* required')
    raw = a.source.read_bytes();native = a.native_source.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PIN or hashlib.sha256(native).hexdigest()!=NATIVE_PIN:
        raise ValueError('Exact matched mt76/native source required')
    s = raw.decode()
    release = function(s,'mt76_rx_release_amsdu')
    burst = function(s,'mt76_rx_release_burst')
    adapted = burst.replace('mt76_rx_release_burst','prototype_mt76_rx_release_burst').replace(
        'mt76_rx_release_amsdu(phy, q);','prototype_release_amsdu(phy, q);')
    anchor = '\tstruct mt76_rx_status *status = (struct mt76_rx_status *)skb->cb;'
    if adapted.count(anchor)!=1:
        raise ValueError('Cache seam changed')
    adapted = adapted.replace(anchor,anchor+'\n\tif (!prototype_capture(phy, skb))\n\t\treturn;',1)
    w.mkdir(mode=0o700)
    model_status,model = run(a,w,'lease-model',(BASE/'experiments/npu-retired-lease/model_cases.c').read_text())
    rx_status,rx = run(a,w,'actual-rx-cache',PRELUDE+release+burst+ADAPTER+adapted+MAIN)
    ntext = native.decode()
    native_names=('native_ppe_stop','native_ppe_restore_idle','wait_parked','fault_stop')
    passed = (model_status==rx_status==0 and len(model)==27 and len(rx)==12 and
        all(x['passed'] for x in model) and all(x['expected_observation_passed'] for x in rx))
    sources = [BASE/'experiments/npu-retired-lease'/n for n in ('retired_lease.h','retired_lease.c','model_cases.c')]
    report = dict(kind='Independent host source prototype; not a Linux driver port',
        mt76_source_sha256=PIN,native_source_sha256=NATIVE_PIN,
        actual_rx_function_sha256={n:hashlib.sha256(function(s,n).encode()).hexdigest() for n in
            ('mt76_rx_release_amsdu','mt76_rx_release_burst')},
        prototype_sources_sha256={str(x.relative_to(BASE)):hashlib.sha256(x.read_bytes()).hexdigest() for x in sources},
        actual_native_scope_function_sha256={n:hashlib.sha256(function(ntext,n).encode()).hexdigest() for n in native_names},
        model_observations=model,rx_source_observations=rx,all_expected_observations_passed=passed,
        baseline_negative_controls_are_safety_passes=False,
        synthetic_provider_only=True,default_missing_provider_denies_release=True,
        untagged_completion_generation_inference=False,
        hardware_provider_implemented=False,actual_skb_storage_or_rcu_integration=False,
        excluded=['Real IRQ/RCU/RTNL synchronization','Native packet-format reachability',
            'Physical FOE/output DMA completion','Full station/remove/devres integration',
            'Kernel/module ABI or target qualification'],
        native_binding_admitted=False,routed_gate_opened=False,xwrt_94104_complete_port=False,
        target_executed=False,existing_source_mutated=False)
    (w/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print('RETIRED_LEASE_SOURCE_PROTOTYPE_RECORDED',len(model),len(rx),passed,flush=True)
    if not passed:
        raise SystemExit(1)


if __name__=='__main__':
    main()
