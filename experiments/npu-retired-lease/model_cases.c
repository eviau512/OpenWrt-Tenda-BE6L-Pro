/* SPDX-License-Identifier: MIT */
#include "retired_lease.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* Synthetic test provider, not native hardware evidence or an admission path. */
struct fake_provider { unsigned mask; int error; bool stale, wrong_band; };
static int synthetic_lease(void *context, const struct be6l_identity *id,
                           struct be6l_evidence *e)
{
 struct fake_provider *f = context;
 *e = (struct be6l_evidence){.epoch=id->epoch + f->stale,
  .wcid=id->wcid,.band=id->band ^ f->wrong_band,.coverage=f->mask};
 return f->error;
}
static int synthetic_device(void *context, uint64_t epoch, struct be6l_evidence *e)
{
 struct fake_provider *f = context;
 *e = (struct be6l_evidence){.epoch=epoch+f->stale,.coverage=f->mask};
 return f->error;
}
static int failures;
static void row(const char *name, bool ok)
{
 failures += !ok;
 printf("{\"scenario\":\"%s\",\"passed\":%s,\"hardware_proved\":false}\n",name,ok?"true":"false");
}
int main(void)
{
 struct be6l_manager m = {0};
 struct be6l_identity copy = {.wcid=1,.band=1,.bss=3,.mac={2,1,2,3,4,5},.replay_cookie=91};
 struct be6l_lease *l, *next;
 struct be6l_resource resources[4] = {
  {BE6L_FOE_OWNER,1},{BE6L_SMAC_OWNER,1},{BE6L_DESTINATION,1},{BE6L_DMA_BACKING,1}};
 struct fake_provider fake = {.mask=BE6L_COVER_ALL};
 struct be6l_provider provider = {synthetic_lease,synthetic_device,&fake};
 assert(!be6l_lease_prepare(&m,&copy,&l));
 for (unsigned i=0;i<4;i++) assert(!be6l_lease_attach(l,&resources[i]));
 row("unpublished-failure-unwinds-without-hardware-obligation",
     !be6l_lease_abort_unpublished(l)&&!m.objects_alive&&resources[0].refs==1&&!m.slot[1]);
 assert(!be6l_lease_prepare(&m,&copy,&l));
 for (unsigned i=0;i<4;i++) assert(!be6l_lease_attach(l,&resources[i]));
 copy.mac[0]=99;copy.replay_cookie=999;
 row("identity-is-copied-without-mac80211-owned-pointer",l->id.mac[0]==2&&l->id.replay_cookie==91);
 assert(!be6l_lease_publish(l));
 row("published-obligation-cannot-use-unpublished-abort",be6l_lease_abort_unpublished(l)==-EBUSY);
 be6l_lease_get(l); /* Host-tagged cache owns an independent metadata ref. */
 assert(!be6l_lease_retire(l));
 row("retire-revokes-untagged-lookup-before-upstream-sta-free",!be6l_lookup_untagged(&m,1));
 row("numeric-quarantine-blocks-reuse-after-void-callback-returns",
     be6l_lease_prepare(&m,&copy,&next)==-EBUSY&&resources[3].refs==2);
 row("hardware-proof-does-not-substitute-for-cpu-detach",be6l_lease_finalize(l,&provider)==-EBUSY);
 assert(!be6l_lease_cpu_detached(l));
 row("cpu-grace-without-hardware-provider-retains-all-owners",
     be6l_lease_finalize(l,NULL)==-EOPNOTSUPP&&m.slot[1]==l&&resources[0].refs==2);
 fake.error=-ETIMEDOUT;
 row("provider-timeout-retains-slot-smac-destination-dma",
     be6l_lease_finalize(l,&provider)==-ETIMEDOUT&&resources[1].refs==2&&resources[2].refs==2&&resources[3].refs==2);
 fake.error=0;fake.stale=true;
 row("late-prior-epoch-proof-rejected",be6l_lease_finalize(l,&provider)==-ESTALE&&m.slot[1]==l);
 fake.stale=false;fake.wrong_band=true;
 row("same-index-other-radio-proof-rejected",be6l_lease_finalize(l,&provider)==-ESTALE);
 fake.wrong_band=false;
 const char *domains[]={"missing-foe","missing-native-writers","missing-output-dma",
  "missing-irq-callbacks","missing-rx-caches","missing-remove-setup"};
 for (unsigned i=0;i<6;i++) {
  fake.mask=BE6L_COVER_ALL&~(1U<<i);
  row(domains[i],be6l_lease_finalize(l,&provider)==-EAGAIN&&m.slot[1]==l&&resources[0].refs==2);
 }
 fake.mask=BE6L_COVER_NATIVE_WRITERS;
 row("abi5-native-only-scope-is-not-all-output-proof",be6l_lease_finalize(l,&provider)==-EAGAIN);
 fake.mask=BE6L_COVER_ALL;
 uint64_t old_epoch=l->id.epoch;
 assert(!be6l_lease_finalize(l,&provider));
 row("synthetic-covered-generation-releases-resources-once",
     resources[0].refs==1&&resources[1].refs==1&&resources[2].refs==1&&resources[3].refs==1);
 assert(!be6l_lease_prepare(&m,&copy,&next));assert(!be6l_lease_publish(next));
 row("host-tagged-old-cache-remains-independent-and-stale-after-reuse",
     m.objects_alive==2&&!be6l_lease_is_current(l)&&l->id.epoch==old_epoch&&next->id.epoch!=old_epoch);
 /* Negative control about the wire format: both identical index-only events
  * resolve identically. No epoch invented on the host can distinguish them.
  * A real provider must ensure the old event no longer exists before reuse. */
 uint16_t hypothetical_old_event=1,new_event=1;
 row("negative-control-untagged-old-and-new-events-indistinguishable",
     be6l_lookup_untagged(&m,hypothetical_old_event)==be6l_lookup_untagged(&m,new_event));
 be6l_lease_put(l);
 assert(!be6l_setup_enter(&m));be6l_shutdown_begin(&m);
 row("shutdown-blocks-new-setup-and-station-publication",
     be6l_setup_enter(&m)==-ESHUTDOWN&&be6l_lease_prepare(&m,&copy,&l)==-ESHUTDOWN);
 assert(!be6l_lease_retire(next));assert(!be6l_lease_cpu_detached(next));
 be6l_lease_get(next);
 assert(!be6l_lease_finalize(next,&provider));
 row("devres-not-released-with-independent-cache-reference",
     be6l_devres_release_gate(&m,&provider)==-EBUSY&&m.objects_alive==1);
 be6l_lease_put(next);
 row("devres-not-released-with-setup-callback-in-flight",be6l_devres_release_gate(&m,&provider)==-EBUSY);
 be6l_setup_exit(&m);fake.mask=BE6L_COVER_ALL&~BE6L_COVER_IRQ_CALLBACKS;
 row("devres-not-released-before-irq-synchronization",be6l_devres_release_gate(&m,&provider)==-EAGAIN);
 row("no-device-provider-means-no-devres-admission",be6l_devres_release_gate(&m,NULL)==-EOPNOTSUPP);
 fake.mask=BE6L_COVER_ALL;
 row("synthetic-device-boundary-admits-only-after-all-owners-gone",!be6l_devres_release_gate(&m,&provider));
 struct be6l_manager overflow={.epoch=UINT64_MAX};
 row("epoch-exhaustion-does-not-wrap-and-republish",be6l_lease_prepare(&overflow,&copy,&l)==-EOVERFLOW&&!overflow.objects_alive);
 return failures?1:0;
}
