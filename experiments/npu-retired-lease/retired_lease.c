/* SPDX-License-Identifier: MIT */
#include "retired_lease.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

int be6l_lease_prepare(struct be6l_manager *m, const struct be6l_identity *copy,
                      struct be6l_lease **result)
{
 struct be6l_lease *l;
 *result = NULL;
 if (m->closing) return -ESHUTDOWN;
 if (copy->wcid >= BE6L_LEASE_SLOTS || copy->band > 1) return -EINVAL;
 if (m->slot[copy->wcid]) return -EBUSY;
 if (m->epoch == UINT64_MAX) return -EOVERFLOW;
 l = calloc(1, sizeof(*l));
 if (!l) return -ENOMEM;
 l->id = *copy;
 l->id.epoch = ++m->epoch;
 l->manager = m;
 l->state = BE6L_PREPARED;
 atomic_init(&l->refs, 1); /* Manager's numeric lease obligation. */
 m->objects_alive++;
 m->slot[l->id.wcid] = l;
 *result = l;
 return 0;
}

int be6l_lease_attach(struct be6l_lease *l, struct be6l_resource *resource)
{
 if (l->state != BE6L_PREPARED) return -EBUSY;
 if (!resource || !resource->refs || l->resource_count == BE6L_LEASE_RESOURCES)
  return -EINVAL;
 for (unsigned i = 0; i < l->resource_count; i++)
  if (l->resource[i] == resource) return -EEXIST;
 resource->refs++;
 l->resource[l->resource_count++] = resource;
 return 0;
}

int be6l_lease_publish(struct be6l_lease *l)
{
 if (l->state != BE6L_PREPARED || l->manager->closing) return -EBUSY;
 l->state = BE6L_LIVE;
 return 0;
}

void be6l_lease_get(struct be6l_lease *l)
{
 assert(atomic_load_explicit(&l->refs, memory_order_relaxed));
 atomic_fetch_add_explicit(&l->refs, 1, memory_order_relaxed);
}

int be6l_lease_abort_unpublished(struct be6l_lease *l)
{
 if (l->state != BE6L_PREPARED) return -EBUSY;
 for (unsigned i = 0; i < l->resource_count; i++) {
  assert(l->resource[i]->refs > 1);
  l->resource[i]->refs--;
 }
 l->resource_count = 0;
 l->manager->slot[l->id.wcid] = NULL;
 l->state = BE6L_RELEASED;
 be6l_lease_put(l);
 return 0;
}

void be6l_lease_put(struct be6l_lease *l)
{
 unsigned old = atomic_fetch_sub_explicit(&l->refs, 1, memory_order_acq_rel);
 assert(old);
 if (old != 1) return;
 /* A cached metadata reference cannot accidentally retire the manager's
  * outstanding hardware/numeric ownership obligation. */
 assert(l->state == BE6L_RELEASED);
 assert(l->resource_count == 0);
 l->manager->objects_alive--;
 free(l);
}

int be6l_lease_retire(struct be6l_lease *l)
{
 if (l->state != BE6L_LIVE && l->state != BE6L_PREPARED) return -EINVAL;
 /* Close admission first. Caller must unpublish the real WCID/sta pointers,
  * finish old CPU users and remove/revalidate caches before marking detached.
  * The independent object contains no such station pointer to retain. */
 l->state = BE6L_RETIRING;
 return 0;
}

int be6l_lease_cpu_detached(struct be6l_lease *l)
{
 if (l->state != BE6L_RETIRING) return -EINVAL;
 l->cpu_detached = true;
 return 0;
}

int be6l_lease_finalize(struct be6l_lease *l, const struct be6l_provider *p)
{
 struct be6l_evidence e = {0};
 int err;
 if (l->state != BE6L_RETIRING) return -EINVAL;
 if (!l->cpu_detached) return -EBUSY;
 if (!p || !p->lease_evidence) return -EOPNOTSUPP;
 err = p->lease_evidence(p->context, &l->id, &e);
 if (err) return err;
 if (e.epoch != l->id.epoch || e.wcid != l->id.wcid || e.band != l->id.band)
  return -ESTALE;
 if ((e.coverage & BE6L_COVER_ALL) != BE6L_COVER_ALL) return -EAGAIN;
 for (unsigned i = 0; i < l->resource_count; i++) {
  assert(l->resource[i]->refs > 1);
  l->resource[i]->refs--;
 }
 l->resource_count = 0;
 assert(l->manager->slot[l->id.wcid] == l);
 l->manager->slot[l->id.wcid] = NULL;
 l->state = BE6L_RELEASED;
 be6l_lease_put(l);
 return 0;
}

bool be6l_lease_is_current(const struct be6l_lease *l)
{
 return l && l->state == BE6L_LIVE && !l->manager->closing &&
        l->manager->slot[l->id.wcid] == l;
}

struct be6l_lease *be6l_lookup_untagged(struct be6l_manager *m, uint16_t idx)
{
 if (idx >= BE6L_LEASE_SLOTS) return NULL;
 struct be6l_lease *l = m->slot[idx];
 /* This cannot infer an event generation. Index reuse is prohibited until
  * the old hardware epoch is fenced; a host-only epoch does not fix ABA. */
 return be6l_lease_is_current(l) ? l : NULL;
}

int be6l_setup_enter(struct be6l_manager *m)
{
 if (m->closing) return -ESHUTDOWN;
 m->setup_users++;
 return 0;
}

void be6l_setup_exit(struct be6l_manager *m)
{
 assert(m->setup_users);
 m->setup_users--;
}

void be6l_shutdown_begin(struct be6l_manager *m)
{
 m->closing = true;
}

int be6l_devres_release_gate(struct be6l_manager *m, const struct be6l_provider *p)
{
 struct be6l_evidence e = {0};
 int err;
 if (!m->closing || m->setup_users || m->objects_alive) return -EBUSY;
 if (!p || !p->device_evidence) return -EOPNOTSUPP;
 err = p->device_evidence(p->context, m->epoch, &e);
 if (err) return err;
 if (e.epoch != m->epoch) return -ESTALE;
 return (e.coverage & BE6L_COVER_ALL) == BE6L_COVER_ALL ? 0 : -EAGAIN;
}
