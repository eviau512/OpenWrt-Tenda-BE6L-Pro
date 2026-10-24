/* SPDX-License-Identifier: MIT */
/* Serialized reference model, NOT an on-device ABI or concurrency primitive.
 * Real integration needs per-token admission tickets and publication fences.
 * A bare FOE slot observed at completion is explicitly insufficient.
 */
#ifndef BE6L_FLOW_LEASE_H
#define BE6L_FLOW_LEASE_H
#include <stdint.h>
#include "../routed-frame/routed-frame.h"
#define FL_PENDING 16
enum fl_state { FL_FREE, FL_LIVE, FL_DRAINING, FL_FROZEN, FL_EXHAUSTED };
struct fl_ticket { uint64_t epoch, cookie, serial; uint32_t generation; };
struct fl_pending {
	struct fl_ticket ticket;
	uint32_t core, bytes, published;
};
struct fl_lease {
	uint64_t epoch, cookie, serial, packets, bytes;
	uint32_t generation, state, ack_mask, reported, stats_invalid;
	struct rf_identity identity;
	struct fl_pending pending[FL_PENDING];
};
static inline int fl_same(const struct fl_ticket *a, const struct fl_ticket *b)
{
	return a->epoch == b->epoch && a->cookie == b->cookie &&
	       a->generation == b->generation && a->serial == b->serial;
}
static inline int fl_id(const struct rf_identity *a, const struct rf_identity *b)
{
	return a->port == b->port && a->vlan == b->vlan && a->wcid == b->wcid &&
	       a->replay_generation == b->replay_generation && a->ct_zone == b->ct_zone;
}
static inline struct fl_pending *fl_find(struct fl_lease *l, const struct fl_ticket *t)
{
	if (!t->serial || t->epoch != l->epoch || t->cookie != l->cookie ||
	    t->generation != l->generation)
		return 0;
	for (unsigned int i = 0; i < FL_PENDING; i++)
		if (fl_same(&l->pending[i].ticket, t))
			return &l->pending[i];
	return 0;
}
static inline int fl_bind(struct fl_lease *l, uint64_t epoch, uint64_t cookie,
			  const struct rf_identity *id)
{
	if (l->state != FL_FREE || !epoch || !cookie || !id->replay_generation ||
	    (l->epoch && l->epoch != epoch))
		return 0;
	if (l->generation == UINT32_MAX || l->serial == UINT64_MAX) {
		l->state = FL_EXHAUSTED;
		return 0; /* Reinitialize only after global DMA quiescence and new epoch. */
	}
	l->epoch = epoch; l->cookie = cookie; l->generation++;
	l->identity = *id; l->packets = 0; l->bytes = 0;
	l->ack_mask = 0; l->reported = 0; l->stats_invalid = 0;
	l->state = FL_LIVE;
	return 1;
}
static inline int fl_admit(struct fl_lease *l, const struct rf_identity *id,
			   uint32_t core, uint32_t bytes, struct fl_ticket *out)
{
	if (l->state != FL_LIVE || core > 1 || bytes < 14 || bytes > 2048 ||
	    !fl_id(id, &l->identity) || l->serial == UINT64_MAX)
		return 0;
	for (unsigned int i = 0; i < FL_PENDING; i++) {
		struct fl_pending *p = &l->pending[i];
		if (p->ticket.serial)
			continue;
		*out = (struct fl_ticket){l->epoch, l->cookie, ++l->serial, l->generation};
		*p = (struct fl_pending){*out, core, bytes, 0};
		return 1;
	}
	return 0;
}
static inline int fl_commit(struct fl_lease *l, const struct fl_ticket *t,
			    const struct rf_identity *rechecked)
{
	struct fl_pending *p = fl_find(l, t);
	if (l->state != FL_LIVE || !p || p->published || !fl_id(rechecked, &l->identity))
		return 0;
	p->published = 1;
	return 1; /* Model only: does not authorize or perform DMA publication. */
}
static inline int fl_finish(struct fl_lease *l, const struct fl_ticket *t, int forwarded)
{
	struct fl_pending *p = fl_find(l, t);
	if ((l->state != FL_LIVE && l->state != FL_DRAINING) || !p ||
	    (forwarded != 0 && forwarded != 1) || (forwarded && !p->published))
		return 0;
	if (forwarded && !l->stats_invalid) {
		if (l->packets == UINT64_MAX || l->bytes > UINT64_MAX - p->bytes)
			l->stats_invalid = 1; /* Never silently wrap or report plausible zero. */
		else {
			l->packets++; l->bytes += p->bytes;
		}
	}
	p->ticket.serial = 0;
	return 1;
}
static inline int fl_revoke(struct fl_lease *l)
{
	if (l->state != FL_LIVE)
		return 0;
	l->state = FL_DRAINING;
	return 1;
}
/* Caller must first prove this worker's queue/publication barrier completed. */
static inline int fl_ack(struct fl_lease *l, uint32_t generation, uint32_t core)
{
	if (l->state != FL_DRAINING || generation != l->generation || core > 1)
		return 0;
	for (unsigned int i = 0; i < FL_PENDING; i++)
		if (l->pending[i].ticket.serial && l->pending[i].core == core)
			return 0;
	l->ack_mask |= 1U << core;
	if (l->ack_mask == 3)
		l->state = FL_FROZEN;
	return 1;
}
static inline int fl_final(struct fl_lease *l, uint64_t cookie, uint32_t generation,
			   uint64_t *packets, uint64_t *bytes)
{
	if (l->state != FL_FROZEN || cookie != l->cookie || generation != l->generation ||
	    l->stats_invalid || l->reported)
		return 0;
	*packets = l->packets; *bytes = l->bytes; l->reported = 1;
	return 1;
}
static inline int fl_release(struct fl_lease *l, int consumer_acknowledged_failure)
{
	if (l->state != FL_FROZEN || (!l->reported &&
	    !(l->stats_invalid && consumer_acknowledged_failure == 1)))
		return 0;
	l->cookie = 0; l->state = FL_FREE;
	return 1;
}
#endif
