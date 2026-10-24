/* SPDX-License-Identifier: MIT */
#ifndef BE6L_FLOW_WORKER_H
#define BE6L_FLOW_WORKER_H
#include "flow-abi.h"
#include "flow-lease.h"
#include "routed-selftest-vectors.h"
struct fa_entry {
	struct fl_lease lease;
	struct rf_action action;
	uint32_t phase;
};
_Static_assert(sizeof(struct fa_entry) <= FA_SLOT_STRIDE, "Flow entry exceeds wire reservation");
static inline uint64_t fa_u64(uint32_t lo, uint32_t hi)
{
	return (uint64_t)hi << 32 | lo;
}
static inline volatile uint32_t *fa_page(uint32_t core)
{
	return (void *)(uintptr_t)(FA_NPU + core * FA_CORE_STRIDE);
}
static inline volatile uint32_t *fa_gate(uint32_t slot)
{
	return (void *)(uintptr_t)(FA_NPU + FA_GATES + slot * 4);
}
static inline struct fa_entry *fa_entry(uint32_t core, uint32_t slot)
{
	return (void *)(uintptr_t)(FA_NPU + core * FA_CORE_STRIDE + FA_TABLE + slot * FA_SLOT_STRIDE);
}
static inline void fa_worker_boot(uint32_t core)
{
	volatile uint32_t *p = fa_page(core);
	for (uint32_t i = 0; i < FA_CORE_STRIDE / 4; i++) p[i] = 0;
	p[0] = FA_MAGIC; p[1] = FA_VERSION; p[2] = core;
	barrier(); p[3] = 1;
}
static inline void fa_worker_stop(uint32_t core)
{
	fa_page(core)[3] = 0; barrier();
}
static inline void fa_decode_action(struct rf_action *a, const uint32_t *w)
{
	*a = (struct rf_action){0};
	a->cookie = fa_u64(w[4], w[5]);
	a->ingress = (struct rf_identity){w[8], w[9], w[10], w[11], w[12]};
	a->version = w[13]; a->protocol = w[13] >> 8; a->mtu = w[13] >> 16;
	uint8_t *macs[4] = {a->src_mac, a->dst_mac, a->out_src_mac, a->out_dst_mac};
	for (uint32_t i = 0; i < 24; i++) macs[i / 6][i % 6] = w[14 + i / 4] >> (8 * (i % 4));
	uint8_t *ips[4] = {a->src_ip, a->dst_ip, a->out_src_ip, a->out_dst_ip};
	for (uint32_t i = 0; i < 64; i++) ips[i / 16][i % 16] = w[20 + i / 4] >> (8 * (i % 4));
	a->src_port = w[36]; a->dst_port = w[36] >> 16;
	a->out_src_port = w[37]; a->out_dst_port = w[37] >> 16;
	a->established = w[38];
}
static inline uint32_t fa_pending(const struct fl_lease *l)
{
	uint32_t count = 0;
	for (uint32_t i = 0; i < FL_PENDING; i++) count += !!l->pending[i].ticket.serial;
	return count;
}
static inline uint32_t fa_execute(uint32_t core, const uint32_t *w)
{
	uint32_t slot = w[2], gen = w[3];
	uint64_t cookie = fa_u64(w[4], w[5]), epoch = fa_u64(w[6], w[7]);
	if (slot >= FA_SLOTS || !gen || !cookie || !epoch) return FA_INVALID;
	for (uint32_t i = 40; i < FA_WORDS; i++) if (w[i]) return FA_INVALID;
	struct fa_entry *e = fa_entry(core, slot);
	struct fl_lease *l = &e->lease;
	if (w[1] == FA_PREPARE) {
		if (e->phase != FA_FREE || *fa_gate(slot)) return FA_STATE;
		if (l->generation == UINT32_MAX || gen != l->generation + 1) return FA_GENERATION;
		struct rf_action a;
		fa_decode_action(&a, w);
		if (a.established != 1 || a.ingress.vlan || !a.ingress.replay_generation ||
		    (a.version != 4 && a.version != 6) || (a.protocol != 6 && a.protocol != 17) ||
		    a.mtu < (a.version == 4 ? 68 : 1280) ||
		    !rf_unicast_mac(a.src_mac) || !rf_unicast_mac(a.dst_mac) ||
		    !rf_unicast_mac(a.out_src_mac) || !rf_unicast_mac(a.out_dst_mac)) return FA_INVALID;
		if (!fl_bind(l, epoch, cookie, &a.ingress)) return FA_STATE;
		e->action = a; e->phase = FA_PREPARED;
		return FA_OK;
	}
	if (gen != l->generation || cookie != l->cookie || epoch != l->epoch) return FA_GENERATION;
	if (w[1] == FA_COMMIT) {
		if (e->phase != FA_PREPARED || *fa_gate(slot)) return FA_STATE;
		e->phase = FA_READY; return FA_OK;
	}
	if (w[1] == FA_SIMULATE) {
		if (e->phase != FA_READY || *fa_gate(slot) != gen || w[39] >= sizeof(rf_vectors)/sizeof(rf_vectors[0])) return FA_STATE;
		struct rf_identity id = {w[8], w[9], w[10], w[11], w[12]};
		struct fl_ticket ticket;
		const struct rf_vector *v = &rf_vectors[w[39]];
		uint8_t frame[128];
		if (!fl_admit(l, &id, core, v->length, &ticket)) return FA_MISMATCH;
		for (uint32_t i = 0; i < v->length; i++) frame[i] = v->before[i];
		if (!fl_commit(l, &ticket, &id) || *fa_gate(slot) != gen) {
			fl_finish(l, &ticket, 0); return FA_STATE;
		}
		int ok = routed_frame_apply(frame, v->length, &e->action, &id) == 1 &&
			 rf_equal(frame, v->after, v->length);
		fl_finish(l, &ticket, ok);
		return ok ? FA_OK : FA_MISMATCH;
	}
	if (w[1] == FA_REVOKE) {
		if (*fa_gate(slot) || (e->phase != FA_READY && e->phase != FA_PREPARED)) return FA_STATE;
		if (!fl_revoke(l)) return FA_STATE;
		e->phase = FA_DRAINING; return FA_OK;
	}
	if (w[1] == FA_FENCE) {
		if (*fa_gate(slot) || e->phase != FA_DRAINING) return FA_STATE;
		if (fa_pending(l)) return FA_BUSY;
		/* This proves only the local synthetic token pool is empty. It is
		 * NOT a hardware DMA/radio/PPE queue-drain acknowledgment.
		 */
		l->state = FL_FROZEN; e->phase = FA_FROZEN; return FA_OK;
	}
	if (w[1] == FA_RELEASE) {
		uint64_t packets, bytes;
		if (*fa_gate(slot) || e->phase != FA_FROZEN ||
		    !fl_final(l, cookie, gen, &packets, &bytes) || !fl_release(l, 0)) return FA_STATE;
		e->phase = FA_FREE; return FA_OK;
	}
	return FA_INVALID;
}
static inline void fa_service(uint32_t core)
{
	volatile uint32_t *page = fa_page(core), *request = page + FA_COMMAND / 4;
	volatile uint32_t *reply = page + FA_RESPONSE / 4;
	uint32_t sequence = request[0], w[FA_WORDS], status;
	if (!sequence || (sequence & 1) || sequence == page[6]) return;
	barrier();
	for (uint32_t i = 0; i < FA_WORDS; i++) w[i] = request[i];
	barrier();
	if (sequence != request[0]) return;
	if (sequence < page[6]) status = FA_REPLAY;
	else {
		page[6] = sequence;
		if ((!w[6] && !w[7]) || ((page[4] || page[5]) &&
		    (page[4] != w[6] || page[5] != w[7]))) status = FA_SESSION;
		else {
			page[4] = w[6]; page[5] = w[7];
			status = fa_execute(core, w);
		}
	}
	struct fa_entry *e = w[2] < FA_SLOTS ? fa_entry(core, w[2]) : 0;
	reply[1] = status; reply[2] = core; reply[3] = w[2]; reply[4] = w[3];
	reply[5] = e ? e->phase : 0;
	for (uint32_t i = 4; i < 8; i++) reply[i + 2] = w[i];
	reply[10] = e ? fa_pending(&e->lease) : 0; reply[11] = 1;
	reply[12] = e ? e->lease.packets : 0; reply[13] = e ? e->lease.packets >> 32 : 0;
	reply[14] = e ? e->lease.bytes : 0; reply[15] = e ? e->lease.bytes >> 32 : 0;
	barrier(); reply[0] = sequence;
}
#endif
