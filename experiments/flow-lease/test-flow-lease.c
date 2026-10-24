/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "flow-lease.h"
static struct rf_identity id = {7, 0, 11, 33, 42};
static uint32_t random_state = 0x62be6a;
static uint32_t random32(void)
{
	random_state ^= random_state << 13; random_state ^= random_state >> 17;
	random_state ^= random_state << 5; return random_state;
}
static void freeze(struct fl_lease *l)
{
	assert(fl_revoke(l)); assert(fl_ack(l, l->generation, 0));
	assert(fl_ack(l, l->generation, 1)); assert(l->state == FL_FROZEN);
}
int main(void)
{
	struct fl_lease l = {0};
	struct fl_ticket a, b, stale, bad, tickets[FL_PENDING];
	struct rf_identity other;
	uint64_t packets, bytes;
	assert(!fl_bind(&l, 0, 1, &id)); assert(!fl_bind(&l, 9, 0, &id));
	assert(fl_bind(&l, 9, 123, &id));
	for (unsigned int field = 0; field < 5; field++) {
		other = id;
		switch (field) {
		case 0: other.port++; break; case 1: other.vlan++; break;
		case 2: other.wcid++; break; case 3: other.replay_generation++; break;
		default: other.ct_zone++;
		}
		assert(!fl_admit(&l, &other, 0, 100, &a));
	}
	assert(!fl_admit(&l, &id, 2, 100, &a));
	assert(fl_admit(&l, &id, 0, 1500, &a));
	assert(!fl_finish(&l, &a, 1));
	other = id; other.replay_generation++;
	assert(!fl_commit(&l, &a, &other)); assert(fl_commit(&l, &a, &id));
	assert(!fl_commit(&l, &a, &id));
	assert(fl_admit(&l, &id, 1, 200, &b));
	assert(fl_revoke(&l)); assert(!fl_bind(&l, 9, 456, &id));
	assert(!fl_commit(&l, &b, &id)); assert(!fl_admit(&l, &id, 0, 100, &bad));
	assert(!fl_ack(&l, l.generation, 0)); assert(!fl_ack(&l, l.generation, 1));
	bad = a; bad.epoch++; assert(!fl_finish(&l, &bad, 1));
	bad = a; bad.cookie++; assert(!fl_finish(&l, &bad, 1));
	bad = a; bad.generation++; assert(!fl_finish(&l, &bad, 1));
	bad = a; bad.serial++; assert(!fl_finish(&l, &bad, 1));
	assert(fl_finish(&l, &a, 1)); assert(!fl_finish(&l, &a, 1));
	assert(fl_finish(&l, &b, 0));
	assert(!fl_ack(&l, l.generation - 1, 0));
	assert(fl_ack(&l, l.generation, 0)); assert(!fl_release(&l, 0));
	assert(fl_ack(&l, l.generation, 1)); assert(!fl_release(&l, 0));
	assert(!fl_final(&l, 456, l.generation, &packets, &bytes));
	assert(fl_final(&l, 123, l.generation, &packets, &bytes));
	assert(packets == 1 && bytes == 1500);
	assert(!fl_final(&l, 123, l.generation, &packets, &bytes));
	stale = a; assert(fl_release(&l, 0));
	assert(!fl_bind(&l, 10, 456, &id)); assert(fl_bind(&l, 9, 456, &id));
	assert(fl_admit(&l, &id, 0, 80, &a)); assert(!fl_finish(&l, &stale, 1));
	assert(fl_commit(&l, &a, &id)); assert(fl_finish(&l, &a, 1));
	freeze(&l); assert(fl_final(&l, 456, l.generation, &packets, &bytes));
	assert(packets == 1 && bytes == 80); assert(fl_release(&l, 0));
	/* Randomized publication/cancel/completion order and bounded queue reuse. */
	for (unsigned int round = 0; round < 2000; round++) {
		uint64_t expected_packets = 0, expected_bytes = 0;
		uint32_t lengths[FL_PENDING], published[FL_PENDING];
		assert(fl_bind(&l, 9, 1000 + round, &id));
		for (unsigned int i = 0; i < FL_PENDING; i++) {
			lengths[i] = 14 + random32() % 2035; published[i] = random32() & 1;
			assert(fl_admit(&l, &id, i & 1, lengths[i], &tickets[i]));
			if (published[i]) assert(fl_commit(&l, &tickets[i], &id));
		}
		assert(!fl_admit(&l, &id, 0, 64, &a)); assert(fl_revoke(&l));
		for (unsigned int left = FL_PENDING; left; left--) {
			unsigned int i = random32() % left;
			int forwarded = published[i] && (random32() & 1);
			assert(fl_finish(&l, &tickets[i], forwarded));
			assert(!fl_finish(&l, &tickets[i], forwarded));
			if (forwarded) { expected_packets++; expected_bytes += lengths[i]; }
			tickets[i] = tickets[left - 1]; lengths[i] = lengths[left - 1];
			published[i] = published[left - 1];
		}
		assert(fl_ack(&l, l.generation, 0)); assert(fl_ack(&l, l.generation, 1));
		assert(fl_final(&l, 1000 + round, l.generation, &packets, &bytes));
		assert(packets == expected_packets && bytes == expected_bytes);
		assert(fl_release(&l, 0));
	}
	/* 64-bit overflow is explicit failure, not a wrapped valid statistic. */
	assert(fl_bind(&l, 9, 2, &id)); l.bytes = UINT64_MAX - 10;
	assert(fl_admit(&l, &id, 0, 64, &a)); assert(fl_commit(&l, &a, &id));
	assert(fl_finish(&l, &a, 1)); assert(l.stats_invalid); freeze(&l);
	assert(!fl_final(&l, 2, l.generation, &packets, &bytes));
	assert(!fl_release(&l, 0)); assert(fl_release(&l, 1));
	l.generation = UINT32_MAX; assert(!fl_bind(&l, 9, 3, &id));
	assert(l.state == FL_EXHAUSTED);
	memset(&l, 0, sizeof(l)); l.serial = UINT64_MAX;
	assert(!fl_bind(&l, 9, 3, &id)); assert(l.state == FL_EXHAUSTED);
	puts("PASS: serialized flow-lease model; 2000 randomized generations, 32000 tokens; no live ABI");
	return 0;
}
