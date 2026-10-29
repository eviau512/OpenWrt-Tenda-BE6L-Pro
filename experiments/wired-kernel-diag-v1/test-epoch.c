/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint64_t u64;
#include "epoch.h"
struct ownership { struct bd_epoch epoch; unsigned int held[3], put[3]; };
static void open(struct ownership *o, u64 now, u64 duration)
{
	assert(bd_epoch_open(&o->epoch, 1, now, duration));
	for (unsigned int i = 0; i < 3; i++) o->held[i]++;
}
static void revoke(struct ownership *o)
{
	if (bd_epoch_close(&o->epoch))
		for (unsigned int i = 0; i < 3; i++) {
			assert(o->held[i] == 1); o->held[i]--; o->put[i]++;
		}
}
int main(void)
{
	unsigned int tests = 0;
	struct bd_epoch e = {};
	assert(!bd_epoch_open(&e, 0, 10, 1)); tests++;
	assert(!bd_epoch_open(&e, 1, 10, 0)); tests++;
	assert(!bd_epoch_open(&e, 1, 10, BD_MAX_NS + 1)); tests++;
	assert(!bd_epoch_open(&e, 1, ~(u64)0, 1)); tests++;
	assert(bd_epoch_open(&e, 1, 100, BD_MAX_NS)); tests++;
	assert(!bd_epoch_live(&e, 99)); tests++;
	assert(bd_epoch_live(&e, 100)); tests++;
	assert(bd_epoch_live(&e, e.deadline - 1)); tests++;
	assert(!bd_epoch_live(&e, e.deadline)); tests++;
	assert(!bd_epoch_open(&e, 2, 100, 1)); tests++;
	assert(bd_epoch_close(&e)); tests++;
	assert(!bd_epoch_close(&e)); tests++;
	assert(!bd_epoch_open(&e, 2, e.deadline, 1)); tests++;
	assert(!bd_epoch_live(&e, 100)); tests++;
	/* All permutations of expiry/notifier/destroy win the same single detach.
	 * These are serialized lock interleavings, not real kernel ref/race tests. */
	unsigned int orders[][3] = {{0,1,2},{0,2,1},{1,0,2},{1,2,0},{2,0,1},{2,1,0}};
	for (unsigned int i = 0; i < 6; i++) {
		struct ownership o = {};
		open(&o, 100, 500);
		for (unsigned int j = 0; j < 3; j++) { (void)orders[i][j]; revoke(&o); }
		for (unsigned int j = 0; j < 3; j++) assert(!o.held[j] && o.put[j] == 1);
		assert(!bd_epoch_open(&o.epoch, 2, 1000, 1)); tests++;
	}
	printf("{\"passed\":true,\"cases\":%u,\"can_publish\":false,\"real_kernel_refs_executed\":false}\n", tests);
}
