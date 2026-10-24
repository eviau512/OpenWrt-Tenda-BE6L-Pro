/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
static inline void barrier(void) { __asm__ volatile("" ::: "memory"); }
#include "flow-worker.h"
#include "flow-actions.h"
static uint32_t sequence;
static uint32_t transact(uint32_t core, const uint32_t *input)
{
	volatile uint32_t *p = fa_page(core), *q = p + FA_COMMAND / 4, *a = p + FA_RESPONSE / 4;
	q[0] = sequence | 1;
	for (uint32_t i = 1; i < FA_WORDS; i++) q[i] = input[i];
	barrier(); q[0] = sequence;
	fa_service(core);
	assert(a[0] == sequence && a[2] == core && a[11] == 1);
	return a[1];
}
static void both(uint32_t *w, uint32_t op, uint32_t expected)
{
	sequence += 2; w[1] = op;
	assert(transact(0, w) == expected); assert(transact(1, w) == expected);
}
int main(void)
{
	void *map = mmap((void *)(uintptr_t)FA_NPU, FA_BYTES, PROT_READ|PROT_WRITE,
		MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
	assert(map == (void *)(uintptr_t)FA_NPU);
	fa_worker_boot(0); fa_worker_boot(1);
	uint32_t w[FA_WORDS] = {0};
	w[2] = 0; w[4] = 123; w[5] = 0x89abcdef; w[6] = 0x12345; w[7] = 0x6789a;
	for (uint32_t fixture = 0; fixture < 5; fixture++) {
		w[3] = fixture + 1; w[4]++;
		for (uint32_t i = 0; i < 32; i++) w[8+i] = fa_actions[fixture][i];
		both(w, FA_COMMIT, FA_GENERATION);
		both(w, FA_PREPARE, FA_OK);
		both(w, FA_SIMULATE, FA_STATE);
		both(w, FA_COMMIT, FA_OK);
		both(w, FA_SIMULATE, FA_STATE);
		*fa_gate(0) = w[3];
		for (uint32_t field = 8; field <= 12; field++) {
			w[field]++; both(w, FA_SIMULATE, FA_MISMATCH); w[field]--;
		}
		for (uint32_t i = 0; i < 8; i++) both(w, FA_SIMULATE, FA_OK);
		for (uint32_t core = 0; core < 2; core++) {
			volatile uint32_t *a = fa_page(core) + FA_RESPONSE / 4;
			assert(fa_u64(a[12],a[13]) == 8 && fa_u64(a[14],a[15]) == 8*fa_lengths[fixture]);
		}
		both(w, FA_REVOKE, FA_STATE);
		*fa_gate(0) = 0;
		both(w, FA_REVOKE, FA_OK); both(w, FA_SIMULATE, FA_STATE);
		both(w, FA_FENCE, FA_OK); both(w, FA_SIMULATE, FA_STATE);
		both(w, FA_RELEASE, FA_OK); both(w, FA_PREPARE, FA_GENERATION);
	}
	/* Invalid reserved fields, slot bounds, mismatched session and old seq. */
	w[3]++; w[40]=1; both(w, FA_PREPARE, FA_INVALID); w[40]=0;
	w[2]=FA_SLOTS; both(w, FA_PREPARE, FA_INVALID); w[2]=0;
	w[6]++; both(w, FA_PREPARE, FA_SESSION); w[6]--;
	sequence -= 2; w[1]=FA_PREPARE;
	assert(transact(0,w)==FA_REPLAY && transact(1,w)==FA_REPLAY); sequence+=2;
	/* Odd publication is never acknowledged or executed. */
	for (uint32_t core=0;core<2;core++) {
		volatile uint32_t *p=fa_page(core), *q=p+FA_COMMAND/4, *a=p+FA_RESPONSE/4;
		uint32_t old=a[0];q[0]=sequence+1;fa_service(core);assert(a[0]==old);
	}
	fa_worker_stop(0);fa_worker_stop(1);
	assert(!fa_page(0)[3] && !fa_page(1)[3]);
	assert(munmap(map,FA_BYTES)==0);
	puts("PASS: two-worker software control ABI, five action vectors, dual ACK/gate, domain rejection, revoke/freeze/reuse/replay; no live DMA");
	return 0;
}
