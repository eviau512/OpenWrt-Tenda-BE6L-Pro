/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
static inline void barrier(void) { __asm__ volatile("" ::: "memory"); }
#include "routed-selftest.h"
int main(void)
{
	volatile uint32_t result[8] = {0};
	for (uint32_t core = 0; core < 2; core++) {
		routed_selftest_run(core, result);
		assert(result[0] == RF_SELFTEST_MAGIC && result[2] == 32);
		assert(result[3] == 1 && result[4] == 0 && result[6] == core && result[7] == 1);
	}
	puts("PASS: golden routed-frame selftest, 32 checks per core, no live routing");
	return 0;
}
