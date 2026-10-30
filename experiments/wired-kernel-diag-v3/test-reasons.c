/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint64_t u64;
typedef uint32_t u32;
#include "reasons.h"
int main(void)
{
 struct bd_reasons state = {0}, before;
 unsigned int i;
 for (i = 0; i < BD_REASON_COUNT; i++)
  assert(state.count[i] == 0);
 for (i = 0; i < BD_REASON_COUNT; i++) {
  assert(bd_reason_add(&state, i));
  assert(state.count[i] == 1 && state.last == i);
 }
 memcpy(&before, &state, sizeof(state));
 assert(!bd_reason_add(&state, BD_REASON_COUNT));
 assert(!memcmp(&before, &state, sizeof(state)));
 assert(!bd_reason_add(&state, UINT32_MAX));
 assert(!memcmp(&before, &state, sizeof(state)));
 state.count[BD_REASON_TX_NO_CT] = UINT64_MAX;
 assert(bd_reason_add(&state, BD_REASON_TX_NO_CT));
 assert(state.count[BD_REASON_TX_NO_CT] == UINT64_MAX);
 assert(state.last == BD_REASON_TX_NO_CT);
 printf("{\"counter_cases\":%u,\"actual_header\":true}\n", BD_REASON_COUNT + 4);
 return 0;
}
