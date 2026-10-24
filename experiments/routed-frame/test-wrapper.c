/* SPDX-License-Identifier: MIT */
#include "routed-frame.h"
int test_apply(volatile uint8_t *frame, size_t length, const struct rf_action *action,
	       const struct rf_identity *identity)
{
	return routed_frame_apply(frame, length, action, identity);
}
