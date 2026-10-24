/* SPDX-License-Identifier: MIT */
/* Experimental software-only control channel. No live routing hooks. */
#ifndef BE6L_FLOW_ABI_H
#define BE6L_FLOW_ABI_H
#ifdef __KERNEL__
#include <linux/types.h>
typedef u32 fa_u32;
#else
#include <stdint.h>
typedef uint32_t fa_u32;
#endif
#define FA_MAGIC 0x46414231U
#define FA_VERSION 1U
#define FA_HOST 0x84220000U
#define FA_NPU 0x44220000U
#define FA_BYTES 0x10000U
#define FA_CORE_STRIDE 0x8000U
#define FA_COMMAND 0x100U
#define FA_RESPONSE 0x200U
#define FA_GATES 0x400U
#define FA_TABLE 0x1000U
#define FA_SLOT_STRIDE 0x600U
#define FA_SLOTS 16U
#define FA_WORDS 64U
#define FA_ACK_WORDS 16U
#define FA_PREPARE 1U
#define FA_COMMIT 2U
#define FA_SIMULATE 3U
#define FA_REVOKE 4U
#define FA_FENCE 5U
#define FA_RELEASE 6U
#define FA_OK 0U
#define FA_INVALID 1U
#define FA_SESSION 2U
#define FA_GENERATION 3U
#define FA_STATE 4U
#define FA_BUSY 5U
#define FA_MISMATCH 6U
#define FA_REPLAY 7U
#define FA_FREE 0U
#define FA_PREPARED 1U
#define FA_READY 2U
#define FA_DRAINING 3U
#define FA_FROZEN 4U
#if FA_TABLE + FA_SLOTS * FA_SLOT_STRIDE > FA_CORE_STRIDE
#error "Experimental flow table exceeds its per-core reserved area"
#endif
#if FA_HOST < 0x84218100U || FA_HOST + FA_BYTES > 0x84240000U
#error "Experimental software ABI overlaps slot diagnostics or native rings"
#endif
/* Request words: seq, op, slot, generation, cookie[2], session[2],
 * identity[5], version/protocol/MTU, MAC[6], IP[16], port-pairs[2],
 * established, synthetic-vector-index, reserved[24]. Publish seq last.
 * Response: ack_seq, result, core, slot, generation, phase, cookie[2],
 * session[2], pending, synthetic_only=1, packets[2], bytes[2].
 * One host writer; wait for BOTH core ACKs before reuse. No sequence wrap.
 * A single aligned 32-bit shared gate activates only after both COMMIT ACKs.
 */
#endif
