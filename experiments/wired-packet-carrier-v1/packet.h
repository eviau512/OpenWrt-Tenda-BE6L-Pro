/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FLOW_DIAG_PACKET_H
#define FLOW_DIAG_PACKET_H
#include <linux/types.h>
#define FLOW_DIAG_PACKET_MAGIC 0x4e314450
#define FLOW_DIAG_PACKET_VERSION 1
/* Scalar diagnostic data, not packet admission or an owned CT reference.
 * Context words are a byte copy of the version2,56-byte producer context.
 * Consumers must memcpy into the typed context and validate all identities.
 */
struct flow_diag_packet {
 u32 magic;
 u16 version;
 u16 reserved;
 u64 lease_generation, deadline_ns;
 s32 ingress_ifindex, output_ifindex;
 u64 context_words[7];
};
int flow_offload_diag_lease_begin(u64 generation, u64 deadline_ns, int lan, int wan);
void flow_offload_diag_lease_end(u64 generation, u64 deadline_ns);
bool flow_offload_diag_lease_packet(struct flow_diag_packet *, int ingress, int output);
#endif
