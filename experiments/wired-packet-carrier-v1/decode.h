/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FLOW_DIAG_DECODE_H
#define FLOW_DIAG_DECODE_H
#include <linux/build_bug.h>
#include <linux/string.h>
#include <linux/flow_diag_packet.h>
#include <net/flow_offload.h>
/* Caller holds its observation lock, validates real netdev/DSA identity and
 * supplies its existing typed context predicate. Output is separate caller
 * storage. No pointer-cookie is dereferenced, CT ref taken or BIND authorized.
 */
static inline bool flow_diag_packet_decode(const struct flow_diag_packet *packet,
 u64 generation, u64 deadline_ns, u64 now_ns, int lan, int wan, int actual_output,
 bool (*context_valid)(const struct flow_rule_ct_context *),
 struct flow_rule_ct_context *output)
{
 struct flow_rule_ct_context copied;
 BUILD_BUG_ON(sizeof(copied) != sizeof(packet->context_words));
 if (!output)
  return false;
 memset(output, 0, sizeof(*output));
 if (!packet || !context_valid || !generation || lan <= 0 || wan <= 0 ||
     lan == wan || actual_output <= 0 || now_ns >= deadline_ns ||
     packet->magic != FLOW_DIAG_PACKET_MAGIC ||
     packet->version != FLOW_DIAG_PACKET_VERSION || packet->reserved ||
     packet->lease_generation != generation || packet->deadline_ns != deadline_ns)
  return false;
 memcpy(&copied, packet->context_words, sizeof(copied));
 if (copied.direction > 1 || !context_valid(&copied))
  return false;
 if (packet->ingress_ifindex != (copied.direction ? wan : lan) ||
     packet->output_ifindex != (copied.direction ? lan : wan) ||
     actual_output != packet->output_ifindex)
  return false;
 memcpy(output, &copied, sizeof(copied));
 return true;
}
#endif
