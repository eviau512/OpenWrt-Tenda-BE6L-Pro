/* SPDX-License-Identifier: MIT */
/* Host API boundary shims; real source types/functions are separately extracted. */
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/ip.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#define __force
#define cpu_to_be16(x) htons(x)
#define cpu_to_be32(x) htonl(x)
#define be16_to_cpu(x) ntohs(x)
#define be32_to_cpu(x) ntohl(x)
#define FIELD_GET(mask, value) (((value) & (mask)) >> __builtin_ctz(mask))
#define AIROHA_FOE_IB1_BIND_PACKET_TYPE 0x0e000000U
#define PPE_PKT_TYPE_IPV4_HNAPT 0
#define PPE_PKT_TYPE_IPV4_ROUTE 1
#define PPE_PKT_TYPE_IPV4_DSLITE 3
#define fallthrough __attribute__((fallthrough))
static bool test_warning(bool condition) { assert(!condition); return condition; }
#define WARN_ON_ONCE(c) test_warning(c)
#define unlikely(x) __builtin_expect(!!(x), 0)
#include "real-types.h"
#include "real-context.h"
struct airoha_foe_entry {
 union { struct { u32 ib1; struct airoha_foe_ipv4 ipv4; }; u32 words[20]; };
};
struct airoha_flow_data {
 struct { __be32 src_addr, dst_addr; } v4;
 __be16 src_port, dst_port;
 struct { u8 h_dest[6], h_source[6]; } eth;
};
enum flow_action_mangle_base {
 FLOW_ACT_MANGLE_HDR_TYPE_ETH, FLOW_ACT_MANGLE_HDR_TYPE_IP4,
 FLOW_ACT_MANGLE_HDR_TYPE_TCP, FLOW_ACT_MANGLE_HDR_TYPE_UDP
};
#define FLOW_ACTION_MANGLE 1
struct flow_action_entry {
 unsigned int id;
 struct { enum flow_action_mangle_base htype; u32 offset, mask, val; } mangle;
};
#define NF_FLOW_RULE_ACTION_MAX 24
struct flow_rule { struct { unsigned int num_entries; struct flow_action_entry entries[24]; } action; };
struct nf_flow_rule { struct flow_rule *rule; };
struct net { int unused; };
enum flow_offload_tuple_dir { FLOW_OFFLOAD_DIR_ORIGINAL, FLOW_OFFLOAD_DIR_REPLY, FLOW_OFFLOAD_DIR_MAX };
struct flow_offload_tuple {
 struct in_addr src_v4, dst_v4;
 __be16 src_port, dst_port;
 u8 l4proto;
};
struct flow_offload { struct { struct flow_offload_tuple tuple; } tuplehash[2]; };
static u32 get_unaligned_be32(const void *p) { u32 v; memcpy(&v, p, sizeof(v)); return ntohl(v); }
static u16 get_unaligned_be16(const void *p) { u16 v; memcpy(&v, p, sizeof(v)); return ntohs(v); }
#include "real-helpers.h"
