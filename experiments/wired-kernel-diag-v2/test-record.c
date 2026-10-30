/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define BD_SLOTS 4
#define BD_ACTIONS 16
#define FLOW_RULE_CT_CONTEXT_VERSION 2
#define FLOW_RULE_CT_CONTEXT_NF_FLOWTABLE 1
#define NF_CT_DEFAULT_ZONE_ID 0
enum ip_conntrack_dir { IP_CT_DIR_ORIGINAL, IP_CT_DIR_REPLY };
enum flow_offload_tuple_dir { FLOW_OFFLOAD_DIR_ORIGINAL, FLOW_OFFLOAD_DIR_REPLY, FLOW_OFFLOAD_DIR_MAX };
struct net { unsigned int id; };
static struct net init_net = { 1 };
static bool net_eq(const struct net *a, const struct net *b) { return a == b; }
/* ACTUAL_DECLARATIONS */
struct nf_conn { const struct net *net; struct nf_conntrack_zone zone; };
struct flow_offload {
 struct { struct { unsigned int marker; } tuple; } tuplehash[2];
 struct nf_conn *ct;
 u64 diag_generation;
};
static const struct net *nf_ct_net(const struct nf_conn *ct) { return ct->net; }
static const struct nf_conntrack_zone *nf_ct_zone(const struct nf_conn *ct) { return &ct->zone; }
/* ACTUAL_FUNCTIONS */
#include "record.h"
/* ACTUAL_ADMISSION */
int main(void)
{
 unsigned int cases = 0;
 struct nf_conn ct = { .net = &init_net, .zone = { .id = 0, .flags = 0, .dir = 3 } };
 struct flow_offload flow = { .ct = &ct, .diag_generation = 10 };
 struct flow_rule_ct_context c = { 0 }, pair;
 struct bd_row rows[BD_SLOTS] = { 0 }, row = { 0 }, saved;
 struct net other = { 2 };
 struct bd_config cfg;
 const char *bad_arm[] = { "arm 0 2 0 1", "arm 1 1 0 1", "arm 1 2 5 1", "arm 1 2 -1 1",
  "arm 1 2 0 0", "arm 1 2 0 1 extra", "arm 1 2 0", "bind 1 2 0 1" };
 assert(!bd_parse_arm("arm 1 2 0 123", &cfg) && cfg.enabled && cfg.duration_ns == 5000000000ULL && cfg.generation == 123); cases++;
 for (unsigned int i = 0; i < sizeof(bad_arm)/sizeof(bad_arm[0]); i++) {
  assert(bd_parse_arm(bad_arm[i], &cfg) == -EINVAL && !cfg.enabled); cases++;
 }
 _Static_assert(sizeof(struct flow_rule_ct_context) == 56, "actual context ABI");
 for (unsigned int d = 0; d < 2; d++) {
  assert(nf_flow_rule_set_ct_context(&c, &init_net, &flow, d));
  assert(c.direction == d && c.generation == 10 && bd_context(&c));
  assert(c.ct_cookie == (unsigned long)&ct && c.flow_cookie == (unsigned long)&flow);
  assert(c.tuple_cookie[d] == (unsigned long)&flow.tuplehash[d].tuple);
  assert(c.tuple_cookie[!d] == (unsigned long)&flow.tuplehash[!d].tuple);
  cases++;
 }
 memset(&c, 0xff, sizeof(c));
 assert(!nf_flow_rule_set_ct_context(&c, &other, &flow, 0));
 for (unsigned int i = 0; i < sizeof(c); i++) assert(!((u8 *)&c)[i]);
 cases++;
 assert(!nf_flow_rule_set_ct_context(&c, &init_net, &flow, 2)); cases++;
 flow.diag_generation = 0;
 assert(!nf_flow_rule_set_ct_context(&c, &init_net, &flow, 0)); cases++;
 flow.diag_generation = 10;
 ct.net = &other;
 assert(nf_flow_rule_set_ct_context(&c, &other, &flow, 0) && !bd_context(&c)); cases++;
 ct.net = &init_net;
 ct.zone.id = 42;
 assert(nf_flow_rule_set_ct_context(&c, &init_net, &flow, 0) && c.zone_raw_id == 42 && !bd_context(&c)); cases++;
 ct.zone.id = 0;
 assert(nf_flow_rule_set_ct_context(&c, &init_net, &flow, 0));
 row.context = c; row.used = true; row.direction = 0; row.action_count = 2;
 row.key[0] = 1; row.key[1] = 2; row.key[2] = 3;
 row.actions[0].value = 123; row.actions[1].mask = 456; row.observed_ns = 99;
 assert(bd_record_replace(rows, &row) == 1); saved = rows[0]; cases++;
 row.actions[0].value = 999;
 assert(rows[0].actions[0].value == 123 && bd_record_replace(rows, &row) == -EEXIST && rows[0].revoked && !rows[0].used); cases++;
 row = saved;
 assert(bd_record_replace(rows, &row) == -ESTALE); cases++;
 memset(rows, 0, sizeof(rows));
 assert(bd_record_replace(rows, &row) == 1);
 row = saved; row.observed_ns++;
 assert(bd_record_replace(rows, &row) == 0 && rows[0].observed_ns == 99); cases++;
 row.context.ct_cookie++;
 assert(bd_record_replace(rows, &row) == -EEXIST); cases++;
 memset(rows, 0, sizeof(rows)); row = saved;
 assert(bd_record_replace(rows, &row) == 1);
 row = saved; row.context.generation--;
 assert(bd_record_replace(rows, &row) == -ESTALE); cases++;
 row = saved; row.context.generation++;
 assert(bd_record_replace(rows, &row) == 2); cases++;
 assert(!bd_record_destroy(rows, &saved.context, saved.context.tuple_cookie[0])); cases++;
 assert(rows[0].used && rows[0].context.generation == 11); cases++;
 assert(!bd_record_destroy(rows, &row.context, 0)); cases++;
 assert(bd_record_destroy(rows, &row.context, row.context.tuple_cookie[0]) == 1 && !rows[0].used); cases++;
 assert(!bd_record_destroy(rows, &row.context, row.context.tuple_cookie[0])); cases++;
 assert(bd_record_replace(rows, &row) == -ESTALE); cases++;
 memset(rows, 0, sizeof(rows));
 row = saved;
 assert(bd_record_replace(rows, &row) == 1);
 assert(nf_flow_rule_set_ct_context(&pair, &init_net, &flow, 1));
 row.context = pair; row.direction = 1; row.key[0] = 2; row.key[1] = 1;
 assert(bd_record_replace(rows, &row) == 1); cases++;
 assert(bd_record_destroy(rows, &c, c.tuple_cookie[0]) == 1 && rows[1].used); cases++;
 assert(bd_record_destroy(rows, &pair, pair.tuple_cookie[1]) == 1); cases++;
 for (unsigned int i = 0; i < 7; i++) {
  row = saved;
  switch (i) {
   case 0: row.context.valid = 0; break;
   case 1: row.context.version = 1; break;
   case 2: row.context.generation = 0; break;
   case 3: row.context.ct_cookie = 0; break;
   case 4: row.context.flow_cookie = 0; break;
   case 5: row.context.tuple_cookie[0] = 0; break;
   case 6: row.context.direction = 2; break;
  }
  assert(bd_record_replace(rows, &row) == -EINVAL);
  assert(!bd_record_destroy(rows, &row.context, 0)); cases++;
 }
 memset(rows, 0, sizeof(rows));
 for (unsigned int i = 0; i < BD_SLOTS; i++) {
  row = saved; row.key[0] = i + 1;
  assert(bd_record_replace(rows, &row) == 1); cases++;
 }
 row.key[0] = 12345;
 assert(bd_record_replace(rows, &row) == -ENOSPC); cases++;
 {
  struct bd_egress e = { .ct_cookie = c.ct_cookie, .direction = 0,
   .logical_output_ifindex = 7, .actual_ifindex = 88, .was_gso = true,
   .summed_before = 3, .summed_after = 0, .frame_bytes = 2048,
   .key = { 30, 20, (5555U << 16) | 443 } };
  memset(rows, 0, sizeof(rows));
  row = saved; row.output_ifindex = 7;
  row.key[0] = 10; row.key[1] = 20; row.key[2] = (1234U << 16) | 443;
  assert(bd_record_replace(rows, &row) == 1);
  row.context = pair; row.direction = 1; row.output_ifindex = 8;
  row.key[0] = 20; row.key[1] = 30; row.key[2] = (443U << 16) | 5555;
  assert(bd_record_replace(rows, &row) == 1);
  assert(bd_record_egress(rows, &e) && rows[0].egress.was_gso && !rows[0].egress.format_complete); cases++;
  e.key[0] = 999;
  assert(rows[0].egress.key[0] == 30 && !bd_record_egress(rows, &e)); cases++;
  e.key[0] = 30; e.ct_cookie++;
  assert(!bd_record_egress(rows, &e)); cases++;
  e.ct_cookie--; e.logical_output_ifindex++;
  assert(!bd_record_egress(rows, &e)); cases++;
  e.logical_output_ifindex--; e.key[2]++;
  assert(!bd_record_egress(rows, &e)); cases++;
  e.key[2]--; e.direction = 2;
  assert(!bd_record_egress(rows, &e)); cases++;
  e.direction = 0; e.delivered = true;
  assert(!bd_record_egress(rows, &e)); cases++;
  e.delivered = false; rows[1].used = false;
  assert(!bd_record_egress(rows, &e)); cases++;
  rows[1].used = true; rows[1].context.generation++;
  assert(!bd_record_egress(rows, &e)); cases++;
  rows[1].context.generation--; rows[1].context.flow_cookie++;
  assert(!bd_record_egress(rows, &e)); cases++;
  rows[1].context.flow_cookie--; e.direction = 1; e.logical_output_ifindex = 8;
  e.key[0] = 20; e.key[1] = 10; e.key[2] = (443U << 16) | 1234;
  e.was_gso = false; e.format_complete = true;
  assert(bd_record_egress(rows, &e) && rows[1].egress.format_complete && !rows[1].egress.delivered); cases++;
  row = rows[0]; row.context.generation++;
  assert(bd_record_replace(rows, &row) == 2 && !rows[1].used && rows[1].revoked && !rows[0].egress.frame_bytes); cases++;
  assert(!bd_record_egress(rows, &e)); cases++;
  assert(!bd_record_destroy(rows, &c, c.tuple_cookie[0]) && rows[0].used); cases++;
 }
 puts("N1_ACTUAL_RECORD_AND_PRODUCER_PASS");
 printf("{\"cases\":%u,\"context_bytes\":%zu,\"can_publish\":false}\n", cases, sizeof(c));
 return 0;
}
