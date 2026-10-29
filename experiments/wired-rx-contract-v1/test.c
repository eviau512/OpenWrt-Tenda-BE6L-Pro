/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#define ETH_P_IP 0x0800
#define ETH_HLEN 14
#define CHECKSUM_NONE 0
#define CHECKSUM_UNNECESSARY 1
#define CHECKSUM_COMPLETE 2
#define CHECKSUM_PARTIAL 3
struct net_device { unsigned int mtu; int role; };
struct airoha_flow_table_entry {
 struct net_device *ingress_dev, *wired_egress_dev;
 bool wired_l4, wired_dead;
};
struct airoha_ppe { int unused; };
struct airoha_foe_entry { int unused; };
struct ethhdr { unsigned char destination[6], source[6]; uint16_t h_proto; };
struct sk_buff {
 _Alignas(8) unsigned char data[1600];
 struct ethhdr ethernet;
 unsigned int len, linear_len, inaccessible_after, copied_reads;
 int mac_offset, ip_summed;
 bool vlan, gso, ingress_match, tuple_match;
};
static bool skb_vlan_tag_present(struct sk_buff *s) { return s->vlan; }
static bool skb_is_gso(struct sk_buff *s) { return s->gso; }
static struct ethhdr *eth_hdr(struct sk_buff *s) { return &s->ethernet; }
static int skb_mac_offset(struct sk_buff *s) { return s->mac_offset; }
static void *skb_header_pointer(struct sk_buff *s, int offset, unsigned int n, void *buffer)
{
 if (offset < 0 || (unsigned int)offset > s->len || n > s->len - offset ||
     (s->inaccessible_after && (unsigned int)offset + n > s->inaccessible_after)) return NULL;
 if ((unsigned int)offset + n <= s->linear_len) return s->data + offset;
 memcpy(buffer, s->data + offset, n); s->copied_reads++; return buffer;
}
static int airoha_ppe_wired_role(struct airoha_ppe *p, struct net_device *d)
{ (void)p; return d->role; }
static bool airoha_ppe_bridge_ingress_match(struct airoha_flow_table_entry *e, struct sk_buff *s)
{ (void)e; return s->ingress_match; }
static bool airoha_ppe_foe_packet_match(struct airoha_ppe *p, struct airoha_foe_entry *h, struct sk_buff *s)
{ (void)p; (void)h; return s->tuple_match; }
/* Extracted actual producer remains GPL under its original source license. */
#include "real-packet-match.h"
#include "rx-extra.c"
#include "vectors.h"
int main(void)
{
 struct net_device input = {.mtu=1500,.role=1}, output = {.mtu=1500,.role=2};
 struct airoha_flow_table_entry entry = {.ingress_dev=&input,.wired_egress_dev=&output,.wired_l4=true};
 struct airoha_ppe ppe = {0}; struct airoha_foe_entry hwe = {0};
 unsigned int cases = 0, stricter_rejections = 0, nonlinear_passes = 0;
 for (unsigned int i = 0; i < sizeof(vectors)/sizeof(vectors[0]); i++) {
  const struct vector *v = &vectors[i];
  struct sk_buff skb = {.ethernet={.h_proto=htons(ETH_P_IP)}, .len=v->length,
    .linear_len=v->linear, .inaccessible_after=v->inaccessible, .mac_offset=-ETH_HLEN,
    .ip_summed=v->checksum_state,.gso=v->gso,.ingress_match=true,.tuple_match=true};
  memcpy(skb.data, v->packet, v->length);
  output.mtu = v->mtu;
  bool original = airoha_ppe_wired_l4_packet_match(&ppe, &entry, &hwe, &skb);
  bool candidate = rx_contract_v1(&ppe, &entry, &hwe, &skb);
  if (original != v->original || candidate != v->expected) {
   fprintf(stderr,"case %s original=%d candidate=%d expected=%d/%d\n",v->name,
     original,candidate,v->original,v->expected); return 1;
  }
  if (original && !candidate) stricter_rejections++;
  if (candidate && skb.copied_reads) nonlinear_passes++;
  cases++;
 }
 /* Retain the actual source's dependency on ingress and key proof. */
 for (unsigned int i = 0; i < 2; i++) {
  struct sk_buff skb = {.ethernet={.h_proto=htons(ETH_P_IP)},.len=vectors[0].length,
    .linear_len=1600,.mac_offset=-ETH_HLEN,.ip_summed=CHECKSUM_UNNECESSARY,
    .ingress_match=i != 0,.tuple_match=i != 1};
  memcpy(skb.data,vectors[0].packet,skb.len); output.mtu=1500;
  assert(!rx_contract_v1(&ppe,&entry,&hwe,&skb)); cases++;
 }
 assert(stricter_rejections >= 10 && nonlinear_passes >= 2);
 printf("{\"passed\":true,\"cases\":%u,\"additional_refusals\":%u,"
        "\"nonlinear_passes\":%u,\"hardware_access\":false,\"can_publish\":false}\n",
        cases,stricter_rejections,nonlinear_passes);
 return 0;
}
