/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "decode.h"
/* ACTUAL_CONTEXT_PREDICATE */
static bool zero(const void *data, size_t length)
{
 const unsigned char *p=data;
 while (length--) if (*p++) return false;
 return true;
}
int main(void)
{
 struct flow_diag_packet packet={.magic=FLOW_DIAG_PACKET_MAGIC,.version=1,
  .lease_generation=123,.deadline_ns=1000,.ingress_ifindex=5,.output_ifindex=3};
 struct flow_rule_ct_context context={.valid=1,.version=2,.producer=1,
  .zone_dir=3,.initial_netns=1,.generation=9,.ct_cookie=0xffff000000001111ULL,
  .flow_cookie=0xffff000000002222ULL,.tuple_cookie={0xffff000000003333ULL,0xffff000000004444ULL}};
 struct flow_rule_ct_context output, changed;
 struct flow_diag_packet bad;
 unsigned int checks=0;
 memcpy(packet.context_words,&context,sizeof(context));
 assert(flow_diag_packet_decode(&packet,123,1000,999,5,3,3,bd_context,&output));
 assert(!memcmp(&output,&context,sizeof(context)));checks++;
 for (unsigned int i=0;i<11;i++) {
  bad=packet;
  switch(i) {
   case 0:bad.magic++;break;
   case 1:bad.version++;break;
   case 2:bad.reserved=1;break;
   case 3:bad.lease_generation=0;break;
   case 4:bad.lease_generation++;break;
   case 5:bad.deadline_ns++;break;
   case 6:bad.ingress_ifindex=0;break;
   case 7:bad.ingress_ifindex=3;break;
   case 8:bad.output_ifindex=0;break;
   case 9:bad.output_ifindex=5;break;
   case 10:bad.ingress_ifindex=6;break;
  }
  memset(&output,0xff,sizeof(output));
  assert(!flow_diag_packet_decode(&bad,123,1000,999,5,3,3,bd_context,&output));
  assert(zero(&output,sizeof(output)));checks++;
 }
 for(unsigned int i=0;i<16;i++) {
  bad=packet;changed=context;
  switch(i) {
   case 0:changed.valid=0;break;
   case 1:changed.version=1;break;
   case 2:changed.producer=0;break;
   case 3:changed.zone_id=1;break;
   case 4:changed.zone_raw_id=1;break;
   case 5:changed.zone_dir=1;break;
   case 6:changed.zone_flags=1;break;
   case 7:changed.direction=2;break;
   case 8:changed.initial_netns=0;break;
   case 9:changed.reserved=1;break;
   case 10:changed.generation=0;break;
   case 11:changed.ct_cookie=0;break;
   case 12:changed.flow_cookie=0;break;
   case 13:changed.tuple_cookie[0]=0;break;
   case 14:changed.tuple_cookie[1]=0;break;
   case 15:changed.tuple_cookie[1]=changed.tuple_cookie[0];break;
  }
  memcpy(bad.context_words,&changed,sizeof(changed));
  memset(&output,0xff,sizeof(output));
  assert(!flow_diag_packet_decode(&bad,123,1000,999,5,3,3,bd_context,&output));
  assert(zero(&output,sizeof(output)));checks++;
 }
 assert(!flow_diag_packet_decode(&packet,123,1000,1000,5,3,3,bd_context,&output));checks++;
 assert(!flow_diag_packet_decode(&packet,123,1000,999,5,3,5,bd_context,&output));checks++;
 assert(!flow_diag_packet_decode(&packet,123,1000,999,5,5,3,bd_context,&output));checks++;
 assert(!flow_diag_packet_decode(&packet,0,1000,999,5,3,3,bd_context,&output));checks++;
 assert(!flow_diag_packet_decode(&packet,123,1000,999,5,3,3,NULL,&output));checks++;
 assert(!flow_diag_packet_decode(NULL,123,1000,999,5,3,3,bd_context,&output));checks++;
 assert(!flow_diag_packet_decode(&packet,123,1000,999,5,3,3,bd_context,NULL));checks++;
 context.direction=1;packet.ingress_ifindex=3;packet.output_ifindex=5;
 memcpy(packet.context_words,&context,sizeof(context));
 assert(flow_diag_packet_decode(&packet,123,1000,999,5,3,5,bd_context,&output));
 assert(!memcmp(&output,&context,sizeof(context)));checks++;
 printf("{\"decode_checks\":%u,\"actual_existing_context_predicate\":true,\"authority_to_publish\":false}\n",checks);
 return 0;
}
