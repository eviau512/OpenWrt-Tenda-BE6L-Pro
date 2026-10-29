/* SPDX-License-Identifier: MIT */
#include "shim.h"
#include "preview.h"
#include "preview.c"

static struct preview_device conduit, lan3, lan2, alias_lan3, wan;
static struct preview_lease lease;
static unsigned int cases;

static unsigned int references(void)
{ return conduit.references + lan3.references + lan2.references + alias_lan3.references + wan.references; }
static void reset(void)
{
 revoke_lease(&lease);
 assert(!references());
 memset(&lease, 0, sizeof(lease));
 conduit = (struct preview_device){.ifindex=100, .incarnation=1, .initial_netns=1,
                                    .role=DEVICE_CONDUIT, .registered=true, .dsa_index=-1};
 lan3 = (struct preview_device){.ifindex=103, .incarnation=1, .initial_netns=1,
     .role=DEVICE_LAN, .dsa_index=2, .logical_port=3, .pse_port=1, .registered=true, .conduit=&conduit};
 lan2 = lan3; lan2.ifindex=102; lan2.logical_port=2; lan2.dsa_index=1;
 alias_lan3 = lan3; /* Same role, index and ifindex; a different object is still excluded. */
 wan = (struct preview_device){.ifindex=104, .incarnation=1, .initial_netns=1,
     .role=DEVICE_WAN, .dsa_index=-1, .pse_port=2, .registered=true};
 assert(!open_lease(&lease, &lan3, &wan, 7, 100, 200));
 assert(references() == 3);
}
static struct preview_request request(unsigned int direction, unsigned int nat_flags)
{
 struct preview_request r = {0};
 struct flow_offload_tuple *a = &r.flow.tuplehash[0].tuple;
 struct flow_offload_tuple *b = &r.flow.tuplehash[1].tuple;
 r.input = direction ? &wan : &lan3; r.output = direction ? &lan3 : &wan;
 r.input_incarnation = r.output_incarnation = 1; r.generation = 7;
 r.ingress_ifindex=r.input->ifindex; r.addr_type=4;
 r.ethernet_protocol=0x0800; r.ip_protocol=IPPROTO_TCP;
 r.context = (struct flow_rule_ct_context){.version=1,.producer=1,.valid=1,
                                        .zone_dir=3,.direction=direction,.initial_netns=1};
 r.masks = (struct preview_masks){.ingress_ifindex=UINT32_MAX,.ipv4_src=UINT32_MAX,
  .ipv4_dst=UINT32_MAX,.source_port=UINT16_MAX,.dest_port=UINT16_MAX,
  .ethernet_protocol=UINT16_MAX,.ip_protocol=UINT8_MAX,.has_meta=true,
  .has_control=true,.has_ipv4=true,.has_ports=true,.has_basic=true};
 *a = (struct flow_offload_tuple){.src_v4={htonl(0xc000020a)},.dst_v4={htonl(0xc6336414)},
                                  .src_port=htons(14174),.dst_port=htons(5201),.l4proto=IPPROTO_TCP};
 *b = (struct flow_offload_tuple){.src_v4=a->dst_v4,.dst_v4=a->src_v4,
                                  .src_port=a->dst_port,.dst_port=a->src_port,.l4proto=IPPROTO_TCP};
 if (nat_flags & 1) { b->dst_v4.s_addr=htonl(0xcb00711e); b->dst_port=htons(44053); }
 if (nat_flags & 2) { b->src_v4.s_addr=htonl(0xcb007128); b->src_port=htons(8443); }
 r.nat_flags = nat_flags;
 const u8 dmac[6]={0x00,0x11,0x22,0x33,0x44,0x55}, smac[6]={0x02,0xaa,0xbb,0xcc,0xdd,0xee};
 memcpy(r.dest_mac,dmac,6); memcpy(r.source_mac,smac,6);
 const struct flow_offload_tuple *in = &r.flow.tuplehash[direction].tuple;
 for (unsigned int i=0;i<20;i++) r.observed_unbound[i]=0xa5a50000U+i;
 r.observed_unbound[0]=0x10000093U;
 r.observed_unbound[1]=ntohl(in->src_v4.s_addr); r.observed_unbound[2]=ntohl(in->dst_v4.s_addr);
 r.observed_unbound[3]=(u32)ntohs(in->src_port)<<16 | ntohs(in->dst_port);
 return r;
}
static struct preview_plan attempt(struct preview_request *r, uint64_t now, int expected)
{
 struct preview_request before=*r;
 struct preview_plan plan;
 memset(&plan,0xff,sizeof(plan));
 int result=preview_request(&lease,r,now,&plan);
 assert(result==expected);
 assert(!memcmp(&before,r,sizeof(before)));
 assert(!plan.can_publish && plan.unresolved==PREVIEW_UNRESOLVED_ALL);
 if (result) for (unsigned int i=0;i<20;i++) assert(!plan.mask[i] && !plan.value[i]);
 cases++;
 return plan;
}
static void validate_plan(const struct preview_request *r, const struct preview_plan *p)
{
 const struct flow_offload_tuple *opposite=&r->flow.tuplehash[!r->context.direction].tuple;
 assert(!memcmp(p->observed_unbound,r->observed_unbound,sizeof(p->observed_unbound)));
 assert(p->generation==7 && p->deadline==200 && p->observed_unbound[0]==0x10000093U);
 assert(!p->mask[0] && !p->value[0]); /* Never propose BIND or neutral IB1. */
 for (unsigned int i=0;i<20;i++) {
  bool known=i==4 || (i>=5 && i<=7) || (i>=12 && i<=15);
  if (!known) assert(!p->mask[i] && !p->value[i]);
 }
 assert(p->value[5]==ntohl(opposite->dst_v4.s_addr));
 assert(p->value[6]==ntohl(opposite->src_v4.s_addr));
 assert(p->value[7]==((u32)ntohs(opposite->dst_port)<<16 | ntohs(opposite->src_port)));
 assert(p->mask[4]==0x1e0U && p->value[4]==r->output->pse_port<<5);
 assert(p->value[12]==0x00112233 && p->value[13]==0x44550000U);
 assert(p->value[14]==0x02aabbcc && p->value[15]==0xddee0000U);
 assert(p->mask[13]==0xffff0000U && p->mask[15]==0xffff0000U);
}
int main(void)
{
 _Static_assert(sizeof(struct airoha_foe_entry)==80,"actual entry type changed");
 _Static_assert(offsetof(struct airoha_foe_entry,ipv4.new_tuple)==0x14,"actual tuple moved");
 _Static_assert(offsetof(struct airoha_foe_entry,ipv4.l2.common.dest_mac_hi)==0x30,"DMAC moved");
 _Static_assert(offsetof(struct airoha_foe_entry,ipv4.l2.src_mac_lo)==0x3e,"SMAC moved");
 struct preview_request r;
 struct preview_plan p, sample;
 for (unsigned int flags=0;flags<=3;flags++) for (unsigned int direction=0;direction<=1;direction++) {
  reset(); r=request(direction,flags); p=attempt(&r,101,0); validate_plan(&r,&p);
  assert(references()==5); attempt(&r,102,0); assert(references()==5); /* Idempotent duplicate. */
  if (flags==1 && !direction) sample=p;
 }
 reset(); r=request(0,1); attempt(&r,101,0);
 r.dest_mac[5]^=1; attempt(&r,102,-EEXIST); assert(references()==5);
 r=request(0,1); r.flow.tuplehash[1].tuple.dst_port=htons(44054); attempt(&r,102,-EEXIST);
 assert(references()==5);
 reset(); r=request(0,1); r.input=&lan2; attempt(&r,101,-EOPNOTSUPP);
 r.input=&alias_lan3; attempt(&r,101,-EOPNOTSUPP); assert(references()==3);
 r=request(1,1); r.output=&lan2; attempt(&r,101,-EOPNOTSUPP);
 r.output=&alias_lan3; attempt(&r,101,-EOPNOTSUPP); assert(references()==3);
 for (unsigned int i=0;i<sizeof(r.context);i++) {
  reset(); r=request(0,1); ((u8 *)&r.context)[i]^=0x80; attempt(&r,101,-EOPNOTSUPP); assert(references()==3);
 }
 reset(); r=request(0,1); r.context.direction=1; attempt(&r,101,-EOPNOTSUPP);
 r=request(0,1); r.generation=6; attempt(&r,101,-EOPNOTSUPP);
 r.generation=8; attempt(&r,101,-EOPNOTSUPP);
 r=request(0,1); r.input_incarnation=2; attempt(&r,101,-EOPNOTSUPP);
 r=request(0,1); r.output_incarnation=2; attempt(&r,101,-EOPNOTSUPP);
 r=request(0,1); r.ingress_ifindex=102; attempt(&r,101,-EOPNOTSUPP);
 r=request(0,1); r.addr_type=6; attempt(&r,101,-EOPNOTSUPP);
 r=request(0,1); r.ethernet_protocol=0x86dd; attempt(&r,101,-EOPNOTSUPP);
 r=request(0,1); r.ip_protocol=IPPROTO_UDP; attempt(&r,101,-EOPNOTSUPP);
#define BAD_MASK(member,value) do { r=request(0,1); r.masks.member=(value); attempt(&r,101,-EOPNOTSUPP); } while (0)
 BAD_MASK(ingress_ifindex,0xfffffffeU); BAD_MASK(ingress_iftype,1); BAD_MASK(l2_miss,1);
 BAD_MASK(ipv4_src,0xfffffffeU); BAD_MASK(ipv4_dst,0xfffffffeU);
 BAD_MASK(source_port,0xfffe); BAD_MASK(dest_port,0xfffe);
 BAD_MASK(ethernet_protocol,0xfffe); BAD_MASK(ip_protocol,0xfe);
 BAD_MASK(has_meta,false); BAD_MASK(has_control,false); BAD_MASK(has_ipv4,false);
 BAD_MASK(has_ports,false); BAD_MASK(has_basic,false); BAD_MASK(extra_keys,true);
 assert(references()==3);
 for (unsigned int i=0;i<4;i++) {
  r=request(0,1); r.observed_unbound[i]^=1U<<(i?0:28); attempt(&r,101,-ESTALE);
 }
 r=request(0,1); r.observed_unbound[0]|=0x40000000U; attempt(&r,101,-ESTALE);
 r=request(0,1); r.flow.tuplehash[1].tuple.l4proto=IPPROTO_UDP; attempt(&r,101,-EOPNOTSUPP);
 r=request(0,1); r.nat_flags=4; attempt(&r,101,-EOPNOTSUPP);
 r=request(0,1); r.source_mac[0]=1; attempt(&r,101,-EOPNOTSUPP);
 r=request(0,1); memset(r.dest_mac,0,6); attempt(&r,101,-EOPNOTSUPP);
 r=request(0,1); r.nat_flags=0; attempt(&r,101,-EINVAL); assert(references()==3);
 reset(); r=request(0,1); attempt(&r,101,0); revoke_lease(&lease); revoke_lease(&lease);
 assert(!references()); attempt(&r,102,-ESTALE);
 assert(open_lease(&lease,&lan3,&wan,7,102,202)==-EOPNOTSUPP); cases++;
 assert(!open_lease(&lease,&lan3,&wan,8,102,202)); attempt(&r,103,-EOPNOTSUPP);
 reset(); r=request(0,1); attempt(&r,199,0); attempt(&r,200,-ESTALE); assert(!references());
 reset(); r=request(0,1); attempt(&r,101,0); attempt(&r,99,-ESTALE); assert(!references());
#define LIFETIME_CHANGE(statement) do { reset(); r=request(0,1); attempt(&r,101,0); statement; attempt(&r,102,-ESTALE); assert(!references()); } while (0)
 LIFETIME_CHANGE(lan3.incarnation++); LIFETIME_CHANGE(wan.incarnation++);
 LIFETIME_CHANGE(conduit.incarnation++); LIFETIME_CHANGE(lan3.registered=false);
 LIFETIME_CHANGE(wan.initial_netns=0); LIFETIME_CHANGE(lan3.conduit=&lan2);
 LIFETIME_CHANGE(lan3.dsa_index=1); LIFETIME_CHANGE(wan.pse_port=3);
 LIFETIME_CHANGE(wan.vlan=true); LIFETIME_CHANGE(lan3.opaque_upper=true);
 LIFETIME_CHANGE(lan3.ifindex++);
 reset();
 for (unsigned int i=0;i<PREVIEW_SLOTS+1;i++) {
  r=request(0,1); r.flow.tuplehash[0].tuple.src_port=htons(15000+i);
  r.observed_unbound[3]=(u32)(15000+i)<<16 | 5201;
  attempt(&r,101,i<PREVIEW_SLOTS?0:-ENOSPC);
 }
 assert(references()==3+2*PREVIEW_SLOTS); revoke_lease(&lease); assert(!references());
 printf("{\"passed\":true,\"cases\":%u,\"can_publish\":false,\"live_device_references\":%u,",cases,references());
 printf("\"sample_generation\":%llu,\"sample_deadline\":%llu,\"unresolved_gate_bits\":%u,",
        (unsigned long long)sample.generation,(unsigned long long)sample.deadline,sample.unresolved);
 printf("\"sample_value\":["); for(unsigned int i=0;i<20;i++) printf("%s%u",i?",":"",sample.value[i]);
 printf("],\"sample_mask\":["); for(unsigned int i=0;i<20;i++) printf("%s%u",i?",":"",sample.mask[i]);
 printf("]}\n");
 return 0;
}
