#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#define READ_ONCE(x) (x)
#define NETREG_REGISTERED 1
#define AIROHA_GDM1_IDX 1
#define AIROHA_GDM2_IDX 2
#define PPE_PKT_TYPE_IPV4_HNAPT 0
#define FLOW_DISSECTOR_KEY_META 1
#define ETH_P_IP 0x0800
#define ETH_HLEN 14
struct net { int id; } init_net, foreign_net = {1};
struct airoha_gdm_port { int id; } lan_port = {1}, wan_port = {2};
struct airoha_gdm_dev { struct airoha_gdm_port *port; bool lan; };
static struct airoha_gdm_dev lan_gdm = {&lan_port, true}, wan_gdm = {&wan_port, false};
struct net_device {
 int ifindex, refs, reg_state, dsa; bool vlan;
 unsigned int mtu; struct net *net;
 struct net_device *conduit; struct airoha_gdm_dev *gdm;
};
static struct net_device lan, wan, conduit, upper;
struct soc { int version, num_ppe; } soc = {0x7563, 1};
struct airoha_eth { struct soc *soc; } eth = {&soc};
struct airoha_ppe { struct airoha_eth *eth; } ppe = {&eth};
struct airoha_flow_table_entry {
 struct net_device *ingress_dev, *wired_egress_dev, *wdma_dev;
 bool wired_l4, wired_dead; unsigned int unbinds;
};
#include "context.h"
struct meta { int ingress_ifindex; unsigned int ingress_iftype, l2_miss; };
struct flow_rule { struct flow_rule_ct_context ct_context; struct meta key, mask; bool has_meta; };
struct flow_match_meta { struct meta *key, *mask; };
static bool net_eq(struct net *a, struct net *b) { return a == b; }
static struct net *dev_net(struct net_device *d) { return d->net; }
static bool is_vlan_dev(struct net_device *d) { return d->vlan; }
static void *netdev_priv(struct net_device *d) { return d->gdm; }
static bool airoha_is_valid_gdm_dev(struct airoha_eth *e, struct airoha_gdm_dev *d)
{ return e == &eth && (d == &lan_gdm || d == &wan_gdm); }
static bool airoha_is_lan_gdm_dev(struct airoha_gdm_dev *d) { return d->lan; }
static bool airoha_is_7563(struct airoha_eth *e) { return e->soc->version == 0x7563; }
static int airoha_get_dsa_port(struct net_device **d)
{ int index = (*d)->dsa; if (index < 0) return -ENODEV; *d = (*d)->conduit; return index; }
static void dev_hold(struct net_device *d) { assert(d); d->refs++; }
static void dev_put(struct net_device *d) { if (d) { assert(d->refs > 0); d->refs--; } }
static struct net_device *dev_get_by_index(struct net *net, int index)
{
 struct net_device *all[] = {&lan, &wan, &upper}; unsigned int i;
 for (i = 0; i < 3; i++) if (all[i]->ifindex == index && all[i]->net == net) {
  dev_hold(all[i]); return all[i];
 }
 return NULL;
}
static bool flow_rule_match_key(struct flow_rule *r, int key)
{ return key == FLOW_DISSECTOR_KEY_META && r->has_meta; }
static void flow_rule_match_meta(struct flow_rule *r, struct flow_match_meta *m)
{ m->key = &r->key; m->mask = &r->mask; }
#include "helpers.c"
static void airoha_ppe_foe_unbind_flow(struct airoha_ppe *p, struct airoha_flow_table_entry *e)
{ assert(p == &ppe); e->unbinds++; }
#include "lifecycle.c"
struct ethhdr { u8 destination[6], source[6]; u16 h_proto; };
struct airoha_foe_entry { int unused; };
struct sk_buff {
 struct ethhdr ethernet; _Alignas(8) u8 data[1600]; unsigned int len;
 int mac_offset; bool vlan, ingress_match, tuple_match;
};
static bool skb_vlan_tag_present(struct sk_buff *s) { return s->vlan; }
static struct ethhdr *eth_hdr(struct sk_buff *s) { return &s->ethernet; }
static int skb_mac_offset(struct sk_buff *s) { return s->mac_offset; }
static void *skb_header_pointer(struct sk_buff *s, int o, unsigned int n, void *buffer)
{ (void)buffer; return o >= 0 && (unsigned int)o <= s->len && n <= s->len - o ? s->data + o : NULL; }
static bool airoha_ppe_bridge_ingress_match(struct airoha_flow_table_entry *e, struct sk_buff *s)
{ (void)e; return s->ingress_match; }
static bool airoha_ppe_foe_packet_match(struct airoha_ppe *p, struct airoha_foe_entry *h, struct sk_buff *s)
{ (void)p; (void)h; return s->tuple_match; }
#include "packet-match.c"
static unsigned int cases;
static void reset(void)
{
 assert(!lan.refs && !wan.refs && !upper.refs);
 conduit = (struct net_device){.reg_state=1, .dsa=-1, .net=&init_net, .gdm=&lan_gdm};
 lan = (struct net_device){.ifindex=3,.reg_state=1,.dsa=2,.mtu=1500,.net=&init_net,.conduit=&conduit};
 wan = (struct net_device){.ifindex=4,.reg_state=1,.dsa=-1,.mtu=1500,.net=&init_net,.gdm=&wan_gdm};
 upper = (struct net_device){.ifindex=5,.reg_state=1,.dsa=-1,.mtu=1500,.net=&init_net};
 soc = (struct soc){0x7563,1};
}
static struct flow_rule rule(void)
{
 struct flow_rule r = {.has_meta=true,.key={.ingress_ifindex=3},.mask={.ingress_ifindex=-1}};
 r.ct_context = (struct flow_rule_ct_context){.version=1,.producer=1,.valid=1,.zone_dir=3,.initial_netns=1};
 return r;
}
static void try_rule(struct flow_rule *r, struct net_device *out, int type, u8 proto, bool success)
{
 struct airoha_flow_table_entry e = {};
 int err = airoha_ppe_wired_l4_get_devs(&ppe, &e, r, out, type, proto);
 assert((err == 0) == success);
 if (success) { assert(e.ingress_dev && e.wired_egress_dev && e.wired_l4); assert(lan.refs == 1 && wan.refs == 1); }
 else { assert(!e.ingress_dev && !e.wired_egress_dev); }
 airoha_ppe_flow_entry_put_devs(&e);
 assert(!lan.refs && !wan.refs && !upper.refs); cases++;
}
int main(void)
{
 struct flow_rule r; struct airoha_flow_table_entry e = {};
 struct sk_buff s = {}; struct airoha_foe_entry h = {};
 struct iphdr *ip; struct tcphdr *tcp; unsigned int i;
 reset(); r=rule(); try_rule(&r,&wan,0,IPPROTO_TCP,true);
 for (i=0;i<sizeof(r.ct_context);i++) {
  r=rule(); ((u8 *)&r.ct_context)[i] ^= 0x80;
  try_rule(&r,&wan,0,IPPROTO_TCP,false);
 }
 r=rule(); r.has_meta=false; try_rule(&r,&wan,0,IPPROTO_TCP,false);
 r=rule(); r.mask.ingress_ifindex=0; try_rule(&r,&wan,0,IPPROTO_TCP,false);
 r=rule(); r.key.ingress_ifindex=99; try_rule(&r,&wan,0,IPPROTO_TCP,false);
 r=rule(); try_rule(&r,NULL,0,IPPROTO_TCP,false); try_rule(&r,&upper,0,IPPROTO_TCP,false);
 try_rule(&r,&lan,0,IPPROTO_TCP,false); try_rule(&r,&wan,1,IPPROTO_TCP,false); try_rule(&r,&wan,0,IPPROTO_UDP,false);
 lan.vlan=true; try_rule(&r,&wan,0,IPPROTO_TCP,false); lan.vlan=false;
 wan.reg_state=0; try_rule(&r,&wan,0,IPPROTO_TCP,false); wan.reg_state=1;
 lan.net=&foreign_net; try_rule(&r,&wan,0,IPPROTO_TCP,false); lan.net=&init_net;
 soc.num_ppe=2; try_rule(&r,&wan,0,IPPROTO_TCP,false); soc.num_ppe=1;
 assert(!airoha_ppe_wired_l4_get_devs(&ppe,&e,&r,&wan,0,IPPROTO_TCP));
 airoha_ppe_wired_l4_event(&ppe,&e,&upper,true); assert(!e.wired_dead && !e.unbinds);
 airoha_ppe_wired_l4_event(&ppe,&e,&conduit,false); assert(e.wired_dead && e.unbinds==1 && lan.refs==1 && wan.refs==1);
 airoha_ppe_wired_l4_event(&ppe,&e,&wan,true); assert(!e.wired_egress_dev && wan.refs==0 && lan.refs==1);
 airoha_ppe_wired_l4_event(&ppe,&e,&lan,true); assert(!e.ingress_dev && lan.refs==0);
 airoha_ppe_flow_entry_put_devs(&e); cases+=4;
 e=(struct airoha_flow_table_entry){}; assert(!airoha_ppe_wired_l4_get_devs(&ppe,&e,&r,&wan,0,IPPROTO_TCP));
 s.ethernet.h_proto=htons(ETH_P_IP); s.mac_offset=-ETH_HLEN; s.len=40; s.ingress_match=true; s.tuple_match=true;
 ip=(struct iphdr *)s.data; tcp=(struct tcphdr *)(s.data+20);
 ip->version=4; ip->ihl=5; ip->protocol=IPPROTO_TCP; ip->ttl=64; ip->tot_len=htons(40); tcp->doff=5; tcp->ack=1;
 assert(airoha_ppe_wired_l4_packet_match(&ppe,&e,&h,&s)); cases++;
#define REJECT(change,undo) do { change; assert(!airoha_ppe_wired_l4_packet_match(&ppe,&e,&h,&s)); undo; cases++; } while(0)
 REJECT(s.vlan=true,s.vlan=false); REJECT(s.ingress_match=false,s.ingress_match=true); REJECT(s.tuple_match=false,s.tuple_match=true);
 REJECT(e.wired_dead=true,e.wired_dead=false); REJECT(ip->ihl=6,ip->ihl=5); REJECT(ip->ttl=1,ip->ttl=64);
 REJECT(ip->frag_off=htons(0x2000),ip->frag_off=0); REJECT(ip->frag_off=htons(1),ip->frag_off=0);
 REJECT(ip->protocol=IPPROTO_UDP,ip->protocol=IPPROTO_TCP); REJECT(ip->tot_len=htons(39),ip->tot_len=htons(40));
 REJECT(ip->tot_len=htons(41),ip->tot_len=htons(40)); REJECT(tcp->doff=4,tcp->doff=5);
 REJECT(tcp->doff=6,tcp->doff=5); REJECT(tcp->syn=1,tcp->syn=0); REJECT(tcp->fin=1,tcp->fin=0); REJECT(tcp->rst=1,tcp->rst=0);
 REJECT(s.len=19,s.len=40); REJECT(lan.mtu=39,lan.mtu=1500); REJECT(lan.reg_state=0,lan.reg_state=1);
 airoha_ppe_flow_entry_put_devs(&e); assert(!lan.refs && !wan.refs);
 printf("WIRED_OWNERSHIP_HELPERS_PASS cases=%u refs_balanced=1 real_source_helpers=1\n",cases);
 return 0;
}
