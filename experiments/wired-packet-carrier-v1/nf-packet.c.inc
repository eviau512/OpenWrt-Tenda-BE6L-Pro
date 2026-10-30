/* SPDX-License-Identifier: GPL-2.0-only */
/* Called after neighbor/output selection, before the existing queue call.
 * Allocation/refcount/COW/free belong to the real skb extension API. No
 * nf_ct_set, extra CT reference, skb->cb reuse or packet-header rewrite.
 */
static void nf_flow_diag_packet_emit(struct sk_buff *skb, const struct net *net,
                                    struct flow_offload *flow,
                                    enum flow_offload_tuple_dir dir,
                                    int ingress, int output)
{
 struct flow_rule_ct_context context;
 struct flow_diag_packet packet, *extension;
 BUILD_BUG_ON(sizeof(context) != sizeof(packet.context_words));
 BUILD_BUG_ON(sizeof(packet) != 88);
 /* Remove only this diagnostic extension; preserve all other extensions. */
 skb_ext_del(skb, SKB_EXT_NF_FLOW_DIAG);
 if (!flow_offload_diag_lease_packet(&packet, ingress, output))
  return;
 if ((unsigned int)dir >= FLOW_OFFLOAD_DIR_MAX ||
     flow->tuplehash[dir].tuple.l3proto != NFPROTO_IPV4 ||
     flow->tuplehash[dir].tuple.l4proto != IPPROTO_TCP ||
     !net_eq(net, &init_net) || skb_vlan_tag_present(skb))
  return;
 if (!nf_flow_ct_context_copy(&context, net, flow, dir) ||
     context.valid != 1 || context.version != 2 || context.producer != 1 ||
     !context.initial_netns || context.zone_id || context.zone_raw_id ||
     context.zone_flags || context.zone_dir != 3 || context.reserved)
  return;
 memcpy(packet.context_words, &context, sizeof(context));
 extension = skb_ext_add(skb, SKB_EXT_NF_FLOW_DIAG);
 if (extension)
  memcpy(extension, &packet, sizeof(packet));
 /* Failure affects diagnostic collection only; original transmit continues. */
}
