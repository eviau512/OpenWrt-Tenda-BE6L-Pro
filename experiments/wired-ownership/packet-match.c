/* Bind-time proof only. This does not implement ASIC exception handling. */
static bool
airoha_ppe_wired_l4_packet_match(struct airoha_ppe *ppe,
				struct airoha_flow_table_entry *e,
				struct airoha_foe_entry *hwe,
				struct sk_buff *skb)
{
	struct iphdr ipbuf, *ip;
	struct tcphdr tcpbuf, *tcp;
	unsigned int length;
	int input, output, offset;

	if (!e->wired_l4 || e->wired_dead || !e->ingress_dev ||
	    !e->wired_egress_dev || skb_vlan_tag_present(skb) ||
	    eth_hdr(skb)->h_proto != htons(ETH_P_IP))
		return false;
	input = airoha_ppe_wired_role(ppe, e->ingress_dev);
	output = airoha_ppe_wired_role(ppe, e->wired_egress_dev);
	if (!input || !output || input == output ||
	    !airoha_ppe_bridge_ingress_match(e, skb) ||
	    !airoha_ppe_foe_packet_match(ppe, hwe, skb))
		return false;
	offset = skb_mac_offset(skb) + ETH_HLEN;
	if (offset < 0 || (unsigned int)offset > skb->len)
		return false;
	ip = skb_header_pointer(skb, offset, sizeof(ipbuf), &ipbuf);
	if (!ip || ip->version != 4 || ip->ihl != 5 ||
	    ip->protocol != IPPROTO_TCP || ip->ttl <= 1 ||
	    (ntohs(ip->frag_off) & 0x3fff))
		return false;
	length = ntohs(ip->tot_len);
	if (length < sizeof(*ip) + sizeof(tcpbuf) ||
	    length > skb->len - offset || length > e->ingress_dev->mtu)
		return false;
	tcp = skb_header_pointer(skb, offset + sizeof(*ip), sizeof(tcpbuf),
				 &tcpbuf);
	if (!tcp || tcp->doff < 5 || tcp->doff * 4 > length - sizeof(*ip) ||
	    tcp->syn || tcp->fin || tcp->rst)
		return false;
	return true;
}
