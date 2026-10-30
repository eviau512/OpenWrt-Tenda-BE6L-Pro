/* Observe the post-neighbor, post-checksum-helper, post-DSA-extraction frame
 * before dma_map_single. A later DMA/queue failure remains possible. This is
 * not a wire-delivery receipt and the skb's CT is only borrowed during call.
 */
void be6l_diag_driver_tx(struct airoha_ppe *ppe, struct sk_buff *skb,
		       struct net_device *netdev, u32 tag, bool was_gso, u8 summed_before)
{
	struct be6l_diag *d;
	struct bd_egress sample = {};
	struct ethhdr eb, *eth;
	struct iphdr ib, *ip;
	struct tcphdr tb, *tcp;
	const struct nf_conntrack_zone *zone;
	enum ip_conntrack_info info;
	struct nf_conn *ct;
	unsigned int length, tlen;
	if (!skb || skb_vlan_tag_present(skb))
		return;
	rcu_read_lock();
	d = rcu_dereference(ppe->route_diag);
	if (!d)
		goto out;
	ct = nf_ct_get(skb, &info);
	if (!ct || !net_eq(nf_ct_net(ct), &init_net))
		goto out;
	zone = nf_ct_zone(ct);
	if (zone->id || zone->flags || zone->dir != 3)
		goto out;
	eth = skb_header_pointer(skb, 0, sizeof(eb), &eb);
	if (!eth || eth->h_proto != htons(ETH_P_IP))
		goto out;
	ip = skb_header_pointer(skb, ETH_HLEN, sizeof(ib), &ib);
	if (!ip || ip->version != 4 || ip->ihl != 5 || ip->protocol != IPPROTO_TCP ||
	    (ntohs(ip->frag_off) & 0x3fff))
		goto out;
	length = ntohs(ip->tot_len);
	if (length < sizeof(ib) + sizeof(tb) || skb->len < ETH_HLEN || length > skb->len - ETH_HLEN)
		goto out;
	tcp = skb_header_pointer(skb, ETH_HLEN + sizeof(ib), sizeof(tb), &tb);
	if (!tcp || tcp->doff < 5 || tcp->doff * 4 > length - sizeof(ib) ||
	    !bd_options(skb, ETH_HLEN + sizeof(ib) + sizeof(tb), tcp->doff * 4 - sizeof(tb)))
		goto out;
	tlen = length - sizeof(ib);
	sample.observed_ns = ktime_get_ns();
	sample.ct_cookie = (unsigned long)ct;
	sample.direction = CTINFO2DIR(info);
	sample.key[0] = ntohl(ip->saddr);
	sample.key[1] = ntohl(ip->daddr);
	sample.key[2] = (u32)ntohs(tcp->source) << 16 | ntohs(tcp->dest);
	sample.actual_ifindex = netdev->ifindex;
	sample.tag = tag;
	sample.frame_bytes = skb->len;
	sample.was_gso = was_gso;
	sample.summed_before = summed_before;
	sample.summed_after = skb->ip_summed;
	sample.ttl = ip->ttl;
	sample.seq = ntohl(tcp->seq);
	sample.ack_seq = ntohl(tcp->ack_seq);
	ether_addr_copy(sample.src_mac, eth->h_source);
	ether_addr_copy(sample.dst_mac, eth->h_dest);
	sample.format_complete = !was_gso && skb->ip_summed != CHECKSUM_PARTIAL &&
		!ip_compute_csum(ip, sizeof(ib)) &&
		!csum_tcpudp_magic(ip->saddr, ip->daddr, tlen, IPPROTO_TCP,
				   skb_checksum(skb, ETH_HLEN + sizeof(ib), tlen, 0));
	/* No state in this sample can establish successful DMA or wire delivery. */
	sample.delivered = false;
	spin_lock_bh(&d->lock);
	if (!bd_epoch_live(&d->epoch, ktime_get_ns()))
		goto unlock;
	if (netdev == d->refs[1] && !tag)
		sample.logical_output_ifindex = d->ifindex[1];
	else if (netdev == d->refs[2] && tag == BIT(d->dsa_index))
		sample.logical_output_ifindex = d->ifindex[0];
	else
		goto unlock;
	if (bd_record_egress(d->snapshot.rows, &sample))
		d->snapshot.egress_accepted++;
	else
		d->snapshot.egress_rejected++;
unlock:
	spin_unlock_bh(&d->lock);
out:
	rcu_read_unlock();
}
