// SPDX-License-Identifier: GPL-2.0-only
/* CPU-only observer. It has no PPE SRAM, owner, BIND or MMIO interface. */
#include <linux/err.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ktime.h>
#include <linux/notifier.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/tcp.h>
#include <linux/workqueue.h>
#include <net/checksum.h>
#include <net/dsa.h>
#include <net/dst_metadata.h>
#include <net/ip.h>
#include "airoha_eth.h"
#include "diag.h"
#include "epoch.h"

enum { BD_OPEN, BD_EXPIRED, BD_CHANGED, BD_DESTROYED };
struct be6l_diag {
	spinlock_t lock;
	struct delayed_work expiry;
	struct notifier_block notifier;
	struct airoha_ppe *ppe;
	struct bd_epoch epoch;
	struct net_device *refs[3]; /* LAN user, real WAN, LAN conduit. */
	int ifindex[3], dsa_index;
	struct bd_snapshot snapshot;
};

static bool bd_registered(struct net_device *dev)
{
	return dev && net_eq(dev_net(dev), &init_net) &&
	       READ_ONCE(dev->reg_state) == NETREG_REGISTERED && !is_vlan_dev(dev);
}
/* Match real registered GDM objects before inspecting their private data. */
static bool bd_gdm(struct airoha_ppe *ppe, struct net_device *dev, int id)
{
	unsigned int i, j;
	for (i = 0; i < ARRAY_SIZE(ppe->eth->ports); i++) {
		struct airoha_gdm_port *port = ppe->eth->ports[i];
		if (!port || port->id != id)
			continue;
		for (j = 0; j < ARRAY_SIZE(port->devs); j++)
			if (port->devs[j] && netdev_from_priv(port->devs[j]) == dev)
				return id != AIROHA_GDM2_IDX ||
				       !airoha_is_lan_gdm_dev(port->devs[j]);
	}
	return false;
}
/* Must hold RTNL. Physical DSA index is an explicit observed configuration,
 * never the synthetic index2 from a host fixture. */
static bool bd_topology(struct be6l_diag *d)
{
	struct dsa_port *dp;
	int i;
	for (i = 0; i < 3; i++)
		if (!bd_registered(d->refs[i]) || d->refs[i]->ifindex != d->ifindex[i])
			return false;
	dp = dsa_port_from_netdev(d->refs[0]);
	return !IS_ERR(dp) && !dp->ds->index && dp->type == DSA_PORT_TYPE_USER &&
	       dp->index == d->dsa_index && dsa_port_to_conduit(dp) == d->refs[2] &&
	       bd_gdm(d->ppe, d->refs[2], AIROHA_GDM1_IDX) &&
	       bd_gdm(d->ppe, d->refs[1], AIROHA_GDM2_IDX);
}
/* Single ownership transition under our own lock. No PPE lock or owner touched. */
static void bd_revoke(struct be6l_diag *d, u32 reason)
{
	struct net_device *put[3] = {};
	int i;
	spin_lock_bh(&d->lock);
	if (bd_epoch_close(&d->epoch)) {
		memcpy(put, d->refs, sizeof(put));
		memset(d->refs, 0, sizeof(d->refs));
		d->snapshot.active = false;
		d->snapshot.refs_owned = 0;
		d->snapshot.reason = reason;
	}
	spin_unlock_bh(&d->lock);
	for (i = 0; i < 3; i++)
		dev_put(put[i]);
}
static void bd_expire(struct work_struct *work)
{
	struct be6l_diag *d = container_of(to_delayed_work(work), struct be6l_diag, expiry);
	bd_revoke(d, BD_EXPIRED);
}
static int bd_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct be6l_diag *d = container_of(nb, struct be6l_diag, notifier);
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	bool affected = false;
	int i;
	switch (event) {
	case NETDEV_UNREGISTER: case NETDEV_GOING_DOWN: case NETDEV_PRECHANGEUPPER:
	case NETDEV_CHANGEUPPER: case NETDEV_CHANGEADDR: case NETDEV_CHANGEMTU:
	case NETDEV_CHANGE: case NETDEV_CHANGENAME:
		break;
	default:
		return NOTIFY_DONE;
	}
	spin_lock_bh(&d->lock);
	for (i = 0; i < 3; i++)
		affected |= d->refs[i] == dev;
	spin_unlock_bh(&d->lock);
	if (affected)
		bd_revoke(d, BD_CHANGED);
	return NOTIFY_DONE;
}
struct be6l_diag *be6l_diag_create(struct airoha_ppe *ppe, const struct bd_config *cfg)
{
	struct be6l_diag *d;
	struct dsa_port *dp;
	int err, i;
	if (!cfg || !cfg->enabled)
		return ERR_PTR(-EACCES);
	if (!ppe || !airoha_is_7563(ppe->eth) || ppe->eth->soc->num_ppe != 1 ||
	    cfg->lan_ifindex <= 0 || cfg->wan_ifindex <= 0 ||
	    cfg->lan_ifindex == cfg->wan_ifindex || cfg->expected_dsa_port < 0 ||
	    cfg->expected_dsa_port >= 5)
		return ERR_PTR(-EINVAL);
	d = kzalloc(sizeof(*d), GFP_KERNEL);
	if (!d)
		return ERR_PTR(-ENOMEM);
	spin_lock_init(&d->lock);
	INIT_DELAYED_WORK(&d->expiry, bd_expire);
	d->ppe = ppe;
	d->dsa_index = cfg->expected_dsa_port;
	d->notifier.notifier_call = bd_event;
	/* Register before taking topology snapshots; open also holds RTNL. */
	err = register_netdevice_notifier(&d->notifier);
	if (err)
		goto free;
	rtnl_lock();
	d->refs[0] = dev_get_by_index(&init_net, cfg->lan_ifindex);
	d->refs[1] = dev_get_by_index(&init_net, cfg->wan_ifindex);
	if (!bd_registered(d->refs[0]) || !bd_registered(d->refs[1]))
		goto fail;
	dp = dsa_port_from_netdev(d->refs[0]);
	if (IS_ERR(dp))
		goto fail;
	d->refs[2] = dsa_port_to_conduit(dp);
	dev_hold(d->refs[2]);
	for (i = 0; i < 3; i++)
		d->ifindex[i] = d->refs[i]->ifindex;
	if (!bd_topology(d) || !bd_epoch_open(&d->epoch, cfg->generation,
					     ktime_get_ns(), cfg->duration_ns))
		goto fail;
	d->snapshot.active = d->snapshot.spent = true;
	d->snapshot.unresolved = 0x3f;
	d->snapshot.refs_owned = 3;
	d->snapshot.generation = d->epoch.generation;
	d->snapshot.created_ns = d->epoch.created;
	d->snapshot.deadline_ns = d->epoch.deadline;
	memcpy(d->snapshot.input_ifindex, d->ifindex, sizeof(d->ifindex));
	rtnl_unlock();
	schedule_delayed_work(&d->expiry, nsecs_to_jiffies(cfg->duration_ns) + 1);
	return d;
fail:
	for (i = 0; i < 3; i++)
		dev_put(d->refs[i]);
	rtnl_unlock();
	unregister_netdevice_notifier(&d->notifier);
	err = -EOPNOTSUPP;
free:
	kfree(d);
	return ERR_PTR(err);
}
void be6l_diag_destroy(struct be6l_diag *d)
{
	if (IS_ERR_OR_NULL(d))
		return;
	/* Caller must first unpublish/drain its CT/RX taps. No live tap is installed. */
	unregister_netdevice_notifier(&d->notifier);
	cancel_delayed_work_sync(&d->expiry);
	bd_revoke(d, BD_DESTROYED);
	kfree(d);
}
static bool bd_context(const struct flow_rule_ct_context *c)
{
	return c->valid == 1 && c->version == FLOW_RULE_CT_CONTEXT_VERSION &&
	       c->producer == FLOW_RULE_CT_CONTEXT_NF_FLOWTABLE &&
	       c->direction <= 1 && c->initial_netns == 1 && !c->zone_id &&
	       !c->zone_raw_id && !c->zone_flags && c->zone_dir == 3 && !c->reserved;
}
int be6l_diag_note_ct(struct be6l_diag *d, const struct flow_rule *rule)
{
	struct flow_match_meta meta;
	struct flow_match_basic basic;
	struct flow_match_control control;
	struct flow_match_ipv4_addrs ip;
	struct flow_match_ports ports;
	struct flow_match_ip tos;
	struct flow_match_tcp tcp;
	const struct flow_action_entry *act;
	struct net_device *output = NULL;
	struct bd_row row = {};
	u64 keys = BIT_ULL(FLOW_DISSECTOR_KEY_META) | BIT_ULL(FLOW_DISSECTOR_KEY_BASIC) |
		   BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) | BIT_ULL(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
		   BIT_ULL(FLOW_DISSECTOR_KEY_PORTS) | BIT_ULL(FLOW_DISSECTOR_KEY_IP) |
		   BIT_ULL(FLOW_DISSECTOR_KEY_TCP);
	int i, slot = -1, redirects = 0, error = -EOPNOTSUPP;
	if (IS_ERR_OR_NULL(d) || !rule || !bd_context(&rule->ct_context) ||
	    rule->match.dissector->used_keys != keys ||
	    !rule->action.num_entries || rule->action.num_entries > BD_ACTIONS)
		return error;
	flow_rule_match_meta(rule, &meta);
	flow_rule_match_basic(rule, &basic);
	flow_rule_match_control(rule, &control);
	flow_rule_match_ipv4_addrs(rule, &ip);
	flow_rule_match_ports(rule, &ports);
	flow_rule_match_ip(rule, &tos);
	flow_rule_match_tcp(rule, &tcp);
	if (meta.mask->ingress_ifindex != -1 || meta.mask->ingress_iftype || meta.mask->l2_miss ||
	    basic.key->n_proto != htons(ETH_P_IP) || basic.key->ip_proto != IPPROTO_TCP ||
	    basic.mask->n_proto != htons(0xffff) || basic.mask->ip_proto != 0xff ||
	    control.key->addr_type != FLOW_DISSECTOR_KEY_IPV4_ADDRS ||
	    control.mask->addr_type != 0xffff || control.mask->thoff || control.mask->flags ||
	    ip.mask->src != htonl(0xffffffff) || ip.mask->dst != htonl(0xffffffff) ||
	    ports.mask->src != htons(0xffff) || ports.mask->dst != htons(0xffff) ||
	    tos.mask->tos != 0xff || tos.mask->ttl ||
	    tcp.key->flags || tcp.mask->flags != htons(0x0005))
		return error;
	row.direction = rule->ct_context.direction;
	row.context = rule->ct_context;
	row.tos = tos.key->tos;
	row.tcp_flags = ntohs(tcp.key->flags);
	row.tcp_mask = ntohs(tcp.mask->flags);
	row.key[0] = ntohl(ip.key->src);
	row.key[1] = ntohl(ip.key->dst);
	row.key[2] = (u32)ntohs(ports.key->src) << 16 | ntohs(ports.key->dst);
	row.action_count = rule->action.num_entries;
	flow_action_for_each(i, act, &rule->action) {
		struct bd_action_copy *copy = &row.actions[i];
		copy->id = act->id;
		switch (act->id) {
		case FLOW_ACTION_REDIRECT:
			if (++redirects != 1 || !act->dev)
				return error;
			output = act->dev;
			row.output_ifindex = act->dev->ifindex;
			break;
		case FLOW_ACTION_MANGLE:
			copy->htype = act->mangle.htype;
			copy->offset = act->mangle.offset;
			copy->mask = act->mangle.mask;
			copy->value = act->mangle.val;
			break;
		case FLOW_ACTION_CSUM:
			copy->checksum_flags = act->csum_flags;
			break;
		default:
			return error;
		}
	}
	if (redirects != 1)
		return error;
	spin_lock_bh(&d->lock);
	if (!bd_epoch_live(&d->epoch, ktime_get_ns())) {
		error = -ESTALE;
		goto out;
	}
	if (meta.key->ingress_ifindex != d->ifindex[row.direction] ||
	    row.output_ifindex != d->ifindex[!row.direction] ||
	    output != d->refs[!row.direction])
		goto out;
	for (i = 0; i < BD_SLOTS; i++) {
		struct bd_row *old = &d->snapshot.rows[i];
		if (!old->used) { if (slot < 0) slot = i; continue; }
		if (memcmp(old->key, row.key, sizeof(row.key)))
			continue;
		/* Conflicting producers/actions for an already observed key are refused. */
		if (old->direction != row.direction || old->tos != row.tos ||
		    old->output_ifindex != row.output_ifindex ||
		    old->action_count != row.action_count ||
		    memcmp(old->actions, row.actions, sizeof(row.actions))) {
			error = -EEXIST;
			goto out;
		}
		error = 0; /* No duplicate allocation or deadline extension. */
		goto out;
	}
	if (slot < 0) { error = -ENOSPC; goto out; }
	row.used = true;
	row.observed_ns = ktime_get_ns();
	d->snapshot.rows[slot] = row;
	d->snapshot.accepted++;
	error = 0;
out:
	if (error)
		d->snapshot.rejected++;
	spin_unlock_bh(&d->lock);
	return error;
}
static bool bd_options(struct sk_buff *skb, int offset, unsigned int length)
{
	u8 buffer[40], *bytes;
	unsigned int i = 0;
	if (!length)
		return true;
	if (length > sizeof(buffer))
		return false;
	bytes = skb_header_pointer(skb, offset, length, buffer);
	if (!bytes)
		return false;
	while (i < length) {
		if (!bytes[i]) return true;
		if (bytes[i] == 1) { i++; continue; }
		if (i + 1 >= length || bytes[i + 1] < 2 || bytes[i + 1] > length - i)
			return false;
		i += bytes[i + 1];
	}
	return true;
}
bool be6l_diag_note_rx(struct be6l_diag *d, struct sk_buff *skb, const u32 unbound[20])
{
	struct iphdr ib, *ip;
	struct tcphdr tb, *tcp;
	struct ethhdr eb, *ethernet;
	struct metadata_dst *md;
	u32 key[3];
	unsigned int length, tlen;
	int i, offset;
	bool matched = false;
	if (IS_ERR_OR_NULL(d) || !skb || !unbound || skb_vlan_tag_present(skb) ||
	    skb_is_gso(skb) || skb->ip_summed == CHECKSUM_PARTIAL ||
	    !skb_mac_header_was_set(skb) ||
	    (unbound[0] & 0x7e000000) != 0x10000000)
		return false;
	offset = skb_mac_offset(skb) + ETH_HLEN;
	if (offset < 0 || (unsigned int)offset > skb->len)
		return false;
	ethernet = skb_header_pointer(skb, offset - ETH_HLEN, sizeof(eb), &eb);
	if (!ethernet || ethernet->h_proto != htons(ETH_P_IP))
		return false;
	ip = skb_header_pointer(skb, offset, sizeof(ib), &ib);
	if (!ip || ip->version != 4 || ip->ihl != 5 || ip->protocol != IPPROTO_TCP ||
	    ip->ttl <= 1 || (ntohs(ip->frag_off) & 0x3fff))
		return false;
	length = ntohs(ip->tot_len);
	if (length < sizeof(ib) + sizeof(tb) || length > skb->len - offset)
		return false;
	tcp = skb_header_pointer(skb, offset + sizeof(ib), sizeof(tb), &tb);
	if (!tcp || tcp->doff < 5 || tcp->doff * 4 > length - sizeof(ib) ||
	    !tcp->ack || tcp->urg || tcp->syn || tcp->fin || tcp->rst)
		return false;
	tlen = length - sizeof(ib);
	if (!bd_options(skb, offset + sizeof(ib) + sizeof(tb), tcp->doff * 4 - sizeof(tb)) ||
	    ip_compute_csum(ip, sizeof(ib)) ||
	    csum_tcpudp_magic(ip->saddr, ip->daddr, tlen, IPPROTO_TCP,
			     skb_checksum(skb, offset + sizeof(ib), tlen, 0)))
		return false;
	key[0] = ntohl(ip->saddr); key[1] = ntohl(ip->daddr);
	key[2] = (u32)ntohs(tcp->source) << 16 | ntohs(tcp->dest);
	if (memcmp(key, unbound + 1, sizeof(key)))
		return false;
	spin_lock_bh(&d->lock);
	if (!bd_epoch_live(&d->epoch, ktime_get_ns()))
		goto out;
	for (i = 0; i < BD_SLOTS; i++) {
		struct bd_row *row = &d->snapshot.rows[i];
		bool input = skb->dev == d->refs[row->direction];
		if (!row->used || memcmp(row->key, key, sizeof(key)) || ip->tos != row->tos ||
		    length > READ_ONCE(d->refs[row->direction]->mtu) ||
		    length > READ_ONCE(d->refs[!row->direction]->mtu))
			continue;
		if (!row->direction && skb->dev == d->refs[2]) {
			md = skb_metadata_dst(skb);
			input = md && md->type == METADATA_HW_PORT_MUX &&
				md->u.port_info.port_id == d->dsa_index;
		}
		if (!input)
			continue;
		memcpy(row->unbound, unbound, sizeof(row->unbound));
		row->rx_ns = ktime_get_ns();
		row->rx_matched = matched = true;
	}
out:
	spin_unlock_bh(&d->lock);
	return matched;
}
void be6l_diag_snapshot(struct be6l_diag *d, struct bd_snapshot *out)
{
	memset(out, 0, sizeof(*out));
	if (IS_ERR_OR_NULL(d))
		return;
	spin_lock_bh(&d->lock);
	*out = d->snapshot;
	/* Delayed work is cleanup, not the authority for observation expiry. */
	out->active = bd_epoch_live(&d->epoch, ktime_get_ns());
	out->can_publish = false;
	out->unresolved = 0x3f;
	spin_unlock_bh(&d->lock);
}
