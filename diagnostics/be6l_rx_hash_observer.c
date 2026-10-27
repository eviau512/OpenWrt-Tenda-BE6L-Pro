// SPDX-License-Identifier: GPL-2.0-only
/* Bounded, read-only skb metadata observations before the flow-table hook.
 * Never touches packet bytes, skb hash, DMA descriptors, MMIO or forwarding.
 */
#include <linux/debugfs.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_netdev.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/tcp.h>
#include <net/net_namespace.h>

#define MAX_RECORDS 64
struct hash_record {
	__be32 src, dst;
	__be16 sport, dport;
	u32 hash;
	int cpu;
	u8 l4, sw;
	char dev[IFNAMSIZ];
};
static struct hash_record records[MAX_RECORDS];
static unsigned int count;
static DEFINE_SPINLOCK(records_lock);
static struct nf_hook_ops hooks[2];
static struct dentry *entry;

static unsigned int observe(void *priv, struct sk_buff *skb,
			    const struct nf_hook_state *state)
{
	struct iphdr ipbuf, *ip;
	struct tcphdr tcpbuf, *tcp;
	struct hash_record *r;
	unsigned long flags;
	unsigned int i, offset;

	if (READ_ONCE(count) >= MAX_RECORDS || skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;
	offset = skb_network_offset(skb);
	ip = skb_header_pointer(skb, offset, sizeof(ipbuf), &ipbuf);
	if (!ip || ip->version != 4 || ip->ihl < 5 || ip->protocol != IPPROTO_TCP ||
	    (ntohs(ip->frag_off) & 0x3fff))
		return NF_ACCEPT;
	tcp = skb_header_pointer(skb, offset + ip->ihl * 4, sizeof(tcpbuf), &tcpbuf);
	if (!tcp || (tcp->source != htons(5201) && tcp->source != htons(5202) &&
		     tcp->dest != htons(5201) && tcp->dest != htons(5202)))
		return NF_ACCEPT;
	spin_lock_irqsave(&records_lock, flags);
	for (i = 0; i < count; i++) {
		r = &records[i];
		if (r->src == ip->saddr && r->dst == ip->daddr &&
		    r->sport == tcp->source && r->dport == tcp->dest &&
		    r->hash == skb_get_hash_raw(skb) && r->cpu == smp_processor_id() &&
		    !strcmp(r->dev, state->in->name))
			goto out;
	}
	if (count == MAX_RECORDS)
		goto out;
	r = &records[count++];
	r->src = ip->saddr; r->dst = ip->daddr;
	r->sport = tcp->source; r->dport = tcp->dest;
	r->hash = skb_get_hash_raw(skb);
	r->cpu = smp_processor_id();
	r->l4 = skb->l4_hash;
	r->sw = skb->sw_hash;
	strscpy(r->dev, state->in->name, IFNAMSIZ);
out:
	spin_unlock_irqrestore(&records_lock, flags);
	return NF_ACCEPT;
}

static int hash_show(struct seq_file *s, void *unused)
{
	struct hash_record *copy;
	unsigned long flags;
	unsigned int i, n;
	copy = kmalloc_array(MAX_RECORDS, sizeof(*copy), GFP_KERNEL);
	if (!copy)
		return -ENOMEM;
	spin_lock_irqsave(&records_lock, flags);
	n = count;
	memcpy(copy, records, n * sizeof(*copy));
	spin_unlock_irqrestore(&records_lock, flags);
	seq_printf(s, "read_only=1 packet_modifications=0 hardware_access=0 records=%u\n", n);
	for (i = 0; i < n; i++) {
		struct hash_record *r = &copy[i];
		seq_printf(s, "%s %pI4:%u -> %pI4:%u hash=%08x cpu=%d l4=%u sw=%u\n",
			   r->dev, &r->src, ntohs(r->sport), &r->dst, ntohs(r->dport),
			   r->hash, r->cpu, r->l4, r->sw);
	}
	kfree(copy);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(hash);

static int __init start(void)
{
	static const char * const names[] = { "lan3", "eth1" };
	int i, err;
	for (i = 0; i < ARRAY_SIZE(hooks); i++) {
		hooks[i].dev = dev_get_by_name(&init_net, names[i]);
		if (!hooks[i].dev) {
			err = -ENODEV;
			goto fail;
		}
		hooks[i].hook = observe;
		hooks[i].pf = NFPROTO_NETDEV;
		hooks[i].hooknum = NF_NETDEV_INGRESS;
		hooks[i].priority = INT_MIN + 16;
	}
	err = nf_register_net_hooks(&init_net, hooks, ARRAY_SIZE(hooks));
	if (err)
		goto fail;
	entry = debugfs_create_file("be6l_rx_hash_observer", 0400, NULL, NULL, &hash_fops);
	if (IS_ERR_OR_NULL(entry)) {
		err = -ENOMEM;
		nf_unregister_net_hooks(&init_net, hooks, ARRAY_SIZE(hooks));
		goto fail;
	}
	return 0;
fail:
	for (i = 0; i < ARRAY_SIZE(hooks); i++)
		if (hooks[i].dev)
			dev_put(hooks[i].dev);
	return err;
}
static void __exit stop(void)
{
	debugfs_remove(entry);
	nf_unregister_net_hooks(&init_net, hooks, ARRAY_SIZE(hooks));
	dev_put(hooks[0].dev);
	dev_put(hooks[1].dev);
}
module_init(start);
module_exit(stop);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bounded read-only skb hash observer for protected RAM diagnostics");
