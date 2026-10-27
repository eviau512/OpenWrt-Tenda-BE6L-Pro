static bool airoha_ppe_wired_depends_on(struct net_device *dev,
				       struct net_device *changed)
{
	struct net_device *conduit = dev;

	if (!dev)
		return false;
	if (dev == changed)
		return true;
	return airoha_get_dsa_port(&conduit) >= 0 && conduit == changed;
}

/* Called under ppe_lock. Other SoCs and existing L2 owners are untouched. */
static void
airoha_ppe_wired_l4_event(struct airoha_ppe *ppe,
			struct airoha_flow_table_entry *e,
			struct net_device *netdev, bool unregister)
{
	if (!e->wired_l4 ||
	    (!airoha_ppe_wired_depends_on(e->ingress_dev, netdev) &&
	     !airoha_ppe_wired_depends_on(e->wired_egress_dev, netdev)))
		return;
	e->wired_dead = true;
	airoha_ppe_foe_unbind_flow(ppe, e);
	if (!unregister)
		return;
	if (e->ingress_dev == netdev) {
		dev_put(e->ingress_dev);
		e->ingress_dev = NULL;
	}
	if (e->wired_egress_dev == netdev) {
		dev_put(e->wired_egress_dev);
		e->wired_egress_dev = NULL;
	}
}
