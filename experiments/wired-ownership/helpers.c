/* Prospective wired L4 ownership only; routed admission remains refused. */
static bool
airoha_ppe_wired_context_valid(const struct flow_rule_ct_context *context)
{
	return context->valid == 1 &&
	       context->version == FLOW_RULE_CT_CONTEXT_VERSION &&
	       context->producer == FLOW_RULE_CT_CONTEXT_NF_FLOWTABLE &&
	       context->direction <= 1 && context->initial_netns == 1 &&
	       !context->zone_id && !context->zone_raw_id &&
	       !context->zone_flags && context->zone_dir == 3 &&
	       !context->reserved;
}

/* A DSA user port on GDM1 or the real GDM2 WAN, never an opaque upper. */
static int airoha_ppe_wired_role(struct airoha_ppe *ppe,
				struct net_device *netdev)
{
	struct airoha_gdm_dev *gdm;
	struct net_device *conduit = netdev;
	int dsa_port;

	if (!netdev || !net_eq(dev_net(netdev), &init_net) ||
	    READ_ONCE(netdev->reg_state) != NETREG_REGISTERED ||
	    is_vlan_dev(netdev))
		return 0;
	dsa_port = airoha_get_dsa_port(&conduit);
	gdm = netdev_priv(conduit);
	if (!airoha_is_valid_gdm_dev(ppe->eth, gdm))
		return 0;
	if (dsa_port >= 0 && dsa_port < 5 &&
	    gdm->port->id == AIROHA_GDM1_IDX)
		return 1;
	if (dsa_port < 0 && conduit == netdev &&
	    gdm->port->id == AIROHA_GDM2_IDX && !airoha_is_lan_gdm_dev(gdm))
		return 2;
	return 0;
}

static int
airoha_ppe_wired_l4_get_devs(struct airoha_ppe *ppe,
			    struct airoha_flow_table_entry *e,
			    struct flow_rule *rule, struct net_device *odev,
			    int type, u8 l4proto)
{
	struct net_device *ingress;
	struct flow_match_meta meta;
	int input, output;

	if (!airoha_is_7563(ppe->eth))
		return 0;
	if (type != PPE_PKT_TYPE_IPV4_HNAPT || l4proto != IPPROTO_TCP ||
	    ppe->eth->soc->num_ppe != 1 ||
	    !airoha_ppe_wired_context_valid(&rule->ct_context) ||
	    !flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_META))
		return -EOPNOTSUPP;
	if (e->ingress_dev || e->wired_egress_dev)
		return -EEXIST;
	flow_rule_match_meta(rule, &meta);
	if (meta.mask->ingress_ifindex != -1 || meta.mask->ingress_iftype ||
	    meta.mask->l2_miss)
		return -EOPNOTSUPP;
	output = airoha_ppe_wired_role(ppe, odev);
	if (!output)
		return -EOPNOTSUPP;
	ingress = dev_get_by_index(&init_net, meta.key->ingress_ifindex);
	if (!ingress)
		return -ENODEV;
	input = airoha_ppe_wired_role(ppe, ingress);
	if (!input || input == output) {
		dev_put(ingress);
		return -EOPNOTSUPP;
	}
	dev_hold(odev);
	e->ingress_dev = ingress;
	e->wired_egress_dev = odev;
	e->wired_l4 = true;
	e->wired_dead = false;
	return 0;
}

static void
airoha_ppe_flow_entry_put_devs(struct airoha_flow_table_entry *e)
{
	dev_put(e->ingress_dev);
	dev_put(e->wired_egress_dev);
	dev_put(e->wdma_dev);
	e->ingress_dev = NULL;
	e->wired_egress_dev = NULL;
	e->wdma_dev = NULL;
}
