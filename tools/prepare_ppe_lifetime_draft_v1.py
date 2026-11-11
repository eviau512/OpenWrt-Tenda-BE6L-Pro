# SPDX-License-Identifier: MIT
"""Prepare an isolated, deliberately unadmitted BE6L PPE lifetime port draft.

This is source research, not an image builder. Native withdrawal is deliberately
unsupported: a table-write ACK, clearing EN and waiting are not a DMA fence.
The resulting patch must not be placed in patches/series or a RAM candidate.
"""
from pathlib import Path
import argparse
import difflib
import hashlib
import json
import shutil
from test_xwrt_sram_policy_v1 import function

PPE_PIN = 'de1f3299891eef4d987a4e9222eedc535ead18bf0d100c996eea2c0f8d5bb2f1'
REF_PIN = '51ad29d2a1e563c60c61d226eb0b160d0624b6c7f8b440d261762827a0012933'


def replace(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f'Anchor count {text.count(old)}: {old[:100]!r}')
    return text.replace(old, new, 1)


def edit_func(text, name, transform):
    old = function(text, name)
    return replace(text, old, transform(old))


WITHDRAW = r'''
/* This boundary needs an AN7552/AN7563 provider that proves outstanding
 * accesses to the physical FOE slot AND referenced output resources drained.
 * UPDMEM/PPE ACK, clearing PPE.EN, RCU and a delay cannot provide that proof.
 * Do not wire this to generic npu->ops.ppe_deinit: native AN7563 bypasses it.
 * No enabling setter exists in this draft. See the explicit admission receipt.
 */
static int airoha_ppe_foe_withdraw_complete(struct airoha_ppe *ppe, u32 hash)
{
	if (airoha_is_7563(ppe->eth))
		return -EOPNOTSUPP;
	return 0;
}

static bool
airoha_ppe_foe_slot_busy(struct airoha_ppe *ppe,
			struct airoha_flow_table_entry *owner, u32 hash)
{
	lockdep_assert_held(&ppe_lock);
	return ppe->foe_owner[hash] && ppe->foe_owner[hash] != owner;
}

static void
airoha_ppe_foe_reserve_slot(struct airoha_ppe *ppe,
			   struct airoha_flow_table_entry *e, u32 hash)
{
	lockdep_assert_held(&ppe_lock);
	e->hash = hash;
	ppe->foe_owner[hash] = e;
}
'''

UNBIND = r'''static int airoha_ppe_foe_unbind_flow(struct airoha_ppe *ppe,
				      struct airoha_flow_table_entry *e)
{
	struct airoha_foe_entry *entry, hwe;
	u32 hash = e->hash;
	int err = 0;

	lockdep_assert_held(&ppe_lock);
	if (hash == 0xffff)
		return 0;
	if (hash >= airoha_ppe_get_total_num_entries(ppe) ||
	    ppe->foe_owner[hash] != e) {
		err = -ESTALE;
		goto failed;
	}
	entry = airoha_ppe_foe_get_entry_locked(ppe, hash);
	if (!entry) {
		err = -EIO;
		goto failed;
	}
	if (FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, entry->ib1) ==
	    AIROHA_FOE_STATE_BIND) {
		hwe = *entry;
		hwe.ib1 &= ~AIROHA_FOE_IB1_BIND_STATE;
		err = airoha_ppe_foe_commit_entry(ppe, &hwe, hash, false);
		if (err)
			goto failed;
	}
	/* Even a successful invalidation has not proved output DMA drained. */
	err = airoha_ppe_foe_withdraw_complete(ppe, hash);
	if (err)
		goto failed;
	ppe->foe_owner[hash] = NULL;
	e->hash = 0xffff;
	return 0;
failed:
	airoha_ppe_foe_write_failed(ppe, err);
	return err;
}
'''

REMOVE = r'''static int airoha_ppe_foe_remove_flow(struct airoha_ppe *ppe,
				      struct airoha_flow_table_entry *e)
{
	int err;

	lockdep_assert_held(&ppe_lock);
	err = airoha_ppe_foe_unbind_flow(ppe, e);
	if (err)
		return err;
	hlist_del_init(&e->list);
	if (e->type == FLOW_TYPE_L2_SUBFLOW) {
		hlist_del_init(&e->l2_subflow_node);
		kfree(e);
	}
	return 0;
}
'''

RELEASE = r'''static int airoha_ppe_foe_release_slot(struct airoha_ppe *ppe, u32 hash)
{
	struct airoha_flow_table_entry *e;

	lockdep_assert_held(&ppe_lock);
	if (hash >= airoha_ppe_get_total_num_entries(ppe))
		return -EINVAL;
	e = ppe->foe_owner[hash];
	if (!e)
		return 0;
	if (e->type == FLOW_TYPE_L2_SUBFLOW)
		return airoha_ppe_foe_remove_flow(ppe, e);
	return airoha_ppe_foe_unbind_flow(ppe, e);
}
'''

REMOVE_PARENT = r'''static int airoha_ppe_foe_remove_l2_flow(struct airoha_ppe *ppe,
					 struct airoha_flow_table_entry *e)
{
	struct airoha_flow_table_entry *sub;
	struct hlist_node *n;
	int err;

	lockdep_assert_held(&ppe_lock);
	hlist_for_each_entry_safe(sub, n, &e->l2_flows, l2_subflow_node) {
		err = airoha_ppe_foe_remove_flow(ppe, sub);
		if (err)
			return err;
	}
	return rhashtable_remove_fast(&ppe->l2_flows, &e->l2_node,
				     airoha_l2_flow_table_params);
}
'''

REMOVE_ENTRY = r'''static int airoha_ppe_foe_flow_remove_entry(struct airoha_ppe *ppe,
					    struct airoha_flow_table_entry *e)
{
	int err;

	/* TC owns parents only. remove_flow frees a child immediately, so it
	 * must never be followed by accesses through this parent cleanup path. */
	if (WARN_ON_ONCE(e->type == FLOW_TYPE_L2_SUBFLOW))
		return -EINVAL;
	spin_lock_bh(&ppe_lock);
	if (e->lifetime_retired) {
		err = 0;
		goto unlock;
	}
	if (e->type == FLOW_TYPE_L2)
		err = airoha_ppe_foe_remove_l2_flow(ppe, e);
	else
		err = airoha_ppe_foe_remove_flow(ppe, e);
	if (!err) {
		hlist_del_init(&e->ingress_node);
		hlist_del_init(&e->wlan_node);
		e->lifetime_retired = true;
	}
unlock:
	spin_unlock_bh(&ppe_lock);
	return err;
}
'''

WIRED_EVENT = r'''static int
airoha_ppe_wired_l4_event(struct airoha_ppe *ppe,
			struct airoha_flow_table_entry *e,
			struct net_device *netdev, bool unregister)
{
	int err;

	if (!e->wired_l4 ||
	    (!airoha_ppe_wired_depends_on(e->ingress_dev, netdev) &&
	     !airoha_ppe_wired_depends_on(e->wired_egress_dev, netdev)))
		return 0;
	e->wired_dead = true;
	err = airoha_ppe_foe_unbind_flow(ppe, e);
	if (err || !unregister)
		return err;
	if (e->ingress_dev == netdev) {
		dev_put(e->ingress_dev);
		e->ingress_dev = NULL;
	}
	if (e->wired_egress_dev == netdev) {
		dev_put(e->wired_egress_dev);
		e->wired_egress_dev = NULL;
	}
	return 0;
}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base', type=Path, required=True)
    p.add_argument('--reference', type=Path, required=True)
    p.add_argument('--work', type=Path, required=True)
    p.add_argument('--patch', type=Path, required=True)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not w.name.startswith('be6l-ppe-lifetime-port-20261111-') or w.exists():
        p.error('Fresh private /root/be6l-ppe-lifetime-port-20261111-* required')
    base = a.base/'drivers/net/ethernet/airoha'
    raw = (base/'airoha_ppe.c').read_bytes()
    refraw = (a.reference/'airoha_ppe.c').read_bytes()
    if hashlib.sha256(raw).hexdigest() != PPE_PIN or hashlib.sha256(refraw).hexdigest() != REF_PIN:
        raise ValueError('Pinned base or reference mismatch')
    original = {name:(base/name).read_text() for name in ('airoha_ppe.c','airoha_eth.h','airoha_eth.c')}
    s = original['airoha_ppe.c']
    ref = refraw.decode()
    smac = '\n'.join(function(ref, n).replace('ppe->common.eth', 'ppe->eth') for n in
        ('airoha_ppe_smac_write','airoha_ppe_smac_get','airoha_ppe_smac_put'))
    # Existing source has no declarations depending on these helpers before the
    # first use. Inserting immediately before write_failed preserves that order.
    anchor = function(s,'airoha_ppe_foe_write_failed')
    s = replace(s, anchor, smac+'\n'+WITHDRAW+'\n'+anchor)
    s = edit_func(s,'airoha_ppe_foe_write_failed', lambda t: replace(t,
        '\tint i;\n', '\tint i;\n\n\tppe->foe_failed = true;\n'))
    s = replace(s, '/* A timed out write may have reached hardware. Stop forwarding before\n\t * releasing its software owner or any referenced destination.\n\t */',
        '/* Containment only: clearing EN is NOT withdrawal/drain proof.\n\t * Preserve the owner and every resource until the provider succeeds.\n\t */')
    for name, body in (('airoha_ppe_foe_unbind_flow',UNBIND),
                       ('airoha_ppe_foe_remove_flow',REMOVE),
                       ('airoha_ppe_foe_release_slot',RELEASE),
                       ('airoha_ppe_foe_remove_l2_flow',REMOVE_PARENT),
                       ('airoha_ppe_foe_flow_remove_entry',REMOVE_ENTRY),
                       ('airoha_ppe_wired_l4_event',WIRED_EVENT)):
        s = edit_func(s,name,lambda _, body=body:body)

    def subflow(t):
        t = replace(t, '\tairoha_ppe_foe_release_slot(ppe, hash);\n',
            '\tif (airoha_ppe_foe_slot_busy(ppe, NULL, hash)) {\n\t\tkfree(f);\n\t\treturn -EBUSY;\n\t}\n'
            '\t/* Publish the physical owner and parent link before a write can\n'
            '\t * reach hardware, including a timed out write. */\n'
            '\tf->data = hwe;\n\tf->type = FLOW_TYPE_L2_SUBFLOW;\n'
            '\tairoha_ppe_foe_reserve_slot(ppe, f, hash);\n'
            '\thlist_add_head(&f->l2_subflow_node, &e->l2_flows);\n')
        t = replace(t, '\t\tairoha_ppe_foe_write_failed(ppe, err);\n\t\tkfree(f);\n',
            '\t\tairoha_ppe_foe_write_failed(ppe, err);\n')
        t = replace(t, '\tf->data = hwe;\n\tf->type = FLOW_TYPE_L2_SUBFLOW;\n\tf->hash = hash;\n\tppe->foe_owner[hash] = f;\n\thlist_add_head(&f->l2_subflow_node, &e->l2_flows);\n', '')
        return replace(t, '    0xf);', '    AIROHA_FOE_SMAC_KEEP);')
    s = edit_func(s,'airoha_ppe_foe_commit_subflow_entry',subflow)

    def insert(t):
        t = replace(t, '\tu32 index, state;', '\tu32 index, state;\n\tint err;')
        t = replace(t, '\tspin_lock_bh(&ppe_lock);\n',
            '\tspin_lock_bh(&ppe_lock);\n\tif (ppe->stopping || ppe->foe_failed ||\n'
            '\t    (airoha_is_7563(ppe->eth) && !ppe->lifetime_ready))\n\t\tgoto unlock;\n')
        t = replace(t, '\t\t\t\tairoha_ppe_foe_remove_flow(ppe, e);',
            '\t\t\t\tif (airoha_ppe_foe_remove_flow(ppe, e))\n\t\t\t\t\tgoto unlock;')
        t = replace(t, '\t\tairoha_ppe_foe_unbind_flow(ppe, e);\n\t\tairoha_ppe_foe_release_slot(ppe, hash);\n'
            '\t\tif (airoha_ppe_foe_commit_entry(ppe, &e->data, hash, rx_wlan)) {\n'
            '\t\t\tairoha_ppe_foe_write_failed(ppe, -EIO);',
            '\t\t/* One physical owner per software flow. Never steal a slot. */\n'
            '\t\tif (airoha_ppe_foe_slot_busy(ppe, e, hash) || e->hash != 0xffff)\n\t\t\tcontinue;\n'
            '\t\tairoha_ppe_foe_reserve_slot(ppe, e, hash);\n'
            '\t\terr = airoha_ppe_foe_commit_entry(ppe, &e->data, hash, rx_wlan);\n'
            '\t\tif (err) {\n\t\t\tairoha_ppe_foe_write_failed(ppe, err);')
        return replace(t, '\t\te->hash = hash;\n\t\tppe->foe_owner[hash] = e;\n', '')
    s = edit_func(s,'airoha_ppe_foe_insert_entry',insert)
    s = edit_func(s,'airoha_ppe_foe_flow_commit_entry',lambda t:replace(t,
        '\tspin_lock_bh(&ppe_lock);\n',
        '\tspin_lock_bh(&ppe_lock);\n\tif (ppe->stopping || ppe->foe_failed ||\n'
        '\t    (airoha_is_7563(ppe->eth) && !ppe->lifetime_ready)) {\n'
        '\t\tret = -EOPNOTSUPP;\n\t\tgoto unlock;\n\t}\n'))

    def flush_entry(t):
        t = replace(t, '\t\t\tairoha_ppe_foe_unbind_flow(ppe, e);',
            '\t\t\terr = airoha_ppe_foe_unbind_flow(ppe, e);')
        return replace(t, '\t\tairoha_ppe_foe_remove_flow(ppe, sub);',
            '\t\terr = airoha_ppe_foe_remove_flow(ppe, sub);\n\t\tif (err)\n\t\t\treturn err;')
    s = edit_func(s,'airoha_ppe_flush_wdma_entry',flush_entry)
    s = edit_func(s,'airoha_ppe_flush_wdma_failed',lambda t:replace(t,
        '\tint i;', '\tint i;\n\n\tppe->foe_failed = true;'))

    def flush(t):
        t = replace(t, '\t\t\t    (key[1] & 0xffff) == wcid + 1)\n\t\t\t\tairoha_ppe_foe_release_slot(ppe, hash);',
            '\t\t\t    (key[1] & 0xffff) == wcid + 1) {\n'
            '\t\t\t\terr = airoha_ppe_foe_release_slot(ppe, hash);\n'
            '\t\t\t\tif (err)\n\t\t\t\t\tgoto failed;\n\t\t\t}')
        return replace(t,'\tif (err)\n\t\tairoha_ppe_flush_wdma_failed(ppe, err);',
            'failed:\n\tif (err)\n\t\tairoha_ppe_flush_wdma_failed(ppe, err);')
    s = edit_func(s,'airoha_ppe_flush_wdma',flush)

    def notifier(t):
        t = replace(t,'\thlist_for_each_entry(e, &ppe->ingress_flows, ingress_node)\n'
            '\t\tairoha_ppe_wired_l4_event(ppe, e, netdev,\n\t\t\t\t\t  event == NETDEV_UNREGISTER);',
            '\thlist_for_each_entry(e, &ppe->ingress_flows, ingress_node) {\n'
            '\t\terr = airoha_ppe_wired_l4_event(ppe, e, netdev,\n'
            '\t\t\t\t\t       event == NETDEV_UNREGISTER);\n\t\tif (err)\n\t\t\tgoto unlock;\n\t}')
        t = replace(t,'\t\thlist_for_each_entry_safe(sub, next, &e->l2_flows, l2_subflow_node)\n'
            '\t\t\tairoha_ppe_foe_remove_flow(ppe, sub);',
            '\t\thlist_for_each_entry_safe(sub, next, &e->l2_flows, l2_subflow_node) {\n'
            '\t\t\terr = airoha_ppe_foe_remove_flow(ppe, sub);\n\t\t\tif (err)\n\t\t\t\tgoto unlock;\n\t\t}')
        t = replace(t,'\t\tif (err)\n\t\t\tairoha_ppe_flush_wdma_failed(ppe, err);',
            '\t\tif (err) {\n\t\t\tairoha_ppe_flush_wdma_failed(ppe, err);\n\t\t\tgoto unlock;\n\t\t}')
        return replace(t,'\treturn NOTIFY_DONE;\n}',
            '\t/* NETDEV_UNREGISTER cannot be vetoed here. Retention prevents an\n'
            '\t * early put, but a provider is required to avoid stalled unregister.\n'
            '\t * This unresolved boundary is why native admission is hard closed. */\n'
            '\treturn NOTIFY_DONE;\n}')
    s = edit_func(s,'airoha_ppe_netdevice_event',notifier)
    s = edit_func(s,'airoha_ppe_foe_flow_entry_update',lambda t:replace(t,
        '\t\tif (ppe->foe_owner[e->hash] == e)\n\t\t\tppe->foe_owner[e->hash] = NULL;\n\t\te->hash = 0xffff;',
        '\t\t/* A mismatching tuple is not withdrawal proof. Keep identity. */\n'
        '\t\tairoha_ppe_foe_write_failed(ppe, -ESTALE);'))
    s = edit_func(s,'airoha_ppe_foe_flow_l2_entry_update',lambda t:replace(t,
        '\t\t\tairoha_ppe_foe_remove_flow(ppe, iter);',
        '\t\t\tif (airoha_ppe_foe_remove_flow(ppe, iter))\n\t\t\t\treturn;'))

    def tc_replace(t):
        t = replace(t, '\terr = airoha_ppe_foe_flow_commit_entry(eth->ppe, e);\n\tif (err)\n\t\tgoto free_entry;\n\n'
            '\terr = rhashtable_insert_fast(&eth->flow_table, &e->node,\n'
            '\t\t\t\t     airoha_flow_table_params);\n\tif (err < 0)\n\t\tgoto remove_foe_entry;',
            '\tif (airoha_is_7563(eth)) {\n'
            '\t\terr = airoha_ppe_smac_get(eth->ppe, e, data.eth.h_source);\n'
            '\t\tif (err)\n\t\t\tgoto free_entry;\n\t}\n'
            '\t/* Cookie must exist before RX can discover the pending owner. */\n'
            '\terr = rhashtable_insert_fast(&eth->flow_table, &e->node,\n'
            '\t\t\t\t     airoha_flow_table_params);\n\tif (err)\n\t\tgoto free_entry;\n'
            '\terr = airoha_ppe_foe_flow_commit_entry(eth->ppe, e);\n'
            '\tif (err)\n\t\tgoto remove_cookie;')
        t = replace(t, 'remove_foe_entry:\n\tairoha_ppe_foe_flow_remove_entry(eth->ppe, e);',
            'remove_cookie:\n\t/* A failed software publication has not inserted an RX-visible list. */\n'
            '\trhashtable_remove_fast(&eth->flow_table, &e->node,\n\t\t\t       airoha_flow_table_params);')
        return replace(t,'free_entry:\n','free_entry:\n\tairoha_ppe_smac_put(eth->ppe, e);\n')
    s = edit_func(s,'airoha_ppe_flow_offload_replace',tc_replace)

    def destroy(t):
        t = replace(t,'\tstruct airoha_flow_table_entry *e;','\tstruct airoha_flow_table_entry *e;\n\tint err;')
        t = replace(t,'\tairoha_ppe_foe_flow_remove_entry(eth->ppe, e);',
            '\terr = airoha_ppe_foe_flow_remove_entry(eth->ppe, e);\n\tif (err)\n\t\treturn err;')
        return replace(t,'\tairoha_ppe_flow_entry_put_devs(e);','\tairoha_ppe_smac_put(eth->ppe, e);\n\tairoha_ppe_flow_entry_put_devs(e);')
    s = edit_func(s,'airoha_ppe_flow_offload_destroy',destroy)
    s = edit_func(s,'airoha_ppe_free_flow',lambda t:replace(t,
        '\tairoha_ppe_foe_flow_remove_entry(ppe, e);',
        '\t/* Deinit must preflight all entries before destructive hash teardown.\n'
        '\t * A void callback cannot restore a cookie that has already gone. */\n'
        '\tif (WARN_ON_ONCE(airoha_ppe_foe_flow_remove_entry(ppe, e)))\n\t\treturn;\n'
        '\tairoha_ppe_smac_put(ppe, e);'))
    # Preflight owns the same control-plane mutex as TC replace/destroy. It may
    # remove successfully drained children, but never destroys the TC table on
    # partial failure. This is necessary, not sufficient: platform remove still
    # needs a fallible withdrawal/reset contract, so native remains gated off.
    preflight = r'''
static int airoha_ppe_lifetime_preflight(struct airoha_eth *eth)
{
	struct rhashtable_iter iter;
	struct airoha_flow_table_entry *e;
	int err = 0;

	rhashtable_walk_enter(&eth->flow_table, &iter);
	rhashtable_walk_start(&iter);
	while ((e = rhashtable_walk_next(&iter))) {
		if (IS_ERR(e)) {
			if (PTR_ERR(e) == -EAGAIN)
				continue;
			err = PTR_ERR(e);
			break;
		}
		err = airoha_ppe_foe_flow_remove_entry(eth->ppe, e);
		if (err)
			break;
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
	return err;
}
'''
    old = function(s,'airoha_ppe_deinit')
    new = replace(old,'\tbe6l_diag_driver_stop(eth->ppe);',
        '\t/* Stop new RX bindings before dropping the notifier/control owner. */\n'
        '\tspin_lock_bh(&ppe_lock);\n\teth->ppe->stopping = true;\n\tspin_unlock_bh(&ppe_lock);\n'
        '\tbe6l_diag_driver_stop(eth->ppe);')
    new = replace(new,'\tmutex_lock(&flow_offload_mutex);',
        '\tmutex_lock(&flow_offload_mutex);\n'
        '\tif (airoha_ppe_lifetime_preflight(eth)) {\n'
        '\t\t/* BLOCKED: this void remove interface cannot stop devres freeing\n'
        '\t\t * resources. Returning is containment, not an unload solution.\n'
        '\t\t * Native admission MUST remain disabled until provider integration. */\n'
        '\t\tdev_err(eth->dev, "PPE withdrawal missing: draft cannot unload safely\\n");\n'
        '\t\tmutex_unlock(&flow_offload_mutex);\n\t\treturn;\n\t}')
    s = replace(s,old,preflight+'\n'+new)
    # Exact source initializer anchor avoids relying only on kzalloc defaults.
    s = edit_func(s,'airoha_ppe_init',lambda t:replace(t,
        '\tppe->eth = eth;',
        '\tppe->eth = eth;\n\tspin_lock_init(&ppe->smac_lock);\n'
        '\t/* No native enable path until notifier/devres withdrawal is complete. */\n'
        '\tppe->lifetime_ready = false;\n'))

    h = original['airoha_eth.h']
    h = replace(h,'\t/* Must be last --ends in a flexible-array member. */',
        '\tbool smac_ref, lifetime_retired;\n\t/* Must be last --ends in a flexible-array member. */')
    h = replace(h,'struct airoha_ppe {',
        '#define AIROHA_FOE_SMAC_KEEP 0xf\n#define AIROHA_PPE_SMAC_SLOTS AIROHA_FOE_SMAC_KEEP\n'
        'struct airoha_ppe_smac {\n\tu8 addr[ETH_ALEN];\n\tu32 refs;\n\tbool valid;\n};\n\n'
        'struct airoha_ppe {\n\tspinlock_t smac_lock;\n'
        '\tstruct airoha_ppe_smac smac[AIROHA_PPE_SMAC_SLOTS];\n'
        '\tbool smac_failed, foe_failed, stopping;\n'
        '\t/* Deliberately false; no setter in an unadmitted source draft. */\n\tbool lifetime_ready;')
    ethc = replace(original['airoha_eth.c'],'\tairoha_ppe_init_upd_mem(dev, addr);',
        '\tif (!airoha_is_7563(eth))\n\t\tairoha_ppe_init_upd_mem(dev, addr);')
    modified = {'airoha_ppe.c':s,'airoha_eth.h':h,'airoha_eth.c':ethc}
    w.mkdir(mode=0o700)
    target = w/'source/drivers/net/ethernet/airoha'
    shutil.copytree(base,target)
    for name, value in modified.items():
        (target/name).write_text(value)
    patch = ''.join(''.join(difflib.unified_diff(original[name].splitlines(True), value.splitlines(True),
        fromfile='a/drivers/net/ethernet/airoha/'+name, tofile='b/drivers/net/ethernet/airoha/'+name))
        for name, value in modified.items())
    patch = ('From: BE6L source research\nSubject: [DRAFT NOT ADMITTED] Stage X-Wrt941-04 PPE ownership port\n\n'
        'SMAC routines adapted from X-Wrt 941-04, GPL-2.0-only (same driver license).\n'
        'Native binding is hard gated. AN7552/AN7563 withdrawal provider and fallible\n'
        'platform removal remain missing; clear/ACK/RCU/delay are not DMA fences.\n'
        'Do not add to series or any candidate. Software fixtures are not target proof.\n\n'+patch)
    if a.patch.exists() and not a.patch.read_text().startswith(
            'From: BE6L source research\nSubject: [DRAFT NOT ADMITTED]'):
        raise ValueError('Refusing to replace an unrelated patch')
    a.patch.parent.mkdir(parents=True,exist_ok=True)
    a.patch.write_text(patch)
    receipt = dict(base_ppe_sha256=PPE_PIN,reference_ppe_sha256=REF_PIN,
        source=str(target),patch=str(a.patch),
        modified_sha256={n:hashlib.sha256(v.encode()).hexdigest() for n,v in modified.items()},
        xwrt_94104_complete_port=False,native_binding_admitted=False,
        hardware_withdrawal_qualified=False,target_executed=False,
        unresolved=['AN7552/AN7563 physical FOE/output DMA withdrawal provider',
            'NETDEV_UNREGISTER bounded completion under RTNL without retained-ref stall',
            'fallible platform remove/devres/IRQ/RX/NPU exit integration',
            'full kernel/module candidate and physical fault validation'])
    (w/'preparation.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print('PPE_LIFETIME_DRAFT_PREPARED',json.dumps(receipt),flush=True)


if __name__ == '__main__':
    main()
