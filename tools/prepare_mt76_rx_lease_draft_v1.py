# SPDX-License-Identifier: MIT
"""Prepare a real mt76 source draft; no candidate, hardware or ALL-provider admission.

The source patch uses a real per-RX-cache sidecar, not invented skb->cb space.
It deliberately never reuses a retired WCID within a device epoch. Consequently
capacity and recovery are restricted until a genuine covering provider exists.
"""
from pathlib import Path
import argparse
import difflib
import hashlib
import json
import shutil
from test_xwrt_sram_policy_v1 import function

PINS = {'mac80211.c':'0646b55c7d330b793e216878ef1efe733ecc840f912e6a39b16d6fc0ec5cce61',
        'mt76.h':'e00a7864d9f28a37deaeee2915e2c5d7968f46b1413a3a9bc64fd431f51c736c',
        'mt7996/main.c':'d175833ff1533eb420e77b82565930cbda9e1abb38e06bee2a2a3bb7f5270269',
        'mt7996/init.c':'b4bc0441252ce4bd14046f6d3fea38ad501b296e92854cc11dd1ab05143d6dde',
        'npu.c':'c526fc278e834b17abca8b7e43502c16958e7a31c690ad6388a782e2a48b2371'}


def one(s, old, new):
    if s.count(old)!=1:
        raise ValueError(f'Anchor count {s.count(old)}: {old[:100]!r}')
    return s.replace(old,new,1)


def edit(s, name, transform):
    old=function(s,name)
    return one(s,old,transform(old))


OWNER = r'''
/* DRAFT: CPU-cache owner and numeric lease, not a DMA-drain provider. */
bool mt76_rx_lease_native_ready(struct mt76_dev *dev)
{
	/* No setter: ALL wired/native/output/remove coverage is not implemented. */
	return false;
}
EXPORT_SYMBOL_GPL(mt76_rx_lease_native_ready);

static void mt76_rx_lease_put(struct mt76_rx_lease *lease)
{
	if (lease && refcount_dec_and_test(&lease->refs))
		kfree(lease);
}

int mt76_rx_lease_prepare(struct mt76_dev *dev, struct mt76_wcid *wcid,
			 u16 idx, u8 band, const u8 *addr)
{
	struct mt76_rx_lease *lease;
	u64 epoch;

	lockdep_assert_held(&dev->mutex);
	if (!dev->rx_lease_enabled)
		return 0;
	if (idx >= MT76_N_WCIDS)
		return -EINVAL;
	if (dev->rx_retired[idx] || rcu_access_pointer(wcid->rx_lease))
		return -EBUSY;
	if (dev->rx_lease_epoch == U64_MAX)
		return -EOVERFLOW;
	lease = kzalloc(sizeof(*lease), GFP_KERNEL);
	if (!lease)
		return -ENOMEM;
	epoch = ++dev->rx_lease_epoch;
	refcount_set(&lease->refs, 1); /* Transferred to retired[] on removal. */
	atomic_set(&lease->live, 1);
	lease->idx = idx;
	lease->band = band;
	lease->epoch = epoch;
	ether_addr_copy(lease->addr, addr);
	/* Allocation and copied identity precede the real WCID publication. */
	rcu_assign_pointer(wcid->rx_lease, lease);
	return 0;
}
EXPORT_SYMBOL_GPL(mt76_rx_lease_prepare);

void mt76_rx_lease_retire(struct mt76_dev *dev, struct mt76_wcid *wcid)
{
	struct mt76_rx_lease *lease;

	lockdep_assert_held(&dev->mutex);
	lease = rcu_dereference_protected(wcid->rx_lease,
					lockdep_is_held(&dev->mutex));
	if (!lease)
		return;
	/* Revoke before normal table unpublication. A reader which already
	 * borrowed a real WCID stays inside the pre-existing RX RCU span. */
	atomic_set(&lease->live, 0);
	if (WARN_ON_ONCE(dev->rx_retired[lease->idx]))
		return; /* Invariant violation cannot authorize number reuse. */
	dev->rx_retired[lease->idx] = lease;
	RCU_INIT_POINTER(wcid->rx_lease, NULL);
	/* No put: untagged late completions carry only idx. Keep it unavailable
	 * for this device epoch; ALL provider support is intentionally absent. */
}
EXPORT_SYMBOL_GPL(mt76_rx_lease_retire);

static struct mt76_rx_lease *
mt76_rx_lease_capture(struct mt76_wcid *wcid)
{
	struct mt76_rx_lease *lease;

	RCU_LOCKDEP_WARN(!rcu_read_lock_held(), "RX lease capture outside RCU");
	lease = rcu_dereference(wcid->rx_lease);
	if (!lease || !atomic_read(&lease->live) ||
	    !refcount_inc_not_zero(&lease->refs))
		return NULL;
	return lease;
}

static bool mt76_rx_lease_resolve(struct mt76_dev *dev,
				struct mt76_rx_lease *lease,
				struct mt76_wcid **result)
{
	struct mt76_wcid *wcid;

	RCU_LOCKDEP_WARN(!rcu_read_lock_held(), "RX lease resolve outside RCU");
	*result = NULL;
	if (!lease)
		return true; /* Original packet had no station identity. */
	if (!atomic_read(&lease->live) || lease->idx >= MT76_N_WCIDS)
		return false;
	wcid = rcu_dereference(dev->wcid[lease->idx]);
	if (!wcid || rcu_access_pointer(wcid->rx_lease) != lease)
		return false;
	*result = wcid;
	return true;
}

void mt76_rx_lease_purge(struct mt76_dev *dev)
{
	int band, q;

	/* Caller must mask/synchronize IRQs, disable NAPI and synchronize_net
	 * first. This routine does not create any of those guarantees itself.
	 * mt7996_cleanup_device supplies that CPU boundary before calling. */
	for (band = 0; band <= ARRAY_SIZE(dev->phys); band++) {
		struct mt76_phy *phy = band ? dev->phys[band - 1] : &dev->phy;

		if (!phy || (band && phy == &dev->phy))
			continue;
		for (q = 0; q < ARRAY_SIZE(phy->rx_amsdu); q++) {
			struct sk_buff *skb = phy->rx_amsdu[q].head;
			struct mt76_rx_lease *lease = phy->rx_amsdu[q].lease;

			phy->rx_amsdu[q].head = NULL;
			phy->rx_amsdu[q].tail = NULL;
			phy->rx_amsdu[q].lease = NULL;
			if (skb)
				dev_kfree_skb(skb);
			mt76_rx_lease_put(lease);
		}
	}
}
EXPORT_SYMBOL_GPL(mt76_rx_lease_purge);

static void mt76_rx_lease_cleanup(struct mt76_dev *dev)
{
	int idx;

	/* CPU metadata only. This is NOT an ALL output-resource/reset fence and
	 * cannot veto Linux's void remove/devres release. Draft remains unadmitted.
	 * Cache callbacks must already be stopped; leases contain no dev pointer. */
	mt76_rx_lease_purge(dev);
	synchronize_rcu();
	for (idx = 0; idx < ARRAY_SIZE(dev->rx_retired); idx++) {
		mt76_rx_lease_put(dev->rx_retired[idx]);
		dev->rx_retired[idx] = NULL;
	}
}
'''

BURST = r'''static void mt76_rx_release_burst(struct mt76_phy *phy, enum mt76_rxq_id q,
				  struct sk_buff *skb)
{
	struct mt76_rx_status *status = (struct mt76_rx_status *)skb->cb;
	struct mt76_dev *dev = phy->dev;
	struct mt76_rx_lease *lease = NULL;

	if (dev->rx_lease_enabled) {
		struct mt76_wcid *wcid = status->wcid;

		/* Actual storage is the queue sidecar, not added skb->cb bytes.
		 * Every cached frame's pointer is erased before a poll can end. */
		if (wcid) {
			lease = mt76_rx_lease_capture(wcid);
			if (!lease) {
				/* A non-station/vif WCID has no owner in this draft.
				 * Do not retain a borrowed pointer as a fallback. */
				dev_kfree_skb(skb);
				return;
			}
		}
		status->wcid = NULL;
	}

	if (phy->rx_amsdu[q].head &&
	    (!status->amsdu || status->first_amsdu ||
	     status->seqno != phy->rx_amsdu[q].seqno ||
	     (dev->rx_lease_enabled && phy->rx_amsdu[q].lease != lease)))
		mt76_rx_release_amsdu(phy, q);

	if (!phy->rx_amsdu[q].head) {
		phy->rx_amsdu[q].tail = &skb_shinfo(skb)->frag_list;
		phy->rx_amsdu[q].seqno = status->seqno;
		phy->rx_amsdu[q].head = skb;
		phy->rx_amsdu[q].lease = lease;
	} else {
		*phy->rx_amsdu[q].tail = skb;
		phy->rx_amsdu[q].tail = &skb->next;
		/* A single independently referenced owner covers this same-peer
		 * fragment chain. No fragment carries a raw station pointer. */
		mt76_rx_lease_put(lease);
	}

	if (!status->amsdu || status->last_amsdu)
		mt76_rx_release_amsdu(phy, q);
}
'''


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('source','work','patch'):
        p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();w=a.work.resolve()
    if w.parent!=Path('/root') or not w.name.startswith('be6l-mt76-rx-lease-draft-20261113-') or w.exists():
        p.error('Fresh private /root/be6l-mt76-rx-lease-draft-20261113-* required')
    names=('mt76.h','mac80211.c','mt7996/main.c','mt7996/init.c','npu.c')
    original={n:(a.source/n).read_text() for n in names}
    for n,pin in PINS.items():
        if pin and hashlib.sha256((a.source/n).read_bytes()).hexdigest()!=pin:
            raise ValueError('Pinned source mismatch: '+n)
    h=original['mt76.h']
    h=one(h,'struct mt76_wcid {',
        '/* Independent CPU-cache metadata. No station/device/key pointers. */\n'
        'struct mt76_rx_lease {\n\trefcount_t refs;\n\tatomic_t live;\n'
        '\tu64 epoch;\n\tu16 idx;\n\tu8 band, addr[ETH_ALEN];\n};\n\n'
        'struct mt76_wcid {\n\tstruct mt76_rx_lease __rcu *rx_lease;')
    h=one(h,'\t} rx_amsdu[__MT_RXQ_MAX];','\t\tstruct mt76_rx_lease *lease;\n\t} rx_amsdu[__MT_RXQ_MAX];')
    h=one(h,'\tstruct mt76_wcid global_wcid;',
        '\t/* DRAFT: no retired number reuse without a covering ALL provider. */\n'
        '\tbool rx_lease_enabled;\n\tu64 rx_lease_epoch;\n'
        '\tstruct mt76_rx_lease *rx_retired[MT76_N_WCIDS];\n\n\tstruct mt76_wcid global_wcid;')
    h=one(h,'void mt76_free_device(struct mt76_dev *dev);',
        'void mt76_free_device(struct mt76_dev *dev);\n'
        'bool mt76_rx_lease_native_ready(struct mt76_dev *dev);\n'
        'int mt76_rx_lease_prepare(struct mt76_dev *dev, struct mt76_wcid *wcid,\n'
        '\t\t\t  u16 idx, u8 band, const u8 *addr);\n'
        'void mt76_rx_lease_retire(struct mt76_dev *dev, struct mt76_wcid *wcid);\n'
        'void mt76_rx_lease_purge(struct mt76_dev *dev);')
    c=original['mac80211.c']
    anchor=function(c,'mt76_free_device');c=one(c,anchor,OWNER+'\n'+anchor)
    c=edit(c,'mt76_free_device',lambda t:one(t,'\tieee80211_free_hw(dev->hw);',
        '\tif (dev->rx_lease_enabled)\n\t\tmt76_rx_lease_cleanup(dev);\n\tieee80211_free_hw(dev->hw);'))
    c=edit(c,'mt76_reset_device',lambda t:one(t,'\t\twcid->sta = 0;',
        '\t\tif (dev->rx_lease_enabled)\n\t\t\tmt76_rx_lease_retire(dev, wcid);\n\t\twcid->sta = 0;'))
    release=function(c,'mt76_rx_release_amsdu')
    release=one(release,'\tstruct mt76_queue *rxq = &dev->q_rx[q];',
        '\tstruct mt76_queue *rxq = &dev->q_rx[q];\n'
        '\tstruct mt76_rx_lease *lease = phy->rx_amsdu[q].lease;\n'
        '\tstruct mt76_wcid *wcid;\n\tstruct sk_buff *frame;')
    release=one(release,'\tphy->rx_amsdu[q].tail = NULL;',
        '\tphy->rx_amsdu[q].tail = NULL;\n\tphy->rx_amsdu[q].lease = NULL;\n\n'
        '\tif (dev->rx_lease_enabled) {\n'
        '\t\t/* Never restore a raw pointer onto a different RRO poll queue. */\n'
        '\t\tif ((mt76_queue_is_wed_rro_data(rxq) &&\n'
        '\t\t     dev->hwrro_mode == MT76_HWRRO_V3) ||\n'
        '\t\t    !mt76_rx_lease_resolve(dev, lease, &wcid)) {\n'
        '\t\t\tmt76_rx_lease_put(lease);\n\t\t\tdev_kfree_skb(skb);\n\t\t\treturn;\n\t\t}\n'
        '\t\t/* Same poll/RCU span must extend through rx_poll_complete. */\n'
        '\t\tfor (frame = skb; frame;\n'
        '\t\t     frame = frame == skb ? skb_shinfo(skb)->frag_list : frame->next)\n'
        '\t\t\t((struct mt76_rx_status *)frame->cb)->wcid = wcid;\n'
        '\t\tmt76_rx_lease_put(lease);\n\t}')
    c=edit(c,'mt76_rx_release_amsdu',lambda _:release)
    c=edit(c,'mt76_rx_release_burst',lambda _:BURST)
    main=original['mt7996/main.c']
    def init_link(t):
        t=one(t,'\tint idx;','\tint idx, err;')
        t=one(t,'\tif (msta->reset_wcid[link_id]) {',
            '\tif (msta->reset_wcid[link_id] &&\n'
            '\t    dev->mt76.rx_retired[msta->reset_wcid[link_id] - 1])\n'
            '\t\treturn -EOPNOTSUPP; /* Full ALL-reset proof still missing. */\n'
            '\tif (msta->reset_wcid[link_id]) {')
        t=one(t,'\t\t} while (dev->mt76.mmio.an7552 &&\n\t\t\t test_bit(idx, dev->npu_rx_retired));',
            '\t\t} while (dev->mt76.rx_retired[idx] ||\n'
            '\t\t\t (dev->mt76.mmio.an7552 &&\n\t\t\t  test_bit(idx, dev->npu_rx_retired)));')
        t=one(t,'\tif (msta->deflink_id == IEEE80211_LINK_UNSPECIFIED)',
            '\terr = mt76_rx_lease_prepare(&dev->mt76, &msta_link->wcid, idx,\n'
            '\t\t\t\t    phy->mt76->band_idx, link_sta->addr);\n'
            '\tif (err) {\n\t\tif (msta_link != &msta->deflink)\n\t\t\tkfree(msta_link);\n'
            '\t\tmt76_wcid_mask_clear(dev->mt76.wcid_mask, idx);\n\t\treturn err;\n\t}\n\n'
            '\tif (msta->deflink_id == IEEE80211_LINK_UNSPECIFIED)')
        return t
    main=edit(main,'mt7996_mac_sta_init_link',init_link)
    main=edit(main,'mt7996_mac_sta_add_links',lambda t:one(t,
        '\t\tif (msta_link) {\n\t\t\tmsta_link->wcid.link_valid = true;',
        '\t\tif (msta_link) {\n'
        '\t\t\tif (dev->mt76.rx_retired[msta_link->wcid.idx]) {\n'
        '\t\t\t\terr = -EOPNOTSUPP;\n\t\t\t\tgoto error_unlink;\n\t\t\t}\n'
        '\t\t\tmsta_link->wcid.link_valid = true;'))
    main=edit(main,'mt7996_mac_sta_remove_link',lambda t:one(t,
        '\tif (dev->recovery.hw_full_reset)\n',
        '\t/* This cannot veto mac80211 free: retire copied metadata instead. */\n'
        '\tmt76_rx_lease_retire(&dev->mt76, &msta_link->wcid);\n\n'
        '\tif (dev->recovery.hw_full_reset)\n'))
    main=edit(main,'mt7996_mac_sta_remove_link',lambda t:one(t,
        '\t\tif (!dev->mt76.mmio.an7552 ||\n\t\t    !test_bit(msta_link->wcid.idx, dev->npu_rx_retired))',
        '\t\tif (!dev->mt76.rx_retired[msta_link->wcid.idx] &&\n'
        '\t\t    (!dev->mt76.mmio.an7552 ||\n\t\t     !test_bit(msta_link->wcid.idx, dev->npu_rx_retired)))'))
    main=edit(main,'mt7996_sta_pre_rcu_remove',lambda t:one(t,
        '\t\tif (msta_link)\n\t\t\trcu_assign_pointer',
        '\t\tif (msta_link)\n\t\t\tmt76_rx_lease_retire(&dev->mt76, &msta_link->wcid);\n'
        '\t\tif (msta_link)\n\t\t\trcu_assign_pointer'))
    init=original['mt7996/init.c']
    init=edit(init,'mt7996_init_wiphy',lambda t:one(t,'\thw->queues = 4;',
        '\tmdev->rx_lease_enabled = is_mt7992(mdev); /* BE6L source draft only. */\n\thw->queues = 4;'))
    init=edit(init,'mt7996_cleanup_device',lambda t:one(t,
        '\ttasklet_kill(&dev->mt76.irq_tasklet);',
        '\ttasklet_kill(&dev->mt76.irq_tasklet);\n'
        '\tmt76_rx_lease_purge(&dev->mt76); /* IRQ/NAPI + synchronize_net above. */'))
    npu=edit(original['npu.c'],'mt76_npu_init',lambda t:one(t,
        '\tif (is_mt7992(dev)) {',
        '\t/* Closed before get/boot: the source draft has no ALL provider. */\n'
        '\tif (is_mt7992(dev) && !mt76_rx_lease_native_ready(dev))\n\t\treturn 0;\n\n'
        '\tif (is_mt7992(dev)) {'))
    modified={'mt76.h':h,'mac80211.c':c,'mt7996/main.c':main,'mt7996/init.c':init,'npu.c':npu}
    w.mkdir(mode=0o700);dest=w/'source'
    shutil.copytree(a.source,dest,ignore=shutil.ignore_patterns('*.o','*.ko','*.mod','*.cmd','*.d'))
    for n,t in modified.items():(dest/n).write_text(t)
    patch='From: BE6L source research\nSubject: [DRAFT NOT ADMITTED] mt76 independent RX cache lease\n\n'
    patch+='Actual per-queue sidecar, closed native admission, no hardware ALL provider.\n'
    patch+='Retired WCIDs are never reused in a device epoch: capacity/reset restrictions.\n'
    patch+='CPU metadata cleanup is not a full void-remove/devres DMA ownership solution.\n\n'
    patch+=''.join(''.join(difflib.unified_diff(original[n].splitlines(True),t.splitlines(True),
        fromfile='a/'+n,tofile='b/'+n)) for n,t in modified.items())
    if a.patch.exists() and not a.patch.read_text().startswith(
            'From: BE6L source research\nSubject: [DRAFT NOT ADMITTED] mt76 independent RX cache lease'):
        raise ValueError('Unrelated draft path already exists')
    a.patch.parent.mkdir(parents=True,exist_ok=True);a.patch.write_text(patch)
    report=dict(source=str(a.source),private_source=str(dest),
        original_sha256={n:hashlib.sha256(t.encode()).hexdigest() for n,t in original.items()},
        modified_sha256={n:hashlib.sha256(t.encode()).hexdigest() for n,t in modified.items()},
        patch_sha256=hashlib.sha256(patch.encode()).hexdigest(),
        actual_queue_sidecar=True,skb_cb_layout_unchanged=True,
        native_admission_closed=True,hardware_all_provider=False,
        numeric_reuse_within_device_epoch=False,full_remove_dma_qualified=False,
        module_abi_qualified=False,target_executed=False,xwrt_lifetime_port_complete=False)
    (w/'preparation.json').write_text(json.dumps(report,indent=2)+'\n')
    print('MT76_RX_LEASE_SOURCE_DRAFT_PREPARED',str(w),flush=True)


if __name__=='__main__':main()
