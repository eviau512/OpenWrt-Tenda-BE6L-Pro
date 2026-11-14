# Actual mt76 RX cache lease source draft

The [new source patch](../patches/next/981-mt76-rx-lease-draft.patch) integrates
an independently allocated owner into a private copy of the exact prepared
mt76 source. Four actual AArch64 driver objects compile against the matching
prepared 6.18.55 kernel/backports. Seventeen source-extracted observations and
eight source-order checks match their expected outcomes, including an expected
unsafe baseline control. The [receipt](evidence/mt76-rx-lease-source-draft-20261113.json)
pins original/modified sources, contextual definitions, tools, compiler commands,
kernel configuration and resulting objects. **This is an unadmitted draft, not
the completed X-Wrt NPU lifetime port or a hardware candidate.** No DUT or active
kernel/module/root tree was changed. The earlier 27+12 model cases were not rerun.

## Real storage and ownership

`mt7996_mac_sta_init_link` calls `mt76_rx_lease_prepare` before either link or
WCID table publication. Allocation failure returns before publication. The
separate heap object contains a reference count, live flag, monotonic host epoch
and copied numeric WCID, band and MAC. It contains **no station, embedded WCID,
key or device pointer**. It is not yet an owner of FOE, SMAC or DMA resources.

The real `phy->rx_amsdu[q]` structure gains one referenced lease sidecar per
cached fragment chain. `struct mt76_rx_status` is byte-for-byte unchanged; this
does not assume free space in `skb->cb`. Capture clears every incoming cached
frame's raw `status->wcid`. A different lease also separates same-sequence
fragments from different peers. At release, retirement or a mismatching current
WCID/lease binding drops the old chain. A valid binding restores the pointer only
inside the current DMA poll's RCU interval, before that poll's receive completion.
The header-error path drops the chain after releasing its sidecar reference.

`mt7996_mac_sta_remove_link`, `sta_pre_rcu_remove` and generic device reset retire
the lease before normal WCID unpublication/cleanup. Retirement transfers the
binding's reference to a device-owned retired array and clears its WCID binding;
it does not retain `drv_priv`. Cached chains can therefore hold independent
metadata after the mac80211-owned station is freed. A local epoch is only copied
metadata: it cannot distinguish two untagged hardware completions carrying the
same index. The actual station allocator and cached-link reactivation path deny
retired indices. They are never authorized for reuse within this device epoch.
`mt76_npu_flush_station` remains void and its errors cannot veto station free.

## CPU concurrency boundary and cleanup

Preparation and retirement assert the existing device mutex. The pre-RCU hook
holds that mutex and the existing status lock. Capture/resolve require an RCU
read-side interval. The existing `mt76_dma_rx_poll` keeps its RCU lock across RX
processing and `mt76_rx_poll_complete`. A borrowed WCID already resolved in that
interval continues to rely on the existing station RCU lifetime; no new lease
reference makes a raw WCID valid outside it. The draft refuses the RRO-v3
cross-queue path instead of putting a restored pointer onto a different poll.

The normal `mt7996_cleanup_device` hook purges primary and secondary PHY caches
after IRQ mask/synchronization, NAPI disable, `synchronize_net` and tasklet kill.
Each cached skb chain and its sidecar reference is released once. Final device
metadata cleanup performs a CPU RCU grace before dropping retired references.
These are CPU boundaries, **not** DMA/output withdrawal. Probe-error unwinds,
all asynchronous/reorder paths and final remove/reprobe are not fully qualified.
In particular, software aggregation in `agg-rx.c` still has its own buffered
skb/work/shutdown lifetime; this patch does not prove every RX raw-pointer path.

## Verification and its limits

The host fixture extracts ten functions directly from the modified source,
including both actual RX cache functions; it also executes the original two RX
functions as controls. It substitutes skb infrastructure, allocation/reference
primitives, RCU/locks and queues. The baseline negative control observes a saved
pointer to a retired stack fixture; it never dereferences actually freed memory
and does not establish a DUT UAF. The controls cover real sidecar storage,
retired/mismatched cache drop, live/mixed-peer fragments, allocation failure,
numeric-reuse denial, epoch overflow, header rejection, RRO rejection, unowned
WCID rejection, idempotent retirement and auxiliary-PHY purge. Final cleanup
asserts every allocated lease was released. These controls found and corrected
an early draft's signed/`ARRAY_SIZE` purge-loop error before this receipt.

The four actual objects are `mac80211.o`, `mt7996/main.o`, `mt7996/init.o` and
`npu.o`. The compiler tool replays the matching saved commands with private
source/output paths, without invoking make or writing prepared build trees.
This checks real kernel types and compilation, not module linking, modversion
or full ABI compatibility. Shared mt76 structures changed; mixing any of these
objects/modules with the old set is forbidden. No kernel candidate was produced.

## Remaining integration boundary

The native init gate returns false before the BE6L native backend is acquired or
booted; it has no enabling setter. The routed gate remains closed. Existing ABI5
scoped token/ring/fenced-park/TDMA primitives retain the limits documented in the
[native audit](NPU-WITHDRAWAL-AUDIT-20261111.md); they do not supply ALL wired
ingress/PSE/GDM/WDMA output, station reuse or void-remove/devres coverage. No ACK,
RCU grace, elapsed delay or panic is used as hardware-drain/recovery evidence.

Before admission, integrate an actual covering withdrawal/reset contract with
the independently owned FOE/SMAC/destination/DMA obligations, setup closure,
completion/IRQ/RX lifetime and no-fail remove/devres boundary. Then complete
probe-error and downstream buffered-work handling, rebuild the entire matching
module set and qualify the real paths. Until then the numeric quarantine can
exhaust WCIDs, full-reset re-add of a retired index fails, nonstation/vif WCIDs
without owners are dropped and RRO-v3 cross-queue traffic is rejected. Device
destruction ends this private CPU owner; it does not establish a safe hardware
epoch boundary for a subsequent probe. This draft must not be applied as a
production fix or treated as completion of the original NPU goal.

Original mt76/OpenWrt authorship and licensing are retained. X-Wrt941-04 remains
the credited PPE/SMAC lifetime reference; this separate RX seam does not replace
that reference or claim the full resource-lifecycle migration is implemented.

Reproduction tools are [prepare](../tools/prepare_mt76_rx_lease_draft_v1.py),
[compile](../tools/compile_mt76_rx_lease_draft_v1.py) and
[source controls](../tools/test_mt76_rx_lease_draft_v1.py). The retained private
source, logs, exact commands and test outputs are under
`/root/be6l-mt76-rx-lease-draft-20261113-r3` (`tests-r2` is the final fixture run).
