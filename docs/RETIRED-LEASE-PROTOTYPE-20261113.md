# Independent retired lease and RX cache prototype

This adds executable **host source prototypes**, not a driver port:
[owner interface](../experiments/npu-retired-lease/retired_lease.h),
[implementation](../experiments/npu-retired-lease/retired_lease.c),
[lifecycle cases](../experiments/npu-retired-lease/model_cases.c) and
[source-bound RX test tool](../tools/test_retired_lease_prototype_v1.py).
[Evidence](evidence/retired-lease-prototype-20261113.json) records 27 lifecycle
observations and 12 RX observations, all matching their expected outcomes.
Negative controls are explicitly expected unsafe observations, not safety passes.

The owner is independently allocated before publication. It copies WCID, band,
BSS, MAC, replay-cookie identifier and a monotonic host epoch; it contains no
mac80211 station, embedded WCID or key-conf pointer. Independent references keep
the object alive after station removal. It retains references to separately
owned FOE, SMAC, destination and DMA-backing resources until covered completion.
An unpublished setup can unwind; a published obligation cannot use that abort.
Retirement closes lookup first and preserves the numeric lease. Missing provider,
timeout, wrong identity/epoch or incomplete coverage preserves all obligations.

The process-context state model separates CPU detachment from FOE/native/output,
IRQ, RX-cache and remove/setup coverage. Shutdown closes new setup and the model
device-release gate also waits in-flight setup and independent cache references.
**These are model predicates, not installed Linux hooks.** Returning an error
from this helper cannot veto mac80211 station free or Linux's void remove/devres
unwind. Actual driver integration must establish its boundary before those
irrevocable releases. C11 atomic references do not implement the missing kernel
RCU, IRQ or lock ordering. No real provider is supplied; its default is
`-EOPNOTSUPP`. The successful provider in tests supplies synthetic evidence only.

Two functions are extracted from exact matched mt76 source SHA256
`0646b55c7d330b793e216878ef1efe733ecc840f912e6a39b16d6fc0ec5cce61`:
`mt76_rx_release_burst` and `mt76_rx_release_amsdu`. Their unchanged control flow
reproduces retention of a raw WCID pointer in an incomplete cross-poll A-MSDU.
Clearing the table and modeling a CPU grace does not rewrite that saved pointer.
The retired stack fixture stays allocated, so this observes pointer retention
without executing a real freed-memory dereference or claiming a DUT UAF.

The generated adapter captures an independent lease tag while the RX pointer is
valid, clears raw WCID before caching, and resolves only a still-current matching
binding during release. Retired or mismatched tags and mixed-peer fragments are
dropped. It preserves live-fragment and unknown-station controls and releases
tags on the actual header-rejection path. One case lets old metadata survive
synthetic hardware completion and same-index reuse: its tag still rejects the
new generation. This demonstrates a narrow CPU-cache improvement in substituted
source execution. Actual skb metadata storage, RX locking and native packet
reachability remain unimplemented/unqualified. Restoring a raw pointer requires
one real RCU span through delivery, not another cross-poll queue.

An explicit negative control shows that two identical **untagged index-only**
events resolve identically after reuse. A host epoch cannot disambiguate them.
The numeric lease must remain unavailable until a real covering fence/reset,
or the transport must carry a checked generation end to end.

## Exact next driver boundary

Preallocate independent lease storage before WCID/firmware/flow publication;
bind it to the real lookup under one defined lock/RCU protocol. Add legitimate
cache-tag storage or a serialized purge at the actual RX seam, and complete
pointer/list/work removal before the no-fail mac80211 callback returns. Wire
station flush failure into retirement without treating errno or a bitmap as
ownership of drv_priv. Integrate setup closure, IRQ synchronization, RX/NAPI
quiescence, probe-error/remove and resource release with that same owner.

The existing ABI5 source already provides scoped primitives. In
`an7552_npu.c`, `native_rro_stop` stops its producer before `native_ppe_stop`;
the latter waits token count, TX BUSY and service inactivity, then checks ring
identity, returned descriptors, completion FIFO and PPE BUSY before restoration.
`fault_stop` parks both fenced firmware writers, stops native DMA, drains the
shared PPE pipeline/FIFO and releases native IRQ callbacks. `tdma_stop` and
`an7552_npu_forward_stop` check their consumers/completions. The prior
[native audit](NPU-WITHDRAWAL-AUDIT-20261111.md) pins their exact definitions.
Four native definitions (`native_ppe_stop`, ring restoration, `wait_parked`
and `fault_stop`) are hash-bound again by this receipt; no MMIO was performed.
These primitives do not establish **ALL** wired ingress/PSE/GDM/WDMA output,
station reuse and Ethernet remove/devres coverage. Fault recovery still relies
on the consumer's subsequent radio reset. The destructor's terminal panic is
not unattended recovery and is not used by this prototype.

Retained private build/logs:
`/root/be6l-retired-lease-prototype-20261113-r1`.
No existing driver, draft, kernel, root, candidate or device was changed. Native
and routed admission remain closed; the full lifetime port remains unfinished.
