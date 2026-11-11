# Unadmitted PPE lifetime draft, 2026-11-11

The [isolated patch](../patches/next/980-xwrt-ppe-lifetime-draft.patch) stages
the X-Wrt 941-04 ownership port against the exact BE6L Linux 6.18.55 source.
It is not in a candidate or an applied patch set. Native AN7563 binding has a
hard closed `lifetime_ready = false` gate and no enabling setter. Routed
admission stays closed. The original complete NPU lifetime objective remains
unfinished.

X-Wrt revision `5ae8e6912e64682fcad54593467e84c80f170656` supplies the three
SMAC functions, adapted only from `ppe->common.eth` to the local `ppe->eth`.
The reference is Linux 6.18.60, reconstructed through 941-04 with the existing
12-pin/185-patch preparation. The original driver is GPL-2.0-only, copyright
2025 AIROHA Inc, author Lorenzo Bianconi; those source notices remain intact.
See [the source lock](../upstream/xwrt-an7563-20261105.json) and
[reference context](XWRT-NPU-PORT.md).

The draft implements the related software changes together:

- Shared SMAC slots across both banks, per-flow references, partial-programming
  failure latch, cached-slot sharing and checked release. Other SoCs retain
  their existing interface MAC initialization.
- Collision rejection and physical owner reservation before a possible FOE
  write; an L2 child's parent link also precedes that write. A timeout retains
  that owner/link instead of freeing the possibly hardware-visible child.
- TC cookie insertion before RX-visible pending-flow publication, checked
  parent/child removal, propagated unbind/release/WDMA errors, and retained
  cookie/device references after failure. A tuple mismatch cannot discard a
  physical owner. A failed transaction poisons further binding.
- Notifier retention and a deinit preflight before destructive hash teardown.
  Successful preflight removal is idempotent. TC parent cleanup rejects a
  child pointer before the child could be freed and accessed again.

The withdrawal boundary is deliberately **unsupported for native AN7563**.
Even a successful invalidation ACK, or an already non-BIND entry, returns
`-EOPNOTSUPP` while retaining ownership. Clearing PPE.EN, mailbox ACK, RCU or a
delay cannot prove physical FOE/output DMA has drained. Native `an7552_npu`
does not become covered by the generic `eth->npu` mailbox backend.

Two exit problems therefore remain explicit. `NETDEV_UNREGISTER` cannot be
vetoed by this notifier; retained device references can stall unregister until
a real withdrawal provider completes. The driver's void remove/deinit API and
platform devres can still free memory after preflight failure. Returning early
only avoids destructive hash teardown inside this function; it is **not** a
safe unload protocol. Both need a bounded provider/reset contract and complete
IRQ/RX/RTNL/platform integration before admission.

The [compact receipt](evidence/ppe-lifetime-draft-20261111.json) records:

- Actual ARM64 ELF64 compilation of `airoha_ppe.c` and `airoha_eth.c`, using the
  existing V2 generated headers/config and recorded compile commands. Outputs
  went only to a private directory; no make, kernel/module link or V2 mutation.
- 25 actual-C lifecycle observations, including the original failure classes,
  parent/child and notifier retention, staged preflight failure, cold/poison/
  stopping gates, and rejection of child cleanup through the parent path.
  **One is an expected unsafe negative control:** a void free callback cannot
  restore a cookie already removed by `rhashtable_free_and_destroy`. The other
  cases passing do not make this teardown path safe.
- 16 transaction/failure cases executing the locally ported SMAC functions.
  Five source-order checks include TC/child publication and preflight ordering.
  These substitute hardware transactions, locks, lists, hash infrastructure,
  allocation and device references. They do not exercise DMA, real concurrency,
  complete TC construction, bounded unregister or full driver/platform exit.
- A read-only `git apply --check` against the pinned original source.

Reproduction uses the three new tools:
[prepare](../tools/prepare_ppe_lifetime_draft_v1.py),
[object compilation](../tools/compile_ppe_lifetime_draft_v1.py), and
[source fault observations](../tools/test_ppe_lifetime_draft_v1.py).
The retained private final revision is
`/root/be6l-ppe-lifetime-port-20261111-r3`, with `preparation.json`,
`object-compile.json`, `objects/`, and `tests-r1/result.json` plus exact C/logs.
The source/patch hashes in the receipt identify that revision. The base source,
V2 kernel, device, flash, host routing and VPN were not changed by this work.
