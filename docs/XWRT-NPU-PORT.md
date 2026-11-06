# X-Wrt port scope and next lifetime gate

Reference revision: `5ae8e6912e64682fcad54593467e84c80f170656`; exact selected
URLs and hashes are in [the source lock](../upstream/xwrt-an7563-20261105.json).
X-Wrt's AN7563 recipe is AArch32. These hardware changes must still build and
run with this project's ARM64 kernel and no-FP native runtime.

The pinned X-Wrt commit actually locks Linux6.18.60, while the BE6L candidate
uses6.18.55. The [reference preparation tool](../tools/prepare_xwrt_ppe_reference_v1.py)
now verifies all12 selected source pins, the immutable Git object and the
6.18.60 archive hash from that Git recipe. Normal generic overlays/patches and
185 platform patches reconstruct snapshots immediately before/after941-04.
An earlier6.18.55 attempt stopped on a generic patch mismatch; it was not forced
through. The reconstructed tree is a source reference, not a BE6L build or a
firmware replacement. [Reference evidence](evidence/xwrt-ppe-reference-20261106.json)
keeps this distinction explicit.

Three actual reference SMAC functions now pass16 substituted host cases,
including sharing/release, exhaustion, each of four partial bank/word failures,
latched rejection of new programming and reuse of an already valid cached MAC
after that latch. The test substitutes symbolic fields, register transactions
and locks; it does not prove concurrent or physical DMA behavior. The local
BE6L driver still has the six known unsafe baseline paths. No941-04 local port
or routed admission is inferred from these reference results.

| Reference patch | Current local status |
| --- | --- |
| 924 coherent mailbox DMA | Equivalent mailbox support already present in the baseline; not newly ported |
| 940-01 extended PPE flow offload | Compare incrementally against existing L2 and routed diagnostic changes; no wholesale replacement |
| 940-02 NPU firmware support | Existing source-built firmware/host ABI5 pair is retained; no reference firmware substituted |
| 941-02 AN7563 Ethernet | Existing AN7563 support is retained; compare individual missing behavior |
| 941-04 native PPE resource retention | Next required port; current failure paths below remain unresolved |
| 941-05 DMA-pool bindings | Reference reviewed; any binding/reservation change requires matched DT/kernel/loader admission |
| 941-06 SRAM-only table policy | Initial AN7563-only source port prepared, 129 substituted host checks and four real ARM64 units/composite pass |
| 994-02 AN758x PON metadata | Other-SoC reference; no BE6L hardware qualification follows |

The first port keeps routed rejection and the existing firmware, flash guards
and wired diagnostic taps. It changes CPU SRAM mirror allocation, DRAM table
programming and entry bounds. A complete matching kernel/modules/FIT now
[builds](FRESH-KERNEL-AND-RECOVERY.md) and [starts on the router](CANDIDATE-2F82-TARGET.md)
with both NPU workers advancing and zero faults. Packet forwarding, resource
lifetime and changed-driver recovery acceptance remain separate gates.

## Concrete failure paths to fix together

The Nov6 [executable baseline fixture](../tools/test_ppe_lifetime_baseline_v1.py)
now extracts seven real functions from this exact ARM64 source. Two normal
unbind/destroy controls pass; six injected read-failure/timeout paths violate
retained-owner/reference invariants. [Observations](evidence/ppe-lifetime-baseline-20261106.json)
cover unbind, L2 child removal, slot replacement, TC destroy and the table-free
callback. Register accesses, lists, allocation, netdev references and hardware
transactions are substituted. Parent L2 removal, notifiers, full deinit, locking
and actual ASIC/DMA withdrawal are explicitly excluded. Recording this known bad
baseline is not a passing driver test or a completed941-04 port.

The following audit is against `airoha_ppe.c` source SHA256
`de1f3299891eef4d987a4e9222eedc535ead18bf0d100c996eea2c0f8d5bb2f1`, produced
by the initial SRAM port. It is a source finding, not an induced device fault.

* `airoha_ppe_foe_write_failed()` clears the PPE enable bit after a failed
  transaction. This alone does not establish drainage or a resource-release
  boundary.
* `airoha_ppe_foe_unbind_flow()` calls that helper after a read/write failure,
  then clears `foe_owner[hash]` and resets `e->hash` regardless of failure.
  `airoha_ppe_foe_remove_flow()` can subsequently free the L2 subflow.
* The L2 commit path releases the previous slot before committing a new owner;
  it frees the newly allocated subflow after a timeout. Reserve/retain the
  physical owner before writes that may reach hardware, and propagate failure
  through slot release and all callers.
* `airoha_ppe_flow_offload_destroy()` removes the software cookie, puts netdev
  references and frees the entry after a void removal call. A local return-type
  change alone is insufficient: TC teardown, L2 parents/subflows, replacement
  and driver deinit need a coherent retained-owner/reset lifecycle.
* The wired netdevice event path unbinds and then drops matching netdev
  references on unregister. Its currently closed routed gate does not justify
  silently carrying that release order into a future enabled path.
* The reference publishes the TC cookie before an RX-visible flow can bind.
  The current local replacement path commits the flow and only then inserts
  its cookie, with a void rollback followed by freeing on insert failure.
  Port publication/rollback ordering together with SMAC and physical owners.
* AN7563 skips the generic `eth->npu` offload setup. Its native
  `an7552_npu` stop/drain path is distinct from generic mailbox `ppe_deinit`.
  An ACK from that generic callback cannot establish withdrawal for this
  native backend. A complete port needs the real provider/RTNL/IRQ ordering.

Port 941-04's cross-bank SMAC references and physical FOE reservation with these
callers, preserving existing L2 VLAN/DSA/WDMA behavior. A partial-bank SMAC write
or SRAM timeout must leave the slot unavailable and its referenced resources
held. Define how normal destruction, retry, driver exit and netdevice teardown
complete without use-after-free or an unbounded unregister deadlock. Do not
replace that design with a delay or an assumed register-drain meaning.

The next port must treat a slot reservation, its flow object, L2 parent/children,
cross-bank SMAC slot and referenced destination as one retained lifetime. A
possible BIND write owns the slot before it is issued. Failed reads or writes
keep that ownership and block reuse; they cannot erase the hash, free a child,
remove a TC cookie or put its netdev references as the current six cases do.
Successful invalidation and a proven controller-wide withdrawal boundary need
separate outcomes. Merely clearing enable is only a fail-closed request.

Notifier and deinit behavior must be designed with this ownership protocol.
Keeping netdev references forever can stall unregister; dropping them while
hardware can still reference the destination is unsafe. An asynchronous worker
that needs RTNL while unregister waits under RTNL can also deadlock. Establish
the actual lock/reset-provider ordering and a bounded, proven withdrawal/reset
path before selecting retry/quarantine policy. Do not merge a return-type-only
fix or enable routed admission on the strength of these substituted tests.

Fault tests must cover failed reads, failed BIND/unbind, partial cross-bank SMAC
writes, slot reuse, replace/destroy, device events and teardown. Then rebuild the
actual driver and complete matching kernel/modules, package, gzip CPIO/Image
and loader checks. Real hardware withdrawal/drain and recovery remain separate
tests. Routed NAT and IPv6 offload must stay closed until their admission gates
pass. Historical L2 success does not qualify a changed lifetime policy.
