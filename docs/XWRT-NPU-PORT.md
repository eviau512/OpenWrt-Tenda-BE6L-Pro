# X-Wrt port scope and next lifetime gate

Reference revision: `5ae8e6912e64682fcad54593467e84c80f170656`; exact selected
URLs and hashes are in [the source lock](../upstream/xwrt-an7563-20261105.json).
X-Wrt's AN7563 recipe is AArch32. These hardware changes must still build and
run with this project's ARM64 kernel and no-FP native runtime.

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

Port 941-04's cross-bank SMAC references and physical FOE reservation with these
callers, preserving existing L2 VLAN/DSA/WDMA behavior. A partial-bank SMAC write
or SRAM timeout must leave the slot unavailable and its referenced resources
held. Define how normal destruction, retry, driver exit and netdevice teardown
complete without use-after-free or an unbounded unregister deadlock. Do not
replace that design with a delay or an assumed register-drain meaning.

Fault tests must cover failed reads, failed BIND/unbind, partial cross-bank SMAC
writes, slot reuse, replace/destroy, device events and teardown. Then rebuild the
actual driver and complete matching kernel/modules, package, gzip CPIO/Image
and loader checks. Real hardware withdrawal/drain and recovery remain separate
tests. Routed NAT and IPv6 offload must stay closed until their admission gates
pass. Historical L2 success does not qualify a changed lifetime policy.
