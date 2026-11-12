# Native withdrawal contracts: source audit, 2026-11-11

The native AN7552 backend already has meaningful, source-defined stop and
completion protocols. It is too broad to say that no native protocol exists.
However, the inspected code does not provide a qualified, general **FOE plus
all output-resource withdrawal** operation that the PPE lifetime draft can call.
The [unadmitted draft](PPE-LIFETIME-DRAFT-20261111.md) therefore stays closed;
this audit neither enables its gate nor completes the X-Wrt 941-04 port.

This is a read-only audit of the pinned BE6L Linux 6.18.55 tree, its paired
source firmware, mt76 source, and the already reconstructed X-Wrt Linux
6.18.60 reference. [Evidence](evidence/npu-withdrawal-audit-20261111.json)
records 23 file hashes and 37 definition locations/hashes. IDs below refer to
that evidence. All 79 protocol/ABI constant values from the paired firmware
match the host header; the firmware ABI is 5. This checks source identity, not
the firmware running on a device. No old fixtures or reference preparation
were rerun, and no device, register, existing source or host network was changed.

## Existing protocols and their limits

| Source boundary | Actual completion evidence | Scope that remains outside it |
| --- | --- | --- |
| `native_ppe_stop`, `an7552_npu.c:657` [N1, N2, F2–F4] | Switches firmware to DRAIN; waits for submitted-token count `q[12]` to reach zero; stops PPE TX DMA and checks BUSY; waits for firmware service `q[13]` to stop. Ring restoration additionally checks producer equals consumer, ring identity, every descriptor returned, completion FIFO empty and PPE BUSY clear, then repeats identity/idle checks. | This is tied to the native 64-entry submission ring and its tracked receive tokens. It does not enumerate arbitrary TC/FOE owners or every wired/PSE/GDM/WDMA output reference. A previously captured firmware batch mode can still submit until the producer is separately stopped. |
| `park_cores` / firmware park and trap handlers [N5, F1; `start.S`] | Both cores publish the park magic after `fence iorw, iorw` and enter permanent WFI. An installed recovery interrupt can park a busy loop; a missing fenced acknowledgment fails the operation. | This fences these firmware writers. It does not by itself empty hardware queues or stop independent wired ingress. Restart requires firmware lifecycle handling; this is not an existing reversible per-flow pause API. |
| `fault_stop`, `an7552_npu.c:1370` [N3, N4] | Parks writers, disables native TX/RX DMA, waits BUSY clear, consumes PPE completion tokens and waits shared PPE BUSY clear, checks/restores the native ring and frees native IRQ handlers. | The source explicitly retains packet storage until the consumer resets radio DMA. `fault_quiesced` permits that next recovery phase; it does not mean every radio-owned output object is already reusable. |
| `tdma_stop` and `an7552_npu_forward_stop` [N8, N9] | Waits TDMA RX DMA idle and firmware consumer indices to catch hardware; direct forwarding waits completed count equals produced count and its worker inactive before restoring rings. | These are native TDMA/direct-forwarding resources. Failures mark the context failed and retain reserved storage. They are not a completion token for an arbitrary FOE hash or shared wired queue. |
| Station/policy handshake [N7, F1, F5] | Revokes eligibility before the request; both firmware cores acknowledge between protected batches; host updates identity/policy and requires both acknowledgments to clear. A failed level handshake poisons later reuse. | It stops relevant software policy users, not hardware packets already submitted to PPE/radio. The core-1 pause does not continue consuming PPE completions, so holding this pause and simply waiting for `q[12]` is not a valid drain composition. |
| `require_quiescent` / terminal shutdown [N6, N11, N12] | Closes setup on terminal shutdown, waits existing setup users, runs the native stop/park obligations and serializes concurrent destructors against shutdown completion. | Setup waiting can be unbounded. Unresolved ownership invokes `panic_timeout = 0` and `panic`, requiring a power cycle. This is an existing destructor guard, not unattended recovery or an appropriate operation inside a PPE spinlock. |

The shared PPE BUSY bit is already named in `airoha_regs.h:259`; native
`fault_drain_ppe` reads the corresponding PPE status after parking its writers
and stopping its native DMA. This is useful existing evidence, not a reason to
invent another MMIO operation. Its success still needs a proven stop for every
other ingress and an output-resource coverage argument before general FOE/SMAC
release. In the inspected native SoC data, **AN7563 has one PPE bank**
(`airoha_eth.c:4774`). SMAC's loop over `num_ppe` supports other multi-bank
SoCs; two-bank host cases are not a BE6L hardware observation.

The generic `airoha_npu_ppe_deinit` merely sends the WAIT_HWNAT_DEINIT mailbox
command [G1]. Native AN7563 bypasses generic `eth->npu` setup [P2]. Neither
that generic reply nor SRAM table-write ACK [P1] supplies missing output drain
semantics. X-Wrt 941-04's checked flow removal retains ownership on a failed
write, but clears it after a successful invalidation [X1]. The inspected
reference does not add a native all-output provider. Its separate v1 engine
enable path waits BUSY clear; its disable branch does not establish a complete
output withdrawal contract [X2]. The original AIROHA/Lorenzo Bianconi source
notices and X-Wrt revision `5ae8e6912e64682fcad54593467e84c80f170656`
remain the provenance of those reference changes.

## Call contexts and lifetime gaps

TC operations take `flow_offload_mutex` [P2]; physical slot changes and the
notifier take `ppe_lock` with bottom halves disabled. RX can bind from Ethernet
NAPI and mt76 callbacks. A sleeping native drain cannot be inserted into the
draft's `withdraw_complete` function while that spinlock is held.

There is also an outer error-loss boundary beyond the previous driver draft.
`airoha_ppe_dev_flush_wdma` returns `int`, but
`mt76_npu_flush_station`, `npu.c:138`, is **void** and ignores that result inside
an RCU read section [M1]. Its caller `mt7996_mac_sta_remove_link` revokes
authorization, ignores the station-handshake result, cleans the WCID and calls
this flush before continuing removal [M2]. Existing key-related retired-WCID
bits preserve some identities; they do not propagate every FOE withdrawal
failure. Full port scope must include this API/caller and WCID reuse policy.
Moving a sleeping provider call into that RCU section would introduce a new
context violation.

The native context is attached once to the radio consumer [N10]. The radio
also holds a PPE provider reference/device link [P3]. Supplier removal can
unbind those consumers first: Linux driver core handles busy device links
before calling the supplier's remove callback [D1]. Radio cleanup already
cancels work, invokes native quiescence, masks/synchronizes IRQs, stops NAPI,
waits networking callbacks, kills the tasklet and resets DMA before freeing
tokens [M4]. Radio reset separately checks recovery readiness before proceeding
to reset/prepare [M3]. These existing sequences are part of a possible global
provider design; Ethernet cannot acquire a second native attachment or assume
the consumer-owned pointer remains valid without a defined registration and
reference contract.

Ethernet remove has a different sequence [E1–E4]: stop NAPI/TX DMA; unregister
netdevs; clean RX DMA/page pools; then call PPE deinit. RX/TX BUSY timeouts on
AN7563 already invoke a terminal guard before releasing those buffers. Shared
Ethernet IRQs use devres; the inspected cleanup does not explicitly mask and
synchronize every bank before deleting its NAPI objects. A complete provider
must establish that IRQ/callback boundary and stop new PPE learning before
resource retirement, including probe-error and remove paths.

`NETDEV_UNREGISTER` executes during unregister under RTNL and its return is not
used to cancel unregister. `netdev_wait_allrefs_any` repeatedly rebroadcasts
the notification while references remain [D3]. A provider cannot solve this by
keeping references forever or by synchronously waiting for a worker that needs
the same RTNL/driver lock. After a driver remove callback returns, Linux calls
`devres_release_all` regardless of an early return inside PPE deinit [D1, D2].
The old draft's preflight remains containment, not a complete remove protocol.

The available FE/PDMA/QDMA reset controller also supplies no substitute proof:
`en7523_reset_update` updates a reset register and returns zero without a
queue-drain/ownership acknowledgment [R1]. Its reset status reads that bit.
An existing reset API name alone does not establish which shared outputs or
outstanding bus transactions it terminates.

## Minimum next implementation boundary

1. Define a provider owned jointly by the Ethernet/PPE and radio/native
   lifecycles, with explicit references, shutdown admission and one lock order.
   It must run in process context outside `ppe_lock` and RCU read sections.
   First implementation may use a coordinated global offload stop, but must
   retire all affected flows/SMAC/output resources as one covered generation;
   it cannot claim to stop one slot while unrelated users continue reusing it.
2. Reuse the existing fenced park, native ring checks, TDMA/direct completion
   handling and consumer reset boundary with their actual error semantics.
   Add the missing verified contract for all wired ingress and shared
   PSE/GDM/WDMA output users. The local sources inspected here do not establish
   that last contract; no guessed register or SMC is justified.
3. Preserve owner/hash, parent links, cookie, SMAC and destination references
   until that provider completes. Propagate failure through mt76 station flush
   and its caller; quarantine every affected WCID independently of whether a
   data key happened to be installed. No allocator reuse follows an ignored
   error. Refuse new binding while a generation is draining or quarantined.
4. Make unregister, probe-error, supplier detach, remove and reboot use the
   same coverage boundary before any IRQ/NAPI/page-pool/devres release. Resolve
   the RTNL/consumer lock interaction and the existing terminal panic behavior
   explicitly. The current panic-with-power-cycle contract cannot serve this
   project's normal unattended recovery policy.
5. Only after the source contract exists, add meaningful delayed-completion,
   late-writer, WCID reuse, IRQ/RTNL and partial-remove fault tests, then build
   matching kernel/modules and qualify a RAM candidate. The old 25/16 fixtures
   neither cover nor qualify these new boundaries.

No implementation was added by this audit. Full hardware withdrawal and the
complete X-Wrt lifetime port remain unqualified; routed admission stays closed.
