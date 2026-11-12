# WCID quarantine and station ownership, 2026-11-12

A WCID bitmap prevents reuse of a number. It neither owns station memory nor
proves hardware completion. Converting a teardown helper from void to int also
cannot keep mac80211's station allocation alive: downward-state errors and
final removal errors are warnings, followed by cleanup/free. The safe minimum
is an independent retirement owner for the outstanding numeric/resource lease,
plus removal of CPU pointer users before the mac80211 callback returns.

This follow-up uses the **matched backports-7.2 mac80211**, not the base kernel's
in-tree mac80211. All 15 inspected files match the corresponding prepared
source byte-for-byte in
`/root/be6l-external-build-guest-interp-20261111-r2`.
[Evidence](evidence/wcid-object-lifetime-audit-20261112.json) pins those files,
39 definition locations, the matching build receipt and the conditional scope
of the findings below. No code, existing draft or device was changed.

## What is actually allocated and freed

| Object | Owner and real pointer relationships | Consequence for retirement |
| --- | --- | --- |
| `sta_info` / `ieee80211_sta.drv_priv` | `__sta_info_alloc`, backports `sta_info.c:659`, allocates `sizeof(*sta) + hw->sta_data_size`. `ieee80211_sta` is the last member of `sta_info`; mt7996 sets `sta_data_size = sizeof(struct mt7996_sta)`. `sta_info_free:494` ends in `kfree(sta)`. [A1, A2] | `mt7996_sta`, its embedded `deflink`, and `deflink.wcid` all end with this allocation. No driver-owned reference counter can veto that free. The mac80211 lifetime documentation provides RCU access, not an independent station ownership/get-put API. |
| Additional driver MLO link | `mt7996_mac_sta_init_link:1779` uses embedded `msta->deflink` when available, otherwise `kzalloc`s a link. Each link stores `sta = msta`, `wcid.def_wcid = &msta->deflink.wcid`, and a raw `ieee80211_key_conf *data_key`. Removal with `flush=true` uses `kfree_rcu` for non-embedded links. [M1, M6] | Merely postponing this separate link's free does not preserve its parent/default-WCID/key pointers. They must not be dereferenced after the station/key lifetime ends. |
| `msta->npu_key[]` | Independently allocated recovery/key copies, but owned by the station. `mt7996_mac_sta_remove:2528` calls `kfree_sensitive` on them regardless of any lower flush failure. [M3] | A future retirement mechanism cannot silently retain these pointers while the existing owner frees them. Withdrawal normally needs copied opaque identity/domain IDs, not retention of the host's whole key object. |
| PPE/native hardware identity | PPE flow owners independently hold a destination netdev reference and copied `wdma_wcid`, band/index and address. Native firmware has copied station/policy/replay state in shared memory. See the [earlier source audit](NPU-WITHDRAWAL-AUDIT-20261111.md). | The inspected paths do **not** demonstrate hardware DMA to a Linux `sta`, `msta`, `msta_link` or `mt76_wcid` pointer. Outstanding hardware references are principally numbers, copied metadata and independently owned packet/ring buffers. Embedded layout alone is not evidence of a hardware-driven station UAF. |

`wcid_to_sta`, `mt76.h:1457`, is especially important [C1]: for a station WCID
it follows `def_wcid` and applies `container_of(..., ieee80211_sta, drv_priv)`.
A copied standalone WCID/link cannot safely masquerade as an ordinary live
station object in that lookup table.

## Errors cannot veto the upper free

These are the relevant return boundaries in the inspected removal, MLO and
rollback paths:

- Native station revocation's int result is ignored by
  `mt7996_mac_sta_remove_link` and the downward authorization transition.
  `mt76_wcid_cleanup` ignores replay-key revocation's int result. The outer
  void `mt76_npu_flush_station` drops PPE's int result. [M1, M4, C2, N1]
- `mt7996_mac_sta_remove_link`, its remove-links aggregator and final
  `mt7996_mac_sta_remove` are void. Final removal still frees recovery keys.
  Add-link rollback and the reset station iterator also use these removal
  helpers; changing one helper's return type does not complete their policy.
  [M1–M3, M7]
- `mt7996_sta_pre_rcu_remove` is void. It clears the public WCID table under
  the status lock; it does not obtain ownership of the station. mac80211
  unhashes the station, invokes this callback, and waits `synchronize_net`
  before final destruction. [M5, S2]
- `_sta_info_move_state:1427` permits upward transitions to fail, but for a
  downward transition it only warns on driver errno, advances `sta_state` and
  returns zero. `__sta_info_destroy_part2:1590` also only warns on the final
  NONE-to-NOTEXIST return, then calls `cleanup_single_sta` and
  `sta_info_free`. An int propagated this far **still cannot retain drv_priv**.
  [S1, S3, A2, A3]
- Station-insertion unwind only warns on downward driver failures and the
  insertion failure path frees the station. A failed upward callback is not a
  place to leave a half-published hardware obligation behind. [S4, S5]
- `ieee80211_sta_remove_link:3575` ignores `drv_change_sta_links`' int result,
  removes the mac80211 link and schedules the separate link allocation for RCU
  free. Active-link switching also warns and proceeds. Driver link changes use
  `flush=false` for removed links, but that temporary retention does not turn
  final full-station destruction into a vetoable operation. [L1, L2, M8]
- The legacy `drv_sta_remove` wrapper also discards a driver's int result.
  mt7996 uses `sta_state`, so this is an alternate API boundary, not an extra
  callback in its current removal chain. [O1]

Int returns are useful for choosing quarantine/recovery internally. They are
not permission to return with live users of mac80211-owned pointers.

## Late completions: numbers versus real pointers

The inspected late TX paths support freeing the station without retaining its
entire C object, provided the pointer publications and CPU users are retired
correctly:

- TXS obtains a WCID index from the event, relooks it up under RCU, and exits
  if the table is NULL. [T3]
- TXFREE obtains the index, relooks it up, and skips station/link accounting
  when `wcid_to_sta` returns NULL. It still releases the independent token and
  its TXWI/SKB/DMA resources. With no link object, `mt7996_txwi_free` extracts
  the numeric index from TXD and passes it to `__mt76_tx_complete_skb`, which
  again relooks up the table. No missing station is reconstructed. [T1, T2, T4]
- `mt76_wcid_cleanup` removes status-IDR entries and marks their TXS side done.
  `__mt76_tx_status_skb_done` queues an SKB for release only after **both**
  DMA_DONE and TXS_DONE. A still-DMA-owned SKB survives through its independent
  TXWI/token; station cleanup does not by itself force its early free.
  [C2, T5, T6]

If the same number is prematurely assigned to a new peer, these index-only
events can instead resolve to the new peer and misattribute status/accounting
or pending hardware actions. A host-only generation value cannot distinguish
an old event that carries no generation. Keep the numeric lease unavailable
until a covering drain/reset proves the old events and hardware users are
gone, or change the transport to carry a checked generation end to end. The
existing firmware replay cookie is a scoped copied identity check, not a
generation field retroactively attached to every TXS/TXFREE/PPE reference.

There are also genuine CPU pointers, which must not be waved away by clearing
the table:

| Pointer-bearing path | Existing protection or required boundary |
| --- | --- |
| `msta_link->sta`, `wcid.def_wcid`, `data_key` | Valid only within their owning station/key lifetimes. Do not retain these as asynchronous withdrawal state. |
| `rc_list` / `wcid.poll_list` / WCID status lists | Driver removal deletes the nodes under their locks. Rate-control work takes the same mt76 mutex as removal; station polling uses its lock plus RCU. Final retirement must preserve these existing cancellation/serialization rules. [M1, C2, W1, W2] |
| RX `skb->cb` contains `mt76_rx_status.wcid` | This is a **real pointer**, not generally an index. Ordinary receive and completion within `mt76_dma_rx_poll` share one RCU read section, so the pre-remove unpublish/grace covers that instance. Software reorder has queue shutdown and synchronous delayed-work cancellation. [R2, R5–R7] |
| `phy->rx_amsdu[q].head` | `mt76_rx_release_burst` can retain an incomplete A-MSDU SKB across polls. Later release queues that same SKB for code that dereferences the saved WCID. Clearing the table does not rewrite its saved pointer. Current mt7996 ops do not register `sync_rx_queues`. This cache needs purge/revalidation, or a complete reachability proof, before claiming all CPU pointers are covered by one grace period. [R3–R5, O3] |

The last row is a conditional source finding, **not a reproduced device UAF**.
For native source-PN plus header-translated A-MSDU, the RX parser explicitly
clears A-MSDU aggregation flags; that special case must not be generalized to
every supported receive path. This audit did not establish a live native
execution of the cross-poll condition. It establishes why a blanket
"clear table, wait grace, therefore every saved pointer is gone" proof is
incomplete.

## Minimum independent retirement owner

Allocate/reserve the owner before publishing a new WCID, firmware eligibility
or dependent hardware flow, while an upward setup error can still reject
admission. A bounded per-device slot pool can avoid allocating during teardown,
where failure cannot veto the upper free. This owner must outlive the station
and must itself remain valid until device/provider teardown has fenced DMA.

It needs only:

1. The numeric WCID/band lease, provider/device epoch and necessary copied
   address/BSS/opaque replay-domain or cookie identifiers; revoked/draining/
   failed/completed state and independently managed references.
2. References to the already independent FOE owners, SMAC/destination owners
   and any packet/token/ring backing still owned by hardware. Existing token
   structures may supply that ownership; duplicate full WCID/STA copies are
   unnecessary. Secret key material is not a default withdrawal requirement.
3. A completion condition covering those resources and numeric-event reuse,
   separate from the CPU unpublish/grace/cache-cancellation condition. Only
   then can the numeric lease and resource references be released.

It must contain **no deferred raw `sta`, `msta`, `msta_link`, key-conf or
station-owned work/list pointer** after callback return. Normal WCID lookup
stays NULL for a retired peer; a retirement record is not a fake live station.
Any required CPU-cache cleanup happens before the mac80211 lifetime ends,
rather than pretending a new reference count can retain its embedded memory.

This is a design boundary, not an implemented provider. Bitmap quarantine is
necessary for index-only reuse protection but insufficient for full resource
retirement. The original full lifetime port and hardware proof remain open;
the existing native/routed admission gates stay closed.
