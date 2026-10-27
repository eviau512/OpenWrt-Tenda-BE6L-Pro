# Bounded IPv4 classification and normal steering ownership

2026-10-28. The protected running image remains `d5a2bc21`. No new kernel image
or routed BIND action was installed in this round.

The old diagnostic incorrectly read a nonexistent second PPE bank and treated
its deadbeef response as an enabled bank. The actual typed SoC reports one PPE.
The corrected observer accesses only that validated bank;44 real configuration
and topology checks now pass. The failure was in the diagnostic, not evidence
of a device fault or a second accelerator needing enablement.

Three exclusive, short IPv4 learning fixtures changed only the known FLOW_CFG
learning bits for5seconds each, then synchronously restored the exact original
value. Software parents and BIND entries remained empty, and no NPU fault or
configuration ownership conflict was observed. Existing routed and DMA guards
were retained. The external lab's no-competing-writer condition is not a claim
to hold the driver's private SRAM/flow locks or prove production concurrency.

A low-rate PC TCP flow used a Windows per-socket Ethernet interface selection
and traversed the DUT to a separate WAN endpoint while independent Wi-Fi retained
control. Linux conntrack's original/reply tuples confirmed CPU NAT. The real
learned original and reply IPv4 keys matched that controlled connection. This
establishes classification/learning, not accelerated NAT throughput.

A separate read-only observer copied20words per selected host-shadow entry
after the driver's existing serialized SRAM refresh. Two equal copies were
retained; they do not establish an atomic hardware snapshot or exclude ABA.
The first four words match the original tuple. UNB scratch words must not be
interpreted as valid BIND rewrite actions, and software bucket hashes must not
be assumed identical to hardware slot selection.

Patch974 prepares real wired ingress/Ethernet-egress references, bind-time packet
checks and L4 lifetime invalidation.53 actual helper/UBSan cases and an isolated
ARM64 PPE object compiled. These prospective paths remain behind the existing
AN7563 routed rejection; no NAT admission or cache-register write was added.

The tested steering/default scripts now have a normal `be6l-network-defaults`
package, with signatures, exact hashes,0755 modes and file ownership verified
in a fresh offline root. The older unowned `/etc` file required an exact-hash
migration before normal APK installation; no force overwrite or database edit
was used. The running image still has its older runtime overlay. Bridger and
the new script package await a complete matching kernel/module/CPIO build.

Next: prove the restricted wired lookup-domain boundary, bound-action format
and AN7563 invalidation completion; then rebuild and qualify the new RAM image.
Do not enable unknown cache registers or remove admission checks to obtain a
positive result. Raw private endpoint traces and stock specifications are not
published in this repository.
