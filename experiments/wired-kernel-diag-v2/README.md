# N1 CPU-only route diagnostics

This version adds real Airoha driver call sites to the earlier Linux observer.
It never returns TC hardware success, creates a PPE owner or publishes BIND.
The default observer pointer is null. No classification register is changed
by its root-only `route_diag` interface.

The internal context is version 2 and 56 bytes. It copies producer, zone,
namespace and direction, plus scalar CT/flow/tuple cookies and a kernel-lifetime
generation. Cookies are never dereferenced or exposed through the text API.
The generation counter lives in built-in `net/core/flow_offload.c`, so unloading
the flow-table module cannot restart it. Zero is rejected. These facts describe
a Linux-approved producer; they do not authorize a later ASIC hit.

The classifier observes REPLACE and DESTROY without changing their result.
An existing UNB CPU copy is observed under the existing PPE lock. The software
egress tap runs after checksum help and DSA tag extraction, before DMA mapping.
It borrows the skb's CT only during the callback and correlates both directions
by the same flow generation and CT. It preserves GSO and pre/post-checksum
labels. `format_complete` does not mean DMA succeeded or a frame reached wire;
`delivered` remains false.

Actual shared record code performs bounded copies, newer-generation replacement,
paired revocation and destruction. Tombstones reject delayed resurrection.
No previous packet or egress evidence is inherited by a new generation.
The owner serializes publication, unpublishes with RCU, drains readers and
withdraws the notifier/work before freeing references. Runtime stress of these
paths is still required; compiling them is not that test.

`route_diag` is mode 0600. `arm LAN_IFINDEX WAN_IFINDEX DSA_PORT GENERATION`
opens CPU observation once per device lifetime for exactly five seconds, after
real topology checks. `stop` revokes observation while retaining bounded audit
records. The separate existing UNB learning preflight and automatic restoration
remain mandatory before any classification experiment. Arming this observer
does not run that experiment.

`prepare_n1_identity_v2.py` creates an isolated patch tree. `run.py` extracts
the actual producer/admission functions and tests the shared record and control
parser under ASan/UBSan. It privately recompiles cached dependent translation
units, and Kbuild compiles/links the complete Ethernet driver. Reuse is permitted
only for matching header/producer overlays; changed Ethernet/PPE C members are
always rebuilt and linked. No SDK image, module or source is changed by these
tests. Normal image integration is a separate explicit operation.

This changes internal kernel layouts. Never hot-install an isolated object or
mix the result with an older kernel/module root. Use a complete matched kernel,
external modules, normally signed APK transaction and admitted CPIO/image.
No live CT/UNB/software-egress correspondence, routed offload, IPv6 hardware
routing or Linux per-flow counter acceptance is implied by the offline tests.
