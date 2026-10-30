# Software packet identity carrier: isolated work in progress

The running image is still fd30e389. None of the following prototypes is
installed in the SDK, a normal package root or the router. No new firmware
image was built from this work. It cannot qualify N1 egress or routed PPE.

The exact CT producer was moved into a shared internal flowtable function,
without changing its body. Its 58 actual-code tests and complete configured
five-object flowtable link passed. There is no new export of that CT copier.

The next isolated prototype adds an 88-byte scalar skb extension produced
after IPv4 TCP output/neighbor selection. It copies the same version-2,
56-byte CT identity, a bounded observation lease and observed interface IDs.
It takes no CT reference, dereferences no cookie, writes no packet header and
does not use skb->cb. It uses the real skb extension allocation/COW/free API;
allocation failure leaves normal forwarding in control. No driver currently
opens its default-off gate or consumes its metadata.

The real configured flowtable composite, built-in flow core and skbuff
implementation compiled against the exact cached ARM64 flags. These were
isolated compilations, not a linked bootable kernel or runtime clone test.
An initial fixture omitted local core headers; its failure was retained.
The corrected fixture copies only necessary local headers and preserves
built-in flags rather than compiling core networking as artificial modules.

The actual lease implementation passed 31 boundary checks with a fake clock
and lock shim. The decoder passed 36 checks using the existing actual CT
predicate and real kernel types. A probe first lacked a declaration under
-Wmissing-prototypes; the corrected probe passed with the warning unchanged.
That initial error remains retained. These tests do not qualify SMP locking.

A separate record-consumer prototype compares the complete carried producer
identity with the recorded direction, including generation and both tuple
cookies. It passed 116 actual producer/record cases: the prior 58 plus two
positive carrier cases and all 56 single-byte identity mutations. Each wrong
identity was rejected without replacing earlier packet evidence. The entire
four-member Airoha driver compiled and linked with real cached built-in flags.
This consumer is not connected to the transmit tap or observation controls.

Next integrate driver begin/end/withdrawal and the decoder under the existing
observation lock, checking real netdev objects and DSA output in addition to
scalar interface IDs. Close a newly opened epoch before releasing references
on any creation failure. End the matching global lease before withdrawal;
a delayed old cleanup must not close a newer lease. Match the full producer
identity and opposite direction, not an IP/port-only guess or skb pointer map.

Changing skb extension IDs/layouts requires a full matched kernel and every
related module/consumer rebuild before a normal APK/root/CPIO/Image audit.
Do not hot-install these objects. The ordinary image memory boundary and
flash protections remain mandatory. Actual clone/COW, GSO segmentation,
allocation failure, expiry, device change, late queued packets and callback
withdrawal/draining still need tests before new target acceptance.

N2 ASIC actions, later-hit ingress containment and verified withdrawal remain
separate gates. This scalar CPU metadata never authorizes a hardware BIND.
