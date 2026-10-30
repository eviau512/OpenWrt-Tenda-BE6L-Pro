# Hardware qualification status

Updated 2026-10-30. This distinguishes the last qualified image from offline
candidates and does not imply a device remains powered or in that RAM image.

The matched N1 image9a3955e7 passed its actual loader fixture,checked watchdog
handoff and startup:84 modules,216 packages,58 native soft C paths,dual CPUs,
UI/TLS/Lua,NPU and flash guards. A real wired-WAN diagnostic observed two CT
generations/four direction rows with matching endpoint byte counts. RX/egress
correlation stayed zero. The failed fractional-sleep sampler is retained and
fixed offline,not retried. See [limited live evidence](N1-LIVE.md).
This does not qualify N1 lifetimes,WAN/NAT hardware or native90 promotion.

Historical L2 results below belong to b3 and are not inherited by this changed
driver image. The known b3 recovery remains immutable.

The known gzip b3 RAM baseline was restored after the failed XZ attempt on
2026-10-29. Exact84 module hashes, ten MTD guards and baseline critical hashes,
NPU progress/fault0, package ownership, LuCI/Lua, NTP and strict TLS passed.
That recovery initially ran no new wireless test. The later continuation on the
same stable boot completed the concurrent L2 result below.

## Last qualified RAM image

`b3ec883f` booted dual-core AArch64 Linux 6.18.55 with 84 matching modules,
216 normal APK records and 58 native soft-ABI ELF paths. Most applications
remain ARM32. Native init/procd, corrected libc, exact module hashes, package
ownership, all ten MTD/BMT guards, NPU worker progress, Chinese Argon UI, Lua /
Nixio and strict normal-MTU Bing TLS passed. Bridger is installed and enabled;
Tailscale and Passwall with sing-box are disabled and contain no credentials.

Automatic 5GHz L2 forwarding passed the following tests:

| Duration per direction | Forward / reverse | Total CPU busy |
| --- | --- | --- |
| 20 seconds | 894 / 395 Mbit/s | 5.0 / 4.2% |
| 300 seconds, sequential | 751 / 381 Mbit/s | 7.1 / 4.7% |
| 300 seconds each, concurrent, Ace3V | 777 / 228 Mbit/s | 6.0% combined |

Exact daemon-owned hardware flowers, native L2 BIND peer directions and PPE
progress correlated with the endpoints. Payload integrity, authentication /
reassociation and AP-down rule cleanup passed. The first two rows were sequential ordinary
and reverse tests. The concurrent row is PC-to-phone / phone-to-PC and has
295.028 seconds of conservative common payload time plus both active sockets
and exact peer bindings at four samples. The live parser initially selected
the inactive reverse-server receiver summary; independent re-review of both
endpoint records passed. Process launch skew was not retained, and the result
is not a peak radio comparison across different clients.
Earlier image driver-exit, CPU controls and reliable 2.4GHz results remain
historical evidence and are not inherited by every new image. The replacement
client's 2.4GHz observations are excluded at the owner's request. Mesh peer
interoperability still needs a real external peer.

## XZ candidate, first boot failed

A normal matching XZ build retains the same 58 native paths, 216 packages and
84 modules while leaving 14,155,776 bytes below the unchanged Image bound.
Exact compressed CPIO, final configuration, module ABI, normal signed package
ownership and actual 110-file loader fixture admission passed. An isolated RAM
chroot passed under the previous kernel. Its first AArch64 boot then reset
unexpectedly into stock firmware, which logged a configuration save. No panic
was printed and the reset cause remains unproved. Ordinary retries are blocked.
See [the actual sizes and remaining gates](XZ-INITRAMFS.md). No larger native
service profile or main service replacement is implied by this space saving.

## Routed PPE remains unfinished

The GUI hardware-offload checkbox is not evidence of WAN/NAT acceleration.
The driver retains routed rejection. Earlier simultaneous wired forwarding
used software offload with zero direct PPE increment and high CPU. Router-local
TCP also consumes CPU and is a distinct path. L2 low-CPU results cannot qualify
routed NAT. IPv6 routing and genuine Linux per-flow hardware statistics are open.

Actual NAT tuple producers, explicit CT-context provenance and prospective wired
ownership helpers passed source-derived CPU tests. Three bounded UNB-only
learning windows restored exactly without BIND or fault, and original/reply keys
correlated with controlled software NAT. The exact-pair non-publishing action
preview passes 108 UBSan cases with balanced modeled references. A further
37 source-derived RX-contract cases check MTU, TCP options and independent full
checksums, including nonlinear access. None changes a routed gate or creates a
hardware owner. The current RX notification is before GRO/netfilter; setting
`CHECKSUM_UNNECESSARY` alone does not independently validate those packet bytes.

A new isolated diagnostic library compiles against actual matching Linux APIs
with retained netdev objects, timer/notifier expiry, copied CT/action data and
RX validation; 20 new shared-epoch UBSan cases pass. It has no production
hooks or target execution. Real CT inputs include seven keys, including TOS
and TCP flags, rather than the earlier five-key synthetic fixture.

The next diagnostic adapter must correlate real CT input, pre-NAT RX evidence
and later software egress separately, while publishing no BIND. A first closed
wired test needs a complete native action, actual traffic containment and a
verified withdrawal or resource-retention/reset boundary. It need not implement
unused wireless workers, IPv6 or per-flow counters first. Generic software keys,
a controller ACK, guessed delays and CPU-only tests do not prove ASIC equality
or packet drainage. No guessed cache register or unknown SMC is allowed.

The pinned [BE5000 reference review](WAN-PPE-REFERENCE.md) is credited in README.
It contains generic routed code, but its published LAN-oriented measurements
and board WAN configuration do not qualify BE6L WAN hardware forwarding. The
current MIT source-built firmware/host pair uses ABI5; related reference ABI1
is not a drop-in replacement. Private specification corrections and focused
follow-up requests are retained outside this public source repository.

## Native userspace and remaining hardware

Native netifd has a real isolated netlink lifecycle; a reproducible 67-ELF
web/Lua closure passed isolated Chinese Argon login, TLS/RPC authorization,
Lua-first module imports, digest, parser and netlink tests. A normal signed 90-path preview
owns 32 additional ELF paths. Its exact native payloads now pass isolated
TLS, RPC authorization and Lua/ucode tests after fixture permission corrections.
A real nested Lua-child negative control and a private path correction with
ten native imports also pass. The latter is a diagnostic substitution until
its new package/profile transaction is admitted. Default-service and new-image
admission remain open. The
system remains mixed. Ordinary AArch64 FP packages are incompatible with the
observed CPU, and HWCAP must not be fabricated. See [native service gates](NATIVE-MANAGEMENT-PLAN.md).

PCIe first-handoff BAR/Gen1 behavior, the older bootloader warm-reset stall,
remaining port/hotplug coverage and actual watchdog reset remain open. None is
assigned to a clock or hardware fault without evidence. The
[early reset audit](EARLY-RESET.md) identifies a real outgoing-watchdog handoff
gap and an asynchronous initramfs wait boundary, without declaring a reset
cause. New timestamped UART capture is CPU-tested but not live-qualified. Only initramfs and RAM
boot are supported; no flashable official release or normal kernel upgrade is
qualified. Raw logs, backups, specification deliveries and credentials remain
private. See [the prioritized TODO](../TODO.md).

The subsequent v2 normal signed package admits exactly the reviewed Lua-child
module delta and preserves89 other native paths, all58 base native paths and
216 original APK records. Its exact90-path package-root fixture has now passed
on the stable RAM system, including all ten child imports and TLS/RPC controls.
The resulting offline root still has217 packages. Defaults, image and binary
redistribution are not promoted. The one-file v2 admission and APK builder are
versioned separately; the original profile and package remain unchanged.
