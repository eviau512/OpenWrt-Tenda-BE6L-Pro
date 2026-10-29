# Hardware qualification status

Updated 2026-10-29. This distinguishes the last qualified image from offline
candidates and does not imply a device remains powered or in that RAM image.

## Last qualified RAM image

`b3ec883f` booted dual-core AArch64 Linux 6.18.55 with 84 matching modules,
216 normal APK records and 58 native soft-ABI ELF paths. Most applications
remain ARM32. Native init/procd, corrected libc, exact module hashes, package
ownership, all ten MTD/BMT guards, NPU worker progress, Chinese Argon UI, Lua /
Nixio and strict normal-MTU Bing TLS passed. Bridger is installed and enabled;
Tailscale and Passwall with sing-box are disabled and contain no credentials.

Automatic 5GHz L2 forwarding passed these separate-direction tests:

| Duration per direction | Forward / reverse | Total CPU busy |
| --- | --- | --- |
| 20 seconds | 894 / 395 Mbit/s | 5.0 / 4.2% |
| 300 seconds | 751 / 381 Mbit/s | 7.1 / 4.7% |

Exact daemon-owned hardware flowers, native L2 BIND peer directions and PPE
progress correlated with the endpoints. Payload integrity, authentication /
reassociation and AP-down rule cleanup passed. These were sequential ordinary
and reverse tests, not simultaneous full duplex or a peak radio guarantee.
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
Lua-first module imports, digest, parser and netlink tests. A 90-path merge
preflight identifies 32 additional ELF paths. Normal signed package/profile,
plugin lookup and full default-service admission are still required. The
system remains mixed. Ordinary AArch64 FP packages are incompatible with the
observed CPU, and HWCAP must not be fabricated. See [native service gates](NATIVE-MANAGEMENT-PLAN.md).

PCIe first-handoff BAR/Gen1 behavior, the older bootloader warm-reset stall,
remaining port/hotplug coverage and actual watchdog reset remain open. None is
assigned to a clock or hardware fault without evidence. Only initramfs and RAM
boot are supported; no flashable official release or normal kernel upgrade is
qualified. Raw logs, backups, specification deliveries and credentials remain
private. See [the prioritized TODO](../TODO.md).
