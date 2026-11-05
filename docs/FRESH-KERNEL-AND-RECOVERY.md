# Fresh kernel and live recovery, 2026-11-05

Subsequent result: [the new candidate passed initial RAM startup](CANDIDATE-2F82-TARGET.md).
This earlier checkpoint records its construction. Live tests below ran on the protected ARM32 handoff
and the previously qualified `fd30e389` ARM64 baseline. The
[selected receipt](evidence/fresh-kernel-live-20261105.json) keeps those scopes
separate. Images, SSH private identities and raw captures are not published.

## Matching build

A fresh Linux6.18.55 source tree was reconstructed from the locked Linux
archive and pinned OpenWrt Git objects. Normal generic/platform overlays and
patch order reproduce the qualified driver source before applying the X-Wrt
SRAM policy. No damaged generated source cache was imported.

The full ARM64 kernel and78 in-tree modules built. A normal signed transaction
rebuilds57 kernel/kmod packages, replaces77 installed in-tree modules and retains
seven external wireless/hotplug modules. All84 installed module structures
match the fresh704-byte probe. Configuration and Airoha interface headers are
checked. `CONFIG_MODVERSIONS` is off: matching `Module.symvers` is **not** a CRC
compatibility proof, and the retained modules still need new-kernel execution.

The final219-package root includes native netifd, recovery r2 and an
image-specific SSH identity. Standard newc/gzip archives match all1,703
regular/link payloads. The actual FIT contains the exact audited CPIO.

| Final private candidate | Value |
| --- | --- |
| FIT SHA256 | `2f82bb557a766d399f94f6f217d6e0c6667c38a7cda6b6a4415c2cb6770b4a1e` |
| FIT bytes | 55,005,896 |
| Effective Image bytes | 64,749,568 |
| Load / unchanged NPU boundary | `0x80200000` / `0x84000000` |
| Effective headroom | 262,144 bytes |
| CPIO SHA256 | `e6e70f56499182680d5dce2d818d88485bb92b8f0acda97fc2bc35c21853bac1` |
| Flash guards | All ten read-only MTD partitions and BMT protection |

The owned build's original full-build receipt is a predecessor. Final image
receipts describe subsequent CPIO-only changes; use `--previous-image` when
finishing another owned build. Old qualified artifacts remain unchanged.

Reproduction helpers, in order:

1. `prepare_fresh_arm64_kernel.py`: pinned sources, normal patch order and979.
2. `build_fresh_arm64_kernel_v1.py`: baseline configuration, full kernel/modules.
3. `audit_module_layout.py` and `package_fresh_kernel_v1.py`: real layout probe,
   normal module stripping, signed packages, ownership and complete root delta.
4. `compose_unattended_ram_v1.py`: private per-image SSH identity, recovery r2,
   signed normal installation and offline service enable.
5. `measure_native_netifd_cpio_v3.py` and `build_matching_kernel_image_v1.py`:
   sealed roots, complete archive checks, standard device image-recipe commands,
   effective Image bound, exact embedded CPIO, DTB/FIT hashes and guards.

The input SDK/cache is not generally admitted by these independent builds.
Full migration materialized1,588,255 files and16,222 symlinks and verified410
critical inputs;469 damaged generated/cache files remain omitted for rebuilding.

## Live native netifd

The candidate's exact small-file payload set was checked on the real ARM64
baseline, then run through `ujail` with a new network namespace, separate RAM
root and private ubus. The1698 selected files omit large unrelated applications
and SSH private identities. Native netifd stays alive for five seconds, registers
`network.device` and `network.interface`, and actually maps all five private
native VM modules: fs, ubus, uloop, uci and nl80211. Host namespace identity and
all ten MTD guards remain unchanged.

This extends the15-ELF static audit with real dynamic loading and ubus operation.
It does not qualify normal startup, DHCP, protocol children, hotplug, Mesh,
long-running network changes or execution under the new kernel. Current CPU
features still omit FP/ASIMD. AAPCS64-soft results are not compatibility with
ordinary Cortex-A53 packages.

## Live recovery and its fix

The first real ARM32 boot exposed a missing dependency: its BusyBox has no
`stat` applet. Recovery r1 failed before entering its loop. Release r2 checks
the exact numeric directory UID and permissions with POSIX `ls`, retains the
symlink refusal and private directory requirement, and passes23 shell/host test
groups. A normal signed RAM APK upgrade, with explicit RAM package caching,
started the real procd service and accepted an authenticated heartbeat. No
`force` or untrusted-package option was used.

A real test temporarily set boot grace and heartbeat expiry to60 seconds.
After the last heartbeat at uptime817, the service logged expiry at877 and
requested reboot. UART observed a fresh U-Boot banner. The literal stock
version marker was not recognized by the capture; independent checks then
verified automatic host DHCP return, HTTP200, authenticated `BE6LProV1.0`
firmware `V16.03.60.67_cn`, changed boot ID and Telnet root preflight.

A second ARM32 boot directly contained r2: default600/300 timing, zero respawns,
accepted heartbeat and an idle NPU were observed. The original checked watchdog
shutdown marker preceded ARM64 entry on the next handoff. Native ARM64 PID1,
two NPU workers, ten MTD guards and unchanged critical partition digests passed
again. Recovery r2 also runs and accepts heartbeats in that ARM64 RAM system.

A subsequent ARM64 test retained the default600/300 policy. Wireless was first
taken down and its NPU detached, with idle engines and zero faults verified.
The final heartbeat at uptime1435 expired at1736, within the five-second sampling
interval of the300-second timeout. UART observed U-Boot; automatic DHCP, HTTP200,
authenticated stock `.67` and Telnet root preflight passed again.

These are two scoped recovery results. The ARM64 default-timeout result has an
explicitly quiesced-NPU precondition. Initial600-second grace without any heartbeat,
active wireless/NPU recovery, hard locks, forced fallback and broader repeated
reset coverage remain open. A user daemon cannot execute during a full kernel
lock. Historical U-Boot NAND warm-reset stalls remain relevant.

The stock bootstrap uses a new private tmpfs, an unchanged protected ARM32
kernel and a separately admitted external initramfs containing a normal signed
root delta. `prepare_unattended_intermediate_v1.py` applies the actual delta to
a copied root and checks the complete result before preparing RAM segments.
It does not modify an admitted FIT, embedded CPIO or APK database by hand.
Host routes, IP settings, VPN and interface priorities were not changed.

## Remaining gates

The new matched FIT subsequently passed the checked ARM32 handoff, module/package
bytes and default native services; see [its startup evidence](CANDIDATE-2F82-TARGET.md).
Its own default expiry after explicit wireless/NPU detach now returns to stock;
active-NPU traffic, forced fallback, hard locks and forwarding/lifetime remain gates.
The current ARM64 configuration has no kexec, so another image needs another
stock-to-ARM32 transition. X-Wrt941-04 resource lifetime work remains a source
audit; routed NAT stays closed. The signed QEMU11.1.3 source now builds as a
no-FP soft-host emulator and [passes selected standard ABI tests](ARM64-INSTRUCTION-FALLBACK.md).
Complete package and child-process acceptance remain open.
