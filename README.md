> [!NOTE]
> This is another AI Slop project, 0% SLA, no working guarantee, hardware might burst in fire, you've been warned already

# OpenWrt for Tenda BE6L Pro

Experimental, RAM-only OpenWrt bring-up for the Tenda BE6L Pro (AN7563).
This repository contains the selected build inputs, source patches and research
prototypes. It does not contain a complete OpenWrt checkout or router backups.

## Current status

The [matched ARM64 binfmt candidate](docs/CANDIDATE-BINFMT-TARGET.md) passes actual
RAM startup with219 packages,84 freshly rebuilt modules,61 marked private-native
ELFs, default native services, Chinese Argon, NPU workers and MTD protection.
A separately staged integer-host emulator passes a20-case standard A53 child
execution matrix and a normal standard-package shell/ucode/btop chain. Its
temporary dispatch rule is removed after testing. General package compatibility,
credential/failed-exec corners and packet forwarding/lifetime remain open. Its
own default300-second recovery after explicit NPU detach also passes, returning
to authenticated stock. Broader recovery remains open. The [earlier2f82 candidate](docs/CANDIDATE-2F82-TARGET.md)
separately passed default expiry after explicit wireless/NPU detach and returned
to authenticated stock. [Build and recovery results](docs/FRESH-KERNEL-AND-RECOVERY.md)
retain their scope. These results do not qualify routed NPU offload.

See the [architecture, implemented features, open problems and next milestones](docs/ARCHITECTURE-AND-ROADMAP.md)
for the current project overview. Standard Cortex-A53 binary-package compatibility
remains a separate goal from the existing custom soft-ABI C components.

The optional [integer-host ARM64 emulator](docs/ARM64-INSTRUCTION-FALLBACK.md)
now passes selected standard-ABI FP/NEON, dynamic musl, C++ and Go tests on the
router, plus a signed standard A53 btop package's version command. A fresh public
source rebuild passes too. Normal signed standard runtime packages and bounded
child execution now pass; broader execution semantics and package workloads
remain open. These are software-emulation results, not native FP support.

- A dual-core AArch64 Linux kernel runs native AAPCS64-soft init/procd and
  selected C components alongside ARM32 applications through COMPAT. A complete
  native userspace and maintainable native SDK remain unfinished.
- Ethernet at the normal 1500-byte MTU, LuCI, wired WAN and verified HTTPS work.
- Both 2.4 GHz and 5 GHz work. Actual wireless-to-Ethernet L2 NPU/PPE forwarding
  has passed data-integrity, sustained-load and recovery tests.
- Routed IPv4 NAT, IPv6 offload and Linux per-flow hardware statistics are
  unfinished. Synthetic packet tests are not live NAT qualification.
  A hardware checkbox still falls back to software; see
  [the wired forwarding investigation](docs/WIRED-FORWARDING.md).
- The full `wpad-mbedtls` variant is selected, including compiled Mesh support.
  Mesh peer interoperability is a separate test, not established by selection.
- The qualified `b3ec883f` RAM image includes enabled `bridger` for automatic
  L2 flow management; see [its evidence and limits](docs/BRIDGER-INTEGRATION.md).
  It does not supply routed NAT support. Its earlier long tests ran each direction
  separately. A later concurrent 300-second L2 test measured about 777/228
  Mbit/s with 6.0% combined DUT CPU; see [scope and evidence](docs/STATUS.md).
- A matching XZ initramfs candidate has 14,155,776 bytes of measured Image
  headroom, with unchanged reserved memory and native package profile.
  [Static and loader admission](docs/XZ-INITRAMFS.md) passed, but its first
  RAM boot unexpectedly reset into stock firmware. It is marked failed; do
  not retry or treat its static headroom as usable firmware qualification.
- All ten MTD partitions and physical BMT write/erase/markbad paths are protected.
  The device profile produces initramfs only and rejects flash upgrades.
- The outgoing ARM32 watchdog shutdown/readback now passed an actual handoff
  to the unchanged gzip baseline. [Evidence and limits](docs/WATCHDOG-HANDOFF.md)
  do not establish the XZ failure's cause.
- [N1 route diagnostics](docs/N1-DIAGNOSTICS.md) now have real driver taps,
  a versioned CPU-only interface and source-derived lifecycle/record tests.
  Their matched-image integration is separate from target acceptance. The
  observer cannot publish a hardware route and does not qualify WAN/NAT.

The image includes LuCI with Simplified Chinese translations, curl, Lua/Nixio,
the Argon theme without its configuration application, btop, Tailscale and
Passwall with sing-box as the sole proxy core. Tailscale and proxy services start
disabled and contain no account, subscription or network credentials.

Read [BUILD.md](docs/BUILD.md), [STATUS.md](docs/STATUS.md), [TODO.md](TODO.md) and
[NOTICE.md](NOTICE.md) before using these experimental inputs.

## Important boundaries

Only initramfs and RAM boot are supported. Do not flash, erase, run sysupgrade,
save bootloader environment variables, or disable the flash protections.
Rebooting loses the RAM system. The mixed build remains a two-SDK experiment,
not an upstream-accepted device port or a general online kernel-upgrade system.
Existing applications use ARM32 packages even when `uname -m` reports `aarch64`.
Only explicitly reviewed soft-ABI packages use the private native namespace;
ordinary Cortex-A53 AArch64 packages cannot execute natively in the current
environment. The instruction-emulation fallback has bounded tests as described above.

Test APs must be configured only after initramfs has booted, using WPA2-PSK with
CCMP and a fresh cryptographically strong random passphrase. Do not embed or
publish that passphrase. APs and test credentials must be removed after testing.

No personal configurations, raw UART logs, serial numbers, personal device MAC addresses,
passwords, private signing/SSH keys, factory calibration dumps or firmware
backups are intentionally distributed here. Do not add them to this repository.

## Attribution

The AN7563 NPU/PPE port references [X-Wrt](https://github.com/x-wrt/x-wrt), pinned
to [5ae8e6912e64682fcad54593467e84c80f170656](https://github.com/x-wrt/x-wrt/commit/5ae8e6912e64682fcad54593467e84c80f170656).
The initial SRAM-only policy derives from X-WRT's `941-06` patch; resource-lifetime
work also reviews `941-04`. Original authorship and Linux licenses are retained.
See the [source lock](upstream/xwrt-an7563-20261105.json),
[port scope and remaining work](docs/XWRT-NPU-PORT.md) and [NOTICE.md](NOTICE.md).
X-Wrt's selected AN7563 target is AArch32; its driver is a hardware reference
for this ARM64 port, not proof of standard AArch64 package compatibility.

`tools/build_split_loader.py` is adapted from
[YangZJ781/Tenda-BE6L-Pro-Telnet-only-ramboot](https://github.com/YangZJ781/Tenda-BE6L-Pro-Telnet-only-ramboot).
The FIT/payload preparation workflow interoperates with that project's RAM-boot
inputs. See [NOTICE.md](NOTICE.md) for the exact scope and license boundaries.
No binary payload from that project is bundled here.

WAN/PPE implementation research also references [Pavel Bragin's BE5000 project](https://github.com/pabragin/xiaomi-be5000-openwrt),
pinned documentation `d88ed6a` and release `be5000-openwrt-20261026`. We use its
native-PPE safety and ABI analysis as a research cross-check. This review
introduced no firmware/ABI replacement; its results do not qualify BE6L WAN/NAT.
See [exact scope, provenance and licensing](docs/WAN-PPE-REFERENCE.md). Original
Iscle/Linux authorship and per-file licenses remain intact for any later port.

## Native soft-float core experiment

Native AArch64 init/procd has RAM-booted with the existing ARM32 applications.
See [acceptance, reproduction and remaining ABI work](docs/NATIVE-SOFTFLOAT.md).
The corrected runtime now has a [package-managed RAM image](docs/SOFT-APK-BUNDLE.md).
[Native netifd](docs/SOFT-NETIFD.md) passed a private-namespace static-IP lifecycle.
The complete native userspace and routed NPU offload remain under development.

## Native management follow-up

The current image still contains ARM32 applications. Reproducible native soft-ABI
web/Lua dependencies and isolated Chinese Argon login now pass actual tests;
see [service evidence and limits](docs/SOFT-SERVICES.md) and the
[package/image integration gates](docs/NATIVE-MANAGEMENT-PLAN.md). A module's
AArch64 ELF label alone does not establish compatibility with this no-FP CPU.
