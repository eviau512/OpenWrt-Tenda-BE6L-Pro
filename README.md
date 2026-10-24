# OpenWrt for Tenda BE6L Pro

Experimental, RAM-only OpenWrt bring-up for the Tenda BE6L Pro (AN7563).
This repository contains the selected build inputs, source patches and research
prototypes. It does not contain a complete OpenWrt checkout or router backups.

## Current status

- A dual-core AArch64 Linux kernel runs with ARM32 soft-float userspace through
  COMPAT. Native AArch64 userspace has not passed hardware validation.
- Ethernet at the normal 1500-byte MTU, LuCI, wired WAN and verified HTTPS work.
- Both 2.4 GHz and 5 GHz work. Actual wireless-to-Ethernet L2 NPU/PPE forwarding
  has passed data-integrity, sustained-load and recovery tests.
- Routed IPv4 NAT, IPv6 offload and Linux per-flow hardware statistics are
  unfinished. Synthetic packet tests are not live NAT qualification.
- The full `wpad-mbedtls` variant is selected, including compiled Mesh support.
  Mesh peer interoperability is a separate test, not established by selection.
- All ten MTD partitions and physical BMT write/erase/markbad paths are protected.
  The device profile produces initramfs only and rejects flash upgrades.

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
ARM32 userspace packages are required even when `uname -m` reports `aarch64`.

Test APs must be configured only after initramfs has booted, using WPA2-PSK with
CCMP and a fresh cryptographically strong random passphrase. Do not embed or
publish that passphrase. APs and test credentials must be removed after testing.

No personal configurations, raw UART logs, serial numbers, personal device MAC addresses,
passwords, private signing/SSH keys, factory calibration dumps or firmware
backups are intentionally distributed here. Do not add them to this repository.

## Attribution

`tools/build_split_loader.py` is adapted from
[YangZJ781/Tenda-BE6L-Pro-Telnet-only-ramboot](https://github.com/YangZJ781/Tenda-BE6L-Pro-Telnet-only-ramboot).
The FIT/payload preparation workflow interoperates with that project's RAM-boot
inputs. See [NOTICE.md](NOTICE.md) for the exact scope and license boundaries.
No binary payload from that project is bundled here.
