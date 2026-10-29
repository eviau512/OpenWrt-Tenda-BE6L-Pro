# XZ initramfs candidate

The versioned `tools/build_ppe_xz_image_v2.py` uses normal OpenWrt
`CONFIG_TARGET_INITRAMFS_COMPRESSION_XZ` and matching kernel XZ decoder options.
The candidate was built on 2026-10-28. Its first RAM boot on 2026-10-29
failed with an unexpected hardware reset. It is not a usable image.

| Actual candidate measurement | Bytes |
| --- | ---: |
| FIT image | 41,363,176 |
| External CPIO | 129,956,352 |
| Embedded XZ CPIO, CRC32 | 36,455,632 |
| Effective ARM64 Image | 50,855,936 |
| Headroom below the unchanged `0x84000000` bound | 14,155,776 |

Image SHA-256:
`db35bcad4ab20b5391c249751c58615971c35a6e9864cd8e503d3acff527c69a`.
The external CPIO and decompressed embedded CPIO both hash to
`6f6e8eceba9bc8b9b120e62f251d93dfa5504a7d9daea441d264e88607ab2edc`.
These are actual Image measurements, not the earlier compression projection.

The native profile remains at 58 ELF paths, 216 normal APK records and 84
matching ARM64 modules. This change does not promote the larger native service
closure or enable routed offload. The old gzip image and its validator remain
unchanged. The new XZ verifier requires bounded decoding, CRC32, exact CPIO
bytes, a unique embedding and matching decoder configuration. CRC64, gzip and
changed-CPIO fixtures are rejected.

A clean kernel build, final-configuration external module rebuild, normal
kernel/kmod APK creation and fresh offline root composition passed. Admission
checks cover signatures, payload ownership, actual ELF/module metadata,
Module.symvers and the numeric flow-rule ABI. The unchanged read-only MTD/BMT
device tree and memory bound also passed. All 110 default-loader fixture files
and modes passed actual CPIO admission and an isolated temporary RAM chroot.
That chroot executes userspace under the previously running kernel; it does
not establish that the new kernel or XZ early boot works.

Remaining gates are protected RAM boot, early decompression, actual modules,
management/HTTPS, flash guards and separate network/PPE regression. Earlier
image results do not qualify this candidate. A larger native package/profile
transaction must receive its own ownership, loader, size and runtime admission.
No reserved-memory limit was moved and no ordinary AArch64 FP package was used.

## First boot failure, 2026-10-29

The exact candidate entered AArch64 Linux and brought up both CPUs. Its last
recorded kernel output was BMT discovery at 1.466707 seconds, after which the
serial log showed ROM/U-Boot and stock Linux. No panic or XZ decoder error was
printed before reset. Stock startup reported watchdog information and logged
a configuration save. No explicit flash-write command was issued by the RAM
loader, but stock startup was not flash-protected. This is a material failure.

The image receipt now rejects ordinary retries. Early decompression timing and
watchdog handoff need investigation; neither is established as the cause. A
future RAM monitor must intercept the observed bootloader autoboot prompt after
an unexpected reset. Restore a previously qualified gzip RAM image first. No
new native image or hardware qualification may inherit this candidate's static
size, loader or module admission. The original 58-path profile remains frozen.
