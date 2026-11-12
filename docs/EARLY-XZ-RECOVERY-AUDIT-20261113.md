# Early XZ boot and recovery boundaries, 2026-11-13

The existing a1ca payload contains `panic=10` and an early registered PSCI
restart path. These can recover a **reported** internal-initramfs failure if
panic and firmware reset complete. They do not provide a timeout for every
pre-`/init` hang or partially extracted root. The user recovery daemon has not
started at that point. An unchanged raw root plus static admission of the new
Image and complete target startup can establish this candidate's successful
boot; it cannot establish automatic recovery from all those failure paths.

The [read-only evidence](evidence/early-xz-recovery-audit-20261113.json) binds
the actual a1ca payload hashes/DTB, 15 kernel source files, 15 definition
locations and a private disassembly. No device fault injection, register/SMC
call, loader execution or existing source change occurred.

## Existing protection

The actual payload DTB `/chosen/bootargs` is
`console=ttyS0,115200 earlycon panic=10`; it has no `bootargs-override` property.
The old config has `CONFIG_PANIC_TIMEOUT=1`, `CONFIG_PANIC_ON_OOPS=y`, empty
built-in command line, and no soft/hard lockup detectors. The command-line
panic parameter overrides the default once parsed.

`init/initramfs.c:718`, `do_populate_rootfs`, calls `panic_show_mem` if the
**built-in** archive unpacker reports an error. This differs from some external
initrd error paths which only print an error. The streaming XZ wrapper reports
allocation, format, unsupported-option and corruption errors to that unpacker.
If panic reaches its timeout, it calls emergency restart; the generic ARM64
emergency wrapper calls `machine_restart`. PSCI initialization in `setup_arch`
registers the restart handler before rootfs initcalls. The DT specifies
`arm,psci-0.2`, `method=smc`; the handler uses existing standard reset functions.
If restart fails, `arch/arm64/kernel/process.c:129` ends in an infinite halt
loop. This audit did not execute or qualify that failure-recovery path.

The pinned `entry.bin` has SHA256
`8d9ca98a6b6d6710654c45f01d6f0acbb6af6391b09b22872ce5b720243969ae`.
Its ARM32 disassembly shows the handoff at offset `0x58`; only **on return**
does it copy the backup from `0x90000000` to `0x80088000` and branch there.
There is no timer monitoring a running ARM64 kernel and no return from its
initramfs unpacker to this trampoline. The backup segment is not a post-entry
fallback service. The previously checked outgoing watchdog stop also cannot
be treated as an armed incoming early watchdog; the incoming driver does not
automatically start it during initramfs unpack.

## Failures outside that promise

- `arch/arm64/kernel/setup.c:170`, `setup_machine_fdt`, loops in `cpu_relax`
  for an invalid early DTB instead of panicking. Early entry/MMU faults, hard
  locks, blocked allocation or a decoder that never returns are not covered
  by `panic=10` merely being present.
- `init/initramfs.c:361`, `do_name`, returns without setting the unpack error
  when `filp_open` fails; mkdir, mknod and some metadata-operation returns
  are also ignored. By contrast `do_copy:414` turns a short/error write into
  an unpack error. Root memory/file-creation failure therefore does not
  uniformly imply a timed panic.
- `init/main.c:1458`, `kernel_init`, can fall back from `/init` through the
  normal init paths and finally `/bin/sh`. A successfully executed shell PID1
  need not panic or launch the recovery guard. A live kernel with a broken
  service root is consequently another distinct boundary.

Prior idle-NPU userspace heartbeat-expiry recovery is scoped evidence for
that later path, not a pre-init panic, hard-lock or forced-fallback test.

## Dictionary and memory placement

This change concerns the **embedded initramfs stream**, not pre-boot in-place
decompression of ARM64 Image. FIT's outer LZMA is decoded while preparing the
payload; the kexec loader maps an already uncompressed ARM64 Image.

The kernel's `xzmisc` recipe is CRC32, LZMA2 `dict=1MiB`, without BCJ.
`unpack_to_rootfs` supplies `flush_buffer`, so `lib/decompress_unxz.c:258`
chooses `XZ_DYNALLOC` and a 4 KiB output buffer. The existing embedded input is
used directly. `xz_dec_lzma2_reset:1162` allocates the dictionary through
`vmalloc` according to each block's properties. The wrapper passes
`UINT32_MAX` as its limit: **1 MiB is an admitted stream property, not a hard
kernel limit**. The historical standalone measurement has 42 blocks, all with
1 MiB dictionaries; that measurement is not the new Image's stream receipt.

The actual board declares 512 MiB RAM `[0x80000000,0xa0000000)` and these
`no-map` regions:

| Region | Range |
| --- | --- |
| NPU firmware | `[0x84000000,0x84400000)` |
| NPU packets | `[0x84400000,0x85a00000)` |

ARM64 reserves its Image and scans DT reserved memory before normal allocation.
Ordinary dictionary/output allocations therefore use allocator pages outside
these reservations. The old Image ends at `0x83fc0000`, leaving 262144 bytes
before NPU firmware; that gap is **not** where the dictionary must fit. Host
compressor RSS is likewise not target decoder memory usage. Peak target demand
also includes extracted file pages, inode/dentry metadata, page tables and the
rest of the kernel. A raw CPIO byte count alone is not a complete peak budget.

Before the new Image's static admission, verify its actual effective Image end
is at or below `0x84000000`, all loader segments remain within admitted RAM and
non-overlapping, and the DT/no-map/bootargs/PSCI inputs are preserved. Bind the
actual embedded XZ stream to its exact raw CPIO/root and check every block's
dictionary, CRC32 and filter properties. Confirm the full matching config has
built-in XZ support and that no compressed-stream/config drift was accepted.
Recheck the new root's memory demand with slack; a smaller compressed Image
does not shrink the extracted filesystem. These static checks and a successful
full target startup remain separate from the unqualified recovery cases above.
