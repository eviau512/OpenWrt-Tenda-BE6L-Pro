# Native64 and X-Wrt continuation, 2026-11-05

This checkpoint contains source and offline component results. The last
qualified RAM image is unchanged. No new image has been booted or flashed.
Selected source hashes and scoped results are in the
[sanitized evidence receipt](evidence/continuation-20261105.json); raw logs and
signing material are excluded.

## Results and scope

| Change | Passed | Remaining |
| --- | --- | --- |
| Native netifd | Real Linux backend, opt-in soft64 VM module paths, 15-ELF static ABI and symbol closure | Dynamic child/script coverage and default-service target execution |
| Signed APK composition | Latest 216-package root becomes 218, owner/bytes/modes checked, wrong ordinary ARM64 architecture refused | Normal SDK integration, matching kernel/modules and Image/loader admission |
| SSH recovery | 21 shell/host test groups on Windows sh and Ubuntu sh, signed component installed and enabled offline | Actual procd/watchdog/reset and stock return |
| X-Wrt SRAM policy | Source port, 129 actual-function host checks with UBSan, four real ARM64 units and composite link | Complete kernel/module build and actual hardware acceptance |
| Root archive | Normal newc/gzip, 1,700 candidate file/link payloads checked, compressed growth 75,808 bytes | Complete Image size and exact embedded CPIO admission |

The netifd composer upgrades the existing package rather than overwriting files
outside the package manager. Four native VM modules already belong to the base
soft runtime and remain identical. The new dependency package owns only the
missing libnl-tiny and nl80211 ELF files plus source notices. Recovery adds the
second new package. Original netifd script dependencies remain; this is still a
mixed userspace, with an explicitly selected native network-manager binary in
the new offline root. The existing root is not modified.

The experimental package architecture is `aarch64_be6l_soft_experimental`.
Clang21 AAPCS64-soft, `-march=armv8-a+nofp+nosimd`, the private interpreter and
per-consumer symbol scopes are required. Ordinary Cortex-A53 AArch64 packages
are incompatible with the observed CPU. No HWCAP or CPU capability is invented.

## X-Wrt reference

The review pins [X-Wrt](https://github.com/x-wrt/x-wrt/tree/5ae8e6912e64682fcad54593467e84c80f170656)
and records the twelve selected source files in
[`upstream/xwrt-an7563-20261105.json`](../upstream/xwrt-an7563-20261105.json).
Its AN7563 target is AArch32; it supplies hardware-driver reference code, not a
native64 runtime. The initial port adapts patch 941-06 only for AN7563: CPU SRAM
mirror allocation, no DRAM FOE table base/hash enable and bounded entry access.
Other SoCs retain their existing DMA policy. Native PPE uses the CPU SRAM path;
wireless NPU queues are a separate interface. Existing routed rejection remains.

The 129 tests use seven extracted real functions and real constants but replace
host types, allocation and register I/O. They exercise bounds, allocation/ACK
failures and other-SoC controls. The four translation units additionally compile
against the actual configured ARM64 kernel headers, then link with `ld -r`.
Neither step proves ASIC behavior, drainage or resource lifetime.

Next NPU work is the 941-04 resource-retention policy and its callers: an ACK
timeout must not release an SMAC/FOE owner still visible to hardware. A controller
ACK alone does not establish packet drainage. Keep routed admission closed until
the native action, withdrawal/lifetime and controlled traffic tests are complete.
Coherent mailbox support already present in the baseline is not a new port.

## Reproduction inputs and order

The repository remains selected source, not a complete SDK. Use the locked source
revisions, a fresh Linux filesystem and verified soft runtime/profile inputs.
Each helper refuses an existing work directory; retain failed attempts and use a
new name. Required arguments are listed by each helper's `--help`.

1. Run `tools/prepare_native_netifd_v3.py` against the pinned netifd source.
   The published `patches/native64/001-netifd-soft64-ucode-paths.patch` is its
   generated delta. Build with `tools/build_native_netifd_v3.py`, the admitted
   90-path service profile, private soft sysroot, Clang21 and cached GNU linker.
2. Run `tools/package_native_netifd_v3.py` against a fresh copy of the qualified
   diagnostic root with the host APK3 tool and host bash. It generates temporary
   fixture signing material, verifies signatures, simulates the valid transaction
   and wrong-architecture control, installs normally, enables recovery offline,
   and checks ownership and the entire root delta. It executes no target service
   and removes its temporary private key on exit. Binary redistribution is not
   admitted by this fixture result.
3. Run `tools/prepare_xwrt_sram_port_v1.py` against the pinned Airoha driver.
   The generated source is checked by `tools/test_xwrt_sram_policy_v1.py` and
   `tools/build_xwrt_sram_objects_v1.py`. Host tests need a working GCC/UBSan
   sysroot; the object build needs matching ARM64 configuration, generated kernel
   headers, compiler command records and the cached cross compiler.
4. Run `python3 tools/recovery/test_recovery_guard.py` for the independent guard
   suite. Its clock, platform and reboot effects are substituted. Read the
   [guard instructions](../packages/be6l-recovery-guard/README.md) before using
   the authenticated heartbeat helper in any new image.
5. `tools/measure_native_netifd_cpio_v3.py` binds its input to the composer's
   file/link/directory-mode fingerprints. It builds both baseline and native
   archives with standard host cpio, Linux gen_init_cpio and gzip, checks every
   regular/link payload and decompression, and preserves the inputs. The native
   archive is 130,340,864 bytes, compressed to 50,367,937 bytes. Its measured
   75,808-byte compressed growth is not an Image-bound or new-driver acceptance.

These helpers do not automatically apply their output to either SDK. Full image
integration must preserve all ten MTD/BMT guards, normal gzip initramfs bounds,
exact module/package ownership, the qualified application selection and the
no-person-on-site bootstrap/recovery gates. The old Telnet distribution embeds
an older image and is not admission for this candidate.

## Environment and acceptance still open

The original Linux archive was deleted. Reconstruction from its member manifest
retains links/modes; 469 damaged generated cache files are explicitly omitted and
must be regenerated from locked sources. Copy progress is not build admission.
Ubuntu's global package configuration is incomplete under WSL1. A separate
versioned host-tool sysroot successfully runs Clang21, CMake and host GCC/UBSan;
it does not imply system package repair or a maintainable target SDK.

The recovery guard uses a 600-second boot grace and 300-second heartbeat expiry.
It cannot execute during a full kernel lock, and historical warm reset can stall
in U-Boot NAND initialization. Real recovery back to stock still needs proof.
Native Go/runtime, C++/btop and a formal soft64 SDK remain open. Routed NAT,
IPv6 offload and Linux per-flow hardware statistics remain unqualified.
