# Explicit initramfs XZ profile — offline and startup admission

The explicit `--initramfs-xz` profile has completed the full offline chain for
FIT `a74f0524e775a8e0f9640b3fc262a6569a5ce8d069799da4aa90a53fb9b1b339`.
[The offline receipt](evidence/xz-profile-offline-20261113.json) binds its
configuration, fresh modules, signed root, exact embedded CPIO and Image.
The exact candidate has now passed target startup and controlled normal return
to independently authenticated stock. This is not normal-A53 main-root or
complete package-compatibility acceptance.

## Explicit source and configuration gates

[The fresh builder](../tools/build_fresh_arm64_kernel_v1.py) defaults to gzip.
XZ requires all three existing flags, `--integer-binfmt --guest-exe-file
--guest-interp-fd`, the fail-closed V2 revision2 source contract, and the separate
`--initramfs-xz` opt-in. Source locks, driver pins and strict unrelated-config
drift rejection remain enforced. Only reviewed raw `.cpio` input is accepted;
precompressed sources would bypass the kernel compression recipe and are refused.

The actual initial `olddefconfig` delta has exactly these six entries:

| Symbol | Qualified baseline | Explicit profile |
| --- | --- | --- |
| CONFIG_INITRAMFS_SOURCE | prior qualified path | reviewed raw native.cpio path |
| CONFIG_BINFMT_MISC | n | y |
| CONFIG_RD_XZ | n | y |
| CONFIG_DECOMPRESS_XZ | absent | y |
| CONFIG_INITRAMFS_COMPRESSION_GZIP | y | n |
| CONFIG_INITRAMFS_COMPRESSION_XZ | absent | y |

Existing gzip decoder support stays enabled. The final matching-root Image
stage permits only the subsequent INITRAMFS_SOURCE path change; compression
choice and decoder configuration must already match the fresh build receipt.

Pinned Linux6.18.55 `usr/Makefile` selects `xzmisc`, whose exact stdin recipe is
`xz --check=crc32 --lzma2=dict=1MiB`. No BCJ filter or extra preset is added.
Both build stages clear GZIP, XZ_DEFAULTS and XZ_OPT overrides. Receipts carry
`initramfs_compression=xz`, `initramfs_compression_profile=be6l-initramfs-xz-v1`
and recipe-file hashes through package, Image and payload preparation. Historical
receipts without those fields admit only legacy gzip; partial/mismatched
declarations cannot authorize XZ by its magic bytes.

## Fresh package and ABI chain

OpenWrt hashes the selected y/m lines of `.config.set` before
Kernel/Configure/Initramfs applies the compression choice. The actual preinit
input has INITRAMFS_SOURCE empty and no active compression choice. Injecting a
final XZ choice there would invent an ABI input. Its legitimate binfmt ABI thus
remains `7b648602069fdc1d228ca9bad74de7f2`; the recorded compression stage is
`post-preinitramfs`, with no fabricated preinit compression delta.

The new kernel package is
`6.18.55~7b648602069fdc1d228ca9bad74de7f2-r105`; legacy V2 gzip remains r104.
The equal preinit ABI does **not** authorize old module reuse. This chain built
all78 in-tree modules and all seven external modules afresh, checked85 compiled
module layouts, and selected77+7=84 module payloads for the unchanged service
selection. All57 kernel/module packages were normally signed and transacted
into the219-package root, with zero retained external modules. Full effective
config, build-receipt, Module.symvers, module-layout and package hashes bind the
new profile. Ten MTD guards and BMT read-only protection remain present.

## Actual new Image and embedded stream

| Artifact or bound | Measured value |
| --- | ---: |
| FIT bytes | 41467992 |
| Image file bytes | 50462728 |
| Effective Image allocation | 50855936 |
| Gap before unchanged NPU reservation | 14155776 |
| Embedded XZ stream bytes | 36496028 |
| XZ blocks | 42 |
| Dictionary in every block | 1048576 bytes |

The effective Image ends at `0x83280000`, before NPU firmware at `0x84000000`.
Its SHA256 is
`212c00de5e08cd3695e1a2f211e488b4821a0432b64aaa37e1123513a1965df1`.
The exactly matched external/embedded CPIO SHA256 is
`ad7be32289cea5df810bcea21697f5e4561295a55d5e0decc0dae1c9078a5bf3`.
These are final candidate measurements, separate from the earlier independent
compression estimates. They do not establish fit after adding the normal A53
main-root runtime, compatibility payloads or early bootstrap.

## Codec acceptance and its limits

[The verifier](../tools/verify_embedded_compat_cpio.py) checks receipt/config
agreement, the real object section's unique occurrence in Image, and exact raw
CPIO equality. For XZ it parses the complete stream/index and **every** block,
requiring CRC32 and a single LZMA2 filter with1MiB dictionary. It rejects extra
filters, empty blocks, oversized dictionaries, corrupt checks, truncation,
trailing bytes/padding, concatenated streams and mismatched CPIO. Gzip retains
its successful existing-Image semantics with strict single-stream decoding.

The explicit host admission limits are4096 blocks and512MiB external CPIO;
block count is bounded before constructing the record list. These are tool
policy bounds, not limits enforced by the target kernel decoder.

[Consolidated host evidence](evidence/xz-host-validation-20261113.json) preserves
the actual gate, independent review and decoder observations below.

| Evidence group | Result | Scope |
| --- | ---: | --- |
| [Codec/config gates](../tools/test_initramfs_compression_v1.py) | 54/54 | Existing real gzip Image, independent real42-block XZ stream, config/ABI policy and malformed fixtures. |
| Independent admission review | 12/12 | Separate real-stream verification and rejection checks, including bounded Index allocation. |
| [Actual Linux decoder harness](../tools/test_kernel_xz_host_v1.py) | 11/11 | Host-built actual XZ Embedded/unxz bodies, callbacks, CRC/truncation/allocation failures and dictionary-policy contrast. |

The decoder harness uses the earlier pinned42-block measurement stream; final
Image/CPIO admission is the separate binding above. The unchanged kernel
streaming wrapper uses XZ_DYNALLOC with UINT32_MAX. Its host test successfully
decoded a stream declaring a2MiB dictionary when allocation was allowed. Thus
1MiB is an enforced **artifact admission property**, not a kernel hard cap.
Host allocation accounting and compressor RSS do not measure target peak RAM
or boot time.

[The early-recovery audit](EARLY-XZ-RECOVERY-AUDIT-20261113.md) explains why
reported built-in-unpack failures can reach timed panic, while early hard locks,
failed reset and some partial-root paths remain outside that promise. Offline
acceptance does not prove unattended recovery from those failures. Target
startup, exact inventory/guards and return to authenticated stock require
separate observations.

## Actual target startup and controlled normal return

[The target receipt](evidence/target-xz-startup-20261113.json) binds the same
FIT to boot ID `c695fbae-aceb-4111-a514-5921af036506` and actual/expected kernel
build ID `4aff18c675e83c59cc4b4c403a9c32808fb67079`. Startup acceptance passes:

* Dual-CPU aarch64, RAM root, all ten MTD guards and unchanged critical-partition
  digests; exact219 installed packages,84 modules and61 private-native ELF files.
* Native PID1 and netifd; default native fs/ubus/uloop/uci/nl80211 modules mapped;
  required services run without respawn and all required application selections
  are preserved. The recovery guard accepts its authenticated heartbeat.
* NPU workers advance with zero reported faults. LuCI returns HTTP403 with its
  login form rendered, including the selected Argon/Chinese interface. This
  does not qualify routed NAT or a successful authenticated LuCI login.

Parsed kernel milestones place init execution at25.499521 seconds and freeing
init memory at25.494726 seconds. They include other kernel work and are not a
decoder-only timing measurement. The post-startup sample reports MemTotal473228,
MemFree219952, MemAvailable197388 and Shmem131508, all in KiB; it does not measure
peak decompression/unpack memory.

The original offline root remains unchanged and no flash operations occurred.
A guarded normal reboot request exits SSH successfully; the125-second UART
capture observes reset without interrupting autoboot. That capture itself does
not authenticate stock. A separate Firmware67 CheckOnly succeeds, followed by
an independent read-only probe of new stock boot
`75f6c090-b563-4d68-9fa0-c033f059f659`: firmware V16.03.60.67_cn, kernel5.4.55,
armv7l and `/dev/root / squashfs ro`, with no RAM root. Both ARM32 and ARM64
heartbeat sessions are terminal.

The target receipt binds the reset and independent-stock receipt hashes. This
qualifies this candidate's **controlled normal return**. It does not test the
default disconnect timeout or early hard-lock recovery, and does not qualify
normal-A53 main-root compatibility, peak decoder memory/time or routed NAT.
