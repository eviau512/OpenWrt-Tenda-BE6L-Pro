# Bridger build inputs and acceptance gates

Future initramfs builds select `bridger` for automatic L2 bridge acceleration.
This selection does not add IPv4 NAT or IPv6 routed PPE support. Those paths
retain their existing rejection and CPU fallback until independently implemented
and qualified.

## Frozen inputs

- OpenWrt revision: `30b833ae5b8a6ba94149268c47a8493308a0ee04`.
- Bridger source revision: `de7e00a5a673fdda38d3326b624c45facc6245d2`.
- Source mirror SHA-256: `480047262ad886699f8abd8b25a8c292b190648d0098d207c2d1e260d0e97ab2`.
- OpenWrt recipe: `package/network/services/bridger/Makefile`.
- Extra sparse source directories: `package/network/services/bridger` and
  `package/kernel/bpf-headers`. The AArch64 kernel SDK also needs its matching
  `package/libs/libbpf` and `package/libs/elfutils` recipes.
- Runtime dependencies: libbpf, libubox, libubus, libudebug, libnl-tiny,
  kmod-sched-core, kmod-sched-flower, kmod-sched-bpf and kmod-sched-act-vlan.

The BPF program is a little-endian eBPF object, not an AArch64 userspace binary.
The current mixed system still needs an ARM32 soft-float bridger executable and
libraries, together with modules built for its exact AArch64 kernel. Do not
select userspace packages by `uname -m`, install ordinary A53 floating-point
packages, or substitute ARM32 modules into the AArch64 kernel.

## Prepare before building

`tools/prepare_bridger.py` accepts an existing pinned sparse checkout and checks
the recipe and host compiler. Run it with `--apply` for both SDKs before their
normal `make defconfig` stages. Provide `--llvm-root` when the host tools are not
in a detected `/usr/lib/llvm-*` directory.

The host LLVM installation must supply clang, llc, llvm-dis, opt and llvm-strip,
including the BPF backend, with all five tools from the same major version. A
clang executable alone is insufficient. The helper
selects the OpenWrt host-LLVM mode and refuses incomplete tools, rather than
starting an LLVM source build. It does not invoke make, modify a device, deploy
a package, alter packet-steering settings or relax any flash protection.

The development host initially lacked four tools. They were supplied by the
fixed Ubuntu `llvm-21=1:21.1.8-6ubuntu1` package, SHA-256
`9227b4149f0f553a58befd85bc905f1c91719dbae1c1971fade102f53692a40b`.
`tools/fetch_bridger_host_llvm.py` can privately extract the four necessary
binaries and package copyright when the matching clang/libLLVM are already
installed. It downloads 20,012,922 bytes, verifies the package against both the
lock and Ubuntu package metadata, and does not install or upgrade system
packages. Other hosts may supply their own complete LLVM installation instead.

The previous hardware-qualified kernel lacks `CONFIG_NET_CLS_BPF` and
`CONFIG_NET_ACT_VLAN`; installing bridger into that RAM system is not sufficient.
Generate the new kernel configuration, matching module APKs and package-owned
rootfs through the normal two-SDK build. Revalidate module layouts, package
ownership, RAM image boundaries and the changed CPIO before RAM boot. The full
`wpad-mbedtls` selection and all initramfs-only protections remain required.

## Hardware acceptance still required

The normal ARM32 package build has passed. The 18,275-byte signed APK has SHA-256
`9065bb93f8d86d9fcedff37b9dc578874c8d34e7bb2697626db3d3643dff1a39`;
its architecture and ARM soft-float EABI were checked after offline signature
verification and extraction. Its 9,440-byte eBPF object has SHA-256
`42d53111ef61c31712002faac2d2681e45aaea225c9cbedadd3ba0759e428740`.
The packaged object matches the built bytes and includes its license section.
This built package is not included in the source-only repository.

No bridger package has been deployed or hardware-qualified by this change.
The prior manual L2 flow tests do not qualify bridger's automatic rule lifecycle.
After a new protected RAM image boots:

1. Verify service startup, BPF object loading, TC attachment and software fallback
   before generating traffic. Confirm that route/NAT requests still reject.
2. Create a temporary WPA2-PSK/CCMP AP with a fresh random key at runtime. Check
   actual 5 GHz bridge forwarding, SHA-256 integrity and positive PPE forwarding
   counters. Keep the unreliable test client's 2.4 GHz result excluded.
3. Check disconnect/reconnect, station reuse, bridge/port changes, service stop
   and restart, radio-driver teardown and CPU fallback. Observe which TC rules
   belong to bridger; do not remove unrelated filters.
4. Confirm no stale bindings, keys, filters or test networks remain. Repeat the
   flash read-only and NPU health checks. Qualify a reliable 2.4 GHz peer and Mesh
   separately.

The upstream default config enables bridge-local TX and leaves bridge-local RX
disabled. Do not infer that either setting makes a routed connection eligible
for hardware NAT, or use a LuCI checkbox as forwarding evidence.

On the old WSL host, the BPF-header recipe's `yes '' | make oldconfig` input
generator remained blocked after configuration finished. Only that verified
build-owned `yes` child was terminated, allowing normal header preparation to
continue. This host intervention is recorded separately from the successful
package build; it is not a kernel or device change. The build now uses the
standard `olddefconfig` step through
`upstream/bpf-headers-olddefconfig.patch`. The tiny recipe change is applied to
both pinned SDKs. Running it on the built private eBPF-header tree completed
without an input generator and preserved its configuration byte for byte:
SHA-256 `753356d058f08345e7d92296bca57ec4cd8da6af5e472d2fc3ba0118e6792381`.
No options were added or removed; no kernel was rebuilt by this compatibility
check. The original package-build log and its host intervention remain retained.
