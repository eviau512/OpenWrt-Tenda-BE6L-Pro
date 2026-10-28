# Bridger build inputs and acceptance gates

## Protected RAM image and automatic forwarding, 2026-10-28

The completed candidate `b3ec883f5b6c2d90737d138e621ebf0a185bbd199d0757c9a35ef24cb4eea0dd`
has booted from RAM. Its84 AArch64 modules match the final kernel/config/ABI;
216 actual installed package records retain the58 native soft-ABI ELF profile.
Bridger is enabled, network defaults have normal APK ownership, and Tailscale
and Passwall remain disabled. Ten MTD/BMT guards, native PID1/libc, strict Bing
TLS, Chinese Argon UI/Lua and advancing NPU workers passed. No flash operation
or Windows firewall change was needed.

Actual effective Image size is64,684,032 bytes with327,680 bytes before the
reserved-memory boundary. The129,955,840-byte CPIO SHA-256 is
`22f2d8185239cb91958dc1f9454e8fc157b02dc4972ba7176bc34059cae40dde`.
The actual embedded archive, loader-file bytes/modes, native APK signatures and
owners were checked; its independent RAM chroot loader test passed.

Automatic5GHz L2 forwarding passed20seconds per direction at894/395Mbit/s,
CPU5.0/4.2%, with integrity/reassociation and teardown checks. Exact peer
MACs, both daemon-created hardware flower directions, corresponding native L2
BIND entries and positive PPE progress were required. No manual TC rule was
inserted. This establishes automatic L2 forwarding; NAT/IPv6 routed offload
and genuine per-flow accounting remain unqualified.

This image also passed300seconds in each direction at751/381Mbit/s and
CPU7.1/4.7%, including exact rule/BIND/PPE checks and AP-down cleanup. No NPU
fault occurred. Final digests/protections/heartbeats/strict TLS passed; test
networks, keys and phone policy rules were removed while bridger stayed enabled.
This does not inherit older-image CPU controls, driver-exit or2.4GHz acceptance.
These runs were sequential normal/reverse transfers, not simultaneous full
duplex. A parallel upload/download test remains a separate acceptance item.
The firewall hardware-offload checkbox still cannot grant routed WAN/NAT
binding through this driver; higher CPU on that separate path is expected.

An offline native-service budget projection adds32ELF paths and601768gzip bytes,
exceeding the current327680-byte headroom by274088bytes before new package/profile
costs. Only deliberately unbootable private budget streams were produced;
normal stronger compression/smaller closure and actual image proof remain.

The versioned image driver and CPIO/ABI admission helpers are now included as
experimental build sources. They preserve the original validators and reject
wrong provenance, module layouts, native ownership and Image size. During
development an empty no-pattern APK query was corrected to an explicit `*`;
the216-record receipt replaced the empty metadata without altering image bytes.
The older partial-build checkpoint below is historical.

## Owner-requested build checkpoint, 2026-10-28

The clean ARM64 kernel with 973/974 and BPF/VLAN selections, first matching
external modules and initial normal kernel/kmod APKs built. A standard
baseline-CPIO install established the final initramfs configuration. The owner
then requested closeout; the final-config external rebuild was stopped and no
build worker remains. Final APK audit, fresh native58/bridger root, intended
CPIO and admitted image have not been produced. Intermediate SDK FIT outputs
are not this candidate. Current hardware remains on the earlier RAM image.

The new `tools/ppe_module_abi.py` records numeric flow-rule layout and exact
per-module vermagic/struct-module data. Its isolated preflight found 48-byte
flow_rule, action offset40 and 16-byte CT context at24/version1; struct module
was704. Re-probe the final configuration and rebuild all consumers before
accepting modules. The incomplete image driver stays private and unqualified.

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
