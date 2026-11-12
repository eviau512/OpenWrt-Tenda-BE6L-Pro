# Normal A53 packages in the main root — inventory and unimplemented plan

This review reads the actual r104 main root at
`/root/be6l-kernel-apk-guest-interp-20261111-r2/root` and the signed28-package
fixture `/root/be6l-standard-a53-guest-20261106-r6`. Neither root was changed.
No mixed-root APK transaction or target test was performed. The existing
isolated-root tests do not qualify a main root or complete normal A53 package
compatibility. Privileged exec remains separately unimplemented.

The [inventory tool](../tools/inventory_mainroot_a53_v1.py) reads APK ownership,
ELF PT_INTERP/DT_NEEDED/SONAME/RPATH/RUNPATH and root-relative symlinks without
executing target code. [Compact evidence](evidence/mainroot-a53-inventory-20261112.json)
binds the full private report, database hashes, exact package sets and manifests.
Both complete root digests were recomputed and match their existing receipts;
the normal fixture's non-ELF payloads have not silently changed either.

## Measured coexistence boundary

| Inventory | Actual result |
| --- | --- |
| Main packages | 219; etc/apk/arch lists arm_cortex-a7 and aarch64_be6l_soft_experimental, not normal A53. |
| Main executable/DSO ELF | 144 ARM32 +61 private integer A64; kernel ET_REL modules are excluded. |
| Standard fixture | 28 packages,30 normal A64 ELF with e_flags0; every ELF hash matches its existing signed-fixture receipt. |
| Package names | All28 already exist at the same version:27 ARM32, one identical noarch ca-bundle. |
|253 standard owned paths | 33 differ,219 are identical, one is absent: lib/ld-musl-aarch64.so.1. |
| Current ARM32 closure | 75 real DSO files +39 symlink aliases; all466 DT_NEEDED edges from144 ARM32 ELFs resolve to ARM32. These are the complete currently selected DSO/module inventory, not a proof of every dynamic load. |

Installing just the normal loader is insufficient. Existing `/lib/libc.so`,
`/lib/libgcc_s.so.1`, common `/lib` DSOs and `/usr/lib` DSOs are ARM32.
`/lib/ld-musl-arm.so.1 -> libc.so`; replacing libc with the normal A53 package
would therefore also redirect the ARM32 interpreter to an A64 file. Existing
ARM32 apk, dropbear, dnsmasq, wpad, rpcd and other selected services need their
own closure. Merely adding A53 to the arch file does not fix this.

The61 private A64 files have five actual owners: be6l-soft-runtime,
be6l-soft-tools, be6l-soft-netifd-deps, procd and netifd. Their dynamic programs
use `/lib/ld-musl-aarch64-soft.so.1 -> aarch64-soft/libc.so` and
`/etc/ld-musl-aarch64-soft.path` contains only `/lib/aarch64-soft`.
They have no direct payload collision with the28 normal packages. Preserve
this separate ABI; never label these files as normal A53 or satisfy a normal
library dependency using their generic ELF machine value.

## DT_NEEDED closure is not the module closure

Actual embedded strings and needed edges expose additional work:

* Both ARM32 and private A64 liblua still default to `/usr/lib/lua/?.so` and
  `/usr/lib/lua/loadall.so`; both libucode variants contain
  `/usr/lib/ucode/*.so`. A private loader .path does not redirect these VM paths.
* Private netifd explicitly contains `/opt/be6l-a64-soft/lib/netifd/*.so` and
  `/opt/be6l-a64-soft/lib/ucode/*.so`, but that does not qualify every other
  private Lua/ucode entry point. Their compiled defaults or per-VM initialization
  must be corrected in private code; global LD_LIBRARY_PATH/LUA_CPATH/UCODE_PATH
  or a CLI-only wrapper is not a complete solution.
* ARM32 wpad embeds libucode; rpcd loads its ARM32 ucode plugin, which embeds
  libucode; ucode/lua.so embeds liblua. They must never load a normal A53 module
  into their ARM32 process. Likewise, normal A53 Lua/ucode cannot use the
  remaining ARM32 modules in their global default directories.
* Current rpcd contains `/usr/lib/rpcd`; pppd contains `/usr/lib/pppd/2.5.4`.
  Current uhttpd has its ARM32 ubus plugin. **uhttpd-mod-lua and uhttpd-mod-ucode
  are not installed**; their init-script conditionals do not prove otherwise.
  Preserve the actual ubus selection; adding an embedded VM later requires a
  new plugin/ABI review.
* Private procd contains `LD_PRELOAD` and `/lib/libsetlbf.so`. That file is
  ARM32, owned by be6l-arm32-procd-compat. A blanket preload cannot serve
  ARM32, private soft A64 and normal A53 children. A future launcher change must
  preserve the intended buffering behavior using the child's actual ABI and
  an admitted matching DSO, without exporting a global ABI-changing environment.

The fixture replaces four of20 current Lua/ucode module ELFs. Retaining the
other16 module selections with normal A53 Lua/ucode requires these additional
normal package names, plus their normal dependency closure:

`liblucihttp-lua liblucihttp-ucode libubus-lua libuci-lua luci-base luci-lib-ip
luci-lib-jsonc luci-lua-runtime lyaml ucode-mod-digest ucode-mod-html ucode-mod-log
ucode-mod-lua ucode-mod-nl80211 ucode-mod-rtnl ucode-mod-uloop`.

Their present ELF edges also require normal liblucihttp0, libnl-tiny1 and libyaml
beyond the28 fixture packages. Thus47 names are an **ELF/module lower bound**,
not an admitted full APK solution. Nine of these19 additional names have no APK
in the inspected A53 SDK bin/staging package caches: liblucihttp-lua,
libubus-lua, libuci-lua, libyaml, luci-lib-ip, luci-lib-jsonc, luci-lua-runtime,
lyaml and ucode-mod-lua. Build/sign/verify the missing ordinary A53 packages
and solve the real metadata graph; do not substitute private soft modules.

## Smallest coherent implementation path to review

1. **Give the normal ABI the canonical layout.** Normal signed A53 packages own
   their unmodified canonical programs, `/lib/libc.so`, normal loader and normal
   DSO/module directories. Preserve archive signatures, ELF headers, PT_INTERP,
   DT_NEEDED, code and data bytes. Do not patch ordinary packages to private
   prefixes, relabel architecture, or re-sign altered normal payloads. Normal
   package-managed conffiles/alternatives are separate observable transactions.
2. **Package a complete ARM32 compatibility closure.** A new private, normally
   signed `be6l-arm32-runtime` can own the75 DSO files and39 aliases under
   `/lib/be6l-arm32` and `/usr/lib/be6l-arm32`, with an architecture-unique
   `/lib/ld-musl-arm.so.1` pointing to its libc and
   `/etc/ld-musl-arm.path` selecting only the ARM32 DSO directories. Record source
   and destination hashes; relocation alone can preserve these ELF bytes.
   Keep all selected executables/services. No normal A53 package may resolve a
   dependency to this private ABI, and no ARM32 DSO may fall through to normal
   A53/default private A64 files.
3. **Isolate each plugin/VM ABI as well.** Keep original ARM32 module bytes in
   private module directories and provide normal signed A53 modules in canonical
   directories. Loader .path alone cannot implement this: rebuild or change
   private VM/consumer initialization for ARM32 libucode/liblua users, rpcd,
   pppd/uhttpd plugin selection where required, and private A64 VM defaults.
   Any changed compat ELF is a new reviewed private artifact, not an unchanged
   relocated original. Audit programmatic dlopen/require paths and preload
   behavior, rather than inferring success from the inventory's string scan.
4. **Fix APK ownership/dependencies explicitly.** The runtime comes from70
   current DSO-owning packages; the evidence lists every source package.
   Consolidation into the one private runtime package avoids inventing70 ABI
   providers, but retained ARM32 consumers must gain an explicit versioned
   compatibility dependency. Split or rebuild/re-sign private compat metadata
   whose old global DSO ownership is transferred; do not leave duplicate owners.
   Where both ABI-specific package identities are retained, rename the private
   identity (for example be6l-arm32-libc), and never provide generic libc,
   libgcc/libstdcpp/libubus or *-any aliases to satisfy normal A53 dependencies.
   The evidence enumerates93 remaining ARM32 ELF-owning package names after
   only the28-name replacement, or74 after the47-name ELF/module lower bound;
   audit every retained consumer's metadata rather than guessing from arch.
5. **Rebuild the affected private signed package set.** be6l-soft-runtime needs
   VM-path corrections; be6l-soft-tools and be6l-soft-netifd-deps need updated
   exact runtime bindings. procd needs the mixed-ABI launch/preload fix and
   updated compatibility dependency; netifd needs its exact dependency/inventory
   rebound. be6l-arm32-procd-compat must transfer or rename its old global DSO
   ownership. Keep these distinct from unchanged normal archives. Generic procd
   and netifd names presently represent private selected implementations:
   co-installing ordinary packages of the same name/path is a separate unresolved
   service-replacement policy, not silently supported by renaming metadata.

Normal APK has one installed identity for a given P; a different A field is not
a simultaneous libc slot. Here P/V are identical across both ABIs, so an
"already installed" message is not proof of migration. A future private-copy
transaction must admit normal A53 plus retained ARM32/private arches, verify all
normal/private signing keys, supply exact reviewed archives/checksum constraints,
simulate first, and query actual installed A/C/V plus every owned payload after
commit. Preserve the complete world/service selections and existing kernel/module
pins. Do not use --allow-untrusted, --force-overwrite, broken-world deletion or
manual DB editing. Architecture preference/provider behavior must be measured
with this APK3.0.5 client; no mixed-root transaction was run by this review.

Two concrete alternatives also need preservation: current `/sbin/ip` selects
ip-full and `/usr/bin/timeout` selects coreutils-timeout, while the standard
busybox payload selects its applets. Use reviewed normal alternatives/trigger
semantics to retain those selected tools; do not quietly replace their behavior
or call an unexplained post-copy symlink change a pristine package transaction.

## Boot and acceptance gates

`/init` currently starts with `#!/bin/sh` and immediately calls shell utilities
before switching root. Normal busybox would make that interpreter a normal A64
ELF. Late SSH registration cannot protect the first exec. A separately admitted
native static early bootstrap must precede the first normal A64 shell, verify
the complete private ELF inventory and the exact trusted signed integer r5
interpreter, and establish POFX dispatch before continuing normal init.
It must retain the native recovery daemon/strict-SSH path independently and
keep all ten MTD/BMT guards read-only. This bootstrap is not implemented here.

Only then build a fresh private main-root composition with the exact matching
kernel/modules, preserve every current service choice, and verify normal signed
transactions, ABI-correct DT_NEEDED **and dlopen** closure, alternatives,
package scripts, boot ordering, all native/emulated child chains and real service
behavior in the main root. Credentials/secureexec remain a separate blocker.
No root, image, bootstrap, service migration or full package-compatibility gate
is marked passed by this inventory or plan.

## Bounded compression measurement, without a new candidate

[The compression evidence](evidence/mainroot-compression-20261112.json) measures
the unchanged admitted130342912-byte native.cpio and the actual signed-package
r5 interpreter independently. Four streams round-trip to their input hashes.
No combined archive, new Image, configuration edit or root change was made.

Linux6.18.55 `usr/Makefile` maps GZIP to `gzip` and XZ to `xzmisc`.
`scripts/Makefile.lib:316,436` gives the exact stdin recipes used here:

```
gzip -n -f -9
xz --check=crc32 --lzma2=dict=1MiB
```

No extra compression preset, ARM64 BCJ filter or -T option was added. GZIP,
XZ_DEFAULTS and XZ_OPT environment overrides were removed. Pinned host tools
were gzip1.14 and XZ5.8.3; that XZ's defaults produced42 blocks for the CPIO and
three for r5. Tool hashes, actual arguments and host-only timing/RSS are retained.

| Unchanged input | gzip stream bytes | exact xzmisc stream bytes |
| --- | ---: | ---: |
| Current native.cpio,130342912 bytes | 50377701 | 36496044 |
| Packaged private r5,7681368 bytes, separate stream | 2107565 | 1507932 |

The reproduced gzip hash exactly matches current `usr/initramfs_inc_data`:
`b3502898cba79b8e651002d842c2f251c29c13c04197ceebfa3ece4d753016c8`.
XZ saves13881657 bytes on **this unchanged CPIO stream**. The current Image is
64356360 file bytes,64749568 effective bytes and has262144 bytes before the
unchanged NPU reservation; its SHA256 remains
`f3406d41f29e70b86d2225e2ef3b826b97efb955400d5dc1d900bb172f5a4120`.

The r5 numbers are independent streams, not its marginal cost in a future CPIO.
They must not be added to predict a final CPIO/Image. The normal A53 runtime,
compatibility duplicates, module/path fixes and early bootstrap have not been
composed or measured. Outer FIT LZMA compression cannot by itself reduce the
effective expanded Image address range. No future main-root fit is established.

Current config has RD_GZIP/DECOMPRESS_GZIP and INITRAMFS_COMPRESSION_GZIP;
RD_XZ/DECOMPRESS_XZ are off although XZ_DEC is already on. A future explicit XZ
profile needs RD_XZ, its selected DECOMPRESS_XZ, and the XZ compression choice
instead of GZIP, with the actual olddefconfig delta reviewed. Existing final
Image tooling admits only an INITRAMFS_SOURCE delta; it cannot silently admit
this new profile. Rebuild the complete kernel and matching modules, repeat the
85/84 module-layout/package checks, signed packages, CPIO/Image/loader and
address-bound admission. Keep all selected services and MTD/BMT protections.
The1MiB stream dictionary is not a measured target boot-memory budget; target
decoder/unpack memory and boot time remain untested. No new candidate was built.
