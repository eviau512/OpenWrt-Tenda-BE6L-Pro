# Reference build procedure

## Scope

This is the reference two-SDK experiment: an ARM32 soft-float userspace, an
AArch64 COMPAT kernel, matching AArch64 modules and signed ARM32-collection
kernel/kmod APK metadata. It is not a finished single OpenWrt multi-ABI target.
The exported source inputs are reviewed separately from runtime qualification;
changing a build produces a new image requiring its own RAM-only acceptance.

The scripts currently use `/root/be6l-openwrt` as their reference Linux work
directory. The repository itself may live elsewhere, including a Windows
checkout mounted into WSL. Use a Linux filesystem for source/build directories.
Do not put private data inside the source repository.

Use a supported Linux build environment with the normal OpenWrt build
dependencies, Python 3.9+, Git, Bash 4.4+ and GNU tar 1.28+. A fresh environment
has not yet completed end-to-end reproduction of this exported wrapper. The
individual underlying build/assembly stages have been exercised in the bring-up
environment; the clean-checkout reproduction remains an explicit TODO.

## Prepare fixed sparse sources

```
python3 tools/prepare_sources.py --apply
```

This initializes partial repositories, fetches exact recorded commits at depth
one with `blob:none`, and checks out only the recorded sparse paths. It never
does a full OpenWrt checkout or a blanket feed update. Existing checkouts must
match their recorded commit. Patch application is checked before mutation.

Build labels in exported configurations are generic. Signing keys are generated
by the build environment and are not included in this repository. As a result,
an independent build is not promised to match a prior signed image byte for
byte. Keep its own configuration, manifests, signatures and hashes.

## Build and assemble

```
bash tools/build_reference.sh
```

The sequence is:

1. Build the ARM32 source tree with LuCI, full wpad-mbedtls and selected tools.
2. Build the AArch64 COMPAT kernel and selected modules. The temporary native
   AArch64 userspace image is not a usable BE6L Pro image and must not be booted.
3. Compose the ARM32 root with the matching AArch64 module payloads.
4. Invoke the native OpenWrt kernel/kmod APK packaging rules with
   `ARCH_PACKAGES=arm_cortex-a7` into an isolated raw directory.
5. Admit only signed `kernel-` and `kmod-` APKs after ELF, ABI and module-payload
   auditing. Automatically emitted AArch64 userspace dependencies remain
   quarantined and must never become an installable feed.
6. Install the admitted packages through normal offline APK solving and
   signature verification. Pin the exact kernel ABI; do not force the solver or
   edit its database to hide a mismatch.
7. Build external CPIO and run the standard OpenWrt image-install target.
8. Verify that the CPIO actually embedded in the FIT kernel matches the audited
   external CPIO, and validate DT/MTD protections and ELF architectures. Compile
   a fresh, never-loaded module-layout probe against the current kernel headers
   and compare every module's `.gnu.linkonce.this_module` size with that probe.

The module-layout guard addresses an observed incremental-build failure:
enabling event tracing changed ARM32 `struct module` from 448 to 768 bytes,
while seven cached external modules retained the old size. A normal image build
had exited successfully, but those modules could not load. That diagnostic image
was recorded as failed. Package metadata and matching ELF architecture alone
would not have detected this. Clean/rebuild the affected external packages after
such kernel configuration changes; do not force a stale module to load. The
layout guard supplements, rather than replaces, exact kernel ABI dependencies,
configuration hashes, payload hashes and hardware acceptance.

Do not install AArch64 userspace packages based on `uname`. The package universe
is `arm_cortex-a7`; actual kernel modules are ELF64/AArch64 and depend on the
exact running kernel ABI. A kernel change requires a matching RAM image and
RAM boot. General live kernel/kmod upgrade support has not been qualified.

The output under `artifacts/arm64-compat/` is still unqualified until hardware
acceptance completes. No build command in this repository flashes a device.
Payload preparation, transport and the verified firmware handoff must retain
the checks used during bring-up; do not guess SMC identifiers or reset writes.

## Offline experimental tests

```
python3 tools/test_routed_frame_offline.py
python3 tools/generate_routed_selftest.py
python3 tools/test_flow_lease.py
```

These are packet-action and serialized lifecycle prototypes. They are not
enabled routed offload or production Linux per-flow statistics.

## Native soft-ABI research extension

See [SOFT-APK-BUNDLE.md](SOFT-APK-BUNDLE.md) and [SOFT-NETIFD.md](SOFT-NETIFD.md).
`prepare_soft_package_profile.py` creates a review lock from pinned cached C,
Lua and TLS closures. Review compiler/source/license and actual ELF evidence
before supplying its independently obtained digest to `build_soft_apk_bundle.py`.
The latter signs, extract/admit-checks and normally transacts four packages in
a fresh offline root, including a same-label FP-provider rejection experiment.

`build_soft_apk_image.py` consumes that root, runs the standard kernel image
target and restores the baseline CPIO in finally. `verify_soft_apk_manifest.py`
exports actual mixed-root package records; native SDK staging is not that root.
Never hot-replace PID1 libc.

These are research extensions with documented pinned cached inputs and recovery
receipts, not a standalone official native SDK. Artifact-specific paths still
need complete versioned recipes and dual-toolchain ownership. Generic upgrades,
binary redistribution licensing and new-image acceptance remain separate gates.
