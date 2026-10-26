# Native soft-ABI package namespace: prototype and integration gates

2026-10-26. The isolated native C closures are reproducible and DUT-tested, but
the running b05 image still has ARM32 package records around native init/procd
overrides. General upgrades remain unqualified. This document records an actual
host-only APK experiment and the work required before image integration.

## ABI identity comes before an architecture label

Arm defines a soft-float PCS variant for Armv8-R, incompatible with the base PCS.
Using Clang's implementation on this Linux target remains an experimental
platform choice; it does not make ordinary A53 packages compatible.
[Arm AAPCS64 section7.4](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst#74-soft-float)
also explains that toolchain support is not mandatory.

AAELF64 assigns machine183 and requires `e_flags` zero. Neither an ELF64 header,
the AArch64 machine value nor zero flags proves this soft calling convention.
[Arm AAELF64 ELF header](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst#52-elf-header).
Do not invent a processor flag. Admission needs the pinned compiler/profile,
source/configuration provenance, complete audited dependencies and target tests.
Instruction audits alone cannot establish calling-convention compatibility.

APK separately compares package architecture against accepted architecture
values; it does not derive the C ABI from every payload file.
[APK package metadata](https://github.com/alpinelinux/apk-tools/blob/master/doc/apk-package.5.scd).
A new local architecture name is a packaging policy, not an upstream registration
or proof of machine-code safety. `noarch` is unsuitable for these native ELFs.

## Completed offline signed transaction

`tools/test_soft_apk_namespace.py` uses the existing host APK3.0.5 in a fresh
owned directory. It never connects to a DUT, runs a target ELF, executes package
scripts, changes the existing APK database or fetches packages.

The experiment builds three signed packages from the exact audited14-ELF Lua
binding closure: runtime/libraries, Lua/luac and ubusd. All use the deliberately
private `aarch64_be6l_soft_experimental` architecture. Runtime versions are bound
to the input manifest fingerprint and application dependencies are exact.
Libraries/modules and executables live under `/opt/be6l-a64-soft`; the unique
soft loader and path file select that runtime. Ordinary system libc is untouched.

Normal signature verification and dependency solving succeeded, and every
installed regular-file byte matched its staged input. Independent negative cases
rejected an untrusted signing key, a missing exact runtime dependency and a
signed foreign-architecture metadata fixture. Logs were checked for the specific
rejection cause. No force, untrusted-install or database-edit option was used.
The new throwaway signing private key was deleted.

The foreign fixture contains no executable. It proves architecture metadata
rejection, not detection of incorrectly labelled hard-float/SIMD code. Target
execution, a booted package-composed image, complete upstream license metadata,
normal upgrades and same-label ABI substitution rejection remain unqualified.
The prototype's license field is explicitly experimental; no binary feed is
published. Per-component notices must be completed before redistribution.

## Ordered integration work

1. Define a versioned target profile with Clang21.1.8, AAPCS64-soft, no-FP/SIMD,
   no outline atomics and contraction disabled. Pin musl/compiler-rt changes and
   generated artifacts. Keep ARM32 compat builds in a different sysroot.
2. Make native recipes own their actual files and exact soft-ABI dependencies.
   Preserve full upstream licenses and build configuration. Distinguish shared
   C modules, executable processes, portable Lua bytecode and kernel modules.
3. Bind APK architecture/profile to the reviewed builder manifest. Reject
   missing provenance or a falsely labelled ordinary AArch64 provider before
   repository admission. Test dependency-version and signature/rollback cases
   in fresh offline roots without forcing the solver.
4. Compose an image from those ordinary package transactions. Its database must
   describe the actual init/procd/libc payloads, not a later unmanaged overwrite.
   Retain protected kernel/MTD/BMT paths and exact matching AArch64 kmods.
5. Build via the fixed sparse OpenWrt target and validate the embedded CPIO,
   module ABI, ELF/loader/dependency closure and required applications. Then
   separately RAM-boot and repeat management, MTU/HTTPS, both-band300s, active
   lifecycle, failure recovery and flash-protection checks for the new hash.
6. Extend the remaining native networking/LuCI closure. Keep ARM32 Go/C++ apps
   isolated until their complete native runtimes qualify. Review the final
   target/toolchain approach against upstream OpenWrt requirements.

No target APK configuration was changed by the prototype. The current b05 RAM
system remains the tested recovery baseline and is not described as a completed
native64 SDK or officially accepted OpenWrt device port.
