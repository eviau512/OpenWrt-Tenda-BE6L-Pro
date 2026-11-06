# V2 loader-descriptor experiment — not target qualified

The measured368a/V1 result still fails missing-PT_INTERP errno and setuid.
The next explicit V2 profile attempts to return loader lookup/permission/header
errors before native exec commits. It does not convert a QEMU startup exit code
into an exec errno, and does not qualify setuid or general package compatibility.

The generated [GPL patch](../upstream/be6l-binfmt-guest-interp.patch) preserves
the V1 original/native-interpreter pins and adds a guest-loader pin. Built-in
binfmt X checks the standard A64 ELF/PT_INTERP boundary using kernel reads and
open_exec. The opened loader inode and its write denial belong to the new mm,
with fork/mmput pairing. After the normal unshare/CLOEXEC/credential sequence,
the kernel installs a separate CLOEXEC descriptor for that same loader inode.
Host AT_FLAGS bit17 plus private AT_BE6L_INTERPFD identify the contract. The
kernel auxv capacity grows by one entry. C+X remains rejected.

An aware r5 interpreter consumes this descriptor once in load_elf_interp; the
ordinary image loader closes it. It does not reopen the checked loader pathname.
No environment switch opts into the kernel contract. Guest auxv must hide both
private flags and the private descriptor entry. A new12-case probe checks that
boundary. Legacy/CLI behavior remains available when the host did not supply
the contract.

This is not a complete copy of native ELF property/mapping validation. It needs
matching full kernel/modules, normal r103 packages, CPIO/Image/loader admission
and actual native/emulated caller tests. Required cases include missing, denied,
bad and replaced loaders; FD cleanup; fork/exit; no_new_privs; and ordinary
package workloads. File capabilities, setuid/setgid, secure environments, direct
mixed-root package integration and general compatibility remain open.

The V2 source, full ARM64 kernel and78 in-tree modules compile successfully.
The static integer r5 APK and12-case probe are also prepared offline.
[Offline evidence](evidence/guest-interp-offline-20261106.json) records the exact
source/kernel/module/binary hashes. Seven matching external modules,85/84 layout,
normal r103 packages and final CPIO/Image/loader admission are not completed.
No V2 target execution or errno fix is claimed. The last tested candidate is
V1/368a, which has already returned to authenticated stock after its own default
expiry. Normal test tools require the V2 contract on both kernel and emulator
before enabling POFX. RAM-only, MTD/BMT guards and strict SSH remain mandatory.
