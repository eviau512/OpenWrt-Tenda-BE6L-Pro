# V2 loader-descriptor experiment — scoped target results

The measured368a/V1 result fails missing-PT_INTERP errno and setuid.
The explicit V2 profile returns selected loader lookup/permission/header
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
matching full kernel/modules, normal r104 packages, CPIO/Image/loader admission
and actual native/emulated caller tests. Required cases include missing, denied,
bad and replaced loaders; FD cleanup; fork/exit; no_new_privs; and ordinary
package workloads. File capabilities, setuid/setgid, secure environments, direct
mixed-root package integration and general compatibility remain open.

The initial V2 source, full ARM64 kernel and78 in-tree modules compiled offline.
The static integer r5 APK and12-case probe are also prepared offline.
[Historical evidence](evidence/guest-interp-offline-20261106.json) records those
initial hashes. Initial V2 and its r103 packages are superseded: an X handler
returning ENOEXEC could let search_binary_handler try native ELF, bypassing the
interpreter. They must not be booted or used for current admission.

Revision2 claims an X match before argument rewriting or loader preflight and
makes every failure terminal for that handler search. The flag resets at the
start of each search round, so a successful rewrite can load the private native
interpreter in the next round. Program-header allocation and read failures keep
their precise errors instead of becoming ENOEXEC. The kernel/emulator descriptor
contract remains V2; the aware r5 interpreter remains required. Build, package,
Image, payload and target-test gates require revision2 and terminal dispatch.

[The source regression](../tools/test_guest_interp_dispatch_v1.py) compiles the
actual search_binary_handler, load_misc_binary and program-header helper bodies
with substituted kernel services. The initial V2 passes16/24 cases; revision2
passes24/24, including injected errors, ordinary fallback and the successful
two-round dispatch. These results do not test kernel locking, concurrent exec,
credentials, a booted kernel or general package compatibility.

Revision2 has completed a fresh full kernel, all seven external modules,85/84
layout, normal r104 packages and final CPIO/Image/loader admission. The offline
FIT is `a1caa815`; its effective Image retains262144 bytes of headroom, and its
219-package root contains84 rebuilt module payloads. All ten MTD and BMT guards
remain read-only. [The offline receipt](evidence/guest-interp-revision2-offline-20261111.json)
binds source, modules, root, CPIO, Image and loader bytes. Its offline results are
separate from the subsequent target observations below. Normal test tools
require the V2 contract on both kernel and emulator
before enabling POFX. RAM-only, MTD/BMT guards and strict SSH remain mandatory.

On the device, `a1caa815` passes actual startup with the exact219 packages,
84 modules,61 private-native ELFs and kernel build ID. Its POFX dispatch passes
20/20 execution cases and11/12 negative/lifetime cases; setuid alone fails.
Missing PT_INTERP now returns ENOENT to the emulated caller. The independent
native ARM32 caller passes16/16 execve/execveat cases: missing/denied/bad/short
loaders, ENOTDIR, original-file denial, bad program headers and successful
controls. Error returns preserve caller execution, FD counts/CLOEXEC flags and
release the temporary program/loader write denials. This is scoped errno
evidence, not complete ELF validation or privileged-exec compatibility.

Eight workloads from28 unmodified signed standard A53 packages pass in the
isolated RAM root. Unregistering while a guest lives keeps the emulator
write-protected; the last guest exit releases it. Owned rules and test mounts
are cleaned, and host payload hashes remain unchanged. The standard runtime
is still isolated; package scripts and a complete mixed host root are not
qualified. See [the target receipt](evidence/guest-interp-revision2-target-20261111.json).

After explicit NPU detach and test-mount cleanup, the candidate's own unchanged
default policy requests reboot300 seconds after the final authenticated
heartbeat (uptime426 to726, polling interval5). UART observes reset and a
separate authenticated read-only probe confirms stock `.67`/5.4.55/armv7l with
a new boot ID. No autoboot interrupt is sent. This qualifies that scoped default
disconnect recovery; active-NPU, hard-lock and broader recovery remain open.

The setuid case remains a known blocker: it requires real uid65534, effective
uid0 and AT_SECURE1 after executing a root-owned04755 guest. Without C, native
credentials come from the ordinary interpreter; the guest inode retained as
mm->exe_file does not change that. Passing no_new_privs or using nosuid does not
qualify setuid compatibility. Do not enable C+X or make the interpreter setuid
as a workaround. A future credentials design must cover secure startup,
environment, descriptors, file capabilities and privilege transitions together.

The optional native ARM32 caller
[probe](../experiments/qemu-integer-host/native-a64-exec-errno.c) and its
[builder](../tools/build_native_exec_errno_probe_v1.py) cover16 execve/execveat
cases with a close-on-exec error pipe, caller survival, descriptor counts/flags
and reference release. It creates only its own copies in the isolated RAM guest.
Use `test_integer_binfmt_v1.py --native-errno-probe` with the exact V2/r5 and
standard-corner fixture admissions; the option runs before unregistering the
owned rule. Building this helper alone does not qualify its target observations.

A separate [native ptrace probe](../experiments/qemu-integer-host/native-loader-inode.c)
and [strict runner](../tools/test_native_loader_inode_v1.py) are prepared for the
next target test. Four cases stop execve/execveat at PTRACE_EVENT_EXEC, rename
the loader and replace its old pathname with a bad ELF before QEMU runs. They
require the retained inode to stay write-protected and usable, then release
after exit. [Offline evidence](evidence/native-loader-inode-offline-20261111.json)
records the static ARM32 build and reviewed kernel/COMPAT event boundary.
These four cases have **not run on the device**; neither inode-replacement
success nor secureexec compatibility is claimed.
