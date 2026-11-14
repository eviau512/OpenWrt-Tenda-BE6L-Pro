# Native early bootstrap — offline implementation, not Image admission

This implements the early ordering required by the
[main-root inventory plan](../../docs/MAINROOT-A53-INVENTORY-PLAN.md).
The [builder](../../tools/build_mainroot_bootstrap_v1.py) creates a new payload
directory and a manifest-bound static AAPCS64-soft binary. It never changes its
input root, performs an APK installation, creates an Image, or accesses a device.
[Current compact evidence](../../docs/evidence/mainroot-bootstrap-offline-20261113-r2.json)
records the corrected crossbuild,60/60 host checks, normally signed package
fixture and12 normal-provenance checks. The original54-check
[receipt](../../docs/evidence/mainroot-bootstrap-offline-20261113.json) remains
historical. This is executable source
and an offline payload, **not a qualified normal A53 main root**.

## Ordering and trust

`/init` and `/usr/libexec/be6l/mainroot-bootstrap` contain identical private-marked
static native binaries. Stage one verifies the compiled manifest and starts a
native phase-zero watcher. It invokes the actual verified static BusyBox
`/opt/be6l-a64-soft/bin/busybox` to interpret
`/usr/libexec/be6l/initramfs-init-native`. The generated script preserves the
reviewed OpenWrt tmpfs-copy/switch_root ordering, using absolute native BusyBox
helpers. Proc/sys/binfmt are mounted **after** copying, so proc is not recursively
copied. Its input `/init` script and static BusyBox are exact SHA256-pinned.

Stage two, running on the final tmpfs root, verifies the complete manifest
again, mounts proc/sys, checks the RAM root, board, BMT read-only property and
ten MTD read-only flags, then requires an empty enabled binfmt registry. It
opens and hashes the exact r5 interpreter, requires a regular root-owned
single-link read-only static private ELF, and registers **POFX**, without C,
through its held `/proc/self/fd/N`. F is intended to pin the verified final-root
inode. Full enabled/interpreter/flags/offset/magic/mask readback is exact.
**This new proc-fd/F registration path has not been executed on the target.**
Existing canonical-path admission must gain a separate reviewed profile;
these host checks do not weaken it or prove real kernel F behavior. The compiled table deliberately omits a full installed APK DB hash: installing its own bootstrap APK changes that DB and would create a self-reference. Final root/APK/Image admission must authenticate the complete final DB; offline normal archive P/V/A ownership checks remain required.

The 52-byte mask matches only normal little-endian AArch64 ET_EXEC/ET_DYN with
e_flags zero. Every enumerated private native A64 remains marked `0xbe6a0001`;
the bootstrap and static BusyBox therefore remain outside X dispatch. V2r2
kernel plus exact aware r5 remain mandatory. C+X and privileged QEMU remain
disabled; privileged normal exec is still a separate unresolved limitation.

Manifest checking uses directory FDs, O_NOFOLLOW, protected root-owned ancestors,
exact modes/hashes/symlink targets, before/after file metadata, and a complete
ARM32/A64 inventory walk. Unexpected executable/DSO ELF files fail closed.
Trusted RAM root writability is intentional, not treated as a read-only mount.
The two self copies cannot contain their own hash: their static/private format
and equality are checked, while their bytes must be authenticated by the final
normally signed bootstrap APK and CPIO/Image admission. No self-authentication
claim is made. SHA256 is integer C with host known-answer/boundary checks.

## Recovery and native SSH interface

The phase-zero watcher uses CLOCK_BOOTTIME and a bounded 600-second deadline.
Only after a native final-root guard reports lease readiness does stage two
send H and wait for the phase-zero watcher to exit. Only then can the first
normal `/bin/sh` execute. Lost pipe, failed trust or setup requests a native
reboot and never deliberately starts normal userland.

The replacement `/usr/sbin/be6l-recovery-guard` is a symlink to this native
binary. It implements the existing `run 600 300 5 30`, heartbeat, arm, disarm
and status interface. Authenticated SSH heartbeat retains the exact
`BE6L_HEARTBEAT <boot UUID> <uptime>` line. Root-only 0700 state and 0600
no-symlink/single-link heartbeat/lock files bind pulses to the current boot.
Early and procd instances share one flock lease on the final-root directory
`/be6l-recovery-state`; passive instances do not run independent timers. Stage
one and stage two both reject preexisting state, so no old lease/heartbeat can
be copied through switch_root. Only the early final-root guard creates state.
It remains outside procd's `/tmp` and `/run` mounts. Changing its directory or
lock inode fails closed instead of migrating a live timer to another inode.
A separate short pulse lock serializes accepted heartbeat/arm/disarm and the
final expiry check/fired marker.

Expiry now synchronizes, waits the configured force_after (default30), and
calls the native reboot syscall. It does **not** first signal PID1: actual
private procd `state.c:187-199` sends SIGTERM and, one second later, SIGKILL to
all userspace during HALT, which could destroy a waiting forced fallback.
No shell, QEMU, guessed MMIO or guessed SMC is used. Host action tests cover
the exact wait5/wait30 arguments and absence of a PID1 signal, with delay/reboot
mocked; actual wall-clock timing and recovery remain untested. Native reboot
still enters kernel device shutdown. An attached-NPU quiescence/park failure
can prevent restart; prior300-second recovery after explicit NPU detach does
not prove this new early path or attached-NPU recovery. Kernel hard lock,
stopped/killed watcher, reboot-firmware failure, real remount/replacement and
concurrent external shutdown remain runtime gates.

The first main-root composition explicitly retains canonical port22 native
ARM32 Dropbear as private `be6l-arm32-dropbear` with its ARM32 runtime closure.
SSH keys, authorized_keys, host identity and strict client trust stay unchanged.
The reserved root shell `/usr/libexec/be6l/native-recovery-shell` invokes the
verified static BusyBox through an FD. Its environment preserves SSH_CONNECTION
and basic identity/PATH, with no global LD/LUA workaround. PATH still addresses
canonical normal programs; recovery commands must explicitly invoke the native
BusyBox or absolute native guard. The private signed transaction fixture now
demonstrates this root account shell, while retaining its actual native ARM32
Dropbear bytes/identity. That baseline package is still named `dropbear`; the
future complete normal composition must use the explicitly selected private
`be6l-arm32-dropbear` package and runtime closure.

## Build interface and remaining gates

The builder requires an explicit input root digest, DTB, real softcc wrapper,
cross objdump prefix, APK verifier and the exact signed r5 package directory.
For normal A64 input files it additionally requires `--normal-package-list`
(a JSON list of exact archive paths) and `--normal-keys-dir`. Each supplied
archive is signature-verified/extracted, its A53/noarch metadata inspected, and
each installed standard ELF must match both original archive bytes and the
installed APK P/V/A owner. The shared branch passed12 checks using the preserved
28 signed archives and30 normal ELF files: signatures, byte/owner positives,
tampered archive/payload and wrong/missing owner negatives. The
[provenance test](../../tools/test_mainroot_normal_provenance_v1.py) reads the
existing isolated fixture; it creates no hybrid root, installs no package and
reruns no old execution workload. The full normal-root branch is still pending.
No normal package bytes are patched. Private A53 ABI additions require separate
explicit source/signature provenance and must not be called ordinary upstream
payload or silently admitted through the ordinary package list.

The measured sealed baseline contains 61 private A64 and144 ARM32 ELF files.
The new trust table adds exact r5, two self copies and critical paths:464 entries.
The corrected build is476528 bytes, static private A64, with13762 audited disassembly
instructions and zero FP/SIMD register uses. Its input root remained unchanged.
The [host test tool](../../tools/test_mainroot_bootstrap_v1.py) compiles actual C
with a host-only main (no mount/reboot/binfmt operation), exercises synthetic
policy negatives plus the real sealed-root copy and payload, and reports60/60.
These tests do not execute target code or prove bootstrap PID1 runtime behavior.
The host filesystem rejected renaming an open directory; the host tests prove
mutual exclusion and the actual identity predicate's rejection of different
named directory/lock inodes, not a live target replacement/remount race.

The [package fixture](../../tools/package_mainroot_bootstrap_v1.py) normally
signs and installs bootstrap, r5, same-name guard r3 and the root-shell config
in a private copy. Actual APK queries prove ownership of `/init`, guard,
native shell and passwd; the baseline's generated `/init` was unowned. The
config package explicitly replaces only its base-files-owned passwd payload.
Default protection creates `.apk-new`; a separate observable conffile merge
accepts it atomically only after its full signed payload equals the frozen
passwd with exactly the root shell changed, and the current original still
matches all frozen bytes/UID/GID/mode. No protection exception is installed.
A changed-original negative preserves both original and `.apk-new`; APK audit
after acceptance is clean; a subsequent signed upgrade against a deliberately
modified copy again creates `.apk-new`, proving default protection remains.
Actual shadow/group/authorized_keys/Ed25519 host private/public key files stay
unchanged. No scripts, force/untrusted options or manual database edits are
used. The installed fixture passes the same compiled C inventory. It is a
baseline offline transaction fixture, not the forthcoming complete normal root.

The separate [native-SSH guard component tool](../../tools/prepare_mainroot_native_guard_package_v1.py)
signs guard `1.0.0-r4` with exact
`be6l-arm32-dropbear=2026.94-r103` and no generic dropbear dependency. It does
not install or solve a root. The SSH/runtime canonical ARM32 interpreter
ownership transition and final normal base-files composition remain separate;
this metadata artifact does not prove those transactions or authorize reuse
of the old baseline C manifest in a normal root.

Source review supports the intended F pin: matched Linux6.18.55
`fs/binfmt_misc.c:969-977` opens and retains the interpreter during registration;
`:369-378` clones that held file during later execution; `:762-775` prints
POFX in the order required by readback. The r5 exec path uses the kernel
AT_EXECFD/bit16/INTERPFD contract, not a later reopen of the interpreter string.
The future target fixture must prove: held-FD registration then FD close/reuse;
exact guest exit/argv and loader-FD semantics; interpreter rename/path replacement
still using the pinned inode; write denial while registered and release after
rule removal/last process exit; native private ELF exclusion; phase pipe survival
through native BusyBox/switch_root; and no duplicated/lost guard after the real
procd mount/service lifecycle. Source inspection is not a substitute for those
tests. The main-root procd profile must preserve already-correct proc/sys mounts
so that an added proc mount does not cover the bootstrap's binfmt submount.

Before a candidate may use this payload, regenerate against the complete final
normal root and complete ordinary signed archive list. Package the replacement
guard/bootstrap/init in an explicitly owned normally signed new private revision;
replace the old guard package through a normal APK transaction. Change only the
root account shell through a normally signed private config package with conffile
handling, preserving password/hash/home/user data. Never force-overwrite ownership
or edit the APK database manually. Re-run compiled inventory after composition,
then complete CPIO/Image/loader/headroom admission, real kernel F/proc-fd+V2r2/r5
execution tests, native SSH/recovery/heartbeat lease/remount tests, normal service
startup and actual return-to-stock qualification. Until then all candidate,
target, recovery and complete normal A53 compatibility flags remain false.
