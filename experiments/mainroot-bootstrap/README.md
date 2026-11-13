# Native early bootstrap — offline implementation, not Image admission

This implements the early ordering required by the
[main-root inventory plan](../../docs/MAINROOT-A53-INVENTORY-PLAN.md).
The [builder](../../tools/build_mainroot_bootstrap_v1.py) creates a new payload
directory and a manifest-bound static AAPCS64-soft binary. It never changes its
input root, performs an APK installation, creates an Image, or accesses a device.
[Compact evidence](../../docs/evidence/mainroot-bootstrap-offline-20261113.json)
records the actual crossbuild and 54/54 host checks. This is executable source
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
Early and procd instances share one flock lease; passive instances do not run
another independent timer. The state directory is re-opened when `/tmp` changes.
Expiry requests SIGTERM to PID1 and, after the configured force interval, uses
the native reboot syscall. No shell, QEMU, guessed MMIO or guessed SMC is used
for this fallback. Kernel hard lock, stopped/killed watcher, reboot-firmware
failure and actual remount/concurrent shutdown races are not proven recoverable.

The first main-root composition explicitly retains canonical port22 native
ARM32 Dropbear as private `be6l-arm32-dropbear` with its ARM32 runtime closure.
SSH keys, authorized_keys, host identity and strict client trust stay unchanged.
The reserved root shell `/usr/libexec/be6l/native-recovery-shell` invokes the
verified static BusyBox through an FD. Its environment preserves SSH_CONNECTION
and basic identity/PATH, with no global LD/LUA workaround. PATH still addresses
canonical normal programs; recovery commands must explicitly invoke the native
BusyBox or absolute native guard. The current demonstrator input does not yet
have this account-shell/config package transaction.

## Build interface and remaining gates

The builder requires an explicit input root digest, DTB, real softcc wrapper,
cross objdump prefix, APK verifier and the exact signed r5 package directory.
For normal A64 input files it additionally requires `--normal-package-list`
(a JSON list of exact archive paths) and `--normal-keys-dir`. Each supplied
archive is signature-verified/extracted, its A53/noarch metadata inspected, and
each installed standard ELF must match both original archive bytes and the
installed APK P/V/A owner. This branch is implemented but **not yet exercised**
against the forthcoming full normal root. No normal package bytes are patched.

The measured sealed baseline contains 61 private A64 and144 ARM32 ELF files.
The new trust table adds exact r5, two self copies and critical paths:464 entries.
The real build is477792 bytes, static private A64, with13645 audited disassembly
instructions and zero FP/SIMD register uses. Its input root remained unchanged.
The [host test tool](../../tools/test_mainroot_bootstrap_v1.py) compiles actual C
with a host-only main (no mount/reboot/binfmt operation), exercises synthetic
policy negatives plus the real sealed-root copy and payload, and reports54/54.
These tests do not execute target code or prove bootstrap PID1 runtime behavior.

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
