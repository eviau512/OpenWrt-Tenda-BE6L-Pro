# Original executable retention experiment

This is an explicit private kernel/QEMU experiment for the BE6L integer-host
fallback. It is not an upstream Linux or Arm ABI and does not qualify general
standard A53 package compatibility. Native FP/SIMD is still unavailable.

## Motivation and measured baseline

The signed r3 emulator was tested on the matched e228 RAM kernel. Its20 positive
execution cases and standard shell/ucode/btop child chain pass. Following
`/proc/self/exe` stat and statx now pass. Opening proc exe after unlink and
returning ENOENT to an exec caller for a missing ELF interpreter still fail.
The temporary POF rule is removed and all62 private host ELF hashes remain
unchanged. These results qualify two path fixes, not complete exec semantics.

## Private X contract

[The generated GPL kernel patch](../upstream/be6l-binfmt-guest-exe.patch) adds an
opt-in `X` flag to built-in binfmt_misc. X implies O and rejects C. It pins the
original executable in the new mm before exec_binprm releases its temporary
write denial. A second immutable mm reference retains the native interpreter
and its write denial. The interpreter reference is duplicated during fork and
released by final mmput, including failed-exec cleanup. Normal POF behavior is
unchanged. X permits a path-inaccessible execveat only because its aware
interpreter receives the kernel's O descriptor.

Before committing exec, the kernel checks the original executable and native
interpreter references. Existing credential, LSM, would_dump, CLOEXEC and mm
installation paths remain in place. Host AT_FLAGS bit16 signals this private
contract. The aware QEMU r4 uses real kernel proc-exe operations only when that
bit and AT_EXECFD came from the kernel. No environment or command-line override
enables it. Guest auxv does not expose the private bit. Legacy/CLI execution
keeps the prior named-file behavior.

The source preparation checks seven original file hashes, generates the exact
reviewed patch in a new owned tree, and preserves the original preparation.
The early five-file r1 draft is superseded and must never be built/admitted.
The admitted source is r2. The full kernel,78 in-tree and7 external modules
require rebuilding; all85 built modules and84 installed payloads require fresh
layout checks. Normal signed kernel/kmod releases advance to r102. Full
CPIO/Image/loader, private-host markers and actual startup checks remain required
before a temporary POFX rule can be registered. Test admission requires both
the exact kernel contract and an aware signed emulator receipt. No rule is
installed at boot.

## Qualification still required

The new368a candidate passes actual default startup with219 packages,84 matching
module payloads and61 marked private ELFs. Both POF and POFX pass all20 positive
execution cases and the standard child chain. The11-case standard-ABI probe
passes4 cases under POF and9 under POFX. Under POFX, linked and deleted proc
open/statx, rename, guest write denial, fork retention, exit cleanup and
no_new_privs pass. Missing-loader errno and setuid guest credentials still fail.
The temporary rule and mount are removed after each run, with62 host hashes
unchanged. [Actual evidence](evidence/guest-exe-target-20261106.json) records both
the control and experiment without converting their failures into success.

A native ARM32 helper opens and closes the interpreter with O_WRONLY, without
O_TRUNC or any write. After unregistering the F rule while a standard Lua guest
remains alive, the helper receives ETXTBSY. After the last guest exits it can
open the same file. This tests the extra interpreter reference independently of
the registration's own write denial. Interpreter bytes remain unchanged.

An isolated normally signed28-package/30-ELF standard runtime also passes eight
workloads: BusyBox pipelines; Lua FP plus Nixio file/fork/pipe; curl version and
file transfer; jsonfilter; UCI transaction; ucode filesystem; and a private ubus
socket. The guest needs four explicit memory character devices and locked test
UID/GID records; the first fixture omitted these. Package bytes remain unchanged
and package scripts stay disabled. This does not qualify direct installation
of arbitrary A53 packages into the mixed native root, WAN/TLS traffic, all package
scripts, performance or the full package ecosystem.

After explicitly detaching wireless/NPU and removing guest proc/tmpfs and the
temporary rule/mount,368a's own baked600/300 policy returns it to authenticated
stock `.67` without an autoboot interrupt. The last heartbeat is uptime1862;
the reboot request is2163, an observed301 seconds within the baked5-second
poll interval. UART confirms reset; independent web/Telnet root readback
establishes5.4.55/armv7l and a changed stock boot ID. No task heartbeat or build
helper remains. This qualifies default expiry after explicit detach only;
active-NPU traffic, initial no-heartbeat grace, forced fallback and hardlock
recovery remain unqualified.

In particular, X does not solve missing-loader errno or qualify setuid, setgid,
file capabilities, secure environment handling or package scripts.
Rejecting C is a deliberate temporary admission limit, not setuid compatibility.

The next [V2 loader-fd experiment](EXEC-LOADER-FD-EXPERIMENT.md) compiles offline
and attempts to return loader errors before exec commits, with a retained inode
and descriptor handoff. It has no target execution evidence and does not close
the measured V1 errno or credential failures.

Routed NPU admission remains closed. The separate941-04 lifetime port and real
hardware drain proof remain incomplete. All candidate experiments use RAM,
read-only MTD/BMT guards, strict SSH trust and boot-qualified heartbeats.
