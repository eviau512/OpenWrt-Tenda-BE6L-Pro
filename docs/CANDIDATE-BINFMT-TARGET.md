# Matched ARM64 binfmt candidate: startup and execution boundary

The Nov6 RAM-only candidate is FIT SHA256
`e228c236c959d821249e04ddb2cf28dbc8c8790b9d26ca366ec4650eb4d35d4a`.
Its actual running kernel GNU build ID is
`3369afd1e7ba3353d80f255f98a9824a0c334ec3`. The
[sanitized evidence](evidence/binfmt-target-20261106.json) records both construction
and target results. This is an experimental execution profile; general standard
A53 package compatibility, routed offload and this candidate's recovery remain open.

## Matching kernel, modules, packages and loader

The opt-in `--integer-binfmt` kernel build enables built-in `CONFIG_BINFMT_MISC`.
The only other initial configuration difference is the admitted CPIO path.
Because this option changes shared kernel structures, all78 in-tree and seven
external modules were rebuilt. Fresh backports7.2, mt76 and GPIO sources use the
normal locked OpenWrt preparation/patch order. Final package selection installs
77 in-tree plus seven external modules; the unused mptcp_diag is not installed.
Fresh real layout probes pass all85 built and all84 installed modules. No old
external module or forced module load is used.

Normal signed APK transactions repackage the five proven private-soft providers,
mark all61 native regular ELFs with experimental `e_flags=0xbe6a0001`, and compose
the matching kernel/kmods. This reserved-field convention is **not an Arm ABI
feature flag**. Standard guest ELF bytes remain unchanged. The219-package root
retains the application selection, SSH/recovery identity and flash protections.

The complete1703-path CPIO and actual embedded archive match. Effective Image
allocation is64,749,568 bytes, with262,144 bytes before the unchanged NPU region
at`0x84000000`. Ten MTD partitions and physical BMT protection remain enforced.
The emulator is staged separately in RAM; it is not appended to this FIT.

The protected stock-to-ARM32-to-new-ARM64 handoff passes actual startup admission:
219 exact packages,84 module payloads,61 native ELF payloads, native PID1 and
default netifd, five VM modules, required services without respawn, Chinese Argon
login, both CPUs, NPU workers advancing without faults and unchanged critical
partition digests. Prior runtime inheritance is recorded honestly: the61 ELF
differences before this new boot were markers only, not a new runtime test.
The actual new boot then supplies its own startup evidence.

## Standard runtime and child execution

Eight cached, normally signed `aarch64_cortex-a53` APKs install into an isolated
guest root: libc, libgcc1, libstdcpp6, BusyBox, json-c, libucode, ucode and btop.
Every package payload is checked after the normal offline transaction. Target
package scripts are disabled. This small runtime is a test fixture, not a full
OpenWrt standard-package system.

The separately signed private emulator uses default Cortex-A53 guest CPU and a
4MiB TCG cache, since binfmt supplies no CLI options. Its whole static ELF has no
dynamic dependencies/interpreter and zero disassembled native FP/SIMD register
uses. Before activation, the target's complete host executable/library inventory
contains62 marked A64 ELFs, including the emulator; none match the guest rule.
The kernel rule matches standard ELF64 LE AArch64 EXEC/DYN with zero e_flags.
Temporary flags are`POF`; kernel execute/permission checks remain active.

The first14-case run passes nine cases and exposes FD path/CLOEXEC gaps. The
gated follow-up resolves failed executable names through the real AT_EXECFD
descriptor, including deleted-file readlink. It retries CLOEXEC execveat only
after ENOENT, only for readable standard A53 ELF, through a new CLOEXEC proc fd.
The original descriptor flags remain unchanged, temporary descriptors close on
success/failure, and the kernel repeats execution checks. Scripts are excluded.
This requires readable procfs/files and is not a universal exec compatibility layer.

The new20-case target matrix passes absolute/relative execve, absolute/dirfd/
empty-path execveat, fexecve, unlinked fd, script, proc-self-exe, custom argv0,
environment, permission/missing/symlink errors, invalid flags, CLOEXEC fd/dirfd
and nofollow handling. Successful children execute real FP and NEON and check
signal dispositions/mask; the privilege-drop case checks UID/GID and empty
supplementary groups. The high CLOEXEC descriptor is actually closed in the child.
The CLOEXEC script still returns the required ENOENT. A standard shell also
executes standard ucode floating-point arithmetic and btop's version command.

Both test runs unregister their rule and remove the binfmt mount. All62 host ELF
payload hashes remain unchanged and authenticated recovery heartbeats continue.
Wireless/NPU were explicitly stopped before software experiments; this does not
qualify traffic withdrawal, the X-Wrt941-04 lifetime port or routed forwarding.

## Still required

Deleted-file proc open/stat/re-exec, missing/bad ELF interpreter error propagation,
setuid/setgid/capabilities/secure exec, procfs/readability limitations, broader
package workloads, RAM/performance and recovery require further work. `POF` omits
credential-from-guest flag`C`; dropped credentials passing does not qualify setuid.
Selected FP/C++/Go tests and this execution matrix remain bounded evidence.
Native FP/SIMD remains unavailable; these results use software emulation.

The build/staging tools never install boot-time rules. Target activation is an
explicit, bounded RAM experiment with strict SSH trust and boot-qualified
heartbeats. Reboot discards it; no flash or host network changes are involved.
