# Privileged standard-A53 exec — design draft, not admitted

This is an independent design review of Linux6.18.55 V2 revision2 and the static
integer r5 emulator at public source `c90986aa969d9ed2a9fde3de1f2378c2456f3d93`.
No credential implementation, privileged experiment or candidate admission is
provided. Keep C+X rejected and r5 ordinary/non-setuid. Native execution remains
the preferred solution. An isolated guest root, private soft ABI, or successful
selected workloads does not qualify complete normal A53 package compatibility.

The input hashes and source observations are in
[the evidence record](evidence/privileged-exec-design-20261111.json).

## Existing behavior and concrete blockers

* Kernel `fs/exec.c:1632` selects original `bprm->executable` only when
  `execfd_creds` is true; otherwise it selects final native `bprm->file`.
  `mm->exe_file` retention does not select credentials. X forbids C. Thus the
  unchanged setuid probe at `experiments/qemu-integer-host/standard-exec-corners.c:178-207`
  cannot acquire the required euid0/AT_SECURE1 from its root-owned04755 guest.
* r5 `linux-user/main.c:629-637` processes environment options with ordinary
  `getenv`; `:752-762` parses options and initializes logs/traces before the
  kernel descriptor contract is read at `:818-831`. `QEMU_LOG_FILENAME` and
  `QEMU_LOG` can select a host file opened for writing by `util/log.c:99,346`.
  Elevating unchanged r5 would expose a concrete pre-guest privileged file-write
  path. This is source evidence, not an exploit executed on the device.
* Filtering in main is insufficient. The actual static r5 contains
  `glib_init_ctor` (nm address0x7c58f4, also present in .init_array at0x9efaf8). GLib2.86.0
  `glib/glib-init.c:514-519` calls `glib_init` from that constructor;
  `:368,389,402` reads `G_MESSAGES_PREFIXED` and `G_DEBUG` with ordinary getenv.
  Private musl `src/env/__libc_start_main.c:80,92` initializes libc and the init
  array before main; `:42-56` sets secure mode and repairs missing standard FDs,
  but does not remove QEMU environment variables. AT_SECURE is not a blanket
  filter for plain getenv or static-library constructors.
* r5 actually disables CONFIG_PLUGIN and CONFIG_MODULES. Retain and verify those
  build gates; their source contains loading paths but they are not asserted to
  be active attack paths in this build. Logs, tracing and the environment
  parser are sufficient to prevent enabling privileged r5.

## Proposed complete credential transaction

Use a new, separately versioned, kernel-authorized trusted-emulator contract.
Do not relax general C+X parsing or interpret an ELF e_flags marker, a pathname,
a userspace environment variable or an APK signature by itself as authorization.
The proposal is contingent on auditing the emulator and its whole static
runtime as privileged trusted code; ordinary QEMU is not claimed to supply that
guarantee. Upstream describes TCG as lacking security/isolation guarantees in
its [security policy](https://www.qemu.org/docs/master/system/security.html).

1. **Select and pin the trusted native interpreter.** An init-user-namespace
   administrator admits exact reviewed native bytes and protocol version into
   a protected trust record. Bind the actual opened file/inode to that record
   and retain write denial, including across F-style registration, rename,
   unregister and guest lifetime. Require protected ownership/modes and an
   integrity mechanism or immutable admitted image; a hash checked once followed
   by an unprotected writable file is insufficient. Reject interpreter suid,
   sgid and filecaps. A child userns registration, caller chroot, replacement
   mount/path, or forged private ELF marker must never choose another privileged
   interpreter. Root in a child userns is not this admission authority.
2. **Prepare before commitment.** At the recognized original ELF in
   `load_misc_binary`, retain revision2's terminal-dispatch rule and exact guest
   and PT_INTERP references. Validate the new trust record, protocol and complete
   required ELF/property boundary. Capture the already staged original argv/env
   bytes under existing size limits, rather than rereading caller pointers.
   `do_execveat_common:1860-1903` is where those strings/counts enter bprm;
   the misc handler can access the staged bprm before final native loading.
   Allocate/validate the bounded handoff and all preflight state before the
   point of no return. Failure must preserve errno and caller survival, and
   must not dispatch the original standard guest natively.
3. **Use the guest as the credential file exactly once.** Immediately before
   `bprm_creds_from_file` in `begin_new_exec:1119-1142`, validate the complete
   private contract against retained guest/native files. Only this validated
   branch may select the original opened guest file in the credential helper.
   Keep `bprm_fill_uid` and `security_bprm_creds_from_file` unchanged and in their
   normal order. Do not substitute userspace UID calculations or a post-start
   setuid helper. Do not combine the guest's privilege bits with QEMU's bits.
4. **Keep native commit semantics.** Preserve cred_guard_mutex, unsafe-exec and
   ptracer checks, de_thread, file-table unshare, CLOEXEC, namespaces, personality,
   dumpability, signal/pdeath handling, rlimits and the original security hooks.
   Commit the prepared kernel credentials once at `fs/exec.c:1294-1312`.
   Failures after the normal point of no return remain fatal, rather than being
   reported as successful guest exec. If LSMs are enabled later, audit all
   file/label users across both format rounds and every committing/committed
   hook; changing the credential-file argument alone is not an LSM proof.
5. **Expose real kernel credentials.** Guest UID/GID, saved/fs IDs, groups,
   capget/capset and permission checks must describe the actual host task.
   QEMU already forwards capget/capset (`syscall.c:12387-12455`) and setresuid/gid
   (`:12758-12794`). Fake guest IDs would disagree with real open/socket/exec
   decisions. Guest AT_UID/EUID/GID/EGID and AT_SECURE must use the kernel's
   prepared results, with private control entries omitted. Do not synthesize
   AT_SECURE from the presence of suid bits or force it to1 for every exec.

All privilege algebra stays in the pinned kernel's native helpers:

| Input/boundary | Required result |
| --- | --- |
| setuid/setgid | Original guest inode and mount idmap; native group-execute rule, ID mappings, saved/fs IDs and supplementary-group semantics. |
| filecaps | Original guest security.capability, VFS revision/rootid/userns checks, bounding/inheritable/ambient/effective sets, securebits and native errors. |
| no_new_privs | Preserve existing NNP and native suppression of new IDs/caps. Never clear it or impose new NNP globally to sidestep compatibility. |
| nosuid, unmapped IDs, ptrace/unsafe exec | Preserve the kernel's suppression, downgrade or error behavior; do not report suppression as successful privileged compatibility. |
| already mixed IDs / inherited authority | Run the trusted startup protocol even without a newly set suid bit; AT_SECURE and actual authority can differ from simple euid!=uid tests. |
| script/other format | Follow native format-specific credential rules; never apply an ELF-only original-file elevation policy to a script interpreter chain. |

The relevant native code is `fs/exec.c:1574-1635` and
`security/commoncap.c:753-792,909-998`. It already handles mount/userns bounds,
filecaps, NNP/ptrace downgrade, saved/fs IDs, ambient cancellation and secureexec.
The current built kernel has USER_NS/SECCOMP_FILTER enabled and SECURITY/AUDIT
disabled. That limits present LSM evidence; capability logic still applies.

## Two environments and a fixed bootstrap

The privileged native process must receive an empty or fixed minimal trusted
environment **from the kernel, before static libc or any constructor runs**.
The kernel must separately preserve the complete original guest argv/env as
bounded, read-only, kernel-created handoff data. Do not silently drop all guest
variables, rewrite argv[0], or claim that a sanitized host environment proves
normal guest environment compatibility. Guest libc/loader must receive the
original guest data and true AT_SECURE so its own native secure-loader policy
can apply. Static guest programs must retain their native static-libc semantics.

This needs an explicit bprm argument-stack/handoff design. Merely setting
`environ` in main, filtering QEMU_* there, using secure_getenv only in QEMU,
or assuming static linkage removes constructor effects does not meet the rule.
If preserving the guest data plus building the minimal native environment cannot
be done before commitment, the privileged profile remains inadmissible. Track
`/proc/*/environ` and cmdline coherence separately: a second guest stack plus an
empty native environment otherwise changes those interfaces.

In the new kernel-origin bootstrap, bypass parse_args entirely. Native argv is
fixed trusted launcher data; guest names, leading '-' argv[0], guest options,
empty argv and execveat names are data obtained from the handoff, never host
options. Validate the kernel contract and FD/type/length/version before any
QEMU module/init/configuration work. Use fixed integer-host CPU/TCG defaults,
no prefix replacement search, and no plugins/modules, debugger socket, logs,
trace output, perf maps or optional host file creation. Keep original guest
environment objects separate; never install them as native environ later.
Explicit CLI must not impersonate this protocol or gain guest-file privileges.

## Descriptor and startup boundary

Use kernel-origin, bounded, read-only handoff data, for example private anon-inode
file operations that cannot be written or resized. Credential authority comes
from the validated kernel exec state, not from data supplied in that file.
Private guest/program/loader/handoff FDs must be distinct, CLOEXEC, and allocated
above2; preserve caller non-CLOEXEC FD numbers, flags and sharing semantics.
Consume each once and close all private FD references before first guest
instruction; mm-owned write pins have their independent lifetime. Test low
RLIMIT_NOFILE and all combinations of closed0/1/2 against the native oracle:
internal FDs must not masquerade as stdin/out/err or leak execute-only contents.
Preserve existing descriptors; do not blanket-close caller FDs as hardening.

The trusted runtime must cover ELF parsing/mapping, TCG/helpers, signal/trampoline
handling, syscall translation, libc/GLib constructors, environment/configuration
reads and guest-driven runtime operations. Privileged guest code has the
authority a native execution would have; an isolated root is not a security
boundary. A wrapper that starts ordinary QEMU with host privileges and later
drops/raises IDs neither supplies atomic exec semantics nor removes pre-start
attack surfaces. Existing seccomp restrictions must remain effective; extra
emulator syscalls and syscall-IP differences are compatibility tests, not a
reason to bypass caller filters.

## Required negative admission tests before any privileged candidate

Use a native oracle on the same kernel/mount/userns and a separately built
standard-A53 fixture. Do not modify the existing passing nonprivileged candidate
to run these while the proposed trust/bootstrap implementation is absent.

| Test group | Required observations |
| --- | --- |
| Trust substitution | Fake protocol/FD/ELF marker, userns registration, chroot/bind/rename replacement, writable interpreter, stale F pin, wrong hash/version all fail before elevation; ordinary native host programs still execute. |
| Pre-main environment | Constructor and earliest-main sentinels observe only fixed host env for hostile QEMU_*, G_DEBUG/G_MESSAGES_*, LD_*, locale/allocator controls; original guest variables remain data. No host log truncation, trace/perf file, socket or load attempt occurs. |
| argv/options | Leading '-' names/argv[0], crafted QEMU-looking guest args, empty argv and execveat paths cannot reach host option handlers. Original guest argv/order are preserved. |
| IDs/caps | Root/nonroot-owned suid; sgid with/without group execute; saved/fs IDs and groups; filecaps effective/non-effective/inheritable/ambient/bounding/securebits; mixed suid+fcaps; dropping and regaining only natively permitted IDs/caps. Compare actual permission outcomes, not just printed IDs. |
| Suppression/namespace | NNP plus each privilege source, nosuid, traced exec, unmapped IDs, namespaced filecap rootid and idmapped mounts. No privilege greater than native; suppressed cases are distinct from suid acceptance. |
| Secure process | Exact guest/host AT_SECURE, secure dynamic-loader env behavior, static guest env behavior, core/dumpability, parent proc/ptrace/memory/FD access, pdeath/signal and rlimit transitions. Unauthorized ptrace must not inspect a newly elevated process. |
| FD/failure races | Closed0/1/2, caller CLOEXEC/non-CLOEXEC descriptors, descriptor exhaustion, interrupted reads, allocation failure, fork/exec/exit, unregister/rename, concurrent mode/xattr changes. No precommit authority change, leaked private FD, missing native suppression, original-native fallback, or released active write pin. |
| Real integration | Normal signed setuid/setgid/capability packages and scripts in a coherent mixed root; guest/native child exec transitions, privilege dropping, restrictive seccomp and proc argv/env views. Include failures and recovery. A chroot workload alone cannot satisfy this gate. |

These tests are proposed, not run. Passing them would qualify their measured
scope, not all Linux APIs or complete standard-package compatibility. The
current setuid FAIL remains in the real checklist. No credential design item is
complete until implementation, independent review, matching full build/package
admission and actual RAM-only target observations exist.

Primary references: the pinned local sources above, Linux's
[C/O/F documentation](https://kernel.org/doc/html/v6.14/admin-guide/binfmt-misc.html)
for their base meaning, and QEMU's [user-mode options](https://www.qemu.org/docs/master/user/main.html).
Current upstream documentation may describe newer features; none are assumed
to exist in the pinned Linux6.18.55 tree or to solve this private contract.
