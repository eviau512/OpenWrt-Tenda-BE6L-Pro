# Standard A53 ABI: first instruction-emulation results

The physical BE6L Pro still reports unavailable FP/AdvSIMD. A native soft-ABI
parent used `waitpid()` to confirm that the standard A53 test child dies with
SIGILL (signal4). No physical HWCAP, CPU registers or standard guest ELF bytes
were changed. Native execution remains preferred; this is the permitted fallback.

On the new `2f82bb55` ARM64 RAM candidate, a private AAPCS64-soft **host** emulator
now executes selected **standard AAPCS64 guests**. This is different from
recompiling those guests with the private ABI. [Sanitized target receipts](evidence/integer-emulator-target-20261105.json)
record the exact emulator, kernel, program and package hashes.

## What actually passed

| Input | Physical-router result through the integer-host emulator |
| --- | --- |
| Standard GCC14.4 static A53 C program | Scalar FP, explicit four-lane NEON, nearest/upward rounding, square root and divide-by-zero FPSR flag |
| Standard dynamic A53 C program | Ordinary musl loader, libc and libgcc; same FP/SIMD checks |
| Standard pthread program | Four threads,40000 atomic64 increments, TLS, four key destructors, signal FPCR restoration, two forks |
| Standard dynamic C++ runtime | libstdc++, STL, exception unwinding, square root, four threads, atomic64 and TLS |
| Standard Go1.27.3 ARM64 v8.0 runtime | FP, SHA256, AES-GCM, eight goroutines,80000 atomic64 increments, GC and SIGUSR1 |
| Cached signed `aarch64_cortex-a53` btop1.4.7-r1 APK | Normal APK verification/extraction and successful `--version`; interactive use untested |

Tests used explicit `-cpu cortex-a53 -R 0 -tb-size 4`. Go used GOMEMLIMIT32MiB
and a4GiB host virtual-address limit; that is not a claim of4GiB physical RAM.
Emulated HWCAP `8fb` describes the virtual CPU. The physical feature report is
unchanged. These are bounded regression tests, not exhaustive IEEE, application,
performance or general package acceptance. They did not exercise `execve` children.
After the tests, the boot identity was unchanged, NPU workers advanced with zero
faults and the recovery guard accepted a heartbeat. All ten MTD flags were zero.

## Source and independent rebuild

[QEMU11.1.3](https://www.qemu.org/download/) release bytes were verified with
the official release signature. The gated source preparation is
[`prepare_qemu_integer_host_v1.py`](../tools/prepare_qemu_integer_host_v1.py).
`BE6L_INTEGER_HOST` disables host TCG vector capabilities/register allocation,
the native hardfloat fast path and host AES/CLMUL acceleration. Guest operations
use scalar lowering and software helpers. It requires a no-FP/no-SIMD compiler
target; `-ffast-math` is not used.

[`build_qemu_integer_host_v1.py`](../tools/build_qemu_integer_host_v1.py) performs
the offline isolated build. Inputs are the admitted soft compiler profile, cached
standard cross toolchain/host tools, verified QEMU source archive/key, locked
Meson/PCRE2/zlib/GLib archives, compiler-rt sources and Python wheels. Their
[build lock](../upstream/qemu-integer-host-build-lock.json) includes the additional
`fixunstfdi` helper at the existing LLVM revision. Minimal GLib/GModule excludes
GObject/GIO and their FFI dependency; PCRE2 JIT is disabled. Existing profiles and
global WSL package state are not modified.

The first admitted static emulator is7681200 bytes, SHA256
`29d0e19cb1173ca674f17b989ba0158a73c1d1f95c2e61324e733be17411df6c`.
An independent fresh-directory build using the public builder also passed static
ELF admission and the real dynamic FP/NEON test. Its SHA256 is
`4c6bdd2cf6e965a6f3a6941f9aaa15a3f42a832f9496abe3f5500f31b5e3e0dd`.
Both have no dynamic interpreter/dependencies and no disassembled FP/SIMD register
uses. The outputs are not byte-identical; source/build paths are not normalized.
Static ELF inspection does not exhaustively audit all future generated TCG code.

The [probe sources](../experiments/qemu-integer-host/) keep standard guest and
private native control builds separate. The emulator and guest runtimes were
uploaded only into an owned RAM directory. They are not embedded in the FIT or
installed over current system packages. Existing Image headroom is262144 bytes;
the emulator cannot simply be appended without a new admission measurement.

## Standard dispatch and the remaining execution boundary

Baseline QEMU hands `execve/execveat` to the host. On this same-ISA machine,
standard child programs can consequently escape emulation and hit SIGILL.
The [upstream v6 interception proposal](https://patchew.org/QEMU/20260127112633.516691-1-Moritz.Haase%40bmw.de/)
was reviewed but not applied. Its shown `execveat` branch remains a raw host call,
and its new argument list does not carry our CPU, runtime-prefix and cache options.
Error/permission/script and failed-exec cleanup semantics also need independent
review. A working parent process does not close this gap.

The [new matched candidate](CANDIDATE-BINFMT-TARGET.md) uses kernel `binfmt_misc`
dispatch with QEMU's AT_EXECFD/AT_FLAGS support. Earlier2f82 had this option
disabled. Enabling it changes `struct user_namespace`, so the new candidate
rebuilds the full kernel and all external/in-tree modules; none are force-loaded
into an old kernel.

The [offline planner](../tools/plan_integer_binfmt_v1.py) showed all61 earlier
private native ELFs shared e_flags0 with standard guests and would recurse through
an indiscriminate rule. Normal signed provider transactions now mark all61 with
private host marker `0xbe6a0001`. It is an experimental
project convention in a reserved ELF field, **not a standard Arm feature flag**.
Only an already proven private soft-ABI provider may receive it; no instruction
scan alone establishes ABI provenance. A separately signed marked emulator brings
the actual host inventory to62; a full target scan and exact hashes verify them
before temporary registration. Standard guest bytes remain unchanged.

The matching CPIO/Image/loader, normal signed private providers, eight signed
standard runtime packages, Cortex-A53/4MiB emulator defaults and actual startup
now pass. A gated FD/proc fix resolves failed `/dev/fd` executable names through
AT_EXECFD. A narrow CLOEXEC retry keeps descriptor flags/closure and kernel
permission checks, applies only to readable standard A53 ELF, and excludes scripts.
All20 target exec/FD/script/argv/env/permission/credential-drop/signal cases pass,
as does the standard shell child chain. The rule is unregistered afterwards.
See [exact evidence and limitations](CANDIDATE-BINFMT-TARGET.md).

Complete semantics remain open: deleted-file proc open/stat/re-exec, bad/missing
ELF interpreter errno, setuid/capabilities/secure exec, procfs/readability,
broader package workloads, RAM/performance and broader recovery. The missing-ELF
interpreter errno, linked proc stat and deleted proc open failures are now
reproduced on the target. Signed standard btop also passes a bounded real TUI
workload, and the new candidate's own default300s recovery after explicit NPU
detach returns to authenticated stock. `POF` has
no credential-from-guest flag`C`. This does not qualify standard A53 packages in
general. The planner itself still performs no registration or root modification.

The [Linux6.18 binfmt documentation](https://docs.kernel.org/6.18/admin-guide/binfmt-misc.html)
describes the credential distinction and the pre-opened interpreter used for
chroots. [QEMU issue2825](https://gitlab.com/qemu-project/qemu/-/work_items/2825)
also reports CLOEXEC empty-path execveat returning ENOENT with misc dispatch and
contrasts proc-fd execution. Our narrow retry has its own tests/limits above;
the report is not an upstream endorsement or a solution to all three new failures.

The older ARM32-QEMU shortcut is excluded: upstream documents broken atomicity for
64-bit linux-user guests on32-bit hosts and disabled that combination in10.0;
all32-bit host support was removed in11.0. See [QEMU's removed-feature record](https://www.qemu.org/docs/master/about/removed-features.html).
