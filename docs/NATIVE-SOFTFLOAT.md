# Native AArch64 soft-float C userspace experiment

The device executes integer-only AArch64 EL0 programs. A traced ordinary musl
loader fails at `__set_thread_area+0x1c`, file offset `0x61cf0`: instruction
`0x3dc27c1f`, `ldr q31, [x0, #2544]`. The integer tracer passed an exit-42
positive control and an intentional SIMD SIGILL negative control. The kernel
continues to advertise no FP/AdvSIMD capability.

Clang 21.1.8 accepts `--target=aarch64-linux-musl
-march=armv8-a+nofp+nosimd -mabi=aapcs-soft`. GCC 14.4.0 does not provide this
ABI; `-mgeneral-regs-only` rejects floating-point functions. The
[AAPCS64 soft-float variant](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst#soft-float)
is incompatible with the ordinary AArch64 calling convention. Standard
`aarch64_cortex-a53` binary packages cannot be mixed with these libraries.

## Implemented and tested

An isolated musl 1.2.6 copy uses generic string, math, floating environment and
floating barriers. Its setjmp/longjmp assembly omits the nonexistent FP
registers. Generic fenv exposes round-to-nearest and `FE_ALL_EXCEPT=0`; other
rounding modes and exception flags are unavailable. The runtime has 44 necessary
software helper objects from locked LLVM 21.1.8 sources. Only 68 source/header
files and their license are fetched, with SHA256 and source Git blob checks.

Real-device acceptance includes:

- 65 static-C and 69 dynamic-C/plugin assertions: arithmetic, conversions,
  parsing/formatting, special values, math, allocation, unaligned memory copies,
  pthreads/TLS, signals, setjmp/longjmp and the declared fenv contract.
- Static AArch64 BusyBox shell arithmetic, awk floating point, SHA256, gzip,
  loopback ping and HTTP response handling.
- New json-c, libubox, ubus/ubusd, UCI, ucode, udebug and procd/init builds. All 35
  packaged ELF files are AArch64, have closed dependencies, and contain no
  FP/SIMD register use in disassembled code.
- UCI transactions in a new RAM directory, ucode math/fs modules, floating JSON,
  private ubus IPC, and a non-PID1 procd supervising a verified AArch64 BusyBox
  child and deleting it. System services and PID1 are unchanged.

Independent build directories produced identical hashes for all five runtime/
BusyBox artifacts and all 35 core ELF files. The source epoch and file-prefix
maps are fixed. A different-length-path comparison exposed leftover CMake RPATH padding; forcing cached CMAKE_SKIP_RPATH=ON and relinking fixed all differences. The final public scripts were exercised from a separate source copy. This reproduces the C
experiment from the existing pinned sparse SDK/cache. A fresh full SDK build
and complete libc/IEEE-754 conformance remain separate work.

## Native init/procd RAM boot

Image `b05a5c8e39664e7922061f77fb1d993286975c8505525cd0eaddba7aba5cfa1c`
booted native soft-float AArch64 init/procd. PID1 is ELF64/AArch64 and maps its
runtime from `/lib/aarch64-soft`, using `/etc/ld-musl-aarch64-soft.path`.
Management, verified normal-MTU Bing HTTPS, required applications and both-band
20-second L2 forwarding/hash/reconnection checks passed. The NPU had zero faults;
all ten MTDs remained read-only and baseline partition digests were unchanged.
Test APs, credentials and rules were cleaned.

This image predates the final RPATH-padding correction. Its frozen runtime
artifacts are separate from subsequent rebuilt files; future images require
separate RAM acceptance. Its own 300-second and full lifecycle checks remain TODO.
The base APK records do not describe the replaced init/procd ELFs; upgrades are
unqualified. Remaining applications, including Go tools and btop, are ARM32.
This is an experimental native64 core with compatible ARM32 applications.

## Reproduce the isolated C build

Use the prepared sparse ARM64 SDK and host Clang 21.1.8. Cached sources, binutils,
CMake and pkg-config are required. Select new absolute Linux output directories
without whitespace. These commands leave the SDK unchanged and build no image.

```sh
export BE6L_ARM64_SDK=/root/be6l-openwrt/arm64-source
python3 tools/fetch_soft_runtime.py
python3 tools/build_a64_soft_suite.py --root /tmp/be6l-soft-build-a
python3 tools/build_a64_soft_suite.py --root /tmp/be6l-soft-build-b
```

Compare manifests in `logs/soft-suite-be6l-soft-build-a/` and
`logs/soft-suite-be6l-soft-build-b/`. Existing output directories are refused;
`--resume` requires an ownership marker and does not qualify as a clean build.
Target assertions are in `diagnostics/a64_soft_runtime_test.c`; RAM deployment
and hardware access are separate from this source-only build. Do not replace a
running libc, treat these as standard AArch64 packages, or boot the experimental
init/procd as PID1 without a separate RAM-boot plan.

## Go remains unqualified

Go 1.27.3's internal `-d=softfloat` switch initially leaves floating min/max
hardware lowering enabled. The independent compiler overlay uses the existing
software fallback when `Arch.SoftFloat` is true. It checks the reviewed source
hash and leaves the original Go installation unchanged. The minimal pure-Go
program then compiles.

It still SIGILLs in `internal/bytealg.IndexByteString` at `VDUP R2, V0.B16`.
Its linked code has 45 function bodies containing 662 FP/SIMD register-use lines,
including integer copies, byte scanning, random and GC/scheduler helpers. Some
feature-gated code may be unreachable; the byte-scanning fault is directly
demonstrated. A complete backend/runtime profile and ABI review are required.
Fixing the first failing instruction or changing capability bits cannot qualify
native Go.

Tailscale and sing-box retain their working ARM32 soft-float packages. Native Go,
C++/btop, the networking/LuCI dependency closure, a distinct package architecture,
a unified SDK and sustained/lifecycle acceptance of the new image remain TODO.
Native PID1 RAM boot itself has passed.
