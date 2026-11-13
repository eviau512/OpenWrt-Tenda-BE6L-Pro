# Immutable ARM32 compatibility runtime

The [builder](../tools/package_arm32_compat_runtime_v1.py) packages the complete
inventoried ARM32 DSO inventory from the unchanged signed XZ r105 composition.
The [compact evidence](evidence/arm32-compat-runtime-20261113.json) binds its APK,
source root, full relocation manifest and consumer policy. No admitted root,
device, main-root composition or Image was changed.

The measured package is `be6l-arm32-runtime=1.0.137005195660218-r1`, architecture
`arm_cortex-a7`. Its `depends` and `provides` are empty. Normal APK signature
verification, extraction, installation into a new empty verification root,
metadata query and ownership of every payload path passed. The temporary private
signing key was removed; the public key is under the private work's `trust/`.
The package does not provide generic `libc`, library names, `*-any` identities
or a normal-A53 ABI capability.

The75 original DSO files retain their hashes under `/lib/be6l-arm32` and
`/usr/lib/be6l-arm32`, including all currently selected Lua, ucode, rpcd, PPPoE
and uhttpd modules. All39 aliases still resolve to the same original ELF hash.
The37 ordinary relative alias targets remain unchanged. Two target texts change
explicitly: `/lib/ld-musl-arm.so.1` selects `be6l-arm32/libc.so`, while ARM32
`ldd` moves to `/usr/lib/be6l-arm32/bin/ldd` so normal A53 can own canonical
`/usr/bin/ldd`. Source/destination target text hashes and resolution hashes are
recorded separately; this does not claim all39 target texts are identical.

`/etc/ld-musl-arm.path` contains exactly:

```
/lib/be6l-arm32:/usr/lib/be6l-arm32
```

The builder freshly scans the complete source root before copying payloads.
Its actual205 regular executable/DSO ELFs include144 ARM32 files; the complete
ARM32 path set, every ELF hash and every owner must match the old inventory.
Additions, removals and ownership changes fail even if the old inventory receipt
still says its earlier root matched. These are measured counts, not substitutes
for the complete-set comparison. The actual full root digest also binds the
current signed source-composition receipt.

An offline search model resolves all466 DT_NEEDED edges of these144 ARM32
ELFs solely to the private ARM32 files. It rejects unreviewed RPATH,
RUNPATH, path-valued dependencies and other interpreter names. It does not
execute the loader and does not qualify dlopen, VM modules, services or jail
mounts. The immutable VM libraries still have their original canonical module
defaults; retaining them as active VM consumers requires a source rebuild.

The complete private artifacts are under
`/root/be6l-arm32-compat-20261113-r3/`: `result.json`,
`relocation-manifest.json`, `consumer-metadata-policy.json`,
`needed-closure.json`, the APK and its trust key. The r3 negative receipt
`inventory-negative-tests.json` records five real-helper checks: the actual
source scan passes, while an added ELF, removed ELF, changed hash or changed
owner in memory is rejected without changing the inventory proof or source
root. The consumer policy covers
all120 source ARM32 ELF-owning packages, rather than only the earlier47-package
normal-A53 lower bound. A retained private consumer needs the exact runtime
dependency above. Original dependencies and providers are recorded for explicit
review: a mixed application/library package dependency must not be dropped just
because one of its DSOs moved. Duplicate ownership, canonical path collisions,
normal package identities and world/service choices require the parent
composition's real APK solver and transaction.

The intended normal-mainroot work now migrates ordinary programs and modules
to unmodified normal A53 packages where available. This complete ARM32 runtime
is a fallback for explicitly retained consumers. If ARM32 VM/plugin consumers
remain, compiled defaults and consumer initialization need separate private
source builds: Lua C paths, ucode `LIB_SEARCH_PATH`, rpcd plus its ucode plugin's
self-reopen path, and pppd's `--with-plugin-dir`. uhttpd's selected ubus plugin
uses a bare dlopen name and can use the private loader search path; unselected
Lua/ucode uhttpd plugins were not added. Jail mounts need an ABI-aware review.

The original procd `service/setlbf.c` calls `setbuf(stdout, NULL)`: stdout is
unbuffered, stderr is unchanged, and `LD_PRELOAD` is not cleared. Its launch
code overwrites `LD_PRELOAD=/lib/libsetlbf.so` when captured stdout is enabled.
A mixed-ABI replacement must preserve that direct-service buffering behavior.
Three matching constructors that clear their own preload environment require
explicit tests for scripts, static targets and intermediate jail/trace helpers:
clearing the variable in a helper before final service exec would otherwise
lose the intended behavior. No preload implementation or qualification is
included in this immutable runtime package.
