# Private procd bare-preload checkpoint, 2026-11-13

The offline candidate builds private procd `2026.10.26.157004332030651-r107`
and three signed logging libraries. It preserves the original constructor's
`setbuf(stdout, NULL)` policy and original final `execvp`, `execve`, and
`execvpe` calls. The new explicit `BE6L_MAINROOT_NATIVE_BOOTSTRAP` profile sets
`LD_PRELOAD=libbe6l-setlbf.so` when procd captures stdout. The loader resolves the
bare name in its own ABI domain. The constructor leaves this bare value intact
for dynamic helpers, static intermediaries, and descendants.

The actual ARM32, standard A53, private A64-soft and host-test musl 1.2.6
`ldso/dynlink.c` all hash to
`a12efe3464982f83fab5da801b61d4124f0f6c836db8eae90862914aa22b5b38`.
`load_preload()` uses `load_library()`, whose bare-name lookup uses the loader's
`/etc/ld-musl-<LDSO_ARCH>.path` and standard default directories. Original
secure-execution filtering and user `LD_LIBRARY_PATH` precedence remain in that
loader. No global environment workaround, ELF string edit, manual shebang
interpreter, executable-FD wrapper or constructor environment clearing is used.

| Package | Architecture | Sole library path | Binding |
| --- | --- | --- | --- |
| `be6l-setlbf-arm32=1.0-r1` | `arm_cortex-a7` | `/lib/be6l-arm32/libbe6l-setlbf.so` | exact ARM32 runtime `1.0.137005195660218-r1` |
| `be6l-setlbf-a64-soft=1.0-r1` | `aarch64_be6l_soft_experimental` | `/lib/aarch64-soft/libbe6l-setlbf.so` | exact soft runtime `0.3.229818857581054-r1` |
| `be6l-setlbf-a53=1.0-r1` | `aarch64_cortex-a53` | `/usr/lib/libbe6l-setlbf.so` | `libc`, resolved by the final ordinary-package solver |

All three have SONAME `libbe6l-setlbf.so`, DT_NEEDED `libc.so`, no RPATH/RUNPATH
and no FP/SIMD register use in the built code. The private soft DSO retains only
its CRT's `_init` and `_fini` dynamic definitions; the other two have no defined
dynamic exports. The ARM32 library uses its normal soft-EABI compiler. The
standard A53 library uses the canonical normal A53 SDK GCC and libc with
`-mgeneral-regs-only`, retaining standard AAPCS64 and its original generated
`e_flags=0`. It is a newly built custom standard-ABI package with its own source
and signature provenance. No upstream ordinary archive was changed. Only the
proved A64-soft library receives private marker `0xbe6a0001`.

The new procd profile uses a separately packaged private helper at
`/usr/libexec/be6l/ujail`; the normal ordinary ujail archive remains unchanged.
For a logging namespace jail with its own ordinary root, this helper queues
read-only nodeps mounts for the full ARM32/private-A64 runtime directories,
their unique interpreter aliases and path files, the private VM module
directories, and the standard A53 logging DSO. It rejects a conflicting queued
mount at an exact required target. It leaves the ordinary dependency scanner's
global basename cache unchanged, avoiding a new cross-ABI libc cache collision.
The ten required paths are recorded in the evidence and full receipt. Actual
mount execution, parent-directory overlays, selected ordinary dependencies and
all final-service chains still require target proof. Logging jails using an
external root or OCI bundle currently fail closed in this experimental profile;
their complete feature-preserving integration remains open. This candidate is
not admitted as the final service root.

Early init under this explicit profile requires existing proc, sysfs and tmpfs
at `/proc`, `/sys` and `/tmp`, using `statfs`. Correct filesystems are retained,
preserving the bootstrap's canonical binfmt subtree and RAM state. A missing or
wrong filesystem logs the failure and waits for the native recovery watchdog.
The source's legacy profile keeps its original mount calls, ujail path and
absolute preload value. The native bootstrap's root-level recovery state and
watchdog remain a separate signed integration dependency.

## Verification and limits

`/root/be6l-procd-preload-host-20261113-r4` builds the actual cached musl libc
for native x86_64 host use. Nine host cases passed: three independent musl
prefix `.path` domains, a buffered negative control, dynamic and static helper
chains, a fork/exec descendant, a real kernel shebang with unchanged AT_EXECFN,
and the six-branch filesystem-type decision. The test checks the live output
token before allowing exit and reads the reporting process's `/proc/.../maps`
to prove the selected logging DSO. Fixtures use no `LD_LIBRARY_PATH`.

The tenth host case measured `execveat` errno 38, ENOSYS, on the actual WSL1
kernel `4.4.0-19041-Microsoft`; it is explicitly unsupported, not a passing
shebang-FD test. Actual Linux 6.18.55 `fs/binfmt_script.c:93` rejects
`BINPRM_FLAGS_PATH_INACCESSIBLE` with ENOENT. The target must still demonstrate
this CLOEXEC/AT_EMPTY_PATH negative case. Production calls remain path-based,
so this candidate does not introduce the rejected script-FD mechanism.

Four synthetic target fixtures were cross-compiled: dynamic ARM32, private
A64-soft, normal A53, and static ARM32. They have not been executed. They are
integer launch/buffering probes, not ordinary package compatibility results.
The signed packages were verified and extracted with exact full-payload
comparison; all temporary signing keys were removed. No APK transaction into a
complete mixed mainroot, live jail, secure-execution chain, env-delegated
interpreter chain, user loader-path override, DUT boot or Image admission has
been established. The original private build's seccomp tracing stays disabled.
Those gates remain necessary before claiming all preserved services or full
standard A53 package support.

## Frozen artifacts

Final private work: `/root/be6l-procd-preload-20261113-r6`.

- Full `result.json` SHA256: `055b57669ea0a666c47d8c0173403c72f956255198b95cd89308171d6f0649d3`.
- `payload-manifest.json` records every delivered file and symlink.
- `mainroot-profile.patch` records the exact source edits; the companion
  bootstrap header is separately source-hashed.
- `approved/procd-2026.10.26.157004332030651-r107.apk` SHA256:
  `cff6b52295fc958d203965f80288e09a05f698de6028988f4ee714f06af0512e`.
- The three logger archives are byte-identical verified copies from frozen r3;
  the normal A53 archive SHA256 remains
  `9aab6eb152e442c8f8bbdb757d07bd52cf4b81b8736c714161afbccaad5ca96d`.
  Its sole ELF SHA256 remains
  `0c0c325eb917e7a9c17ed74df9fe356c50cffb3d77895e11a5cc98892bc84438`.
- `trust/be6l-private-preload.pem` verifies the frozen logger archives;
  `trust/be6l-private-procd-profile.pem` verifies the new procd archive.

The procd payload preserves all twelve previous paths, rebuilds five existing
executables, updates its legacy `.list` with the added private ujail, and adds
that helper. The new private helper and soft logger add two marked private
ELFs relative to the frozen VM composition. A new complete mainroot inventory
must scan and bind every actual file; it must not reuse the old 61-ELF lock.
The prior procd dependencies and `procd-any` provide remain, with three exact
logger package dependencies added. Removal of the old ARM32 compatibility
dependency is deliberately left to the complete solver/ownership review.

Public implementation:
`tools/rebuild_private_procd_preload_v1.py`,
`tools/test_procd_bare_preload_host_v1.py`,
`experiments/procd-mixed-abi/{setlbf.c,bootstrap-mount.h,host-fixture.c}`.
Compact full-payload evidence:
`docs/evidence/private-procd-bare-preload-20261113.json`.

Reproduction uses a new work directory:

```sh
python3 '/mnt/c/Users/lazar/Desktop/Tenda BE6L/openwrt-be6l-public/tools/rebuild_private_procd_preload_v1.py' \
  --work /root/be6l-procd-preload-20261113-repro1 \
  --vm-composition /root/be6l-a64-vm-isolation-20261113-r1 \
  --arm32-runtime /root/be6l-arm32-compat-20261113-r3 \
  --soft-context /root/be6l-openwrt/a64-soft-no-contract-repro-long-v2 \
  --sdk /root/be6l-openwrt/arm64-source --arm32-sdk /root/be6l-openwrt/source \
  --host-prefix /root/be6l-host-tools-20261105-r2 \
  --apk /root/be6l-openwrt/source/staging_dir/host/bin/apk \
  --host-test /root/be6l-procd-preload-host-20261113-r4 \
  --reuse-logger-package-set /root/be6l-procd-preload-20261113-r3
```

`--reuse-logger-package-set` compares all rebuilt logger payloads before
copying and independently verifying those exact signed archives. This keeps
the explicit standard-ABI supplementary provenance bound to its reviewed
archive while allowing the private procd profile to evolve independently.
