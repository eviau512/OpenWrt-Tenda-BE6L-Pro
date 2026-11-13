# Private A64 VM path revision

The [builder](../tools/rebuild_private_a64_vm_paths_v1.py) rebuilt the private
Lua and ucode libraries in a new work directory and normally signed their
complete five-package dependency graph. [Compact evidence](evidence/private-a64-vm-paths-20261113.json)
binds the actual source root, package archives, payload manifest and provenance.
The original r105 root and cached sources remained unchanged. This is an
offline compiled-default and packaging checkpoint, not a main-root or target
qualification.

The final private work is `/root/be6l-a64-vm-isolation-20261113-r1`. Its
`approved/` directory contains these packages, all retaining architecture
`aarch64_be6l_soft_experimental`:

| Package | New version |
| --- | --- |
| be6l-soft-runtime | 0.3.229818857581054-r1 |
| be6l-soft-tools | 0.3.229818857581054-r1 |
| be6l-soft-netifd-deps | 1.1.229818857581054-r1 |
| procd | 2026.10.26.157004332030651-r106 |
| netifd | 2026.09.11~06d06c86-r106 |

Tools, netifd-deps, procd and netifd each depend on the exact new runtime version.
Netifd also binds the exact new netifd-deps version. Existing semantic
dependencies and procd's existing service provider are preserved. In particular,
procd still depends on the old `be6l-arm32-procd-compat` while preload remains
unfixed. This dependency is not evidence that its existing preload is suitable
for normal A53 children.

Only three existing payload ELFs change: `liblua.so.5.1.5`, `libucode.so` and
`libucode.so.0` under `/lib/aarch64-soft`. Their DT_NEEDED, SONAME and exported
symbol sets match the original libraries. Their rebuilt code passed the
FP/SIMD-register audit and carries the explicit private ELF marker `0xbe6a0001`.
The other58 private ELFs retain their hashes, and the real private ELF inventory
remains61. All19 existing private VM module ELFs remain unchanged.

Private Lua now defaults to:

```
/usr/lib/be6l-a64-soft/lua/?.so;/usr/lib/be6l-a64-soft/lua/loadall.so
```

The new private `lua` directory alias points to the existing
`/opt/be6l-a64-soft/lib/lua` directory and preserves its four selected modules:
nixio, ubus, uci and uloop. The private library reads
`BE6L_A64_SOFT_LUA_CPATH` instead of the normal ABI's `LUA_CPATH`. This is a
private-ABI policy; ordinary normal A53 Lua is unchanged. Only the C-module
defaults and private C-path environment name change. Existing pure `.lua`
search paths remain shared and unchanged, and no global environment file is
introduced.

Private ucode's compiled default is:

```
/opt/be6l-a64-soft/lib/ucode/*.so:/usr/share/ucode/*.uc:./*.uc
```

This selects the existing15 private ucode modules and agrees with netifd's
existing private C-module prefix. Canonical and current-directory `.so`
fallbacks are removed from this private default; pure `.uc` paths remain.
Embedded consumers continue to use the rebuilt libraries without a CLI wrapper
or global environment change. Programmatic module loading and actual services
still need runtime testing.

The source changes are retained as `private-lua-cpath.patch` and the recorded
CMake `LIB_SEARCH_PATH`. `build-provenance.json` contains source-file hashes,
compiler inputs, DSO exports and every preserved private module hash.
`payload-manifest.json` records every owned payload of all five packages.
`result.json` records the three changed paths, two added private paths, no
removed paths, exact installed dependencies and signed package hashes. The old
profile lock is explicitly baseline provenance; the new VM entries require
this revision's hashes and must not reuse the old complete-ELF proof.

Signature verification, full extracted-payload comparison, normal APK
simulation, normal upgrade in a fresh copy, installed metadata, complete
ownership, private inventory and module preservation checks passed. The
temporary signing key was removed; `trust/be6l-private-vm.pem` is the new public
key. No admitted root or ordinary A53 payload was modified.

Preload, real VM dlopen, normal-mainroot solving/composition, early bootstrap,
matching kernel/module/CPIO/Image admission and target service behavior remain
separate gates. The existing procd launch string still injects the original
absolute `/lib/libsetlbf.so`; the five-package transaction does not fix it.
Its original constructor makes stdout unbuffered. A future per-final-exec
integration must preserve that behavior through jail/trace helpers and scripts,
handle static targets, and prevent wrong-ABI preload inheritance. No such fix,
new Image, RAM boot or complete standard-A53 compatibility is claimed here.
