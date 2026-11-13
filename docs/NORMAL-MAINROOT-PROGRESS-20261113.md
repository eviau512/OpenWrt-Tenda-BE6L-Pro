# Normal A53 main-root preparation, 2026-11-13

Nine previously uncached ordinary packages now build from the existing
OpenWrt/LuCI recipes in an isolated A53 SDK: liblucihttp-lua, libubus-lua,
libuci-lua, libyaml, luci-lib-ip, luci-lib-jsonc, luci-lua-runtime, lyaml and
ucode-mod-lua. All nine archives pass their ordinary SDK signature checks;
their nine ELF files retain normal A53 headers, flags and loader paths.
[Compact evidence](evidence/normal-a53-module-build-20261113.json) records the
actual archive/ELF hashes, versions, dependencies, recipe and configuration pins.
No target package scripts or router programs ran.

[The cache planner](../tools/plan_normal_mainroot_packages_v1.py) examines the
complete219-package admitted root. Excluding the kernel/private selections,
153 ordinary package names have111 exact-version signed cached archives and42
missing exact filenames before this build. A missing filename can still be a
virtual provider; this count is not an APK solver result or42 mandatory builds.
The full original world is retained in the private report.

[The builder](../tools/build_normal_a53_missing_modules_v1.py) selects only an
ordinary Cortex-A53 profile. Its own SDK copy excludes regenerable build/ccache
contents. Host compiler wrappers and a separate host sysroot provide the
missing native GCC entry and matching libmvec without changing the WSL system,
original SDK or previous host prefix. The host overlay requires identical
installed/private libc and libm hashes. Failed attempts are retained; the final
attempt completes all nine recipes, including the original LuaRocks host
dependency. [Archive verification](../tools/verify_normal_a53_module_archives_v1.py)
binds the completed recipe/configuration receipt before signature/extraction
and ordinary ELF checks.

Other independent preparation is recorded in
[ARM32 compatibility runtime](ARM32-COMPAT-RUNTIME.md),
[private A64 VM isolation](PRIVATE-A64-VM-PATHS.md), and
[retired NPU lease prototype](RETIRED-LEASE-PROTOTYPE-20261113.md).
These results are not a composed normal main root.

The next transaction must solve the complete actual metadata graph using all
required ordinary archives and explicit private identities. Preserve every
selected service and matching r105 kernel/module package. The provisional
recovery choice keeps native ARM32 Dropbear on canonical port22 with unchanged
SSH trust, a private runtime dependency and an honest private package identity.
Normal Lua/ucode modules take canonical directories; the private VM packages
retain their separate ABI. Generic normal library dependencies must never be
satisfied by private soft or ARM32 providers.

Still open: the complete APK solution and arch/provider behavior, remaining
ordinary archives, ownership/conffile/alternative transactions, a signed final
native bootstrap/recovery-shell configuration, real kernel F/procfd dispatch,
mixed-child procd buffering/preload, actual dlopen/service behavior, complete
root/CPIO/Image admission and RAM startup. The47-name module lower bound is
not a complete dependency solution. Secureexec/setuid and full NPU lifecycle
also remain open. No new candidate was booted in this preparation window.
