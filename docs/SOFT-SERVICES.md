# Native soft-ABI web/RPC service closure

2026-10-26 reply-2 continuation. This is a private-namespace qualification;
the running5b3df962 image and its ordinary ARM32 management services are unchanged.

`build_a64_soft_services.py` builds cached rpcd2026.10.04~d99f703e,
uhttpd2026.08.24~373145f7 and ustream-ssl2026.03.01~99f1c0db against the corrected
no-FP C runtime and the matching patched Lua5.1 development ABI. TLS uses the
already qualified soft-ABI mbedTLS3.6.7. All source copies and build outputs
live in fresh owned roots, without SDK changes or source downloads.

Two different-length paths produced identical25-service-plus-ucode-client ELF
closures:26 files, matching source maps, no FP/SIMD register instructions,
no RPATH/RUNPATH and a closed strong-symbol dependency set. The private soft
loader remains `/lib/ld-musl-aarch64-soft.so.1`; ordinary A53 packages are not
compatible merely because both report machine183.

Enabled features: rpcd file/rpcsys/ucode plugins, uhttpd Lua/ubus/ucode/TLS
plugins and mbedTLS ustream. rpcd iwinfo and full LuCI C modules are still
missing. No full native LuCI or package/image integration claim is made.

`prepare_soft_services_namespace.py` creates a fixture with a fresh random
synthetic login/hash, an ephemeral self-signed localhost certificate/key,
public CA bundle, synthetic UCI/ACL configuration and random128KiB payload.
No real configuration, saved credentials, flash device or physical network
interface enters the fixture. The build-side private key file is deleted after
the private test archive is formed. No archive/key is part of public source.

The audited static launcher uses separate mount, network and PID namespaces,
private propagation, a new proc, read-only sysfs exposing only loopback and
only null/random/urandom binds. Its fixed `/tmp` prefix+32hex ownership check,
core limit and60-second deadline remain enforced. Namespace PID1 exit reaps
all children. The generated root and launcher are deleted on exit.

## Actual DUT result

`logs/soft-services-namespace-20261026-200556/result.json` passed:

- Native uhttpd served a trusted-certificate HTTPS128KiB payload with exact
  comparison/SHA256; an explicit unrelated public CA rejected it with curl60.
- Native Lua handler passed numerical pow/sqrt and native ucode handler ran.
  CGI used the preserved ARM32 shell; it is not claimed native CGI execution.
- Actual RPC authentication rejected the wrong synthetic password. Anonymous
  UCI reads were denied; authenticated read of the fixture config succeeded;
  a read-only role could not write; a destroyed session could no longer read.
- No `-a` or other JSON-RPC authentication bypass was used. uhttpd returns
  JSON-RPC-32002 for transport-level Access denied, while wrong login returns
  ubus result6. The validator checks the exact expected interface for each.
- Host service PIDs, namespace, LAN/WAN addresses/routes and MTD protection
  stayed unchanged; NPU faults remained0. System daemons were not replaced.

Earlier fixture failures remain recorded: missing native plugin search path,
missing Lua numeric header during build, plain script versus required ucode
template syntax, non-world-readable synthetic static payload and absent default
CA file. These were corrected in the fixture/recipe; no daemon authentication,
TLS verification, entropy requirement or instruction audit was relaxed.

Next: complete missing native modules/iwinfo and full LuCI closure, review
normal soft-ABI package ownership/admission, then audit image RAM size before
any standard image build. The current image has only393216 bytes of effective
RAM headroom; new services must not be silently appended beyond0x84000000.

## LuCI C extensions: same-round follow-up

`build_a64_soft_luci.py` added cached iwinfo2026.05.26~66bdd1a0 (nl80211,
SONAME20230701), lucihttp2023.03.15~9b5b683f, the LuCI core extension,
rpcd-mod-luci20240305, rpcd-mod-rrdns20170710 and rpcd with iwinfo enabled.
The52-ELF closure includes native ucode modules and Lua iwinfo/lucihttp bindings.
Two fresh paths produced identical output and source maps. Cached public LuCI
source symlinks are resolved into owned copies before builds; the SDK is not
modified. Its missing standalone Make dependencies are ordered explicitly.
Only rpcd-mod-luci's existing constant-folded strlen array warning is demoted;
no struct layout or runtime check is changed.

Unsigned-to-single conversion required one additional compiler-rt file,
`floatunsisf.c`,1774 bytes at the same pinned LLVM commit. Both Git blob and
SHA256 are checked in `llvm21-soft-builtins-extra-lock.json`; the main runtime
lock and all already-qualified roots remain unchanged. The new helper is added
only to this fresh root's archive. The original Windows Python CA-store failure
was resolved by using WSL's normal verified CA store, without a TLS bypass.

`logs/soft-luci-namespace-20261026-203552/result.json` passes the original
TLS/RPC auth/ACL/revocation cases with these new plugins, loading of all selected
native ucode C modules, HTTP URL decoding, native Lua iwinfo with no radio in
the private namespace, and registration of iwinfo/luci-rpc/network.rrdns.
The new helper also passes nine actual no-FP DUT bit-pattern vectors covering
zero, signed-boundary values, ties-to-even and UINT32_MAX rounding.

**Full native LuCI rendering is still blocked.** The actual baseline LuCI CGI
was invoked through native ucode, but returned502: dispatcher import could not
resolve native `html`. The fixture deliberately does not copy ARM32 `.so`
modules as substitutes. Further html/digest/lua/nl80211/rtnl dependencies need
their own source/ABI closure review before claiming a complete native UI.
No new image or RAM boot was attempted; live management remains unchanged.
This round ended at the user's explicit pause request, ahead of the10% quota
threshold. No automatic continuation is scheduled.

## Reply-3 continuation: native login and module-order correction

2026-10-27. The existing5b3df962 protected RAM baseline was restored through
the verified ARM32 TFTP intermediate and known firmware handoff ABI. Exact
native PID1,81 modules, all ten MTD guards/digests, advancing NPU workers and
strict Bing TLS passed again. No new image was built. The user explicitly
authorized a narrowly scoped temporary PC TFTP firewall lease; it was restored
immediately after transfer. PC default route, VPN and metrics were not changed.

The user supplied a directly connected upstream NTP service. Applying it only
after protected RAM boot corrected the epoch clock automatically; a later
read-only check found0.763s difference from local UTC and the expected running
ntpd command. No manual workstation clock-set command was executed. This local
endpoint remains in private runtime configuration, not public build sources.

`build_a64_soft_luci_web.py` adds cached native HTML to53 audited ELFs. Different
length paths have identical outputs and source inventories. Real namespace
acceptance `logs/soft-luci-web-namespace-20261027-103058/result.json` passed the
unchanged TLS/auth/ACL/revocation suite, Chinese Argon login rendering, rejection
of a wrong synthetic password, valid HTTPS session-cookie login and access to
a protected synthetic template through the actual LuCI dispatcher.

`build_a64_soft_ucode_modules.py` adds libmd1.2.0, digest, Lua bridge, rtnl and
nl80211 from cached sources, then the exact qualified native Nixio/UCI/ubus/
uloop Lua bindings:62 ELFs. ucode's own `include/linux` compatibility headers
are required. An initial attempt incorrectly selected mac80211 kernel-private
headers; the final recipe follows the project's own include directory instead.
No kernel header was fabricated or source repository fetched.

A real weak-initializer interposition bug was reproduced: after the Lua bridge
reopened itself with RTLD_GLOBAL, a subsequently loaded C module could invoke
Lua's weak `uc_module_init`, exposing the wrong module API. The four newly
linked modules now explicitly export only the loader ABI `uc_module_entry`.
Actual dynamic exports are checked; imported liblua symbols remain available
to native Lua extensions. This is an explicit project link policy, not a claim
that the cached upstream CMake already supplies the same policy.

Corrected v5/v6 roots reproduce exactly. Actual acceptance passed in
`logs/soft-ucode-modules-namespace-20261027-110301/result.json`, including a new
Lua-first import sequence for all selected modules, native Lua/Nixio/iwinfo,
MD5/SHA1/SHA256 known answers and real loopback rtnetlink. A successful empty
nl80211 multipart dump returns null with null error in this cached API, rather
than an empty array or boolean true. Earlier fixture assertions for that return
were wrong and remain recorded as failures; the final assertion checks the
exact observed/source-supported pair and the namespace still exposes no radio.

These are native module/login slices. CGI scaffolding uses an ARM32 shell,
live management daemons remain unchanged, full device pages/default-service
replacement and native package/image integration are not yet qualified.

## Installed Lua C extension closure

`build_a64_soft_lua_ui.py` adds the cached LuCI IP, JSON and Lua-template parser,
libyaml0.2.5 and lyaml6.2.7 matching the actual installed ARM32 package versions.
All eight C extension paths present in the installed Lua tree now have native
counterparts in the fixture; the closure also includes additional iwinfo/uloop
bindings. This does not mean every exported function was exercised.

The67-ELF outputs reproduce byte for byte. Source inventories exclude four
Autoconf-generated Makefiles containing build-root paths, while retaining their
Makefile.in inputs. libyaml uses the complete cached Autoconf distribution;
the distribution's optional CMake files are incomplete. No missing source was
invented and no new source archive was downloaded.

`logs/soft-lua-ui-namespace-20261027-111436/result.json` passed the prior TLS,
authentication, import-order, digest/netlink and actual Chinese Argon dispatcher
checks plus native IP/CIDR containment, IPv6 parsing, JSON numeric roundtrip,
template compilation/execution/escaping, YAML numeric load/dump and malformed
JSON/template/YAML rejection. LuCI's encoder emits decimal HTML entities;
an initial fixture expecting named entities was corrected against its source.
No encoder or input-validation behavior was weakened.

The read-only merge preflight against the independently reviewed frozen58-ELF
package profile and native netifd found90 unique installed-path candidates,
45 byte-identical duplicate providers, zero conflicts and32 new ELFs totaling
2927760 raw bytes. Every DT_NEEDED provider is present. This is not an approved
new admission lock, a package transaction or a measured Image size. See
`P3-NATIVE-UI-PLAN.md` before integration. Current default services remain ARM32.
