# Native soft-float TLS and curl dependency closure

2026-10-26. This advances native C userspace while real routed NPU integration
remains blocked. Authenticated DUT access has been restored and actual no-FP
CPU tests now pass. No new whole firmware image was built. Installed curl and
working ARM32 applications are unchanged.

## Build and audit

`tools/build_a64_soft_network.py` uses the existing fixed sparse SDK cache:
mbedTLS3.6.7 and curl8.23.0, Clang21.1.8, AAPCS64-soft musl1.2.6 and compiler-rt.
It creates a fresh, marked output directory and an independent sysroot; it does
not change either SDK, the accepted RAM image, or the original soft runtime.
Optional assembly/AES crypto-extension implementations are disabled in the
isolated mbedTLS configuration. Hardware capability reporting is unchanged.

The first build exposed a cached Autoconf `lib/curl_config.h` shadowing CMake's
new header. The builder now removes only that generated file from its own source
copy. The next link identified missing unsigned128-bit integer division helpers.
Only `udivti3.c` and `udivmodti4.c` were fetched:5712bytes total, from the already
pinned LLVM commit, with independent Git blob and SHA256 checks. Existing headers
and license are reused; no LLVM/OpenWrt tree was downloaded.

Final audit covers14 ELF paths representing6 distinct images: curl, libcurl,
three mbedTLS libraries and musl, including their SONAME aliases. All are ELF64
EM_AARCH64, all executable sections pass the no-FP/no-SIMD register audit, every
DT_NEEDED library is included, strong dynamic symbols close over that set, and
there is no RPATH/RUNPATH. The runtime archive includes the two integer helpers;
they are not hardware floating-point emulation switches.

The experimental curl supports HTTP/HTTPS, threaded DNS and compiled IPv6. To
keep this closure bounded, optional compression, HTTP2 and unrelated protocols
are disabled. This is not yet feature parity with the existing installed curl,
a standard APK package, or a unified OpenWrt target/toolchain.

## Independent reproduction

Two new output roots with different path lengths produced identical SHA256
values for all14 ELF paths. The second audit additionally checked strong dynamic
symbols and RPATH. Evidence: `logs/soft-network-reproduction.json` and
`logs/soft-network-a64-soft-network-v1/` / its second-root counterpart.
Artifacts: `artifacts/a64-soft-network/manifest.json` and `network.tar`.

```sh
python3 tools/build_a64_soft_network.py \
  --root /tmp/soft-network-a --base-soft-root /tmp/soft-core-a
python3 tools/build_a64_soft_network.py \
  --root /tmp/soft-network-longer-path-b --base-soft-root /tmp/soft-core-a
```

The base soft root must have completed the existing C suite first. Existing
output directories are refused unless `--resume` validates the ownership marker;
a resumed invocation does not count as a fresh reproduction.

## Functional tests on the authorized Android peer

`tools/test_a64_soft_network_peer.py` stages only the audited closure into a new
temporary directory and invokes its own musl loader explicitly. USB reverse
forwarding reaches loopback-only test services. Saved Wi-Fi configurations,
phone network selection and PC routing are not modified.

- Native curl version/feature reporting passed.
- HTTP and TLS1.3 each transferred2MiB with the exact expected SHA256.
- A mismatched hostname was rejected with curl status60.
- An unrelated trust anchor was rejected with curl status60.
- No certificate-verification bypass was used. Temporary files, USB reverse
  mappings, local servers and throwaway fixture private keys were removed.

Evidence: `logs/soft-network-peer-20261026-000919/result.json`. The14 hashes
reproduced by the second root are identical to the peer-tested binaries.

The Android peer has different CPU capabilities. These tests alone validate
C ABI/TLS behavior, not execution on the BE6L no-FP CPU. Actual DUT results are
recorded separately below; neither set proves NPU forwarding or peak throughput.

## Actual BE6L qualification and corrected runtime

The b05 protected RAM system executed the closure using an explicit private
loader, with no system library replacement. Native HTTP, normal-MTU Bing HTTPS
with the real CA bundle, hostname DNS resolution and IPv6 loopback HTTP passed.
Unrelated-CA Bing access was rejected with curl status60 and no HTTP bytes.
This backend leaves `ssl_verify_result` zero on that early certificate failure
path; the test checks actual exit status and certificate error, not that field
alone. Public IPv6 connectivity is not qualified by the loopback result.

A later Lua test exposed generic libc `fma` recursion introduced by compiler
floating-point contraction. The C wrapper now disables contraction, and both
fresh C roots,14-path TLS/curl roots and their strong-symbol/no-FP/RPATH audits
reproduce independently. The rebuilt closure passed its own DUT HTTP/Bing,
IPv6-loopback and CA-rejection tests. See [SOFT-LUA.md](SOFT-LUA.md) for the
runtime regression and the72 static/76 dynamic-plugin assertion boundary.

A new DUT fixture also served2MiB through owned SSH loopback tunnels. HTTP and
TLS1.3 both matched the expected SHA256; server-side negotiation was TLS1.3.
Wrong-hostname and unrelated-CA cases both returned60 with no HTTP payload.
The fixture used fresh throwaway certificates. All local private fixture keys,
servers, tunnels, DUT files and loopback listeners were removed. This is an
actual no-FP CPU correctness test, not a throughput benchmark.

## Remaining acceptance

Package the distinct soft ABI with correct dependencies and source/configuration
provenance; add public IPv6 when a suitable upstream is available. The corrected
libraries remain isolated and are not integrated in b05. A new integrated image
needs its own RAM-boot, dual-band300s, lifecycle and flash-protection checks.
