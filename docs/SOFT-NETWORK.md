# Native soft-float TLS/curl experiment

This is a bounded dependency-closure experiment, not a firmware image, an APK
package, or a supported ordinary AArch64 runtime. Use the existing sparse SDK
and completed AAPCS64-soft C suite described in [NATIVE-SOFTFLOAT.md](NATIVE-SOFTFLOAT.md).

## Build

```sh
python3 tools/fetch_soft_runtime.py
python3 tools/build_a64_soft_network.py \
  --root /tmp/soft-network-a --base-soft-root /tmp/soft-core-a
python3 tools/build_a64_soft_network.py \
  --root /tmp/soft-network-longer-path-b --base-soft-root /tmp/soft-core-a
```

The base soft root must already contain its compiler wrappers, sysroot and
compiler-rt archive. The builder copies it into a fresh marked directory and
uses cached mbedTLS3.6.7/curl8.23.0 sources. Existing output directories are
refused unless --resume validates their marker; resumed builds are not fresh
reproduction. Original SDK/runtime sources and installed applications are
unchanged. No target execution or hardware register access occurs in this step.

The copied curl source drops a cached Autoconf-generated lib/curl_config.h
which would shadow CMake's new configuration. mbedTLS uses generic integer
implementations without optional ASM/AES crypto-extension code. Two additional
unsigned128-bit division helpers are hash-locked to the existing LLVM commit;
only those necessary files were fetched,5712bytes total.

## Checks and scope

The output contains curl, libcurl, three mbedTLS libraries and musl:14 ELF paths
including aliases,6 distinct images. Executable sections pass the FP/SIMD
register audit; DT_NEEDED and strong dynamic symbols close over the included
set, and no RPATH/RUNPATH is allowed. Compare files.*.sha256 in the two generated
manifests. All14 paths reproduced exactly in two fresh different-length roots.

HTTP/HTTPS, threaded DNS, IPv6, HSTS and HTTPS proxies are compiled. Optional
compression, HTTP2 and unrelated protocols are disabled to keep this slice
bounded. It is not yet parity with the installed curl. Outputs are generated
under artifacts/a64-soft-network and excluded from Git. No credentials, vendor
firmware or saved network configuration are needed.

## Optional authorized-peer validation

```sh
python3 tools/test_a64_soft_network_peer.py \
  --adb /path/to/adb --serial AUTHORIZED_TEST_DEVICE
```

Use only an authorized rooted AArch64 Android test peer. The harness stages
the verified archive into a fresh temporary directory and invokes its loader
explicitly, with -q as curl's first argument to ignore saved curl configuration.
USB reverse forwarding reaches loopback-only HTTP/TLS fixtures.
It verifies version/protocol reporting,2MiB HTTP and TLS downloads by SHA256,
and rejection of a mismatched hostname and unrelated CA. It never bypasses
certificate verification or changes saved Wi-Fi settings/PC routes. Exact
staged filenames, reverse mappings, local services and throwaway fixture
private keys are removed in cleanup. It currently requires Windows with WSL
and OpenSSL for fixture creation, matching the development host.

All tests passed, with TLS1.3 observed. The Android CPU is different from the
BE6L CPU: these results validate C ABI and protocol/certificate behavior, not
BE6L no-FP execution, DUT forwarding, NPU acceleration or throughput. Compiled
DNS/IPv6 features still need dedicated functional coverage.

Next: validate the unchanged closure under a private /tmp directory on the
protected BE6L initramfs, using its explicit loader and real CA bundle; verify
normal-MTU Bing HTTPS. Do not replace a running libc. A distinct package ABI,
correct package metadata, complete dependencies and independent integrated-image
RAM/lifecycle acceptance remain required.
