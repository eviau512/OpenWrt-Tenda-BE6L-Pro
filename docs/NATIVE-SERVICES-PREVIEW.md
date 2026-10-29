# Signed native services preview

An independent normal signed APK owns 32 added native ELF paths in a fresh
private root. The resulting root has 217 packages: all 216 original entries
unchanged plus `be6l-soft-services-preview`. A new content-bound profile covers
90 native ELF paths, including aliases, with 79 distinct payload hashes. The
original 58-path profile, existing package payloads, SDK configuration and
ARM32 default service files remain unchanged.

A cached-source private rebuild corrected native rpcd/uhttpd ELF plugin paths,
absolute native TLS backend selection and embedded Lua/ucode C-module paths.
Text Lua/ucode search paths remain available. Two hosts and seven matching
plugins were rebuilt with the audited soft ABI; ELF, interpreter, dependency
scope and no-FP/SIMD provenance checks passed. The normal offline solver,
signatures, installed bytes/modes and per-file ownership passed. An ordinary
AArch64 architecture candidate and a signed same-label changed payload were
rejected by their respective solver/content gates. The throwaway signing key
was removed. Source notices for 19 components were collected; binary
redistribution review is still incomplete, so no APK or fixture is published.

A private loopback mount/network/PID namespace fixture is prepared from the
actual package-root bytes for TLS, RPC login/ACL/revocation and module tests.
It has not run on the target. The nested ucode Lua bridge child VM still needs
its own default C-module-path test or fix. Default services and image admission
remain blocked; a successful isolated test will not by itself qualify full
native LuCI/netifd/Wi-Fi/routing lifecycle. The failed XZ kernel provides no
hardware qualification for this separate package work. Run the exact fixture
on a stable known RAM system before promotion, and admit a complete image only
after the boot failure is understood and contained.
