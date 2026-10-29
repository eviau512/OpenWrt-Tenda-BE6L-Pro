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

The exact90 native payloads have now passed a private loopback
mount/network/PID fixture on the stable gzip RAM baseline. Strict TLS payload
verification, untrusted-CA rejection, RPC login/read-only ACL/revocation and
Lua/ucode/CGI checks passed. Initial fixture-only EACCES and HTTP403 failures
were traced to the ARM32 interpreter mode and public static-file readability;
versioned copies restored source-package modes and correct data-file roles,
without changing ELF bytes. The generator now preserves those modes.

The nested ucode Lua child VM was tested separately. The unchanged bridge
retains legacy C-module paths and fails a native nixio import; a private
source-built correction preserves text paths and imports all ten native
modules from its private C-module directory with no environment override.
The corrected module has only diagnostic substitution qualification until
admitted through a new content-bound profile and signed package transaction.
All three fixtures cleaned owned resources and preserved host services,
network, MTD guards and NPU health.

Default services and image admission remain open; isolated tests do not
qualify complete native LuCI/netifd/Wi-Fi/routing lifecycle. The failed XZ
kernel supplies no hardware qualification for this package work. Retain the
working gzip baseline, and admit a new image only after the boot failure is
understood and contained. Binary redistribution review remains incomplete.

The subsequent v2 normal signed package admits exactly the reviewed Lua-child
module delta and preserves89 other native paths, all58 base native paths and
216 original APK records. Its exact90-path package-root fixture has now passed
on the stable RAM system, including all ten child imports and TLS/RPC controls.
The resulting offline root still has217 packages. Defaults, image and binary
redistribution are not promoted. The one-file v2 admission and APK builder are
versioned separately; the original profile and package remain unchanged.
