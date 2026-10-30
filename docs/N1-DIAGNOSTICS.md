# N1 current target status

Startup and real CT observation have now occurred; correlation remains incomplete.
See [live evidence and limits](N1-LIVE.md).

## Earlier offline phase

# N1 identity and real driver integration, 2026-10-30

The latest isolated implementation passes 58 actual-code ASan/UBSan cases.
The complete Airoha Ethernet driver compiles and links. A full pass rebuilt
328 cached ABI-dependent translation units against the matching context; later
local driver/control changes reused only identical ABI/producer overlays and
rebuilt every Ethernet/PPE/diagnostic driver member. The test points preserved
89 SDK images, configs, modules and selected source files. Subsequent normal
image integration intentionally installs the new source patch; do not extend
the earlier unchanged-file claim to that operation.

Evidence: `logs/n1-identity-v2-20261030-120735/result.json`, including its
source-bound earlier full-consumer receipt. This is offline evidence. No N1
observer has been armed on hardware and no routed BIND has been attempted.

## New implementation

- Version-2, 56-byte CT producer context carries scalar identities and a
  generation for both REPLACE and DESTROY. A built-in kernel counter avoids
  restarting the generation on flow-table module reload.
- Real driver TC and UNB RX call sites preserve existing routed refusal and
  hardware ownership. The RX source is an existing CPU copy, not an atomic
  hardware snapshot.
- The post-neighbor egress tap runs after checksum completion and DSA tag
  extraction, before DMA mapping. It borrows the live skb CT, resolves the
  selected physical output, and checks the reverse opposite-direction tuple.
  GSO/checksum state and sequence/TTL/MAC fields remain separate from any
  delivery claim. No raw kernel pointer cookie is exported by the text API.
- Bounded record copying, generation replacement, paired revocation and stale
  destroy handling use the same code exercised by the host tests. Conflicting
  or destroyed generations keep tombstones; later callbacks cannot revive them.
- Publication/removal uses the owning mutex and RCU. The driver prevents a late
  arm during teardown, drains callbacks, cancels expiry and unregisters the
  notifier before releasing references.
- A root-only versioned `route_diag` snapshot/control interface is inactive by
  default. It opens one five-second CPU observation lease; it changes no UNB
  classification and cannot publish. The separate existing learning-window
  preflight/restoration is still required.

## What remains before N1 acceptance

The normal full kernel/external-module/APK/root/CPIO/gzip reconstruction passed.
Candidate SHA256 is
`9a3955e73fcee9bccee1c8bbf88a56f6eacaf8fa37c71ff6516d1a22578f2855`:
84 exact ARM64 modules,216 packages,58 native paths and327,680 bytes below the
unchanged Image boundary. Its 110 selected loader files match both the embedded
CPIO and the previously tested fixture. This is static binding; the real new
fixture execution is pending and `default_loader_chroot_tested` remains false.
No RAM-boot payload/runner qualification or N1 target acceptance is implied.

The first post-build audit correctly stopped at the legacy strict16-byte/v1
ABI checker. That checker is unchanged. A separate strict v2 checker reads18
compiler-generated values, requires56 bytes/version2 and exact identity-field
offsets, and checks classifier/flow-generation bounds. Normal incremental build
and final package reconstruction then passed; the failed probe is retained.
No mismatched module was admitted and no target action used the failed result.

After a safely recoverable candidate boots, exercise real CT creation,
bidirectional tuple/action correspondence, UNB RX and post-neighbor output.
Verify rejected generations, flow deletion/replacement, flow-table unbind,
device changes, expiry and driver removal under concurrent callbacks. No direct
CT-destroy notifier is installed: validate the actual NF flow teardown/CT-ref
release ordering and callback-withdrawal cases, rather than claiming a separate
CT-destroy event was observed. A snapshot timestamp and a successful compile do
not prove those lifetimes. The full Linux branch keeps NF_FLOW_HW independent
of the driver's success flag, but the actual target lifecycle still needs tests.

## Routing and native64 boundaries

This is N1 instrumentation, not first hardware NAT. Complete native actions,
later-hit ingress-domain constraints and checked withdrawal/resource retention
remain N2 gates. There is no closed public-WAN first-BIND exception. IPv6,
wireless identity and proxy-policy coverage remain separate acceptance work.
The LuCI hardware checkbox remains unqualified for WAN/NAT.

The running known gzip baseline remains 58 native C paths with ARM32 applications.
The normally signed 90-path v2 closure is still isolated-test qualified only.
No new Go/runtime, sing-box, Tailscale or C++ native-application acceptance was
performed during this watchdog/N1 stage. Ordinary A53 FP binaries remain invalid.
