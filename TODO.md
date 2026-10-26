# Project TODO

Priorities: NPU, Ethernet/networking and Wi-Fi first. After those are complete,
prioritize native AArch64 work; native work can also proceed while routed NPU
integration is blocked. Every hardware test remains initramfs/RAM-only.

- [ ] Implement the complete host/NPU identity, action and revocation ABI.
- [ ] Integrate safe live IPv4 NAT and IPv6 routing, including firewall/CT
  isolation, equal tuples in different domains, invalidation and CPU fallback.
- [ ] Integrate trustworthy Linux per-flow statistics with generations,
  late-completion handling, consistent snapshots and no double counting.
- [x] Qualify full wpad-mbedtls with both-band 300-second L2 forwarding and secure Mesh interface initialization.
- [ ] Test actual Mesh peer interoperability.
- [x] Complete sustained-load and active-binding lifecycle acceptance for the
  previous full-wpad baseline and the frozen b05 native PID1 image, including
  both-band300s, CPU controls and driver exit/recovery. New image hashes require
  their own independent acceptance.
- [ ] Explain early PCIe endpoint reset/BAR loss and initial Gen1 negotiation.
- [ ] Reproduce the exported build from a clean fixed sparse checkout and make
  the mixed architecture a single maintainable target/toolchain flow.
- [ ] Review device DTS, profiles, patches, package metadata, provenance and
  licensing against upstream OpenWrt requirements.
- [ ] Complete all LAN/WAN port, link recovery and sustained-load checks.
- [ ] Complete LED, button, temperature/clock and actual watchdog-reset tests.
- [ ] Investigate native AArch64 userspace without assuming FP/AdvSIMD works,
  falsifying hardware capabilities or writing unknown feature switches.
- [x] Trace the ordinary native loader's actual SIMD fault and prove integer EL0.
- [x] Build/reproduce the isolated soft-float C runtime and core components;
  verify native BusyBox, UCI, ucode, private ubus and non-PID1 procd supervision.
- [ ] Complete Go backend/runtime and C++ soft-float support, a distinct package
  ABI, full dependency closure and corrected-runtime image integration.

See [native soft-float status](docs/NATIVE-SOFTFLOAT.md) for exact acceptance and
the current blockers. Native soft-float AArch64 init/procd has now RAM-booted
with management, HTTPS and both-band short L2 acceptance. Most default apps
remain ARM32. A subsequent signed package-managed image contains the corrected
native runtime and owns actual init/procd through ordinary package records.
Its full wireless acceptance is separate from the frozen baseline.
See [SOFT-APK-BUNDLE.md](docs/SOFT-APK-BUNDLE.md).
New testing/builds stopped when the five-hour quota reached10% remaining.
Final safety checks and temporary-test cleanup passed. No automatic continuation is scheduled.

Test APs must be created after RAM boot only, with WPA2-PSK + CCMP and fresh
strong random secrets. Never embed a real network credential or device identity
in source/configuration. Remove temporary tests, keys and routes on completion.


- [x] Build/reproduce a native no-FP TLS/curl closure and validate HTTP/TLS1.3,
  payload integrity and certificate rejection on the authorized Android peer.
- [x] Validate corrected TLS/curl on the actual no-FP BE6L: HTTP/TLS1.3 integrity,
  certificate rejection, real-CA Bing HTTPS/DNS and IPv6 loopback.
- [x] Correct generic fma contraction recursion; reproduce the failure on the
  old C runtime and pass new static/dynamic numerical regressions after repair.
- [x] Build/reproduce and DUT-test native Lua/Nixio and UCI/ubus/uloop bindings.
- [x] Prototype signed soft-ABI packages in a new host-only root, with exact
  dependencies and explicit untrusted-signature/foreign-architecture negatives.
  This is not a booted package-composed image or same-label ABI admission proof.
  See [NATIVE-APK.md](docs/NATIVE-APK.md).
- [x] Integrate the corrected runtime and native C slices with reviewed soft-ABI
  package metadata and basic RAM startup. Full image qualification, public IPv6, complete LuCI,
  Go and C++ remain additional work. See [SOFT-LUA.md](docs/SOFT-LUA.md).

- [x] Review a soft-ABI profile with58 ELF paths/14 source components and reject
  a validly signed same-label ordinary FP provider before repository admission.
- [x] Compose and RAM-boot native-package-owned init/procd with corrected libc,
  matching modules and basic management/networking acceptance.
- [x] Complete the replacement endpoint's5GHz default-EHT L2 tests,300 seconds
  per direction with file integrity, re-authentication and zero NPU faults.
- [ ] Complete the new image's both-band/active-lifecycle qualification, investigate the
  replacement Wi-Fi7 endpoint's2.4GHz issue and autonomous NTP startup.
- [x] Reproduce native libnl-tiny/netifd and qualify real loopback netlink
  up/down/up through private ubus in private mount/net/PID namespaces.
- [ ] Integrate remaining native services and complete maintainable SDK,
  corresponding-source/licensing review and normal upgrade qualification.

Excluded: parental controls/access-time windows, cloud remote control, telemetry,
NetEase UU/GearUP and unrelated stock business features. Focus on OpenWrt
hardware support. New reverse-engineering claims must be checked against real
producer/consumer code and observations before becoming register operations.
