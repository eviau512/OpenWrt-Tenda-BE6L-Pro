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
  previously qualified full-wpad mixed baseline. The later native PID1 image
  still needs its own300-second and complete active-binding lifecycle acceptance.
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
  ABI, full dependency closure and sustained/lifecycle acceptance of the native PID1 image.

See [native soft-float status](docs/NATIVE-SOFTFLOAT.md) for exact acceptance and
the current blockers. Native soft-float AArch64 init/procd has now RAM-booted
with management, HTTPS and both-band short L2 acceptance. Applications remain
ARM32, and native override package metadata still needs work. Development has
resumed; DUT hardware tests await an authenticated root console and verified
direct management path. No automatic continuation is scheduled.

Test APs must be created after RAM boot only, with WPA2-PSK + CCMP and fresh
strong random secrets. Never embed a real network credential or device identity
in source/configuration. Remove temporary tests, keys and routes on completion.


- [x] Build/reproduce a native no-FP TLS/curl closure and validate HTTP/TLS1.3,
  payload integrity and certificate rejection on the authorized Android peer.
- [ ] Validate that closure on the BE6L under a private RAM-only test directory;
  complete real-CA Bing HTTPS, DNS/IPv6 and correct soft-ABI packaging.

Excluded: parental controls/access-time windows, cloud remote control, telemetry,
NetEase UU/GearUP and unrelated stock business features. Focus on OpenWrt
hardware support. New reverse-engineering claims must be checked against real
producer/consumer code and observations before becoming register operations.
