# Project TODO

Priorities: NPU, Ethernet/networking and Wi-Fi first. After those are complete,
prioritize native AArch64 work. Every hardware test remains initramfs/RAM-only.

- [ ] Implement the complete host/NPU identity, action and revocation ABI.
- [ ] Integrate safe live IPv4 NAT and IPv6 routing, including firewall/CT
  isolation, equal tuples in different domains, invalidation and CPU fallback.
- [ ] Integrate trustworthy Linux per-flow statistics with generations,
  late-completion handling, consistent snapshots and no double counting.
- [x] Qualify full wpad-mbedtls with both-band 300-second L2 forwarding and secure Mesh interface initialization.
- [ ] Test actual Mesh peer interoperability.
- [x] Complete sustained-load and active-binding lifecycle acceptance for the
  current full-wpad mixed image. Every future image still needs its own acceptance.
- [ ] Explain early PCIe endpoint reset/BAR loss and initial Gen1 negotiation.
- [ ] Reproduce the exported build from a clean fixed sparse checkout and make
  the mixed architecture a single maintainable target/toolchain flow.
- [ ] Review device DTS, profiles, patches, package metadata, provenance and
  licensing against upstream OpenWrt requirements.
- [ ] Complete all LAN/WAN port, link recovery and sustained-load checks.
- [ ] Complete LED, button, temperature/clock and actual watchdog-reset tests.
- [ ] Investigate native AArch64 userspace without assuming FP/AdvSIMD works,
  falsifying hardware capabilities or writing unknown feature switches.

Test APs must be created after RAM boot only, with WPA2-PSK + CCMP and fresh
strong random secrets. Never embed a real network credential or device identity
in source/configuration. Remove temporary tests, keys and routes on completion.
