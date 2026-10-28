# Development TODO

This is RAM-only experimental work. Preserve all MTD/BMT write, erase and markbad
guards; never flash, sysupgrade, save bootloader environment or guess SMC/MMIO.
Only fetch pinned necessary sparse sources. New image hashes need independent
runtime acceptance; old-image results are not inherited.

Completed:

- [x] Dual-core AArch64 kernel with matching modules and protected RAM startup.
- [x] Native no-FP C runtime, package-owned init/procd, Lua/Nixio and strict TLS.
- [x] Real L2 NPU forwarding with hardware/CPU controls and lifecycle evidence.
- [x] Full wpad-mbedtls selection and Mesh interface initialization.
- [x] Current-image5GHz300s each direction, active binding recovery and matched
  duration/PHY CPU controls; retain the previous reliable2.4GHz evidence.
- [x] Native netifd real loopback netlink lifecycle in private namespaces.
- [x] Reproducible67-ELF native web/Lua closure; actual Chinese Argon login,
  TLS/RPC authorization, Lua-first import and parser/digest/netlink tests.
- [x] Local upstream NTP runtime synchronization after protected RAM restoration.
- [x] Exact-hash native service merge preflight:90 paths, no provider conflicts.

Next, in priority order:

- [ ] Review https://github.com/pabragin/xiaomi-be5000-openwrt for routed WAN/PPE
  techniques using pinned necessary files only. Not researched/adopted yet;
  if any code or method is used, explicitly credit it in README and preserve
  applicable licensing and revision/file provenance.
- [ ] Simultaneous upload/download with two independent server ports. Existing
  20s/300s direction tests were sequential; qualify L2 and routed WAN separately.
- [ ] Native-service merge compression budget:32 additional ELF paths add601768
  gzip bytes against327680-byte headroom; assess normal compression/scope before
  profile/package admission and an actual rebuilt Image.
- [x] Finish the matching bridger image, normal216-record APK root and actual
  CPIO/Image/default-loader admission; protected b3ec883f RAM boot and basic
  runtime passed with84 matching modules and327680-byte Image headroom.
- [x] Automatic5GHz L2 short test: exact daemon flower/BIND peer correlation,
  positive PPE progress, integrity/reassociation and cleanup.20s each direction.
- [x] This image's own automatic5GHz300s each direction, exact peer/rule/BIND
  evidence, integrity/reassociation/AP teardown and final safety/cleanup.
- [ ] Reliable2.4GHz/Mesh peer, new-image driver-exit/CPU controls, NAT/IPv6
  and per-flow accounting remain separate pending work.
- [x] Actual IPv4 NAT producer/tuple-encoder CPU tests:4098 positive/five
  negative cases, UBSan and two private historical CT/capture correlations.
  No complete BIND image or hardware call; domain/defaults/completion remain.
- [x] Correct single-bank diagnostic;44actual preconditions and bounded IPv4
  UNB learning with exact restoration/no BIND/no fault.
- [x] Interface-pinned PC->DUT->WAN low-rate CPU NAT plus original/reply raw
  learned-key correlation; not hardware NAT or a performance benchmark.
- [x] Prospective wired L4 ownership/packet/lifetime source helpers,53tests and
  isolated ARM64 compilation, while keeping routed admission rejected.
- [x] Signed normal steering/defaults APK with exact payload ownership and0755
  modes in a fresh offline root; exact known unowned-file migration only.

- [x] Explicit CT-context producer and rejection-only consumer;120 source-helper
  tests and three ARM64 object builds. Not deployed; internal ABI changed.
- [x] Pinned bridger ARM32/BPF package build and signature/architecture checks.
  Not installed or hardware-qualified; new matching BPF/VLAN modules required.
- [x] Diagnose the bounded learning fixture's read-only preflight rejection,
  then observe real IPv4 UNB keys with no routed binding and exact restoration.
- [ ] Complete a restricted wired NAT path: actual equality fields, action and
  invalidation/cache ownership. Separate wire-only ownership from radio queues;
  never fabricate unsupported per-flow counters or infer packet-domain safety
  from a single zone-zero control-plane request.
- [ ] Rebuild matching kernel/modules/rootfs for973 and bridger; accept a new
  RAM image and bridger automatic L2 lifecycle. Prioritize PPE/network before
  advancing native64-bit default services.

0. [ ] Integrate the tested runtime DSA steering policy through normal package/
   build ownership. The corrected image's 5GHz L2 long, CPU controls and active
   lifecycle tests passed; wired software forwarding and actual L4 hashes passed.
   Routed hardware offload is still unavailable. Investigate the older image's
   bootloader warm-reset stall without guessing hardware reset writes.

1. [ ] Routed NAT/IPv6 offload and genuine Linux per-flow statistics require real
   ingress-domain/CT-zone/WCID/epoch producers, token ownership, both-worker DMA
   completion/quiescence and counter read/consume contracts. Keep CPU routing
   and admission guards until those are proved; global counts are not per-flow.
   Scope these requirements to actual owners; the first restricted wired NAT
   experiment need not implement unused radio-worker or byte-accounting APIs.
2. [ ] Complete current-image2.4GHz lifecycle/matched CPU controls using a reliable
   peer. Replacement Wi-Fi7 client2.4GHz observations are excluded by the user,
   not counted as a DUT fault or a pass. Test actual Mesh peer interoperability.
3. [ ] Create a reviewed new native package profile and normal signed ownership/
   rollback transactions; audit default interpreter/module paths across both
   ABIs. Measure actual compressed CPIO growth within the393216-byte headroom.
4. [ ] Integrate native web/RPC and netifd DHCP/WiFi/routing through normal build
   rules, then qualify a new RAM image and actual device pages. Keep ordinary
   A53/FP packages out of the private soft ABI. Full Nixio API/public IPv6 open.
5. [ ] Reproducible sparse clean build, maintained soft-ABI/dual toolchain SDK,
   Go and C++ support, complete licensing/corresponding-source review and normal
   package/kernel upgrade qualification. The current image remains mixed.
6. [ ] PCIe first-handoff BAR/Gen1 cause, all physical ports/hotplug/negotiation,
   firmware command/version compatibility, LED/buttons/temperature/clocks and
   actual watchdog reset. Do not infer a hardware-clock cause from timing alone.

Create APs only after RAM boot using WPA2-PSK+CCMP and fresh strong random keys;
remove temporary keys, rules, bindings and tests afterwards. Do not read saved
wireless credentials or alter workstation default routing, VPN or metrics.
Keep LuCI translations,curl,Lua/Nixio,Argon theme,btop; Tailscale unlogged and
disabled, Passwall with sing-box only disabled. No unrelated stock cloud,
parental-control,telemetry or UU/GearUP work. No automatic continuation.
