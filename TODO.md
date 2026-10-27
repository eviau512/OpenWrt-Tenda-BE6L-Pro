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

0. [ ] Integrate the tested runtime DSA steering policy through normal package/
   build ownership. The corrected image's 5GHz L2 long, CPU controls and active
   lifecycle tests passed; wired software forwarding and actual L4 hashes passed.
   Routed hardware offload is still unavailable. Investigate the older image's
   bootloader warm-reset stall without guessing hardware reset writes.

1. [ ] Routed NAT/IPv6 offload and genuine Linux per-flow statistics require real
   ingress-domain/CT-zone/WCID/epoch producers, token ownership, both-worker DMA
   completion/quiescence and counter read/consume contracts. Keep CPU routing
   and admission guards until those are proved; global counts are not per-flow.
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
