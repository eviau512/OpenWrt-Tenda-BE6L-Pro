# Development TODO

This is RAM-only experimental work. Preserve all MTD/BMT write, erase and
markbad guards. Never flash, sysupgrade, save bootloader environment or guess
SMC/MMIO commands. Fetch only pinned necessary sparse sources. Each new image
requires its own runtime acceptance.

## Completed

- [x] Dual-core AArch64 kernel, matching modules and protected RAM startup.
- [x] Package-owned native no-FP init/procd and selected C components, including
  corrected libc, curl/TLS, Lua/Nixio and strict HTTPS. Most apps remain ARM32.
- [x] Real wireless/Ethernet L2 NPU forwarding with bindings, payload integrity,
  CPU fallback and lifecycle evidence on the corresponding historical images.
- [x] Full wpad-mbedtls with compiled Mesh support. Peer interoperability open.
- [x] Protected b3ec883f image: 84 matching modules, 216 normal APK records,
  58 native ELF paths, package-owned steering policy and enabled bridger.
- [x] b3 automatic 5GHz L2: 20 seconds each direction, then 300 seconds each
  direction, with exact daemon flower/BIND peer correlation, positive PPE
  progress, integrity, reassociation and AP teardown. These were sequential.
- [x] Reproducible isolated native netifd and 67-ELF web/Lua closure, including
  private netlink lifecycle, Chinese Argon login, TLS/RPC and module tests.
- [x] Source-bound IPv4 NAT producer/tuple tests, CT-context guards and wired
  ownership helpers. Routed rejection remains; these are not hardware NAT.
- [x] Bounded UNB-only learning, exact restoration and CPU-NAT tuple correlation.
- [x] Pinned BE5000 source review with explicit README attribution and version /
  license scope. Related firmware ABI differences are recorded, not transplanted.
- [x] Non-publishing exact-pair preview: 108 CPU/UBSan cases and balanced modeled
  references. A further 37 RX-contract cases cover MTU, TCP and checksum checks.
- [x] Prepared owner-safe simultaneous two-port test harness with 10 CPU/process
  fixtures. Live full-duplex acceptance remains pending.
- [x] Actual matching XZ candidate: 14,155,776 bytes of Image headroom below the
  unchanged memory bound. Normal APK/module/root admission, exact embedded CPIO,
  110 loader fixture files and isolated RAM chroot passed. First live XZ boot
  failed with an unexpected reset; static evidence is not hardware acceptance.

## Next, in priority order

1. [x] Restore and safety-check the known protected gzip RAM baseline.
   [ ] Investigate the failed XZ
   boot with an automatic bootloader stop before attempting any new image.
   Separately qualify startup, exact modules,
   MTD guards, native loaders, UI/HTTPS, network and PPE. New image results are
   independent of the b3 acceptance. Verify independent management connectivity
   before every operation that interrupts Ethernet.
2. [ ] Run genuinely simultaneous upload/download using independent ports and
   record overlapping active windows, CPU, exact peer bindings and PPE progress.
   Keep L2, routed WAN/NAT and router-local TCP measurements separate.
3. [ ] Add a disabled non-publishing diagnostic adapter for real CT/RX/egress
   observations and selected device references. Do not return hardware success,
   install owners or write BIND entries. Current RX notification precedes GRO /
   netfilter; the checksum label alone is not independent packet validation.
4. [ ] Complete one restricted wired IPv4/TCP native action, closed test domain
   and checked withdrawal or contained resource-retention/reset boundary before
   a controlled routed BIND test. Full wireless/IPv6/accounting support is not a
   prerequisite for that first proof, but later packets must remain contained.
5. [ ] Execute the exact signed native preview fixture on a stable RAM baseline;
   normal offline installation already owns all 32 added ELF paths. Complete the
   nested Lua-bridge C-module-path check. See [preview status](docs/NATIVE-SERVICES-PREVIEW.md).
   Admit the larger native closure through new signed APKs and a content-bound
   profile; fix plugin paths and qualify exact default loaders before service
   promotion. Keep the frozen 58-path packages and ARM32 defaults intact until
   the new transaction and runtime checks pass. Ordinary A53 FP packages fail
   this platform's ABI requirements.
6. [ ] Reliable 2.4GHz endpoint, actual Mesh peer, current-image driver-exit and
   matched CPU controls. The replacement Wi-Fi7 client's 2.4GHz is excluded by
   the owner and cannot establish either DUT failure or acceptance.
7. [ ] Ordinary NAT/IPv6 policy and lifecycle coverage, genuine per-flow counters,
   maintainable soft-ABI/dual-toolchain SDK, Go/C++ packages and clean sparse
   reproduction. Firmware ABI5 and reference ABI1 require their matched hosts.
8. [ ] PCIe first-handoff BAR/Gen1 and warm-reset cause; all ports, hotplug,
   negotiation, LED/buttons/temperature/clocks and actual watchdog reset.

Create test APs only after RAM boot using WPA2-PSK+CCMP and fresh strong random
keys. Clean only owned test resources. Do not read saved wireless credentials
or change workstation default routing, VPN or metrics. Keep Chinese LuCI,
curl, Lua/Nixio, Argon theme, btop and bridger; Tailscale remains unlogged and
disabled, Passwall uses sing-box only and remains disabled. No unrelated stock
cloud, parental-control, telemetry or accelerator work. No automatic reschedule.
