# Native management integration gates

2026-10-27. The running protected5b3 image is unchanged. Native login has passed
inside a synthetic private namespace; this is not a full native firmware release.

1. Completed: the installed Lua C extension set, including LuCI IP/JSON/template
   parser and YAML. Use cached Lua5.1 headers/numeric ABI and libyaml0.2.5/
   lyaml6.2.7 matching the actual installed package records. The67-ELF closure
   reproduced and passed native positive/negative runtime tests. Full API
   coverage remains separate from these selected functional cases.
2. Inventory every default ucode/Lua/rpcd/uhttpd module and map installed paths
   to normally owned packages. Avoid a default native interpreter loading ARM32
   `.so` modules, or ARM32 Lua subprocesses inheriting native-only search paths.
   The module-entry export policy must survive Lua RTLD_GLOBAL and import-order
   changes. Do not call ELF machine183 or an A53 package label ABI admission.
3. Merge the new C closure with the existing corrected native runtime by exact
   hash and dependency identity. Create a new reviewed content-bound profile;
   never silently change the previously reviewed58-ELF profile or APK metadata.
   Native default services must depend on the exact private soft-ABI runtime.
   Preserve ARM32 libraries still required by remaining ARM32 applications.
4. Use normal signed APK transactions in a fresh host-only root, preserve real
   file ownership, and retain same-label/foreign-ABI substitution negatives.
   Do not edit the installed database, force-overwrite paths or enable ordinary
   A53 packages. Full SDK/toolchain and license/corresponding-source review remain.
5. Measure actual CPIO/compressed Image growth before a new build. The current
   effective Image leaves393216 bytes below0x84000000. A module tar's size is
   not the Image growth. If the safe bound fails, review normal initramfs
   compression/layout and exact matching kernel/module metadata before boot.
6. Only then build through standard target/linux/install, verify embedded CPIO,
   normal package metadata, module layouts and all MTD/BMT guards. A new hash
   needs its own RAM startup, native services, MTU/Bing HTTPS, both-band transfer,
   lifecycle and CPU fallback qualification. Do not inherit another hash's pass.

Native netifd already passed private loopback up/down/up, but DHCP/WiFi and real
routing integration remain open. The current kernel has no VETH/DUMMY support;
do not claim a virtual Ethernet DHCP test was performed. TUN is a module, but
adding a TAP/device to the fixture would need its own explicit isolation plan,
not a quiet relaxation of the three-standard-device launcher boundary.

NPU routed identity, DMA completion and per-flow statistics still lack a proven
producer/consumer contract after reply-3. Keep guards and CPU routing intact.
Mesh peer, PCIe handoff, physical ports and watchdog reset remain separate work.
