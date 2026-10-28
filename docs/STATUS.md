# Hardware qualification status

## New bridger RAM image, 2026-10-28 afternoon

Protected `b3ec883f` has booted with84 matching modules,216 actual package
records, the unchanged58 native soft-ABI ELF profile and enabled bridger.
Default loaders, package ownership, MTD/BMT guards, NPU workers, Chinese Argon
UI/Lua and strict Bing TLS passed. Automatic5GHz L2 forwarding reached894/395
Mbit/s at5.0/4.2% CPU over20seconds each direction, with exact daemon-rule/BIND
correlation, real PPE progress and integrity/reconnection/teardown checks.
Its own300-second runs then passed751/381Mbit/s at7.1/4.7% CPU, with no NPU
fault and successful test-peer/AP teardown. Final protections/digests/TLS and
test network/key/phone-policy cleanup passed. Routed NAT/IPv6 and per-flow statistics
are still unqualified. See [BRIDGER-INTEGRATION.md](BRIDGER-INTEGRATION.md).

## Resumed wired action review, 2026-10-28

Actual Linux NAT producers and Airoha tuple encoders passed 4098 positive/five
negative CPU cases with UBSan and two historical original/reply correlations.
No complete BIND action or hardware NAT was enabled. New stock-producer evidence
corrects older field diagrams and exposes a discarded ACK error; native defaults,
hardware domain boundaries and invalidation completion still need evidence.
The protected running image remains `d5a2bc21`. A new matching bridger/kernel/
module/package build is paused at the owner's request. The clean kernel,
first matching external modules and initial APKs built; final-config module
rebuild, final audit, root composition and intended image remain unfinished.
No new-image hardware pass is claimed.

## IPv4 learning follow-up, 2026-10-28

The actual single-bank preflight now passes44checks. Three5-second learning-only
windows restored exactly, with no BIND or faults. Real PC-through-DUT CPU NAT
tuples correlate with both learned IPv4 keys. Patch974's prospective wired
ownership/packet/lifetime helpers passed53cases and ARM64 object compilation;
routed rejection remains. The steering scripts now have a signed normal APK
and verified ownership in a fresh offline root. No new image or NAT hardware
qualification is claimed. See [PPE-LEARNING.md](PPE-LEARNING.md).

## PPE development follow-up, 2026-10-27 evening

The running image remains `d5a2bc21`; no new firmware was installed. Single-flow
DUT-local TX/RX reached963/1304Mbit/s at64.4/85.9% CPU. Normalized CPU cost was
nearly equal, and four-stream TX reached1218Mbit/s. These are TCP endpoints,
not forwarding tests. See [LOCAL-IPERF.md](LOCAL-IPERF.md).

Patch973 implements explicit CT provenance and rejection diagnostics.120 actual
source UBSan cases and three ARM64 object compilations passed; routed actions
remain rejected. This changes the internal flow_rule ABI and requires a full
matching rebuild before deployment. Wired-only scope and radio ownership are
now separated in [LIVE-OFFLOAD-PLAN.md](LIVE-OFFLOAD-PLAN.md).

The pinned bridger ARM32 soft-float package and eBPF object built normally;
package signature, architecture and packaged BPF bytes passed. The current
kernel lacks required BPF/VLAN modules, so bridger has not been installed or
hardware-qualified. Future build selections and sparse dependencies are ready.
A one-line header-only olddefconfig compatibility fix preserves its exact
configuration while avoiding a host pipe hang. See
[BRIDGER-INTEGRATION.md](BRIDGER-INTEGRATION.md).

A bounded IPv4 learning fixture was compiled, but its default read-only live
preflight rejected. No active learning window, routed BIND or NAT test ran.
Keep that failure visible and diagnose the precise typed precondition before
attempting any register change. No guard has been relaxed to obtain a pass.

## RX-hash follow-up, 2026-10-27

The protected `d5a2bc21` RAM image now runs the AN7563 receive-hash correction.
Its CPIO, package-owned userspace, 81 modules and final configuration are exactly
the previous `5b3df962` image's content. Basic startup, module layout, protections,
NTP and strict Bing TLS passed. A tested runtime steering overlay defers LAN RPS
until after DSA metadata decoding; it is not embedded in this image's CPIO.

Real wired forwarding still falls back to software: paired four-stream tests
over 300 seconds reached 366/793 Mbit/s, both CPUs busy, PPE direct delta zero
and no NPU faults. A separate 5GHz L2 short test reached 668/343 Mbit/s at about
4.2/4.6% total CPU with positive PPE forwarding and file/reassociation checks.
Its own 5GHz L2 runs completed 300 seconds per direction at 718/341 Mbit/s and
3.5/3.0% total CPU. Separate 20-second CPU controls reached 563/121 Mbit/s at
64.6/49.1% CPU with no PPE forwarding. This does not inherit previous-image
qualification or establish a matched-duration peak benchmark. Active binding
disconnect, driver exit/recovery, CPU fallback and hardware re-admission also
passed with payload hashes and no faults. Final cleanup/protection/TLS checks
passed. See [WIRED-FORWARDING.md](WIRED-FORWARDING.md).

A previous-image warm reboot stopped during bootloader NAND initialization;
cold power-on recovered it. Root cause and controlled reset acceptance remain
open. All flash protections remain intact. No new routed ABI or unknown
hardware command was enabled.

## Previous package-managed baseline, 2026-10-27

The5b3df962 RAM image remains the protected baseline: native soft-ABI init/procd,
corrected libc,58 native ELF paths,212 normally installed package records and81
matching AArch64 modules. Most default applications are still ARM32. Repeated
RAM restoration, exact PID1/module/protection checks and strict normal-MTU Bing
TLS passed. A user-provided directly connected NTP service corrected the epoch
clock automatically; its private address is deliberately excluded from source.
No new firmware image or default-service replacement is claimed this round.

Current-image5GHz default-EHT L2 forwarding passed300s per direction at269/169
Mbit/s, CPU6.8/5.9%, positive PPE direct-forward progress and fault0. It also
passed active-binding disconnect/driver exit/recovery/rebinding and2MiB SHA256.
Matched-PHY/duration CPU controls passed273/142Mbit/s with PPEdelta0. These are
sequential RF samples, not proof of a peak speed advantage. Earlier same-image
2.4GHz long results from the previous Wi-Fi6 peer remain valid. The replacement
Wi-Fi7 client's2.4GHz results are excluded at the user's request because that
client/ROM appears faulty; do not assign them to a DUT regression or turn them
into passes. Remaining2.4GHz acceptance needs a reliable endpoint.

Native rpcd/uhttpd/TLS and LuCI dependencies now have reproducible67-ELF private
closures. Actual isolated Chinese Argon login, wrong-password rejection, valid
cookie/protected-template access, RPC ACL/session revocation, TLS trust rejection,
Lua-first module import order, digest known answers, real loopback rtnetlink,
Lua IP/JSON/template/YAML and malformed-input tests passed. A weak initializer
interposition defect exposed by Lua RTLD_GLOBAL was corrected by an explicit
module-entry export policy. Full default-service/device-page integration and a
complete native SDK are still open. See [SOFT-SERVICES.md](SOFT-SERVICES.md) and
[NATIVE-MANAGEMENT-PLAN.md](NATIVE-MANAGEMENT-PLAN.md).

A content-bound host-only merge preflight found90 ELF paths, zero provider
conflicts and32 additions totaling2927760 raw bytes. The current Image has only
393216 bytes of safe headroom: actual normal package composition and compressed
CPIO measurement must precede another image build or RAM boot.

New specifications corrected several coordinates but still do not establish
counter read side effects, actual routed identity producers, DMA completion/
quiescence or genuine per-flow statistics. Software accumulation alone is not
proof of hardware read-clear. Routed admission guards remain in force; the LuCI
hardware NAT checkbox is not qualified. Private stock slices/specifications and
runtime secrets are not published.

Native netifd/libnl-tiny have a reproducible10-ELF real-Linux closure and private
loopback up/down/up acceptance. System netifd remains ARM32; actual native DHCP,
WiFi and routing integration are pending. See [SOFT-NETIFD.md](SOFT-NETIFD.md).

## Earlier frozen native-init baseline, 2026-10-26

The frozen b05 native soft64 init/procd image has now completed its own
both-band300-second L2 forwarding in each direction, data integrity/reconnection,
CPU controls and both-band active-binding disconnect/driver exit/recovery.
Observed hardware rates were162/88 Mbit/s on2.4GHz and271/144 Mbit/s on5GHz;
total CPU busy was about3.5/4.1% and6.0/4.8%, with zero NPU faults.
The20-second CPU controls had zero PPE direct-forward increments and about
35/37% and60/47% busy CPU. Sequential samples with different durations are not
a matched RF peak benchmark; hardware acceleration is not claimed faster from
these rates alone. Bindings, direct-forward increments and CPU controls establish
the exercised L2 path. NAT/IPv6 routing and Linux per-flow statistics remain open.

Native no-FP TLS/curl and Lua/Nixio/UCI/ubus/uloop closures separately pass actual
DUT tests and fresh-path reproducibility. They are not part of b05. A generic
libc fma contraction bug was found and corrected in these new builds; b05 keeps
its frozen older runtime. See [SOFT-LUA.md](SOFT-LUA.md) and
[SOFT-NETWORK.md](SOFT-NETWORK.md). A new integrated image needs new acceptance.

## Established

- Dual-core AArch64 Linux with ARM32 soft-float userspace, matching AArch64
  modules, working management, DHCP/WAN and normal-MTU verified HTTPS.
- Both Wi-Fi bands with authentication, reconnection and file SHA256 checks.
- Real wireless/Ethernet L2 NPU forwarding, with hardware bindings, completion
  evidence, data integrity and a CPU fallback control. Local iperf to the router
  itself is not considered forwarding proof.
- The prior mixed baseline passed 300 seconds per direction on both bands:
  approximately 172/174 Mbit/s on 2.4 GHz and 739/365 Mbit/s on 5 GHz, with zero
  NPU faults. Active-binding disconnect/re-authentication, driver exit/recovery
  and CPU fallback passed on that baseline.
- Kernel/kmod APK architecture and exact kernel-ABI dependencies have been
  corrected using ordinary signing and dependency resolution. Foreign-userland
  architecture and old-kernel-ABI negative simulations were rejected.

## Experimental and incomplete

- New image hashes receive separate acceptance. Prior whole-image long-test
  qualification is not automatically inherited by a newly assembled image.
- Full wpad-mbedtls has been compiled with Mesh support. Mesh peer testing and
  runtime acceptance are recorded separately from package selection. Its new
  RAM image passed 20 seconds in each direction on both bands, data SHA256 and
  reconnection with runtime-only WPA2-PSK/CCMP random credentials. An initial
  300-second run ended with an iperf control/accept error and is not a pass;
  the subsequent full repeat passed 300 seconds per direction on both bands (about 177/177 and 720/346 Mbit/s). The original error remains unexplained and is retained as a failure, not counted as a pass. These rates were observed with a concurrent PC-side build, not an idle-host peak benchmark. Secure SAE Mesh interfaces also initialized on both bands with fresh runtime-only secrets and were removed afterwards; no external peer was tested.
- Slot-lifetime NPU counters crossed the 32-bit byte boundary in actual hardware.
  They are not yet Linux per-flow counters. Per-token generations, revocation
  barriers, late completions and L2 parent/child aggregation remain to integrate.
- A two-core software rule channel passed 128 actual command transactions and
  266 result assertions. It demonstrates staged activation and synthetic
  revocation, not live DMA draining or routed NAT. See [FLOW-ABI.md](FLOW-ABI.md).
- IPv4 NAT/IPv6 packet-action prototypes passed independent offline tests and
  32 synthetic checks on each NPU core. They are not connected to live routing.
  The driver continues to reject unsupported routed offload requests.
- The full native AArch64 userspace image received SIGILL at PID1. A pure-integer
  EL2 probe reported FP and AdvSIMD as unimplemented. The mixed system does not
  prove that native AArch64 userspace is usable.
- Early PCIe endpoint reset/BAR loss and first-handoff Gen1 negotiation need a
  root-cause diagnosis. Timing correlation is not proof of a clock problem.

No claim is made that the LuCI hardware NAT checkbox is qualified. Flashing,
bootloader updates and unknown firmware services remain outside the test plan.

## Actual WAN routing baseline

A Wi-Fi client connected through the DUT to a separate wired WAN-side server.
The server observed the DUT's translated WAN source, confirming real NAT
traversal. In 20-second forward/reverse tests, throughput was approximately
137/377 Mbit/s, total DUT CPU use was 69%/52%, and the PPE direct-forward delta
was zero in each direction. This is a CPU-routing baseline, not NAT hardware
offload qualification. The dedicated server and its temporary files were removed.

The full-wpad image also passed active-binding disconnect/re-authentication,
normal driver exit/recovery, CPU fallback and hardware re-admission, with file
SHA256 checks in all five phases and zero NPU faults. A test-server readiness
race encountered in an earlier attempt was addressed by checking the actual
listener, rather than assuming a fixed startup delay was sufficient.

## Controlled GPIO diagnosis

A diagnostic kernel enabled software GPIO events with stack traces. Its first
build exposed stale external modules: seven modules had a 448-byte module
structure while the tracing kernel required 768 bytes. Standard package rebuilds
corrected all 70 modules. A build guard now checks actual module layout; the
mixed-kernel positive control passed all 81 modules at 704 bytes.

A controlled stock-to-RAM comparison used the same repaired diagnostic kernel.
Omitting only the known external PHY reset GPIO and its two delay properties
from a temporary RAM device tree did not prevent Gen1 negotiation or erased
Wi-Fi BARs. That reset action alone does not explain the fault. This experiment
is not a production fix and is not part of the qualified mixed image. The
complete root cause remains open; software GPIO traces cannot establish unknown
board wiring or all hardware reset sources.

The software-versus-hardware-request WAN comparison confirmed software fallback,
not hardware NAT. See [LIVE-OFFLOAD-PLAN.md](LIVE-OFFLOAD-PLAN.md) for the actual
results, the verified Linux CT-identity gap and ordered integration gates.
