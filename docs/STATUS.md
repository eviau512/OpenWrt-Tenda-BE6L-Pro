# Hardware qualification status

## Package-managed native C image, 2026-10-26 follow-up

A new RAM image boots native soft-ABI init/procd with corrected libc and58 native
ELF paths. Four signed packages were installed through ordinary APK transactions;
init/procd ownership matches the files. Original ARM32 libc and81 matching kernel
modules remain intact. The actual212-package manifest, embedded CPIO, loaders,
module layout, MTD guards/digests, native Bing HTTPS/Lua bindings and Chinese
Argon login page passed. The fresh clock needed volatile UTC calibration;
autonomous NTP remains unqualified. See [SOFT-APK-BUNDLE.md](SOFT-APK-BUNDLE.md).

This image passed both-band short L2 tests with the previous Wi-Fi6 endpoint.
Its long campaign completed three directions before endpoint replacement, which
is not a full both-band pass. The replacement Wi-Fi7 endpoint passed5GHz HE CPU
controls, while2.4GHz shows low-rate/retry/loss symptoms without PPE bindings.
Default-EHT5GHz L2 hardware forwarding subsequently passed300 seconds per
direction at269/169 Mbit/s, with6.8/5.9% CPU busy, positive PPE direct-forward
increments and zero faults. The2MiB integrity check and re-authentication
passed. New-image2.4GHz and active lifecycle qualification remain incomplete. Different endpoint/PHY conditions
must not be merged into a peak benchmark.

Native netifd/libnl-tiny have reproducible10-ELF real-Linux-backend closures.
Private mount/net/PID namespace loopback up/down/up passed with the host network
and daemon unchanged. System netifd remains ARM32. See [SOFT-NETIFD.md](SOFT-NETIFD.md).

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
