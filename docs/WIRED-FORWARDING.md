# Wired forwarding and receive hash investigation

The hardware-offload checkbox requests a hardware flow table. It does not prove
that the driver accepted a routed flow. The current AN7563 implementation still
rejects routed IPv4/IPv6 rules and falls back to the CPU. Do not remove that
guard: ingress identity, DMA completion and per-flow statistics remain open.

## Actual findings

The wired path used a separate upstream iperf3 endpoint. The DUT did not run the
benchmark server. The client source and workstation route were checked, with
workstation Wi-Fi disconnected by the owner. LAN negotiated 1 Gbit/s full duplex
and WAN 2.5 Gbit/s full duplex. No workstation route, VPN or metric was changed.

Both requested offload options were enabled, and the nftables flow table had
`flags offload`. Test connections had `OFFLOAD`, but no `HW_OFFLOAD`; hardware
bindings were empty and PPE direct-forward increments were zero. This is
software forwarding, not a failed hardware throughput qualification.

A bounded read-only packet-metadata observer found 20 distinct direction/tuple
records carrying one identical purported hardware L4 hash. The driver derived
that hash from FOE metadata which did not distinguish these CPU-routed packets.
Linux therefore reused it instead of dissecting the packets, concentrating RPS
on one CPU. Moving the RPS mask moved the saturated core without fixing this.

Patch 972 leaves the skb hash unset on AN7563, allowing software dissection.
The raw FOE slot used by PPE learning is preserved. Other SoCs, checksum/TSO
capabilities, packet ownership and routed admission are unchanged.

There is a second boundary: the Ethernet conduit still exposes the DSA switch
protocol when parent-interface RPS runs. Its software hash can be only an L2
hash, shared by unrelated LAN connections. Deferring conduit RPS until the LAN
user devices produces genuine distinct software L4 hashes in both directions.
The observed records then used both CPUs. The observation module never changes
packets, hashes, DMA or hardware state, and is unloaded before benchmarks.

## Measured software path

These are sequential samples from this setup, not universal speed guarantees.
Rates below are receiver results. Each direction of the paired test uses an
independent server process/port, with four TCP streams per direction.

| Configuration | Duration | Upload / download Mbit/s | Total DUT CPU |
| --- | --- | --- | --- |
| Original kernel and original receive masks | 20 s | 343 / 495 | 73% |
| Original kernel, both-CPU masks including DSA devices | 20 s | 309 / 563 | 75% |
| Corrected RX hash, both-CPU masks | 20 s | 389 / 659 | 86% |
| Corrected hash, DSA conduit RPS deferred | 20 s | 356 / 767 | 93% |
| Corrected hash and standard mode 2 with platform policy | 300 s | 366 / 793 | 95% |

The last run completed about 13.7 GB upload and 29.8 GB download with zero NPU
faults. Both CPUs were busy; the remaining throughput limit is still a CPU
software-path limit. Higher CPU use here accompanies higher offered throughput;
these runs do not demonstrate lower CPU cost at a fixed packet rate. Every
wired routed run had zero PPE direct-forward increments. Owner-reported direct
endpoint rates were not independently reproduced in this round.

The same corrected image separately exercised the real 5GHz-to-LAN L2 PPE path:
300 seconds per direction reached 718/341 Mbit/s at 3.5/3.0% total CPU, with
positive PPE forwarding, a 2 MiB SHA256 transfer, reconnection and zero faults.
The 20-second software bridge controls reached 563/121 Mbit/s at 64.6/49.1% CPU
and zero PPE forwarding. These distinct topologies explain why the existing
wireless L2 acceleration does not establish wired routed NAT support. A brief
ADB disconnect occurred only during the final post-transfer status check;
cleanup was independently rechecked after re-enumeration, without rerunning or
discarding the completed transfers.

The corrected image also passed active binding disconnect, driver unload with
bindings, recovery and re-admission. Each of five lifecycle transfers verified
the 2 MiB SHA256 payload; CPU fallback had zero PPE increments, hardware phases
had positive increments, and no faults or test-owned state remained afterwards.

## Runtime and build boundaries

The separate corrected RAM image begins `d5a2bc21`. Its embedded CPIO is exactly
the previous image's CPIO: package-managed userspace, all 81 modules and final
kernel configuration match by hash. The normal compile target temporarily uses
a non-initramfs configuration; normal image install restores the six initramfs
source/compression fields and the exact reviewed final configuration digest.
CPIO identity, module layout, reserved-memory bounds and ten read-only MTD
partitions are verified before RAM boot. The previous image remains available.

The platform steering helper and `packet_steering=2` have been exercised as a
RAM configuration overlay. They are included in the source defaults for future
normal builds; they are not embedded in the unchanged CPIO of this image. Do
not claim that the runtime overlay is a newly package-qualified firmware build.
The helper first runs the standard netifd policy, checks this board, two online
CPUs and all three DSA parent relationships, then defers conduit RPS. Other
boards and modes retain the generic policy.

A warm reboot of the previous image stalled during U-Boot NAND initialization,
before any new-image upload. Cold power-on and the existing protected RAM boot
chain recovered it. The reset cause remains unknown and is a separate TODO.
Before a future RAM recovery, ask the owner to enable the separate workstation
Wi-Fi link; after management is restored, ask them to disconnect it before
wired measurement. Do not switch workstation networking automatically.

`tools/inspect_flow_offload.sh` collects read-only status. Global PPE counters
can corroborate an exercised L2 path but cannot qualify routed NAT or substitute
for Linux per-flow statistics. See [LIVE-OFFLOAD-PLAN.md](LIVE-OFFLOAD-PLAN.md).
