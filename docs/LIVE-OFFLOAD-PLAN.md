# Live routed-offload integration plan

This is an implementation plan, not a supported routing data path. Keep the
AN7563 routed-rule rejection and L2-only hardware classification in place until
the requirements below have actual packet-path evidence.

## Verified Linux-side gap

In the pinned Linux 6.18.55 source, `net/netfilter/nf_flow_table_offload.c`,
`nf_flow_rule_match()` supplies ingress ifindex, IP/transport fields and selected
encapsulation fields. This translator contains no `FLOW_DISSECTOR_KEY_CT`,
`nf_ct_zone()` or equivalent explicit conntrack-zone transfer. A missing zone
field must not be interpreted as an explicitly approved zone zero. Likewise,
the runtime observation of zone zero for one test does not restrict all future
flows or establish namespace isolation.

The existing PPE bridge path separately validates its private ingress domain
and refreshes wireless station identity before binding. The IP tuple key does
not preserve that domain. The two-core experimental channel carries synthetic
identity values, but no Linux control-plane adapter currently populates them
from approved live connections.

## Required implementation order

1. Define an explicit Linux admission contract. Identify the approved flow's
   network namespace, CT zone and direction, ingress device/port/VLAN stack,
   station/WCID and key/replay generation. Retain references or immutable
   snapshots with defined lifetimes. Reject unavailable or ambiguous identity;
   never infer an authorization domain from an IP address alone. Review the
   appropriate flow-table API extension before changing generic kernel code.
2. Build an immutable, versioned action from Linux-approved original/reply
   tuples, NAT rewrites, output device, resolved neighbor, MTU and rule/route
   epochs. Unsupported headers, fragments, expiry or unresolved neighbors stay
   in software. Explicitly define TTL/hop-limit and checksum behavior.
3. Find and prove the actual ownership boundary in each native DMA/PPE/radio
   path. Capture the full session/cookie/slot/generation ticket before ownership
   is transferred, retain it through completion, and specify cache/barrier
   ordering. Looking up the current slot generation at completion is unsafe.
   The synthetic channel's empty token pool is not hardware drain evidence.
4. Connect prepare/commit and the common activation gate only after both workers
   acknowledge the exact immutable action. On CT/rule/route/neighbor/station/key
   invalidation, close admission first, revoke both workers, drain actual old
   owners and consume final counters before reuse. A timeout quarantines the
   slot and preserves CPU fallback; it must not force successful retirement.
5. Attach Linux per-flow statistics only to retained tickets. Specify direction,
   byte convention, drops versus CPU exceptions, parent/child aggregation,
   consistent 64-bit snapshots and late completions. Global PPE counts cannot
   be divided among flows or substituted for per-flow statistics.

## Acceptance gates

First test missing identity, equal tuples across ports/VLANs/stations/CT zones
and namespaces, stale key generations, unauthorized traffic, invalidation during
load, worker failure, timeout and slot reuse. A rejected request must remain a
software flow or fail an explicit `skip_sw` request. Then verify a single real
bidirectional NAT/IPv6 flow with payload hashes and a CPU control, followed by
sustained load and lifecycle recovery. Only then qualify the LuCI switch.

## Current real WAN comparison

The client traversed the DUT to a separate WAN server; it did not terminate its
iperf traffic on the DUT. These were single 20-second tests, not an exhaustive
performance benchmark.

| Requested mode | Forward / reverse Mbit/s | Total DUT CPU % | Evidence |
| --- | --- | --- | --- |
| Default off | 137 / 377 | 69 / 52 | PPE direct delta zero |
| Software | 140 / 426 | 59 / 53 | CT `OFFLOAD`, PPE direct delta zero |
| Hardware requested | 130 / 420 | 65 / 56 | CT `OFFLOAD`, no `HW_OFFLOAD`, PPE direct delta zero |

The hardware-request flow table contained `flags offload`, but no real hardware
NAT binding was demonstrated. This is software fallback, not NPU NAT success.
The original firewall settings, temporary AP credentials and dedicated remote
test server were restored or removed afterwards.
