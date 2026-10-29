# Versioned wired RX eligibility proposal

This CPU-only fixture compiles the exact, hash-locked patch974
`airoha_ppe_wired_l4_packet_match()` body and compares it with an additional
diagnostic eligibility contract. It does not change that source, a kernel,
SDK, firmware, module, image, classifier, route gate or hardware owner.
There is no publisher; `can_publish` remains false.

On 2026-10-29 the fixture passed **37 cases with UBSan**. Seventeen inputs that
the original notification predicate accepts are refused by the additional
contract. Two successful cases exercise copied/nonlinear header access.
Receipt: `../../logs/wired-rx-contract-v1-20261029-092908/result.json`.
The previous 108 preview cases were not rerun or counted again.

The real extracted function SHA-256 is
`6ec2379e185181f5fd1783ddbc956eefb5657a24c3013fd9c6cc3deed5891732`;
its frozen `airoha_ppe.c` SHA-256 is
`39b585e3b1f2bc808e19ebdffd5dc53e34feac4558f76336b024b58aae676e35`.
`run.py` verifies the source and both existing routed/classifier guards before
extracting its body. The generated C body retains its Linux/Airoha source
license; authored fixture files have MIT notices. The fixture does not execute
the specification provider's vectors.

The proposed extra checks cover:

- the selected egress MTU, including exact-boundary acceptance;
- an ACK without URG, and a non-GSO complete received packet;
- bounded TCP option-length syntax, including missing/zero/overrun lengths;
- actual IPv4 and complete TCP/pseudoheader checksums, independent of the
  `skb->ip_summed` label;
- linear and copied/nonlinear header and payload access, including unavailable
  tails and an odd payload length.

Packets and checksums are produced by an independent Python network-order
oracle. The C contract streams bounded reads through `skb_header_pointer()`
and uses separate checksum code. Bad checksum cases retain the
`CHECKSUM_UNNECESSARY` flag deliberately. A changed IPv4 pseudoheader with a
repaired IP checksum is still refused by TCP verification. `CHECKSUM_NONE` and
`CHECKSUM_COMPLETE` with correct complete bytes pass; `CHECKSUM_PARTIAL` fails.

The current driver's RX function sets `CHECKSUM_UNNECESSARY` at
`airoha_eth.c:971`, before calling `airoha_ppe_check_skb()` at1023..1025 and
before `napi_gro_receive()` at1028. The flag alone therefore cannot serve as
independent evidence for this proposed pre-stack guard. This fixture does
not establish that the driver's hardware-checksum behavior is faulty.

Boundary shims model `sk_buff`, packet copying and device roles. Ingress and
learned-key proof are explicit boolean dependencies, each tested for refusal;
the fixture does not requalify their real kernel/DSA implementation. The
checksum helper is an authored CPU proposal, not an extracted kernel checksum
implementation. Before use in a kernel, select and compile the actual Linux
API/stack strategy against the matching source and assess its stack usage.

An option with a valid generic length is only **syntactically** accepted. This
does not prove ASIC treatment of that option, of subsequent direct-hit packets,
TTL/FIN/RST exceptions, checksum failures or MTU changes. A stricter bind-trigger
predicate cannot enforce those conditions on packets that later bypass the
CPU. Native action defaults, a closed domain and withdrawal containment remain
separate requirements for a first controlled wired BIND proof.

Run `python3 run.py` on the configured build host. Only temporary CPU files
and a timestamped private receipt are written. The old preview fixture and
the actual patch974 remain unchanged.
