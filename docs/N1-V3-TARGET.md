# N1 v3 target result: CT and UNB correspond, egress remains incomplete

The matched fd30e389 RAM image passed its checked watchdog handoff and normal
startup checks: dual-core AArch64, 84 exact modules, 216 packages, 58 native
soft C paths, UI/Chinese/Argon, Lua/Nixio, strict Bing TLS, NPU worker progress
and all ten MTD guards with unchanged critical digests. Most apps remain ARM32.

A new five-second, no-BIND diagnostic used a three-second low-rate TCP client
through the wired LAN/WAN. Both endpoint summaries reported 1,966,080 payload
bytes. The relay's upstream sockets selected the wired interface explicitly.
All six one-second snapshots completed with empty BIND output. The classifier
restored its exact original value, with no ownership conflict or flow/L2
parents. The separate typed restoration report was retained this time.

The real CT producer supplied four direction rows. Twenty RX observations
matched the UNB tuple and accepted CT rows; two reached the row check without
a match. Four flow-rule DESTROY row revocations occurred within the lease.
This is real NF flow-rule teardown evidence, not a direct CT-destruction
notifier or proof of final CT reference/free ordering.

The egress tap saw 2,716 packets: 2,590 lacked skb CT, 104 had no matching
direction pair, two failed the Ethernet check and twenty failed IPv4 parsing.
No egress was accepted. Do not attribute every absent-CT packet to a particular
flow using these aggregate counts. The cached software-flow path transmits
without attaching CT; a diagnostic per-packet identity carrier is the next
design to review. It must retain generation and both tuple identities, survive
queuing/cloning, and never confer authority to publish hardware forwarding.
The 104 unmatched-pair cases also remain unresolved.

The observer expired with zero held netdev references. The owned module and
relays were removed, firewall deltas reverted without commit, the original
firewall file hash matched, and bridger restarted. No NPU fault occurred;
the direct PPE forwarding counter stayed zero. No AP or phone configuration
was changed. This is a diagnostic, not a speed benchmark.

N1 remains incomplete: software egress correspondence, replacement, flow-block
withdrawal, device changes, concurrent callback draining and final CT-ref
ordering still need tests. N2 native-action, later-hit ingress and checked
withdrawal gates are unchanged. No routed BIND, NAT/IPv6 hardware qualification,
per-flow counters or LuCI WAN hardware-offload acceptance is claimed.

The older v2 sampling failure and partial result remain in N1-LIVE.md.
This distinct image/boot does not erase that failure.
