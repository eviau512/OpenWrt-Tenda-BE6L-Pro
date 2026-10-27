# DUT-local TCP receive and transmit costs

These measurements terminate TCP on the router. They are not evidence of PPE
forwarding, NAT acceleration or a LAN-to-WAN throughput ceiling. They use the
existing protected `d5a2bc21` image and a separate wired upstream server.
No steering, offload, route, firewall or clock setting changed during the test.

Four sequential20-second samples produced these receiver-reported rates:

| DUT direction | TCP streams | Mbit/s | Total CPU busy | CPU percentage per Gbit/s |
| --- | ---: | ---: | ---: | ---: |
| Transmit | 1 | 963 | 64.4% | 66.9 |
| Receive (`-R`) | 1 | 1304 | 85.9% | 65.9 |
| Transmit | 4 | 1218 | 80.5% | 66.1 |
| Receive (`-R`) | 4 | 1152 | 84.1% | 73.0 |

The single-stream normalized costs differ by about1.5%. A higher receive CPU
percentage therefore largely accompanies more processed traffic, rather than
demonstrating a large per-byte receive penalty. The four-stream transmit result
also shows that the observed single-stream rate is not a fixed1Gbit/s transmit
cap. Stream scheduling, TCP behavior, queue serialization and receive processing
can limit throughput before aggregate CPU reaches100%; this test does not
identify one of them as the complete root cause.

The CPU breakdown differs: single-stream transmit had about34.0% system and
26.9% softirq time, versus receive74.6% system and7.9% softirq. Thread and core
samples were retained privately. This is accounting for the measured setup,
not a full call-stack profile or a claim that IRQ work costs nothing. Threaded
NAPI can account work outside the softirq bucket.

Current driver capabilities also differ by direction: generic TX checksum,
scatter/gather and TSO are disabled, while software GRO is enabled. The RX path
marks received checksums internally; ethtool's RX feature flag alone cannot
prove that every received byte was checksummed by the CPU. Linux documents
[segmentation and GRO](https://docs.kernel.org/networking/segmentation-offloads.html)
and [receive/transmit steering](https://docs.kernel.org/networking/scaling.html)
as separate mechanisms. Exact AN7563 descriptor semantics still need validation
before enabling new hardware offloads.

The first data collection completed its traffic but its large SSH JSON output
was truncated. That attempt remains a harness failure. The successful run wrote
temporary RAM files and read them in bounded chunks; it does not overwrite the
failed raw log. No test process or temporary output remained afterwards.
