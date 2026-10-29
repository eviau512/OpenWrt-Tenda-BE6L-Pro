# BE5000 reference and remaining routed admission

The research reference is [Pavel Bragin's BE5000 project](https://github.com/pabragin/xiaomi-be5000-openwrt),
documentation commit `d88ed6a9881544ff891207a2c3c06df26fc095e1` and release
[`be5000-openwrt-20261026`](https://github.com/pabragin/xiaomi-be5000-openwrt/releases/tag/be5000-openwrt-20261026).
The selected477434-byte source bundle SHA-256 is
`4e33759dbb02ec5bd32c69d42097e466fd5e511f0b1754839944d764c9a1fea9`.
Only necessary pinned patches/files were fetched; no full OpenWrt clone or
foreign firmware/bootloader image was downloaded or executed.

The generic driver really constructs IPv4 HNAPT translations and IPv6 routes.
Its documented high-throughput tests primarily cross Wi-Fi and wired LAN;
WAN DHCP setup and a generic NAT builder do not prove routed hardware forwarding
on BE6L. The reconstructed equality compares protocol/original tuples without
an ingress or CT-zone identity. It does not close this project's admission gap.
This review does not assert that the author's WAN is broken.

Patch0089, commit `720c49f80357db9a76a38172b1d24307f3b71f91`, rejects router-local
IP destinations during L2 subflow binding. It informs a focused safety test.
Our native BRIDGE-only guard already excludes the reference's exact generic
IP-subflow path; copying the guard would not itself solve all local-IP or
identity conflicts under an existing native MAC-keyed entry. No drop-in port
or hardware-NAT enablement is claimed.

The reference replaces RX-only firmware with source-built MIT firmware and a
coordinated host/mt76 ABI. BE6L retains its independently validated, hash-locked
firmware/host pair. Its own source lock also contains source-firmware inputs;
calling that pair a vendor binary was not justified. Compare the actual ABI
versions/layouts before any substitution. Current firmware/header and host use
ABI5, while reference release sources declare ABI1. Basic protocol constants
match; current PN/PPE-domain/QoS/recovery extensions do not make the layouts
interchangeable. This is related source-firmware work, and this review changed
neither pair. A firmware transplant is not a prerequisite for the first wired
NAT proof; routed identity/action/withdrawal evidence remains the separate gate.
Existing bridger netlink-error and policy-invalidation changes
already match locally; they were not duplicated. Preserve per-file GPL/MIT
licenses, authors and sign-offs for any future code adaptation.

Independent audits of the new private specification also found a PORT_AG
skip sentinel mistaken for a stored default, reversed port halves, an IPv6
hash branch cited as IPv4, omitted later native writers and an unsupported
RCU/time-delay drain claim. Actual initial tail-clear and ACK-error evidence
remain useful. No delivered script was executed or routed BIND published.

New source-only preview work passed108 CPU/UBSan cases: an exact selected device
pair, generations/deadlines, conflict rejection and balanced references. Plans
contain only proven tuple/MAC/output value/mask fields; unresolved fields remain
unknown and `can_publish` is always false. This is not a deployed kernel adapter
or an ASIC equality/withdrawal proof. Existing routed gates remain active.

Parallel160MHz owner-AP test tooling is prepared separately; no live parallel
pass is claimed. It preserves the owner's AP/credentials/association and owns
only its own processes. Sequential per-direction results stay labeled as such.
