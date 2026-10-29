# Compile-only Linux wired observer v1

This is a finite, nonpublishing Linux API library, not an installed PPE patch.
`diag.c` compiles against the exact cached Linux6.18.55 ARM64 headers. A zeroed
`bd_config` refuses creation. No module init, exported symbol, debugfs writer,
production hook or remote arming command is installed.

The library retains the actual LAN user port, real GDM2 WAN and GDM1 conduit.
It resolves DSA through the matching Linux API, requires an explicitly supplied
physical DSA index, verifies registered initial-netns objects and exact GDM
identity, and takes three real netdev references while holding RTNL. It never
uses the host fixture's synthetic DSA index2. Held object identity plus notifier
invalidation prevents an ifindex reuse from silently substituting a new device.

The lease is one-shot and at most five seconds. A separate observer lock guards
references and four copied rows; there is no acquisition of the PPE owner lock.
Expiry, a relevant unregister/down/upper/MAC/MTU/change/name event and destroy
converge on one detach. References are put outside that lock. Namespace movement
uses Linux's existing unregister events; no invented notifier constant is used.
Every CT/RX observation checks the monotonic deadline itself, independently of
when the delayed worker is scheduled. A snapshot distinguishes an expired
observation window from any references still awaiting scheduled cleanup.

`note_ct` copies explicit CT/default-zone provenance, exact original IPv4/TCP
keys and up to16 pointer-free raw actions. It supports the actual producer's
seven keys, including exact IP/TOS and TCP FIN/RST masks. It requires exact
redirect object identity, not merely the same output ifindex. Only one redirect,
raw mangle and checksum action kinds are copied. A different action for an
already observed key is refused; identical duplicates do not extend the lease.
There is no persistent flow-rule, action, netdev-action or conntrack pointer.
The direction scope is explicitly LAN-initiated original and WAN reply.

`note_rx` accepts an already copied UNB snapshot; it issues no hardware read.
It checks the real skb input object or GDM1 DSA metadata, pre-NAT tuple/key,
both MTUs, complete non-GSO packets, IPv4/TCP shape, TCP option syntax and
ACK/no-SYN/FIN/RST/URG. Linux `ip_compute_csum`, `skb_checksum` and
`csum_tcpudp_magic` check the bytes independently of `ip_summed`; the diagnostic
does not trust `CHECKSUM_UNNECESSARY` or mutate a packet. A true return means
only a recorded observer match. It must never become a TC offload result.

The caller owns lifecycle integration. Before destroy it must unpublish and
drain CT/RX/snapshot callers. It must supply a current generation and pass a
consistent already copied UNB while obeying existing DMA/read ownership. None
of those driver hook/drain contracts is installed here. Rows are historical
observations, not proof that a CT flow remains alive; CT destroy/replace
correlation, opposite-tuple pairing and software-egress observations remain
to implement. No raw action is claimed to be a qualified ASIC action encoder.

`run.py` compiles the actual ARM64 object in a separate directory, verifies
88 cached SDK files byte-identical and inspects undefined symbols for the
expected kernel APIs and absence of publisher calls. It runs20 UBSan tests of
the same finite epoch code, including all six serialized expiry/notifier/
destroy orderings. These are modeled lock interleavings, not executed kernel
refcount, KUnit, KCSAN or packet-path tests. The previous RX37 matrix and
preview108 matrix are not rerun or counted as new tests.

Run in the existing WSL environment:

```sh
python3 experiments/wired-kernel-diag-v1/run.py
```

No firmware, module package, image, classifier, BIND slot, SRAM owner, MMIO,
SMC, target setting or current SDK source changes. Snapshot `can_publish`
remains false and all six unresolved admission bits remain set (`0x3f`).
