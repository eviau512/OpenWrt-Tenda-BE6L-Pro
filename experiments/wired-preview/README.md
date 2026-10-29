# Non-publishing wired IPv4 preview contract

This CPU-only experiment prepares a software contract for a future diagnostic
adapter. It does not install a driver, construct a BIND image, expose a
publisher, change classification or access hardware. `can_publish` is always
false. The existing AN7563 routed refusal gates remain unchanged.

The successful receipt is
`../../logs/wired-preview-20261028-203200/result.json`; its sibling `plan.json`
contains the synthetic partial value/mask example. The run passed **108 cases
with UBSan**, finishing with zero retained device references. The first
compile caught a warning in the host WARN_ON_ONCE shim; correcting that shim
produced the successful receipt. The previous4098-vector experiment was not
rerun.

## Real inputs and boundary shims

`run.py` verifies all frozen source hashes before extracting the actual C
bodies. It uses the patch974 compilation receipt's isolated source, not the
current SDK checkout:

| Input | SHA-256 |
| --- | --- |
| frozen974 airoha_ppe.c | `39b585e3b1f2bc808e19ebdffd5dc53e34feac4558f76336b024b58aae676e35` |
| frozen974 airoha_eth.h | `7b7e6913c66fc6927f9392b233c40923cc24fffceffc04a7e1bf10b0c7073fff` |
| saved nf_flow_table_offload.c | `6c1ebd3240663cd2bf78a05cc48a9a5d7f8338aa75890d63e8190ab458097d23` |

Extracted code includes Linux's real IPv4/port SNAT and DNAT producers,
Airoha's actual mangle consumers and IPv4 tuple encoder, the actual tuple/MAC
structs and the patch974 CT-context validator. Four MAC assignments are copied
exactly from the real Airoha constructor into a narrow wrapper; its unqualified
neutral defaults are deliberately not extracted. Static assertions verify the
80-byte typed view and translated-tuple/MAC offsets. The context type comes
from the explicit patch973 addition, whose hash is recorded in the receipt.

Kernel API types outside those extracted layouts are narrow host shims.
`preview_device`, its incarnation counter and integer reference counter are
**experiment types**, not additions to Linux net_device or a firmware ABI.
The three modeled lease references and two references per preview entry test
balanced ownership; they do not prove actual netdev/RCU/DMA lifetime semantics.

The authored fixture portions carry MIT notices. Extracted Linux/Airoha code
retains its upstream GPL source licensing and authorship; the wrapper does not
relicense the extracted bodies. No proprietary delivery code is included or
executed.

## Exact software lease

The fixture pins one specific LAN3 object, its conduit and one real WAN object.
LAN3 uses logical port3 / DSA index2 and PSE selector1; WAN uses real untagged
GDM2 with PSE selector2. These are explicit **synthetic selected-device inputs**,
not proof of the currently connected router's physical-port mapping. A future
kernel adapter must resolve and verify the real pair and references first.

Only original LAN3→WAN and reply WAN→LAN3 requests are accepted. Another DSA
LAN port, or a second object with the same role/index/ifindex as LAN3, is
rejected. Requests must match the selected pointers, incarnations, current
ifindices and explicit ingress-ifindex match. Foreign namespaces, VLAN or
opaque upper devices and changed selected-device shapes are refused.

A lease has a monotonically increasing, nonzero generation and a deadline in
caller-supplied monotonic ticks. The example's100..200 ticks are not hardware
time units. Old/future request generations are rejected. Device/conduit
change, a backwards clock or deadline expiry revokes the entire lease and
releases every preview entry plus lease references. Explicit revoke is
idempotent. A generation cannot be reused after revoke.

The real CT validator requires explicit producer/version/valid, original or
reply direction, initial namespace, raw and effective zone0, default zone
direction, zero zone flags and zero reserved bits. The additional software
contract requires complete IPv4/TCP address/port/protocol and ingress masks,
the matching IPv4/TCP selector values and no extra match keys. This metadata is
not a proof of the domain of every later hardware packet.

## Partial action plan

The observed20 words are retained unchanged as a separate UNB snapshot. Its
state/type/protocol and original key prefix must match the approved direction
of the paired Linux tuples. Actual extracted Linux producers and Airoha
consumers compute the translated tuple. The final translation must equal the
reverse of the opposite approved tuple; inconsistent NAT flags are rejected.

The separate20-word `value` / `mask` arrays describe only these supported
fields:

| Words | Known mask | Meaning |
| --- | --- | --- |
| 4 | `0x000001e0` | Output selector bits8..5 for the selected modeled device |
| 5..7 | `0xffffffff` each | Translated source/destination IPv4 and source-high16/destination-low16 ports |
| 12,14 | `0xffffffff` each | Numeric destination/source MAC high32 fields |
| 13,15 | `0xffff0000` each | MAC low16 fields; adjacent VLAN/PPPoE halves remain unknown |
| All other bits | zero | Unknown, not a proposed zero/default value |

The native address/port/MAC writers and INFO2 output-field position are
corroborated in `../../REPLY-20261028-1-2-BIND-AUDIT.md`. The software output
selector values do not qualify the complete native routed action contract.
No IB1 BIND value, timestamp, TTL, DSCP, PORT_AG, QoS force, action-data, tag,
meter or remaining-word default is synthesized. The private typed encoder
scratch retains UNB; it is never promoted or serialized as an80-byte BIND.

Every plan retains all six unresolved gate bits (`0x3f`): complete native
control/defaults, ASIC equality/domain isolation, checked withdrawal/drain,
exception semantics, actual packet/physical-ingress proof, and a matching
non-publishing kernel adapter. None can be cleared by this experiment. It has
no API that can publish a plan, including after all CPU checks succeed.

An identical key/action request is idempotent and takes no new references or
deadline extension. The same software key with a different translated tuple,
MAC action or direction is rejected; table exhaustion also fails without
reference leakage. This is a software conflict table, not an assertion that
the ASIC comparator has the same key or that Linux CT uniqueness is proven.

## Verification and next adapter boundary

The108 cases cover both directions and Linux NAT shapes, exact-pair rejection,
context/mask/selector failures, altered UNB keys, wrong protocol, invalid MAC,
inconsistent tuple translation, conflicting duplicate actions, idempotence,
generation reuse, stale devices/conduit/ifindex, expiration, revoke and table
exhaustion. Each failed request returns an empty unknown plan with
`can_publish=false`; all final reference counts are zero.

On the configured Linux/WSL host, run `python3 run.py`. It reads only the frozen
inputs, compiles a temporary host executable, deletes that temporary directory
and writes a timestamped receipt under logs. It neither builds a kernel nor
modifies SDK source, Image, modules, CPIO, hardware or flash.

A next diagnostic adapter must supply real retained devices, verified packet
and CT provenance and lifecycle callbacks, then expose only this partial
non-publishing result. This host fixture has no real packet-path or hardware
qualification. Native defaults, domain/equality and withdrawal remain open;
passing this test does not authorize removing the routed driver guards.
