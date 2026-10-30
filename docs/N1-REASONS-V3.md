# N1 bounded refusal diagnostics v3

The v3 delta adds 23 finite CPU observation stages for RX and TX. It preserves
all existing packet predicates, producer identity checks, the five-second
lease, record semantics and routed rejection. No counter is authority to
publish BIND. The diagnostic snapshot is version 3; the internal CT producer
context remains version 2 and 56 bytes.

Counters distinguish packet-format stages, absent skb CT, namespace/zone,
selected output and failure to find a matching direction pair. They advance
only under the observer lock during a live lease. An unarmed or expired
observer collects no new packet observations. The counters saturate rather
than wrap. The last-stage marker is meaningful only with an observed count.
RX_BASIC is a grouped initial-format rejection; do not infer a particular
failed predicate solely from that group.

The actual shared producer/record tests passed 58 cases. Tests of the actual
counter header passed 27 checks covering initialization, each stage, invalid
indices and saturation. All 328 related cached translation units were freshly
compiled, and the complete Airoha driver linked. Those tests preserved 93
selected SDK files. Normal integration subsequently installed the reviewed
counter patch as an explicit separate operation.

Patch SHA256:
6437af289fc210125881fcbe99a64b74ce75a88481d86492e56503e577ea62c2
Source lock:
303589c428317ef31ff2e3fcdef8ffa5407bdff632238eb71414311cf4d6ec86
Only this patch differs from the v2 source lock.

The normal clean kernel, external modules, signed APK transaction, embedded
CPIO and gzip Image checks passed. Candidate SHA256:
fd30e3894dfda619b1cd27e1575adb7388a58376a8fdb5c8b4ed88cbbea60835
It retains 84 exact modules, 216 packages, 58 native soft C paths and 327,680
bytes below the unchanged Image boundary. Its actual loader fixture passed
under the previous qualified kernel. Exact RAM payload hashes and 18 negative
candidate-admission cases passed. These facts alone do not qualify boot,
packet correspondence, lifetimes, routed PPE or default native-service changes.

Live startup and the next short observation are now recorded separately in
[the actual target result](N1-V3-TARGET.md). Software egress remains incomplete.
The failed v2 sampler and its partial result remain in N1-LIVE.md; do not
replace that failure with a result from a different image or boot.
