# Experimental two-core software flow channel

The channel in `experiments/flow-abi/` is a real host-to-NPU software transport
prototype. It is not connected to live routed packets or hardware DMA queues.
The synthetic controller is `diagnostics/be6l_flow_channel.c`.

## Demonstrated behavior

The ARM64 host controller and both actual RV32 NPU workers completed 128 command
transactions and 266 core/result assertions without an error. Five synthetic
IPv4 TCP/UDP/UDP-zero and IPv6 TCP/UDP actions were serialized by the host and
decoded by each worker. Each worker processed eight valid frames per action.
The frames were private synthetic buffers, not captured client traffic.

The tests covered prepare/commit, rejection before final activation, port/VLAN/
WCID/replay-generation/CT-zone mismatch, rejection of premature revoke, gate
closure, local freeze, final-statistic consumption, slot reuse, stale generation,
reserved-word and session mismatch. Additional offline tests covered replayed
sequence numbers and incomplete odd-sequence publication, under UBSan.

## Transport contract

Only aligned 32-bit little-endian words cross the ABI; neither native pointers
nor C structure padding is serialized. Separate per-core command/response pages
have one host writer and one worker. The host first publishes an odd sequence,
writes the body, issues a write barrier and publishes a new even sequence. A
worker copies and rechecks the sequence before execution. The host waits for
both exact ACKs and checks session, cookie, generation and core identities.
Sequences do not wrap; recovery must end a failed session before reuse.

PREPARE records an immutable action without granting forwarding. COMMIT makes
each local action ready. Only after both COMMIT ACKs may the host publish one
shared 32-bit generation gate. Revocation closes that gate before either worker
is asked to revoke. Each local synthetic token pool must be empty before its
FENCE response; final counters must be consumed before the slot is reused.

The reserved host interval is `0x84220000..0x8422ffff`, within the existing
NPU workspace. Compile-time bounds separate it from the earlier diagnostic
counter page and native rings. The controller validates the board, NPU memory
reservation, version, worker identity and ready announcement before writing.
It does not write a peripheral register, queue index, descriptor or payload.

## What this does not prove

An empty synthetic token pool is **not** a drained PPE/TDMA/radio hardware queue.
Actual LAN-to-radio frames may already have passed hardware lookup before a
worker can capture a generation. That ownership/invalidation boundary remains
to resolve; a software FENCE must never be relabeled as a hardware drain ACK.

Before live integration, the driver must supply Linux-approved actions and
complete ingress/CT domains, retain per-token tickets through all actual queues,
define cache/DMA ordering, and handle neighbor/route/rule/CT/key changes, worker
faults and late completions. L2 parent/child statistic aggregation and byte
semantics remain unfinished. No unsupported admission or DMA check is removed.

The diagnostic firmware retains the existing native firmware ABI 5, adds a
separate software-channel version 1, and leaves ordinary forwarding workers
unchanged. After the hardware experiment the original firmware was restored
and the controller unloaded. Nothing from the experiment was flashed.
