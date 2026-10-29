# Timestamped boot capture v1

CPU-only preparation for a later authorized RAM handoff. Importing
`tools/arm64/boot_capture_v1.py` does not open a port or operate a device.
`capture_boot()` accepts an already-owned nonblocking/bounded UART object;
the caller retains all route, artifact, RAM, flash and shutdown admission.

For every receive chunk the JSONL sidecar records raw-file byte offset/size,
SHA-256, host monotonic time immediately before and after the UART read, and
host UTC record time. These are host observation bounds, not device packet,
kernel-stage or precise wire-arrival timestamps. Raw output remains separate.
Capture is limited to180s maximum and16MiB. The default is120s.

Only a completely observed `Hit ctrl+c to stop autoboot` marker permits the
existing bounded Ctrl-C/Ctrl-C/CR sequence. No command, reset, environment save
or repeated attempt is sent. Evidence distinguishes the attempt, successful
serial API writes and a wholly subsequent `ECNT> ` prompt. Successful writes
are not proof that the bootloader received or acted on them. A prompt already
present in the same receive chunk cannot confirm the attempted interruption.
The confirmation deadline is at most8s by default, within the total deadline.

Timeout, a reset banner without a stopped prompt and a failed/short serial
write never establish containment. Observing stock Linux5.4 means the helper
will not claim stock autoboot was contained, even if a later prompt appears.
An actual prompt is current observation, not a guarantee against later resets.
The helper never qualifies successful boot or unchanged flash.

`run_ramboot_guarded_v3.py` is an unexecuted integration copy. Its complete
prefix through artifact/failure admission, flash hashes, memory/route/NPU
guards and kexec launch is identical to v2. Only the subsequent capture tail
uses this helper and records `boot-capture-result.json`. It fails the boot on
an unexpected U-Boot/autoboot marker even when the prompt was confirmed.
The original v2 file is unchanged. No failed-XZ retry was made or newly
admitted. Existing `--diagnostic` policy was not relaxed.

Run the offline fixtures with:

```
python experiments/boot-capture-v1/test.py
```

Ten test methods pass, including all26 internal autoboot-marker splits and
all5 internal ECNT splits, pre-interrupt/partial prompt refusal, timeout,
reset-only, stock continuation, serial-write failure evidence and no repeated
control transmission. Receipt: `logs/boot-capture-v1-cpu-20261029.json`.
No serial library, hardware, network or subprocess is used by those fixtures.
Three changed Python files also passed AST parsing. Live capture remains
unqualified and should first accompany a separately admitted known gzip boot.
