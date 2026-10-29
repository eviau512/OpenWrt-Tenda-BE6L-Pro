# Early RAM reset investigation

The first XZ candidate reset after starting both AArch64 CPUs. Its final BMT
message does not locate the failure or measure the elapsed time until reset.
The working gzip baseline remains the qualified image; XZ ordinary retries
remain blocked.

A static comparison of the matching ARM32 and ARM64 Linux 6.18.55 sources
finds a watchdog handoff gap. Their identical Airoha watchdog driver registers
stop-on-unregister but has no platform shutdown callback or inherited-running
adoption. Standard kexec performs device shutdown rather than driver unregister.
Adding stop-on-reboot alone would still miss this kernel's SYS_RESTART path.
This is a concrete source gap, not proof that the observed reset was watchdog.

After BMT discovery, the MTD parser can request a missing parser module and
wait for asynchronous initramfs population. The main init output can therefore
pause there while decompression continues. The previous serial capture has no
host monotonic timestamps, so its final kernel timestamp cannot establish the
decoder duration. Subsequent stock pretimeout text is not independently proven
to describe a persistent preceding-reset latch.

The new offline-tested [capture helper](../tools/arm64/boot_capture_v1.py)
records per-chunk receive time bounds, offsets and hashes. It distinguishes
an interrupt attempt, completed serial writes and a wholly new stopped-ECNT
prompt. Timeout alone never qualifies reset containment or a successful boot.
Its integration is prepared but has not been exercised on the router.

Before a new boot experiment, review the outgoing ARM32 watchdog shutdown and
readback, qualify instrumentation with the known gzip baseline, and verify
independent management connectivity. Preserve all flash guards and memory
reservations. Do not retry the failed XZ artifact or change unknown registers.
