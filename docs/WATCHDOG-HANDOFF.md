# Checked watchdog shutdown for the ARM32 kexec intermediate

## Scope and status

This change addresses a demonstrated gap in the outgoing ARM32 watchdog
driver. It does not establish the cause of the earlier XZ boot failure.
The known gzip baseline remains the qualification target; the failed XZ
candidate has not been retried.

The normal OpenWrt ARM32 build completed, including the related packages and
85 matching modules. The known gzip handoff and incoming runtime checks passed.
A successful build,
a shutdown symbol, or a boot capture timeout alone is not runtime acceptance.

## Implementation

Patch `976-watchdog-checked-kexec-handoff.patch` adds a platform shutdown
callback which acts only during kexec. It reuses the driver's existing stop
operation and checks the existing watchdog-enable and timer-enable bits by
readback. A stuck bit returns `-EIO`; the timeout and suspend paths propagate
that failure. `WDOG_NO_WAY_OUT` is respected. Ordinary restart is unchanged.

The callback records one of the following markers:

- `BE6L_WDT_KEXEC_STOPPED enable_readback=0`
- `BE6L_WDT_KEXEC_STOP_FAILED`
- `BE6L_WDT_KEXEC_REFUSED nowayout=1`

The platform shutdown callback returns void and cannot veto kexec. Therefore
the failure marker cannot be described as an abortable handoff check. Runtime
acceptance requires a successful marker before the next kernel starts, no
unexpected reset or stock boot, and separate checks of the incoming system.
Incoming timer adoption is not implemented by this patch.

## Offline evidence

`logs/wdt-handoff-v1-20261030-102852/result.json` records 15 tests of the
extracted actual driver functions, including sticky-bit/readback faults,
NOWAYOUT, ordinary shutdown, timeout propagation and PM. ARM32 and ARM64
objects compiled against their actual kernel headers. The isolated test
preserved 162 protected SDK files. The subsequent normal ARM32 SDK build
intentionally installs the new patch; the unchanged-file statement does not
apply to that integration step.

The first package-install attempt failed because the inherited Windows PATH
contained a relative component rejected by GNU find's `-execdir`. The failure
receipt is retained. Installation and image creation completed with a fixed
Linux-only build PATH.

## Candidate and memory checks

ARM32 FIT SHA256:
`4f1d61e6ddfa92181655156f2d1bc91bc32b956b69d519e5e345b7a9af195cd1`.

- FIT size: 50,618,124 bytes.
- Decoded kernel size: 59,823,232 bytes.
- Kernel interval: `[0x80088000, 0x83995480)`.
- Existing reserved boundary: `0x84000000`; headroom: 6,728,576 bytes.
- TFTP staging interval: `[0x88000000, 0x8b045f0c)`.
- All ten read-only partitions and the BMT protection remain present.

The independently admitted candidate has a 64 MiB FIT-file check. The default
old recovery image retains its 32 MiB check. No reserved-memory boundary was
moved. The original ARM32 recovery and ARM64 gzip artifacts remain unchanged.

## Runtime qualification protocol

1. Verify independent host Wi-Fi DNS and strict HTTPS immediately before
   transfer and again before boot.
2. Transfer only the admitted FIT from a stopped ECNT prompt. Check its exact
   size, target CRC32 and FIT metadata before `bootm`; never save environment.
3. Capture UART with host monotonic receive timestamps. A reset is a failure;
   distinguish sending Ctrl-C from actually observing a subsequent ECNT prompt.
4. Verify the outgoing protected ARM32 system, its boot ID, shutdown handler,
   ten MTD flags and critical partition digests.
5. Use that exact outgoing boot proof to qualify the unchanged ARM64 gzip
   baseline. Require the stop marker before the incoming Linux boot marker.
6. Independently verify incoming architecture, image/modules, RAM root,
   management, NPU state and flash protection. Restore the temporary firewall
   lease immediately after transfer and preserve its restoration receipt.

No routed BIND, XZ retry, flash operation, unknown register or SMC is part of
this qualification.

## Observed target result

The ECNT transfer completed with exact size and target CRC32. The first
combined post-boot UART guard timed out; its raw exception output was not
persisted by that version of the wrapper. The failure is retained and no
successful guard is inferred from it. A separate paced, read-only follow-up
verified the same ARM32 boot, the handler symbol, ten read-only MTD flags and
the critical digests. The wrapper now retains command-failure output.

`logs/arm64-ramboot-20261030-111954/qualification.json` records the actual
handoff. The outgoing `BE6L_WDT_KEXEC_STOPPED enable_readback=0` marker precedes
the incoming AArch64 Linux boot. The timestamped capture observed no reset or
stock boot. `logs/ppe-bridger-runtime-20261030-112321/result.json` separately
verified both CPUs, all 84 exact ARM64 module hashes, native package-owned
PID1, Lua/Nixio, Chinese LuCI/Argon, strict Bing TLS, advancing NPU workers and
zero faults. Runtime NTP used the already authorized private upstream.

The host obtained its normal LAN DHCP lease automatically. The scoped TFTP
firewall helper recorded early restoration after transfer. An independent
unprivileged firewall-rule query was denied by Windows; do not present that
query as successful verification. The helper's restoration receipt is
`logs/wdt-v1-tftp-firewall-20261030-lease.json`.

The immutable baseline gzip image was restored; no XZ retry, routed BIND or
flash operation occurred. This is one successful checked gzip handoff,
not repeated-start qualification or evidence of the XZ failure's cause.
