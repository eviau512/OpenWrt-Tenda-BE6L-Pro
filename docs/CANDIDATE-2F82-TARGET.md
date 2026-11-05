# New ARM64 candidate startup and scoped recovery, 2026-11-05

The matched `2f82bb55` initramfs was loaded through the protected ARM32
intermediate and started on the actual router. Initial startup acceptance
passes. The firmware remains RAM-only and contains a private test SSH identity;
no image or private key is published. Selected evidence is in
[`candidate-2f82-target-20261105.json`](evidence/candidate-2f82-target-20261105.json).

| Requirement | Actual result |
| --- | --- |
| FIT SHA256 | `2f82bb557a766d399f94f6f217d6e0c6667c38a7cda6b6a4415c2cb6770b4a1e` |
| Running kernel GNU build ID | `4dcb3923d187eb5430344d5b3f3668e750700ae6`, read from `/sys/kernel/notes`, matches the sealed new vmlinux |
| Architecture and root | Two AArch64 CPUs, tmpfs RAM root, correct board |
| Kernel modules | All84 module files match the composed candidate |
| Package transaction | All219 package names, versions and architectures match the offline signed composition |
| Native userspace | All61 regular AArch64 user ELF files match; actual PID1 and default netifd executables match |
| Native VM | Default netifd maps fs, ubus, uloop, uci and nl80211 |
| Default services | Network, SSH, HTTP and recovery run with zero observed respawns |
| NPU | Both ABI5 workers advance, zero reported faults |
| Flash protection | Ten MTD flags remain read-only; critical bootloader/environment/Factory digests unchanged |
| Management | Chinese Argon login form renders with the dispatcher's expected unauthenticated403 response |
| Recovery | Authenticated heartbeat and default300-second expiry after explicit wireless/NPU detach return to authenticated stock `.67` |

This completes compilation, RAM loading and initial on-device testing of the
new initramfs. It does not establish release readiness or normal Cortex-A53
binary-package compatibility.

## Exact loading and identity

`prepare_arm64_candidate_payload_v1.py` binds the actual FIT/CPIO/root to the
prior qualified loader fixture and the real isolated netifd test. The fixture
contains111 members:110 image paths plus a test-only curl probe. All110 image
paths remain identical in bytes, modes and symlinks. The prior trampoline,
ARM32 fallback and kexec executor remain identical. The new static loader is
compiled for the new Image/allocation/DTB sizes; only allowlisted RAM boot
arguments change.

The admission function also rejects actual Image/DTB mutations that overlap
NPU memory, change the load address or remove a read-only partition guard.
`stage_arm64_candidate_v1.py` checks the outgoing boot ID, RAM ranges, memory
margin, idle NPU, checked watchdog symbol, MTD protection and all target file
hashes before calling `kexec_load`. It does not execute the image.

The timestamped boot capture then observes the old kernel's checked watchdog
stop marker before ARM32 shutdown, AArch64 entry and incoming Linux. No reset
banner or panic was observed. The kernel build ID independently distinguishes
the new build from the older6.18.55 baseline; a release string alone would not.

`qualify_arm64_candidate_runtime_v1.py` verifies actual process bytes, package
owners and the complete module/package/native-ELF sets. Earlier attempts are
retained: a local Python string escape stopped before SSH; a later check
incorrectly required HTTP200 for the unauthenticated login. The pinned LuCI
dispatcher deliberately returns403 and `X-LuCI-Login-Required: yes`. The final
check requires that exact header, login fields, Chinese language and Argon
resources, rather than accepting an arbitrary forbidden response.

## Default expiry after explicit NPU detach

The same new candidate subsequently completed its own recovery test with the
baked-in r2 guard and unchanged600/300 defaults. Normal `wifi down` and
`rmmod mt7996e` first left NPU running0/attached0, PPE/TDMA0 and faults0.
The last authenticated heartbeat at uptime7161 expired at7465:304 seconds,
within the configured five-second polling interval. UART recorded a fresh
U-Boot banner without any autoboot interruption. Automatic host DHCP return,
authenticated stock `V16.03.60.67_cn` web/Telnet root preflight and a changed
stock boot identity were independently verified. No image was uploaded after reset.

All host heartbeat/capture jobs were stopped or terminal and the device was
left in stock. This is a scoped new-kernel result: the guard does not itself
perform the explicit wireless/NPU detach. Active-NPU traffic, initial600-second
grace without any heartbeat, forced fallback and hard locks remain unqualified.

## Remaining scope

WAN DHCP is currently down and the PPE bind table is empty. Advancing NPU
workers prove firmware/host startup, not packet forwarding through the newly
ported SRAM policy. No routed BIND, NAT, IPv6 offload, throughput or withdrawal
test follows from these startup checks. The941-04 SMAC/FOE lifetime port is
still required. Existing routed rejection remains unchanged.

The two earlier recovery cycles belong to the ARM32 intermediate and old ARM64
kernel. They retain their own scope; the new-kernel result is documented above.

The native runtime still uses the private AAPCS64-soft ABI. ARM32 applications
remain through COMPAT. The allowed emulation fallback now [passes selected
standard ABI tests](ARM64-INSTRUCTION-FALLBACK.md); complete package and child
execution acceptance remain separate work.
