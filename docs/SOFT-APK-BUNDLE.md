# Package-managed native soft-ABI C bundle

2026-10-26 follow-up. This replaces the earlier unmanaged init/procd image
composition for the new candidate, not the currently qualified b05 baseline.
It remains an experimental mixed system, not a complete native SDK.

## Reproducible admission inputs and normal ownership

`prepare_soft_package_profile.py` merges the corrected C, Lua bindings and TLS
closures:58 native ELF paths and14 source components. It audits actual ELF
instructions, interpreter paths and DT_NEEDED closure; collects per-file source
inventories, compiler/builder fingerprints and license/source notices. The
profile requires Clang21.1.8, AAPCS64-soft, noFP/SIMD, no outline atomics and
`-ffp-contract=off`. The corrected libc hash starts143100b85695.

The reviewed v2 profile SHA256 is
`8ecb6b705abb2e003d032938d4332686e3f84233c448dee2658b8ecb035d5177`.
The admission caller must supply that digest independently. A changed profile
does not authorize itself. Exact content binding is essential: an ELF64
AArch64 header and a package architecture string cannot establish this PCS.

`build_soft_apk_bundle.py` creates four normally signed packages and uses the
normal APK solver in a fresh clone of the APK-managed hybrid root. It does not
edit the installed database, force a conflict, execute package scripts, download
packages, modify the baseline root or change the running DUT.

- `be6l-soft-runtime`: unique soft loader,58-ELF closure libraries/modules,
  reviewed profile and upstream source/license notices.
- `be6l-soft-tools`: isolated native programs below `/opt/be6l-a64-soft/bin`.
  Existing ARM32 Lua/curl and other application packages remain available.
- `procd`: native init/procd/askfirst/udevtrigger/upgraded and existing non-ELF
  scripts, with an exact dependency on the native runtime version.
- `be6l-arm32-procd-compat`: the original ARM32 `/lib/libsetlbf.so`, independently
  owned for ARM32 shell preloading. Native libsetlbf has its own soft library path.

The first three use the private `aarch64_be6l_soft_experimental` namespace;
compatibility uses `arm_cortex-a7`. Only those two architectures are admitted in
the new root. Ordinary Cortex-A53 AArch64 packages are not enabled.

The transaction yields212 packages, actual init/procd ownership in the new native
package, original ARM32 libc and81 byte-identical matching AArch64 modules.
An incompatible runtime version is rejected by normal dependency solving.
The throwaway signing private key is deleted; no binary feed is published.
License inventory is collected, but complete binary redistribution license and
corresponding-source review remains pending.

## Deliberate same-label substitution negative

A real ordinary-PCS fixture containing `fadd d0,d0,d1` replaces the candidate
runtime's libc. Its package uses the same name/version/architecture and a valid
signature from the fixture trust key. Normal APK simulation accepts its metadata.
The separate admission gate extracts it with signature verification, compares
the entire payload to the reviewed recipe and rejects the substitution. It never
enters the approved directory or the installed root and is never executed.
A modified provenance lock is independently rejected. This demonstrates a local
repository admission policy, not a new capability in the DUT APK executable.

Evidence: `logs/soft-bundle-soft-bundle-v2/result.json`. An earlier v1 transaction
succeeded but its subsequent read-only ownership query incorrectly included an
APK mutation-only option; the clean v2 run fixes that harness error.

## Protected image and loader preflight

`build_soft_apk_image.py` builds from the transacted root using standard
`target/linux/install`. It verifies the actual embedded CPIO, effective RAM
range, unchanged kernel configuration,81 module layouts and ten read-only MTD
partitions plus BMT protection. It restores the baseline external CPIO in finally.
`verify_soft_apk_manifest.py` exports the212 actual mixed-root records rather
than the native SDK staging manifest. Generic package/kernel upgrades remain
unqualified.

New candidate SHA256:
`5b3df962bc3db18acae277565bedeab92561a8c2cba7b3abe67b797b8f4a1a86`.
Effective Image size64618496 bytes leaves393216 bytes before the existing
0x84000000 limit. Future additions need a new size/layout audit.

The package's actual loader paths passed an isolated DUT chroot: native procd
invalid-option handling, native BusyBox/curl, Lua/Nixio/UCI/ubus/uloop including
the fma regression, and ARM32 shell/libsetlbf compatibility.
Evidence: `logs/soft-apk-loader-20261026-144905`.

The initial chroot curl failure was real but specific to the fixture:
`/tmp` is mounted nodev, so newly created random device nodes returnedEACCES;
getrandom itself succeeded. A probe reported mbedTLS entropy-60/PSA-148.
Binding only the actual null/random/urandom devices into the owned chroot gave
entropy0/PSA0/curl0. All binds and the test directory were removed. No entropy
bytes were printed and no library or entropy checks were weakened.

This is a loader preflight, not qualification of the entire new image. The
new hash still needs its own RAM startup, network/MTU/HTTPS, dual-band300-second
transfers, active lifecycle, recovery and flash-protection checks. Existing b05
wireless qualifications do not transfer to this new hash.

## Actual RAM startup

The candidate has now RAM-booted with the known protected ARM32 handoff and
the previously verified installed-firmware ABI. The ARM32 intermediate was
loaded by standard bootloader TFTP/bootm, after size/CRC/FIT checks, with wireless
module loading disabled. Temporary bootloader network/bootargs settings were
not saved. No stock kernel, flash write or unknown firmware service was used.

The actual native PID1/libc, package ownership,81 module hashes, ten MTD flags
and three baseline partition digests passed. Native Bing HTTPS at MTU1500,
Lua/fma/Nixio/bindings and the Simplified-Chinese Argon login page passed.
An unauthenticated LuCI403 with the login-required header and form is expected,
not an authentication failure to bypass.

The fresh clock initially remained at the epoch; strict TLS correctly rejected
the certificate. A volatile UTC calibration from the workstation restored TLS
verification. Autonomous NTP startup remains unqualified and must be investigated.
No RTC or certificate checks were modified. Basic evidence is
`logs/soft-apk-runtime-20261026-152154`.

Both-band short L2 forwarding passed with the previous Wi-Fi6 endpoint. Its
subsequent long test completed three directions but was interrupted when that
endpoint was replaced. The new Wi-Fi7 endpoint has separately passed5GHz HE CPU
controls, while2.4GHz has low-rate/retry/packet-loss observations even without
PPE bindings. Different endpoint, PHY and routing conditions must remain labelled.
See the endpoint-specific final results below; complete both-band and lifecycle qualification remains pending.

## Replacement endpoint and final campaign result

The new image separately passed default-EHT 5 GHz L2 forwarding with the
replacement Wi-Fi7 endpoint: 300 seconds per direction, approximately269/169
Mbit/s and6.8/5.9% total CPU busy. PPE direct-forward increments were298495
and4343272; both samples had zero NPU faults. The2 MiB SHA256 check and initial
re-authentication passed. Evidence: `logs/p2-phone-20261026-170711/result.json`.
This is a wired-LAN/client bridge test, not router-local throughput or routed NAT.
The HE80 CPU control separately passed275/142 Mbit/s for20 seconds, with zero
PPE direct-forward increments; duration and PHY differ, so these are not a
matched peak-performance comparison.

The replacement endpoint's2.4 GHz case remains unresolved. A no-PPE HE20 sample
transferred1251220 bytes within the25-second file deadline, with high retries
and a reported1 Mbit/s transmit rate. This is slow progress, not proof of a
permanent stall or a single NPU/VPN/RF/client cause. The user manually paused
the phone tunnel; no workstation VPN/default/metric setting was changed.
New-image active-binding/driver-exit qualification is still pending. Earlier
baseline lifecycle results are not inherited by this image.

At the quota threshold, APs/keys, TC bindings/owned qdiscs and phone test
networks/files were removed. Phone-owned policy priorities9001/9002 are absent.
The disconnected previous endpoint could not be checked for saved test networks;
their DUT secrets have been revoked. Ten MTD flags/digests, original NPU
firmware, two advancing worker heartbeats and normal-MTU Bing TLS passed final
checks. Watchdog status was running with24-second timeout and5-second feed;
actual reset acceptance remains pending. No flash writes or saved bootloader
environment changes were made. No automatic continuation is scheduled.
