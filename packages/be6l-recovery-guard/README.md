# BE6L Pro initramfs SSH recovery guard

Status, 2026-11-05: release r2 passes23 shell/host groups, normal signed APK
installation and real ARM32/ARM64 procd and heartbeat checks. One temporary
60-second ARM32 expiry returned to authenticated stock management. The new
matched ARM64 FIT includes r2 but has not been booted. Default600/300 expiry,
ARM64 expiry and hard-lock recovery remain unqualified. See the
[actual results and scope](../../docs/FRESH-KERNEL-AND-RECOVERY.md).

Release r1 exposed an absent BusyBox stat applet on the first target boot.
Release r2 uses numeric POSIX ls to require UID0 and exact0700 permissions,
without adding a new runtime utility. The symlink refusal remains in place.

The owner has no on-site person to power-cycle or interrupt UART. Include this
package in the next protected RAM candidate through the normal signed package
workflow. Do not patch an already admitted image, its CPIO, or its APK database.

Default timings:

| Setting | Seconds | Meaning |
| --- | ---: | --- |
| boot_grace | 600 | Earliest expiry, measured from kernel uptime zero |
| disconnect_timeout | 300 | Time allowed after the last accepted SSH heartbeat |
| poll_interval | 5 | Deadline sampling interval |
| force_after | 30 | Delay from normal reboot request to one forced fallback |

Expiry occurs at `max(boot_grace, last_heartbeat + disconnect_timeout)`, with up
to one poll interval of sampling delay. Without any SSH heartbeat, expiry is
600 seconds after boot. Before using this image, start its host heartbeat
helper as soon as SSH is available. A long-running SSH terminal alone does not
refresh the guard. This avoids trusting half-open sockets or leftover sessions.

The receipt is an authenticated root SSH command, not an open network service.
The daemon uses `/proc/uptime`, a boot-ID-qualified atomic file, and a root-only
temporary directory. NTP changes do not move its deadline. Accepted heartbeats
extend the deadline after reconnection; restarting the daemon does not create a
new boot grace. State is RAM-only. A per-boot firing marker prevents repeated
attempts after daemon respawn. Root can explicitly disarm and rearm it.

The board compatible must include `tenda,be6l-pro`, and the root mount must be
rootfs, ramfs or tmpfs. It refuses persistent root filesystems. It does not open
`/dev/watchdog`, replace procd's watchdog owner, touch MTD, or change networking.

## Host and target commands

After verifying the candidate's SSH host key and runtime board/root checks:

```sh
python3 tools/recovery/ssh_heartbeat.py --host 192.168.1.1 --duration 3600 \
  --identity-file /path/to/private-test-key --known-hosts /path/to/verified-hosts
```

The helper uses strict host-key verification and noninteractive key/agent
authentication. It never prompts for or saves a password. A known-hosts file
can be selected with `--known-hosts`. `--expected-boot-id` adds a runtime boot
pin. The helper stops on a changed boot ID. Stopping it leaves recovery armed;
the last receipt's deadline remains in force. It is a bounded foreground task,
not an automatically scheduled or detached job.

```sh
# Run these through an already authenticated root SSH session.
/usr/sbin/be6l-recovery-guard status
/usr/sbin/be6l-recovery-guard disarm
/usr/sbin/be6l-recovery-guard arm
```

`status` reports policy state; independently check the procd service instance
is actually running. Heartbeats fail while explicitly disarmed. `arm` requires
SSH context and writes a fresh heartbeat before removing the disarmed flag.
The UCI configuration is `/etc/config/be6l-recovery`.

## Package integration and remaining admission

`tools/package_native_netifd_v3.py` builds the signed component APK and installs
it with the offline solver alongside native netifd. The latest 216-package
diagnostic root becomes 218 packages. File ownership, exact bytes, modes and
offline service enable pass; the original root is unchanged. This fixture uses
a temporary signing key, removed on exit, and does not execute target services.
It is not a normal SDK package build or a bootable-image acceptance.

1. Copy this package source into a new restored SDK package directory, preserve
   source hashes, select it in the new candidate, and build a normal signed APK.
2. Add it with the offline APK solver to a new matched root. Verify every
   installed file's package owner and bytes; reject `.apk-new` leftovers.
3. Explicitly enable `be6l-recovery` in the offline root with `rc.common` when
   using `--scripts=no`, and verify `S95be6l-recovery`. The component composer
   performs this step; a future complete image builder must retain the check.
4. Measure CPIO/gzip Image growth against the unchanged `0x84000000` boundary.
   Reuse none of the old image's admission or runtime claims for the new image.
5. Verify real procd start/respawn, directory permissions, RAM/board refusal,
   authenticated reconnect, timer expiry, forced fallback and returned stock
   management before relying on unattended recovery. Coordinate the heartbeat
   helper with the complete Telnet/RAM bootstrap rather than an on-site UART stop.

Twenty-one actual-shell/state/host test groups passed on both Windows sh and
Ubuntu 26.04.1 `/bin/sh`; reboot, platform and clock effects were mocked. This
does not qualify real kernel locking, shutdown, procd, or hardware reset.

## Recovery limits

A userspace daemon cannot run during a full kernel hard lock. The existing
procd hardware-watchdog behavior and a real watchdog reset remain separate
target acceptance work. Historical warm reset stalled in U-Boot NAND setup;
a reboot request does not prove recovery. RAM firmware is discarded by reset,
so success should return to the original stock system, not relaunch RAM Linux.
The stock-to-RAM chain must remain separately usable without physical help.

References: [OpenWrt procd init scripts](https://openwrt.org/docs/guide-developer/procd-init-scripts)
and [hardware watchdog ownership](https://openwrt.org/docs/guide-user/hardware/watchdog).
