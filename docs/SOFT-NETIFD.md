# Native soft-ABI netifd: real Linux backend, isolated acceptance

2026-10-26. Cached libnl-tiny2025.12.02~40493a65 and
netifd2026.09.11~06d06c86 now build with the corrected AAPCS64-soft C closure.
`build_a64_soft_netifd.py` clones only the required source components and an
owned private sysroot. It does not download a repository, modify either SDK or
replace the live network manager.

The Linux backend is explicitly enabled; `DUMMY_MODE=OFF` is audited. All ten
ELFs pass actual no-FP/SIMD, interpreter/dependency and strong-symbol checks.
Two fresh roots with different path lengths produce identical ELF hashes and
source maps: `logs/soft-netifd-reproduction.json`.

The builds retain warnings but demote two specific Clang diagnostics from
Werror: musl's signed CMSG macro comparison and the existing GNU ethtool
flexible-array request layout. No structure, ioctl, backend or runtime capability
is replaced to bypass a failure. This remains an experimental toolchain build.

## Actual private-namespace test

The static audited `a64_private_netifd_runner.c` creates private mount, network
and PID namespaces, makes mount propagation private, mounts new proc and
read-only sysfs views, binds only null/random/urandom and enters an owned chroot.
Only loopback exists in its network namespace. Its sixty-second deadline kills
the namespace's init; normal init exit also removes its remaining children.

The root contains synthetic network/passwd/group files, native ubusd/ubus,
the exact netifd dependency closure and an ARM32 shell for scripts. It contains
no live network configuration, credentials, physical interface or MTD device.
The configured address is the synthetic127.0.0.2/8 on loopback. All IPC uses
the fixture's explicitly named Unix socket.

Native netifd brought the interface up, reported its address over ubus,
processed down, and restored up/address. The parent network namespace, real
netifd PID, LAN/WAN addresses and routes remained identical; MTD guards and
NPU faults0 remained intact. Fixture and launcher were removed afterwards.
Evidence: `logs/soft-netifd-namespace-20261026-170649/result.json`.

Earlier fixture failures identified a missing socket alias and missing synthetic
passwd/group data. The actual ubusd source requires getpwuid/getgrgid to accept
a peer. Those test inputs were corrected; authentication was not disabled and
no operator account/password file was copied into the chroot.

This qualifies the exercised native static-IP/netlink/ubus lifecycle in a
private namespace. It does not qualify DHCP, PPPoE, Wi-Fi scripts, the complete
native networking service, routed NPU offload or cross-zone hardware isolation.
The running firmware still uses its existing ARM32 system netifd. Normal APK
integration and a separately qualified image are future work.
