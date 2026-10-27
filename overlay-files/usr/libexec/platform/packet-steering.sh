#!/bin/sh
# SPDX-License-Identifier: MIT
# Standard netifd policy plus BE6L DSA receive-hash placement.
# This is CPU steering, not routed PPE support.
set -eu
policy="${1:-1}"
case "$policy" in 0|1|2) ;; *) exit 2 ;; esac
flows="$(uci -q get network.@globals[0].steering_flows || true)"
case "$flows" in ''|*[!0-9]*) flows=0 ;; esac
if [ "$flows" -gt 0 ]; then
	/usr/libexec/network/packet-steering.uc -l "$flows" "$policy"
else
	/usr/libexec/network/packet-steering.uc "$policy"
fi
[ "$(cat /tmp/sysinfo/board_name)" = tenda,be6l-pro ] || exit 0
[ "$policy" = 2 ] || exit 0
[ "$(cat /sys/devices/system/cpu/online)" = 0-1 ] || exit 0
parent="$(cat /sys/class/net/eth0/ifindex)"
for dev in lan2 lan3 lan4; do
	[ "$(cat /sys/class/net/$dev/iflink)" = "$parent" ] || exit 0
done
# DSA has not decoded the switch protocol at the conduit RPS boundary.
# Its L2 hash would otherwise be retained by every LAN user port.
for path in /sys/class/net/eth0/queues/rx-*/rps_cpus; do
	[ ! -w "$path" ] || printf '%s' 0 > "$path"
done
for dev in eth1 lan2 lan3 lan4; do
	for path in /sys/class/net/$dev/queues/rx-*/rps_cpus; do
		[ ! -w "$path" ] || printf '%s' 3 > "$path"
	done
done
