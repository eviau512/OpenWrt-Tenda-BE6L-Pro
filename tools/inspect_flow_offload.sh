#!/bin/sh
# SPDX-License-Identifier: MIT
# Read-only evidence. A requested offload flag is not a hardware success result.
set -eu
test "$(cat /tmp/sysinfo/board_name)" = tenda,be6l-pro
grep -q '^tmpfs / tmpfs ' /proc/mounts
count=0
for d in /sys/class/mtd/mtd[0-9]; do
    test "$(cat "$d/flags")" = 0x0
    count=$((count+1))
done
test "$count" = 10
printf '%s\n' 'PROTECTED_RAM=1' 'GLOBAL_COUNTERS_ARE_NOT_PER_FLOW_STATS=1'
printf '%s\n' 'SECTION_REQUESTED_OFFLOAD'
for key in flow_offloading flow_offloading_hw; do
    printf '%s=' "$key"
    uci -q get "firewall.@defaults[0].$key" || echo unset
done
printf '%s\n' 'SECTION_FLOWTABLE'
nft list flowtable inet fw4 ft 2>/dev/null || true
printf '%s\n' 'SECTION_NPU'
cat /sys/kernel/debug/1e900000.npu/status
printf '%s\n' 'SECTION_BINDINGS'
cat /sys/kernel/debug/ppe/bind
printf '%s\n' 'SECTION_CPU'
head -n 3 /proc/stat
printf '%s\n' 'SECTION_IRQ'
cat /proc/interrupts
printf '%s\n' 'SECTION_SOFTIRQ'
cat /proc/softirqs
printf '%s\n' 'SECTION_SOFTNET'
cat /proc/net/softnet_stat
printf '%s\n' 'SECTION_NETDEV'
cat /proc/net/dev
printf '%s\n' 'SECTION_RPS'
for dev in eth0 eth1; do
    for path in /sys/class/net/$dev/queues/rx-*/rps_cpus; do
        test ! -r "$path" || { printf '%s=' "$path"; cat "$path"; }
    done
done
printf '%s\n' 'READ_ONLY_SNAPSHOT_COMPLETE'
