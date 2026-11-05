# SPDX-License-Identifier: MIT
# Pure state functions, shared by the daemon and offline shell tests.

guard_uint() {
	# Bound arithmetic and reject signs, octal, whitespace and shell syntax.
	case "$1" in ''|*[!0-9]*|0[0-9]*|??????????*) return 1 ;; esac
	return 0
}

guard_range() {
	guard_uint "$1" && [ "$1" -ge "$2" ] && [ "$1" -le "$3" ]
}

guard_config() {
	guard_range "$1" 60 3600 && guard_range "$2" 60 3600 &&
	guard_range "$3" 1 30 && guard_range "$4" 5 30 &&
	[ "$3" -lt "$2" ]
}

guard_accept_heartbeat() {
	# heartbeat boot, time, extra, current boot, now. Never evaluate file data.
	[ "$1" = "$4" ] && [ -z "$3" ] && guard_uint "$2" &&
	[ "$2" -le "$5" ]
}

guard_step() {
	# now, grace-from-boot, disconnect timeout, last trusted heartbeat or -1.
	guard_uint "$1" && guard_range "$2" 60 3600 &&
	guard_range "$3" 60 3600 || return 1
	[ "$4" = -1 ] || { guard_uint "$4" && [ "$4" -le "$1" ]; } || return 1
	GUARD_DEADLINE=$2
	if [ "$4" != -1 ] && [ "$(( $4 + $3 ))" -gt "$GUARD_DEADLINE" ]; then
		GUARD_DEADLINE=$(( $4 + $3 ))
	fi
	GUARD_ACTION=wait
	[ "$1" -lt "$GUARD_DEADLINE" ] || GUARD_ACTION=reboot
}
