#!/bin/sh
# SPDX-License-Identifier: MIT
# Isolated guest RAM root only; no WAN, daemon configuration or package scripts.
set -u
PATH=/bin:/usr/bin:/sbin:/usr/sbin
export PATH
dir=/tmp/be6l-standard-workloads-$$
/bin/busybox mkdir "$dir" || exit 2
trap '/bin/busybox rm -rf "$dir"' EXIT HUP INT TERM
failed=0
count=0
run_case() {
    name=$1; shift
    "$@"
    code=$?
    count=$((count+1))
    if test "$code" = 0; then state=PASS; else state=FAIL; failed=$((failed+1)); fi
    printf 'PACKAGE_CASE %s %s status=%d\n' "$name" "$state" "$code"
}
run_case busybox-pipeline /bin/sh -ec 'result=$(printf "3\n1\n2\n" | /bin/busybox sort -n | /bin/busybox awk "{s+=\$1} END {print s}"); test "$result" = 6'
run_case lua-nixio-fp-file-fork /usr/bin/lua /tmp/be6l-standard-package-nixio.lua "$dir"
run_case curl-version /usr/bin/curl --version
printf 'standard-curl-file\n' >"$dir/curl-input"
run_case curl-file-transfer /bin/sh -ec 'test "$(/usr/bin/curl --fail --silent --show-error --max-time 10 file://"$1"/curl-input)" = standard-curl-file' sh "$dir"
printf '{"arch":"aarch64_cortex-a53","value":3.75}\n' >"$dir/input.json"
run_case jsonfilter /bin/sh -ec 'test "$(/usr/bin/jsonfilter -i "$1/input.json" -e "@.arch")" = aarch64_cortex-a53' sh "$dir"
/bin/busybox mkdir "$dir/config"
printf "config test 'sample'\n option number '3.75'\n" >"$dir/config/be6l"
run_case uci-transaction /bin/sh -ec '/sbin/uci -c "$1/config" set be6l.sample.number=4.25; /sbin/uci -c "$1/config" commit be6l; test "$(/sbin/uci -c "$1/config" get be6l.sample.number)" = 4.25' sh "$dir"
run_case ucode-fs-module /usr/bin/ucode -e 'import * as fs from "fs"; let f = fs.open("/tmp/be6l-ucode-fs-test", "w"); if (!f || f.write("ucode-standard-3.75\n") != 20 || !f.close()) exit(1); if (fs.readfile("/tmp/be6l-ucode-fs-test") != "ucode-standard-3.75\n") exit(2); fs.unlink("/tmp/be6l-ucode-fs-test");'
run_case ubus-private-socket /bin/sh -ec '
    socket="$1/ubus.sock"
    /sbin/ubusd -s "$socket" >"$1/ubusd.log" 2>&1 & server=$!
    trap "kill $server 2>/dev/null; wait $server 2>/dev/null" EXIT HUP INT TERM
    for attempt in 1 2 3 4 5; do test -S "$socket" && break; /bin/busybox sleep 1; done
    /bin/ubus -s "$socket" list
    kill "$server"; wait "$server" || :
    trap - EXIT HUP INT TERM
' sh "$dir"
printf 'STANDARD_PACKAGE_WORKLOADS cases=%d failures=%d\n' "$count" "$failed"
test "$failed" = 0
