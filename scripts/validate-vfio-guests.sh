#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# End-to-end acceptance on the isolated lab created by vfio-vpp-lab.sh.
set -euo pipefail
if [[ $# != 1 ]]; then echo "usage: $0 <lab-directory>" >&2; exit 2; fi
lab=$(cd "$1" && pwd)
options=(-i "$lab/runtime/guest_key" -o BatchMode=yes -o ConnectTimeout=5
    -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$lab/runtime/known_hosts")
logs="${UET_ACCEPTANCE_LOG_ROOT:-$lab/logs}/acceptance-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$logs"
guest() {
    local side=$1 port
    shift
    if [[ "$side" == a ]]; then port=22271; else port=22272; fi
    ssh "${options[@]}" -p "$port" uet@127.0.0.1 "$@"
}
for side in a b; do
    if [[ "$side" == a ]]; then port=22271; else port=22272; fi
    for ((attempt=0; attempt<120; attempt++)); do
        if guest "$side" true 2>/dev/null; then break; fi
        sleep 1
    done
    scp "${options[@]}" -P "$port" "$lab/src/scripts/configure-vfio-guest.sh" \
        uet@127.0.0.1:/home/uet/
    guest "$side" "sudo bash /home/uet/configure-vfio-guest.sh $side" \
        > "$logs/configure-$side.log" 2>&1
    cat "$logs/configure-$side.log"
done
guest a 'ping -c 3 -W 2 192.0.2.6' > "$logs/ping-a.log"
guest b 'ping -c 3 -W 2 192.0.2.2' > "$logs/ping-b.log"
gid_a=$(guest a 'cat /home/uet/uet/gid-index')
gid_b=$(guest b 'cat /home/uet/uet/gid-index')
[[ "$gid_a" =~ ^[0-9]+$ && "$gid_b" =~ ^[0-9]+$ ]] || exit 1
prefix='sudo env LD_LIBRARY_PATH=/home/uet/uet/lib'
prefix+=' LD_PRELOAD=/home/uet/uet/lib/libuet_ref.so timeout 60s /home/uet/uet/bin/'
run_case() {
    local label=$1 app=$2 flags=$3 server_status=0 client_status=0 server_pid
    guest a "$prefix$app -d uet_ref0 -g $gid_a -n 100 $flags" > "$logs/$label-server.log" 2>&1 &
    server_pid=$!
    sleep 1
    guest b "$prefix$app -d uet_ref0 -g $gid_b -n 100 $flags 192.0.2.2" \
        > "$logs/$label-client.log" 2>&1 || client_status=$?
    wait "$server_pid" || server_status=$?
    printf '%s server=%s client=%s\n' "$label" "$server_status" "$client_status" | \
        tee -a "$logs/results.txt"
    if (( server_status != 0 || client_status != 0 )); then
        cat "$logs/$label-server.log" "$logs/$label-client.log" >&2
        return 1
    fi
}
case "${UET_ACCEPTANCE_SUITE:-basic}" in
basic)
    run_case send-recv-64 ibv_ru_pingpong '-s 64 -c'
    run_case send-recv-4096 ibv_ru_pingpong '-s 4096 -c'
    run_case rma-64 ibv_ru_rma '-s 64 -c'
    run_case rma-4096 ibv_ru_rma '-s 4096 -c'
    ;;
events)
    run_case send-recv-events-64 ibv_ru_pingpong '-s 64 -e -c'
    run_case rma-events-64 ibv_ru_rma '-s 64 -e -c'
    ;;
scatter)
    run_case send-recv-sg4 ibv_ru_pingpong '-s 4096 -S 4 -c'
    run_case rma-sg4 ibv_ru_rma '-s 4096 -S 4 -c'
    ;;
*) echo 'UET_ACCEPTANCE_SUITE must be basic, events or scatter' >&2; exit 2 ;;
esac
printf 'Acceptance logs: %s\n' "$logs"
