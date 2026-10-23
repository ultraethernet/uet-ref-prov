#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Verify real guest traffic on the Linux inter-namespace control link.
set -euo pipefail
if [[ $# != 2 || $EUID != 0 ]]; then
    echo "usage: sudo $0 <lab-directory> <output-directory>" >&2
    exit 2
fi
lab=$(cd "$1" && pwd)
mkdir -p "$2"
logs=$(cd "$2" && pwd)
source "$lab/runtime/physical-state.env"
options=(-i "$lab/runtime/guest_key" -o BatchMode=yes -o ConnectTimeout=5
    -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$lab/runtime/known_hosts")
snapshot() {
    local phase=$1 side port
    for side in a b; do
        if [[ "$side" == a ]]; then port=$physical_port_a; else port=$physical_port_b; fi
        ip -n "uetvf-$side" -j -s link show dev uet-ctrl > "$logs/control-$side-$phase.json"
        ip netns exec "uetvf-$side" ethtool -S "$port" > "$logs/physical-$side-$phase.txt"
    done
}
for side in a b; do
    if [[ "$side" == a ]]; then peer_guest=192.0.2.6; else peer_guest=192.0.2.2; fi
    route=$(ip -n "uetvf-$side" route get "$peer_guest")
    printf '%s: %s\n' "$side" "$route" >> "$logs/routes.txt"
    [[ "$route" == *'dev uet-ctrl '* ]] || { echo 'control route bypasses uet-ctrl' >&2; exit 1; }
done
capture_pid=
stop_capture() {
    if [[ -n "$capture_pid" ]]; then
        kill -INT "$capture_pid" 2>/dev/null || true
        wait "$capture_pid" || true
        capture_pid=
    fi
}
trap stop_capture EXIT
ip netns exec uetvf-a tcpdump --immediate-mode -n -U -s 96 -i uet-ctrl -w "$logs/control.pcap" ip \
    > "$logs/tcpdump.log" 2>&1 &
capture_pid=$!
for ((attempt=0; attempt<50; attempt++)); do
    if grep -q 'listening on' "$logs/tcpdump.log"; then break; fi
    kill -0 "$capture_pid"
    sleep .1
done
grep -q 'listening on' "$logs/tcpdump.log"
snapshot before
ssh "${options[@]}" -p 22271 uet@127.0.0.1 'sudo ping -n -i .05 -c 20 -W 2 192.0.2.6' \
    > "$logs/ping-a.log"
ssh "${options[@]}" -p 22272 uet@127.0.0.1 'sudo ping -n -i .05 -c 20 -W 2 192.0.2.2' \
    > "$logs/ping-b.log"
snapshot after
stop_capture
tcpdump -nn -r "$logs/control.pcap" icmp > "$logs/control-icmp.txt" 2> "$logs/read-pcap.log"
tcpdump -nn -r "$logs/control.pcap" 'ip proto 253 or udp port 49150' \
    > "$logs/unexpected-uet.txt" 2>> "$logs/read-pcap.log"
[[ ! -s "$logs/unexpected-uet.txt" ]] || {
    echo 'UET packets on the Linux control link' >&2; exit 1;
}
python3 - "$logs" <<'PY'
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
result = {}
for side in ('a', 'b'):
    values = {}
    for phase in ('before', 'after'):
        control = json.loads((root / f'control-{side}-{phase}.json').read_text())[0]['stats64']
        physical = {}
        for line in (root / f'physical-{side}-{phase}.txt').read_text().splitlines():
            if ':' not in line:
                continue
            key, value = line.strip().split(':', 1)
            if value.strip().isdigit():
                physical[key] = int(value)
        values[phase] = {'control_rx': control['rx']['packets'],
                         'control_tx': control['tx']['packets'],
                         **{key: physical[key] for key in ('rx_packets_phy', 'tx_packets_phy')}}
    delta = {key: values['after'][key] - values['before'][key] for key in values['before']}
    assert delta['control_rx'] >= 40 and delta['control_tx'] >= 40, delta
    result[side] = delta
result['icmp_packets_captured'] = len((root / 'control-icmp.txt').read_text().splitlines())
assert result['icmp_packets_captured'] == 80, result
result['uet_packets_captured'] = 0
(root / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
PY
