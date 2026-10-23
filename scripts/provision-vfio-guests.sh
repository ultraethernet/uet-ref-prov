#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
if [[ $# != 1 ]]; then echo "usage: $0 <lab-directory>" >&2; exit 2; fi
lab=$(cd "$1" && pwd)
key="$lab/runtime/guest_key"
for side in a b; do
    if [[ "$side" == a ]]; then port=22271; else port=22272; fi
    options=(-i "$key" -o BatchMode=yes -o ConnectTimeout=5
        -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$lab/runtime/known_hosts")
    guest=(ssh "${options[@]}" -p "$port" uet@127.0.0.1)
    "${guest[@]}" 'cloud-init status --wait || test "$?" = 2'
    scp "${options[@]}" -P "$port" "$lab/runtime/guest-payload.tar.gz" uet@127.0.0.1:/home/uet/
    "${guest[@]}" 'mkdir -p /home/uet/uet &&
        tar -xzf /home/uet/guest-payload.tar.gz -C /home/uet/uet &&
        uname -r &&
        env LD_LIBRARY_PATH=/home/uet/uet/lib ldd /home/uet/uet/bin/ibv_ru_pingpong &&
        modinfo /home/uet/uet/uet_ref.ko | head -8'
done
