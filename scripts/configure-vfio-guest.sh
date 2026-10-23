#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Execute inside the guest after copying the runtime payload to /home/uet/uet.
set -euo pipefail
if [[ $# != 1 || $EUID != 0 ]]; then echo "usage: sudo $0 <a|b>" >&2; exit 2; fi
side=$1
case "$side" in
    a) control=192.0.2.2; gateway=192.0.2.1; peer=192.0.2.4/30
       data=10.99.0.1; peer_data=10.99.0.2; suffix=0a63:0001 ;;
    b) control=192.0.2.6; gateway=192.0.2.5; peer=192.0.2.0/30
       data=10.99.0.2; peer_data=10.99.0.1; suffix=0a63:0002 ;;
    *) exit 2 ;;
esac
if ! grep -q '^uet_ref ' /proc/modules; then insmod /home/uet/uet/uet_ref.ko; fi
for ((attempt=0; attempt<100; attempt++)); do
    [[ -d /sys/class/infiniband/uet_ref0 ]] && break
    sleep .1
done
[[ -d /sys/class/infiniband/uet_ref0 ]] || { dmesg | tail -40; exit 1; }
netdevs=(/sys/class/infiniband/uet_ref0/device/net/*)
[[ -d "${netdevs[0]}" ]] || { echo 'UET netdev missing' >&2; exit 1; }
netdev=$(basename "${netdevs[0]}")
ip link set dev "$netdev" up
ip address replace "$control/30" dev "$netdev"
ip address replace "$data/32" dev "$netdev"
ip route replace "$peer" via "$gateway" dev "$netdev"
# Kernel AH creation resolves the peer GID through this netdev.
ip route del "$data/32" via "$gateway" dev "$netdev" 2>/dev/null || true
ip route replace "$peer_data/32" via "$gateway" dev "$netdev"
gid_index=
for ((attempt=0; attempt<100; attempt++)); do
    for path in /sys/class/infiniband/uet_ref0/ports/1/gids/*; do
        if [[ "$(cat "$path")" == *"$suffix" ]]; then gid_index=$(basename "$path"); break; fi
    done
    [[ -n "$gid_index" ]] && break
    sleep .1
done
[[ -n "$gid_index" ]] || { echo "GID for $data not registered" >&2; exit 1; }
printf '%s\n' "$gid_index" > /home/uet/uet/gid-index
chmod 644 /home/uet/uet/gid-index
ip -br address show dev "$netdev"
env LD_LIBRARY_PATH=/home/uet/uet/lib LD_PRELOAD=/home/uet/uet/lib/libuet_ref.so \
    /home/uet/uet/bin/ibv_devinfo -d uet_ref0
printf 'UET GID index: %s\n' "$gid_index"
