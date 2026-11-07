#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Omit the device socket for initial management-only cloud-init provisioning.
set -euo pipefail
if [[ $# -lt 2 || $# -gt 3 || $EUID != 0 ]]; then
    echo "usage: sudo $0 <lab-directory> <a|b> [vfio-user-device-socket]" >&2
    exit 2
fi
lab=$(cd "$1" && pwd)
side=$2
case "$side" in
    a) number=1; port=22271 ;;
    b) number=2; port=22272 ;;
    *) exit 2 ;;
esac
directory="$lab/runtime/$side"
if [[ -f "$directory/qemu.pid" ]] && kill -0 "$(cat "$directory/qemu.pid")" 2>/dev/null; then
    echo "guest $side is already running" >&2
    exit 1
fi
device=()
if [[ $# == 3 ]]; then
    [[ -S "$3" ]] || { echo "missing device socket: $3" >&2; exit 1; }
    device=(-device "{\"driver\":\"vfio-user-pci\",\"socket\":{\"type\":\"unix\",\"path\":\"$3\"}}")
fi
qemu-system-x86_64 -enable-kvm -cpu host -m 4G -smp 2 -display none \
    -serial "file:$directory/console.log" \
    -monitor "unix:$directory/monitor.sock,server=on,wait=off" \
    -daemonize -pidfile "$directory/qemu.pid" \
    -kernel "$lab/deps/linux/out-vfio/arch/x86/boot/bzImage" \
    -append 'root=/dev/vda1 rw console=ttyS0 net.ifnames=0' \
    -object memory-backend-memfd,id=mem0,size=4G,share=on \
    -machine memory-backend=mem0 \
    -drive "file=$directory/guest.qcow2,if=virtio,format=qcow2" \
    -drive "file=$directory/seed.img,if=virtio,format=raw" \
    -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$port-:22" \
    -device "virtio-net-pci,netdev=n0,mac=52:54:00:55:00:0$number" \
    "${device[@]}"
echo "guest $side: QEMU PID $(cat "$directory/qemu.pid"), SSH port $port"
