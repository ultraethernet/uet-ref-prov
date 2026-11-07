#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Configure one side of an isolated, two-VPP IPv4 vfio-user prototype.
set -euo pipefail
if [[ $# != 5 || $EUID != 0 ]]; then
    echo "usage: sudo $0 <a|b> <vppctl> <cli-socket> <uplink-interface> <runtime-directory>" >&2
    exit 2
fi
side=$1
vppctl=$2
cli_socket=$3
uplink=$4
runtime=$5
case "$side" in
    a) local_id=1; peer_id=2 ;;
    b) local_id=2; peer_id=1 ;;
    *) echo 'side must be a or b' >&2; exit 2 ;;
esac
[[ -x "$vppctl" && -S "$cli_socket" ]] || { echo 'vppctl or CLI socket missing' >&2; exit 1; }
mkdir -p "$runtime"
runtime=$(cd "$runtime" && pwd)
segment="uet-vfio-$side"
mac="02:55:45:54:00:0$local_id"
cli() {
    local result
    result=$("$vppctl" -s "$cli_socket" "$@")
    [[ -z "$result" ]] || printf '%s\n' "$result"
    # vppctl can return zero for a CLI error. Retain the diagnostic and stop.
    if [[ "$result" =~ [Ee]rror|[Ff]ailed|[Uu]nknown|[Ii]nvalid|[Aa]lready ]]; then
        return 1
    fi
}
# The launcher prepares ordinary guest Ethernet with vfio-linux-control.sh.
# This script configures only the UET path in a fresh VPP instance.
[[ -f "$runtime/guest-network.sh" ]] || {
    echo 'Linux control network is not prepared' >&2; exit 1;
}
ip link show dev uet-guest >/dev/null
cli set interface state "$uplink" up
cli set interface ip address "$uplink" "198.18.0.$local_id/30"
cli create loopback interface instance 70
cli set interface state loop70 up
cli set interface ip address loop70 "10.99.0.$local_id/32"
cli ip route add "10.99.0.$peer_id/32" via "198.18.0.$peer_id" "$uplink"
cli uet enable
cli uet svm create name "$segment" queue-size 256
# QEMU shares guest RAM with uet_dev; this VPP buffer mapping is independent.
# The DMA broker lives next to the VPP CLI socket in this prototype layout.
vpp_runtime=$(dirname "$cli_socket")
{
    printf 'export UET_NIC_SHIM=vpp\nexport UET_PDS=pds\n'
    printf 'export UET_IFNAME=vpp0\nexport UET_DEV_L2_IFNAME=uet-guest\n'
    printf 'export UET_VPP_SEGMENT=%q\n' "$segment"
    printf 'export UET_VPP_DMA_SOCKET=%q\n' "$vpp_runtime/uet-dma.sock"
    printf 'export UET_VPP_IPV4_ADDR=10.99.0.%s\n' "$local_id"
    printf 'export UET_VPP_MAC_ADDR=%q\nexport UET_VPP_MTU=1500\n' "$mac"
} > "$runtime/device.env"
printf 'Device environment: %s\nGuest network setup: %s\n' \
    "$runtime/device.env" "$runtime/guest-network.sh"
printf 'Peer TCP control address: %s\n' "$([[ $side == a ]] && echo 192.0.2.6 || echo 192.0.2.2)"
printf 'Select the guest GID corresponding to 10.99.0.%s for verbs.\n' "$local_id"
