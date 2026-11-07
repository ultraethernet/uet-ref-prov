#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Common ordinary-Ethernet network for both vfio-user transport backends.
# Run after creating the lab's two namespaces, before starting the models.
set -euo pipefail
if [[ $# != 3 || $EUID != 0 ]]; then
    echo "usage: sudo $0 <lab-directory> <guest-mac-a> <guest-mac-b>" >&2
    exit 2
fi
lab=$(cd "$1" && pwd)
mac_a=$2
mac_b=$3
for mac in "$mac_a" "$mac_b"; do
    [[ "$mac" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]] || exit 2
done
for side in a b; do
    ip -n "uetvf-$side" link show lo >/dev/null
    for interface in uet-guest uet-gw uet-ctrl; do
        if ip -n "uetvf-$side" link show "$interface" >/dev/null 2>&1; then
            echo "uetvf-$side already contains $interface; stop the lab first" >&2
            exit 1
        fi
    done
done
# Control traffic stays on this host, independently of the physical UET link.
ip link add uet-ctrl netns uetvf-a type veth peer name uet-ctrl netns uetvf-b
for side in a b; do
    if [[ "$side" == a ]]; then
        id=1; peer=2; mac=$mac_a
        gateway=192.0.2.1; guest=192.0.2.2; peer_control=192.0.2.4/30
    else
        id=2; peer=1; mac=$mac_b
        gateway=192.0.2.5; guest=192.0.2.6; peer_control=192.0.2.0/30
    fi
    ns="uetvf-$side"
    ip -n "$ns" link add uet-guest type veth peer name uet-gw
    # The AF_PACKET endpoint represents the guest; Linux routes on its peer.
    ip -n "$ns" link set dev uet-guest address "$mac" up
    ip -n "$ns" link set dev uet-gw address "02:55:43:54:00:0$id" up
    ip -n "$ns" address add "$gateway/30" dev uet-gw
    ip -n "$ns" neigh replace "$guest" lladdr "$mac" nud permanent dev uet-gw
    ip -n "$ns" link set dev uet-ctrl address "02:55:43:55:00:0$id" up
    ip -n "$ns" address add "198.19.0.$id/30" dev uet-ctrl
    ip -n "$ns" route add "$peer_control" via "198.19.0.$peer" dev uet-ctrl
    ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
    # GID routes in the guest are also needed for address-handle creation.
    cat > "$lab/runtime/$side/guest-network.sh" <<GUEST
#!/usr/bin/env bash
set -euo pipefail
if [[ \$# != 1 ]]; then echo 'usage: sudo guest-network.sh <uet_ref netdev>' >&2; exit 2; fi
ip link set dev "\$1" up
ip address replace $guest/30 dev "\$1"
ip address replace 10.99.0.$id/32 dev "\$1"
ip route replace $peer_control via $gateway dev "\$1"
ip route replace 10.99.0.$peer/32 via $gateway dev "\$1"
GUEST
    chmod +x "$lab/runtime/$side/guest-network.sh"
done
