#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Start private VPP instances, namespaces, device models and KVM guests.
# Optional RDMA mode moves two dedicated mlx5 netdevs into the namespaces.
set -euo pipefail
if [[ $# != 3 || $EUID != 0 ]]; then
    echo "usage: sudo $0 <start|stop|status> <lab-directory> <VPP-prefix>" >&2
    exit 2
fi
action=$1
link_kind=${UET_LAB_LINK:-memif}
lab=$(cd "$2" && pwd)
prefix=$(cd "$3" && pwd)
source_root="$lab/src"
model_binary=${UET_LAB_MODEL:-$source_root/uet_dev_vpp}
runtime="$lab/runtime"
mkdir -p "$runtime"
vpp_lib=$(find "$prefix/lib" -name libvppinfra.so -print -quit)
vpp_lib=$(dirname "$vpp_lib")
ldpath="$source_root:$source_root/build/vpp-plugin/lib:$lab/deps/libfabric/src/.libs"
ldpath+=":$lab/deps/libvfio-user/build/lib:$vpp_lib:$prefix/lib"
namespace() { printf 'uetvf-%s' "$1"; }
wait_socket() {
    local path=$1 pid=$2
    for ((attempt=0; attempt<200; attempt++)); do
        [[ -S "$path" ]] && return 0
        kill -0 "$pid" 2>/dev/null || return 1
        sleep .1
    done
    return 1
}
stop_pid() {
    local file=$1 expected=$2 pid
    [[ -f "$file" ]] || return 0
    pid=$(cat "$file")
    [[ -r /proc/$pid/cmdline ]] || return 0
    # Only act on the recorded task process, even if a PID has been reused.
    if tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Fq -- "$expected"; then
        kill "$pid" 2>/dev/null || true
        for ((attempt=0; attempt<30; attempt++)); do
            kill -0 "$pid" 2>/dev/null || return 0
            sleep .1
        done
        kill -KILL "$pid" 2>/dev/null || true
    fi
}
case "$action" in
status)
    for side in a b; do
        printf '\nSIDE %s\n' "$side"
        for name in vpp model qemu; do
            file="$runtime/$side/$name.pid"
            if [[ -f "$file" ]]; then ps -p "$(cat "$file")" -o pid,etime,args || true; fi
        done
    done
    exit 0
    ;;
stop)
    # Guests first. Models block in libvfio-user and may need SIGKILL after
    # their guest disconnects; those SVM segments are discarded with VPP.
    for side in a b; do
        if [[ "$side" == a ]]; then port=22271; else port=22272; fi
        if [[ -f "$runtime/$side/qemu.pid" ]]; then
            ssh -i "$runtime/guest_key" -o BatchMode=yes -o ConnectTimeout=2 \
                -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$runtime/known_hosts" \
                -p "$port" uet@127.0.0.1 'sudo poweroff' 2>/dev/null || true
            for ((attempt=0; attempt<50; attempt++)); do
                kill -0 "$(cat "$runtime/$side/qemu.pid" 2>/dev/null)" 2>/dev/null || break
                sleep .1
            done
        fi
        stop_pid "$runtime/$side/qemu.pid" "$runtime/$side/guest.qcow2"
    done
    for side in a b; do stop_pid "$runtime/$side/model.pid" "$runtime/$side/device.sock"; done
    for side in a b; do
        if [[ -S "$runtime/$side/cli.sock" ]]; then
            env LD_LIBRARY_PATH="$ldpath" "$prefix/bin/vppctl" \
                -s "$runtime/$side/cli.sock" uet svm delete name "uet-vfio-$side" || true
        fi
    done
    for side in a b; do stop_pid "$runtime/$side/vpp.pid" "$runtime/$side/vpp.conf"; done
    if [[ -f "$runtime/physical-state.env" ]]; then
        source "$runtime/physical-state.env"
        for side in a b; do
            if [[ "$side" == a ]]; then port=$physical_port_a; was_up=$physical_up_a;
            else port=$physical_port_b; was_up=$physical_up_b; fi
            ns=$(namespace "$side")
            if ip -n "$ns" link show dev "$port" >/dev/null 2>&1; then
                ip -n "$ns" link set dev "$port" down
                ip -n "$ns" link set dev "$port" netns 1
            fi
            if [[ -e /sys/class/net/$port ]]; then
                if [[ "$was_up" == 1 ]]; then ip link set dev "$port" up;
                else ip link set dev "$port" down; fi
            fi
        done
        mv "$runtime/physical-state.env" "$runtime/physical-last-state.env"
    fi
    for side in a b; do ip netns delete "$(namespace "$side")" 2>/dev/null || true; done
    if [[ -S "$runtime/uplink.sock" ]]; then unlink "$runtime/uplink.sock"; fi
    exit 0
    ;;
start) ;;
*) echo 'expected start, stop or status' >&2; exit 2 ;;
esac
for side in a b; do
    if ip netns list | awk '{print $1}' | grep -qx "$(namespace "$side")"; then
        echo "namespace $(namespace "$side") already exists; stop the lab first" >&2
        exit 1
    fi
done
for file in "$model_binary" "$source_root/build/vpp-plugin/lib/vpp_plugins/uet_plugin.so" \
    "$lab/deps/linux/out-vfio/arch/x86/boot/bzImage" \
    "$runtime/a/guest.qcow2" "$runtime/b/seed.img"; do
    [[ -f "$file" ]] || { echo "missing $file" >&2; exit 1; }
done
[[ -x "$model_binary" ]] || { echo "model is not executable: $model_binary" >&2; exit 1; }
model_env=(env -u UET_DEV_TRACE LD_LIBRARY_PATH="$ldpath")
case "${UET_LAB_TRACE:-1}" in
1) model_env+=(UET_DEV_TRACE=1) ;;
0) ;;
*) echo 'UET_LAB_TRACE must be 0 or 1' >&2; exit 2 ;;
esac
case "$link_kind" in
memif) transport_plugin=memif_plugin.so ;;
rdma)
    transport_plugin=rdma_plugin.so
    physical_port_a=${UET_LAB_PORT_A:?set UET_LAB_PORT_A}
    physical_port_b=${UET_LAB_PORT_B:?set UET_LAB_PORT_B}
    [[ "$physical_port_a" != "$physical_port_b" ]] || { echo 'ports must differ' >&2; exit 1; }
    for port in "$physical_port_a" "$physical_port_b"; do
        [[ "$port" =~ ^[a-zA-Z0-9_.:-]+$ && -d /sys/class/net/$port ]] || exit 1
        [[ ! -e /sys/class/net/$port/master ]] || { echo "$port is enslaved" >&2; exit 1; }
        driver=$(basename "$(readlink -f "/sys/class/net/$port/device/driver")")
        [[ "$driver" == mlx5_core ]] || { echo "$port does not use mlx5_core" >&2; exit 1; }
        if ip -o address show dev "$port" scope global | grep -q .; then
            echo "$port has a configured global IP address" >&2; exit 1
        fi
    done
    physical_up_a=$(( $(cat "/sys/class/net/$physical_port_a/flags") & 1 ))
    physical_up_b=$(( $(cat "/sys/class/net/$physical_port_b/flags") & 1 ))
    {
        printf 'physical_port_a=%q\nphysical_port_b=%q\n' "$physical_port_a" "$physical_port_b"
        printf 'physical_up_a=%s\nphysical_up_b=%s\n' "$physical_up_a" "$physical_up_b"
    } > "$runtime/physical-state.env"
    ;;
*) echo 'UET_LAB_LINK must be memif or rdma' >&2; exit 2 ;;
esac
for side in a b; do ip netns add "$(namespace "$side")"; done
"$source_root/scripts/vfio-linux-control.sh" "$lab" 02:55:45:54:00:01 02:55:45:54:00:02
for side in a b; do
    ns=$(namespace "$side")
    directory="$runtime/$side"
    # A socket pathname can survive a previous process. Remove only the lab's
    # stale sockets before readiness checks; namespace ownership was checked.
    for socket in cli.sock device.sock; do
        if [[ -S "$directory/$socket" ]]; then unlink "$directory/$socket"; fi
    done
    ip -n "$ns" link set lo up
    cpu_config='workers 1'
    if [[ "$link_kind" == rdma ]]; then
        if [[ "$side" == a ]]; then port=$physical_port_a; else port=$physical_port_b; fi
        numa=$(cat "/sys/class/net/$port/device/numa_node")
        [[ "$numa" != -1 ]] || numa=0
        mapfile -t cores < <(lscpu -p=CPU,NODE,CORE | awk -F, -v node="$numa" \
            '$1 !~ /^#/ && $2 == node && !seen[$3]++ {print $1; if (++count == 2) exit}')
        [[ ${#cores[@]} == 2 ]] || { echo "not enough CPUs on NUMA $numa" >&2; exit 1; }
        cpu_config="main-core ${cores[0]} corelist-workers ${cores[1]}"
        ip link set dev "$port" netns "$ns"
        ip -n "$ns" link set dev "$port" up
    fi
    cat > "$directory/vpp.conf" <<CONFIG
unix { nodaemon runtime-dir $directory cli-listen $directory/cli.sock log $directory/vpp.log }
api-segment { prefix uet-vfio-$side }
statseg { socket-name $directory/stats.sock }
cpu { $cpu_config }
plugins {
  add-path $source_root/build/vpp-plugin/lib/vpp_plugins
  plugin default { disable }
  plugin $transport_plugin { enable }
  plugin uet_plugin.so { enable }
}
CONFIG
    ip netns exec "$ns" env LD_LIBRARY_PATH="$ldpath" \
        "$prefix/bin/vpp" -c "$directory/vpp.conf" > "$directory/vpp.stdout" 2>&1 &
    pid=$!
    echo "$pid" > "$directory/vpp.pid"
    wait_socket "$directory/cli.sock" "$pid" || { cat "$directory/vpp.stdout"; exit 1; }
    cli=(ip netns exec "$ns" env LD_LIBRARY_PATH="$ldpath"
        "$prefix/bin/vppctl" -s "$directory/cli.sock")
    if [[ "$link_kind" == memif ]]; then
        "${cli[@]}" create memif socket id 70 filename "$runtime/uplink.sock"
        if [[ "$side" == a ]]; then role=master; else role=slave; fi
        "${cli[@]}" create interface memif id 0 socket-id 70 "$role"
        uplink=memif70/0
    else
        "${cli[@]}" create interface rdma host-if "$port" name uet-uplink \
            num-rx-queues 1 rx-queue-size 512 tx-queue-size 512 mode auto no-striding
        uplink=uet-uplink
    fi
    ip netns exec "$ns" env LD_LIBRARY_PATH="$ldpath" \
        "$source_root/vpp-plugin/tools/vfio-vpp-configure.sh" "$side" \
        "$prefix/bin/vppctl" "$directory/cli.sock" "$uplink" "$directory"
    # The parent shell reads the generated environment; exec preserves it in
    # the namespace child and the pidfile identifies the actual model.
    set -a
    source "$directory/device.env"
    set +a
    ip netns exec "$ns" "${model_env[@]}" \
        "$model_binary" "$directory/device.sock" > "$directory/model.log" 2>&1 &
    pid=$!
    echo "$pid" > "$directory/model.pid"
    wait_socket "$directory/device.sock" "$pid" || { tail -60 "$directory/model.log"; exit 1; }
    "$source_root/scripts/boot-vfio-guest.sh" "$lab" "$side" "$directory/device.sock"
done
printf 'Guests launched. SSH on 127.0.0.1:22271 and :22272 with user uet and key %s\n' \
    "$runtime/guest_key"
