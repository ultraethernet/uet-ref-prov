#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ $# -ne 4 || $EUID -ne 0 ]]; then
	echo "usage: sudo $0 <vpp-prefix> <rdma-core-source> <plugin-build-dir> <uet-ref-provider-dir>" >&2
	exit 2
fi

test_uid=${SUDO_UID:-0}
test_gid=${SUDO_GID:-0}
vpp_user=()
app_user=()
if (( test_uid != 0 )); then
	vpp_user=(setpriv --reuid="$test_uid" --regid="$test_gid" --init-groups
		--inh-caps=+net_raw,+ipc_lock,+sys_nice
		--ambient-caps=+net_raw,+ipc_lock,+sys_nice)
	app_user=(setpriv --reuid="$test_uid" --regid="$test_gid" --init-groups)
fi

vpp_prefix=$(cd "$1" && pwd)
rdma_source=$(cd "$2" && pwd)
plugin_build=$(cd "$3" && pwd)
provider_dir=$(cd "$4" && pwd)
rdma_build=${RDMA_BUILD:-$rdma_source/build}
vpp="$vpp_prefix/bin/vpp"
vppctl="$vpp_prefix/bin/vppctl"
test_name=${UET_VERBS_TEST:-ibv_ru_pingpong}
case "$test_name" in
	ibv_ru_pingpong|ibv_ru_rma) ;;
	*) echo "unsupported UET_VERBS_TEST: $test_name" >&2; exit 2 ;;
esac
test_app="$rdma_build/bin/$test_name"
uprot_module="$rdma_source/providers/uprot/kmod/rdma_uprot.ko"
plugin_dir="$plugin_build/lib/vpp_plugins"
vpp_lib_dir=$(dirname "$(find "$vpp_prefix/lib" -maxdepth 2 \
	-name libvppinfra.so -print -quit)")
runtime=$(mktemp -d /tmp/uet-vpp-uprot.XXXXXX)

suffix=$$
ns_a="uet-uprot-a-$suffix"
ns_b="uet-uprot-b-$suffix"
data_a="uvda$suffix"
data_b="uvdb$suffix"
ctrl_a="uvca$suffix"
ctrl_b="uvcb$suffix"
rdma_a="uprota$suffix"
rdma_b="uprotb$suffix"
segment_a="uet-uprot-a-$suffix"
segment_b="uet-uprot-b-$suffix"
vpp_pid_a=
vpp_pid_b=
server_pid=
loaded_module=0

cleanup()
{
	for pid in "$server_pid" "$vpp_pid_a" "$vpp_pid_b"; do
		if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
			kill "$pid" 2>/dev/null || true
			wait "$pid" 2>/dev/null || true
		fi
	done
	ip netns delete "$ns_a" 2>/dev/null || true
	ip netns delete "$ns_b" 2>/dev/null || true
	if (( loaded_module )); then
		rmmod rdma_uprot 2>/dev/null || true
	fi
	echo "logs: $runtime"
}
trap cleanup EXIT

for file in "$vpp" "$vppctl" "$test_app" "$uprot_module" \
	"$rdma_build/lib/libibverbs.so" \
	"$rdma_build/lib/libuprot-rdmav57.so" \
	"$plugin_dir/uet_plugin.so" \
	"$plugin_build/lib/libuet_vpp_client.so" \
	"$provider_dir/libuet_verbs_vpp.so"; do
	[[ -e "$file" ]] || {
		echo "missing required file: $file" >&2
		exit 1
	}
done

if ! grep -q '^rdma_uprot ' /proc/modules; then
	insmod "$uprot_module"
	loaded_module=1
fi

mkdir -p "$runtime/a" "$runtime/b"
cat >"$runtime/vpp-a.conf" <<EOF
unix { nodaemon runtime-dir $runtime/a cli-listen $runtime/a/cli.sock log $runtime/vpp-a.log }
api-segment { prefix uet-uprot-a-$suffix }
statseg { socket-name $runtime/a/stats.sock }
cpu { workers 1 }
plugins { add-path $plugin_dir plugin uet_plugin.so { enable } }
EOF
cat >"$runtime/vpp-b.conf" <<EOF
unix { nodaemon runtime-dir $runtime/b cli-listen $runtime/b/cli.sock log $runtime/vpp-b.log }
api-segment { prefix uet-uprot-b-$suffix }
statseg { socket-name $runtime/b/stats.sock }
cpu { workers 1 }
plugins { add-path $plugin_dir plugin uet_plugin.so { enable } }
EOF
if (( test_uid != 0 )); then
	chown -R "$test_uid:$test_gid" "$runtime"
fi

ip netns add "$ns_a"
ip netns add "$ns_b"
ip link add "$data_a" type veth peer name "$data_b"
ip link set "$data_a" netns "$ns_a"
ip link set "$data_b" netns "$ns_b"
ip -n "$ns_a" link set "$data_a" name uet-data
ip -n "$ns_b" link set "$data_b" name uet-data
ip link add "$ctrl_a" type veth peer name "$ctrl_b"
ip link set "$ctrl_a" netns "$ns_a"
ip link set "$ctrl_b" netns "$ns_b"
ip -n "$ns_a" link set "$ctrl_a" name uet-control
ip -n "$ns_b" link set "$ctrl_b" name uet-control
for ns in "$ns_a" "$ns_b"; do
	ip -n "$ns" link set lo up
	ip -n "$ns" link set uet-data up
	ip -n "$ns" link set uet-control up
done
ip -n "$ns_a" address add 198.18.0.1/30 dev uet-control
ip -n "$ns_b" address add 198.18.0.2/30 dev uet-control
ip netns exec "$ns_a" rdma link add "$rdma_a" type uprot netdev uet-control
ip netns exec "$ns_b" rdma link add "$rdma_b" type uprot netdev uet-control

vpp_ld="$vpp_lib_dir:$vpp_prefix/lib"
ip netns exec "$ns_a" "${vpp_user[@]}" env LD_LIBRARY_PATH="$vpp_ld" \
	"$vpp" -c "$runtime/vpp-a.conf" >"$runtime/vpp-a.stdout" 2>&1 &
vpp_pid_a=$!
ip netns exec "$ns_b" "${vpp_user[@]}" env LD_LIBRARY_PATH="$vpp_ld" \
	"$vpp" -c "$runtime/vpp-b.conf" >"$runtime/vpp-b.stdout" 2>&1 &
vpp_pid_b=$!

wait_for_vpp()
{
	local pid=$1 socket=$2 output=$3
	for _ in $(seq 1 200); do
		[[ -S "$socket" ]] && return 0
		kill -0 "$pid" 2>/dev/null || {
			cat "$output" >&2
			return 1
		}
		sleep 0.05
	done
	echo "timed out waiting for $socket" >&2
	return 1
}
wait_for_vpp "$vpp_pid_a" "$runtime/a/cli.sock" "$runtime/vpp-a.stdout"
wait_for_vpp "$vpp_pid_b" "$runtime/b/cli.sock" "$runtime/vpp-b.stdout"
cli_a=("$vppctl" -s "$runtime/a/cli.sock")
cli_b=("$vppctl" -s "$runtime/b/cli.sock")
"${cli_a[@]}" create host-interface name uet-data
"${cli_b[@]}" create host-interface name uet-data
"${cli_a[@]}" set interface state host-uet-data up
"${cli_b[@]}" set interface state host-uet-data up
"${cli_a[@]}" set interface ip address host-uet-data 198.18.0.1/30
"${cli_b[@]}" set interface ip address host-uet-data 198.18.0.2/30
"${cli_a[@]}" uet enable
"${cli_b[@]}" uet enable
"${cli_a[@]}" uet svm create name "$segment_a" queue-size 256
"${cli_b[@]}" uet svm create name "$segment_b" queue-size 256

app_ld="$rdma_build/lib:$provider_dir:$plugin_build/lib:$vpp_lib_dir:$vpp_prefix/lib"
run_verbs_test()
{
	local ns=$1 device=$2 segment=$3 dma_socket=$4 local_ip=$5
	shift 5
	ip netns exec "$ns" "${app_user[@]}" env IBV_DRIVERS=uprot \
		LD_LIBRARY_PATH="$app_ld" UET_NIC_SHIM=vpp \
		UET_VPP_SEGMENT="$segment" UET_VPP_DMA_SOCKET="$dma_socket" \
		UET_VPP_IPV4_ADDR="$local_ip" timeout 60s \
		"$test_app" -d "$device" -g 1 -n 100 -s 64 "$@"
}

ip netns exec "$ns_a" rdma link show >"$runtime/rdma-a.log"
ip netns exec "$ns_b" rdma link show >"$runtime/rdma-b.log"
run_verbs_test "$ns_a" "$rdma_a" "$segment_a" \
	"$runtime/a/uet-dma.sock" 198.18.0.1 >"$runtime/server.log" 2>&1 &
server_pid=$!
sleep 1
kill -0 "$server_pid" 2>/dev/null || {
	cat "$runtime/server.log" >&2
	exit 1
}

set +e
run_verbs_test "$ns_b" "$rdma_b" "$segment_b" \
	"$runtime/b/uet-dma.sock" 198.18.0.2 198.18.0.1 \
	>"$runtime/client.log" 2>&1
client_status=$?
if (( client_status == 0 )); then
	wait "$server_pid"
	server_status=$?
else
	server_status=1
fi
server_pid=
set -e

if (( client_status != 0 || server_status != 0 )); then
	echo "$test_name failed: client=$client_status server=$server_status" >&2
	cat "$runtime/server.log" "$runtime/client.log" >&2
	"${cli_a[@]}" show uet >&2 || true
	"${cli_b[@]}" show uet >&2 || true
	exit 1
fi

cat "$runtime/rdma-a.log" "$runtime/rdma-b.log"
cat "$runtime/server.log" "$runtime/client.log"
"${cli_a[@]}" show uet
"${cli_b[@]}" show uet
echo "UET VPP AF_PACKET $test_name test passed"
