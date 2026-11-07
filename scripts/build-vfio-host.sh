#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Host/userspace build for a private vfio-user/VPP evaluation directory.
set -euo pipefail
if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "usage: $0 <dependency-directory> <VPP-prefix> [jobs]" >&2
    exit 2
fi
deps=$(cd "$1" && pwd)
vpp_prefix=$(cd "$2" && pwd)
jobs=${3:-8}
source_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$deps/libvfio-user"
meson setup build --buildtype=release
ninja -C build -j"$jobs" lib/libvfio-user.so.0.0.1
cd "$deps/libfabric"
./autogen.sh
./configure --enable-only --enable-sockets --disable-silent-rules
make -j"$jobs"
cd "$source_root"
vpp_cmake=$(find "$vpp_prefix/lib" -name VPPConfig.cmake -print -quit)
[[ -n "$vpp_cmake" ]] || { echo 'VPP SDK config missing' >&2; exit 1; }
cmake --fresh -S vpp-plugin -B build/vpp-plugin \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$vpp_prefix" \
    -DVPP_DIR="$(dirname "$vpp_cmake")"
cmake --build build/vpp-plugin --parallel "$jobs" --target uet_plugin uet_vpp_client
vpp_lib=$(find "$vpp_prefix/lib" -name libvppinfra.so -print -quit)
[[ -n "$vpp_lib" ]] || { echo 'VPP runtime library missing' >&2; exit 1; }
make -j"$jobs" dev-vpp LIBFABRIC="$deps/libfabric" \
    LIBVFIO_USER="$deps/libvfio-user" VPP_PLUGIN_BUILD="$source_root/build/vpp-plugin" \
    LDFLAGS="-lpthread -Wl,-rpath-link,$(dirname "$vpp_lib")"
cmake -S "$deps/rdma-core" -B "$deps/rdma-core/build" \
    -DIN_PLACE=1 -DNO_MAN_PAGES=1 -DNO_PYVERBS=1
cmake --build "$deps/rdma-core/build" --parallel "$jobs"
make -C uet_vfio/provider RDMA_BUILD="$deps/rdma-core/build" -j"$jobs"
