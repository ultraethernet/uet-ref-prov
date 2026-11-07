#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
if [[ $# != 1 ]]; then echo "usage: $0 <lab-directory>" >&2; exit 2; fi
lab=$(cd "$1" && pwd)
payload="$lab/runtime/guest-payload"
mkdir -p "$payload/lib" "$payload/bin"
cp -a "$lab/deps/rdma-core/build/lib/." "$payload/lib/"
for binary in ibv_devinfo ibv_ru_pingpong ibv_ru_rma; do
    cp "$lab/deps/rdma-core/build/bin/$binary" "$payload/bin/"
done
cp -a "$lab/src/uet_vfio/provider/"libuet_ref*.so "$payload/lib/"
cp "$lab/src/uet_vfio/kmod/uet_ref.ko" "$payload/"
tar -czf "$lab/runtime/guest-payload.tar.gz" -C "$payload" .
printf 'Guest payload: %s/runtime/guest-payload.tar.gz\n' "$lab"
