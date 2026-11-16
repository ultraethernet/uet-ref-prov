#!/bin/sh
# SPDX-License-Identifier: MIT
# Run from the repository root. Optional: CC=clang TSAN=1 BUILD_DIR=/tmp/...
set -eu
build_dir=${BUILD_DIR:-$(mktemp -d /tmp/uet-msg-id-test.XXXXXX)}
mkdir -p "$build_dir"
test_flags=
if [ "${TSAN:-0}" = 1 ]; then
    test_flags='-fsanitize=thread -fno-omit-frame-pointer -g'
fi
for verbs in 0 1; do
    # Intentional word splitting for compiler/test flags.
    ${CC:-cc} -std=gnu2x -O2 -UNDEBUG $test_flags -DENABLE_VERBS="$verbs" \
        -ffunction-sections -fdata-sections -Wl,--gc-sections -pthread \
        -Wno-unused-variable -Wno-unused-function \
        -Wno-implicit-function-declaration -Wno-int-conversion \
        -Wno-address-of-packed-member \
        -I. -Iutil -Inic_shim -Iimp_shim -Icrypto \
        -Ilibfabric_headers -Ilibfabric_headers/include \
        tests/msg_id_concurrency.c -o "$build_dir/msg-id-$verbs"
    "$build_dir/msg-id-$verbs"
done
