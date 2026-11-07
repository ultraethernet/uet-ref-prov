#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build a guest-only kernel; never install it or change the host boot setup.
set -euo pipefail
if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "usage: $0 <UET-patched-linux-tree> [jobs]" >&2
    exit 2
fi
kernel=$(cd "$1" && pwd)
jobs=${2:-16}
source_root=$(cd "$(dirname "$0")/.." && pwd)
out="$kernel/out-vfio"
make -C "$kernel" O="$out" x86_64_defconfig
config=("$kernel/scripts/config" --file "$out/.config")
for option in SMP MODULES MODULE_UNLOAD PCI PCI_MSI NET INET IPV6 \
    UNIX PACKET VIRTIO_PCI VIRTIO_BLK VIRTIO_NET VIRTIO_CONSOLE \
    EXT4_FS DEVTMPFS DEVTMPFS_MOUNT TMPFS TMPFS_POSIX_ACL \
    ISO9660_FS NLS_ISO8859_1 SERIAL_8250 SERIAL_8250_CONSOLE \
    INFINIBAND INFINIBAND_USER_ACCESS INFINIBAND_ADDR_TRANS RDMA_RXE \
    CGROUPS CGROUP_SCHED CGROUP_PIDS CGROUP_BPF SECCOMP SECCOMP_FILTER; do
    "${config[@]}" --enable "$option"
done
"${config[@]}" --disable DEBUG_INFO --disable DEBUG_INFO_BTF \
    --disable LOCALVERSION_AUTO --disable SYSTEM_TRUSTED_KEYS \
    --set-str LOCALVERSION '-uet-vpp'
make -C "$kernel" O="$out" olddefconfig
make -C "$kernel" O="$out" -j"$jobs" bzImage modules
make -C "$source_root/uet_vfio/kmod" KERNELDIR="$out" -j"$jobs"
printf 'Guest kernel: %s/arch/x86/boot/bzImage\n' "$out"
make -s -C "$kernel" O="$out" kernelrelease
