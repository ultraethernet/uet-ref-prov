# UET vfio-user device model with a VPP packet backend

This example exposes the reference UET transport to two KVM guests through
QEMU vfio-user and the `uet_ref` kernel/userspace drivers. Prerequisites are
the VPP NIC shim (#157), VPP Verbs library (#162), and independent provider
ring-credit fix (#168).

## Architecture

```text
Guest verbs application -> libibverbs / libuet_ref-rdmav<N>.so
  -> uet_ref.ko -> virtual PCI function / QEMU vfio-user
Host uet_dev_vpp -> libuet_verbs_vpp.so (reference SES/PDS/TSS)
  -> VPP NIC shim / libuet_vpp_client
  -> SSVM descriptors + mapped VPP packet buffers
  -> UET plugin -> VPP routing -> physical Ethernet or local memif
```

UET transport state, segmentation, completions, timers and retransmissions
remain in the device-model process. VPP provides packet routing and I/O.
Guest RAM is mapped by the model; VPP buffers are mapped separately and the
shim copies packets between them. This is not a native VPP libibverbs provider
or UET transport termination inside VPP, and it does not use UPROT.

Ordinary guest Ethernet has its own Linux control path:

```text
Guest uet_ref netdev -> PCIe L2 rings -> uet_dev AF_PACKET / uet-guest
  -> uet-gw veth peer -> Linux routing -> uet-ctrl veth -> peer namespace
  -> peer Linux gateway / model / guest netdev
```

`scripts/vfio-linux-control.sh` creates this local inter-namespace network.
`UET_DEV_L2_IFNAME=uet-guest` selects the model's L2 endpoint independently of
the logical VPP shim name `UET_IFNAME=vpp0`. No VPP TAP is needed. The guest
retains a route to the peer GID through its `uet_ref` netdev for AH creation.
Management SSH uses a separate virtio/slirp interface.

The model retains its main vfio-user thread and one progress thread, which
also polls the guest L2 path. Each VPP instance in this example has one worker.
Adding VPP workers does not partition reference transport state. The default
progress pause remains 100 microseconds per sweep.

## Prerequisites and layout

Use an x86-64 Linux host with KVM, QEMU exposing `vfio-user-pci`, a compatible
VPP SDK/runtime, and the UET kernel and rdma-core branches. A stock kernel and
rdma-core do not provide the required UET interfaces yet. See
[the device-model prerequisites](../uet_vfio/README.md#the-kernel).

The scripts expect an absolute `LAB` path with this private layout:

```text
$LAB/src/                    this source checkout
$LAB/deps/linux/             UET Linux tree
$LAB/deps/rdma-core/         UET rdma-core tree
$LAB/deps/libfabric/         libfabric source tree
$LAB/deps/libvfio-user/      libvfio-user source tree
$LAB/deps/vpp-install/      VPP installation with SDK and runtime
$LAB/images/ubuntu-26.04-amd64.qcow2
$LAB/runtime/               generated guest keys, overlays and sockets
$LAB/logs/                  validation output
```

Tested dependency revisions and results are in
[VFIO_VALIDATION.md](VFIO_VALIDATION.md). These are reference versions, not
general minimum-version requirements. VPP buffer/handoff APIs vary by SDK.

Host tools include a C/C++ toolchain, Make, Meson/Ninja, CMake 3.24+, libnl and
libudev development files, Python 3, OpenSSH, cloud-image-utils, iproute2 and
ethtool. Physical verification uses tcpdump. Build the VPP native RDMA plugin
with rdma-core/libibverbs and mlx5 development libraries for physical mlx5 I/O.

## Build and provision

After obtaining the dependencies and an Ubuntu amd64 cloud image:

```sh
mkdir -p "$LAB/runtime" "$LAB/logs"
bash "$LAB/src/scripts/build-vfio-guest-kernel.sh" "$LAB/deps/linux" 16
bash "$LAB/src/scripts/build-vfio-host.sh" "$LAB/deps" "$LAB/deps/vpp-install" 12
python3 "$LAB/src/scripts/prepare-vfio-guests.py" "$LAB"
bash "$LAB/src/scripts/package-vfio-guest.sh" "$LAB"
sudo "$LAB/src/scripts/boot-vfio-guest.sh" "$LAB" a
sudo "$LAB/src/scripts/boot-vfio-guest.sh" "$LAB" b
bash "$LAB/src/scripts/provision-vfio-guests.sh" "$LAB"
sudo "$LAB/src/scripts/vfio-vpp-lab.sh" stop "$LAB" "$LAB/deps/vpp-install"
```

The kernel helper builds a guest kernel/module without installing a host
kernel. Preparation creates a private SSH key, cloud-init seeds and qcow2
overlays. Provisioning copies the provider, module and examples into the
management-only guests; the final command shuts those guests down.

After building the plugin/client, the model can also be built directly:

```sh
make -C "$LAB/src" dev-vpp \
  LIBFABRIC="$LAB/deps/libfabric" LIBVFIO_USER="$LAB/deps/libvfio-user" \
  VPP_PLUGIN_BUILD="$LAB/src/build/vpp-plugin"
```

This creates `uet_dev_vpp` linked to `libuet_verbs_vpp.so`. `make dev` continues
to build the direct raw-socket model. `UET_VPP_MAC_ADDR` optionally supplies
the guest identity. Model startup reports a missing or unusable L2 endpoint.

## Start and validate

The launcher defaults to local memif between VPP instances. Physical mode
uses two dedicated back-to-back mlx5 ports, with no configured global
addresses or bridge/bond master. Set `PORT_A` and `PORT_B` to those netdevs:

```sh
sudo env UET_LAB_LINK=rdma \
  UET_LAB_PORT_A="${PORT_A:?set a dedicated mlx5 interface}" \
  UET_LAB_PORT_B="${PORT_B:?set its back-to-back peer}" UET_LAB_TRACE=0 \
  "$LAB/src/scripts/vfio-vpp-lab.sh" start "$LAB" "$LAB/deps/vpp-install"
```

Each physical netdev is temporarily moved to a private namespace (`uetvf-a`
or `uetvf-b`), retaining `mlx5_core`. The VPP RDMA plugin uses raw Ethernet
packet I/O; the NIC does not implement the UET transport here. VPP receives
NUMA-local main/worker CPU assignments.

| Identity | Side A | Side B |
| --- | --- | --- |
| Guest control address | 192.0.2.2/30 | 192.0.2.6/30 |
| Linux gateway, uet-gw | 192.0.2.1/30 | 192.0.2.5/30 |
| Linux interconnect, uet-ctrl | 198.19.0.1/30 | 198.19.0.2/30 |
| UET/GID address | 10.99.0.1/32 | 10.99.0.2/32 |
| VPP physical uplink address | 198.18.0.1/30 | 198.18.0.2/30 |
| SSH on host loopback | port 22271 | port 22272 |

Run the official examples through `libuet_ref.so`:

```sh
bash "$LAB/src/scripts/validate-vfio-guests.sh" "$LAB"
UET_ACCEPTANCE_SUITE=scatter bash "$LAB/src/scripts/validate-vfio-guests.sh" "$LAB"
UET_ACCEPTANCE_SUITE=events bash "$LAB/src/scripts/validate-vfio-guests.sh" "$LAB"
```

Basic cases cover SEND/RECV and extended RMA at 64 and 4096 bytes; the other
suites cover four-entry scatter/gather and event delivery. TCP exchanges
parameters over the Linux control addresses; verbs use the UET GIDs.
Results are saved under `$LAB/logs/acceptance-*`.

For event mode, the UET `ru_pingpong.c` example at the recorded revision needs
its initial `ibv_req_notify_cq()` call before receive posting/address exchange.
A peer can otherwise deliver a CQE before that arm and leave the example
waiting. Apply that separate example fix in rdma-core before packaging guest
binaries for the event tests. This PR does not modify rdma-core.

In physical mode, with UET applications idle, verify the Linux control path:

```sh
sudo "$LAB/src/scripts/validate-vfio-linux-control.sh" "$LAB" "$LAB/logs/control-check"
```

This checks routes, runs 20 ping round trips in each direction, captures the
80 ICMP packets, checks for UET packets in that control capture, and records
physical packet-counter deltas.

## Cleanup and limits

```sh
sudo "$LAB/src/scripts/vfio-vpp-lab.sh" stop "$LAB" "$LAB/deps/vpp-install"
```

Cleanup stops this example's guests/models/VPP instances, moves selected ports
back to the root namespace and restores their administrative state, then
removes the private namespaces. Run `stop` after a partially failed start as
well. Guest disks, keys and logs remain in the private working area.

This example connects two guests on one host; multiple hosts need a Linux
control uplink. Current functional validation covers IPv4 native UET on the
physical link. IPv6, security and transport scaling were not validated through
this frontend. Payload copies remain; functional checks do not establish
line-rate performance.
