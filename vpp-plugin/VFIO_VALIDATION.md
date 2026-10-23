# vfio-user/VPP functional validation

Validated on 23 October 2026 with the new `uet_ref` driver/provider and
QEMU vfio-user. The tested source combines current `main` (`9effe362`),
the VPP prerequisites #157/#162, the provider credit fix #168, and this
device-model integration.

## Environment

| Component | Validated revision / configuration |
| --- | --- |
| Execution host | x86-64 Linux, KVM, two ConnectX-5 Ex Ethernet ports connected back to back |
| QEMU | 10.2.1, `vfio-user-pci`, two guests with 2 vCPUs and 4 GiB each |
| Linux UET, `insanum/linux-rdma`, `uet-ib-core` | `ce72dd2ad1fef115c7b15bdc6fd4734a5c845f7e` |
| rdma-core UET, `insanum/rdma-core`, `uet-v2` | `8db37d9b02fac926ddd099ba7c05fac66f0e243a` |
| VPP | `795347cb5ee1c13ba4a8e6ce5fa1f0e783682e5a` |
| libvfio-user | `803924493a7c787b2ba358751f55f07d5dba64b2` |
| libfabric | 1.20.1, `e43589a5113ad3db0a18a6a1a02b6e6f4ee317d6` |
| Physical I/O | VPP native RDMA plugin, mlx5dv, one RX queue and one VPP worker per endpoint |
| Link | 100 Gb/s negotiated, NIC MTU 1500, UET payload MTU 1024 |
| Model | `-O2 -g`, tracing disabled, original 100-microsecond progress pause |

The guest runs `uet_ref.ko` and the out-of-tree `libuet_ref` provider. The
model links the VPP-backed reference Verbs library. VPP routes native IPv4
UET packets over the physical link. The reference SES/PDS/TSS transport runs
in the model, without UET transport offload in the NIC or VPP workers.

The model and provider were rebuilt from this branch. Prepared guest images,
the recorded guest kernel/module and the compatible VPP plugin/client build
were reused for the functional runs.

## Functional matrix

The branch was built and the three suites in
[`GETTING_STARTED_VFIO.md`](GETTING_STARTED_VFIO.md#start-and-validate)
were run with full data checks, 100 iterations per case:

| Case | Result |
| --- | --- |
| SEND/RECV, 64 bytes | server/client exit 0 |
| SEND/RECV, 4096 bytes | server/client exit 0 |
| Extended RMA read/write, 64 bytes | server/client exit 0 |
| Extended RMA read/write, 4096 bytes | server/client exit 0 |
| SEND/RECV, 4096 bytes, 4 SGEs | server/client exit 0 |
| RMA, 4096 bytes, 4 SGEs | server/client exit 0 |
| SEND/RECV, 64 bytes, events | server/client exit 0 |
| RMA, 64 bytes, events | server/client exit 0 |

For the event cases, `ru_pingpong.c` in the recorded rdma-core revision has a
separate local correction: move the initial `ibv_req_notify_cq()` call before
receive posting and address exchange. This avoids waiting on a completion
that arrived before notification was armed. That dependency change is outside
this device-model PR.

## Linux control network

Both model netdevs use AF_PACKET endpoints on `uet-guest`, paired with Linux
gateways. The two namespaces are connected locally by `uet-ctrl`; VPP has no
guest TAP. Guest GID routes remain on the `uet_ref` netdevs for AH creation.

With the verbs applications idle, the control validator ran 20 ping round
trips in each direction:

- all 40 round trips passed;
- the inter-namespace capture contained 80 ICMP packets;
- each endpoint's interconnect counters increased by at least 40 RX and 40 TX
  packets; and
- no native UET or UET/UDP packet was present in that control capture.

Two control checks were observed. The first had zero physical packet-counter
increments. The repeat recorded one physical A-to-B frame and one additional
packet on the Linux interconnect; neither was classified by these counters.
The physical counters cover all port traffic. Both checks captured the full
80 ICMP packets on the local control link and passed the routing checks.

## Limits and cleanup

These are functional checks. They do not establish line-rate performance.
The polling/performance tuning used in separate prototype measurements is
outside this PR. IPv6, security and transport scaling have not been validated
through this vfio-user frontend.

After validation, the example was stopped, its private namespaces were removed,
and the selected physical ports were returned to their original namespace,
MAC, MTU and administrative state. The host management interface was preserved.
Private VM keys, disks and full machine-specific logs are not part of this PR.
