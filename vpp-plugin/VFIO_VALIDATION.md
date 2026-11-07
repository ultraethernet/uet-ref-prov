# vfio-user/VPP functional validation

The functional matrix passed on 23 October and again on 7 November 2026
with the new `uet_ref` driver/provider and QEMU vfio-user. The October tree combined
the then-current `main` (`9effe362`), the VPP changes tracked in PRs #157 and
#162, the provider ring-credit correction tracked in PR #168, and this
device-model integration.

## Rebase and build checks (7 November 2026)

The branch now starts at `main` commit `5b4e049`, which includes the merged
VPP shim, software endpoint indices and PDC shutdown updates. Remaining
prerequisites are the Verbs/VPP library in PR #162 and the provider
ring-credit correction in PR #170 (replacement for PR #168).

On Linux/ARM64 (Ubuntu 26.04.1, kernel 6.8.0-106, GCC 15.2), the refreshed
library-only branch and combined device-model branch both pass `make all`,
`make strict-core` and `make vpp-verbs`. The combined branch also passes
`make dev` and `make dev-vpp`. The client library was compiled from the
branch against an existing VPP SDK with `libsvm`/`libvppinfra` ABI 24.10;
this is a compilation check, not a VPP plugin or runtime compatibility test.
Libfabric 1.20.1 and libvfio-user `8039244` were rebuilt for these checks.
The standalone ring-consumer regression passes on Linux/ARM64 and macOS/ARM64.
ELF inspection confirms that only the VPP transport library acquires a
`libuet_vpp_client.so` dependency; the default Verbs library does not.

## Physical revalidation (7 November 2026)

The published integration tree `1af09b0` was exported and rebuilt on the
x86-64 KVM host using the dependency revisions in the table below. Both
that tree and the standalone PR #162 library commit `5f5da25` pass
`make all`, `make strict-core` and `make vpp-verbs`. The integration tree
also passes `make dev` and `make dev-vpp`. Its VPP plugin, client library,
reference transport, model and userspace provider were rebuilt. The guest
kernel/module and images were reused. The standalone ring-consumer
regression passes on x86-64 as well.

All eight full-data-checked guest cases pass with 100 iterations each and
the default 100-microsecond progress pause, with tracing disabled. The
control check captures all 80 ICMP packets and zero UET packets on the local
Linux link. Each endpoint records exactly 40 RX and 40 TX packets there;
physical RX and TX packet-counter deltas are zero during the control check.

Both VPP endpoints finish with zero invalid requests, TX-completion-ring-full
errors, RX-ring-full errors, invalid RX releases and outstanding RX buffers.
Afterward, an audit verifies restoration of all four physical ports' MAC,
MTU, flags and addresses, the management interface, and the namespace list.
The wrapper completes with exit status 0.

This rerun validates the source changes on top of the merged PDC shutdown
updates. The documentation-only follow-up records these results without
changing the tested implementation.

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

The model and provider were rebuilt for both validations. Prepared guest
images and the recorded guest kernel/module were reused. October reused
the compatible VPP plugin/client build; November rebuilt both from the
published integration tree.

## Functional matrix

The branch was built and the three suites in
[`GETTING_STARTED_VFIO.md`](GETTING_STARTED_VFIO.md#start-and-validate)
were run with full data checks, 100 iterations per case, on both dates:

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

Two control checks were observed on 23 October. The first had zero physical packet-counter
increments. The repeat recorded one physical A-to-B frame and one additional
packet on the Linux interconnect; neither was classified by these counters.
The physical counters cover all port traffic. Both checks captured the full
80 ICMP packets on the local control link and passed the routing checks.
The 7 November control rerun records zero physical RX/TX packet increments
on both sides and exactly 40 RX/40 TX packets per side on the local link.

## Limits and cleanup

These are functional checks. They do not establish line-rate performance.
The polling/performance tuning used in separate prototype measurements is
outside this PR. IPv6, security and transport scaling have not been validated
through this vfio-user frontend.

After validation, the example was stopped, its private namespaces were removed,
and the selected physical ports were returned to their original namespace,
MAC, MTU and administrative state. The host management interface was preserved.
Private VM keys, disks and full machine-specific logs are not part of this PR.
