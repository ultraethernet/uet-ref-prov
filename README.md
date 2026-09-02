
# UEC Reference Provider (libfabric)

This repository provides a reference implementation of the UEC transport
specifications including:
- Semantic Sublayer (SES)
- Packet Delivery Sublayer (PDS) - Reliability and Congestion Management
- Transport Security Sublayer (TSS) - Encryption and Integrity

See SDR4001 and the UEC Libfabric Mapping Specification for additional details.

## Goals

- Reference implementation of the libfabric mapping, semantic, packet delivery, and security layers
- Investigate lower-level interfaces in libfabric (memory management)
- Provide a framework to define Linux kernel interfaces (i.e., netlink)
- Development/integration vehicle for higher level libraries (i.e, xCCL)
- User and kernel mode integration options
- Clarity and feature coverage is more important than performance
- Minimal external dependencies

## Overview

The framework for the UET Reference Provider is layered. The layers include
SES, PDS, TSS, and NIC.

- The SES layer is accessed via UET APIs (see uet_api.h)
- SES interfaces with PDS via SES-PDS APIs (see uet_pds.h)
- PDS interfaces with TSS via PDS-TSS APIs (see uet_sec.h)
- The NIC shim interface is accessed via a set of abstracted APIs (see
uet_nic.h).

The current SES implementation supports a subset of the functionality required
for:
- Sending and receiving untagged messages
- Sending and receiving tagged messages
- Deferred send operations
- RMA write operations
- RMA read operations

This is a work-in-progress and additional functionality will be incrementally
added.

## Status

There are two PDS implementations available which can be selected using
the `UET_PDS` environment variable. The first PDS implementation is a simple
stop-and-go ROD transport that is sufficient to enable development of other
layers. The second PDS implementation is fully featured transport based on the
UET PDS Specification. It supports the RUD, ROD, RUDI, and UUD delivery modes
(see [Delivery Modes](#delivery-modes) below).

There are currently two implementations of the NIC shim interface APIs:
- Raw Ethernet socket
- AF_XDP

Testing is performed using a simple top-level program that performs ping-pong
message data transfer operations between a client and a server (see `uet.c`).

### Delivery Modes

The `pds` backend (`UET_PDS=pds`) supports all four UET PDS delivery modes:

- **RUD** - Reliable Unordered Delivery. The default for unordered operations.
- **ROD** - Reliable Ordered Delivery. Selected when the endpoint is configured
  for message ordering.
- **RUDI** - Reliable Unordered Delivery for Idempotent operations. A
  connectionless mode: no PDC, non-sequential per-packet ids, one response per
  request (no ACK), and all reliability state at the initiator (per-packet RTO).
  Used for idempotent RMA. Selected by setting `UET_FORCE_RUDI=1` on the `rma`
  command and it requires the target memory region to be `IDEMPOTENT_SAFE` as
  well as the peer advertising support for the HPC profile.
- **UUD** - Unreliable Unordered Delivery. A connectionless, best-effort
  single-packet datagram send (no PDC, no ACK, no retransmit - fire and forget).
  Selected by setting `UET_FORCE_UUD=1` on the `uud` command.

RUDI and UUD are only available on the `pds` backend as the `sng` backend rejects
them. Both are exercised by the test harness via the `rudi` and `uud` test
names, and are folded into the `all` sweep on every `pds`-capable configuration
(see `scripts/uet_test.sh`).

### Congestion Control

A partial implementation of UET Network Signal Congestion Control (NSCC), based
on the v0.6 specification, can be found in the `cc` subdirectory. Multi-path
packet delivery is not fully supported.

The CC algorithm can be tested separately with a basic test app, which
simulates multiple senders transmitting to a single receiver. Packets can be
dropped, ECN marked or trimmed. The application measures the throughput
achieved by each sender, to verify that the CC algorithm enables high bandwidth
utilization and fair sharing among the senders. The app runs on a single
machine and does not generate network traffic. The sources are located in the
`cc_sim` subdirectory.

## Preparation

Make sure the proper development libraries/headers are installed:
```
% sudo apt install linux-headers-$(uname -r)
% sudo apt install gcc gcc-multilib clang libbpf-dev libxdp-dev
```

## libfabric

- https://github.com/ofiwg/libfabric/releases

Download and build libfabric in the parent directory. Version v1.20.1 or
later is needed. The directory name needs to be 'libfabric'. The steps
below build libfabric v1.20.1 and use a symlink for the common name.

```
% cd ..
% wget https://github.com/ofiwg/libfabric/releases/download/v1.20.1/libfabric-1.20.1.tar.bz2
% tar -jxvf libfabric-1.20.1.tar.bz2
% ln -s libfabric-1.20.1 libfabric
% cd libfabric
% autoreconf
% ./configure
% make -j
```

## Build and Run

### Strict core diagnostics

The `strict-core` target performs a compile-only check of the project sources
for both the libfabric (`ENABLE_VERBS=0`) and verbs (`ENABLE_VERBS=1`) library
variants:

```sh
make strict-core
```

It promotes implicit function declarations and integer/pointer conversions to
errors. These diagnostics remain suppressed by the normal standalone build for
compatibility with its external libfabric headers. The target does not link or
install additional binaries; it provides an early check for type-incorrect core
code and is also run by the GitHub sanity workflow.

### rawsock

> The `uet` program only has the `rawsock` NIC shim built into it.

```
% make

# server...
% sudo LD_LIBRARY_PATH=../libfabric/src/.libs:. \
       UET_IFNAME=ens4f0np0 \
       ./uet server 192.168.1.2

# client...
% sudo LD_LIBRARY_PATH=../libfabric/src/.libs:. \
       UET_IFNAME=ens4f0np0 \
       ./uet client 192.168.1.1
```

#### Containerized

Run `scripts/build` to build `uet` et al into an OCI (docker) image.  Run
`scripts/run [<flavor>]` to run said image in a container pair, writing
out a .pcap of the packets into the current directory.  The `<flavor>` is
passed to `uet` (and is used to name the .pcap file), and could be e.g.
`tag`, `rma`, or none.

The tools currently require [`buildah`](https://buildah.io/) to build and
[`podman`](https://podman.io/) (and `tcpdump` on host) to run.

### xdp

> The `uet_xdp` program has both `rawsock` and `xdp` built into it and the
> default NIC shim is `xdp`. The `UET_NIC_SHIM` environment variable can be
> used to override the default.

The current XDP implementation performs a copy to/from the XDP umem Tx/Fill
packet buffers. This interface will be enhanced to eliminate the copy.

The eBPF program loaded for the UET XDP interface only picks out packets with
Ethernet protocol number 253. All other packets are sent to the Linux network
stack so traditional L2 traffic (i.e., ARP, SSH, etc) will continue to flow
over the interface.

```
% make xdp

# server...
% sudo LD_LIBRARY_PATH=../libfabric/src/.libs:. \
       UET_IFNAME=ens4f0np0 \
       ./uet_xdp server 192.168.1.2

# client...
% sudo LD_LIBRARY_PATH=../libfabric/src/.libs:. \
       UET_IFNAME=ens4f0np0 \
       ./uet_xdp client 192.168.1.1
```

### vpp

The experimental `vpp` NIC shim connects the existing UET transport to the
out-of-tree VPP host-dataplane plugin and `libuet_vpp_client`. VPP owns packet
I/O, IPv4/IPv6 FIB lookup, multipath, adjacency resolution and interface
output; UET transport termination remains in the `uet_vpp` process.

Build the separate VPP plugin/client contribution first, then build the shim:

```sh
cmake -S vpp-plugin -B build/vpp-plugin \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=/opt/vpp \
  -DVPP_DIR=/opt/vpp/lib/x86_64-linux-gnu/cmake/vpp
cmake --build build/vpp-plugin

make vpp \
  LIBFABRIC=/path/to/libfabric \
  VPP_PLUGIN_BUILD=build/vpp-plugin
```

The dedicated binary defaults to `UET_NIC_SHIM=vpp`. Configure one VPP-owned
application segment per process and provide its name, DMA socket, local IP
address and optional MTU through the variables below. The plugin architecture,
VPP CLI and manual low-level tests are documented in
[`vpp-plugin/README.md`](vpp-plugin/README.md).

### CC Tester

Simulation parameters (link speed, RTT, queue size, drop thresholds etc.) can be set by modifying
the main function located in `cc_sim/sim.c`.

```
% make cc_sim
% ./uet_cc_sim 2
```

Replace `2` with the desired number of senders.

## Environment Variables

- **LD_LIBRARY_PATH** - Needed for dynamic linking to the `libfabric` and `libuet` libraries.
- **UET_IFNAME** - The ifname of the interface to attach to.
- **UET_NIC_SHIM** - [ `rawsock` | `xdp` | `vpp` ] (`vpp` is available in
  the dedicated `make vpp` build).
- **UET_VPP_SEGMENT** - VPP-owned application segment used by the `vpp` shim.
- **UET_VPP_DMA_SOCKET** - Unix socket used to receive the authorized VPP
  buffer-pool mapping.
- **UET_VPP_IPV4_ADDR** / **UET_VPP_IPV6_ADDR** - One or both local addresses
  exposed by the `vpp` shim.
- **UET_VPP_MTU** - IP MTU exposed by the `vpp` shim (default=`1500`).
- **UET_PDS** - [ `sng` | `pds` ] (default=`sng` stop-n-go)
- **UET_PDS_PER_PKT_ACK_ENB** - [ `0` | `1` ] (default=`0`)
- **UET_PDS_ACK_TYPE** - [ `ack` | `ack_cc` | `ack_ccx` ] (default=`ack`)
- **UET_PDS_TX_TIMEOUT** - Time in milliseconds to wait for an ack before retransmitting a Tx packet (default=`5`).
- **UET_PDS_MAX_TX_RETRIES** - Max number of times a Tx packet is retransmitted before failing (default=`5`).
- **UET_NUM_ITERATIONS** - Override the number of message iterations the test app runs (default=`100`). Used to wall-clock-size a run (e.g., long enough to span several TSS key rotations).
- **UET_MSG_SIZE** - Override the message size used by the test app (default=`4096`).
- **UET_FORCE_RUDI** - [ `0` | `1` ] (default=`0`) Force the RUDI (Reliable Unordered Delivery for Idempotent operations) PDS delivery mode for RMA read/write operations.
- **UET_FORCE_UUD** - [ `0` | `1` ] (default=`0`) Force the UUD (Unreliable Unordered Delivery) best-effort single-packet datagram PDS delivery mode for an untagged send.
- **UET_SEC_MODE** - [ `direct` | `cluster` | `server` ]
- **UET_SEC_SSI** - The SSI to be used for crypto operations. This value must be unique for all instances of `uet`. If not set the source IP address will be used instead as the source identifier.
- **UET_SEC_CLIENT_SSI** - If set, the client SSI to be used by the server side of the session. This is only valid for the `UET_SEC_MODE=server` configuration.
- **UET_SEC_SERVER** - Marks this instance as the *server* side of a `UET_SEC_MODE=server` session. **Set automatically by the application** via `setenv()` when it starts as the server (not the client), so it is not normally set by the user. When set, the instance stamps the peer's SSI (`UET_SEC_CLIENT_SSI`) into the security header instead of its own `UET_SEC_SSI`; when unset the instance acts as a client and uses its own `UET_SEC_SSI`. Only meaningful for `UET_SEC_MODE=server`.
- **UET_SEC_KEY_ROTATION** - [ `0` | `1` ] (default=`0`) Enable AN key rotation for TSS (an SDME stand-in test). Both peers rotate keys off the shared wall clock, so no key exchange is needed. Not supported in `server` mode. See [Key Rotation](#key-rotation).
- **UET_PDS_PSN_METHOD** - [ `0rtt` | `1rtt` ] (default=`0rtt`) Secure PDC establishment method. For 0-RTT the target accepts a start PSN at or above the per-SDI expected PSN, so the common case establishes with no extra round trip. For 1-RTT the target mints a random start PSN and returns it in a NACK, costing one round trip. The method is per-FEP and it only governs how that FEP validates an incoming SYN. The two peers may run different methods and still interoperate. Only applies when `UET_SEC_MODE` is set.
- **UET_NEW_PDC_TIME** - (default=`1000`) Milliseconds a target holds a half-open (pending) secure PDC before reaping it when the initiator never re-drives the establishment with the assigned start PSN. Should be set well above the network RTT so normal establishment never trips it.
- **UET_PDC_CLOSE_THRESH** - Randomly close a PDC after message Tx EOM (100=1% chance to close, default=0).
- **UET_PKT_DROP_THRESH** - Randomly drop a Tx packet before sending (100=1% chance to drop, default=0). Ignored when `UET_IMPAIRMENT_SHIM` is set.
- **UET_IMPAIRMENT_SHIM** - Path to a TOML configuration file that enables the impairment shim. See [Impairment Shim](#impairment-shim) below.

## Security

UET communications can be secured using the TSS protocol which results in all
packets sent by PDS to be encrypted. All four modes of operation defined by
TSS are supported and environment variables are used to select/configure
the mode.

At this stage of the implementation, only a single static Secure Domain (SD)
is provisioned with a fixed set of cryptographic keys. No key exchange is
supported. Automatic rekeying is enabled using the counter (TSC) field in the
packet security header. AN key rotation is available as a test feature
(`UET_SEC_KEY_ROTATION`), see [Key Rotation](#key-rotation) below.

- Direct mode
    - `UET_SEC_MODE=direct`
    - If `UET_SEC_SSI` is set, the SSI will be used in the IV. When set, the value must be unique across all instances of `uet`.
- Cluster mode
    - `UET_SEC_MODE=cluster`
    - If `UET_SEC_SSI` is set, the SSI will be used in the KDF and IV. When set, the value must be unique across all instances of `uet`. If not set, the source IP address will be used instead.
- Server mode
    - server: `UET_SEC_SSI=1 UET_SEC_MODE=server UET_SEC_CLIENT_SSI=2`
    - client: `UET_SEC_SSI=2 UET_SEC_MODE=server`
    - At this time, server mode requires that SSIs be used.

Example for `direct` mode without SSIs:
```
# server...
% sudo LD_LIBRARY_PATH=../libfabric/src/.libs:. \
       UET_IFNAME=ens4f0np0 \
       UET_SEC_MODE=direct \
       ./uet server 192.168.1.2

# client...
% sudo LD_LIBRARY_PATH=../libfabric/src/.libs:. \
       UET_IFNAME=ens4f0np0 \
       UET_SEC_MODE=direct \
       ./uet client 192.168.1.1
```

Example for `cluster` mode using SSIs:
```
# server...
% sudo LD_LIBRARY_PATH=../libfabric/src/.libs:. \
       UET_IFNAME=ens4f0np0 \
       UET_SEC_MODE=cluster \
       UET_SEC_SSI=1 \
       ./uet server 192.168.1.2

# client...
% sudo LD_LIBRARY_PATH=../libfabric/src/.libs:. \
       UET_IFNAME=ens4f0np0 \
       UET_SEC_MODE=cluster \
       UET_SEC_SSI=2 \
       ./uet client 192.168.1.1
```

Example for `server` mode:
```
# server...
% sudo LD_LIBRARY_PATH=../libfabric/src/.libs:. \
       UET_IFNAME=ens4f0np0 \
       UET_SEC_MODE=server \
       UET_SEC_SSI=1 \
       UET_SEC_CLIENT_SSI=2 \
       ./uet server 192.168.1.2

# client...
% sudo LD_LIBRARY_PATH=../libfabric/src/.libs:. \
       UET_IFNAME=ens4f0np0 \
       UET_SEC_MODE=server \
       UET_SEC_SSI=2 \
       ./uet client 192.168.1.1
```

### Key Rotation

Setting `UET_SEC_KEY_ROTATION=1` enables AN (Association Number) key
rotation, a test stand-in for the out-of-band, SDME-driven rotation of a
real deployment. Both peers rotate through a compiled-in pool of keys on
a fixed interval derived from the absolute wall clock, so they stay
synchronized without any key exchange or signaling (the peers must be
NTP-synced). Per the TSS spec, each rotation resets the security counter
and epoch and a fresh per-rotation key preserves IV uniqueness across the
reset. Rotation is not supported in `server` mode.

Because a rotation spans several seconds, a meaningful test must run long enough
to cross several rotations — use `UET_NUM_ITERATIONS` to size the run. Example
(cluster mode with rotation, on both server and client):

```
       UET_SEC_MODE=cluster
       UET_SEC_KEY_ROTATION=1
       UET_NUM_ITERATIONS=800
```

### Crypto

Standalone implementations of the cryptographic algorithms are provided for
the security layer. This includes implementations of AES, AES-GCM, CMAC,
and the KDF. Source code can be found under the `crypto` directory.
Verification tests are provided for each of the algorithms and where
applicable, the set of respective NIST test vectors have been included
into the test application. Do the following to build and run these tests:

```
% cd crypto/tests
% make
% ./crypto_test
```

## XDP

Use `UET_NIC_SHIM=xdp` to send/receive packets over XDP.

Make sure the underlying NIC interface (i.e., `UET_IFNAME`) uses only a single
queue. The current XDP implementation does not yet support multiple sockets.

```
% sudo ethtool -L ens4f0np0 combined 1
```

Use `xdp-loader` to check if an XDP program is loaded and attached to the
interface. If the UET application was killed ungracefully, the XDP program
could remain attached. Use `xdp-loader` to unload any XDP programs.

```
% sudo xdp-loader status
% sudo xdp-loader unload --all ens4f0np0
```

## Impairment Shim

The impairment shim (`imp_shim`) is a Tx queuing module that sits between the
PDS/TSS and NIC shim layers. It supports random packet dropping and random
packet delaying to enable testing of out-of-order packet processing with RUD.
When enabled, packets arriving at the peer will be received out-of-order and/or
require retransmission.

The impairment shim is enabled by setting the `UET_IMPAIRMENT_SHIM` environment
variable to the path of a TOML configuration file. A sample configuration file
is provided at `imp_shim/imp_shim.toml`.

The TOML configuration file contains a `[config]` section with the following
variables:

- **`num_paths`** - Number of Tx queues managed by the impairment shim. Packets are distributed across queues randomly. The transmit thread services each queue in round-robin order, pulling from the front of the queue.
- **`drop_rate`** - Rate at which packets are randomly dropped. The value is in hundredths of a percent (0.01% granularity). For example, 100=1% drop chance.
- **`delay_max`** - Maximum random delay assigned to a packet, in nanoseconds. Each packet receives a uniformly random delay between 0 and `delay_max`. A packet will only be transmitted when it reaches the front of its Tx queue and the current time is greater than or equal to its calculated transmit time.

Note that only the `uet_pds.c` module can use the impairment shim (`UET_PDS=pds`).

When the impairment shim is enabled, the `UET_PKT_DROP_THRESH` environment
variable is ignored as the impairment shim provides its own drop mechanism via
the TOML configuration.

## Contributing

Code changes, fixes, enhancements, etc are encouraged and greatly welcome!

Please submit a
[pull request](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests)
to be reviewed before being merged into the master branch.

The source code in this repo follows the Linux kernel coding style. Before
submitting changes, please run the modified files using the Linux kernel
`checkpatch.pl` script:
- All ERRORs must be fixed.
- All WARNINGs should be fixed if possible (use discretion).
- https://docs.kernel.org/dev-tools/checkpatch.html
- https://raw.githubusercontent.com/torvalds/linux/master/scripts/checkpatch.pl

Running `checkpatch.pl` out of tree against a local `.h` or `.c` file:
```
% ~/checkpatch.pl --no-tree -f uet_api.h
```

Thank you! 😀
