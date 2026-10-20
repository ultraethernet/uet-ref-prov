# UET VPP plugin

This directory contains an experimental out-of-tree VPP UET host-dataplane
plugin and its external-process client library. The current milestone supports
one VPP main thread and one independent external SPSC channel per VPP worker.
It uses VPP's normal device and interface graphs and has no dependency on a
specific NIC driver. Hardware-specific validation is maintained separately
from the driver-independent plugin sources and tests.

The plugin and `libuet_vpp_client` are self-contained in this directory. The
NIC shim connects the existing UET transport to the client API. Applications
can reach that transport through either the libfabric integration maintained
in the dedicated `uet-libfabric` repository or the experimental UET Verbs
`uprot` provider maintained in `uet-rdma-core`. See the
[`UET Verbs getting-started guide`](GETTING_STARTED_VERBS.md) for an end-to-end
AF_PACKET test.

## Why VPP

The integration has two first-order benefits:

- Independent per-worker queues and lockless SPSC channels provide a natural
  path from one queue/core to a multiqueue, multicore UET dataplane.
- UET becomes observable through the mature VPP operations environment.
  Packet traces show the path and disposition of individual packets; node
  errors and counters identify drops and resource pressure; structured logs
  expose lifecycle and authorization events; `show uet` reports aggregate and
  per-worker state; and the binary API makes the same controls and telemetry
  available to automation.

These facilities are part of the design rather than benchmark-only
instrumentation. They make routing, filtering, queue ownership, saturation,
and client-lifecycle problems diagnosable with the standard VPP CLI, logging,
and tracing workflow.

## Routing and local delivery

RX traffic follows the normal VPP Ethernet and IP graphs. The plugin registers
IP protocol 253 and UDP destination port 49150 with the IPv4 and IPv6 local
dispatch tables. Consequently, the UET nodes are reached only after the FIB
has selected a local/Receive DPO for the destination address:

```text
VPP interface RX -> ethernet-input -> ip4-input/ip6-input -> FIB/local DPO
  -> protocol 253: uet4-ip-input/uet6-ip-input
  -> UDP 49150:   ip4-udp-lookup/ip6-udp-lookup
                  -> uet4-udp-input/uet6-udp-input
```

A packet for a routed destination remains transit traffic even when its IP
protocol or UDP port matches UET. A local UDP packet for another port also
does not enter the plugin.

By default, RX delivery keeps the worker selected by the normal VPP input
graph (`uet rx placement current-worker`). This preserves hardware RSS
placement without adding a cross-worker hop. On a device that cannot include
native UET entropy in its RSS hash, `uet rx placement entropy-handoff`
extracts the native EV, or the UDP source port, after local IP/UDP dispatch and
hands the packet to a stable VPP worker before publishing it to SVM. This mode
is driver-independent and allows different endpoint entropy values to use
different worker channels. The original worker still performs device input
and IP local lookup, so this software handoff is not a substitute for
programmable hardware RSS when line-rate ingress scaling is required.

Client TX starts with a complete IPv4 or IPv6 packet, not an Ethernet frame.
The worker validates the IP length and UET protocol/port, then enqueues the
VLIB buffer to `ip4-lookup` or `ip6-lookup`. `uet tx fib table <table-id>`
overrides the default IPv4 and IPv6 table 0; separate table IDs can be selected
with `ip4-table` and `ip6-table`. The default is installed by `uet enable` when
no explicit selection has already been made. No output interface is accepted
or stored by the plugin. FIB lookup, multipath selection, adjacency rewrite,
neighbor resolution, interface output and the device path remain VPP
responsibilities.

For UET-over-UDP, UE Specification 1.0.3 section 3.5.10.1 requires
`udp.checksum` to be zero on send and ignored on receive, for both IPv4 and
IPv6 encapsulation. The TX worker therefore overwrites that field with zero
and does not request UDP checksum offload. The IPv4 header checksum remains
the packet producer's responsibility (and is updated by the normal VPP IPv4
forwarding path when routing changes the header); IPv6 has no IP header
checksum.

## Threading and process model

The VPP main thread owns configuration, SVM lifecycle, protocol registration,
and node state changes. It uses the VPP worker barrier when changing state.
Each worker owns its rings, buffer ownership, TX completion state, RX release
state, counters, and eventually its UET PDC/timer state. There is no mutex in
the datapath and no SPSC ring is shared between workers.

Each client process owns one named SSVM segment containing one independent
SPSC channel per VPP worker. VPP may host several such application segments at
the same time and polls every active TX channel on its owning worker. One
`libuet_vpp_client` object maps that segment and the common VPP buffer pool
once; datapath calls select a channel index. Each channel has one progress
owner, while different channels can be used concurrently without an internal
datapath mutex. All worker channels currently use the same physical VPP buffer
pool and must be on the same NUMA node.

`libuet_vpp_client_open()` takes a non-blocking exclusive lock on the segment's
SHM object before SSVM attaches. A second opener, whether it is another process
or a second open in the same process, receives `-EBUSY` and cannot overwrite
the active channel owner. The lock and the shared owner PID are released by a
clean close. The kernel releases the lock if the process exits, but the owner
PID deliberately remains set: a later open returns `-EOWNERDEAD`, because
rings and VPP-buffer ownership may have been left in an indeterminate state.
Delete and recreate the SVM segment before attaching a replacement client
after such a crash.
VPP refuses to delete a segment whose owner process is still alive.

Each client registers its endpoints through the segment's low-rate control
rings. The RX lookup key is the local IP version/address, absolute versus
relative addressing mode, JobID for relative addressing, PIDonFEP, and Resource
Index. VPP rejects a key already owned by another process. The provider removes
the key when the endpoint closes; deleting a segment also removes every key
owned by that segment, including after a crashed client. The endpoint-control
API is part of `libuet_vpp_client`; policy for connecting a transport or an
application framework to that API is intentionally outside this plugin PR.

For an initial RUD/ROD SYN, RUDI request, or UUD request, VPP reads the standard
SES destination fields and performs the endpoint lookup. Established PDC
traffic carries the process namespace in the high ten PDCID bits; RUDI
responses carry it in the high ten `pkt_id` bits. These are opaque wire
identifiers, so VPP does not keep per-packet or per-flow steering state. With
only one ready process, the original fast path is retained: no UET parsing is
performed and the RX ring producer is published once per VPP frame.

PDC and RUDI identifier translation is confined to the VPP NIC shim, after the
traditional transport has serialized TX and before it parses RX. The shim
refreshes CRC32C after changing a cleartext identifier. The UET PDS and RUDI
implementations contain no VPP-specific namespace logic.

When several processes are ready, a malformed packet, a packet type without a
supported destination identifier, or a security-encapsulated packet that hides
those identifiers is dropped as ambiguous and increments `rx-ambiguous`; VPP
never guesses a destination segment. Extending demux to encrypted multi-process
traffic requires a visible steering identifier or moving security/transport
termination into VPP.

VPP Session Layer and VCL are intentionally absent. The external application
communicates through SSVM metadata plus shared VPP physmem. The main thread is
sufficient for serialized control only because configuration callbacks run on
that thread and use worker barriers; it is not used to serialize datapath
access.

## Shared ABI 4.2

The ABI is defined in [`uet/svm_abi.h`](uet/svm_abi.h). Structures use fixed
width fields and offsets from a mapping base; process pointers never cross the
boundary. A major version mismatch is rejected. New trailing fields require a
minor version bump.

ABI 4.2 contains the production SPSC dataplane plus a low-rate endpoint control
channel:

- lockless TX and TX-completion rings;
- a lockless RX descriptor ring and RX-release ring;
- a VPP physmem file descriptor passed over a Unix `SOCK_SEQPACKET` socket;
- a provider-ready handshake counted across all workers, which makes DMA
  unmapping safe;
- an exclusive owner PID, backed by a lifetime SHM lock rather than a datapath
  mutex;
- one request/completion SPSC pair per application segment for endpoint add and
  delete operations; and
- a nonzero 10-bit process namespace assigned by VPP; and
- an application mode flag that lets RX demultiplex both real PDS identifiers
  and the endpoint overlay used by the stop-and-go implementation.

The client library serializes endpoint control operations with one mutex. This
does not affect TX, RX, completion, or release rings. VPP worker 0 consumes the
control requests and updates a shared bihash; all workers perform lockless RX
lookups. Namespaces are not reused during a VPP lifetime, preventing delayed
packets from being redirected to a newly created process. Consequently, the
current ABI permits 1023 segment creations before VPP must be restarted.

The VPP NIC shim declares the selected PDS implementation before mapping DMA.
Real PDS continues to use namespaced PDC and RUDI identifiers. SNG keeps its
existing endpoint overlay unchanged; VPP resolves standard requests and ACKs
against the registered endpoint key. `show uet` reports the mode for each
application segment.

The experimental `svm_msg_q` request path, payload verifier and fixed SSVM
payload pool present in ABI 2.x have been removed. SSVM remains responsible
for creating and mapping the channel set; packet data stays in shared VPP
physmem, while SSVM carries only descriptors and the endpoint control channel.

The TX pool starts with one VLIB buffer per shared slot. The client
acquires a slot, writes the IP packet directly into its mapped VLIB data area,
and publishes the descriptor. The worker transfers that buffer to the normal
VPP graph, allocates a replacement VLIB buffer for the shared slot, updates the
slot descriptor, and only then publishes the completion. The client therefore
reuses the slot through its replacement while VPP exclusively owns the
submitted buffer. Buffer lifetime does not depend on an output interface or on
calling a device TX node from the plugin. A successful TX completion means that
the replacement slot is available and the submitted buffer has been accepted
by the VPP graph; it is deliberately not a physical-NIC-transmission
completion.

For RX, VPP publishes the full IP packet as up to eight scatter/gather segments
pointing into the mapped VPP buffer pool. It retains the VLIB buffer chain
until the client publishes a release. The release carries an opaque token;
the worker resolves it through a private table before freeing the chain, so an
external value is never treated directly as a VLIB buffer index. Outstanding
RX ownership is bounded by the configured ring depth. The client library also
tracks the exact token-to-RX-ID association and rejects stale, forged, or
duplicate releases before publishing them.

### DMA mapping trust boundary

The Unix-socket filesystem permissions are the first authorization boundary.
Before passing the physmem file descriptor, the plugin also reads the
kernel-supplied `SO_PEERCRED` identity and requires the peer PID to match
exactly one exclusive owner PID among the ready SSVM segments. The client must therefore
attach its SSVM segment before requesting the DMA mapping. A process that
merely knows the socket path receives `-EACCES` without an `SCM_RIGHTS`
descriptor; accepted and rejected attempts are visible in `show uet`.

An authorized client is still a trusted dataplane process. RX queues can
allocate from VPP's default NUMA buffer pool, and the current VPP device API
does not let this out-of-tree plugin select a private pool for those queues.
Preserving zero-copy RX can consequently require exporting the backing file
for that complete pool. This is not an isolation boundary for mutually
untrusted tenants. Restricting the mapping requires VPP support for assigning
a dedicated RX buffer pool, followed by moving both UET TX slots and the
selected RX queues to that pool.

The zero-copy boundaries are therefore:

| Boundary | Current state |
| --- | --- |
| Shared ring descriptors | No copy |
| VPP RX buffer to external client | No packet-data copy in the validated device setup |
| Client DMA TX slot to VPP graph | Ownership of the same VLIB buffer is transferred without a packet-data copy |
| Arbitrary application allocation to TX slot | Requires a copy unless the application obtains/uses the shared DMA arena |

The client still uses VPP's SSVM attach API and must be built against a
compatible VPP SDK. The packet-channel layout itself is defined by
`uet/svm_abi.h` and checked as ABI 4.2 when a client opens a channel set. The
plugin also declares the required `VPP_BUILD_VER`, so VPP rejects an
incompatible binary at load time.

## Device-driver independence

The plugin consumes packets from the normal VPP IP graph and submits TX back
to the normal IP lookup nodes. Interface creation and queue assignment remain
standard VPP configuration and are intentionally absent from the plugin. The
companion validation branch records the native-driver setup used for the
published measurements.

## VPP operations

The plugin is disabled by default. Enable the binary explicitly in the VPP
startup configuration, then enable its dataplane after the interfaces and FIB
are configured:

```text
plugins {
  plugin default { disable }
  plugin uet_plugin.so { enable }
}

uet enable
uet rx placement entropy-handoff
uet svm create name uet
```

Create a different segment name for each client process. When several
segments exist, deletion names the target explicitly:

```text
uet svm create name uet-app-a
uet svm create name uet-app-b
uet svm delete name uet-app-a
```

The default queue depth is 256. Each application segment reserves
`worker-count * queue-depth` VPP buffers for its TX DMA slots, in addition to
the buffers needed by the normal VPP graph. Size `buffers-per-numa` for the
sum of all application segments before selecting a larger queue depth.

This uses IPv4 and IPv6 table 0. Add `uet tx fib ...` before or after `uet
enable` only to select other tables. The RX placement command is optional;
`current-worker` is the default.

The following native VPP facilities expose the useful operational state:

```text
show uet
show errors
show log
set logging class uet level debug
trace add uet-input 20
trace add uet4-udp-input 20
show trace
clear uet counters
```

`show uet` gives aggregate, per-application, and per-worker channel state,
including application namespaces and endpoint registration/collision counts.
Standard node errors
count malformed external TX requests, completion-ring saturation, invalid RX
releases, absent or ambiguous clients, RX-ring saturation, malformed VLIB
chains, and worker handoff queue saturation. Packet traces identify direction, worker, native-IP
versus UDP encapsulation, IP version, packet length, request/RX identifier, and
delivery/drop disposition. Lifecycle events use the `uet` VPP log class;
detailed mapping-export messages are emitted only at debug level.

The binary API mirrors the controls with `uet_enable_disable`,
`uet_svm_create`, `uet_svm_delete`, `uet_tx_fib_set`, and
`uet_clear_counters`.
`uet_worker_dump` streams one `uet_worker_details` record per worker, including
attachment/readiness state, queue occupancy, and the principal TX/RX counters.
These APIs are management-plane snapshots; the packet datapath remains on the
per-worker lockless SPSC rings.

## Build

```sh
cmake -S vpp-plugin -B build/vpp-plugin \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=/opt/vpp \
  -DVPP_DIR=/opt/vpp/lib/x86_64-linux-gnu/cmake/vpp
cmake --build build/vpp-plugin
```

Single-configuration generators default to `Release` when no build type is
specified. Use an explicit `Debug` or `RelWithDebInfo` build when required;
throughput results must use `Release`.

Native package generation is optional and requires a Git checkout plus the
packaging tools. Enable it with `-DUET_VPP_ENABLE_PACKAGING=ON`.

## Tests

The basic topology and SVM ownership tests are:

```sh
vpp-plugin/tests/smoke-one-worker.sh /opt/vpp build/vpp-plugin 2 3
vpp-plugin/tests/smoke-multiworker.sh /opt/vpp build/vpp-plugin 2 3,4,5,6
vpp-plugin/tests/reject-invalid-worker-count.sh /opt/vpp build/vpp-plugin 2
vpp-plugin/tests/smoke-svm.sh /opt/vpp build/vpp-plugin 2 3
```

`smoke-multiworker.sh` has been validated with 1, 2, 4, and 8 workers. It opens
two concurrent client processes, each with its own multi-worker segment, and
verifies independent request and completion progress plus routed TX buffer
replacement on every worker. It also verifies safe ambiguous-packet rejection,
cross-process endpoint-collision detection, cleanup after an owner crash, and
exact delivery to the respective SVM segment for RUD SYN and established
traffic, ACK, PDC and RUDI NACK, CTRL, RUDI request/response, and UUD request
packets. It also exercises the stop-and-go request and ACK endpoint overlay.

`smoke-svm.sh` also connects an unattached process to the DMA socket and
verifies that it receives `-EACCES` and no file descriptor before exercising
the authorized client path. It selects distinct IPv4 and IPv6 table IDs through
the binary API, then cycles IPv4/IPv6 native-UET and UDP packets through the TX
slots without configuring an output interface or device. Its negative phase
checks client-side ownership enforcement, rejected and atomic TX submissions,
malformed-packet completions, DMA-slot exhaustion, and a completion ring filled
to its configured depth. A packet-generator stream supplies real UET-over-UDP
RX descriptors so the client can reject forged IDs, forged tokens, duplicate
and stale releases without publishing them. The default queue depth of 257
exercises modulo-based SPSC indexing; set `UET_SVM_QUEUE_DEPTH=256` to exercise
the power-of-two mask path. The test also verifies that a concurrent attach is
rejected, that a clean close releases ownership, and that a crashed owner is
reported as `-EOWNERDEAD` until the SVM segment is recreated.

## Companion hardware validation and performance

Hardware-specific functional tests and performance tools are maintained on the
companion
[`feature/vpp-uet-benchmarks`](https://github.com/jtollet/uet-ref-prov/tree/feature/vpp-uet-benchmarks)
branch. They are intentionally not proposed for merge in this RFC.

That branch records the test topology and provides:

- IPv4/IPv6 native-UET and UET-over-UDP local-delivery checks, including
  matching transit traffic and non-UET UDP ports;
- routed TX checks, including normalization of the UET UDP checksum to zero;
- interoperability with the traditional raw-socket UET implementation
  in both role directions;
- VPP multicore functional and performance scaling.

The reference measurements used Release builds, explicitly pinned application
and VPP worker cores, and back-to-back test ports. The exact device and driver
configuration is recorded only on the companion validation branch. Performance
results are intentionally not part of this RFC: they must distinguish
client-to-VPP graph completion from lossless physical transmission and be
revalidated whenever buffer ownership or routing changes. The companion branch
records the exact commands, limitations, and device restoration procedures.
