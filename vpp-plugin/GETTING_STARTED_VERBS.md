# Getting started with UET Verbs over VPP

This guide validates the experimental UET Verbs path through the VPP NIC shim.
It uses two Linux network namespaces and two VPP instances connected by an
AF_PACKET `veth` pair. No physical NIC, DPDK binding, VF, or XDP setup is
required.

```text
ibv_ru_pingpong / ibv_ru_rma
  -> libibverbs.so
  -> libuprot-rdmav57.so
  -> libuet_verbs_vpp.so
  -> libuet_vpp_client.so
  -> uet_plugin.so in VPP A
  -> AF_PACKET / veth / AF_PACKET
  -> uet_plugin.so in VPP B
  -> the same libraries in reverse order
```

UET transport still terminates in the application process. VPP supplies the
shared packet-buffer exchange, IP FIB/local-delivery integration, worker
dataplane, packet I/O, tracing, counters, and CLI.

## Version policy

The Linux and VPP versions below describe a validated configuration, not
general minimum versions.

| Component | Compatibility requirement | Configuration validated on 4 September 2026 |
| --- | --- | --- |
| Linux | Build `rdma_uprot.ko` with headers and a compiler compatible with the running kernel. | Linux 6.18.39 |
| VPP | Build the plugin and client against the same VPP SDK used by the runtime. | VPP v26.10-rc0, commit `a4b80adfc` |
| `uet-ref-prov` | Use a checkout containing the VPP plugin, NIC shim, and `vpp-verbs` target. | `feature/vpp-verbs-provider`, commit `9c5f9b1` |
| `uet-rdma-core` | Use the UEC `uet` branch with selectable UET-library support. | Base commit `7845173` plus the patches listed below |

A different distribution, kernel, or VPP release may work. The important
constraints are the matching kernel headers and matching VPP build/runtime;
the versions in the last column make the reported validation reproducible.

The validation included these contributions. They may already be merged when
you read this guide:

- [`uet-ref-prov` #157](https://github.com/ultraethernet/uet-ref-prov/pull/157):
  VPP NIC shim.
- [`uet-ref-prov` #160](https://github.com/ultraethernet/uet-ref-prov/pull/160):
  UET Verbs `fi_info` ownership fix.
- [`uet-ref-prov` #161](https://github.com/ultraethernet/uet-ref-prov/pull/161):
  single-buffer receive-vector cleanup.
- [`uet-rdma-core` #63](https://github.com/ultraethernet/uet-rdma-core/pull/63):
  `uprot` compatibility with Linux 6.17 and newer. It is not needed on older
  kernels.
- [`uet-rdma-core` #64](https://github.com/ultraethernet/uet-rdma-core/pull/64):
  selection of `libuet_verbs_vpp.so`; this is required for the VPP path.
- [`uet-rdma-core` #65](https://github.com/ultraethernet/uet-rdma-core/pull/65):
  completion-queue cleanup found during ASAN validation.

## Prerequisites

- An x86-64 Linux host with at least two logical CPUs.
- Git, CMake, a C compiler, and the normal VPP and rdma-core build
  dependencies.
- An authenticated GitHub account with access to the UEC `uet-rdma-core`
  repository. The commands below use a registered SSH key.
- Matching headers for the running Linux kernel and the compiler expected by
  those headers.
- `iproute2`, including the `ip` and `rdma` commands, plus `setpriv` from
  `util-linux`.
- `sudo` access for loading `rdma_uprot.ko` and creating temporary network
  namespaces and `veth` interfaces.

The script uses privilege only for host setup and cleanup. When invoked with
`sudo`, it runs VPP as the invoking user with the required capabilities and
runs both Verbs applications as that user without capabilities.

## 1. Clone and build VPP

Start from an empty evaluation directory:

```sh
mkdir uet-vpp-verbs-evaluation
cd uet-vpp-verbs-evaluation
export UET_EVAL_ROOT=$PWD

git clone https://gerrit.fd.io/r/vpp
git -C vpp checkout a4b80adfcf792ba8a59ef0f3a9687842333269dd

make -C vpp UNATTENDED=yes install-dep

cmake -S vpp/src -B vpp-build-uet \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$UET_EVAL_ROOT/vpp-install-uet" \
  -DVPP_PLUGINS=af_packet \
  -DVPP_DRIVERS=none \
  -DVPP_CRYPTO_ENGINES=none
cmake --build vpp-build-uet --parallel "$(nproc)"
cmake --install vpp-build-uet

export UET_VPP_PREFIX="$UET_EVAL_ROOT/vpp-install-uet"
export UET_VPP_CMAKE_DIR="$(dirname "$(find "$UET_VPP_PREFIX" \
  -name VPPConfig.cmake -print -quit)")"
"$UET_VPP_PREFIX/bin/vpp" --version
```

This is a small functional-test build with AF_PACKET and no optional PCI
driver or crypto-engine build. Keep the normal drivers and optimized CPU
variants in a performance build. The local install does not modify an existing
system VPP installation.

The checkout above pins the validation baseline. To test a newer VPP, omit
that checkout and record `git -C vpp rev-parse HEAD`. No particular VPP
release is otherwise imposed by the plugin, but the external plugin and client
must be rebuilt against that VPP installation.

## 2. Check out and build `uet-ref-prov`

Use the contribution branch containing this guide. For an already merged
version, a normal clone of the official repository is sufficient:

```sh
cd "$UET_EVAL_ROOT"
git clone https://github.com/ultraethernet/uet-ref-prov.git
cd uet-ref-prov

# When testing this guide from an unmerged pull request:
git fetch origin pull/<pull-request-number>/head:uet-vpp-verbs
git switch uet-vpp-verbs

cmake -S vpp-plugin -B build/vpp-plugin \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$UET_VPP_PREFIX" \
  -DVPP_DIR="$UET_VPP_CMAKE_DIR"
cmake --build build/vpp-plugin --parallel

make -j"$(nproc)" vpp-verbs \
  LIBFABRIC="$PWD/libfabric_headers" \
  VPP_PLUGIN_BUILD="$PWD/build/vpp-plugin"

export UET_REF_PROV_ROOT=$PWD
```

The common Makefile still requires its `LIBFABRIC` argument, but `vpp-verbs`
uses the compatibility headers bundled in `libfabric_headers` and does not
link `libfabric.so`. The Verbs application therefore does not pass through
libfabric at runtime.

The relevant output is:

| File | Role |
| --- | --- |
| `libuet_verbs_vpp.so` | UET Verbs-enabled reference transport with the VPP NIC shim. |
| `build/vpp-plugin/lib/libuet_vpp_client.so` | Application-process client for VPP shared buffers and rings. |
| `build/vpp-plugin/lib/vpp_plugins/uet_plugin.so` | Out-of-tree VPP dataplane plugin. |

## 3. Build `uet-rdma-core` and `uprot`

Clone the UEC branch rather than canonical `linux-rdma/rdma-core`:

```sh
cd "$UET_EVAL_ROOT"
git clone --branch uet git@github.com:ultraethernet/uet-rdma-core.git
cd uet-rdma-core
```

Until the prerequisite changes are merged, fetch their pull-request heads.
Apply #63 only on Linux 6.17 or newer; #64 is required; #65 is recommended for
clean resource validation.

```sh
git fetch origin pull/63/head:pr-63 pull/64/head:pr-64 pull/65/head:pr-65
# Linux 6.17 and newer only:
git merge --no-edit pr-63
# Required for libuet_verbs_vpp.so selection:
git merge --no-edit pr-64
# Recommended resource cleanup:
git merge --no-edit pr-65
```

Configure `uprot` to load the VPP-specific UET Verbs library, then build its
userspace provider, examples, and out-of-tree kernel module:

```sh
export UET_RDMA_ROOT=$PWD
export UET_REF_PROV_PATH="$UET_REF_PROV_ROOT"

cmake -S . -B build \
  -DIN_PLACE=1 \
  -DNO_MAN_PAGES=1 \
  -DNO_PYVERBS=1 \
  -DUET_REF_PROV_LIB="$UET_REF_PROV_ROOT/libuet_verbs_vpp.so"
cmake --build build --parallel

make -C providers/uprot/kmod
```

The kernel build normally selects the correct compiler. If it fails with an
error such as `gcc-N: not found`, install that compiler or pass an appropriate
`CC=/path/to/compiler` to the last `make` command. This is a property of the
installed kernel build, not a UPROT or VPP version requirement. In particular,
the Ubuntu mainline 6.18 headers on the validation host requested GCC 15; the
host used its existing GCC 13 compatibility wrapper for this functional test.

`rdma_uprot.ko` provides device discovery and the minimal Linux RDMA control
surface. Queue pairs, completion queues, memory regions, and UET transport are
managed in userspace by `libuprot-rdmav57.so` and the reference transport.

## 4. Run the AF_PACKET test

From the `uet-ref-prov` checkout:

```sh
cd "$UET_REF_PROV_ROOT"
sudo ./vpp-plugin/tests/uprot-af-packet.sh \
  "$UET_VPP_PREFIX" \
  "$UET_RDMA_ROOT" \
  "$PWD/build/vpp-plugin" \
  "$PWD"
```

The script automatically:

1. loads the locally built `rdma_uprot.ko` if necessary;
2. creates two network namespaces and an `uprot` RDMA device in each;
3. starts one VPP instance and one UET application segment in each namespace;
4. connects the VPP instances through AF_PACKET on a temporary `veth` pair;
5. runs 100 64-byte `ibv_ru_pingpong` exchanges; and
6. prints `rdma link` and `show uet` state before removing the namespaces.

A successful run ends with:

```text
UET VPP AF_PACKET ibv_ru_pingpong test passed
```

Run the RMA example over the same topology with:

```sh
sudo UET_VERBS_TEST=ibv_ru_rma \
  ./vpp-plugin/tests/uprot-af-packet.sh \
  "$UET_VPP_PREFIX" \
  "$UET_RDMA_ROOT" \
  "$PWD/build/vpp-plugin" \
  "$PWD"
```

The temporary log directory is printed at exit and is retained for inspection.
The VPP CLI socket paths and `show uet` output are included in those logs. For
the full plugin CLI and binary-API reference, see
[`README.md`](README.md#vpp-operations).

## What this test establishes

The test validates standard libibverbs application entry points, `uprot`
device discovery, UET resource creation, message or RMA transfer, VPP shared
buffer exchange, IP routing/local delivery, AF_PACKET I/O, completion, and
cleanup. It is a functional test, not a performance benchmark. Physical-NIC
queueing, RSS, NUMA placement, and multicore throughput require a separate,
platform-specific setup.
