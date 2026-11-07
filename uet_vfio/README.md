
# UET reference device model

A PCIe device, emulated in userspace, that presents this repository's Ultra
Ethernet reference implementation to a guest operating system. The guest
sees a real PCI function: it binds a kernel driver to it, registers an
`ib_device` and a netdev, and runs unmodified verbs applications against
them. Underneath, every operation is served by the same SES/PDS/TSS code
the standalone `./uet` application uses.

The point is to develop and test a UET kernel driver and a UET verbs
provider without hardware, against a device whose behaviour is defined by
this repository rather than by a vendor.

```
  guest                                    host
  ---------------------------------        ------------------------------
  application (ibv_ru_pingpong, ...)
        |
  libibverbs + uet_ref provider            uet_dev
        |                                    |  device model (this dir)
  uet_ref.ko  (kmod/)                        |  + uet-ref-prov library
        |  netdev + ib_device                |
  PCI function 14e4:4242  <--- vfio-user --->|  raw socket
        |                     (QEMU)         |
        +------------------------------------+--> the wire
```

`uet_dev` is a [libvfio-user](https://github.com/nutanix/libvfio-user)
server. QEMU is the vfio-user client: it is started with
`-device vfio-user-pci` pointing at the model's UNIX socket, and the guest
then enumerates an ordinary PCI device. Guest RAM is shared with the model
through a memfd, so the device reaches guest buffers by ordinary loads and
stores rather than by copying across the socket.

## What is in this directory

| Path | Contents |
|---|---|
| `uet_dev_abi.h` | the device ABI: PCI identity, BAR layout, every register, the admin command set, and the shared structures. The contract between model and driver. |
| `uet_dev_core.c` | bring-up and teardown, the progress thread |
| `uet_dev_objs.c` | the object model: jobs, job keys, address tables, address handles, memory regions, completion queues, queue pairs |
| `uet_dev_data.c` | the datapath: work requests in, completions out |
| `uet_dev_admin.c` | the admin queue: executes the commands the driver posts |
| `uet_dev_l2.c` | the L2 rings that carry ordinary Ethernet frames to the guest's netdev |
| `uet_dev_regs.c` | the register interface: BAR0 snapshot, BAR2 control, BAR3 doorbells |
| `uet_dev_vfio.c` | the libvfio-user wrapper - the only file that knows the protocol exists |
| `uet_dev_priv.h` | state shared by the modules above; private to the model |
| `kmod/` | the `uet_ref` kernel driver, built in the guest |
| `provider/` | the `uet_ref` userspace provider, built against an rdma-core build tree |
| [`REGISTERS.md`](REGISTERS.md) | the register map, explained |
| [`VFIO_MEMORY_MODEL.md`](VFIO_MEMORY_MODEL.md) | what vfio-user guarantees about memory access and ordering, and where it differs from a real bus |

Everything outside `uet_dev_vfio.c` is free of libvfio-user symbols, so the
device's behaviour can be reasoned about, and in principle driven, without
the protocol.

For a VPP packet backend, see the optional
[`dev-vpp` setup](../vpp-plugin/GETTING_STARTED_VFIO.md). It keeps the reference
transport in the model and connects ordinary guest Ethernet to Linux separately.

## Building

### The model

```sh
% make dev -j$(nproc)
```

`dev` is deliberately not part of `all`: the default build stays exactly
what it was for the standalone application. Building `all` does **not**
rebuild `uet_dev`, which is worth remembering before concluding that a
change had no effect.

The Makefile finds libvfio-user by walking up from the build directory,
the same way it finds libfabric, and accepts the first `libvfio-user*`
directory holding a build tree (`build/lib`, where `meson compile` leaves
the library). Name it explicitly when it lives elsewhere or is installed:

```sh
% make dev LIBVFIO_USER=/path/to/libvfio-user
% make dev LIBVFIO_USER_INC=/usr/local/include LIBVFIO_USER_LIB=/usr/local/lib
```

The model links `libuet_verbs.so`, the verbs flavour of the library. That
is not incidental: a queue pair's identity - its PIDonFEP, Resource Index,
initiator and job - is carried by `uet_endpoint()` only in this flavour.
Built the other way it compiles, runs, and quietly gives every endpoint the
library's default identity.

### The kernel

`uet_ref.ko` implements twelve `ib_device_ops` members that a released
kernel does not have - `alloc_job`, `create_jkey`, `query_qp_semantics`,
`reg_user_mr_ex`, `qp_attach_mr` and the rest - and uses the `IB_QPT_RU`
queue pair type, the `IB_UVERBS_QP_SEMANTICS_*` and `IB_UVERBS_QPN_UET_*`
definitions, and `RDMA_DRIVER_UET_REF`. **None of that exists upstream
yet**, so the module does not compile against a stock tree and would have
nothing to call if it did. Until the series lands, build a kernel from a
tree carrying it:

```sh
% git clone git://git.kernel.org/pub/scm/linux/kernel/git/rdma/rdma.git \
      ~/rdma-next
% cd ~/rdma-next && git checkout <the branch carrying the UET series>
% make olddefconfig && make -j$(nproc)
```

The configuration this has been run with matters in four places:

| Option | Why |
|---|---|
| `CONFIG_INFINIBAND=y`, `CONFIG_INFINIBAND_USER_ACCESS=y` | ib_core and ib_uverbs built in, so nothing has to be modprobed in the guest |
| `CONFIG_VIRTIO_BLK=y`, `CONFIG_VIRTIO_PCI=y`, `CONFIG_EXT4_FS=y` | the guest boots this kernel directly with no initramfs, so the root disk has to be reachable without one |
| `CONFIG_NLS_ISO8859_1=y`, `CONFIG_ISO9660_FS=y` | the cloud image's EFI partition is vfat and the cloud-init seed is an ISO; without these the guest drops to emergency mode |
| `CONFIG_LOCALVERSION="-uet"` | tells this kernel apart from any other tree you build. `MODVERSIONS` is off, so vermagic is the only thing stopping a module built against one tree from loading into another |

`CONFIG_RDMA_RXE=y` is worth having too: rxe is the cheapest way to check
the series has not broken the drivers that were already there.

### The kernel driver

Built against the kernel tree above, not against the guest's headers - the
guest runs a kernel built here and its module tree has no `build/` link. The
tree layout matters: `kmod/` includes `uet_dev_abi.h` from one directory up,
so copy `uet_vfio` whole.

```sh
% make -C uet_vfio/kmod KERNELDIR=$HOME/rdma-next
```

`KERNELDIR` defaults to `/lib/modules/$(uname -r)/build`, which is right
only when the running kernel is the patched one and its build tree is still
there.

The driver checks the device ABI version at probe: the major must match and
the minor must be at least its own, so a mismatched pair fails at load
rather than misbehaving later.

### The provider

`provider/` holds the userspace half. It is built out of tree, against an
rdma-core **build** directory rather than an installed one: rdma-core
installs `verbs.h` and little else, and a provider needs `driver.h`,
`cmd_ioctl.h` and `kern-abi.h`, which are published into the build tree and
never into `/usr/include`.

```sh
# guest
% git clone https://github.com/linux-rdma/rdma-core.git ~/rdma-core
% cd ~/rdma-core && cmake -GNinja -B build . && ninja -C build
% make -C ~/uet_vfio/provider RDMA_BUILD=$HOME/rdma-core/build
```

**That clone has to carry the Ultra Ethernet verbs**, and so does the
kernel the guest runs. The provider is written against them: the `IBV_QPT_RU`
queue pair type, jobs and job keys, the extended address handle and memory
registration calls, 64-bit memory keys, and the `kernel-headers/rdma/` UAPI
that mirrors the kernel's. Until that work is upstream a branch carrying it
is needed - against a stock checkout the provider does not compile, and
against a kernel without the matching uverbs ABI the driver's commands are
rejected.

That produces `libuet_ref-rdmav<N>.so`, where `<N>` is the private provider
ABI version read out of the rdma-core build - never hardcode it, it is
bumped whenever a structure the provider allocates changes shape. A stable
`libuet_ref.so` symlink is made beside it.

Nothing is installed. The provider is loaded by preloading it:

```sh
# guest
% sudo env LD_LIBRARY_PATH=$HOME/rdma-core/build/lib \
      LD_PRELOAD=$HOME/uet_vfio/provider/libuet_ref.so \
      ~/rdma-core/build/bin/ibv_devinfo
```

This works because a provider registers itself from a constructor, and
libibverbs consults the drivers already registered before it goes looking
for `/etc/libibverbs.d/*.driver` files. No root-owned config, no install
step, and it applies to one process rather than the machine.

**Rebuild the driver and the provider together.** They share
`uet_ref-abi.h` and a device ABI revision, and a stale half presents from
userspace as a device that is simply broken rather than as a version
mismatch.

## Provisioning a test host

Any Linux host with KVM, a QEMU new enough to have the vfio-user client
(10.1 or later), and enough memory for the guests.

**1. Packages.** Build tooling, QEMU, cloud-image tools, `meson`/`ninja`
for libvfio-user, and `iproute2`/`ethtool`. On Arch:

```sh
% sudo pacman -S --needed qemu-system-x86 qemu-img cloud-image-utils \
      base-devel meson ninja git ethtool iproute2 cmocka
```

Confirm the client is present:

```sh
% qemu-system-x86_64 -device help 2>&1 | grep vfio-user-pci
```

**2. libvfio-user.** Not packaged; build it into a private prefix.

```sh
% mkdir -p ~/uet-vfio/src && cd ~/uet-vfio/src
% git clone https://github.com/nutanix/libvfio-user.git
% cd libvfio-user
% meson setup build -Dc_args=-Wno-error=deprecated-declarations
% meson compile -C build
```

The `-Dc_args` is required with cmocka 2.x, which deprecates
`expect_check()` - fatal under the `-Werror` of a debug build.

**3. libfabric.** As for the rest of this repository; see the top-level
README.

**4. Network namespaces.** The topology is two namespaces joined by a veth
pair, one device model in each:

```sh
% sudo ip netns add uet0
% sudo ip netns add uet1
% sudo ip link add veth0 type veth peer name veth1
% sudo ip link set veth0 netns uet0
% sudo ip link set veth1 netns uet1
% sudo ip -n uet0 link set veth0 up
% sudo ip -n uet1 link set veth1 up
% sudo ip -n uet0 link set lo up
% sudo ip -n uet1 link set lo up
% sudo ip netns exec uet0 ethtool -K veth0 tx off rx off tso off gso off gro off
% sudo ip netns exec uet1 ethtool -K veth1 tx off rx off tso off gso off gro off
```

The veths are left **unnumbered**: in this mode the guest owns the network
identity and assigns the address to its own netdev. Disabling the offloads
is not optional - the reference implementation computes its own checksums
and veth offloads will mangle them. Namespaces do not survive a reboot.

**5. Guest image.** Ubuntu 24.04 cloud image, used for its root filesystem
only - the kernel it ships cannot run this driver, and the guest is booted
on the one built in *Building* above rather than on anything installed
inside it. Create a qcow2 overlay per guest and a cloud-init seed carrying
your ssh key; the overlays are disposable. Disable unattended upgrades, so
the image does not churn underneath you.

**6. Guest packages.**

```sh
# guest
% sudo apt-get install -y build-essential cmake ninja-build pkg-config \
      libnl-3-dev libnl-route-3-dev libudev-dev python3-docutils pandoc \
      cython3 python3-dev
```

Userspace only. The guest builds rdma-core and the provider; the kernel and
`uet_ref.ko` are built outside and brought in, so no kernel headers are
needed here. Install `cython3` **before** configuring rdma-core: cmake
decides whether to build pyverbs at configure time, and without it the
Python tests have nothing to import.

## Running

Bringing the topology up is four steps per side, and **the order is what
matters**: the model must be listening before QEMU starts, because the
socket is what QEMU connects to.

**1. Build the model** - `make dev`, not `make`. Then start one per
namespace, each on its own socket:

```sh
% sudo ip netns exec uet0 env LD_LIBRARY_PATH=/path/to/libfabric:. \
      UET_NIC_SHIM=rawsock UET_PDS=pds UET_IFNAME=veth0 \
      UET_LOCAL_IP=10.99.0.1 \
      ./uet_dev /tmp/uet-dev0.sock >/tmp/uet_dev0.log 2>&1 &
```

and the same for `uet1`, `veth1`, `10.99.0.2`, `/tmp/uet-dev1.sock`. Wait
for the socket file to appear before continuing - `ss` run unprivileged
will not show a root-owned listener, so test for the file itself.

**2. Start the guest.** QEMU needs its RAM shared with the model:

```sh
% sudo qemu-system-x86_64 -enable-kvm -m 4G -smp 4 -nographic \
    -kernel ~/rdma-next/arch/x86/boot/bzImage \
    -append "root=/dev/vda1 ro console=ttyS0" \
    -object memory-backend-memfd,id=mem0,size=4G,share=on \
    -machine memory-backend=mem0 \
    -drive file=g0.qcow2,if=virtio -drive file=seed0.iso,if=virtio,format=raw \
    -netdev user,id=n0,hostfwd=tcp::2220-:22 -device virtio-net-pci,netdev=n0 \
    -device '{"driver":"vfio-user-pci","socket":{"path":"/tmp/uet-dev0.sock","type":"unix"}}'
```

The two memory-backend lines are required, not decoration: libvfio-user
must be able to map guest RAM, and `share=on` is what allows it. Every DMA
path depends on them. The second guest is the same with `mem1`, `g1.qcow2`,
`seed1.iso`, port 2221 and `/tmp/uet-dev1.sock`.

**3. Load the driver** in each guest, and give its netdev an address:

```sh
# guest
% sudo insmod ~/uet_vfio/kmod/uet_ref.ko
% echo 0000:00:06.0 | sudo tee /sys/bus/pci/drivers_probe
% sudo ip addr add 10.99.0.1/24 dev <the new netdev>   # .2 on the other guest
% sudo ip link set <the new netdev> up
```

There is nothing to modprobe: ib_core and ib_uverbs are built into this
kernel, and `modprobe ib_core` fails outright because there is no such
module. The write to `drivers_probe` is needed because the PCI device was
enumerated at boot, when no driver claimed it; loading the module later does
not re-run the match. Reloading is `rmmod uet_ref` and the same two lines
again.

**4. Build the provider**, as in *Building* above. Nothing installs it;
every verbs command preloads it.

A rebuilt model needs the whole topology restarted, not just the model: the
vfio-user socket dies with it, and a guest whose device vanished cannot be
recovered without a reboot. Tear down in the reverse order - guests first,
then the models - because QEMU holds the socket.

In the guest, a successful probe looks like:

```
uet_ref 0000:00:06.0: UET reference device, abi 1.0, state 1
uet_ref 0000:00:06.0: device info: jobs 256 jkeys 256 addrs 4096 imm 1024
uet_ref 0000:00:06.0: ib device uet_ref0 registered on eth0
```

### Tracing

`UET_DEV_TRACE=1` in the model's environment makes it log
every object it mints and every completion it posts, with timestamps. Off
by default - it is a line per object, which is noise during a transfer and
exactly what is wanted during bring-up. The models log to
`/tmp/uet_dev0.log` and `/tmp/uet_dev1.log`.

## Tests

Every command below needs the provider preloaded. It is worth setting once:

```sh
# guest
% P="LD_LIBRARY_PATH=$HOME/rdma-core/build/lib \
     LD_PRELOAD=$HOME/uet_vfio/provider/libuet_ref.so"
```

**The device is alive:**

```sh
% sudo env $P ~/rdma-core/build/bin/ibv_devinfo
% ping -c3 10.99.0.2
```

**The pyverbs suites.** `tests.test_ru` covers jobs, job keys, queue pairs
and their semantics, protection domain and memory region id spaces, device
attributes and loopback traffic; the generic suite covers what any device
must do. Both skip themselves on a device that does not advertise
`IBV_DEVICE_RU`, so check they actually ran rather than trusting `OK` -
`Ran N tests` with no skips is the thing to look for.

```sh
% cd ~/rdma-core && sudo env $P ./build/bin/run_tests.py -v tests.test_ru
% cd ~/rdma-core && sudo env $P ./build/bin/run_tests.py -v tests.test_device \
      tests.test_pd tests.test_mr
```

### Traffic

`ibv_ru_pingpong` and `ibv_ru_rma` are the two verbs applications, built
with rdma-core into `~/rdma-core/build/bin`. Both take a server and a client:
start the server with no address, then the client with the server's. `-g 1`
selects the IPv4 GID entry, and - with the one exception noted below - both
sides must be given the same options.

**Send and receive**, guest 1 then guest 0:

```sh
# guest 1 - server
% sudo env $P ~/rdma-core/build/bin/ibv_ru_pingpong -d uet_ref0 -g 1 -n 5 -s 256
# guest 0 - client
% sudo env $P ~/rdma-core/build/bin/ibv_ru_pingpong -d uet_ref0 -g 1 -n 5 -s 256 \
      10.99.0.2
```

Worth running with, each on both sides:

| Option | Exercises |
|---|---|
| *none* | 64-bit memory keys, the default |
| `-L` | 32-bit keys instead |
| `-N` | the `ibv_wr_*` send API rather than `ibv_post_send` |
| `-S 4` | a four-entry scatter/gather list |
| `-I 32`, `-I 64` | immediate data, narrow and wide |
| `-Q` | a device-assigned QPN rather than a chosen one |
| `-c` | validate the received buffer, not just the completion |
| `-e` | wait on a completion channel instead of polling |

**RDMA**, the same shape:

```sh
# guest 1 - server
% sudo env $P ~/rdma-core/build/bin/ibv_ru_rma -d uet_ref0 -g 1 -n 3
# guest 0 - client
% sudo env $P ~/rdma-core/build/bin/ibv_ru_rma -d uet_ref0 -g 1 -n 3 10.99.0.2
```

| Option | Exercises |
|---|---|
| *none* | `rma_ex64`: the `ibv_wr_*` API, 64-bit keys, 64-bit immediate |
| `-t rma_ex` | the same API over 32-bit keys |
| `-t rma` | `ibv_post_send` instead, 32-bit keys |
| `-A` | address the peer through the job address table |
| `-J` | a memory region bound to a job |
| `-u 0x1234` | a caller-chosen rkey |
| `-D` | a region derived from another |
| `-D -J`, `-D -u 0x1234` | those combinations |
| `-S 4`, `-c`, `-e` | as above |
| `-m 256`, `-m 512`, `-m 1024` | a path MTU below the link's |
| `-b -j <id>` | absolute addressing, a distinct JobID per side |

Two of these need care. **`-m` must match on both sides**: a read request's
first packet has nowhere to carry a length, so the chunk size is implied by
the MTU alone, and a target that disagrees answers with the wrong amount of
data. Nothing negotiates it. And **`-b`, absolute addressing, needs a
different JobID per side** - the server imports the client's, and one device
cannot hold two jobs under one JobID:

```sh
# guest 1 - server
% sudo env $P ~/rdma-core/build/bin/ibv_ru_rma -d uet_ref0 -g 1 -n 3 -b -j 43
# guest 0 - client
% sudo env $P ~/rdma-core/build/bin/ibv_ru_rma -d uet_ref0 -g 1 -n 3 -b -j 42 \
      10.99.0.2
```

### Leak checks

The device publishes its live object counts, so "did that leak?" is a read
rather than an exhaustion run: note the counts, create objects, `SIGKILL`
the process so userspace destroys nothing, and watch them come back.

Anything touching `uet_api.c` or the nic shims is also a change to the
standalone application, so run the ref-prov matrix as well - the device
model and `./uet` share that code.

The device also publishes its own counters through `ib_core`, which is
often the fastest way to see what happened:

```sh
% cd /sys/class/infiniband/uet_ref0/hw_counters && grep . *
```

Live object counts returning to zero after a test is the leak check; the
`admin_errors`, `sq_errors`, `rq_errors`, `cq_errors` and `cq_overruns`
counters name the failure when something went wrong inside the device.

## BARs and registers

The device exposes four BARs. This is the shape of it;
**[REGISTERS.md](REGISTERS.md) is the explanation, and `uet_dev_abi.h` is
the contract.**

| BAR | Size | Access | Written by | Contents |
|---|---|---|---|---|
| 0 | 4 KiB | read | - | identity, configuration, live counters |
| 1 | 4 KiB | read/write | PCI core | MSI-X table and PBA, 4 vectors |
| 2 | 4 KiB | write | kernel only | L2 ring config, admin queue, their doorbells |
| 3 | 256 KiB | write | userspace | 64 doorbell pages, one per ucontext |

BAR2 and BAR3 are separate so that a doorbell can be reached from an
unprivileged process without handing that process the admin queue.

The driver talks to the device two ways: the **admin queue** in BAR2 for
everything slowpath - jobs, keys, regions, queue pairs - and **mapped rings
in guest memory** for the datapath, rung by a doorbell in BAR3. Both are
described in [REGISTERS.md](REGISTERS.md): section 4.2 covers the admin
protocol - command and completion formats, doorbells, flow control and what
a driver must do - and section 5 covers the doorbell pages.

**Memory ordering here is not a PCIe bus, and the differences do not all
run in the same direction.** Writes to a memory BAR are posted, as on a
bus, and a read of any region cannot pass them - but the ordering is
stronger than PCIe, because one socket carries everything in order. In the
other direction it is weaker: the device reaches guest memory with ordinary
stores, so a completion entry has only the host CPU's memory model behind
it, not a bus's. Neither difference is visible in a passing test, and both
change what a driver may assume. Treat any ordering result obtained here
with suspicion before relying on it against hardware.

## Gotchas

Each of these cost real time at least once.

- **`make` does not build the model.** `make dev` does. A change that seems
  to have no effect is usually a model that was never rebuilt.
- **Rebuild the driver and the provider together.** They share
  `uet_ref-abi.h` and a device ABI revision. A stale half does not report a
  version mismatch; it presents as a device that is simply broken.
- **After a pyverbs change, rebuild rdma-core from scratch.** A `.pxd` edit
  does not reliably force dependent modules to recompile, and the result is
  `ValueError: Context size changed` at import - which reads as a code bug
  rather than a stale object.
- **Shut guests down, do not kill them.** A build that exists only in the
  page cache does not survive `pkill -9`, and the binaries come back zero
  length after the next boot - which reads as a broken toolchain rather
  than a lost write.
- **The model ignores SIGTERM.** It sits in the libvfio-user run loop, so a
  plain `pkill` followed by a wait loop waits for ever. Escalate to
  `SIGKILL`, then remove the socket.
- **Stop the guest before the model.** QEMU holds the socket; pulling the
  device out from under a running guest leaves it with a PCI function that
  has stopped answering.
- **Verbs modules are not loaded by default.** Without `ib_core` and
  `ib_uverbs`, inserting the driver fails with unresolved symbols that name
  nothing useful.

