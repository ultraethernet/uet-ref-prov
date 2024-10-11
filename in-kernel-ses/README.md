
# In-kernel SoftUET driver

In-kernel SoftUET driver with the SES / PDS / NIC sources of uet-ref-prov ported in 
kernel space.

Block diagram -

                 -------------------------------------------------------
                 |                      uet.c                          |
                 -------------------------------------------------------
                 | Userspace UET APIs(uet_api.c, uet_api.h, uet_uapi.h |
                 |                uet_api_internal.c)                  |
                 -------------------------------------------------------
                                                                           User space
     -------------------------------------------------------------------------------------
                                                                         Kernel space
                 -------------------------------------------------------
                 |                  uet_core.ko (SES)                  |
                 -------------------------------------------------------
                 |                 uet_pds_gen.ko (PDS)                |
                 -------------------------------------------------------
                 |                 uet_nic_raw.ko (NIC)                |
                 -------------------------------------------------------



## Preparation

Make sure the proper development libraries/headers are installed:
```
% sudo apt install linux-headers-$(uname -r)
% sudo apt install gcc gcc-multilib clang libbpf-dev libxdp-dev
```

### libfabric

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

## Build

```
% make all
```

## Run

### Server

```
% sudo insmod uet_core.ko
% sudo insmod uet_nic_raw.ko param_ifname=eth1
% sudo insmod uet_pds_gen.ko
% sudo mknod /dev/uet c 248 0
% sudo UET_CHAR_DEV=/dev/uet LD_LIBRARY_PATH=../../libfabric/src/.libs ./uet server 192.168.1.2
```

### Client

```
% sudo insmod uet_core.ko
% sudo insmod uet_nic_raw.ko param_ifname=eth1
% sudo insmod uet_pds_gen.ko
% sudo mknod /dev/uet c 248 0
% ping -c1 192.168.1.1
% sudo UET_CHAR_DEV=/dev/uet LD_LIBRARY_PATH=../../libfabric/src/.libs ./uet client 192.168.1.1
```

## Run with vmtest

### Compile uet-linux-kernel

```
% git clone git@github.com:rabhunia-keysight/uet-linux-kernel-memmapped-q.git
% cd uet-linux-kernel-memmapped-q
% git checkout memmapped-queues
% git submodule update --init
% make O=.build uet_defconfig
% cd .build
% make -j$(nproc) bzImage modules && make -j$(nproc) modules_install INSTALL_MOD_PATH=$(pwd)/.modstage
% sudo brctl addbr brtest0
% sudo ifconfig brtest0 up
```

### Compile uet-ref-prov

```
% KDIR=../uet-linux-kernel-memmapped-q/.build make all
% cp -vf in-kernel-ses/app/uet ../uet-linux-kernel-memmapped-q/.build/
% cp -vf in-kernel-ses/driver/*.ko ../uet-linux-kernel-memmapped-q/.build/
```

### Start capture

```
% sudo tcpdump -i brtest0 -w /tmp/uet.pcap
```

### Start server

```
cd uet-linux-kernel-memmapped-q/.build
sudo QEMU_KERNEL_APPEND="vmtest.autorun=/run/kernel/source/drivers/uecon/vmtest.sh" QEMU_BRIDGE=brtest0 QEMU_INSTANCE=3 make tools/vmtest
```

### Start client

```
sudo QEMU_KERNEL_APPEND="vmtest.autorun=/run/kernel/source/drivers/uecon/vmtest.sh" QEMU_BRIDGE=brtest0 QEMU_INSTANCE=2 make tools/vmtest
```

## Run fi_pingpong with vmtest

### Compile uet-libfabric

```
git clone git@github.com:rabhunia-keysight/uet-libfabric-kernel-ses.git
cd uet-libfabric-kernel-ses
git submodule sync
git submodule update --init --recursive --remote
./autogen.sh
./configure --enable-only --enable-uet --enable-debug --prefix=<<install directory full path>> --disable-dependency-tracking
make -j
gcc -Wall -g -O0 -Wall -Wundef -Wpointer-arith -fstack-protector-strong -Wno-missing-field-initializers -Wno-sign-compare -Wno-unused-parameter -Wextra -pipe -fvisibility=hidden -Wall -Wundef -Wpointer-arith -static -o util/.libs/fi_pingpong util/pingpong.o  src/.libs/libfabric.a -latomic -lpthread -ldl
cp util/.libs/fi_pingpong ../uet-linux-kernel-memmapped-q/.build/
```

### Start server

```
sudo QEMU_KERNEL_APPEND="vmtest.autorun=/run/kernel/source/drivers/uecon/vmtest.sh" QEMU_BRIDGE=brtest0 QEMU_INSTANCE=5 make tools/vmtest
```

### Start client

```
sudo QEMU_KERNEL_APPEND="vmtest.autorun=/run/kernel/source/drivers/uecon/vmtest.sh" QEMU_BRIDGE=brtest0 QEMU_INSTANCE=4 make tools/vmtest
```

## Status and Pending Issues

Currently, untagged send / recv of 4KBytes with ROD was tested to be working with 2 iterations.
List of TODOs -

- Dynamic ARP resolution in uet_nic_raw.ko.
- Retry timeout and timers, replace uet_list with in-kernel list APIs.
- Use of tasklet for processing incoming packet and work request posted in SRQ / RRQ. Currently it's done from the context of uet app.
- Code cleanup.


