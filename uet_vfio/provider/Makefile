# SPDX-License-Identifier: GPL-2.0-only OR Linux-OpenIB

# Copyright (c) 2026, Broadcom. All rights reserved. The term Broadcom
# refers to Broadcom Inc. and/or its subsidiaries.

# Out-of-tree build for the uet_ref userspace provider driver.
#
# Built and loaded from the top of the uet-ref-prov worktree:
#
#     make -C uet_vfio/provider RDMA_BUILD=~/rdma-core/build
#     LD_PRELOAD=$PWD/uet_vfio/provider/libuet_ref.so ibv_devinfo
#
# LD_PRELOAD needs an absolute path or one starting "./", so a bare
# filename will not work.
#
# rdma-core does not support out-of-tree providers. It installs verbs.h and
# little else. driver.h, cmd_ioctl.h, and kern-abi.h are internal headers,
# published into the build tree and never into /usr/include. So this builds
# against an rdma-core build directory, not an installed one, and that
# directory is the only thing it needs. Using -I to include the build's
# include directory covers everything.
#
# The consequence is that this Makefile is coupled to rdma-core's build
# layout, which is private and free to change. When it does, the failure is
# a missing file rather than anything subtle. Should be easy to fix.
#
# Loading is by LD_PRELOAD rather than an /etc/libibverbs.d/*.driver file.
# A provider registers itself from a constructor, see PROVIDER_DRIVER() in
# driver.h, and libibverbs consults the list of registered drivers before
# it goes looking for .driver files. So preloading the object is enough.

RDMA_BUILD ?= $(HOME)/rdma-core/build

# The ABI version rdma-core was built with. Read rather than hardcoded.
PABI := $(shell sed -n 's/^\#define IBVERBS_PABI_VERSION \([0-9]*\).*/\1/p' \
		$(RDMA_BUILD)/include/config.h 2>/dev/null)

SO       := libuet_ref-rdmav$(PABI).so
LINKNAME := libuet_ref.so

# The uet_ref-abi.h header is the driver's own kernel/user ABI and it lives
# with the uet_ref kernel driver.
ABI_DIR := ../kmod

CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -fPIC -Wall -Wextra -Wno-sign-compare \
	  -Wno-unused-parameter -Wmissing-prototypes -Wmissing-declarations \
	  -Wwrite-strings -Wstrict-prototypes -Wold-style-definition
CPPFLAGS += -I$(RDMA_BUILD)/include -I$(ABI_DIR)

# --no-undefined so a missing libibverbs symbol fails here rather than at
# dlopen. The version script keeps every symbol local, as rdma-core's own
# providers do. Nothing is exported as the constructor does the work.
LDFLAGS += -shared -Wl,--no-undefined -Wl,--version-script,uet_ref.map
LDLIBS  += $(RDMA_BUILD)/ccan/libccan_pic.a \
	   $(RDMA_BUILD)/util/librdma_util_pic.a \
	   $(RDMA_BUILD)/lib/libibverbs.so

all: check $(SO) $(LINKNAME)

check:
	@test -n "$(PABI)" || { \
		echo "no rdma-core build at $(RDMA_BUILD)"; \
		echo "  expected $(RDMA_BUILD)/include/config.h"; \
		echo "  set RDMA_BUILD to an rdma-core build directory"; \
		exit 1; }
	@test -f $(ABI_DIR)/uet_ref-abi.h || { \
		echo "no uet_ref-abi.h at $(ABI_DIR)"; exit 1; }

$(SO): uet_ref.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

uet_ref.o: uet_ref.c uet_ref.h uet_ref_hw.h uet_ref_ring_cons.h $(ABI_DIR)/uet_ref-abi.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

# A stable name to preload. The versioned one records which rdma-core ABI
# the object was built against; nothing dlopens it by name here, so the
# symlink costs nothing and keeps any test harness free of the version.
$(LINKNAME): $(SO)
	ln -sf $(SO) $@

clean:
	rm -f uet_ref.o $(LINKNAME) libuet_ref-rdmav*.so

.PHONY: all check clean
