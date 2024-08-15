
KDIR ?= /lib/modules/`uname -r`/build
MDIR ?= ${PWD}

obj-m += uet_core.o
obj-m += uet_pds_gen.o
obj-m += uet_nic_raw.o

uet_nic_raw-y := uet_nic/uet_nic_raw.o

uet_core-y := uet_core/uet_core_main.o uet_core/uet_api_private.o uet_core/uet_nic.o uet_core/uet_pds_init.o

uet_pds_gen-y := uet_pds/pds/uet_pds.o uet_pds/common/uet_sec.o uet_utils/bitmap.o

ccflags-y := -Wall -Wno-unused-variable -Wno-implicit-fallthrough -I$(MDIR)/uet_core -I$(MDIR)/uet_utils -I$(MDIR)/uet_crypto -I$(MDIR)/uet_pds/common -I$(MDIR)/uet_pds/pds -I$(MDIR)/include

all:
	make -C $(KDIR) M=$(MDIR) modules

clean:
	make -C $(KDIR) M=$(MDIR) clean

