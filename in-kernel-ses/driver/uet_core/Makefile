
KDIR ?= /lib/modules/`uname -r`/build
MDIR ?= ${PWD}

obj-m := uet_core.o

ccflags-y := -Wno-implicit-fallthrough -I$(MDIR) -I$(MDIR)/../uet_utils -I$(MDIR)/../uet_crypto -I$(MDIR)/../include

uet_core-y := uet_core_main.o \
			  uet_api_private.o \
			  uet_nic.o \
			  uet_pds_init.o \
			  uet_sec.o

all:
	make -C $(KDIR) M=$(MDIR) modules

clean:
	make -C $(KDIR) M=$(MDIR) clean

