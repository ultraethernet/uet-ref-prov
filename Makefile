
CC=gcc
CLANG=clang

KDIR ?= /lib/modules/`uname -r`/build

LIBFABRIC=../libfabric

INCS=-I. -I./util -I./nic_shim -I./crypto \
     -I$(LIBFABRIC) -I$(LIBFABRIC)/include
CFLAGS=-Wall                              \
       -Wno-unused-variable               \
       -Wno-implicit-function-declaration \
       -Wno-int-conversion                \
       -Wno-address-of-packed-member
LDFLAGS=-L$(LIBFABRIC)/src/.libs -lfabric

HDRS=$(wildcard *.h util/*.h nic_shim/*.h crypto/*.h)

BIN=uet
SRC=$(filter-out $(wildcard nic_shim/*xdp*), \
		 $(wildcard *.c              \
			    util/*.c         \
			    nic_shim/*.c     \
			    crypto/*.c))
OBJ_DIR=obj
OBJ=$(patsubst %.c, $(OBJ_DIR)/%.o, $(SRC))

XDP_BIN=uet_xdp
XDP_SRC=$(SRC) \
	$(filter-out nic_shim/*xdp_kern*, \
		     $(filter $(wildcard nic_shim/*xdp*.c), \
			      $(wildcard *.c \
					 util/*.c \
					 nic_shim/*.c \
					 crypto/*.c)))
XDP_OBJ_DIR=obj_xdp
XDP_OBJ=$(patsubst %.c, $(XDP_OBJ_DIR)/%.o, $(XDP_SRC))
XDP_KERN_SRC=$(wildcard nic_shim/*xdp_kern*)
XDP_KERN_BIN=uet_xdp_kern.o

CC_SIM_BIN=uet_cc_sim
CC_SIM_SRC=$(wildcard cc/*.c cc_sim/*.c)
CC_SIM_OBJ_DIR=obj_cc_sim
CC_SIM_OBJ=$(patsubst %.c, $(CC_SIM_OBJ_DIR)/%.o, $(CC_SIM_SRC))

xdp: CFLAGS+=-DENABLE_XDP -DXDP_PROG=$(XDP_KERN_BIN)
xdp: LDFLAGS+=-lpthread -lbpf -lxdp

$(OBJ_DIR)/%.o: %.c $(HDRS)
	@mkdir -p $(OBJ_DIR)/$(dir $<)
	@echo 'Building file: $<'
	@$(CC) $(CFLAGS) $(INCS) -c -o $@ $<

$(BIN): $(OBJ)
	@echo 'Building program: $@'
	@$(CC) $(OBJ) -o $@ $(LDFLAGS)

$(XDP_OBJ_DIR)/%.o: %.c $(HDRS)
	@mkdir -p $(XDP_OBJ_DIR)/$(dir $<)
	@echo 'Building file: $<'
	@$(CC) $(CFLAGS) $(INCS) -c -o $@ $<

$(XDP_BIN): $(XDP_OBJ)
	@echo 'Building program: $@'
	@$(CC) $(XDP_OBJ) -o $@ $(LDFLAGS)

$(XDP_KERN_BIN): $(XDP_KERN_SRC)
	@echo 'Building XDP kernel program: $@'
	@$(CLANG) -O2 -g -Wall -target bpf -c -o $(XDP_KERN_BIN) $(XDP_KERN_SRC)

$(CC_SIM_OBJ_DIR)/%.o: %.c $(HDRS)
	@mkdir -p $(CC_SIM_OBJ_DIR)/$(dir $<)
	@echo 'Building file: $<'
	@$(CC) $(CFLAGS) $(INCS) -c -o $@ $<

$(CC_SIM_BIN): $(CC_SIM_OBJ)
	@echo 'Building program: $@'
	@$(CC) $(CC_SIM_OBJ) -o $@ $(LDFLAGS)

in-kernel-ses:
	cd in-kernel-ses/app && make all STATIC=$(STATIC) && cd -
	cd in-kernel-ses/driver && make all KDIR=$(KDIR) && cd -

all: $(BIN) in-kernel-ses

xdp: $(XDP_BIN) $(XDP_KERN_BIN)

cc_sim: $(CC_SIM_BIN)

clean:
	@rm -rf $(OBJ_DIR) $(BIN) \
		$(CC_SIM_OBJ_DIR) $(CC_SIM_BIN) \
		$(XDP_OBJ_DIR) $(XDP_BIN) $(XDP_KERN_BIN)
	cd in-kernel-ses/app && make clean STATIC=$(STATIC) && cd -
	cd in-kernel-ses/driver && make clean KDIR=$(KDIR) && cd -

.PHONY: all xdp cc_sim clean in-kernel-ses

