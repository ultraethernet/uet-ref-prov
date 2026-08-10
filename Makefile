
CC=gcc
CLANG=clang

# Auto-discover libfabric directory by searching up parent directories
# Use LIBFABRIC environment variable if set, otherwise auto-discover
ifneq ($(MAKECMDGOALS),clean)
ifndef LIBFABRIC
LIBFABRIC := $(shell \
	current_dir=$(CURDIR); \
	while [ "$$current_dir" != "/" ]; do \
		for dir in $$current_dir/libfabric*; do \
			if [ -d "$$dir/src/.libs" ]; then \
				echo "$$dir"; \
				exit 0; \
			fi; \
		done; \
		current_dir=$$(dirname $$current_dir); \
	done; \
)
ifeq ($(LIBFABRIC),)
$(error a libfabric directory was not found)
endif
$(info Found libfabric directory: $(LIBFABRIC))
else
$(info Using libfabric directory from environment: $(LIBFABRIC))
endif
endif

LF_HDRS=-I$(LIBFABRIC) -I$(LIBFABRIC)/include
LF_LIBS=-L$(LIBFABRIC)/src/.libs -lfabric

LF_LOCAL_HDRS=-I./libfabric_headers -I./libfabric_headers/include

INCS=-I. -I./util -I./imp_shim -I./nic_shim -I./crypto
CFLAGS=-Wall \
       -Wno-unused-variable \
       -Wno-implicit-function-declaration \
       -Wno-int-conversion \
       -Wno-address-of-packed-member
LDFLAGS=-lpthread

HDRS=$(wildcard *.h util/*.h imp_shim/*.h nic_shim/*.h crypto/*.h)

# Shared library sources (common for both variants)
LIB_SRC=$(filter-out uet.c, \
	$(filter-out $(wildcard nic_shim/*xdp*), \
		     $(wildcard *.c \
				util/*.c \
				imp_shim/*.c \
				nic_shim/*.c \
				crypto/*.c)))

# Fabric shared library (ENABLE_VERBS=0)
FABRIC_LIBNAME=uet_fabric
FABRIC_LIB=lib$(FABRIC_LIBNAME).so
FABRIC_LIB_OBJ_DIR=obj_libuet_fabric
FABRIC_LIB_OBJ=$(patsubst %.c, $(FABRIC_LIB_OBJ_DIR)/%.o, $(LIB_SRC))

# Verbs shared library (ENABLE_VERBS=1)
VERBS_LIBNAME=uet_verbs
VERBS_LIB=lib$(VERBS_LIBNAME).so
VERBS_LIB_OBJ_DIR=obj_libuet_verbs
VERBS_LIB_OBJ=$(patsubst %.c, $(VERBS_LIB_OBJ_DIR)/%.o, $(LIB_SRC))

# Compile-only objects used to enforce diagnostics on project sources without
# inheriting compatibility suppressions needed by the standalone application.
STRICT_CFLAGS=$(filter-out -Wno-implicit-function-declaration \
	-Wno-int-conversion,$(CFLAGS)) \
	-Werror=implicit-function-declaration \
	-Werror=int-conversion
STRICT_FABRIC_OBJ_DIR=obj_strict_libuet_fabric
STRICT_FABRIC_OBJ=$(patsubst %.c, $(STRICT_FABRIC_OBJ_DIR)/%.o, $(LIB_SRC))
STRICT_VERBS_OBJ_DIR=obj_strict_libuet_verbs
STRICT_VERBS_OBJ=$(patsubst %.c, $(STRICT_VERBS_OBJ_DIR)/%.o, $(LIB_SRC))

# Main executable
BIN=uet
MAIN_SRC=uet.c
OBJ_DIR=obj_uet
MAIN_OBJ=$(OBJ_DIR)/uet.o

# XDP shared library
XDP_LIBNAME=xdpuet
XDP_LIB=lib$(XDP_LIBNAME).so
XDP_LIB_SRC=$(filter-out uet.c, \
	    $(filter-out nic_shim/*xdp_kern*, \
			 $(wildcard *.c \
				    util/*.c \
				    imp_shim/*.c \
				    nic_shim/*.c \
				    crypto/*.c)))
XDP_LIB_OBJ_DIR=obj_xdp_lib
XDP_LIB_OBJ=$(patsubst %.c, $(XDP_LIB_OBJ_DIR)/%.o, $(XDP_LIB_SRC))

# XDP executable
XDP_BIN=uet_xdp
XDP_MAIN_SRC=uet.c
XDP_OBJ_DIR=obj_xdp
XDP_MAIN_OBJ=$(XDP_OBJ_DIR)/uet.o
XDP_KERN_SRC=$(wildcard nic_shim/*xdp_kern*)
XDP_KERN_BIN=uet_xdp_kern.o

xdp: CFLAGS+=-DENABLE_XDP -DXDP_PROG=$(XDP_KERN_BIN)
xdp: LDFLAGS+=-lbpf -lxdp

CC_SIM_BIN=uet_cc_sim
CC_SIM_SRC=$(wildcard cc/*.c cc_sim/*.c)
CC_SIM_OBJ_DIR=obj_cc_sim
CC_SIM_OBJ=$(patsubst %.c, $(CC_SIM_OBJ_DIR)/%.o, $(CC_SIM_SRC))

# Default target - build both shared libraries and the executable
all: $(FABRIC_LIB) $(VERBS_LIB) $(BIN)

# XDP target
xdp: $(XDP_BIN) $(XDP_KERN_BIN)

# Check project sources with diagnostics that are suppressed for some external
# libfabric headers used by the standalone application.
strict-core: $(STRICT_FABRIC_OBJ) $(STRICT_VERBS_OBJ)

# CC sim target
cc_sim: $(CC_SIM_BIN)

# Fabric library object files (compiled with -fPIC, ENABLE_VERBS=0)
$(FABRIC_LIB_OBJ_DIR)/%.o: %.c $(HDRS)
	@mkdir -p $(FABRIC_LIB_OBJ_DIR)/$(dir $<)
	@echo 'Building fabric library object: $<'
	@$(CC) $(CFLAGS) -DENABLE_VERBS=0 $(INCS) $(LF_LOCAL_HDRS) -fPIC -c -o $@ $<

# Fabric shared library
$(FABRIC_LIB): $(FABRIC_LIB_OBJ)
	@echo 'Building fabric shared library: $@'
	@$(CC) -shared $(FABRIC_LIB_OBJ) -o $@ $(LDFLAGS)

# Verbs library object files (compiled with -fPIC, ENABLE_VERBS=1)
$(VERBS_LIB_OBJ_DIR)/%.o: %.c $(HDRS)
	@mkdir -p $(VERBS_LIB_OBJ_DIR)/$(dir $<)
	@echo 'Building verbs library object: $<'
	@$(CC) $(CFLAGS) -DENABLE_VERBS=1 $(INCS) $(LF_LOCAL_HDRS) -fPIC -c -o $@ $<

# Verbs shared library
$(VERBS_LIB): $(VERBS_LIB_OBJ)
	@echo 'Building verbs shared library: $@'
	@$(CC) -shared $(VERBS_LIB_OBJ) -o $@ $(LDFLAGS)

$(STRICT_FABRIC_OBJ_DIR)/%.o: %.c $(HDRS)
	@mkdir -p $(STRICT_FABRIC_OBJ_DIR)/$(dir $<)
	@echo 'Strict-checking fabric library object: $<'
	@$(CC) $(STRICT_CFLAGS) -DENABLE_VERBS=0 $(INCS) $(LF_LOCAL_HDRS) \
		-fPIC -c -o $@ $<

$(STRICT_VERBS_OBJ_DIR)/%.o: %.c $(HDRS)
	@mkdir -p $(STRICT_VERBS_OBJ_DIR)/$(dir $<)
	@echo 'Strict-checking verbs library object: $<'
	@$(CC) $(STRICT_CFLAGS) -DENABLE_VERBS=1 $(INCS) $(LF_LOCAL_HDRS) \
		-fPIC -c -o $@ $<

# XDP shared library object files (compiled with -fPIC) (w/ extra CFLAGS)
$(XDP_LIB_OBJ_DIR)/%.o: %.c $(HDRS)
	@mkdir -p $(XDP_LIB_OBJ_DIR)/$(dir $<)
	@echo 'Building XDP library object: $<'
	@$(CC) $(CFLAGS) $(INCS) $(LF_LOCAL_HDRS) -fPIC -c -o $@ $<

# XDP shared library (w/ extra LDFLAGS)
$(XDP_LIB): $(XDP_LIB_OBJ)
	@echo 'Building XDP shared library: $@'
	@$(CC) -shared $(XDP_LIB_OBJ) -o $@ $(LDFLAGS)

# Main executable object file
$(OBJ_DIR)/%.o: %.c $(HDRS)
	@mkdir -p $(OBJ_DIR)/$(dir $<)
	@echo 'Building file: $<'
	@$(CC) $(CFLAGS) $(INCS) $(LF_HDRS) -c -o $@ $<

# Main executable (links against fabric shared library)
$(BIN): $(FABRIC_LIB) $(MAIN_OBJ)
	@echo 'Building program: $@'
	@$(CC) $(MAIN_OBJ) -o $@ -L. -l$(FABRIC_LIBNAME) $(LDFLAGS) $(LF_LIBS)

# XDP executable object file (w/ extra CFLAGS)
$(XDP_OBJ_DIR)/%.o: %.c $(HDRS)
	@mkdir -p $(XDP_OBJ_DIR)/$(dir $<)
	@echo 'Building XDP file: $<'
	@$(CC) $(CFLAGS) $(INCS) $(LF_HDRS) -c -o $@ $<

# XDP executable (links against XDP shared library) (w/ extra LDFLAGS)
$(XDP_BIN): $(XDP_LIB) $(XDP_MAIN_OBJ)
	@echo 'Building XDP program: $@'
	@$(CC) $(XDP_MAIN_OBJ) -o $@ -L. -l$(XDP_LIBNAME) $(LDFLAGS) $(LF_LIBS)

$(XDP_KERN_BIN): $(XDP_KERN_SRC)
	@echo 'Building XDP kernel program: $@'
	@$(CLANG) -O2 -g -Wall -target bpf \
		  -I/usr/include/$(shell uname -m)-linux-gnu \
		  -c -o $(XDP_KERN_BIN) $(XDP_KERN_SRC)

$(CC_SIM_OBJ_DIR)/%.o: %.c $(HDRS)
	@mkdir -p $(CC_SIM_OBJ_DIR)/$(dir $<)
	@echo 'Building file: $<'
	@$(CC) $(CFLAGS) $(INCS) -c -o $@ $<

$(CC_SIM_BIN): $(CC_SIM_OBJ)
	@echo 'Building program: $@'
	@$(CC) $(CC_SIM_OBJ) -o $@ $(LDFLAGS)

clean:
	@rm -rf $(FABRIC_LIB_OBJ_DIR) $(FABRIC_LIB) \
		$(VERBS_LIB_OBJ_DIR) $(VERBS_LIB) \
		$(STRICT_FABRIC_OBJ_DIR) $(STRICT_VERBS_OBJ_DIR) \
		$(OBJ_DIR) $(BIN) \
		$(XDP_LIB_OBJ_DIR) $(XDP_LIB) \
		$(XDP_OBJ_DIR) $(XDP_BIN) \
		$(XDP_KERN_BIN) \
		$(CC_SIM_OBJ_DIR) $(CC_SIM_BIN)

.PHONY: all xdp strict-core cc_sim clean
