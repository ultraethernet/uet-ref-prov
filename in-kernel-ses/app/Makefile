

CC=gcc
RANLIB=ranlib
AR=ar
CLANG=clang


CFLAGS=-Wall                              \
       -Wno-unused-variable               \
       -Wno-implicit-function-declaration \
       -Wno-int-conversion                \
       -Wno-address-of-packed-member

LIBFABRIC=../../../libfabric
INCS=-I$(LIBFABRIC) -I$(LIBFABRIC)/include -I. -I../driver/include
LDFLAGS=-L$(LIBFABRIC)/src/.libs -lfabric


%.o: %.c
	$(CC) $(CFLAGS) $(INCS) -c -o $@ $<

uet: uet.o uet_api.o
	$(CC) uet.o uet_api.o -o $@ $(LDFLAGS)


all: uet

clean:
	rm -rf *.o uet
