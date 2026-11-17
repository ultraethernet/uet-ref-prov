
CC=gcc

INCS=-I. -I../../util
CFLAGS=-Wall -Wextra -g
LDFLAGS=

BIN=bitmap_test
SRC=test_bitmap.c ../../util/bitmap.c
HDRS=../../util/bitmap.h
CRC_BIN=crc32c_test

$(BIN): $(SRC) $(HDRS)
	@echo 'Building program: $@'
	@$(CC) $(CFLAGS) $(INCS) $(SRC) -o $@ $(LDFLAGS)

$(CRC_BIN): test_crc32c.c ../../util/crc32c.c ../../util/crc32c.h
	@echo 'Building program: $@'
	@$(CC) $(CFLAGS) $(INCS) test_crc32c.c ../../util/crc32c.c -o $@ $(LDFLAGS)

all: $(BIN) $(CRC_BIN)

test: all
	@./$(BIN)
	@./$(CRC_BIN)

clean:
	@rm -rf $(BIN) $(CRC_BIN)

.PHONY: all test clean
