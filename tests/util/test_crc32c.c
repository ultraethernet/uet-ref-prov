// SPDX-License-Identifier: BSD-2-Clause
/* Compare the public API to an independent bitwise CRC32C implementation. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "crc32c.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

static unsigned int checks;

#define CHECK(condition) do { \
	checks++; \
	if (!(condition)) { \
		fprintf(stderr, "CRC32C check failed at line %d\n", __LINE__); \
		exit(1); \
	} \
} while (0)

static uint32_t reference(uint32_t crc, const uint8_t *data, uint32_t length)
{
	while (length--) {
		crc ^= *data++;
		for (unsigned int bit = 0; bit < 8; bit++)
			crc = (crc >> 1) ^ ((crc & 1) ? UINT32_C(0x82f63b78) : 0);
	}
	return crc;
}

static void check_buffer(const uint8_t *data, uint32_t length)
{
	const uint32_t seeds[] = { 0, UINT32_MAX, UINT32_C(0x12345678) };
	uint32_t split = length / 3;
	uint32_t expected;

	for (unsigned int i = 0; i < ARRAY_SIZE(seeds); i++) {
		expected = reference(seeds[i], data, length);
		CHECK(crc32c_update(seeds[i], data, length) == expected);
		CHECK(crc32c_update(crc32c_update(seeds[i], data, split),
				    data + split, length - split) == expected);
		CHECK(crc32c_update(expected, NULL, 0) == expected);
	}
	expected = reference(UINT32_MAX, data, length);
	CHECK(crc32c(data, length) == htonl(~expected));
	CHECK(crc32c_finish(expected) == htonl(~expected));
}

int main(void)
{
	const uint32_t lengths[] = { 511, 512, 513, 1499, 1500, 1501,
		4095, 4096, 4097, 65535, 65536 };
	uint8_t *buffer = malloc(65536 + 16);
	uint32_t random = 1;
	long page = sysconf(_SC_PAGESIZE);
	uint8_t *guard;
	const uint8_t golden[] = { 0xe3, 0x06, 0x92, 0x83 };
	uint32_t crc;

	CHECK(buffer != NULL && page >= 256);
	CHECK(crc32c_init() == UINT32_MAX);
	CHECK(crc32c(NULL, 0) == 0);
	crc = crc32c((const uint8_t *)"123456789", 9);
	CHECK(memcmp(&crc, golden, sizeof(golden)) == 0);
	for (unsigned int pattern = 0; pattern < 4; pattern++) {
		for (unsigned int i = 0; i < 65536 + 16; i++) {
			random ^= random << 13;
			random ^= random >> 17;
			random ^= random << 5;
			buffer[i] = pattern == 0 ? 0 : pattern == 1 ? 255 :
				    pattern == 2 ? (uint8_t)i : (uint8_t)random;
		}
		for (unsigned int offset = 0; offset < 16; offset++) {
			for (unsigned int length = 0; length <= 256; length++)
				check_buffer(buffer + offset, length);
			for (unsigned int i = 0; i < ARRAY_SIZE(lengths); i++)
				check_buffer(buffer + offset, lengths[i]);
		}
	}
	/* Every short tail ends immediately before an inaccessible page. */
	guard = mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(guard != MAP_FAILED);
	memset(guard, 0xa5, (size_t)page);
	CHECK(mprotect(guard + page, (size_t)page, PROT_NONE) == 0);
	for (unsigned int length = 0; length <= 256; length++)
		check_buffer(guard + page - length, length);
	CHECK(munmap(guard, (size_t)page * 2) == 0);
	free(buffer);
	printf("CRC32C: %u checks passed\n", checks);
	return 0;
}
