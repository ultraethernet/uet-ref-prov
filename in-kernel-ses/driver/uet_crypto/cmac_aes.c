/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#include <stdlib.h>
#include <string.h>
#include "aes.h"
#include "cmac_aes.h"

static void BLOCK_XOR(uint8_t *dst,
		      uint8_t *a,
		      uint8_t *b)
{
	int i;

	for (i = 0; i < BLOCK_SIZE; i++)
		dst[i] = (a[i] ^ b[i]);
}

static void BLOCK_LSHIFT(uint8_t *dst,
			 uint8_t *src)
{
	uint8_t overflow = 0;
	int i;

	for (i = (BLOCK_SIZE - 1); i >= 0; i--) {
		dst[i] = (src[i] << 1);
		dst[i] |= overflow;
		overflow = (src[i] & 0x80) ? 1 : 0;
	}
}

static void generate_subkeys(uint8_t *key,
			     uint32_t keybits,
			     uint8_t *k1,
			     uint8_t *k2)
{
	struct aes_context aes_ctx;
	uint8_t rb[BLOCK_SIZE];
	uint8_t l[BLOCK_SIZE];

	memset(rb, 0, sizeof(rb));
	rb[BLOCK_SIZE - 1] = 0x87;

	memset(l, 0, sizeof(l));

	aes_init(&aes_ctx);
	aes_setkey_enc(&aes_ctx, key, keybits);
	aes_encrypt(&aes_ctx, l, l);

	BLOCK_LSHIFT(k1, l);
	if (l[0] & 0x80)
		BLOCK_XOR(k1, k1, rb);

	BLOCK_LSHIFT(k2, k1);
	if (k1[0] & 0x80)
		BLOCK_XOR(k2, k2, rb);
}

void cmac_aes(uint8_t *key,
	      uint32_t keybits,
	      uint8_t *in,
	      uint32_t len,
	      uint8_t *out)
{
	struct aes_context aes_ctx;
	uint8_t k1[BLOCK_SIZE];
	uint8_t k2[BLOCK_SIZE];
	uint8_t *cur_block;
	uint8_t *last_block;
	uint8_t *m;
	int aligned = 0;
	int i, n;

	generate_subkeys(key, keybits, k1, k2);

	if (len == 0) {
		n = 1;
	} else {
		n = (len / BLOCK_SIZE);
		if ((len % BLOCK_SIZE) == 0)
			aligned = 1;
		else
			n++;
	}

	m = calloc(1, (n * BLOCK_SIZE));
	memcpy(m, in, len);

	last_block = (m + ((n - 1) * BLOCK_SIZE));
	if (aligned) {
		BLOCK_XOR(last_block, last_block, k1);
	} else {
		m[len] = 0x80;
		BLOCK_XOR(last_block, last_block, k2);
	}

	aes_init(&aes_ctx);
	aes_setkey_enc(&aes_ctx, key, keybits);

	aes_encrypt(&aes_ctx, m, out);
	for (i = 1; i < n; i++) {
		cur_block = (m + (i * BLOCK_SIZE));
		BLOCK_XOR(cur_block, cur_block, out);
		aes_encrypt(&aes_ctx, cur_block, out);
	}

	free(m);
}

int cmac_aes_verify(uint8_t *key,
		    uint32_t keybits,
		    uint8_t *in,
		    uint32_t len,
		    uint8_t *expected)
{
	uint8_t result[BLOCK_SIZE];

	cmac_aes(key, keybits, in, len, (uint8_t *)result);

	return !memcmp(result, expected, BLOCK_SIZE);
}

