/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include "cmac_aes.h"
#include "kdf_ctr_cmac_aes.h"

void kdf_ctr_cmac_aes_fixed(uint8_t *key,
			    uint32_t keybits,
			    uint32_t ctr_len,
			    uint8_t *fixed,
			    uint32_t fixed_len,
			    uint8_t *key_out,
			    uint32_t keybits_out)
{
	uint8_t *tmp_fixed;
	uint32_t tmp_fixed_len;
	uint8_t *k_out;
	uint32_t i, be_i, n;

	// don't be lame
	assert((ctr_len % 8) == 0);
	assert((keybits_out % 8) == 0);

	n = (keybits_out / BLOCK_SIZE);
	if ((keybits_out % BLOCK_SIZE) != 0)
		n++;

	tmp_fixed_len = ((ctr_len / 8) + fixed_len);
	tmp_fixed = calloc(1, tmp_fixed_len);
	memcpy((tmp_fixed + (ctr_len / 8)), fixed, fixed_len);

	k_out = calloc(1, (n * BLOCK_SIZE));

	for (i = 0; i < n; i++) {
		be_i = htonl(i + 1);
		switch (ctr_len) {
		case 8:
			memcpy(tmp_fixed, ((uint8_t *)&be_i + 3), 1);
			break;
		case 16:
			memcpy(tmp_fixed, ((uint8_t *)&be_i + 2), 2);
			break;
		case 24:
			memcpy(tmp_fixed, ((uint8_t *)&be_i + 1), 3);
			break;
		case 32:
			memcpy(tmp_fixed, (uint32_t *)&be_i, 4);
			break;
		default:
			assert(0);
			break;
		}

		cmac_aes(key, keybits, tmp_fixed, tmp_fixed_len,
			 (k_out + (i * BLOCK_SIZE)));
	}

	memcpy(key_out, k_out, (keybits_out / 8));

	free(tmp_fixed);
	free(k_out);
}

void kdf_ctr_cmac_aes(uint8_t *key,
		      uint32_t keybits,
		      uint32_t ctr_len,
		      uint8_t *label,
		      uint32_t label_len,
		      uint8_t *context,
		      uint32_t context_len,
		      uint8_t *key_out,
		      uint32_t keybits_out)
{
	uint8_t *fixed;
	uint32_t fixed_len;
	uint32_t be_keybits_out;

	// don't be lame
	assert((ctr_len % 8) == 0);
	assert((keybits_out % 8) == 0);

	fixed_len = (label_len +
		     1 + // 0x00
		     context_len +
		     sizeof(uint32_t));
	fixed = calloc(1, fixed_len);

	memcpy(fixed, label, label_len);
	memcpy((fixed + label_len + 1), context, context_len);

	be_keybits_out = htonl(keybits_out);
	memcpy((fixed + label_len + 1 + context_len),
	       (uint8_t *)&be_keybits_out,
	       sizeof(uint32_t));

	kdf_ctr_cmac_aes_fixed(key,
			       keybits,
			       ctr_len,
			       fixed,
			       fixed_len,
			       key_out,
			       keybits_out);

	free(fixed);
}

