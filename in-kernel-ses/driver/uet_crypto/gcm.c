/*
 *  NIST SP800-38D compliant GCM implementation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 * - Original code modifications: refactoring and API simplifications
 */

#include <string.h>
#include "gcm.h"

/* Implementation that should never be optimized out by the compiler */
static inline void zeroize(void *v, size_t n)
{
	volatile uint8_t *p = v;

	if (v == NULL)
		return;

	while (n--)
		*p++ = 0;
}

/* 32-bit integer manipulation macros (big endian) */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n, b, i)                  \
{                                               \
	(n) = (((uint32_t)(b)[(i)]     << 24) | \
	       ((uint32_t)(b)[(i) + 1] << 16) | \
	       ((uint32_t)(b)[(i) + 2] <<  8) | \
	       ((uint32_t)(b)[(i) + 3]));       \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n, b, i)               \
{                                            \
	(b)[(i)]     = (uint8_t)((n) >> 24); \
	(b)[(i) + 1] = (uint8_t)((n) >> 16); \
	(b)[(i) + 2] = (uint8_t)((n) >>  8); \
	(b)[(i) + 3] = (uint8_t)((n));       \
}
#endif

/* first ciphertext block has ctr=2 */
#define BLOCK_CTR(offset) (((offset) / 16) + 2)
#define VALID_BLOCK(offset) (((offset) % 16) == 0)

void gcm_init(struct gcm_context *ctx)
{
	memset(ctx, 0, sizeof(struct gcm_context));
}

void gcm_free(struct gcm_context *ctx)
{
	zeroize(ctx, sizeof(struct gcm_context));
}

int gcm_setkey(struct gcm_context *ctx,
	       const uint8_t *key,
	       uint32_t keybits)
{
	if ((keybits != 128) && (keybits != 192) && (keybits != 256))
		return -1;

	aes_init(&ctx->aes_ctx);
	if (aes_setkey_enc(&ctx->aes_ctx, key, keybits) != 0)
		return -1;

	memset(ctx->h, 0, 16);
	AES_ENCRYPT(&ctx->aes_ctx, ctx->h);

	return 0;
}

static void shift_right_block(uint8_t *v)
{
	uint32_t val;

	GET_UINT32_BE(val, v, 12);
	val >>= 1;
	if (v[11] & 0x01)
		val |= 0x80000000;
	PUT_UINT32_BE(val, v, 12);

	GET_UINT32_BE(val, v, 8);
	val >>= 1;
	if (v[7] & 0x01)
		val |= 0x80000000;
	PUT_UINT32_BE(val, v, 8);

	GET_UINT32_BE(val, v, 4);
	val >>= 1;
	if (v[3] & 0x01)
		val |= 0x80000000;
	PUT_UINT32_BE(val, v, 4);

	GET_UINT32_BE(val, v, 0);
	val >>= 1;
	PUT_UINT32_BE(val, v, 0);
}

static void xor_block(uint8_t *dst, const uint8_t *src)
{
	uint32_t *d = (uint32_t *)dst;
	uint32_t *s = (uint32_t *)src;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
}

/* Multiplication in GF(2^128) */
static void gcm_mult(const uint8_t x[16],
		     const uint8_t y[16],
		     uint8_t output[16])
{
	uint8_t v[16];
	uint8_t z[16];
	int i, j;

	memset(z, 0, 16); /* Z_0 = 0^128 */
	memcpy(v, y, 16); /* V_0 = Y */

	for (i = 0; i < 16; i++) {
		for (j = 0; j < 8; j++) {
			if (x[i] & (1 << (7 - j))) {
				/* Z_(i + 1) = Z_i XOR V_i */
				xor_block(z, v);
			} else {
				/* Z_(i + 1) = Z_i */
			}

			if (v[15] & 0x01) {
				/* V_(i + 1) = (V_i >> 1) XOR R */
				shift_right_block(v);
				/* R = 11100001 || 0^120 */
				v[0] ^= 0xe1;
			} else {
				/* V_(i + 1) = V_i >> 1 */
				shift_right_block(v);
			}
		}
	}

	memcpy(output, z, 16);
}

int gcm_start(struct gcm_context *ctx,
	      int mode,
	      const uint8_t *iv,
	      size_t iv_len,
	      const uint8_t *aad,
	      size_t aad_len)
{
	size_t i;
	const uint8_t *p;
	size_t use_len;

	/* IV and AAD are limited to 2^64 bits, so 2^61 bytes */
	if ((iv_len != 12) ||
	    (((uint64_t)aad_len >> 61) != 0))
		return -1;

	memset(ctx->iv, 0, sizeof(ctx->iv));
	memset(ctx->hash, 0, sizeof(ctx->hash));

	ctx->mode = mode;

	memcpy(ctx->iv, iv, iv_len);

	p = aad;
	while (aad_len > 0) {
		use_len = (aad_len < 16) ? aad_len : 16;

		for (i = 0; i < use_len; i++)
			ctx->hash[i] ^= p[i];

		gcm_mult(ctx->h, ctx->hash, ctx->hash);

		aad_len -= use_len;
		p += use_len;
	}

	return 0;
}

/*
 * Process a single block by generating the ciphertext/plaintext output
 * and updating the current hash value. Note that the caller must make sure
 * (byte_offset + num_bytes) <= 16
 */
static void gcm_proc_block(int mode,
			   uint8_t *hash,
			   size_t byte_offset,
			   size_t num_bytes,
			   const uint8_t *ectr,
			   const uint8_t *input,
			   uint8_t *output)
{
	size_t i;

	for (i = 0; i < num_bytes; i++) {
		if (mode == GCM_DECRYPT) {
			/* update the hash: decryption input = ciphertext */
			hash[byte_offset + i] ^= input[i];
		}

		output[i] = (ectr[byte_offset + i] ^ input[i]);

		if (mode == GCM_ENCRYPT) {
			/* update the hash: encryption output = ciphertext */
			hash[byte_offset + i] ^= output[i];
		}
	}
}

/* Prepare and encrypt the IV/counter value based on the byte offset. */
static void gcm_iv_ctr(struct gcm_context *ctx,
		       size_t offset,
		       uint8_t *ectr)
{
	/* prepare the iv/ctr for encrypting this block */
	memcpy(ectr, ctx->iv, 12);
	PUT_UINT32_BE((offset == 1) ? 1 : BLOCK_CTR(offset), ectr, 12);

	/* encrypt the iv/ctr */
	AES_ENCRYPT(&ctx->aes_ctx, ectr);
}

/*
 * Current hash: ctx->hash = Y_n-1
 *
 * X_n = all block bytes
 * A_n = partial block bytes in 1st pkt (right padded zeros)
 * B_n = remaining partial block bytes in 2nd pkt (left padded zeros)
 *
 * X_n = (A_n ^ B_n)
 * Y_n = (Y_n-1 ^ X_n) * H
 *     = (Y_n-1 ^ A_n ^ B_n) * H
 *     = ((Y_n-1 ^ A_n) * H) ^ (B_n * H)
 *
 * X_n = all block bytes
 * A_n = partial block bytes in 1st pkt (right padded zeros)
 * B_n = middle partial block bytes in 2nd pkt (left/right padded zeros)
 * C_n = remaining partial block bytes in 3rd pkt (left padded zeros)
 *
 * X_n = (A_n ^ B_n ^ C_n)
 * Y_n = (Y_n-1 ^ X_n) * H
 *     = (Y_n-1 ^ A_n ^ B_n ^ C_n) * H
 *     = ((Y_n-1 ^ A_n) * H) ^ (B_n * H) ^ (C_n * H)
 */

int gcm_update(struct gcm_context *ctx,
	       size_t offset,
	       size_t length,
	       const uint8_t *input,
	       uint8_t *output)
{
	uint8_t ectr[16];
	uint8_t hash[16];
	size_t partial_offset;
	size_t partial_length;

	if (!length)
		return 0; /* all done */

	/*
	 * If the data doesn't start at a multiple of the block size or the
	 * length is less than a single block, treat these bytes as a partial.
	 */
	if (!VALID_BLOCK(offset) || (length < 16)) {
		/*
		 * Adjust the offset to the floor of the block size. Note that
		 * this bit masking works since the block size (16B) is a power
		 * of two.
		 */
		partial_offset = (offset % 16);
		partial_length =
			(length > (16 - partial_offset))
			    ? (16 - partial_offset) : length;
		offset &= ~(16 - 1);

		/* prepare the iv/ctr for encrypting this block */
		gcm_iv_ctr(ctx, offset, ectr);

		memset(hash, 0, 16);

		gcm_proc_block(ctx->mode, hash, partial_offset,
			       partial_length, ectr, input, output);

		/* update Y_n (roll the computed hash into the current hash) */
		if (partial_offset == 0) {
			/* Y_n = ((Y_n-1 ^ A_n) * H) */
			xor_block(ctx->hash, hash);
			gcm_mult(ctx->h, ctx->hash, ctx->hash);
		} else {
			/* Y_n = (Y_n ^ (B_n * H)) ... */
			gcm_mult(ctx->h, hash, hash);
			xor_block(ctx->hash, hash);
		}

		/* skip to the next block */
		length -= partial_length;
		input += partial_length;
		output += partial_length;
		offset += 16;
	}

	if (!length)
		return 0; /* all done */

	/* process all the full sized blocks */
	while (length >= 16) {
		/* prepare the iv/ctr for encrypting this block */
		gcm_iv_ctr(ctx, offset, ectr);

		gcm_proc_block(ctx->mode, ctx->hash, 0, 16, ectr, input, output);

		gcm_mult(ctx->h, ctx->hash, ctx->hash);

		length -= 16;
		input += 16;
		output += 16;
		offset += 16;
	}

	if (!length)
		return 0; /* all done */

	/*
	 * If there is still a remaining length (i.e. < 16B) then we have to
	 * process this block as the start of a new partial.
	 */

	/* prepare the iv/ctr for encrypting this block */
	gcm_iv_ctr(ctx, offset, ectr);

	memset(hash, 0, 16);

	gcm_proc_block(ctx->mode, hash, 0, length, ectr, input, output);

	/* update Y_n (roll the computed hash into the current hash) */
	/* Y_n = ((Y_n-1 ^ A_n) * H) */
	xor_block(ctx->hash, hash);
	gcm_mult(ctx->h, ctx->hash, ctx->hash);

	return 0;
}

int gcm_finish(struct gcm_context *ctx,
	       size_t total_data_len,
	       size_t aad_len,
	       uint8_t *tag,
	       size_t tag_len)
{
	uint8_t work_buf[16];
	uint64_t orig_len = (total_data_len * 8);
	uint64_t orig_aad_len = (aad_len * 8);

	if (tag_len > 16 || tag_len < 4)
		return -1;

	if (tag_len != 0) {
		/* prepare the iv/ctr for encrypting this block */
		gcm_iv_ctr(ctx, 1, work_buf);

		memcpy(tag, work_buf, tag_len);
	}

	if (orig_len || orig_aad_len) {
		memset(work_buf, 0, 16);

		PUT_UINT32_BE((orig_aad_len >> 32), work_buf,  0);
		PUT_UINT32_BE((orig_aad_len),       work_buf,  4);
		PUT_UINT32_BE((orig_len >> 32),     work_buf,  8);
		PUT_UINT32_BE((orig_len),           work_buf, 12);

		xor_block(ctx->hash, work_buf);

		gcm_mult(ctx->h, ctx->hash, ctx->hash);

		xor_block(tag, ctx->hash);
	}

	return 0;
}

int gcm_crypt_and_tag(struct gcm_context *ctx,
		      int mode,
		      size_t length,
		      const uint8_t *iv,
		      size_t iv_len,
		      const uint8_t *aad,
		      size_t aad_len,
		      const uint8_t *input,
		      uint8_t *output,
		      size_t tag_len,
		      uint8_t *tag)
{
	int ret;

	ret = gcm_start(ctx, mode, iv, iv_len, aad, aad_len);
	if (ret != 0)
		return ret;

	ret = gcm_update(ctx, 0, length, input, output);
	if (ret != 0)
		return ret;

	ret = gcm_finish(ctx, length, aad_len, tag, tag_len);
	if (ret != 0)
		return ret;

	return 0;
}

int gcm_auth_decrypt(struct gcm_context *ctx,
		     size_t length,
		     const uint8_t *iv,
		     size_t iv_len,
		     const uint8_t *aad,
		     size_t aad_len,
		     const uint8_t *tag,
		     size_t tag_len,
		     const uint8_t *input,
		     uint8_t *output)
{
	int ret;
	uint8_t check_tag[16];
	size_t i;
	int diff;

	ret = gcm_crypt_and_tag(ctx, GCM_DECRYPT, length, iv, iv_len,
				aad, aad_len, input, output, tag_len,
				check_tag);
	if (ret != 0)
		return ret;

	for (diff = 0, i = 0; i < tag_len; i++)
		diff |= (tag[i] ^ check_tag[i]);

	if (diff != 0) {
		zeroize(output, length);
		return -1;
	}

	return 0;
}

