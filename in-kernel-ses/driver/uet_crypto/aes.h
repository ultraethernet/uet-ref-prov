/*
 *  FIPS-197 compliant AES implementation
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

#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>

#define AES_ENCRYPT(ctx, buf) aes_encrypt((ctx), (buf), (buf))
#define AES_DECRYPT(ctx, buf) aes_decrypt((ctx), (buf), (buf))

/*
 * AES context structure
 * buf is able to hold 32 extra bytes, which can be used:
 *   - for alignment purposes if VIA padlock is used, and/or
 *   - to simplify key expansion in the 256-bit case by
 *     generating an extra round key
 */
struct aes_context {
	int nr;           /* number of rounds */
	uint32_t *rk;     /* AES round keys */
	uint32_t buf[68]; /* unaligned data */
};

void aes_init(struct aes_context *ctx);

/*
 * AES key schedule (encryption)
 * ctx      AES context to be initialized
 * key      encryption key
 * keybits  must be 128, 192 or 256
 */
int aes_setkey_enc(struct aes_context *ctx,
		   const uint8_t *key,
		   uint32_t keybits);

/*
 * AES key schedule (decryption)
 * ctx      AES context to be initialized
 * key      decryption key
 * keybits  must be 128, 192 or 256
 */
int aes_setkey_dec(struct aes_context *ctx,
		   const uint8_t *key,
		   uint32_t keybits);

/*
 * AES block encryption function
 * ctx     AES context
 * input   Plaintext block
 * output  Output (ciphertext) block
 */
void aes_encrypt(struct aes_context *ctx,
		 const uint8_t input[16],
		 uint8_t output[16]);

/*
 * AES block decryption function
 * ctx     AES context
 * input   Ciphertext block
 * output  Output (plaintext) block
 */
void aes_decrypt(struct aes_context *ctx,
		 const uint8_t input[16],
		 uint8_t output[16]);

#endif /* _AES_H_ */

