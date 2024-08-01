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

#ifndef _GCM_H_
#define _GCM_H_

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "aes.h"

#define GCM_ENCRYPT 1
#define GCM_DECRYPT 0

/* GCM context structure */
struct gcm_context {
	struct aes_context aes_ctx;  /* AES context used */
	uint8_t h[16];        /* H */
	uint8_t iv[12];       /* IV/nonce */
	uint8_t hash[16];     /* authentication hash working value */
	int mode;             /* GCM_ENCRYPT or GCM_DECRYPT */
};

void gcm_init(struct gcm_context *ctx);
void gcm_free(struct gcm_context *ctx);

/*
 * GCM initialization (encryption)
 * ctx       GCM context to be initialized
 * key       encryption key
 * keybits   must be 128, 192 or 256
 */
int gcm_setkey(struct gcm_context *ctx,
	       const uint8_t *key,
	       uint32_t keybits);

/*
 * GCM buffer encryption/decryption using AES
 *
 * On encryption, the output buffer can be the same as the input buffer.
 * On decryption, the output buffer cannot be the same as input buffer.
 * If buffers overlap, the output buffer must trail at least 8 bytes
 * behind the input buffer.
 *
 * ctx       GCM context
 * mode      GCM_ENCRYPT or GCM_DECRYPT
 * length    length of the input data
 * iv        initialization vector
 * iv_len    length of IV
 * aad       additional data
 * aad_len   length of additional data
 * input     buffer holding the input data
 * output    buffer for holding the output data
 * tag_len   length of the tag to generate
 * tag       buffer for holding the tag
 */
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
		      uint8_t *tag);

/*
 * GCM buffer authenticated decryption using AES
 *
 * On decryption, the output buffer cannot be the same as input buffer.
 * If buffers overlap, the output buffer must trail at least 8 bytes
 * behind the input buffer.
 *
 * ctx       GCM context
 * length    length of the input data
 * iv        initialization vector
 * iv_len    length of IV
 * aad       additional data
 * aad_len   length of additional data
 * tag       buffer holding the tag
 * tag_len   length of the tag
 * input     buffer holding the input data
 * output    buffer for holding the output data
 */
int gcm_auth_decrypt(struct gcm_context *ctx,
		     size_t length,
		     const uint8_t *iv,
		     size_t iv_len,
		     const uint8_t *aad,
		     size_t aad_len,
		     const uint8_t *tag,
		     size_t tag_len,
		     const uint8_t *input,
		     uint8_t *output);

/*
 * Generic GCM stream start function
 *
 * ctx       GCM context
 * mode      GCM_ENCRYPT or GCM_DECRYPT
 * iv        initialization vector
 * iv_len    length of IV
 * aad       additional data (or NULL if length is 0)
 * aad_len   length of additional data
 *
 * total_data_len  total length of plaintext/ciphertext
 */
int gcm_start(struct gcm_context *ctx,
	      int mode,
	      const uint8_t *iv,
	      size_t iv_len,
	      const uint8_t *aad,
	      size_t aad_len);

/*
 * Generic GCM update function. Encrypts/decrypts using the
 * given GCM context. Expects input to be a multiple of 16
 * bytes and only the last call before gcm_finish() can be less
 * than 16 bytes.
 *
 * On decryption, the output buffer cannot be the same as input buffer.
 * If buffers overlap, the output buffer must trail at least 8 bytes
 * behind the input buffer.
 *
 * ctx      GCM context
 * offset   stream byte offset
 * length   length of the input data
 * input    buffer holding the input data
 * output   buffer for holding the output data
 *
 * total_data_len  total length of plaintext/ciphertext
 */
int gcm_update(struct gcm_context *ctx,
	       size_t offset,
	       size_t length,
	       const uint8_t *input,
	       uint8_t *output);

/*
 * Generic GCM finalization function. Wraps up the GCM stream
 * and generates the tag. The tag can have a maximum length of
 * 16 bytes.
 *
 * ctx             GCM context
 * total_data_len  total data length
 * aad_len         length of additional data
 * tag             buffer for holding the tag (may be NULL if tag_len is 0)
 * tag_len         length of the tag to generate
 */
int gcm_finish(struct gcm_context *ctx,
	       size_t total_data_len,
	       size_t aad_len,
	       uint8_t *tag,
	       size_t tag_len);

#endif /* _GCM_H_ */

