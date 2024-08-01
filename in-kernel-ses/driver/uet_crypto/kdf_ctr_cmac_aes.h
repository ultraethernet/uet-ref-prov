/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#ifndef _KDF_CTR_CMAC_AES_
#define _KDF_CTR_CMAC_AES_

#include <stdint.h>

void kdf_ctr_cmac_aes_fixed(uint8_t *key,
			    uint32_t keybits,
			    uint32_t ctr_len,
			    uint8_t *fixed,
			    uint32_t fixed_len,
			    uint8_t *key_out,
			    uint32_t keybits_out);

void kdf_ctr_cmac_aes(uint8_t *key,
		      uint32_t keybits,
		      uint32_t ctr_len,
		      uint8_t *label,
		      uint32_t label_len,
		      uint8_t *context,
		      uint32_t context_len,
		      uint8_t *key_out,
		      uint32_t keybits_out);

#endif /* _KDF_CTR_CMAC_AES_ */

