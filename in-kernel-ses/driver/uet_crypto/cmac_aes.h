/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#ifndef _CMAC_AES_H_
#define _CMAC_AES_H_

#include <stdint.h>

#define BLOCK_SIZE 16

void cmac_aes(uint8_t *key,
	      uint32_t keybits,
	      uint8_t *in,
	      uint32_t len,
	      uint8_t *out);

int cmac_aes_verify(uint8_t *key,
		    uint32_t keybits,
		    uint8_t *in,
		    uint32_t len,
		    uint8_t *out);

#endif /* _CMAC_AES_H_ */

