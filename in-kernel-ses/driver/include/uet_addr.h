/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* UET Address Format Definitions */

#ifndef _UET_ADDR_H_
#define _UET_ADDR_H_

#include <stdint.h>

	/* TODO: remove defaults when address resolution is implemented */
#define UET_ADDR_DEF_PID_ON_FEP		0
#define UET_ADDR_DEF_INDEX		15
#define UET_ADDR_DEF_INITIATOR_ID	16

#define UET_ADDR_VERSION	0

#define UET_ADDR_VER_MASK	0xf0
#define UET_ADDR_VER_SHIFT	4

#define UET_IPV6_ADDR_OCTETS	16

/* uet fabric address */
struct uet_fa {
	union {
		uint32_t v4;
		uint8_t v6[UET_IPV6_ADDR_OCTETS];
	};
};

/* uet address */
struct uet_addr {
	uint8_t ver;
#define UET_ADDR_FEP_CAP_V	(1 << 0)
#define UET_ADDR_FA_V		(1 << 1)
#define UET_ADDR_PID_ON_FEP_V	(1 << 2)
#define UET_ADDR_INDEX_V	(1 << 3)
#define UET_ADDR_INITIATOR_V	(1 << 4)
#define UET_ADDR_RELATIVE_MODE	(0 << 5)
#define UET_ADDR_ABSOLUTE_MODE	(1 << 5)
#define UET_ADDR_IPV4		(0 << 6)
#define UET_ADDR_IPV6		(1 << 6)
#define UET_ADDR_BIG_MSG_SIZE	(0 << 7)
#define UET_ADDR_MTU_MSG_SIZE	(1 << 7)
	uint8_t flags;
#define UET_FEP_CAP_AI_MIN	(1 << 0)
#define UET_FEP_CAP_AI_FULL	(1 << 1)
#define UET_FEP_CAP_HPC		(1 << 2)
#define UET_FEP_CAP_REORDER	(1 << 6)
#define UET_FEP_CAP_OPT_NM_SEM	(1 << 7)
	uint8_t fep_cap;
	struct uet_fa fa;
	uint16_t pid_on_fep;
	uint16_t start_index;
	uint16_t num_indices;
	uint32_t initiator_id;
};

#endif /* _UET_ADDR_H_ */
