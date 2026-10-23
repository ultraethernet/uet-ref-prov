/* SPDX-License-Identifier: GPL-2.0-only OR Linux-OpenIB */
#ifndef UET_REF_RING_CONS_H
#define UET_REF_RING_CONS_H

#include <stdint.h>

/* RU completions may be unordered. Keep the furthest reported consumption
 * position, including across uint32_t wrap. A ring has fewer than 2^31 entries.
 */
static inline uint32_t uet_ref_ring_cons_advance(uint32_t current,
					     uint32_t reported)
{
	return (int32_t)(reported - current) > 0 ? reported : current;
}

#endif
