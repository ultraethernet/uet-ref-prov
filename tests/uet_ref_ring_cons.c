// SPDX-License-Identifier: GPL-2.0-only OR Linux-OpenIB
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "uet_ref_ring_cons.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

int main(void)
{
	const uint32_t completions[] = {12, 8, 10, 12};
	uint32_t producer = 16, consumer = 0;
	unsigned int i;

	/* A later completion releases twelve slots. Older completions in the
	 * same CQ batch cannot reduce those credits before the application posts.
	 */
	for (i = 0; i < ARRAY_SIZE(completions); i++) {
		consumer = uet_ref_ring_cons_advance(consumer, completions[i]);
		assert(consumer == 12);
	}
	assert(consumer == 12);
	assert(producer - consumer == 4);
	producer += 12;
	assert(producer - consumer == 16);

	/* A new lap advances through zero; a delayed previous-lap completion
	 * still cannot move the consumer back.
	 */
	consumer = UINT32_MAX - 1;
	consumer = uet_ref_ring_cons_advance(consumer, 0);
	assert(consumer == 0);
	consumer = uet_ref_ring_cons_advance(consumer, UINT32_MAX);
	assert(consumer == 0);
	consumer = uet_ref_ring_cons_advance(consumer, 3);
	assert(consumer == 3);
	consumer = uet_ref_ring_cons_advance(consumer, 1);
	assert(consumer == 3);
	puts("unordered ring credits and uint32_t wrap: pass");
	return 0;
}
