/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#ifndef _BITMAP_H_
#define _BITMAP_H_

#include <stdint.h>
#include <stdbool.h>

struct bitmap {
	uint64_t *bit_arr;
	int bit_arr_len;
	void **data_arr; /* pointer to store data per bit */
	int size;
};

struct bitmap *bm_create(int size); /* size = number of bits (mult of 64) */
void bm_destroy(struct bitmap *bm);
void bm_clear(struct bitmap *bm);
int bm_count(const struct bitmap *bm); /* total bits set */
void bm_set(struct bitmap *bm, int i, void *data);
void bm_unset(struct bitmap *bm, int i);
bool bm_get(const struct bitmap *bm, int i, void **data);
int bm_min(const struct bitmap *bm); /* -1 if empty */
int bm_max(const struct bitmap *bm); /* -1 if empty */
void bm_shift_left(struct bitmap *bm, int s);
void bm_shift_right(struct bitmap *bm, int s);

/*
 * Iterate over all the set bits:
 *   for (int i = 0; bm_next_set_bit_iter(b, &i); i++) {
 *       ...
 *   }
 */
bool bm_next_set_bit_iter(const struct bitmap *bm, int *i);

void bm_print_idx(const struct bitmap *b);
void bm_print_bits(const struct bitmap *b);

#endif /* _BITMAP_H_ */
