/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "bitmap.h"

#define TRAILING_ZEROES __builtin_ctzll
#define LEADING_ZEROES  __builtin_clzll
#define TOTAL_NONZERO   __builtin_popcountll

struct bitmap *bm_create(int size)
{
	struct bitmap *bm = NULL;

	if ((size % sizeof(uint64_t)) != 0)
		return NULL;

	/* Allocate the bm itself. */
	bm = (struct bitmap *)malloc(sizeof(struct bitmap));
	if (bm == NULL)
		return NULL;

	bm->size = size;
	bm->bit_arr_len = (bm->size / (sizeof(uint64_t) * 8));

	bm->bit_arr = (uint64_t *)calloc(bm->bit_arr_len, sizeof(uint64_t));
	if (bm->bit_arr == NULL) {
		free(bm);
		return NULL;
	}

	bm->data_arr = (void *)calloc(bm->size, sizeof(void *));
	if (bm->data_arr == NULL) {
		free(bm->bit_arr);
		free(bm);
		return NULL;
	}

	return bm;
}

void bm_destroy(struct bitmap *bm)
{
	free(bm->data_arr);
	free(bm->bit_arr);
	free(bm);
}

void bm_clear(struct bitmap *bm)
{
	memset(bm->bit_arr, 0, (sizeof(uint64_t) * bm->bit_arr_len));
	memset(bm->data_arr, 0, (sizeof(void *) * bm->bit_arr_len));
}

int bm_count(const struct bitmap *bm)
{
	int i, total = 0;

	for (i = 0; i < bm->bit_arr_len; i++)
		total += TOTAL_NONZERO(bm->bit_arr[i]);

	return total;
}

void bm_set(struct bitmap *bm, int i, void *data)
{
	int idx = (i / 64);

	if (idx >= bm->bit_arr_len)
		return; /* could assert() here */

	if ((i < 0) || (i >= bm->size))
		return; /* could assert() here */

	bm->bit_arr[idx] |= ((uint64_t)1 << (i % 64));
	bm->data_arr[i] = data;
}

void bm_unset(struct bitmap *bm, int i)
{
	int idx = (i / 64);

	if (idx >= bm->bit_arr_len)
		return; /* could assert() here */

	if ((i < 0) || (i >= bm->size))
		return; /* could assert() here */

	bm->bit_arr[idx] &= ~((uint64_t)1 << (i % 64));
	bm->data_arr[i] = NULL;
}

bool bm_get(const struct bitmap *bm, int i, void **data)
{
	int idx = (i / 64);

	if (idx >= bm->bit_arr_len)
		return false; /* could assert() here */

	if ((i < 0) || (i >= bm->size))
		return NULL; /* could assert() here */

	if (data)
		*data = bm->data_arr[i];

	return ((bm->bit_arr[idx] & ((uint64_t)1 << (i % 64))) != 0);
}

int bm_min(const struct bitmap *bm)
{
	uint64_t idx_val;
	int i;

	for (i = 0; i < bm->bit_arr_len; i++) {
		idx_val = bm->bit_arr[i];
		if (idx_val != 0)
			return (TRAILING_ZEROES(idx_val) + (i * 64));
	}

	return -1;
}

int bm_max(const struct bitmap *bm)
{
	uint64_t idx_val;
	int i;

	for (i = bm->bit_arr_len; i > 0; i--) {
		idx_val = bm->bit_arr[i - 1];
		if (idx_val != 0)
			return (63 - LEADING_ZEROES(idx_val) + ((i - 1) * 64));
	}

	return -1;
}

void bm_shift_left(struct bitmap *bm, int s)
{
	uint32_t chop_words = (s / 64);
	int shift = (s % 64);
	int i;

	if (s == 0)
		return; /* nothing to do */

	if (shift == 0) {
		for (i = (bm->bit_arr_len - 1); i >= chop_words; i--)
			bm->bit_arr[i] = bm->bit_arr[i - chop_words];
	} else {
		for (i = (bm->bit_arr_len - 1); i >= (chop_words + 1); i--) {
			bm->bit_arr[i] =
				((bm->bit_arr[i - chop_words] <<
				  shift) |
				 (bm->bit_arr[i - 1 - chop_words] >>
				  (64 - shift)));
		}

		bm->bit_arr[chop_words] = (bm->bit_arr[0] << shift);
	}

	for (i = 0; i < chop_words; i++)
		bm->bit_arr[i] = 0;

	/* shift the data pointer array */
	for (i = (bm->size - 1); i >= s; i--)
		bm->data_arr[i] = bm->data_arr[i - s];
	for (i = 0; i < s; i++)
		bm->data_arr[i] = NULL;
}

void bm_shift_right(struct bitmap *bm, int s)
{
	uint32_t chop_words = (s / 64);
	int shift = (s % 64);
	int i;

	if (s == 0)
		return; /* nothing to do */

	if (shift == 0) {
		for (i = 0; i < (bm->bit_arr_len - chop_words); i++)
			bm->bit_arr[i] = bm->bit_arr[i + chop_words];
	} else {
		for (i = 0; i < (bm->bit_arr_len - 1 - chop_words); i++) {
			bm->bit_arr[i] =
				((bm->bit_arr[i + chop_words] >>
				  shift) |
				 (bm->bit_arr[i + 1 + chop_words] <<
				  (64 - shift)));
		}

		bm->bit_arr[bm->bit_arr_len - 1 - chop_words] =
			(bm->bit_arr[bm->bit_arr_len - 1] >> shift);
	}

	for (i = 0; i < chop_words; i++)
		bm->bit_arr[bm->bit_arr_len - 1 - i] = 0;

	/* shift the data pointer array */
	for (i = 0; i < (bm->size - s); i++)
		bm->data_arr[i] = bm->data_arr[i + s];
	for (i = (bm->size - s); i < bm->size; i++)
		bm->data_arr[i] = NULL;
}

bool bm_next_set_bit_iter(const struct bitmap *bm, int *i)
{
	uint64_t idx_val;
	int idx = (*i / 64);

	if (idx >= bm->bit_arr_len)
		return false; /* could assert() here */

	idx_val = bm->bit_arr[idx];
	idx_val >>= (*i & 63);

	if (idx_val != 0) {
		*i += TRAILING_ZEROES(idx_val);
		return true;
	}

	for (++idx; idx < bm->bit_arr_len; idx++) {
		idx_val = bm->bit_arr[idx];
		if (idx_val == 0)
			continue;

		*i = (idx * 64 + TRAILING_ZEROES(idx_val));
		return true;
	}

	return false;
}

void bm_print_idx(const struct bitmap *b)
{
	void *data;
	bool found_bit = false;
	int i;

	printf("{\n");
	for (i = 0; bm_next_set_bit_iter(b, &i); i++) {
		if (found_bit)
			printf(",\n");
		bm_get(b, i, &data);
		printf("  %u -> %p", i, data);
		found_bit = true;
	}
	printf("\n}\n");
}

void bm_print_bits(const struct bitmap *b)
{
	int i, idx, bit, word_size;

	word_size = (sizeof(uint64_t) * 8);
	for (idx = (b->bit_arr_len - 1); idx >= 0; idx--) {
		for (i = (word_size - 1); i >= 0; i--) {
			bit = (i + (idx * word_size));
			printf("%d", (bm_get(b, bit, NULL) ? 1 : 0));
			if ((i != 0) && ((i % 8) == 0))
				printf(".");
		}
		printf(" (%d..%d)\n",
		       (((idx + 1) * word_size) - 1),
		       (idx * word_size));
	}
}

