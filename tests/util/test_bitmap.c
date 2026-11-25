/*
 * Copyright (c) 2026, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/*
 * Unit tests for the bitmap implementation in util/bitmap.c.
 *
 * The harness is intentionally tiny: every check funnels through CHECK()/
 * CHECK_EQ(), which record pass/fail counts and print the first failing
 * location. Run with no args to execute every group, or pass -h for usage.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#include "../../util/bitmap.h"

static int g_checks;
static int g_failures;

#define CHECK(cond)                                                          \
	do {                                                                 \
		g_checks++;                                                  \
		if (!(cond)) {                                               \
			g_failures++;                                        \
			printf("  [FAIL] %s:%d: CHECK(%s)\n",                \
			       __func__, __LINE__, #cond);                   \
		}                                                            \
	} while (0)

#define CHECK_EQ(got, exp)                                                   \
	do {                                                                 \
		uint64_t _g = (uint64_t)(got);                               \
		uint64_t _e = (uint64_t)(exp);                               \
		g_checks++;                                                  \
		if (_g != _e) {                                              \
			g_failures++;                                        \
			printf("  [FAIL] %s:%d: %s == %s "                   \
			       "(got 0x%" PRIx64 ", want 0x%" PRIx64 ")\n",  \
			       __func__, __LINE__, #got, #exp, _g, _e);      \
		}                                                            \
	} while (0)

/* A few distinct non-NULL sentinels to exercise the per-bit data array. */
static int marker_a, marker_b, marker_c;
#define PA ((void *)&marker_a)
#define PB ((void *)&marker_b)
#define PC ((void *)&marker_c)

/* ------------------------------------------------------------------ */
/* bm_create / bm_destroy: sizing rules and input validation          */
/* ------------------------------------------------------------------ */
static void test_create_destroy(void)
{
	struct bitmap *bm;

	/* Valid sizes must be multiples of 64. */
	bm = bm_create(64);
	CHECK(bm != NULL);
	if (bm) {
		CHECK_EQ(bm->size, 64);
		CHECK_EQ(bm->bit_arr_len, 1);
		bm_destroy(bm);
	}

	bm = bm_create(128);
	CHECK(bm != NULL);
	if (bm) {
		CHECK_EQ(bm->size, 128);
		CHECK_EQ(bm->bit_arr_len, 2);
		/* Freshly created bitmap must be all-zero. */
		CHECK_EQ(bm_count(bm), 0);
		CHECK_EQ(bm_min(bm), -1);
		CHECK_EQ(bm_max(bm), -1);
		bm_destroy(bm);
	}

	/*
	 * Regression for the input-validation fix: sizes that are a multiple
	 * of 8 but NOT of 64 used to slip through and produce bit_arr_len == 0.
	 * They must now be rejected.
	 */
	CHECK(bm_create(8) == NULL);
	CHECK(bm_create(16) == NULL);
	CHECK(bm_create(63) == NULL);
	CHECK(bm_create(100) == NULL);

	/* a larger multiple of 64 is still valid */
	bm = bm_create(192);
	CHECK(bm != NULL);
	if (bm) {
		CHECK_EQ(bm->bit_arr_len, 3);
		bm_destroy(bm);
	}
}

/* ------------------------------------------------------------------ */
/* bm_set / bm_get / bm_unset / bm_count                              */
/* ------------------------------------------------------------------ */
static void test_set_get_unset(void)
{
	struct bitmap *bm = bm_create(128);
	void *data;

	CHECK(bm != NULL);
	if (!bm)
		return;

	/* set a handful of bits across both 64-bit words */
	CHECK(bm_set(bm, 0, PA) == true);
	CHECK(bm_set(bm, 63, PB) == true);
	CHECK(bm_set(bm, 64, PC) == true);
	CHECK(bm_set(bm, 127, PA) == true);
	CHECK_EQ(bm_count(bm), 4);

	/* bm_get returns the bit state and hands back the stored pointer */
	data = NULL;
	CHECK(bm_get(bm, 0, &data) == true);
	CHECK(data == PA);
	data = NULL;
	CHECK(bm_get(bm, 64, &data) == true);
	CHECK(data == PC);

	/* an unset bit reports false; data pointer for it is NULL */
	data = PB;
	CHECK(bm_get(bm, 1, &data) == false);
	CHECK(data == NULL);

	/* bm_get tolerates a NULL data out-param */
	CHECK(bm_get(bm, 63, NULL) == true);

	/* unset clears both the bit and its data slot */
	bm_unset(bm, 63);
	data = PB;
	CHECK(bm_get(bm, 63, &data) == false);
	CHECK(data == NULL);
	CHECK_EQ(bm_count(bm), 3);

	/* out-of-range / negative indices are rejected without changing state */
	CHECK(bm_set(bm, -1, PA) == false);
	CHECK(bm_set(bm, 128, PA) == false);
	CHECK(bm_set(bm, 100000, PA) == false);
	CHECK_EQ(bm_count(bm), 3);
	CHECK(bm_get(bm, -1, NULL) == false);
	CHECK(bm_get(bm, 128, NULL) == false);

	bm_destroy(bm);
}

/* ------------------------------------------------------------------ */
/* bm_clear: must zero the WHOLE data array, not just bit_arr_len ptrs */
/* ------------------------------------------------------------------ */
static void test_clear(void)
{
	struct bitmap *bm = bm_create(128);
	void *data;
	int i;

	CHECK(bm != NULL);
	if (!bm)
		return;

	/* populate every bit with a non-NULL data pointer */
	for (i = 0; i < 128; i++)
		bm_set(bm, i, PA);
	CHECK_EQ(bm_count(bm), 128);

	bm_clear(bm);

	/* all bits gone */
	CHECK_EQ(bm_count(bm), 0);
	CHECK_EQ(bm_min(bm), -1);

	/*
	 * Regression for the bm_clear fix: every data slot (including those
	 * beyond index bit_arr_len) must be reset to NULL. We read the data
	 * array directly so the check does not depend on bm_get's bit gating.
	 */
	for (i = 0; i < bm->size; i++)
		CHECK(bm->data_arr[i] == NULL);

	/* after clear the map is fully reusable */
	bm_set(bm, 70, PB);
	data = NULL;
	CHECK(bm_get(bm, 70, &data) == true);
	CHECK(data == PB);

	bm_destroy(bm);
}

/* ------------------------------------------------------------------ */
/* bm_min / bm_max                                                    */
/* ------------------------------------------------------------------ */
static void test_min_max(void)
{
	struct bitmap *bm = bm_create(128);

	CHECK(bm != NULL);
	if (!bm)
		return;

	CHECK_EQ(bm_min(bm), -1);
	CHECK_EQ(bm_max(bm), -1);

	bm_set(bm, 10, PA);
	CHECK_EQ(bm_min(bm), 10);
	CHECK_EQ(bm_max(bm), 10);

	bm_set(bm, 5, PA);
	bm_set(bm, 120, PA);
	CHECK_EQ(bm_min(bm), 5);
	CHECK_EQ(bm_max(bm), 120);

	/* boundary bits 0 and size-1 */
	bm_set(bm, 0, PA);
	bm_set(bm, 127, PA);
	CHECK_EQ(bm_min(bm), 0);
	CHECK_EQ(bm_max(bm), 127);

	bm_destroy(bm);
}

/* ------------------------------------------------------------------ */
/* bm_next_set_bit_iter                                               */
/* ------------------------------------------------------------------ */
static void test_iter(void)
{
	struct bitmap *bm = bm_create(128);
	int expect[] = { 0, 1, 63, 64, 65, 127 };
	int n = (int)(sizeof(expect) / sizeof(expect[0]));
	int seen = 0;
	int i;

	CHECK(bm != NULL);
	if (!bm)
		return;

	for (i = 0; i < n; i++)
		bm_set(bm, expect[i], PA);

	for (i = 0; bm_next_set_bit_iter(bm, &i); i++) {
		CHECK(seen < n);
		if (seen < n)
			CHECK_EQ(i, expect[seen]);
		seen++;
	}
	CHECK_EQ(seen, n);

	/* empty bitmap: iterator finds nothing */
	bm_clear(bm);
	i = 0;
	CHECK(bm_next_set_bit_iter(bm, &i) == false);

	bm_destroy(bm);
}

/* ------------------------------------------------------------------ */
/* bm_extract64: SACK-style 64-bit window extraction                  */
/* ------------------------------------------------------------------ */
static void test_extract64(void)
{
	struct bitmap *bm = bm_create(128);

	CHECK(bm != NULL);
	if (!bm)
		return;

	/* empty map extracts to 0 at a valid index */
	CHECK_EQ(bm_extract64(bm, 0), 0ULL);

	/* bit 0 set -> lsb of the window */
	bm_set(bm, 0, PA);
	CHECK_EQ(bm_extract64(bm, 0), 0x1ULL);

	/* bit 5 set, extract from index 5 -> lsb again */
	bm_clear(bm);
	bm_set(bm, 5, PA);
	CHECK_EQ(bm_extract64(bm, 5), 0x1ULL);
	CHECK_EQ(bm_extract64(bm, 0), (1ULL << 5));

	/* window straddling the 64-bit word boundary */
	bm_clear(bm);
	bm_set(bm, 63, PA);
	bm_set(bm, 64, PA);
	/* extract from 63: bit63 -> pos0, bit64 -> pos1 */
	CHECK_EQ(bm_extract64(bm, 63), 0x3ULL);

	/* index >= size returns 0 */
	CHECK_EQ(bm_extract64(bm, 128), 0ULL);
	CHECK_EQ(bm_extract64(bm, 200), 0ULL);

	/* fully negative window (i + 64 <= 0) is all ones */
	CHECK_EQ(bm_extract64(bm, -64), ~0ULL);
	CHECK_EQ(bm_extract64(bm, -100), ~0ULL);

	/*
	 * Partially negative window: positions below 0 are filled with 1,
	 * the rest come from the bitmap. With bit 0 set and shift = 3, the
	 * low 3 bits are fill-ones and bit0 lands at position 3.
	 */
	bm_clear(bm);
	bm_set(bm, 0, PA);
	CHECK_EQ(bm_extract64(bm, -3), (0x7ULL | (1ULL << 3)));

	bm_destroy(bm);
}

/* ------------------------------------------------------------------ */
/* bm_shift_left / bm_shift_right (bits and the parallel data array)   */
/* ------------------------------------------------------------------ */
static void test_shift(void)
{
	struct bitmap *bm = bm_create(128);
	void *data;

	CHECK(bm != NULL);
	if (!bm)
		return;

	/* shift by 0 is a no-op */
	bm_set(bm, 10, PA);
	bm_shift_left(bm, 0);
	CHECK(bm_get(bm, 10, NULL) == true);
	bm_shift_right(bm, 0);
	CHECK(bm_get(bm, 10, NULL) == true);

	/* left shift within a word moves bit and data together */
	bm_clear(bm);
	bm_set(bm, 1, PA);
	bm_set(bm, 2, PB);
	bm_shift_left(bm, 4);
	CHECK(bm_get(bm, 1, NULL) == false);
	data = NULL;
	CHECK(bm_get(bm, 5, &data) == true);
	CHECK(data == PA);
	data = NULL;
	CHECK(bm_get(bm, 6, &data) == true);
	CHECK(data == PB);

	/* left shift across the word boundary */
	bm_clear(bm);
	bm_set(bm, 60, PC);
	bm_shift_left(bm, 8);
	CHECK(bm_get(bm, 60, NULL) == false);
	data = NULL;
	CHECK(bm_get(bm, 68, &data) == true);
	CHECK(data == PC);

	/* right shift is the inverse direction */
	bm_clear(bm);
	bm_set(bm, 70, PA);
	bm_set(bm, 65, PB);
	bm_shift_right(bm, 8);
	data = NULL;
	CHECK(bm_get(bm, 62, &data) == true);
	CHECK(data == PA);
	data = NULL;
	CHECK(bm_get(bm, 57, &data) == true);
	CHECK(data == PB);

	/* right shift by a whole word (multiple of 64) */
	bm_clear(bm);
	bm_set(bm, 100, PA);
	bm_shift_right(bm, 64);
	data = NULL;
	CHECK(bm_get(bm, 36, &data) == true);
	CHECK(data == PA);
	CHECK(bm_get(bm, 100, NULL) == false);

	/* bits shifted off the low end are dropped, and freed slots are NULL */
	bm_clear(bm);
	bm_set(bm, 3, PA);
	bm_shift_right(bm, 8);
	CHECK_EQ(bm_count(bm), 0);
	data = PA;
	CHECK(bm_get(bm, 0, &data) == false);
	CHECK(data == NULL);

	/* Shift past the data array boundary without exposing expired pointers. */
	bm_clear(bm);
	bm_set(bm, 0, PA);
	bm_set(bm, 127, PB);
	bm_shift_right(bm, 63);
	CHECK(bm_get(bm, 64, &data) && data == PB);
	data = PA;
	CHECK(!bm_get(bm, 65, &data) && data == NULL);
	bm_set(bm, 126, PC);
	bm_shift_right(bm, 64);
	CHECK(bm_get(bm, 0, &data) && data == PB);
	CHECK(bm_get(bm, 62, &data) && data == PC);
	bm_set(bm, 65, PA);
	bm_shift_right(bm, 1);
	CHECK(bm_get(bm, 61, &data) && data == PC);
	bm_shift_left(bm, 3);
	CHECK(bm_get(bm, 64, &data) && data == PC);
	CHECK(bm_get(bm, 67, &data) && data == PA);
	bm_shift_left(bm, 129);
	CHECK_EQ(bm_count(bm), 0);

	bm_destroy(bm);
}

/* ------------------------------------------------------------------ */

static void run_all(void)
{
	printf("== test_create_destroy ==\n"); test_create_destroy();
	printf("== test_set_get_unset ==\n");  test_set_get_unset();
	printf("== test_clear ==\n");          test_clear();
	printf("== test_min_max ==\n");        test_min_max();
	printf("== test_iter ==\n");           test_iter();
	printf("== test_extract64 ==\n");      test_extract64();
	printf("== test_shift ==\n");          test_shift();
}

int main(void)
{
	run_all();

	printf("\n----------------------------------------\n");
	printf("bitmap unit tests: %d checks, %d failure(s)\n",
	       g_checks, g_failures);

	return (g_failures == 0) ? 0 : 1;
}
