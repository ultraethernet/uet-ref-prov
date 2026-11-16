/* SPDX-License-Identifier: MIT */
/* Include the implementation to exercise the actual private allocator, not a
 * second implementation. Unused transport sections are removed at link time. */
#define _GNU_SOURCE
#include "../uet_api.c"
#include <assert.h>
#include <pthread.h>
#include <sched.h>

#define WORKERS 8
#define ROUNDS 50000
static struct uet_instance instance;
static pthread_barrier_t start;
static unsigned char live[UET_MAX_MSG_ID + 1];

static void *worker(void *arg)
{
	(void)arg;
	struct uet_rx_desc descriptor;
	int barrier_rc = pthread_barrier_wait(&start);
	assert(barrier_rc == 0 || barrier_rc == PTHREAD_BARRIER_SERIAL_THREAD);
	for (unsigned i = 0; i < ROUNDS; i++) {
		uint16_t id;
		assert(uet_alloc_msg_id(&instance, &id) == FI_SUCCESS);
		assert(__atomic_exchange_n(&live[id], 1, __ATOMIC_SEQ_CST) == 0);
		/* Each allocated slot owns its descriptor storage until release. */
		assert(instance.msg_id_cb.rx_desc[id] == NULL);
		instance.msg_id_cb.rx_desc[id] = &descriptor;
		if (!(i % 127))
			sched_yield();
		assert(__atomic_exchange_n(&live[id], 0, __ATOMIC_SEQ_CST) == 1);
		uet_dealloc_msg_id(&instance, id);
	}
	return NULL;
}

int main(void)
{
	pthread_t threads[WORKERS];
	uint16_t id;
	unsigned char seen[UET_MAX_MSG_ID + 1] = { 0 };
	/* Wrap and exhaust the whole ID space without duplicates. */
	instance.msg_id_cb.next_msg_id = UET_MAX_MSG_ID;
	for (unsigned i = 0; i <= UET_MAX_MSG_ID; i++) {
		assert(uet_alloc_msg_id(&instance, &id) == FI_SUCCESS);
		assert(!seen[id]);
		seen[id] = 1;
	}
	assert(uet_alloc_msg_id(&instance, &id) == -FI_EBUSY);
	uet_dealloc_msg_id(&instance, 17);
	assert(uet_alloc_msg_id(&instance, &id) == FI_SUCCESS && id == 17);
	for (unsigned i = 0; i <= UET_MAX_MSG_ID; i++)
		uet_dealloc_msg_id(&instance, (uint16_t)i);
	assert(!pthread_barrier_init(&start, NULL, WORKERS));
	for (unsigned i = 0; i < WORKERS; i++)
		assert(!pthread_create(&threads[i], NULL, worker, NULL));
	for (unsigned i = 0; i < WORKERS; i++)
		assert(!pthread_join(threads[i], NULL));
	assert(!pthread_barrier_destroy(&start));
	for (unsigned i = 0; i <= UET_MAX_MSG_ID; i++) {
		assert(!live[i]);
		assert(instance.msg_id_cb.state[i] == UET_MSG_ID_AVAILABLE);
		assert(instance.msg_id_cb.rx_desc[i] == NULL);
	}
	printf("msg-id: wrap/exhaustion/reuse and %u concurrent lifetimes passed\n",
	       WORKERS * ROUNDS);
	return 0;
}
