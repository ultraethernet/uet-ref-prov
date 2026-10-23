/*
 * Copyright (c) 2026 Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/*
 * UET reference device model - bring-up and progress
 *
 * Creates a live uet-ref-prov instance and runs the progress thread that
 * drives everything.
 */

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "uet_dev_priv.h"
#include "uet_dev_regs.h"
#include "uet_dev_l2.h"
#include "uet_dev_data.h"

/* return if tracing is enabled or not */
static bool uet_dev_tracing(void)
{
	static int on = -1;

	if (on < 0)
		on = (getenv("UET_DEV_TRACE") != NULL) ? 1 : 0;

	return on == 1;
}

void uet_dev_trace_announce(void)
{
	if (uet_dev_tracing())
		fprintf(stderr, "uet_dev: trace: enabled\n");
}

/* log trace to stderr if enabled */
void uet_dev_trace(const char *fmt, ...)
{
	va_list ap;
	struct timespec ts;

	if (!uet_dev_tracing())
		return;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	fprintf(stderr, "[%ld.%06ld] ", (long)ts.tv_sec,
		ts.tv_nsec / 1000);

	va_start(ap, fmt);
	fprintf(stderr, "uet_dev: trace: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

/* the library's page walker reaches guest memory through this */
static void *uet_dev_xlate(void *ctx,
			   uet_dma_addr_t addr,
			   size_t len)
{
	struct uet_dev *dev = ctx;

	return dev->backend.dma_map(dev->backend.ctx, addr, len);
}

/* Drive the instance independently of any completion queue polling. */
static void *uet_dev_progress_loop(void *arg)
{
	struct uet_dev *dev = arg;

	while (!dev->progress_stop) {
		uet_progress(dev->domain_handle);
		uet_dev_l2_poll(dev);
		uet_dev_datapath_poll(dev);
		dev->progress_iters++;

		/* The library gives no way to tell a sweep that did work from
		 * one that did not - progress_rx returns 0 for both - so this
		 * idles unconditionally rather than spinning a core. Revisit
		 * when there is traffic to measure against.
		 */
		usleep(UET_DEV_PROGRESS_IDLE_US);
	}

	return NULL;
}

static void uet_dev_eq_cb(uet_handle_t handle,
			  struct fi_eq_entry *entry)
{
	(void)handle;
	(void)entry;
}

static void uet_dev_eq_err_cb(uet_handle_t handle,
			      struct fi_eq_err_entry *entry)
{
	(void)handle;
	(void)entry;
}

struct uet_dev *uet_dev_create(const struct uet_dev_backend *backend)
{
	struct uet_dev *dev;
	struct uet_addr src_node;
	struct fi_info *hints = NULL;
	size_t plen;
	int rc;

	dev = calloc(1, sizeof(*dev));
	if (dev == NULL) {
		fprintf(stderr, "uet_dev: out of memory\n");
		return NULL;
	}

	if (backend != NULL)
		dev->backend = *backend;

	dev->l2_fd = -1;
	dev->state = UET_DEV_STATE_INIT;
	clock_gettime(CLOCK_MONOTONIC, &dev->started);

	uet_dev_read_config(dev);

	rc = uet_initialize(&dev->uet_handle);
	if (rc != 0) {
		fprintf(stderr, "uet_dev: uet_initialize failed (%d)\n", rc);
		goto err;
	}

	dev->caps |= UET_DEV_CAP_INSTANCE;
	dev->caps |= (UET_DEV_CAP_MR_UNRESTRICTED |
		      UET_DEV_CAP_MR_JOB_RESTRICTED |
		      UET_DEV_CAP_MR_RI_RESTRICTED |
		      UET_DEV_CAP_MR_RI_JOB_RESTRICTED);

	hints = fi_allocinfo();
	if (hints == NULL) {
		fprintf(stderr, "uet_dev: allocinfo failed\n");
		goto err;
	}

	hints->caps |= (FI_ATOMIC | FI_RMA | FI_MSG);

	memset(&src_node, 0, sizeof(src_node));
	src_node.flags = UET_ADDR_IPV4;

	rc = uet_getinfo(dev->uet_handle, &src_node, hints, &dev->info);
	if (rc != 0) {
		fprintf(stderr, "uet_dev: uet_getinfo failed (%d)\n", rc);
		goto err;
	}

	uet_dev_read_identity(dev);

	/* the advertised io vector limit is what the library publishes */
	if ((dev->info != NULL) && (dev->info->tx_attr != NULL))
		dev->iov_limit = (uint32_t)dev->info->tx_attr->iov_limit;

	rc = uet_domain(dev->uet_handle, &dev->fabric, dev->info,
			&dev->domain, dev, uet_dev_eq_cb, uet_dev_eq_err_cb,
			&dev->domain_handle);
	if (rc != 0) {
		fprintf(stderr, "uet_dev: uet_domain failed (%d)\n", rc);
		goto err;
	}

	/* Now that the domain exists, take the packet size from the library
	 * The guest reads this out of BAR0 and reports it as the port's MTU.
	 */
	plen = uet_max_payload_len(dev->domain_handle);
	if (plen != 0)
		dev->max_payload = (uint32_t)plen;

	switch (uet_tx_encap(dev->domain_handle)) {
	case UET_ENCAP_UDP:
		dev->gid_type = UET_DEV_GID_TYPE_UDP;
		break;
	case UET_ENCAP_UFH:
		dev->gid_type = UET_DEV_GID_TYPE_UFH;
		break;
	case UET_ENCAP_IP:
	default:
		dev->gid_type = UET_DEV_GID_TYPE_IP;
		break;
	}

	/* Every memory region the guest registers is described by addresses
	 * that mean nothing in this process until this address translation
	 * function is installed.
	 */
	if (dev->backend.dma_map != NULL)
		uet_set_dma_xlate(dev->uet_handle, uet_dev_xlate, dev);

	pthread_mutex_init(&dev->ring_lock, NULL);
	pthread_mutex_init(&dev->obj_lock, NULL);

	/* object storage */
	dev->jobs = calloc(UET_DEV_MAX_JOB_IDS, sizeof(*dev->jobs));
	dev->jkeys = calloc(UET_DEV_MAX_JOB_KEYS, sizeof(*dev->jkeys));
	dev->ahs = calloc(UET_DEV_MAX_AHS, sizeof(*dev->ahs));
	dev->mrs = calloc(UET_DEV_MAX_MRS, sizeof(*dev->mrs));
	dev->qps = calloc(UET_DEV_MAX_QPS, sizeof(*dev->qps));
	dev->cqs = calloc(UET_DEV_MAX_CQS, sizeof(*dev->cqs));
	if ((dev->jobs == NULL) || (dev->jkeys == NULL) ||
	    (dev->mrs == NULL) || (dev->qps == NULL) ||
	    (dev->cqs == NULL)) {
		fprintf(stderr, "uet_dev: out of memory for job tables\n");
		goto err;
	}

	rc = uet_dev_l2_open(dev);
	if (rc != 0)
		goto err;

	rc = pthread_create(&dev->progress_thread, NULL,
			    uet_dev_progress_loop, dev);
	if (rc != 0) {
		fprintf(stderr, "uet_dev: progress thread failed (%d)\n", rc);
		goto err;
	}

	dev->progress_running = true;
	dev->caps |= UET_DEV_CAP_PROGRESS_THREAD;

	dev->state = UET_DEV_STATE_READY;

	if (hints != NULL)
		fi_freeinfo(hints);

	return dev;

err:
	dev->state = UET_DEV_STATE_ERROR;

	if (hints != NULL)
		fi_freeinfo(hints);

	uet_dev_destroy(dev);
	return NULL;
}

void uet_dev_destroy(struct uet_dev *dev)
{
	size_t i;

	if (dev == NULL)
		return;

	if (dev->progress_running) {
		dev->progress_stop = true;
		pthread_join(dev->progress_thread, NULL);
		dev->progress_running = false;
	}

	uet_dev_l2_close(dev);

	pthread_mutex_destroy(&dev->ring_lock);
	pthread_mutex_destroy(&dev->obj_lock);

	if (dev->jobs != NULL) {
		for (i = 0; i < UET_DEV_MAX_JOB_IDS; i++)
			free(dev->jobs[i].addrs);

		free(dev->jobs);
		dev->jobs = NULL;
	}

	free(dev->jkeys);
	dev->jkeys = NULL;

	free(dev->ahs);
	dev->ahs = NULL;

	if (dev->qps != NULL) {
		for (i = 0; i < UET_DEV_MAX_QPS; i++) {
			if (dev->qps[i].used)
				uet_ep_close(dev->qps[i].ep);
		}

		free(dev->qps);
		dev->qps = NULL;
	}

	free(dev->cqs);
	dev->cqs = NULL;

	free(dev->mrs);
	dev->mrs = NULL;

	if (dev->domain_handle != NULL)
		uet_domain_close(dev->domain_handle);

	if (dev->info != NULL)
		fi_freeinfo(dev->info);

	if (dev->uet_handle != NULL)
		uet_finalize(dev->uet_handle);

	free(dev);
}

