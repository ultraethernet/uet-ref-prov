/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* PDS Interface for SES downcall API's */

#include "uet_api_private.h"
#include "uet_pds.h"

/* PDS implementation (real) */
int (*uet_pds_initialize_fn)(struct uet_instance *uet);
void (*uet_pds_finalize_fn)(struct uet_instance *uet);
int (*uet_pds_ep_initialize_fn)(struct uet_ep *uet_ep);
void (*uet_pds_ep_finalize_fn)(struct uet_ep *uet_ep);
int (*uet_pds_tx_pkt_fn)(uet_pkt_handle_t tx_pkt_handle,
			  struct uet_ep *uet_ep,
			  uet_addr_handle_t dst_addr_handle,
			  uet_pds_mode_t mode, uet_pds_tx_flags_t flags,
			  struct uet_pds_info *pds_info,
			  uint16_t msg_id, uet_next_hdr_t next_hdr,
			  void *ses, size_t ses_len, void *pkt,
			  size_t pkt_len, bool dma_rdy);
int (*uet_pds_progress_tx_fn)(struct uet_ep *uet_ep,
			       uet_pkt_handle_t *err_pkt_handle);
int (*uet_pds_msg_cmpl_ind_fn)(struct uet_ep *uet_ep,
				uet_addr_handle_t dst_addr_handle,
				uet_pds_mode_t mode, uint16_t msg_id);
int (*uet_pds_progress_rx_fn)(struct uet_instance *uet);
void (*uet_pds_ep_close_wait_fn)(struct uet_ep *uet_ep);

EXPORT_SYMBOL(uet_pds_initialize_fn);
EXPORT_SYMBOL(uet_pds_finalize_fn);
EXPORT_SYMBOL(uet_pds_ep_initialize_fn);
EXPORT_SYMBOL(uet_pds_ep_finalize_fn);
EXPORT_SYMBOL(uet_pds_tx_pkt_fn);
EXPORT_SYMBOL(uet_pds_progress_tx_fn);
EXPORT_SYMBOL(uet_pds_msg_cmpl_ind_fn);
EXPORT_SYMBOL(uet_pds_progress_rx_fn);
EXPORT_SYMBOL(uet_pds_ep_close_wait_fn);

int uet_pds_init(struct uet_instance *uet)
{
	struct uet_ses_to_pds_funcs *downcall;     /* ptr's to pds functions */

	downcall = &uet->pds.downcall;

	downcall->initialize    = uet_pds_initialize_fn;
	downcall->finalize      = uet_pds_finalize_fn;
	downcall->ep_initialize = uet_pds_ep_initialize_fn;
	downcall->ep_finalize   = uet_pds_ep_finalize_fn;
	downcall->msg_cmpl_ind  = uet_pds_msg_cmpl_ind_fn;
	downcall->tx_pkt        = uet_pds_tx_pkt_fn;
	downcall->progress_tx   = uet_pds_progress_tx_fn;
	downcall->progress_rx   = uet_pds_progress_rx_fn;
	downcall->ep_close_wait = uet_pds_ep_close_wait_fn;

	return downcall->initialize(uet);
}

