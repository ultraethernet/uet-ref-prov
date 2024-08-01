/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* PDS Interface for SES downcall API's */

#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

#include "uet_api_private.h"
#include "uet_pds.h"

/* PDS implementation (real) */
extern int uet_pds_initialize(struct uet_instance *uet);
extern void uet_pds_finalize(struct uet_instance *uet);
extern int uet_pds_ep_initialize(struct uet_ep *uet_ep);
extern void uet_pds_ep_finalize(struct uet_ep *uet_ep);
extern int uet_pds_tx_pkt(uet_pkt_handle_t tx_pkt_handle,
			  struct uet_ep *uet_ep,
			  uet_addr_handle_t dst_addr_handle,
			  uet_pds_mode_t mode, uet_pds_tx_flags_t flags,
			  struct uet_pds_info *pds_info,
			  uint16_t msg_id, uet_next_hdr_t next_hdr,
			  void *ses, size_t ses_len, void *pkt,
			  size_t pkt_len, bool dma_rdy);
extern int uet_pds_progress_tx(struct uet_ep *uet_ep,
			       uet_pkt_handle_t *err_pkt_handle);
extern int uet_pds_msg_cmpl_ind(struct uet_ep *uet_ep,
				uet_addr_handle_t dst_addr_handle,
				uet_pds_mode_t mode, uint16_t msg_id);
extern int uet_pds_progress_rx(struct uet_instance *uet);
extern void uet_pds_ep_close_wait(struct uet_ep *uet_ep);

/* PDS stop-n-go implementation (basic) */
extern int uet_pds_sng_initialize(struct uet_instance *uet);
extern void uet_pds_sng_finalize(struct uet_instance *uet);
extern int uet_pds_sng_ep_initialize(struct uet_ep *uet_ep);
extern void uet_pds_sng_ep_finalize(struct uet_ep *uet_ep);
extern int uet_pds_sng_tx_pkt(uet_pkt_handle_t tx_pkt_handle,
			      struct uet_ep *uet_ep,
			      uet_addr_handle_t dst_addr_handle,
			      uet_pds_mode_t mode, uet_pds_tx_flags_t flags,
			      struct uet_pds_info *pds_info,
			      uint16_t msg_id, uet_next_hdr_t next_hdr,
			      void *ses, size_t ses_len, void *pkt,
			      size_t pkt_len, bool dma_rdy);
extern int uet_pds_sng_msg_cmpl_ind(struct uet_ep *uet_ep,
				    uet_addr_handle_t dst_addr_handle,
				    uet_pds_mode_t mode, uint16_t msg_id);
extern int uet_pds_sng_progress_tx(struct uet_ep *uet_ep,
				   uet_pkt_handle_t *err_pkt_handle);
extern int uet_pds_sng_progress_rx(struct uet_instance *uet);
extern void uet_pds_sng_ep_close_wait(struct uet_ep *uet_ep);

int uet_pds_init(struct uet_instance *uet)
{
	struct uet_ses_to_pds_funcs *downcall;     /* ptr's to pds functions */
	char *pds;

	downcall = &uet->pds.downcall;

	/* get pds name from environment variable */
	pds = getenv(UET_PDS);

	if ((pds == NULL) || (strcmp(pds, "sng") == 0)) {
		downcall->initialize    = uet_pds_sng_initialize;
		downcall->finalize      = uet_pds_sng_finalize;
		downcall->ep_initialize = uet_pds_sng_ep_initialize;
		downcall->ep_finalize   = uet_pds_sng_ep_finalize;
		downcall->tx_pkt        = uet_pds_sng_tx_pkt;
		downcall->msg_cmpl_ind  = uet_pds_sng_msg_cmpl_ind;
		downcall->progress_tx   = uet_pds_sng_progress_tx;
		downcall->progress_rx   = uet_pds_sng_progress_rx;
		downcall->ep_close_wait = uet_pds_sng_ep_close_wait;
	} else if (strcmp(pds, "pds") == 0) {
		downcall->initialize    = uet_pds_initialize;
		downcall->finalize      = uet_pds_finalize;
		downcall->ep_initialize = uet_pds_ep_initialize;
		downcall->ep_finalize   = uet_pds_ep_finalize;
		downcall->msg_cmpl_ind  = uet_pds_msg_cmpl_ind;
		downcall->tx_pkt        = uet_pds_tx_pkt;
		downcall->progress_tx   = uet_pds_progress_tx;
		downcall->progress_rx   = uet_pds_progress_rx;
		downcall->ep_close_wait = uet_pds_ep_close_wait;
	} else {
		UET_API_ERR("invalid UET_PDS environment variable");
		return -ENODEV;
	}

	return downcall->initialize(uet);
}

