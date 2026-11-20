/*
 * Copyright (c) 2026, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/*
 * RUDI (Reliable Unordered Delivery for Idempotent operations) engine. RUDI
 * is a connectionless PDS delivery mode with no PDC, no PSN, etc. Each
 * request carries a non-sequential 32-bit pkt_id and is answered by exactly
 * one RUDI response (not an ACK). All reliability state lives at the
 * initiator (a per-packet RTO) and the target is stateless. This RUDI engine
 * bypasses the PDS PDC control plane entirely.
 */

#ifndef _UET_PDS_RUDI_H_
#define _UET_PDS_RUDI_H_

#include <stdint.h>
#include <stdbool.h>

#include "uet_pds.h"
#include "uet_util.h"

struct uet_ep;
struct uet_instance;

/* initialize/free the RUDI engine's outstanding-request state */
void uet_pds_rudi_init(void);
void uet_pds_rudi_finalize(void);

/* Initiate a RUDI request transmit (mode=RUDI path of uet_pds_tx_pkt). Same
 * arguments as the PDS engine's tx_pkt() downcall.
 */
int uet_pds_rudi_tx_pkt(uet_pkt_handle_t tx_pkt_handle,
			uint64_t pkt_cnt,
			struct uet_ep *uet_ep,
			uet_addr_handle_t dst_addr_handle,
			uet_pds_mode_t mode,
			uet_pds_tx_flags_t flags,
			struct uet_pds_info *pds_info,
			uint16_t msg_id,
			uet_pds_next_hdr_t next_hdr,
			void *ses,
			size_t ses_len,
			void *pkt,
			size_t pkt_len,
			bool dma_rdy);

/* Drop every outstanding RUDI request built from a SES transmit descriptor.
 * Called from uet_pds_drop_tx_pkts().
 */
size_t uet_pds_rudi_drop_tx_pkts(uet_pkt_handle_t tx_pkt_handle);

/* Progress RUDI engine intitiator side reliability. Driven from the PDS
 * engine's uet_pds_progress_tx().
 */
int uet_pds_rudi_progress_tx(struct uet_ep *uet_ep,
			     uet_pkt_handle_t *err_pkt_handle);

/* Process a received RUDI packet (REQ or RSP). Dispatched from the PDS
 * engine's uet_pds_progress_rx(). Takes full ownership of the packet!
 */
int uet_pds_rudi_rx(struct uet_instance *uet, struct uet_parsed_pkt *pp);

#endif /* _UET_PDS_RUDI_H_ */
