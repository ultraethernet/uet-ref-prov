/*
 * Copyright (c) 2026, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/*
 * UUD (Unreliable Unordered Delivery) engine. UUD is a connectionless
 * best-effort datagram mode with no PDC, no PSN, no ACK, no response, no
 * retransmit, etc. A single-packet untagged send is transmitted once (fire and
 * forget). The initiator completes immediately on transmit and the target
 * delivers the payload to a posted receive and sends no response. This UUD
 * engine bypasses the PDS PDC control plane entirely.
 */

#ifndef _UET_PDS_UUD_H_
#define _UET_PDS_UUD_H_

#include <stdint.h>
#include <stdbool.h>

#include "uet_pds.h"
#include "uet_util.h"

struct uet_ep;
struct uet_instance;

/* Transmit one UUD datagram (mode=UUD path of uet_pds_tx_pkt). Same arguments
 * as the PDS engine's tx_pkt() downcall. Completes at the initiator on
 * transmit (no response is expected).
 */
int uet_pds_uud_tx_pkt(uet_pkt_handle_t tx_pkt_handle,
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

/* Process a received UUD packet. Dispatched from the PDS engine's
 * uet_pds_progress_rx(). Delivers the untagged send and sends no response.
 * Takes full ownership of the packet!
 */
int uet_pds_uud_rx(struct uet_instance *uet, struct uet_parsed_pkt *pp);

#endif /* _UET_PDS_UUD_H_ */
