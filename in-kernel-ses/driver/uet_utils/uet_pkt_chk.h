/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#include <stdbool.h>
#include <string.h>

#include "uet_pkt_hdr.h"
#include "uet_nic.h"

//#include "uet_api_private.h"

/*
 * parse and validate received packet as follows:
 *   - validate dest mac address
 *   - validate ethertype
 *   - validate ip header version
 *   - validate ip header len
 *   - validate ip header total length
 *   - validate ip header checksum
 *   - validate ip protocol
 *   - validate uet packet type
 *
 * parms:
 *      uet        - ptr to uet instance struct
 *      pkt        - ptr to received packet
 *      pkt_size   - size of received packet in bytes
 *      pkt_is_ack - ptr to location where indication of packet type
 *                   is returned, true => packet is an ack packet,
 *                   only valid when function returns true
 *      pkt_is_rd_rsp - ptr to location where indication of packet type
 *                      is returned, true => packet is a read response in
 *                      a pds request, only valid when function returns true
 *
 * returns:
 *      true  => packet passed validation checks
 *      false => packet did not pass validation checks
 */
bool uet_pds_rx_pkt_chk(struct uet_nic *uet,
			uint8_t *pkt,
			size_t pkt_size,
			bool *pkt_is_ack,
			bool *pkt_is_rd_rsp);

