/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#include "uet_util.h"
#include "uet_uapi.h"

#define UET_SEC_MAX_HDR_LEN sizeof(struct uet_sec_ssi)
#define UET_SEC_TAG_LEN     16

/*
 * If the SD is enabled, the security header is injected in the packet.
 *
 * The security header is injected into the headroom of the pkt_buf. It is
 * expected that there is enough empty space before the pkt pointer to hold
 * the security header. The headers before the PDS header are copied down to
 * make room for the security header which is then filled in with the fields
 * from the SD.
 *
 * The updated pkt pointer and length are returned in new_pkt/new_pkt_len.
 */
int uet_sec_build_hdr(uint32_t sdi,
		      uint32_t ssi,
		      uint8_t *pkt_buf,
		      int pkt_buf_len,
		      uint8_t *pkt,
		      int pkt_len,
		      uint8_t **new_pkt,
		      int *new_pkt_len);

/*
 * Update the TSC field in the security header. Used for retransmits.
 */
int uet_sec_update_hdr_tsc(uint8_t *pkt);

/*
 * Encryption does not occur inplace.
 *
 * The encrypted packet is written to the upper half of the pkt_buf. The
 * cleartext packet is located in the lower half of the pkt_buf (pointed to
 * by pkt). Checks are made to ensure that pkt_buf is large enough to hold
 * the encrypted packet and that the cleartext packet isn't overwritten.
 *
 * The crypto APIs support inplace encryption but that isn't used here so
 * a cleartext copy of the packet remains for possible retransmission. For
 * a retransmission, only the TSC field needs to be updated and the packet
 * re-encrypted without having to first descrypt the packet before processing.
 *
 * The encrypted pkt pointer and length are returned in enc_pkt/enc_pkt_len.
 */
int uet_sec_enc_pkt(uint8_t *pkt_buf,
		    int pkt_buf_len,
		    uint8_t *pkt,
		    int pkt_len,
		    uint8_t **enc_pkt,
		    int *enc_pkt_len);

/*
 * Decryption occurs inplace. The length of the tag is returned so the
 * payload length can be determined from the total packet length.
 */
int uet_sec_dec_pkt(uint8_t *pkt,
		    int pkt_len,
		    int *tag_len);

int uet_sec_init(void);

