/*
 * Copyright (c) 2026, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* UUD (Unreliable Unordered Delivery) engine */

/*
 * UUD + TSS: REPLAY PROTECTION IS **NOT** SUPPORTED! UUD is connectionless
 * with no PDC/PSN state, so there is no anti-replay window. Packets may be
 * lost/replayed/duplicated.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "uet_api.h"
#include "uet_api_private.h"
#include "uet_pds.h"
#include "uet_pds_uud.h"
#include "uet_util.h"
#include "uet_log.h"
#include "uet_pkt_hdr.h"
#include "uet_sec.h"
#include "uet_nic.h"
#include "imp_shim.h"
#include "crc32c.h"

/* scratch structure for building/transmitting one UUD datagram. */
struct uet_uud_pkt {
	uint8_t  *pkt_buf; /* full buffer (incl sec headroom) */
	int       pkt_buf_len;
	uint8_t  *pkt; /* start of eth frame (cleartext) */
	int       pkt_len; /* cleartext frame len (no crc/tag) */
	bool      sec_enabled;
	uint32_t  sdi;
	uint32_t  ssi;
	bool      is_ipv6;
};

/* FIXME: get the security SDI/SSI, same source as uet_pdsm_get_sdi()! */
static void uet_uud_get_sec(bool *sec_enabled, uint32_t *sdi, uint32_t *ssi)
{
	char *sec_ssi;

	*sec_enabled = !!getenv(UET_SEC_MODE);
	*sdi = 1; /* fixed SDI, matches the PDC path */
	*ssi = 0;

	sec_ssi = getenv(UET_SEC_SSI);
	if (sec_ssi)
		*ssi = strtoul(sec_ssi, NULL, 10);
}

/* Apply CRC (no security) or security header + encryption, then transmit the
 * frame once. PDC-free; there is no retransmit so no cleartext copy is kept.
 */
static int uet_uud_send(struct uet_instance *uet, struct uet_uud_pkt *up)
{
	struct uet_parsed_pkt pp;
	uint8_t *out;
	int out_len;
	uint8_t *crc_start;
	uint32_t crc;
	uint8_t *new_pkt;
	int new_pkt_len;
	uint8_t *enc_pkt;
	int enc_pkt_len;
	uint8_t *enc_ip;
	int rc;

	if (!up->sec_enabled) {
		rc = uet_parse_pkt(uet, up->pkt, up->pkt_len, &pp);
		if (rc != 0)
			return rc;

		/* CRC covers from the IP src addr through the payload */
		crc_start = (pp.is_ipv6) ? ((uint8_t *)pp.ip + 8)
					 : ((uint8_t *)pp.ip + 12);
		crc = crc32c(crc_start,
			     (pp.pkt_len - (crc_start - (uint8_t *)pp.eth)));
		memcpy((up->pkt + up->pkt_len), &crc, CRC_LEN);

		out = up->pkt;
		out_len = up->pkt_len + CRC_LEN;

		if (imp_shim_is_enabled())
			return imp_shim_tx_pkt(UET_NIC(uet), out, pp.ip, out_len);

		return uet_nic_tx_pkt(UET_NIC(uet), out, pp.ip, out_len);
	}

	/* security enabled */
	rc = uet_sec_build_hdr(up->sdi, up->ssi, up->pkt_buf, up->pkt_buf_len,
			       up->pkt, up->pkt_len, &new_pkt, &new_pkt_len,
			       up->is_ipv6);
	if (rc != 0)
		return rc;

	up->pkt = new_pkt;
	up->pkt_len = (new_pkt_len + UET_SEC_TAG_LEN);

	rc = uet_parse_pkt(uet, up->pkt, up->pkt_len, &pp);
	if (rc != 0)
		return rc;

	if (pp.is_ipv6) {
		uet_update_ipv6_pl(pp.ip,
				   (up->pkt_len - uet->nic.l2_hdr_size -
				    sizeof(struct ipv6hdr)));
	} else {
		uet_update_ipv4_tl(pp.ip,
				   (up->pkt_len - uet->nic.l2_hdr_size));
	}

	rc = uet_sec_enc_pkt(uet, up->pkt_buf, up->pkt_buf_len, up->pkt,
			     up->pkt_len, &enc_pkt, &enc_pkt_len, up->is_ipv6);
	if (rc != 0)
		return rc;

	/* the IP header sits at a fixed offset in the encrypted frame */
	enc_ip = enc_pkt + sizeof(struct ethhdr);

	if (imp_shim_is_enabled())
		return imp_shim_tx_pkt(UET_NIC(uet), enc_pkt, enc_ip,
				       enc_pkt_len);

	return uet_nic_tx_pkt(UET_NIC(uet), enc_pkt, enc_ip, enc_pkt_len);
}

/* Build a UUD datagram frame (eth/ip/entropy/UUD/SES/payload) into a freshly
 * allocated buffer.
 */
static int uet_uud_build_frame(struct uet_instance *uet,
			       uint8_t tos,
			       uint16_t entropy,
			       const uint8_t *dst_mac,
			       const struct uet_fa *dst_fa,
			       bool is_ipv6, bool sec_enabled,
			       uet_pds_next_hdr_t next_hdr,
			       void *ses, size_t ses_len,
			       void *payload, size_t payload_len,
			       struct uet_uud_pkt *up)
{
	struct uet_entropy *entropy_hdr;
	struct uet_pds_uud_req *uud_hdr;
	void *ses_hdr, *pl;
	size_t ip_hdr_size;
	int hdr_len;
	uint16_t tnf;
	struct uet_fa src_ip;

	ip_hdr_size = (is_ipv6) ? sizeof(struct ipv6hdr)
				: sizeof(struct iphdr);

	memset(&src_ip, 0, sizeof(src_ip));

	if (is_ipv6)
		memcpy(src_ip.v6, uet->nic.ipv6_addr, 16);
	else
		src_ip.v4 = uet->nic.ipv4_addr;

	up->pkt_buf_len = (uet->nic.max_pkt_size * ((sec_enabled) ? 2 : 1));
	up->pkt_buf = calloc(1, up->pkt_buf_len);
	if (up->pkt_buf == NULL) {
		UET_PDS_ERR("UUD: failed to alloc packet buffer");
		return -ENOMEM;
	}

	/* reserve head space for the security header if needed */
	up->pkt = (sec_enabled) ? (up->pkt_buf + UET_SEC_MAX_HDR_LEN)
				: up->pkt_buf;

	uet_build_eth_hdr((struct ethhdr *)up->pkt, (uint8_t *)dst_mac,
			  uet->nic.mac_addr, is_ipv6);

	entropy_hdr = (struct uet_entropy *)(up->pkt + sizeof(struct ethhdr) +
					     ip_hdr_size);
	uud_hdr = (struct uet_pds_uud_req *)(up->pkt + sizeof(struct ethhdr) +
					     ip_hdr_size +
					     sizeof(struct uet_entropy));
	ses_hdr = (uud_hdr + 1);
	pl = ((uint8_t *)ses_hdr + ses_len);

	hdr_len = (sizeof(struct ethhdr) +
		   ip_hdr_size +
		   sizeof(struct uet_entropy) +
		   sizeof(struct uet_pds_uud_req) +
		   ses_len);

	up->pkt_len = (hdr_len + payload_len);

	/* fill in the entropy */
	entropy_hdr->entropy = htons(entropy);
	entropy_hdr->rsvd = 0;

	/* fill in the UUD header */
	tnf = ((UET_PDS_TYPE_UUD_REQ << UET_PDS_TYPE_SHIFT) |
	       (next_hdr << UET_PDS_NEXT_HDR_SHIFT));
	uud_hdr->prlg.type_next_flags = htons(tnf);
	uud_hdr->rsvd = 0;

	/* fill in the SES header */
	if (ses_len)
		memcpy(ses_hdr, ses, ses_len);

	/* fill in the payload */
	if (payload_len)
		memcpy(pl, payload, payload_len);

	/* IP header (crc_en=true only when security is disabled) */
	if (is_ipv6) {
		uet_build_ipv6_hdr(uet,
				   (struct ipv6hdr *)(up->pkt +
						      sizeof(struct ethhdr)),
				   dst_fa->v6, src_ip.v6,
				   (up->pkt_len - uet->nic.l2_hdr_size -
				    ip_hdr_size),
				   tos, !sec_enabled);
	} else {
		uet_build_ipv4_hdr(uet,
				   (struct iphdr *)(up->pkt +
						    sizeof(struct ethhdr)),
				   htonl(dst_fa->v4), htonl(src_ip.v4),
				   (up->pkt_len - uet->nic.l2_hdr_size),
				   tos, !sec_enabled);
	}

	return 0;
}

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
		       bool dma_rdy)
{
	struct uet_instance *uet = uet_ep->uet_domain->uet;
	struct uet_av_entry *av = (struct uet_av_entry *)dst_addr_handle;
	bool is_ipv6 = uet_addr_is_ipv6(av->addr);
	struct uet_uud_pkt up;
	bool sec_enabled;
	uint32_t sdi, ssi;
	int rc;

	/* UUD is a datagram send only with no return-data (read) path */
	if (pds_info) {
		UET_PDS_ERR("UUD: return-data path not supported (send only)");
		return -ENOSYS;
	}

	uet_uud_get_sec(&sec_enabled, &sdi, &ssi);

	memset(&up, 0, sizeof(up));
	up.sec_enabled = sec_enabled;
	up.sdi         = sdi;
	up.ssi         = ssi;
	up.is_ipv6     = is_ipv6;

	rc = uet_uud_build_frame(uet, uet_ep->msg_ip_tos, uet_ep->entropy,
				 av->nh_mac_addr,
				 &av->addr->fa, is_ipv6, sec_enabled, next_hdr,
				 ses, ses_len, pkt, pkt_len, &up);
	if (rc != 0)
		return rc;

	rc = uet_uud_send(uet, &up);

	UET_PDS_DBG("UUD TX REQ msg_id %u len %d%s (rc %d)",
		    msg_id, up.pkt_len, (sec_enabled) ? " (sec)" : "", rc);

	free(up.pkt_buf);

	if (rc != 0)
		return rc;

	/* Fire-and-forget: no response will arrive, so complete the SES tx
	 * descriptor immediately. rx_rsp() with a NULL response packet just
	 * decrements unack_pkts (the "implicitly acknowledged" path).
	 */
	uet->pds.upcall.rx_rsp(tx_pkt_handle, NULL);

	return 0;
}

int uet_pds_uud_rx(struct uet_instance *uet, struct uet_parsed_pkt *pp)
{
	struct uet_pds_info pds_info;
	uet_pds_next_hdr_t rsp_next_hdr;
	uint8_t rsp_ses_hdr[sizeof(struct uet_ses_rsp_d)];
	size_t rsp_ses_hdr_len;
	bool ses_nack = false, gtd_del = false;
	int rc;

	/*
	 * Note: rx_req writes a response SES header to the rsp_ses_hdr
	 * buffer without any payload. No response is ever sent for a UUD
	 * request so the buffer is just a local sink.
	 */

	memset(&pds_info, 0, sizeof(pds_info));

	/* Deliver the untagged single-packet send to a posted receive. SES
	 * generates the rx completion inline.
	 */
	rc = uet->pds.upcall.rx_req((uet_pkt_handle_t)pp, uet, pp, &pds_info,
				    &rsp_next_hdr, rsp_ses_hdr, &rsp_ses_hdr_len,
				    &ses_nack, &gtd_del);
	if (rc != 0)
		UET_PDS_ERR("UUD: SES rx_req failed (rc %d)", rc);

	UET_PDS_DBG("UUD RX REQ delivered (no response)");

	return rc;
}
