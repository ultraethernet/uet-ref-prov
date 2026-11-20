/*
 * Copyright (c) 2026, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* RUDI (Reliable Unordered Delivery for Idempotent operations) engine */

/*
 * RUDI + TSS: REPLAY PROTECTION IS **NOT** SUPPORTED! RUDI is connectionless
 * with no PDC/PSN state, so there is no anti-replay window. Packets may be
 * replayed/duplicated. This is only "safe" because RUDI is used exclusively
 * for idempotent operations (the target MR must be IDEMPOTENT_SAFE).
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include <ofi_list.h>
#include <uthash.h>

#include "uet_api.h"
#include "uet_api_private.h"
#include "uet_pds.h"
#include "uet_pds_rudi.h"
#include "uet_util.h"
#include "uet_log.h"
#include "uet_pkt_hdr.h"
#include "uet_sec.h"
#include "uet_nic.h"
#include "imp_shim.h"
#include "crc32c.h"

/* Per outstanding RUDI request (initiator side). Holds the built cleartext
 * frame for retransmit. On the security path the cleartext lives in the lower
 * half of pkt_buf (see uet_sec_enc_pkt) and only the TSC is refreshed on
 * retransmission.
 */
struct uet_rudi_out_pkt {
	UT_hash_handle     hh; /* rudi.out_ht lookup by pkt_id */
	struct dlist_entry node; /* rudi.rto_list (tx-time ordered) */
	uint32_t           pkt_id; /* wire RUDI packet id (hash key) */
	uet_pkt_handle_t   tx_pkt_handle; /* SES handle, for rx_rsp upcall */
	uint16_t           msg_id;
	struct uet_ep     *uet_ep;
	uint8_t           *pkt_buf; /* full buffer (incl sec headroom) */
	int                pkt_buf_len;
	uint8_t           *pkt; /* start of eth frame (cleartext) */
	int                pkt_len; /* cleartext frame len (no crc/tag) */
	bool               sec_enabled;
	uint32_t           sdi;
	uint32_t           ssi;
	bool               is_ipv6;
	bool               sec_hdr_built; /* sec header injected into pkt */
	int                tx_retry_cnt;
	time_t             tx_time;
};

/* Outstanding RUDI requests are held in two structures kept in sync:
 *   out_ht   - uthash keyed by pkt_id, for response matching (rx_rsp).
 *   rto_list - tx-time ordered (oldest at head) so the RTO walk can stop at
 *              the first not-yet-timed-out entry (progress_tx). A
 *              retransmitted packet gets a fresh tx_time and moves to the
 *              tail.
 */
static struct {
	struct uet_rudi_out_pkt *out_ht; /* uthash head (by pkt_id) */
	struct dlist_entry       rto_list; /* tx-time ordered list */
	uint32_t                 next_pkt_id; /* locally-unique id allocator */
} rudi;

void uet_pds_rudi_init(void)
{
	rudi.out_ht = NULL;
	dlist_init(&rudi.rto_list);

	/* The pkt_id is not a sequence number. Any locally-unique value is
	 * valid. Simple implementation here uses a monotonic counter.
	 */
	rudi.next_pkt_id = 1;
}

void uet_pds_rudi_finalize(void)
{
	struct uet_rudi_out_pkt *rp, *tmp;

	HASH_ITER(hh, rudi.out_ht, rp, tmp) {
		HASH_DEL(rudi.out_ht, rp);
		dlist_remove(&rp->node);
		free(rp->pkt_buf);
		free(rp);
	}
}

size_t uet_pds_rudi_drop_tx_pkts(uet_pkt_handle_t tx_pkt_handle)
{
	struct uet_rudi_out_pkt *rp, *tmp;
	size_t dropped = 0;

	if (tx_pkt_handle == NULL)
		return 0;

	HASH_ITER(hh, rudi.out_ht, rp, tmp) {
		if (rp->tx_pkt_handle != tx_pkt_handle)
			continue;

		HASH_DEL(rudi.out_ht, rp);
		dlist_remove(&rp->node);
		free(rp->pkt_buf);
		free(rp);
		dropped++;
	}

	return dropped;
}

/* FIXME: get the security SDI/SSI, same source as uet_pdsm_get_sdi()! */
static void uet_rudi_get_sec(bool *sec_enabled, uint32_t *sdi, uint32_t *ssi)
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
 * frame. Mirrors uet_pds_sec_tx_pkt() but is PDC-free.
 */
static int uet_rudi_send(struct uet_instance *uet,
			 struct uet_rudi_out_pkt *rp,
			 bool is_rtx)
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

	if (!rp->sec_enabled) {
		rc = uet_parse_pkt(uet, rp->pkt, rp->pkt_len, &pp);
		if (rc != 0)
			return rc;

		/* CRC covers from the IP src addr through the payload */
		crc_start = (pp.is_ipv6) ? ((uint8_t *)pp.ip + 8)
					 : ((uint8_t *)pp.ip + 12);
		crc = crc32c(crc_start,
			     (pp.pkt_len - (crc_start - (uint8_t *)pp.eth)));
		memcpy((rp->pkt + rp->pkt_len), &crc, CRC_LEN);

		out = rp->pkt;
		out_len = rp->pkt_len + CRC_LEN;
		uet_gettime(&rp->tx_time);

		if (imp_shim_is_enabled())
			return imp_shim_tx_pkt(UET_NIC(uet), out, pp.ip, out_len);

		return uet_nic_tx_pkt(UET_NIC(uet), out, pp.ip, out_len);
	}

	/* security enabled */
	if (is_rtx) {
		/* refresh only the TSC and re-encrypt from the cleartext copy */
		rc = uet_sec_update_hdr_tsc(rp->pkt, rp->is_ipv6);
		if (rc != 0)
			return rc;
	} else if (!rp->sec_hdr_built) {
		rc = uet_sec_build_hdr(rp->sdi, rp->ssi, rp->pkt_buf,
				       rp->pkt_buf_len, rp->pkt, rp->pkt_len,
				       &new_pkt, &new_pkt_len, rp->is_ipv6);
		if (rc != 0)
			return rc;

		rp->pkt = new_pkt;
		rp->pkt_len = (new_pkt_len + UET_SEC_TAG_LEN);
		rp->sec_hdr_built = true;

		/* fix IP length after security header injection */
		rc = uet_parse_pkt(uet, rp->pkt, rp->pkt_len, &pp);
		if (rc != 0)
			return rc;

		if (pp.is_ipv6) {
			uet_update_ipv6_pl(pp.ip,
					   (rp->pkt_len -
					    uet->nic.l2_hdr_size -
					    sizeof(struct ipv6hdr)));
		} else {
			uet_update_ipv4_tl(pp.ip,
					   (rp->pkt_len -
					    uet->nic.l2_hdr_size));
		}
	}

	rc = uet_sec_enc_pkt(uet, rp->pkt_buf, rp->pkt_buf_len, rp->pkt,
			     rp->pkt_len, &enc_pkt, &enc_pkt_len, rp->is_ipv6);
	if (rc != 0)
		return rc;

	uet_gettime(&rp->tx_time);

	/* get a pointre to the IP header in the encrypted packet */
	enc_ip = enc_pkt + sizeof(struct ethhdr);

	if (imp_shim_is_enabled())
		return imp_shim_tx_pkt(UET_NIC(uet), enc_pkt, enc_ip,
				       enc_pkt_len);

	return uet_nic_tx_pkt(UET_NIC(uet), enc_pkt, enc_ip,
			      enc_pkt_len);
}

/* Build a RUDI frame (request or response). Allocates a new pkt_buf and fills
 * in the cleartext packet (eth/ip/entropy/RUDI/SES/payload).
 */
static int uet_rudi_build_frame(struct uet_instance *uet,
				uint8_t tos,
				uint16_t entropy,
				const uint8_t *dst_mac,
				const struct uet_fa *dst_fa,
				bool is_ipv6, bool sec_enabled,
				uet_pds_pkt_type_t pds_type,
				uet_pds_next_hdr_t next_hdr,
				uint32_t pkt_id,
				void *ses, size_t ses_len,
				void *payload, size_t payload_len,
				struct uet_rudi_out_pkt *rp)
{
	struct uet_entropy *entropy_hdr;
	struct uet_pds_rudi_req *rudi_hdr;
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

	rp->pkt_buf_len = (uet->nic.max_pkt_size * ((sec_enabled) ? 2 : 1));
	rp->pkt_buf = calloc(1, rp->pkt_buf_len);
	if (rp->pkt_buf == NULL) {
		UET_PDS_ERR("RUDI: failed to alloc packet buffer");
		return -ENOMEM;
	}

	/* reserve head space for the security header if needed */
	rp->pkt = (sec_enabled) ? (rp->pkt_buf + UET_SEC_MAX_HDR_LEN)
				: rp->pkt_buf;

	uet_build_eth_hdr((struct ethhdr *)rp->pkt, (uint8_t *)dst_mac,
			  uet->nic.mac_addr, is_ipv6);

	entropy_hdr = (struct uet_entropy *)(rp->pkt + sizeof(struct ethhdr) +
					     ip_hdr_size);
	rudi_hdr = (struct uet_pds_rudi_req *)(rp->pkt + sizeof(struct ethhdr) +
					       ip_hdr_size +
					       sizeof(struct uet_entropy));
	ses_hdr = (rudi_hdr + 1);
	pl = ((uint8_t *)ses_hdr + ses_len);

	hdr_len = (sizeof(struct ethhdr) +
		   ip_hdr_size +
		   sizeof(struct uet_entropy) +
		   sizeof(struct uet_pds_rudi_req) +
		   ses_len);

	rp->pkt_len = (hdr_len + payload_len);

	/* fill in the entropy */
	entropy_hdr->entropy = htons(entropy);
	entropy_hdr->rsvd = 0;

	/* fill in the RUDI header */
	tnf = ((pds_type << UET_PDS_TYPE_SHIFT) |
	       (next_hdr << UET_PDS_NEXT_HDR_SHIFT));
	rudi_hdr->prlg.type_next_flags = htons(tnf);
	rudi_hdr->rsvd = 0;
	rudi_hdr->pkt_id = htonl(pkt_id);

	/* fill in the SES header */
	if (ses_len)
		memcpy(ses_hdr, ses, ses_len);

	/* fill in the payload */
	if (payload_len)
		memcpy(pl, payload, payload_len);

	/* IP header (crc_en=true only when security is disabled) */
	if (is_ipv6) {
		uet_build_ipv6_hdr(uet,
				   (struct ipv6hdr *)(rp->pkt +
						      sizeof(struct ethhdr)),
				   dst_fa->v6, src_ip.v6,
				   (rp->pkt_len - uet->nic.l2_hdr_size -
				    ip_hdr_size),
				   tos, !sec_enabled);
	} else {
		uet_build_ipv4_hdr(uet,
				   (struct iphdr *)(rp->pkt +
						    sizeof(struct ethhdr)),
				   htonl(dst_fa->v4), htonl(src_ip.v4),
				   (rp->pkt_len - uet->nic.l2_hdr_size),
				   tos, !sec_enabled);
	}

	return 0;
}

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
			bool dma_rdy)
{
	struct uet_instance *uet = uet_ep->uet_domain->uet;
	struct uet_av_entry *av = (struct uet_av_entry *)dst_addr_handle;
	bool is_ipv6 = uet_addr_is_ipv6(av->addr);
	struct uet_rudi_out_pkt *rp;
	bool sec_enabled;
	uint32_t sdi, ssi, pkt_id;
	int rc;

        /* RUDI has no PDC and no SES-driven return-data path. A RUDI read is
         * answered inline by the stateless responder (uet_rudi_rx_req builds
         * the data-carrying RUDI response), never via pds_info.
         */
        if (pds_info) {
		UET_PDS_ERR("RUDI: pds_info return-data path not used by RUDI");
		return -ENOSYS;
	}

	uet_rudi_get_sec(&sec_enabled, &sdi, &ssi);

	rp = calloc(1, sizeof(*rp));
	if (rp == NULL)
		return -ENOMEM;

	pkt_id = rudi.next_pkt_id++;

	rc = uet_rudi_build_frame(uet, uet_ep->msg_ip_tos, uet_ep->entropy,
				  av->nh_mac_addr,
				  &av->addr->fa, is_ipv6, sec_enabled,
				  UET_PDS_TYPE_RUDI_REQ, next_hdr, pkt_id,
				  ses, ses_len, pkt, pkt_len, rp);
	if (rc != 0) {
		free(rp);
		return rc;
	}

	rp->pkt_id        = pkt_id;
	rp->tx_pkt_handle = tx_pkt_handle;
	rp->msg_id        = msg_id;
	rp->uet_ep        = uet_ep;
	rp->sec_enabled   = sec_enabled;
	rp->sdi           = sdi;
	rp->ssi           = ssi;
	rp->is_ipv6       = is_ipv6;
	rp->tx_retry_cnt  = 0;

	rc = uet_rudi_send(uet, rp, false);
	if (rc != 0) {
		free(rp->pkt_buf);
		free(rp);
		return rc;
	}

	UET_PDS_DBG("RUDI TX REQ pkt_id %u msg_id %u len %d%s",
		    pkt_id, msg_id, rp->pkt_len,
		    (sec_enabled) ? " (sec)" : "");

	/* track for response matching (hash) + per-packet RTO (dlist) */
	HASH_ADD(hh, rudi.out_ht, pkt_id, sizeof(rp->pkt_id), rp);
	dlist_insert_tail(&rp->node, &rudi.rto_list);

	return 0;
}

/* Target: RUDI request received -> SES processing -> one RUDI response */
static int uet_rudi_rx_req(struct uet_instance *uet,
			   struct uet_parsed_pkt *pp)
{
	struct uet_pds_info pds_info;
	uet_pds_next_hdr_t rsp_next_hdr;
	void *rsp_ses_hdr;
	size_t rsp_ses_hdr_len;
	bool sec_enabled, ses_nack = false, gtd_del = false;
	uint32_t sdi, ssi;
	struct uet_rudi_out_pkt rsp;
	struct uet_fa dst_fa;
	uint8_t *dst_mac;
	struct ethhdr *eth;
	int rc;

        /* Sized to hold a full read-response chunk inline. A RUDI read
         * request is answered by one data-carrying RUDI response and the
	 * chunk is up to max_payload_len bytes. A write response carries
	 * no data and this just over-allocates for it.
         */
        rsp_ses_hdr = calloc(1, (sizeof(struct uet_ses_rsp_d) +
				 uet->max_payload_len));
	if (rsp_ses_hdr == NULL)
		return -ENOMEM;

	/* RUDI has no PDC; pds_info is unused for the (write) response. */
	memset(&pds_info, 0, sizeof(pds_info));

	rc = uet->pds.upcall.rx_req((uet_pkt_handle_t)pp, uet, pp,
				    &pds_info, &rsp_next_hdr, rsp_ses_hdr,
				    &rsp_ses_hdr_len, &ses_nack, &gtd_del);
	if (rc != 0) {
		UET_PDS_ERR("RUDI: SES rx_req failed (pkt_id %u rc %d)",
			    pp->pds_rudi_pkt_id, rc);
		free(rsp_ses_hdr);
		return rc;
	}

	if (ses_nack) {
		/*
		 * FIXME: send a RUDI NACK. For now, not responding causes the
		 * initiator's RTO to retransmit the request.
		 */
		UET_PDS_WARN("RUDI: SES NACK for pkt_id %u (no response sent)",
			     pp->pds_rudi_pkt_id);
		free(rsp_ses_hdr);
		return 0;
	}

	uet_rudi_get_sec(&sec_enabled, &sdi, &ssi);

	/* build the RUDI response back to the initiator echoing pkt_id */

	eth = (struct ethhdr *)pp->eth;
	dst_mac = eth->h_source;

	memset(&dst_fa, 0, sizeof(dst_fa));
	if (pp->is_ipv6)
		memcpy(dst_fa.v6, &((struct ipv6hdr *)pp->ip)->saddr, 16);
	else
		dst_fa.v4 = ntohl(((struct iphdr *)pp->ip)->saddr);

	/* FIXME: RUDI responses should use the DSCP controll codepoint */
	memset(&rsp, 0, sizeof(rsp));
	rc = uet_rudi_build_frame(uet, uet->default_msg_ip_tos,
				  pp->entropy_val, dst_mac,
				  &dst_fa, pp->is_ipv6, sec_enabled,
				  UET_PDS_TYPE_RUDI_RESP, rsp_next_hdr,
				  pp->pds_rudi_pkt_id, rsp_ses_hdr,
				  rsp_ses_hdr_len, NULL, 0, &rsp);
	if (rc != 0) {
		free(rsp_ses_hdr);
		return rc;
	}

	rsp.sec_enabled = sec_enabled;
	rsp.sdi = sdi;
	rsp.ssi = ssi;
	rsp.is_ipv6 = pp->is_ipv6;

	rc = uet_rudi_send(uet, &rsp, false);

	UET_PDS_DBG("RUDI TX RSP pkt_id %u len %d%s (rc %d)",
		    pp->pds_rudi_pkt_id, rsp.pkt_len,
		    (sec_enabled) ? " (sec)" : "", rc);

	free(rsp.pkt_buf);
	free(rsp_ses_hdr);

	return rc;
}

/* Initiator: RUDI response received -> match pkt_id -> SES completion */
static int uet_rudi_rx_rsp(struct uet_instance *uet,
			   struct uet_parsed_pkt *pp)
{
	struct uet_rudi_out_pkt *rp;
	uint32_t pkt_id = pp->pds_rudi_pkt_id;

	HASH_FIND(hh, rudi.out_ht, &pkt_id, sizeof(pkt_id), rp);
	if (rp == NULL) {
		/* no match: dup/late response, idempotent safely ignored */
		UET_PDS_DBG("RUDI RX RSP pkt_id %u unmatched (duplicate) -- ignored",
			    pkt_id);
		return 0;
	}

	UET_PDS_DBG("RUDI RX RSP pkt_id %u -> complete", rp->pkt_id);

	/* SES completion for this packet (decrements unack_pkts) */
	uet->pds.upcall.rx_rsp(rp->tx_pkt_handle, pp);

	HASH_DEL(rudi.out_ht, rp);
	dlist_remove(&rp->node);
	free(rp->pkt_buf);
	free(rp);

	return 0;
}

int uet_pds_rudi_rx(struct uet_instance *uet, struct uet_parsed_pkt *pp)
{
	int rc;

	if (pp->pds_type == UET_PDS_TYPE_RUDI_REQ)
		rc = uet_rudi_rx_req(uet, pp);
	else
		rc = uet_rudi_rx_rsp(uet, pp);

	return rc;
}

int uet_pds_rudi_progress_tx(struct uet_ep *uet_ep,
			     uet_pkt_handle_t *err_pkt_handle)
{
	struct uet_instance *uet = uet_ep->uet_domain->uet;
	struct uet_rudi_out_pkt *rp;
	struct dlist_entry *tmp;
	uet_pkt_handle_t failed;
	time_t now;
	int rc;

	uet_gettime(&now);

	/* rto_list is ordered oldest-first, so stop at the first entry that
	 * has not yet timed out. A retransmitted entry gets a fresh tx_time
	 * and is moved to the tail to preserve the ordering.
	 */
	dlist_foreach_container_safe(&rudi.rto_list, struct uet_rudi_out_pkt,
				     rp, node, tmp) {
		if ((now - rp->tx_time) < uet->pds.tx_timeout)
			break;

		if (rp->tx_retry_cnt >= uet->pds.max_tx_retries) {
			failed = rp->tx_pkt_handle;

			UET_PDS_ERR("RUDI: pkt_id %u exceeded max retries",
				    rp->pkt_id);

			if (err_pkt_handle)
				*err_pkt_handle = failed;

			HASH_DEL(rudi.out_ht, rp);
			dlist_remove(&rp->node);
			free(rp->pkt_buf);
			free(rp);

			/* Everything else outstanding for this message goes
			 * as well. The upcall below fails the whole message.
			 */
			uet_pds_rudi_drop_tx_pkts(failed);

			/* This upcall completes the descriptor and hands it
			 * back for reuse.
			 */
			uet->pds.upcall.pds_err(failed, UET_PDS_ERR_NONE);

			return -EPROTO;
		}

		rp->tx_retry_cnt++;

		UET_PDS_DBG("RUDI: RTO retransmit pkt_id %u (retry %d)",
			    rp->pkt_id, rp->tx_retry_cnt);

		/* move to the tail, uet_rudi_send() refreshes tx_time */
		dlist_remove(&rp->node);
		dlist_insert_tail(&rp->node, &rudi.rto_list);

		rc = uet_rudi_send(uet, rp, true);
		if (rc != 0)
			return rc;
	}

	return 0;
}
