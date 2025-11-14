/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <ofi_list.h>
#include <uthash.h>

#include "uet_api.h"
#include "uet_pds.h"
#include "uet_api_private.h"
#include "uet_nic.h"
#include "uet_util.h"
#include "uet_log.h"
#include "uet_pkt_chk.h"
#include "uet_pkt_hdr.h"
#include "uet_sec.h"
#include "bitmap.h"
#include "crc32c.h"

#define UET_DEFAULT_TC        0
#define UET_DEFAULT_MPR       128
#define UET_DEFAULT_START_PSN 13
#define UET_DEFAULT_ENTROPY   0x4242

#define UET_PDC_MAX 64

/*
 * These random thresholds can be overridden with the UET_PDC_CLOSE_THRESH
 * and the UET_PKT_DROP_THRESH environment variables. The values are
 * represented in hundredths of a percent (1=0.01%, 100=1%, etc).
 */
#define UET_PDC_CLOSE_THRESH 50
#define UET_PKT_DROP_THRESH  50

typedef enum {
	PDC_STATE_UNALLOC,
	PDC_STATE_SYN,
	PDC_STATE_ESTABLISHED,
	PDC_STATE_CLOSING,
	PDC_STATE_ERROR,
} pdc_state_t;

typedef enum {
	PDC_TYPE_NONE,
	PDC_TYPE_RUD,
	PDC_TYPE_ROD,
} pdc_type_t;

struct uet_pdc_pkt {
	struct dlist_entry    node;
	int                   psn;
	uint16_t              msg_id;

	uint8_t              *pkt_buf;
	int                   pkt_buf_len;
	uint8_t              *pkt;
	int                   pkt_len;
	time_t                tx_time; /* tx time for detecting timeout */
	int                   tx_retry_cnt;  /* number of retransmissions */
	uet_pkt_handle_t      tx_pkt_handle;
	bool                  tx_pkt_acked; /* this packet has been acked */
	uet_pds_tx_flags_t    flags;

	bool                  needs_clear;
	bool                  reordered; /* rx_req() upcall called for ROD */

	uint8_t              *ack_buf;
	int                   ack_buf_len;
	uint8_t              *ack;
	int                   ack_len;

	struct uet_parsed_pkt pkt_pp;
	bool                  pkt_parsed;
	struct uet_parsed_pkt ack_pp;
	bool                  ack_parsed;
};

/* The PDC key used for hash table lookups. */
struct uet_pdc_ini_key {
	pdc_type_t    type;
	uint32_t      job_id;
	struct uet_fa src_ip;
	struct uet_fa dst_ip;
	uint8_t       tc;
};

struct uet_pdc_tgt_key {
	struct uet_fa src_ip;
	struct uet_fa dst_ip;
	uint16_t      spdcid;
};

struct uet_pdc {
	struct dlist_entry  node;

	pdc_state_t         state;
	bool                is_initiator;

	uint16_t            pdc_id; /* local PDC identifier */
	uint16_t            dpdcid; /* peer PDC identifier */

	uint16_t            active_msg_id; /* msg_id currently being sent */
	bool                active_msg_id_valid;

	bool                close_requested; /* close has been requested */
	bool                close_started; /* close has started */
	uint32_t            close_cmd_psn; /* PSN of the close command */

	struct uet_pdc_ini_key ini_hkey;
	UT_hash_handle         pdc_ini_hh; /* initiator hash handle for the PDC */
	struct uet_pdc_tgt_key tgt_hkey;
	UT_hash_handle         pdc_tgt_hh; /* target hash handle for the PDC */

	struct dlist_entry  tx_pkt_list_head; /* 'tx_time' order (for rtx) */

	/* initiator side fields (and target side reverse direction) */
	uint8_t              src_mac_addr[ETH_ALEN];
	uint8_t              dst_mac_addr[ETH_ALEN];
	struct uet_fa        src_addr;
	struct uet_fa        dst_addr;
	uint16_t             syn_offset; /* initiator SYN offset until ACK */
	uint32_t             next_psn; /* next Tx pkt seq number */
	struct bitmap       *tx_bm;
	uint32_t             tx_bm_base_psn; /* start PSN for initiator MPR */

	/* target side fields */
	struct bitmap      *rx_bm;
	uint32_t            rx_bm_base_psn; /* start PSN for target MPR */

	/* security fields, for Tx */
	bool                sec_enabled;
	uint32_t            sdi;
	uint32_t            ssi;
};

struct uet_msgid_map {
	uint16_t        msg_id;
	UT_hash_handle  msgid_hh; /* hash handle for the PDC */
	struct uet_pdc *pdc;
};

struct uet_pds_state {
	bool                  ready;
	struct uet_pdc        pdc[UET_PDC_MAX];
	struct dlist_entry    pdc_alloc_head;
	struct dlist_entry    pdc_free_head;
	struct uet_pdc       *pdc_ini_ht; /* key=[type|jobid|srcip|dstip|tc] */
	struct uet_pdc       *pdc_tgt_ht; /* key=[srcip|dstip|spdcid] */
	struct uet_msgid_map *pdc_msgid_ht; /* key=[msg_id] */
};

static struct uet_pds_state pds_state;

static int pds_pdc_close_thresh = UET_PDC_CLOSE_THRESH;
static int pds_pkt_drop_thresh = UET_PKT_DROP_THRESH;

/*
 * Test if a random event should occur based on a threshold. Threshold is in
 * hundredths of a percent (0.01% granularity). Returns true if event should
 * occur.
 */
static inline bool uet_pds_random_check(int thresh)
{
	return ((rand() % 10000) < thresh);
}

#define PDS_GO()                                          \
	do {                                              \
		if (pds_state.ready != true) {            \
			UET_PDS_ERR("PDS is not ready!"); \
			exit(1);                          \
		}                                         \
	} while (0)

#define PSN_IN_MPR(psn, base_psn)                            \
	(((uint32_t)((psn) - (base_psn)) >= 0) &&            \
	 ((uint32_t)((psn) - (base_psn)) < UET_DEFAULT_MPR))

#define PSN_IN_PRIOR_MPR(psn, base_psn)                             \
	PSN_IN_MPR((psn), (uint32_t)((base_psn) - UET_DEFAULT_MPR))

#define PDS_TYPE_TO_STR(t)                                 \
	(((t) == UET_PDS_TYPE_RUD_REQ)    ? "RUD_REQ" :    \
	 ((t) == UET_PDS_TYPE_ROD_REQ)    ? "ROD_REQ" :    \
	 ((t) == UET_PDS_TYPE_RUDI_REQ)   ? "RUDI_REQ" :   \
	 ((t) == UET_PDS_TYPE_RUDI_RESP)  ? "RUDI_RSP" :   \
	 ((t) == UET_PDS_TYPE_UUD_REQ)    ? "UUD_REQ" :    \
	 ((t) == UET_PDS_TYPE_ACK)        ? "ACK" :        \
	 ((t) == UET_PDS_TYPE_ACK_CC)     ? "ACK_CC" :     \
	 ((t) == UET_PDS_TYPE_ACK_CCX)    ? "ACK_CCX" :    \
	 ((t) == UET_PDS_TYPE_NACK)       ? "NACK" :       \
	 ((t) == UET_PDS_TYPE_CTRL)       ? "CTRL" :       \
	 ((t) == UET_PDS_TYPE_NACK_CCX)   ? "NACK_CCX" :   \
	 ((t) == UET_PDS_TYPE_RUD_CC_REQ) ? "RUD_CC_REQ" : \
	 ((t) == UET_PDS_TYPE_ROD_CC_REQ) ? "ROD_CC_REQ" : \
					   "UNKNOWN")

#define PDS_CTRL_TO_STR(n)                                        \
	(((n) == UET_PDS_CTRL_TYPE_NOP)         ? "NOP" :         \
	 ((n) == UET_PDS_CTRL_TYPE_ACK_REQ)     ? "ACK_REQ" :     \
	 ((n) == UET_PDS_CTRL_TYPE_CLEAR)       ? "CLEAR" :       \
	 ((n) == UET_PDS_CTRL_TYPE_CLEAR_REQ)   ? "CLEAR_REQ" :   \
	 ((n) == UET_PDS_CTRL_TYPE_CLOSE)       ? "CLOSE" :       \
	 ((n) == UET_PDS_CTRL_TYPE_CLOSE_REQ)   ? "CLOSE_REQ" :   \
	 ((n) == UET_PDS_CTRL_TYPE_PROBE)       ? "PROBE" :       \
	 ((n) == UET_PDS_CTRL_TYPE_CREDIT)      ? "CREDIT" :      \
	 ((n) == UET_PDS_CTRL_TYPE_CREDIT_REQ)  ? "CREDIT_REQ" :  \
	 ((n) == UET_PDS_CTRL_TYPE_NEGOTIATION) ? "NEGOTIATION" : \
						  "UNKNOWN")

#define NEXT_HDR_TO_STR(n)                                    \
	(((n) == UET_HDR_NONE)           ? "NONE" :           \
	 ((n) == UET_HDR_REQ_SMALL)      ? "REQ_SMALL" :      \
	 ((n) == UET_HDR_REQ_MEDIUM)     ? "REQ_MEDIUM" :     \
	 ((n) == UET_HDR_REQ_STD)        ? "REQ_STD" :        \
	 ((n) == UET_HDR_RSP)            ? "RSP" :            \
	 ((n) == UET_HDR_RSP_DATA)       ? "RSP_DATA" :       \
	 ((n) == UET_HDR_RSP_DATA_SMALL) ? "RSP_DATA_SMALL" : \
					   "UNKNOWN")

#define PDS_DBG_TX(pp, msg)                                      \
	UET_PDS_DBG("PDC %u [Tx %u] [PSN %u] [%s/%s] - %s (%d)", \
		    (pp)->pds_spdcid, (pp)->pds_dpdcid,          \
		    (pp)->pds_psn,                               \
		    PDS_TYPE_TO_STR((pp)->pds_type),             \
		    ((pp)->pds_type == UET_PDS_TYPE_CTRL)        \
			? PDS_CTRL_TO_STR((pp)->pds_ctrl_type)   \
			: NEXT_HDR_TO_STR((pp)->next_hdr),       \
		    (msg),                                       \
		    (pp)->pkt_len)

#define PDS_DBG_RX(pp, msg)                                      \
	UET_PDS_DBG("PDC %u [Rx %u] [PSN %u] [%s/%s] - %s (%d)", \
		    (pp)->pds_dpdcid, (pp)->pds_spdcid,          \
		    (pp)->pds_psn,                               \
		    PDS_TYPE_TO_STR((pp)->pds_type),             \
		    ((pp)->pds_type == UET_PDS_TYPE_CTRL)        \
			? PDS_CTRL_TO_STR((pp)->pds_ctrl_type)   \
			: NEXT_HDR_TO_STR((pp)->next_hdr),       \
		    (msg),                                       \
		    (pp)->pkt_len)

static void uet_pds_pkt_dbg(struct uet_instance *uet,
			    struct uet_parsed_pkt *pp,
			    bool is_tx,
			    const char *msg)
{
#if defined(UET_LOG_PDS) && (UET_LOG_LVL >= UET_LOG_DBG)
	if (is_tx)
		PDS_DBG_TX(pp, msg);
	else
		PDS_DBG_RX(pp, msg);
#endif

	UET_PDS_PKT_HDR_TRACE(uet, pp, NULL, 0, msg);
}

int16_t psn_2c_offset(uint32_t base_psn, uint32_t psn)
{
	int32_t offset;

	offset = (~(base_psn - psn) + 1); /* two's complement */
	assert((base_psn + offset) == psn);

	return offset;
}

char uet_pdc_tx_bit_char(void *data)
{
	struct uet_pdc_pkt *pdc_pkt = (struct uet_pdc_pkt *)data;
	return (pdc_pkt == NULL) ? '.' : (pdc_pkt->tx_pkt_acked ? 'X' : 'O');
}

char uet_pdc_rx_bit_char(void *data)
{
	struct uet_pdc_pkt *pdc_pkt = (struct uet_pdc_pkt *)data;
	return (pdc_pkt == NULL) ? '.' : '*';
}

/****************************************************************************/
/*                       Security and NIC Shim APIs                         */
/****************************************************************************/

static int uet_pds_sec_tx_pkt(struct uet_instance *uet,
			      struct uet_pdc *pdc,
			      struct uet_pdc_pkt *pdc_pkt,
			      bool tx_pkt, /* false = tx_ack */
			      bool is_rtx)
{
	uint8_t *pkt_buf;
	int pkt_buf_len;
	uint8_t **pkt;
	int *pkt_len;
	uint8_t *new_pkt;
	int new_pkt_len;
	struct uet_parsed_pkt *pp;
	bool *pp_parsed;
	struct uet_pds_req *pds_hdr;
	uint32_t crc;
	uint8_t *crc_start;
	bool update_ipv4_tl = false;
	int rc;

	if (tx_pkt) {
		pkt_buf     = pdc_pkt->pkt_buf;
		pkt_buf_len = pdc_pkt->pkt_buf_len;
		pkt         = &pdc_pkt->pkt;
		pkt_len     = &pdc_pkt->pkt_len;
		pp          = &pdc_pkt->pkt_pp;
		pp_parsed   = &pdc_pkt->pkt_parsed;
	} else {
		pkt_buf     = pdc_pkt->ack_buf;
		pkt_buf_len = pdc_pkt->ack_buf_len;
		pkt         = &pdc_pkt->ack;
		pkt_len     = &pdc_pkt->ack_len;
		pp          = &pdc_pkt->ack_pp;
		pp_parsed   = &pdc_pkt->ack_parsed;
	}

	/*
	 * If security is not enabled, just pass the packet through. The CRC
	 * will be added and for IPv4, the total length already includes the
	 * length of the CRC. Lastly, if the packet hasn't been parsed yet for
	 * debug then do it now.
	 */
	if (pdc->sec_enabled == false) {
		if (*pp_parsed == false) {
			rc = uet_parse_pkt(uet, *pkt, *pkt_len, pp);
			if (rc != 0) {
				UET_PDS_ERR("malformed %s packet",
					    (tx_pkt) ? "Tx" : "ACK");
				return rc;
			}

			*pp_parsed = true;
		}

		/* calculate the CRC (include src/dst IP and UDP) */
		/* TODO: IPv6 support */
		crc_start = ((uint8_t *)pp->ip + 12);
		crc = crc32c(crc_start,
			     (pp->pkt_len -
			      (crc_start - (uint8_t *)pp->eth)));

		/* append the CRC and adjust the transmit length */
		memcpy((*pkt + *pkt_len), &crc, CRC_LEN);
		new_pkt_len = (*pkt_len + CRC_LEN);

		if (tx_pkt)
			uet_gettime(&pdc_pkt->tx_time);

		/* randomly drop packets for testing retransmit logic */
		if (pds_pkt_drop_thresh &&
		    uet_pds_random_check(pds_pkt_drop_thresh)) {
			UET_PDS_WARN("PDC %u PSN %u random drop %s packet!",
				     pdc->pdc_id, pp->pds_psn,
				     (tx_pkt) ? "Tx" : "ACK");
			return 0;
		}

		/* TODO: IPv6 support */
		return uet_nic_tx_pkt(UET_NIC(uet), *pkt, pp->ip, new_pkt_len);
	}

	/* inject/build the security header and encrypt the packet */

	if (is_rtx) {
		rc = uet_sec_update_hdr_tsc(*pkt);
		if (rc != 0)
			return rc;
	} else {
		rc = uet_sec_build_hdr(pdc->sdi,
				       pdc->ssi,
				       pkt_buf,
				       pkt_buf_len,
				       *pkt,
				       *pkt_len,
				       &new_pkt,
				       &new_pkt_len);
		if (rc != 0)
			return rc;

		*pkt     = new_pkt;
		*pkt_len = (new_pkt_len + UET_SEC_TAG_LEN);

		/* for IPv4 the total length and checksum needs fixing */
		/* TODO: not with IPv6 */
		update_ipv4_tl = true;
	}

	/* If the packet hasn't been parsed yet for debug then do it now. */
	if (*pp_parsed == false) {
		rc = uet_parse_pkt(uet, *pkt, *pkt_len, pp);
		if (rc != 0) {
			UET_PDS_ERR("malformed %s packet with security",
				    (tx_pkt) ? "Tx" : "ACK");
			return rc;
		}

		*pp_parsed = true;
	}

	/* TODO: IPv6 support (don't do this) */
	if (update_ipv4_tl)
		uet_update_ipv4_tl(pp->ip, (*pkt_len - uet->nic.l2_hdr_size));

	rc = uet_sec_enc_pkt(uet,
			     pkt_buf,
			     pkt_buf_len,
			     *pkt,
			     *pkt_len,
			     &new_pkt,
			     &new_pkt_len);
	if (rc != 0)
		return rc;

	if (tx_pkt)
		uet_gettime(&pdc_pkt->tx_time);

	/* randomly drop packets for testing retransmit logic */
	if (pds_pkt_drop_thresh &&
	    uet_pds_random_check(pds_pkt_drop_thresh)) {
		UET_PDS_WARN("PDC %u PSN %u random drop %s packet!",
			     pdc->pdc_id, pp->pds_psn,
			     (tx_pkt) ? "Tx" : "ACK");
		return 0;
	}

	/* TODO: IPv6 support */
	return uet_nic_tx_pkt(UET_NIC(uet), new_pkt, pp->ip, new_pkt_len);
}

/*
 * Returns:
 *   0, no valid packet available
 *   1, read a packet
 *   negative value corresponding to errno, err reading packet
 */
static int uet_pds_sec_rx_pkt(struct uet_instance *uet,
			      uint8_t **pkt,
			      size_t *pkt_len)
{
	int tag_len;
	int rc;

	*pkt = NULL;
	*pkt_len = 0;

	/* check if packet is available */
	rc = uet_nic_rx_poll(UET_NIC(uet));
	if (rc != 1)
		return rc;

	/* TODO: Remove this malloc... */
	/* allocate a receive packet buffer */
	*pkt = calloc(1, uet->nic.max_pkt_size);
	if (*pkt == NULL) {
		UET_PDS_ERR("failed to alloc Rx packet buffer");
		return -ENOMEM;
	}

	/* receive the packet */
	rc = uet_nic_rx_pkt(UET_NIC(uet),
			    *pkt,
			    uet->nic.max_pkt_size,
			    pkt_len);
	if (rc != 1)
		goto err_exit;

	/* decrypt the packet if the security header is present */
	rc = uet_sec_dec_pkt(uet, *pkt, *pkt_len, &tag_len);
	if (rc != 0)
		goto err_exit;

	return 1;

err_exit:
	free(*pkt);
	*pkt = NULL;
	*pkt_len = 0;
	return rc;
}

/****************************************************************************/
/*                            PDS Manager APIs                              */
/****************************************************************************/

static void uet_init_pdc(struct uet_pdc *pdc,
			 pdc_state_t state,
			 bool is_initiator)
{
	pdc->state = state;
	pdc->is_initiator = is_initiator;

	pdc->dpdcid = 0;

	pdc->active_msg_id = 0;
	pdc->active_msg_id_valid = false;

	pdc->close_requested = false;
	pdc->close_started = false;
	pdc->close_cmd_psn = 0;

	dlist_init(&pdc->tx_pkt_list_head);

	memset(pdc->src_mac_addr, 0, ETH_ALEN);
	memset(pdc->dst_mac_addr, 0, ETH_ALEN);
	memset(&pdc->src_addr, 0, sizeof(struct uet_fa));
	memset(&pdc->dst_addr, 0, sizeof(struct uet_fa));

	pdc->syn_offset = 0;
	pdc->next_psn = 0;
	bm_clear(pdc->tx_bm);
	pdc->tx_bm_base_psn = 0;

	bm_clear(pdc->rx_bm);
	pdc->rx_bm_base_psn = 0;
}

static struct uet_pdc *uet_pdsm_alloc_pdc(void)
{
	struct uet_pdc *pdc;

	PDS_GO();

	/* allocate a new PDC from the head of the free list */
	pdc = dlist_first_entry_or_null(&pds_state.pdc_free_head,
					struct uet_pdc, node);
	if (pdc == NULL)
		return NULL;

	dlist_remove(&pdc->node);

	dlist_insert_tail(&pdc->node, &pds_state.pdc_alloc_head);

	return pdc;
}

static void uet_pdsm_free_pdc(struct uet_pdc *pdc)
{
	PDS_GO();

	UET_PDS_DBG("freeing PDC %u (state=UNALLOC) (is_initiator=%d)",
		    pdc->pdc_id, pdc->is_initiator);

	/* remove from hash tables */
	if (pdc->is_initiator)
		HASH_DELETE(pdc_ini_hh, pds_state.pdc_ini_ht, pdc);
	else
		HASH_DELETE(pdc_tgt_hh, pds_state.pdc_tgt_ht, pdc);

	pdc->state = PDC_STATE_UNALLOC;

	/* reset close tracking fields */
	pdc->close_requested = false;
	pdc->close_started = false;
	pdc->close_cmd_psn = 0;

	/* reset active message tracking */
	pdc->active_msg_id = 0;
	pdc->active_msg_id_valid = false;

	/* free a PDC by inserting to the tail of the free list */
	dlist_remove(&pdc->node);
	dlist_insert_tail(&pdc->node, &pds_state.pdc_free_head);
}

/* FIXME: get the security SDI/SSI based on JobID */
static void uet_pdsm_get_sdi(struct uet_pdc *pdc)
{
	char *sec_ssi;

	pdc->sec_enabled = !!getenv(UET_SEC_MODE);
	pdc->sdi = 1; /* fixed SDI for now... */
	pdc->ssi = 0;

	sec_ssi = getenv(UET_SEC_SSI);
	if (sec_ssi)
		pdc->ssi = strtoul(sec_ssi, NULL, 10);
}

static struct uet_pdc *uet_pdsm_assign_ini_pdc(struct uet_ep *uet_ep,
					       struct uet_av_entry *av_entry,
					       uet_pds_mode_t mode)
{
	struct uet_pdc_ini_key pdc_key;
	struct uet_pdc *pdc;

	PDS_GO();

	/* get the PDC if it already exists */
	memset(&pdc_key, 0, sizeof(pdc_key));
	pdc_key.type = ((mode == UET_PDS_MODE_ROD) ? PDC_TYPE_ROD :
			(mode == UET_PDS_MODE_RUD) ? PDC_TYPE_RUD :
						     PDC_TYPE_NONE);
	pdc_key.job_id = uet_ep->job_id;
	pdc_key.tc = UET_DEFAULT_TC;
	/* TODO: IPv6 support */
	memcpy(&pdc_key.src_ip, &uet_ep->ipv4_addr, sizeof(uet_ep->ipv4_addr));
	memcpy(&pdc_key.dst_ip, &av_entry->addr->fa, sizeof(struct uet_fa));

	HASH_FIND(pdc_ini_hh, pds_state.pdc_ini_ht, &pdc_key,
		  sizeof(pdc_key), pdc);
	if (pdc) {
		/* if the PDC is in error state, don't use it */
		if (pdc->state == PDC_STATE_ERROR) {
			UET_PDS_DBG("initiator lookup found an errored PDC %u",
				    pdc->pdc_id);
			return NULL;
		}

		/* if the PDC is closing, don't use it for new messages */
		if (pdc->close_requested) {
			UET_PDS_DBG("initiator lookup found a closing PDC %u",
				    pdc->pdc_id);
			return NULL;
		}

		return pdc;
	}

	/* allocate a new PDC from the head of the free list */
	pdc = uet_pdsm_alloc_pdc();
	if (!pdc) {
		UET_PDS_ERR("no free PDCs available for initiator");
		return NULL;
	}

	/* initialze this initiator PDC and stick it in the hashtable */
	uet_init_pdc(pdc, PDC_STATE_SYN, true);

	memcpy(pdc->src_mac_addr, uet_ep->uet_domain->uet->nic.mac_addr,
	       ETH_ALEN);
	memcpy(pdc->dst_mac_addr, av_entry->nh_mac_addr,
	       ETH_ALEN);

	/* TODO: IPv6 support */
	memcpy(&pdc->src_addr, &uet_ep->ipv4_addr,
	       sizeof(pdc->src_addr.v4));
	memcpy(&pdc->dst_addr, &av_entry->addr->fa.v4,
	       sizeof(pdc->dst_addr.v4));

	pdc->next_psn       = UET_DEFAULT_START_PSN;
	pdc->tx_bm_base_psn = UET_DEFAULT_START_PSN;
	pdc->rx_bm_base_psn = UET_DEFAULT_START_PSN;
	memcpy(&pdc->ini_hkey, &pdc_key, sizeof(pdc_key));
	HASH_ADD(pdc_ini_hh, pds_state.pdc_ini_ht, ini_hkey,
		 sizeof(pdc_key), pdc);

	uet_pdsm_get_sdi(pdc);

	UET_PDS_DBG("allocated initiator PDC %u (state=SYN)", pdc->pdc_id);

	return pdc;
}

static struct uet_pdc *uet_pdsm_assign_tgt_pdc(struct uet_parsed_pkt *pp)
{
	struct uet_ses_req_cmn *ses_cmn = (struct uet_ses_req_cmn *)pp->ses;
	struct ethhdr *eth = (struct ethhdr *)pp->eth;
	struct iphdr *ipv4 = (struct iphdr *)pp->ip; /* TODO: IPv6 support */
	struct uet_pdc_tgt_key pdc_key;
	struct uet_pdc *pdc;

	if ((pp->pds_type != UET_PDS_TYPE_RUD_REQ) &&
	    (pp->pds_type != UET_PDS_TYPE_ROD_REQ))
		return NULL;

	if ((pp->next_hdr != UET_HDR_REQ_SMALL) &&
	    (pp->next_hdr != UET_HDR_REQ_MEDIUM) &&
	    (pp->next_hdr != UET_HDR_REQ_STD))
		return NULL;

	if (!(pp->pds_flags & UET_PDS_REQ_FLAGS_SYN))
		return NULL;

	memset(&pdc_key, 0, sizeof(pdc_key));
	/* TODO: IPv6 support */
	pdc_key.src_ip.v4 = ntohl(ipv4->saddr);
	pdc_key.dst_ip.v4 = ntohl(ipv4->daddr);
	pdc_key.spdcid = pp->pds_spdcid; /* target side needs spdcid */

	HASH_FIND(pdc_tgt_hh, pds_state.pdc_tgt_ht, &pdc_key,
		  sizeof(pdc_key), pdc);
	if (pdc) {
		UET_PDS_DBG("lookup found target PDC %u", pdc->pdc_id);

		/* can't receive a SYN on an initiator PDC */
		if (pdc->is_initiator) {
			UET_PDS_ERR("PDC %u is initiator and received SYN",
				     pdc->pdc_id);
			return NULL;
		}

		UET_PDS_DBG("SYN request for PDC %u (PSN %u offset %u)",
			    pdc->pdc_id, pp->pds_psn, pp->pds_syn_off);

		return pdc;
	}

	UET_PDS_DBG("first SYN request from PDC %u (PSN %u offset %u)",
		    pp->pds_spdcid, pp->pds_psn, pp->pds_syn_off);

	/* allocate a new PDC from the head of the free list */
	pdc = uet_pdsm_alloc_pdc();
	if (!pdc) {
		UET_PDS_ERR("no free PDCs available for target");
		return -ENODEV;
	}

	/* initialze this target PDC and stick it in the hashtable */
	uet_init_pdc(pdc, PDC_STATE_ESTABLISHED, false);

	memcpy(pdc->src_mac_addr, eth->h_dest, ETH_ALEN);
	memcpy(pdc->dst_mac_addr, eth->h_source, ETH_ALEN);

	/* TODO: IPv6 support */
	pdc->src_addr.v4 = ntohl(ipv4->daddr);
	pdc->dst_addr.v4 = ntohl(ipv4->saddr);

	pdc->dpdcid         = pp->pds_spdcid;
	pdc->rx_bm_base_psn = (pp->pds_psn - pp->pds_syn_off);
	pdc->tx_bm_base_psn = pdc->rx_bm_base_psn;
	pdc->next_psn       = pdc->tx_bm_base_psn;
	memcpy(&pdc->tgt_hkey, &pdc_key, sizeof(pdc_key));
	HASH_ADD(pdc_tgt_hh, pds_state.pdc_tgt_ht, tgt_hkey,
		 sizeof(pdc_key), pdc);

	uet_pdsm_get_sdi(pdc);

	UET_PDS_DBG("allocated target PDC %u (state=ESTABLISHED) (dpdcid=%u)",
		    pdc->pdc_id, pdc->dpdcid);

	return pdc;
}

static struct uet_pdc *uet_pdsm_get_pdc(uint16_t pdc_id,
					bool for_fwd)
{
	struct uet_pdc *pdc;

	if (pdc_id >= UET_PDC_MAX) {
		UET_PDS_ERR("invalid PDC %u (range)", pdc_id);
		return NULL;
	}

	pdc = &pds_state.pdc[pdc_id];

	if (pdc->state == PDC_STATE_UNALLOC) {
		UET_PDS_ERR("invalid PDC %u (unalloc)", pdc_id);
		return NULL;
	}

	if (pdc->state == PDC_STATE_ERROR) {
		UET_PDS_ERR("invalid PDC %u (error)", pdc_id);
		return NULL;
	}

	if (for_fwd && pdc->is_initiator) {
		UET_PDS_ERR("invalid forward PDC %u (initiator)", pdc_id);
		return NULL;
	}

	return pdc;
}

static int uet_pdsm_map_msgid_pdc(uint16_t msg_id,
				  struct uet_pdc *pdc)
{
	struct uet_msgid_map *msgid_map;

	PDS_GO();

	/* TODO: pull msgid_map descriptor from a pool (not malloc) */
	msgid_map = calloc(1, sizeof(*msgid_map));
	if (msgid_map == NULL)
		return -ENOMEM;

	msgid_map->msg_id = msg_id;
	msgid_map->pdc    = pdc;

	HASH_ADD(msgid_hh, pds_state.pdc_msgid_ht, msg_id,
		 sizeof(uint16_t), msgid_map);

	return 0;
}

static int uet_pdsm_unmap_msgid_pdc(uint16_t msg_id)
{
	struct uet_msgid_map *msgid_map;

	PDS_GO();

	HASH_FIND(msgid_hh, pds_state.pdc_msgid_ht, &msg_id,
		  sizeof(uint16_t), msgid_map);
	if (msgid_map == NULL) {
		UET_PDS_ERR("msg_id %u not found", msg_id);
		return -ENOKEY;
	}

	HASH_DELETE(msgid_hh, pds_state.pdc_msgid_ht, msgid_map);
	free(msgid_map);

	return 0;
}

static struct uet_pdc *uet_pdsm_get_msgid_pdc(uint16_t msg_id)
{
	struct uet_msgid_map *msgid_map;

	PDS_GO();

	HASH_FIND(msgid_hh, pds_state.pdc_msgid_ht, &msg_id,
		  sizeof(uint16_t), msgid_map);
	if (msgid_map == NULL) {
		UET_PDS_ERR("msg_id %u not found", msg_id);
		return NULL;
	}

	return msgid_map->pdc;
}

#if 0
static struct uet_pdc *uet_pdsm_select_pdc_to_close(void)
{
	PDS_GO();

	/* TODO: not implemented yet */
	return NULL;
}

static int uet_pdsm_check_pkt(struct uet_pdc_pkt *pdc_pkt)
{
	PDS_GO();

	/* TODO: not implemented yet */
	return -ENOSYS;
}

static struct uet_pdc *uet_pdsm_check_pdc(struct uet_pdc_pkt *pdc_pkt)
{
	PDS_GO();

	/* TODO:
	 * - get PDC (from tpdcid)
	 * - verify valid event
	 */

	return NULL;
}

static int uet_pdsm_check_nack_code(struct uet_pdc_pkt *pdc_pkt)
{
	PDS_GO();

	/* TODO: not implemented yet */
	return -ENOSYS;
}
#endif

/****************************************************************************/
/*                            PDC Initiator APIs                            */
/****************************************************************************/

static int uet_pds_send_close_cmd(struct uet_instance *uet,
				  struct uet_pdc *pdc)
{
	struct uet_pdc_pkt *pdc_pkt;
	struct uet_pds_ctrl *ctrl_hdr;
	struct uet_entropy *entropy_hdr;
	uint16_t ctrl_flags;
	int rc;

	/* allocate the packet descriptor */
	pdc_pkt = calloc(1, sizeof(struct uet_pdc_pkt));
	if (pdc_pkt == NULL) {
		UET_PDS_ERR("failed to alloc PDC packet for close command");
		return -ENOMEM;
	}

	/* allocate the packet buffer */
	pdc_pkt->pkt_buf_len = (uet->nic.max_pkt_size *
				((pdc->sec_enabled) ? 2 : 1));
	pdc_pkt->pkt_buf = calloc(1, pdc_pkt->pkt_buf_len);
	if (pdc_pkt->pkt_buf == NULL) {
		UET_PDS_ERR("failed to alloc packet buffer for close command");
		free(pdc_pkt);
		return -ENOMEM;
	}

	/* reserve head space for security header if needed */
	pdc_pkt->pkt = (pdc->sec_enabled)
			? (pdc_pkt->pkt_buf + UET_SEC_MAX_HDR_LEN)
			: pdc_pkt->pkt_buf;

	/* build Ethernet header */
	uet_build_eth_hdr((struct ethhdr *)pdc_pkt->pkt,
			  pdc->dst_mac_addr, pdc->src_mac_addr);

	/* set up pointers to headers */
	entropy_hdr = (struct uet_entropy *)(pdc_pkt->pkt +
					     sizeof(struct ethhdr) +
					     sizeof(struct iphdr));
	ctrl_hdr = (struct uet_pds_ctrl *)(pdc_pkt->pkt +
					   sizeof(struct ethhdr) +
					   sizeof(struct iphdr) +
					   sizeof(struct uet_entropy));

	pdc_pkt->pkt_len = (sizeof(struct ethhdr) +
			    sizeof(struct iphdr) +
			    sizeof(struct uet_entropy) +
			    sizeof(struct uet_pds_ctrl));

	/* fill in the entropy header */
	entropy_hdr->entropy = htons(UET_DEFAULT_ENTROPY);

	/* fill in the control packet header */
	ctrl_flags = ((UET_PDS_TYPE_CTRL << UET_PDS_TYPE_SHIFT) |
		      (UET_PDS_CTRL_TYPE_CLOSE << UET_PDS_CTRL_TYPE_SHIFT) |
		      (UET_PDS_CTRL_FLAGS_AR << UET_PDS_FLAGS_SHIFT));

	ctrl_hdr->prlg.type_ctrl_flags = htons(ctrl_flags);
	ctrl_hdr->rsvd = 0;

	/* assign PSN for close command */
	pdc->close_cmd_psn = pdc->next_psn++;
	pdc_pkt->psn = pdc->close_cmd_psn;
	ctrl_hdr->psn = htonl(pdc_pkt->psn);

	ctrl_hdr->spdcid = htons(pdc->pdc_id);
	ctrl_hdr->dpdcid = htons(pdc->dpdcid);

	/* payload is 0x0 for close command */
	ctrl_hdr->payload = 0;

	/* build the IP header */
	uet_build_ipv4_hdr(uet,
			   (struct iphdr *)(pdc_pkt->pkt +
					    sizeof(struct ethhdr)),
			   htonl(pdc->dst_addr.v4),
			   htonl(pdc->src_addr.v4),
			   (pdc_pkt->pkt_len - uet->nic.l2_hdr_size),
			   uet->pds.ack_ip_tos,
			   !pdc->sec_enabled);

	/* save packet params */
	pdc_pkt->msg_id = 0; /* control packets have no msg_id */
	pdc_pkt->tx_retry_cnt = 0;
	pdc_pkt->tx_pkt_handle = NULL; /* no SES handle for control packets */
	pdc_pkt->tx_pkt_acked = false;
	pdc_pkt->flags = 0;

	/* send the packet */
	rc = uet_pds_sec_tx_pkt(uet, pdc, pdc_pkt, true, false);
	if (rc != 0) {
		UET_PDS_ERR("failed to send close command for PDC %u",
			    pdc->pdc_id);
		free(pdc_pkt->pkt_buf);
		free(pdc_pkt);
		return rc;
	}

	/* the packet was sent successfully */
	uet_pds_pkt_dbg(uet, &pdc_pkt->pkt_pp, true, "TX CLOSE COMMAND");

	/* set this packet in the tx_bm for tracking ACK */
	UET_PDS_DBG("PDC %u tx_bm: base=%u psn=%u SET bit=%u (close cmd)",
		    pdc->pdc_id, pdc->tx_bm_base_psn, pdc_pkt->psn,
		    (pdc_pkt->psn - pdc->tx_bm_base_psn));

	bm_set(pdc->tx_bm, (pdc_pkt->psn - pdc->tx_bm_base_psn), pdc_pkt);

	/* insert the packet to the end of the timeout queue for retries */
	dlist_insert_tail(&pdc_pkt->node, &pdc->tx_pkt_list_head);

	UET_PDS_DBG("PDC %u close command sent (psn=%u)",
		    pdc->pdc_id, pdc_pkt->psn);

	return 0;
}

static int uet_pds_initiate_pdc_close(struct uet_instance *uet,
				      struct uet_pdc *pdc)
{
	int rc;

	/* bail if the close command has already been sent */
	if (pdc->close_requested && pdc->close_started)
		return 0;

	UET_PDS_DBG("PDC %u sending close command", pdc->pdc_id);

	if (!pdc->is_initiator) {
		UET_PDS_ERR("PDC %u is not an initiator, cannot close",
			    pdc->pdc_id);
		return -EINVAL;
	}

	if (pdc->state != PDC_STATE_ESTABLISHED) {
		UET_PDS_DBG("PDC %u not established (state %d), skip close",
			    pdc->pdc_id, pdc->state);
		return -EINVAL;
	}

	/* set close_requested if not already set */
	pdc->close_requested = true;

	/* check if the active message has drained */
	if (pdc->active_msg_id_valid) {
		UET_PDS_DBG("PDC %u still has an active message (msg_id %u)",
			    pdc->pdc_id, pdc->active_msg_id);
		return -EAGAIN;
	}

	/*
	 * Check if all outstanding packets have been ACK'ed. The initiator
	 * MUST wait for all PDS ACKs to arrive before sending a close
	 * command on a PDC.
	 */
	if (!dlist_empty(&pdc->tx_pkt_list_head)) {
		UET_PDS_DBG("PDC %u has un-ACK'ed packets (cannot close)",
			    pdc->pdc_id);
		return -EAGAIN;
	}

	/* all messages and packets have drained, send the close command */
	rc = uet_pds_send_close_cmd(uet, pdc);
	if (rc != 0) {
		UET_PDS_ERR("PDC %u failed to send close command",
			    pdc->pdc_id);
		return rc;
	}

	/* close command packet has been sent */
	pdc->close_started = true;

	/* transition to the CLOSING state */
	pdc->state = PDC_STATE_CLOSING;

	UET_PDS_DBG("PDC %u transitioned to the CLOSING state", pdc->pdc_id);

	return 0;
}

/****************************************************************************/
/*                             PDC Target APIs                              */
/****************************************************************************/

/****************************************************************************/
/*                             SES->PDS APIs                                */
/****************************************************************************/

int uet_pds_initialize(struct uet_instance *uet)
{
	struct uet_pdc *pdc;
	int i;

	/* seed random number generator for PDC close and packet drop */
	srand(time(NULL));

	/* configure random PDC close threshold */
	if (getenv("UET_PDC_CLOSE_THRESH")) {
		pds_pdc_close_thresh =
			strtoul(getenv("UET_PDC_CLOSE_THRESH"), NULL, 10);
	}

	/* configure random packet drop threshold */
	if (getenv("UET_PKT_DROP_THRESH")) {
		pds_pkt_drop_thresh =
			strtoul(getenv("UET_PKT_DROP_THRESH"), NULL, 10);
	}

	uet->pds.tx_timeout     = UET_DEFAULT_TX_TIMEOUT;
	uet->pds.max_tx_retries = UET_DEFAULT_MAX_TX_RETRIES;
	uet->pds.msl            = UET_DEFAULT_MSL;
	uet->pds.ack_ip_tos     = uet_dscp_to_tos(UET_IP_DEFAULT_ACK_DSCP);

	memset(&pds_state, 0, sizeof(struct uet_pds_state));

	/* initialize the PDCs */

	dlist_init(&pds_state.pdc_alloc_head);
	dlist_init(&pds_state.pdc_free_head);
	pds_state.pdc_ini_ht = NULL;
	pds_state.pdc_tgt_ht = NULL;
	pds_state.pdc_msgid_ht = NULL;

	for (i = 0; i < UET_PDC_MAX; i++) {
		pdc = &pds_state.pdc[i];
		pdc->state = PDC_STATE_UNALLOC;
		pdc->pdc_id = i;

		pdc->tx_bm = bm_create(UET_DEFAULT_MPR);
		if (!pdc->tx_bm) {
			UET_PDS_ERR("failed to create Tx bitmap");
			uet_pdsm_free_pdc(pdc);
			return -ENOMEM; /* FIXME unwind and free PDCs */
		}

		pdc->rx_bm = bm_create(UET_DEFAULT_MPR);
		if (!pdc->rx_bm) {
			UET_PDS_ERR("failed to create Rx bitmap");
			bm_destroy(pdc->tx_bm);
			return -ENOMEM; /* FIXME unwind and free PDCs */
		}

		dlist_insert_tail(&pdc->node, &pds_state.pdc_free_head);
	}

	/* good to go... */
	pds_state.ready = true;

	return 0;
}

void uet_pds_finalize(struct uet_instance *uet)
{
	struct uet_pdc *pdc;
	struct uet_pdc_pkt *pdc_pkt;

	PDS_GO();

	/* TODO: reclaim/free all packets stored in the bitmaps... */

	/* destory all allocated PDCs */
	while (!dlist_empty(&pds_state.pdc_alloc_head)) {
		dlist_pop_front(&pds_state.pdc_alloc_head,
				struct uet_pdc, pdc, node);

		if (pdc->is_initiator)
			HASH_DELETE(pdc_ini_hh, pds_state.pdc_ini_ht, pdc);
		else
			HASH_DELETE(pdc_tgt_hh, pds_state.pdc_tgt_ht, pdc);

		if (pdc->tx_bm)
			bm_destroy(pdc->tx_bm);

		if (pdc->rx_bm)
			bm_destroy(pdc->rx_bm);
	}

	/* destroy all free PDCs */
	while (!dlist_empty(&pds_state.pdc_free_head)) {
		dlist_pop_front(&pds_state.pdc_free_head,
				struct uet_pdc, pdc, node);

		if (pdc->tx_bm)
			bm_destroy(pdc->tx_bm);

		if (pdc->rx_bm)
			bm_destroy(pdc->rx_bm);
	}

	/* wipe out all existing state */
	memset(&pds_state, 0, sizeof(struct uet_pds_state));
	pds_state.ready = false;
}

int uet_pds_ep_initialize(struct uet_ep *uet_ep)
{
	PDS_GO();

	/* TODO: Anything needed here? */
	uet_ep->pds = &pds_state;

	return 0;
}

void uet_pds_ep_finalize(struct uet_ep *uet_ep)
{
	PDS_GO();

	/* TODO: Anything needed here? */
	uet_ep->pds = NULL;
}

int uet_pds_tx_pkt(uet_pkt_handle_t tx_pkt_handle,
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
	struct uet_instance *uet;
	struct uet_av_entry *av_entry;
	struct uet_pdc_pkt *pdc_pkt;
	uet_pds_pkt_type_t pds_pkt_type;
	struct uet_pdc *pdc;
	struct uet_entropy *entropy_hdr;
	struct uet_pds_req *pds_hdr;
	void *ses_hdr, *payload;
	uint16_t pds_flags;
	int rc, hdr_len;

	PDS_GO();

	uet = uet_ep->uet_domain->uet;
	av_entry = (struct uet_av_entry *)dst_addr_handle;

	switch (mode) {
	case UET_PDS_MODE_RUD:
		pds_pkt_type = UET_PDS_TYPE_RUD_REQ;
		break;
	case UET_PDS_MODE_ROD:
		pds_pkt_type = UET_PDS_TYPE_ROD_REQ;
		break;
	case UET_PDS_MODE_RUDI:
		pds_pkt_type = UET_PDS_TYPE_RUDI_REQ;
		break;
	case UET_PDS_MODE_UUD:
		pds_pkt_type = UET_PDS_TYPE_UUD_REQ;
		break;
	default:
		UET_PDS_ERR("unsupported pkt delivery mode %d", mode);
		return -EINVAL;
	}

	if ((next_hdr != UET_HDR_REQ_STD) &&
	    (next_hdr != UET_HDR_RSP_DATA)) {
		UET_PDS_ERR("unsupported next header type %d", next_hdr);
		return -EINVAL;
	}

	/*
	 * If pds_info is specified, take the PDC from its pdcid, else
	 * perform a hash lookup to find the PDC. For a SOM the lookup is
	 * based on the uet_pdc_ini_key. For a middle or EOM the lookup is
	 * based on the msg_id. In either case, if a PDC is not found then
	 * -EAGAIN is returned to indicate the caller should retry. In
	 * this reference implementation, the SES does the right thing by
	 * calling the Tx routine again later. This prevents the PDS manager
	 * from having to maintain a pending packet list that is pulled
	 * from when PDCs become available.
	 */

	if (pds_info) {
		UET_PDS_DBG("SES Tx %p msg_id %u (pds_info pdcid %u psn %u)",
			    tx_pkt_handle, msg_id, pds_info->pdcid,
			    pds_info->opsn);
		pdc = uet_pdsm_get_pdc(pds_info->pdcid, true);
		if (pdc == NULL)
			return -ENODEV;
	} else if (flags & UET_PDS_FLAG_SOM) {
		UET_PDS_DBG("SES Tx %p msg_id %u [SOM]%s",
			    tx_pkt_handle, msg_id,
			    ((flags & UET_PDS_FLAG_EOM) ? " [EOM]" : ""));
		pdc = uet_pdsm_assign_ini_pdc(uet_ep, av_entry, mode);
		if (pdc) {
			/* verify PDC has no active message */
			if (pdc->active_msg_id_valid) {
				UET_PDS_DBG("PDC %u already has "
					    "active_msg_id %u, cannot start "
					    "msg_id %u (EAGAIN)",
					    pdc->pdc_id, pdc->active_msg_id,
					    msg_id);
				return -EAGAIN;
			}

			rc = uet_pdsm_map_msgid_pdc(msg_id, pdc);
			if (rc != 0)
				return rc;

			/* set the active message for this PDC */
			pdc->active_msg_id = msg_id;
			pdc->active_msg_id_valid = true;
		} else {
			UET_PDS_DBG("failed to get PDC for SOM %p "
				    "msg_id %u (EAGAIN)",
				    tx_pkt_handle, msg_id);
			return -EAGAIN;
		}
	} else {
		UET_PDS_DBG("SES Tx %p msg_id %u%s",
			    tx_pkt_handle, msg_id,
			    ((flags & UET_PDS_FLAG_EOM) ? " [EOM]" : ""));

		pdc = uet_pdsm_get_msgid_pdc(msg_id);
		if (!pdc) {
			UET_PDS_DBG("failed to get PDC for non-SOM %p "
				    "msg_id %u (EAGAIN)",
				    tx_pkt_handle, msg_id);
			return -EAGAIN;
		}
	}

	/* TODO: IPv6 support */
	if (memcmp(&pdc->dst_addr.v4, &av_entry->addr->fa.v4,
		   sizeof(pdc->dst_addr.v4)) != 0) {
		UET_PDS_ERR("PDC %u dst_addr does not match AV for Tx pkt %p",
			    pdc->pdc_id, tx_pkt_handle);
		return -EINVAL;
	}

	/* for non-SOM packets, verify msg_id matches the active message */
	if (!(flags & UET_PDS_FLAG_SOM)) {
		if (!pdc->active_msg_id_valid) {
			UET_PDS_ERR("PDC %u has no active message, cannot send "
				    "non-SOM packet for msg_id %u",
				    pdc->pdc_id, msg_id);
			return -EINVAL;
		}

		if (pdc->active_msg_id != msg_id) {
			UET_PDS_ERR("PDC %u active_msg_id %u does not match "
				    "msg_id %u",
				    pdc->pdc_id, pdc->active_msg_id, msg_id);
			return -EINVAL;
		}
	}

	if (!pds_info && (flags & UET_PDS_FLAG_EOM)) {
		if (flags & UET_PDS_FLAG_MAINTAIN_PDC) {
			UET_PDS_DBG("PDC %u flagged with MAINTAIN_PDC on EOM",
				    pdc->pdc_id);
		} else {
			/* clear the active message on this PDC */
			pdc->active_msg_id = 0;
			pdc->active_msg_id_valid = false;

			rc = uet_pdsm_unmap_msgid_pdc(msg_id);
			if (rc != 0)
				return rc;

			/* randomly mark the PDC for close */
			if (pds_pdc_close_thresh &&
			    pdc->is_initiator && !pdc->close_requested &&
			    uet_pds_random_check(pds_pdc_close_thresh)) {
				UET_PDS_WARN("PDC %u random marked for close!",
					     pdc->pdc_id);
				pdc->close_requested = true;
			}
		}
	}

	/* allocate descriptor and buffer to build packet */

	/* TODO:
	 * - pull packet descriptor and buffer from a pool (not malloc)
	 * - add support for gather iov send
	 */

	pdc_pkt = calloc(1, sizeof(struct uet_pdc_pkt));
	if (pdc_pkt == NULL) {
		UET_PDS_ERR("failed to alloc PDC packet");
		return -ENOMEM;
	}

	pdc_pkt->pkt_buf_len = (uet->nic.max_pkt_size *
				((pdc->sec_enabled) ? 2 : 1));
	pdc_pkt->pkt_buf = calloc(1, pdc_pkt->pkt_buf_len);
	if (pdc_pkt->pkt_buf == NULL) {
		UET_PDS_ERR("failed to alloc packet buffer");
		free(pdc_pkt);
		return -ENOMEM;
	}

	/* reserve head space for security header if needed */
	pdc_pkt->pkt = (pdc->sec_enabled)
			? (pdc_pkt->pkt_buf + UET_SEC_MAX_HDR_LEN)
			: pdc_pkt->pkt_buf;

	uet_build_eth_hdr((struct ethhdr *)pdc_pkt->pkt,
			  pdc->dst_mac_addr, pdc->src_mac_addr);

	/* TODO: IPv6 support and UDP support */
	entropy_hdr = (struct uet_entropy *)(pdc_pkt->pkt +
					     sizeof(struct ethhdr) +
					     sizeof(struct iphdr));
	pds_hdr = (struct uet_pds_req *)(pdc_pkt->pkt +
					 sizeof(struct ethhdr) +
					 sizeof(struct iphdr) +
					 sizeof(struct uet_entropy));
	ses_hdr = (pds_hdr + 1);
	payload = ((uint8_t *)ses_hdr + ses_len);

	/* TODO: IPv6 support and UDP support */
	hdr_len = (sizeof(struct ethhdr) +
		   sizeof(struct iphdr) +
		   sizeof(struct uet_entropy) +
		   sizeof(struct uet_pds_req) +
		   ses_len);

	pdc_pkt->pkt_len = (hdr_len + pkt_len);

	/* fill in the entropy header */
	/* TODO: UDP support */
	entropy_hdr->entropy = htons(UET_DEFAULT_ENTROPY);

	/* fill in the PDS header */

	pds_flags = ((pds_pkt_type << UET_PDS_TYPE_SHIFT)          |
		     (UET_PDS_REQ_FLAGS_AR << UET_PDS_FLAGS_SHIFT) |
		     (next_hdr << UET_PDS_NEXT_HDR_SHIFT));
	if (pdc->state == PDC_STATE_SYN) {
		pds_flags |= (UET_PDS_REQ_FLAGS_SYN <<
			      UET_PDS_FLAGS_SHIFT);
	}

	pds_hdr->prlg.type_next_flags = htons(pds_flags);

	pdc_pkt->psn = pdc->next_psn++;
	pds_hdr->psn = htonl(pdc_pkt->psn);

	/*
	 * Set the clear_psn to the left edge (-1) of the tx_bm which moves
	 * forward as ACKs are received. Note that this is considered a
	 * cumulative clear value.
	 */
	pds_hdr->clear_psn_offset =
		htons(psn_2c_offset(pdc_pkt->psn,
				    (pdc->tx_bm_base_psn - 1)));

	pds_hdr->spdcid = htons(pdc->pdc_id);

	if (pdc->state == PDC_STATE_SYN) {
		pds_hdr->pdc_info_psn_offset =
			htons((pdc->syn_offset &
			       UET_PDS_REQ_PSN_OFFSET_MASK) <<
			      UET_PDS_REQ_PSN_OFFSET_SHIFT);
		pdc->syn_offset++;
	} else {
		pds_hdr->dpdcid = htons(pdc->dpdcid);
	}

	/* copy in the SES header and payload */
	/* TODO: support for gather iov send */

	memcpy(ses_hdr, ses, ses_len);
	memcpy(payload, pkt, pkt_len);

	/* build the IP header */

	/* TODO: IPv6 support and UDP support */
	uet_build_ipv4_hdr(uet,
			   (struct iphdr *)(pdc_pkt->pkt +
					    sizeof(struct ethhdr)),
			   htonl(pdc->dst_addr.v4),
			   htonl(pdc->src_addr.v4),
			   (pdc_pkt->pkt_len - uet->nic.l2_hdr_size),
			   uet_ep->msg_ip_tos,
			   !pdc->sec_enabled);

	/* save some params specific for this packet */
	pdc_pkt->msg_id        = msg_id;
	pdc_pkt->tx_retry_cnt  = 0;
	pdc_pkt->tx_pkt_handle = tx_pkt_handle;
	pdc_pkt->tx_pkt_acked  = false;
	pdc_pkt->flags         = flags;

	/* send the packet */
	rc = uet_pds_sec_tx_pkt(uet, pdc, pdc_pkt, true, false);
	if (rc != 0) {
		free(pdc_pkt->pkt_buf);
		free(pdc_pkt);
		return rc;
	}

	/* the packet was sent successfully */
	uet_pds_pkt_dbg(uet, &pdc_pkt->pkt_pp, true, "TX PACKET");

	/* set this packet in the tx_bm */
	UET_PDS_DBG("PDC %u tx_bm: base=%u psn=%u SET bit=%u",
		    pdc->pdc_id, pdc->tx_bm_base_psn, pdc_pkt->psn,
		    (pdc_pkt->psn - pdc->tx_bm_base_psn));

	bm_set(pdc->tx_bm, (pdc_pkt->psn - pdc->tx_bm_base_psn), pdc_pkt);

	if (UET_LOG_LVL >= UET_LOG_DBG) {
		UET_PDS_DBG("PDC %u tx_bm (base %u):",
			    pdc->pdc_id, pdc->tx_bm_base_psn);
		bm_print_bits(pdc->tx_bm, uet_pdc_tx_bit_char);
	}

	/* insert the packet to the end of the timeout queue */
	dlist_insert_tail(&pdc_pkt->node, &pdc->tx_pkt_list_head);

	/* if close was requested, send it now */
	if ((pdc->state == PDC_STATE_ESTABLISHED) && pdc->is_initiator &&
	    pdc->close_requested && !pdc->close_started) {
		rc = uet_pds_initiate_pdc_close(uet, pdc);
		if ((rc != 0) && (rc != -EAGAIN)) {
			UET_PDS_WARN("PDC %u failed to initiate close (rc=%d)",
				     pdc->pdc_id, rc);
		}
	}

	return 0;
}

static int uet_pds_rtx_pkt(struct uet_instance *uet,
			   struct uet_pdc *pdc,
			   struct uet_pdc_pkt *pdc_pkt)
{
	struct uet_pds_req *pds_hdr;
	uint8_t *new_pkt;
	int new_pkt_len;
	int rc;

	/* set the retransmit flag in the PDS header */
	pds_hdr = (struct uet_pds_req *)pdc_pkt->pkt_pp.pds;
	pds_hdr->prlg.type_next_flags |=
		 htons(UET_PDS_REQ_FLAGS_RETX << UET_PDS_FLAGS_SHIFT);
	pdc_pkt->pkt_pp.pds_flags |= UET_PDS_REQ_FLAGS_RETX;

	/* retransmit the packet */
	rc = uet_pds_sec_tx_pkt(uet, pdc, pdc_pkt, true, true);
	if (rc != 0)
		return rc;

	/* the packet was sent successfully */

	pdc_pkt->tx_retry_cnt++;

	uet_pds_pkt_dbg(uet, &pdc_pkt->pkt_pp, true, "TX PACKET (retransmit)");

	return 0;
}

static int uet_pds_check_rtx_pkt(struct uet_instance *uet,
				 struct uet_pdc *pdc,
				 struct uet_pdc_pkt *pdc_pkt)
{
	time_t now, delta;
	int rc;

	uet_gettime(&now);
	delta = (now - pdc_pkt->tx_time);
	if (delta < uet->pds.tx_timeout)
		return 0; /* no retransmit */

	if (pdc_pkt->tx_retry_cnt >= uet->pds.max_tx_retries) {
		UET_PDS_ERR("PDC %u PSN %u retry exceeded",
			    pdc->pdc_id, pdc_pkt->psn);
		return -EIO; /* assume this PDC is dead */
	}

	UET_PDS_WARN("PDC %u PSN %u retransmit", pdc->pdc_id, pdc_pkt->psn);

	rc = uet_pds_rtx_pkt(uet, pdc, pdc_pkt);
	if (rc != 0) {
		UET_PDS_ERR("PDC %u PSN %u retransmit failed",
			    pdc->pdc_id, pdc_pkt->psn);
		return -EIO; /* assume this PDC is dead */
	}

	return -EAGAIN; /* pkt retransmitted, could be more */
}

int uet_pds_progress_tx(struct uet_ep *uet_ep,
			uet_pkt_handle_t *err_pkt_handle)
{
	struct uet_instance *uet;
	struct uet_pdc *pdc;
	struct dlist_entry *tmp1, *tmp2;
	struct uet_pdc_pkt *pdc_pkt;
	time_t now, delta;
	int rc;

	PDS_GO();

	uet = uet_ep->uet_domain->uet;

	/* TODO:
	 * [x] walk the allocated PDC list
	 *     [x] walk the tx_pkt_list (sorted in tx time order, oldest first)
	 *         [x] if the packet has not timed out
	 *             [x] done with this PDC, continue
	 *         [x] increment the retry count
	 *         [x] if the retry count has exceeeded the max
	 *             [x] set the error handle to the tx_handle
	 *             [x] change PDC state to ERROR
	 *         [x] update the tx time
	 *         [x] move the packet to the end of the tx_pkt_list
	 *         [x] retransmit the pkt
	 */

	dlist_foreach_container_safe(&pds_state.pdc_alloc_head,
				     struct uet_pdc, pdc, node, tmp1) {
		dlist_foreach_container_safe(&pdc->tx_pkt_list_head,
					     struct uet_pdc_pkt, pdc_pkt,
					     node, tmp2) {
			rc = uet_pds_check_rtx_pkt(uet, pdc, pdc_pkt);
			if (rc == 0) {
				break; /* no retransmit, done with this PDC */
			} else if (rc == -EIO) {
				/*
				 * Max retries exceeded - transition PDC to
				 * error state and notify upper layer.
				 */
				UET_PDS_ERR("PDC %u transitioning to ERROR "
					    "state (max retries exceeded)",
					    pdc->pdc_id);
				pdc->state = PDC_STATE_ERROR;

				/* notify upper layer of failed packet */
				if (err_pkt_handle)
					*err_pkt_handle = pdc_pkt->tx_pkt_handle;

				dlist_remove(&pdc_pkt->node);

				/* free the packet buffers and structure */
				if (pdc_pkt->ack_buf)
					free(pdc_pkt->ack_buf);
				if (pdc_pkt->pkt_buf)
					free(pdc_pkt->pkt_buf);
				free(pdc_pkt);

				/*
				 * Return immediately to give SES layer a
				 * chance to handle this error before checking
				 * other PDCs.
				 */
				return -EPROTO;
			} else if (rc == -EAGAIN) {
				/*
				 * This packet was retransmitted, move this
				 * packet to the end of the list and continue.
				 */
				dlist_remove(&pdc_pkt->node);
				dlist_insert_tail(&pdc_pkt->node,
						  &pdc->tx_pkt_list_head);
			}
		}
	}

	return 0;
}

int uet_pds_msg_cmpl_ind(struct uet_ep *uet_ep,
			 uet_addr_handle_t dst_addr_handle,
			 uet_pds_mode_t mode,
			 uint16_t msg_id)
{
	struct uet_pdc *pdc;
	int rc;

	pdc = uet_pdsm_get_msgid_pdc(msg_id);
	if (pdc == NULL)
		return -EINVAL;

	UET_PDS_DBG("PDC %d msg_id %u completion indication from SES",
		    pdc->pdc_id, msg_id);

	/* clear active message for MAINTAIN_PDC messages */
	pdc->active_msg_id = 0;
	pdc->active_msg_id_valid = false;

	rc = uet_pdsm_unmap_msgid_pdc(msg_id);
	if (rc != 0)
		return rc;

	/* if close was requested and not started, send it now */
	if (pdc->close_requested && !pdc->close_started) {
		rc = uet_pds_initiate_pdc_close(uet_ep->uet_domain->uet, pdc);
		if ((rc != 0) && (rc != -EAGAIN)) {
			UET_PDS_ERR("PDC %u failed to initiate close (rc=%d)",
				    pdc->pdc_id, rc);
			return rc;
		}
	}

	return 0;
}

static void uet_pds_build_ack_pkt(struct uet_instance *uet,
				  struct uet_pdc *pdc,
				  struct uet_pdc_pkt *pdc_pkt,
				  uet_pds_next_hdr_t next_hdr,
				  void *ses_hdr,
				  size_t ses_hdr_len)
{
	uint8_t flags;
	struct uet_entropy *entropy_hdr;
	struct uet_pds_ack *ack_pds;
	uint8_t *ack_ses;

	/* TODO: IPv6 support and UDP support */
	entropy_hdr = (struct uet_entropy *)(pdc_pkt->ack +
					     sizeof(struct ethhdr) +
					     sizeof(struct iphdr));
	ack_pds = (struct uet_pds_ack *)(pdc_pkt->ack +
					 sizeof(struct ethhdr) +
					 sizeof(struct iphdr) +
					 sizeof(struct uet_entropy));

	uet_build_eth_hdr((struct ethhdr *)pdc_pkt->ack,
			  ((struct ethhdr *)pdc_pkt->pkt_pp.eth)->h_source,
			  ((struct ethhdr *)pdc_pkt->pkt_pp.eth)->h_dest);

	/* TODO: IPv6 support */
	uet_build_ipv4_hdr(uet,
			   (struct iphdr *)(pdc_pkt->ack +
					    sizeof(struct ethhdr)),
			   ((struct iphdr *)pdc_pkt->pkt_pp.ip)->saddr,
			   ((struct iphdr *)pdc_pkt->pkt_pp.ip)->daddr,
			   (pdc_pkt->ack_len - uet->nic.l2_hdr_size),
			   uet->pds.ack_ip_tos,
			   !pdc->sec_enabled);

	/* TODO: UDP support */
	entropy_hdr->entropy = htons(pdc_pkt->pkt_pp.entropy_val);

	/* TODO: support ACK_CC and ACK_CCX */
	flags = (pdc_pkt->needs_clear) ? UET_PDS_ACK_FLAGS_REQ_CLR_CLS
				       : UET_PDS_ACK_FLAGS_NONE;
	ack_pds->prlg.type_next_flags =
		htons((UET_PDS_TYPE_ACK << UET_PDS_TYPE_SHIFT) |
		      (next_hdr << UET_PDS_NEXT_HDR_SHIFT) |
		      (flags << UET_PDS_FLAGS_SHIFT));

	/* FIXME start tracking a real cumulative ack value */
	ack_pds->ack_psn_offset = 0;
	ack_pds->cack_psn = htonl(pdc_pkt->pkt_pp.pds_psn);

	ack_pds->spdcid = htons(pdc->pdc_id);
	ack_pds->dpdcid = htons(pdc->dpdcid);

	/* only copy SES header if needed */
	if (ses_hdr && ses_hdr_len > 0) {
		ack_ses = (uint8_t *)(ack_pds + 1);
		memcpy(ack_ses, ses_hdr, ses_hdr_len);
	}
}

static int uet_pds_tx_ack_pkt(struct uet_instance *uet,
			      struct uet_pdc *pdc,
			      struct uet_pdc_pkt *pdc_pkt,
			      uet_pds_next_hdr_t next_hdr,
			      size_t ses_hdr_len,
			      void *ses_hdr,
			      bool gtd_del)
{
	uint16_t ack_pkt_len;
	uint16_t ack_data_len;
	int rc;

	/* TODO: IPv6 support and UDP support */

	if (next_hdr == UET_HDR_NONE) {
		pdc_pkt->ack_len = (sizeof(struct ethhdr) +
				    sizeof(struct iphdr) +
				    sizeof(struct uet_entropy) +
				    sizeof(struct uet_pds_ack));
	} else if (next_hdr == UET_HDR_RSP) {
		pdc_pkt->ack_len = (sizeof(struct ethhdr) +
				    sizeof(struct iphdr) +
				    sizeof(struct uet_entropy) +
				    sizeof(struct uet_pds_ack) +
				    sizeof(struct uet_ses_rsp));
	} else { /* response w/ data */
		ack_data_len = (ses_hdr_len - sizeof(struct uet_ses_rsp_d));
		pdc_pkt->ack_len = (sizeof(struct ethhdr) +
				    sizeof(struct iphdr) +
				    sizeof(struct uet_entropy) +
				    sizeof(struct uet_pds_ack) +
				    sizeof(struct uet_ses_rsp_d) +
				    ack_data_len);
	}

	/* allocate buffer for ack packet */
	pdc_pkt->ack_buf_len = ((pdc_pkt->ack_len +
				 (pdc->sec_enabled
				  ? (UET_SEC_MAX_HDR_LEN + UET_SEC_TAG_LEN)
				  : CRC_LEN)) *
				(pdc->sec_enabled ? 2 : 1));
	pdc_pkt->ack_buf = calloc(1, pdc_pkt->ack_buf_len);
	if (pdc_pkt->ack_buf == NULL) {
		UET_PDS_ERR("failed to alloc ACK packet buffer");
		return -ENOMEM;
	}

	/* reserve head space for security header if needed */
	pdc_pkt->ack = (pdc->sec_enabled)
			? (pdc_pkt->ack_buf + UET_SEC_MAX_HDR_LEN)
			: pdc_pkt->ack_buf;

	pdc_pkt->needs_clear = gtd_del;

	/* build the ACK packet */
	uet_pds_build_ack_pkt(uet, pdc, pdc_pkt, next_hdr,
			      ses_hdr, ses_hdr_len);

	/* send the ACK packet */
	rc = uet_pds_sec_tx_pkt(uet, pdc, pdc_pkt, false, false);
	if (rc != 0) {
		pdc_pkt->needs_clear = false;
		pdc_pkt->ack_len = 0;
		free(pdc_pkt->ack_buf);
		return rc;
	}

	uet_pds_pkt_dbg(uet, &pdc_pkt->ack_pp, true, "TX ACK PACKET");

	return 0;
}

static int uet_pds_tx_def_rsp_ack_pkt(struct uet_instance *uet,
				      struct uet_pdc *pdc,
				      struct uet_pdc_pkt *pdc_pkt)
{
	uint8_t *def_rsp_buf;
	int def_rsp_buf_len;
	uint8_t *def_rsp;
	int def_rsp_len;
	struct uet_pdc_pkt tmp_pdc_pkt;
	struct uet_entropy *entropy_hdr;
	struct uet_pds_ack *ack_pds;
	struct uet_pds_def_rsp *ack_ses;
	int rc;

	/* TODO: IPv6 support and UDP support */
	def_rsp_len = (sizeof(struct ethhdr) +
		       sizeof(struct iphdr) +
		       sizeof(struct uet_entropy) +
		       sizeof(struct uet_pds_ack) +
		       sizeof(struct uet_pds_def_rsp));

	/* allocate buffer for ack packet */
	def_rsp_buf_len = ((def_rsp_len +
			    (pdc->sec_enabled
			     ? (UET_SEC_MAX_HDR_LEN + UET_SEC_TAG_LEN)
			     : CRC_LEN)) *
			   (pdc->sec_enabled ? 2 : 1));
	def_rsp_buf = calloc(1, def_rsp_buf_len);
	if (def_rsp_buf == NULL) {
		UET_PDS_ERR("failed to alloc DEF_RSP ACK packet buffer");
		return -ENOMEM;
	}

	/* reserve head space for security header if needed */
	def_rsp = (pdc->sec_enabled)
			? (def_rsp_buf + UET_SEC_MAX_HDR_LEN)
			: def_rsp_buf;

	memset(&tmp_pdc_pkt, 0, sizeof(tmp_pdc_pkt));
	tmp_pdc_pkt.ack_buf     = def_rsp_buf;
	tmp_pdc_pkt.ack_buf_len = def_rsp_buf_len;
	tmp_pdc_pkt.ack         = def_rsp;
	tmp_pdc_pkt.ack_len     = def_rsp_len;
	tmp_pdc_pkt.ack_parsed  = false;

	/* TODO: IPv6 support and UDP support */
	entropy_hdr = (struct uet_entropy *)(def_rsp +
					     sizeof(struct ethhdr) +
					     sizeof(struct iphdr));
	ack_pds = (struct uet_pds_ack *)(def_rsp +
					 sizeof(struct ethhdr) +
					 sizeof(struct iphdr) +
					 sizeof(struct uet_entropy));
	ack_ses = (struct uet_pds_def_rsp *)(ack_pds + 1);

	/* TODO: UDP support */
	entropy_hdr->entropy = htons(pdc_pkt->pkt_pp.entropy_val);

	uet_build_eth_hdr((struct ethhdr *)def_rsp,
			  ((struct ethhdr *)pdc_pkt->pkt_pp.eth)->h_source,
			  ((struct ethhdr *)pdc_pkt->pkt_pp.eth)->h_dest);

	/* TODO: IPv6 support */
	uet_build_ipv4_hdr(uet,
			   (struct iphdr *)(def_rsp +
					    sizeof(struct ethhdr)),
			   ((struct iphdr *)pdc_pkt->pkt_pp.ip)->saddr,
			   ((struct iphdr *)pdc_pkt->pkt_pp.ip)->daddr,
			   (def_rsp_len - uet->nic.l2_hdr_size),
			   uet->pds.ack_ip_tos,
			   !pdc->sec_enabled);

	/* TODO: add SACK header, UET_PDS_ACK_FLAGS_AX */
	ack_pds->prlg.type_next_flags =
		htons((UET_PDS_TYPE_ACK << UET_PDS_TYPE_SHIFT) |
		      (UET_HDR_RSP << UET_PDS_NEXT_HDR_SHIFT) |
		      (UET_PDS_ACK_FLAGS_NONE << UET_PDS_FLAGS_SHIFT));

	/* FIXME start tracking a real cumulative ack value */
	ack_pds->ack_psn_offset = 0;
	ack_pds->cack_psn = htonl(pdc_pkt->pkt_pp.pds_psn);

	ack_pds->spdcid = htons(pdc->pdc_id);
	ack_pds->dpdcid = htons(pdc->dpdcid);

	ack_ses->list_opcode =
		(UET_DEFAULT_RESPONSE << UET_PDS_SES_DEF_RSP_OPCODE_SHIFT);
	ack_ses->ver_return_code =
		(UET_RC_NULL << UET_PDS_SES_DEF_RSP_RETCODE_SHIFT);
	ack_ses->msg_id = htons(pdc_pkt->pkt_pp.ses_msg_id);

	/* send the default response ACK packet */
	rc = uet_pds_sec_tx_pkt(uet, pdc, &tmp_pdc_pkt, false, false);
	if (rc != 0) {
		free(def_rsp_buf);
		return rc;
	}

	uet_pds_pkt_dbg(uet, &tmp_pdc_pkt.ack_pp, true,
			"TX DEF_RSP ACK PACKET (duplicate)");

	free(def_rsp_buf);
	return 0;
}

static int uet_pds_check_duplicate_and_rtx(struct uet_instance *uet,
					   struct uet_pdc *pdc,
					   struct uet_pdc_pkt *pdc_pkt,
					   bool *rtx)
{
	struct uet_pdc_pkt *orig_pkt = NULL;
	int rc;

	*rtx = false;

	/* if the PSN is outside the current +/- MPR then drop it */

	if (PSN_IN_PRIOR_MPR(pdc_pkt->pkt_pp.pds_psn,
			     pdc->rx_bm_base_psn)) {
		orig_pkt = NULL; /* indicate a default response */
	} else if (PSN_IN_MPR(pdc_pkt->pkt_pp.pds_psn,
			      pdc->rx_bm_base_psn)) {
		/* check if this packet is a duplicate */
		if (!bm_get(pdc->rx_bm,
			    (pdc_pkt->pkt_pp.pds_psn - pdc->rx_bm_base_psn),
			    (void **)&orig_pkt)) {
			return 0; /* new PSN */
		}
	} else {
		UET_PDS_WARN("invalid PSN %u on PDC %u (outside MPR %u[+/-%u])",
			     pdc_pkt->pkt_pp.pds_psn, pdc->pdc_id,
			     pdc->rx_bm_base_psn, UET_DEFAULT_MPR);
		return -EINVAL;
	}

	UET_PDS_WARN("duplicate %sPSN %u on PDC %u (ACK retransmit)",
		     (pdc_pkt->pkt_pp.pds_flags &
		      UET_PDS_REQ_FLAGS_SYN) ? "SYN " : "",
		     pdc_pkt->pkt_pp.pds_psn, pdc->pdc_id);

	if (orig_pkt == NULL) {
		/* send a default response */
		rc = uet_pds_tx_def_rsp_ack_pkt(uet, pdc, pdc_pkt);
		if (rc != 0)
			return rc;

		*rtx = true;
	} else if (orig_pkt->ack) {
		/* resend previous ACK/response */
		rc = uet_pds_sec_tx_pkt(uet, pdc, orig_pkt, false, true);
		if (rc != 0)
			return rc;

		uet_pds_pkt_dbg(uet, &orig_pkt->ack_pp, true,
				"TX ACK PACKET (duplicate)");

		*rtx = true;
	} else {
		UET_PDS_ERR("no ACK to retransmit PSN %u on PDC %u",
			    pdc_pkt->pkt_pp.pds_psn, pdc->pdc_id);
		return -EINVAL;
	}

	return 0;
}

static int uet_pds_upcall_ses_rx_req(struct uet_instance *uet,
				     struct uet_pdc *pdc,
				     struct uet_pdc_pkt *pdc_pkt)
{
	struct uet_pds_info pds_info;
	uet_pds_next_hdr_t rsp_next_hdr;
	void *rsp_ses_hdr;
	size_t rsp_ses_hdr_len;
	bool ses_nack, gtd_del;
	int rc;

	/* upcall for ses processing */
	memset(&pds_info, 0, sizeof(struct uet_pds_info));
	pds_info.opsn  = pdc_pkt->pkt_pp.pds_psn;
	pds_info.pdcid = pdc->pdc_id;

	/* allocate a buffer for the SES reponse data */
	rsp_ses_hdr = calloc(1, (sizeof(struct uet_ses_rsp_d) +
				 uet->pds.max_ack_data));
	if (rsp_ses_hdr == NULL) {
		UET_PDS_ERR("failed to alloc SES response buffer");
		return -ENOMEM;
	}

	rc = uet->pds.upcall.rx_req((uet_pkt_handle_t)pdc_pkt, uet,
				    &pdc_pkt->pkt_pp, &pds_info,
				    &rsp_next_hdr, rsp_ses_hdr,
				    &rsp_ses_hdr_len, &ses_nack,
				    &gtd_del);
	if (rc == 0) {
		/* TODO: add support for sending a PDS NACK
		 * For now, if this is a bad request, not sending a
		 * NACK will cause a retransmit of the request packet
		 * by the initiator.
		 */
		if (ses_nack) {
			UET_PDS_ERR("PDC %u PSN %u SES NACK",
				    pdc->pdc_id, pdc_pkt->pkt_pp.pds_psn);
			rc = -EINVAL;
		} else {
			/* transmit ACK */
			rc = uet_pds_tx_ack_pkt(uet, pdc, pdc_pkt,
						rsp_next_hdr, rsp_ses_hdr_len,
						rsp_ses_hdr, gtd_del);
		}
	} else {
		UET_PDS_ERR("PDC %u PSN %u SES upcall failed (rx_req=%d)",
			    pdc_pkt->pkt_pp.pds_dpdcid,
			    pdc_pkt->pkt_pp.pds_psn, rc);
	}

	free(rsp_ses_hdr);
	return rc;
}

static int uet_pds_shift_rx_window(struct uet_instance *uet,
				   struct uet_pdc *pdc,
				   bool is_rod)
{
	struct uet_pdc_pkt *pdc_pkt;
	bool shifted = false;
	int rc;
	int max_rx_psn_offset;
	int clear_to_base_diff;

	while (true) {
		/*
		 * Previous Behavior and Bug Description:
		 * - When handling unexpected messages, if the Receiver has not
		 *   yet posted a buffer, the SES sets the `gtd_del` flag to 1.
		 * - In such cases, the Client-side RX bitmap's `base_psn` does
		 *   not update and remains set to its default value. This leads
		 *   to test failures and inconsistency in packet handling.
		 *
		 * Fix Description:
		 * - To resolve this, we now check if a `clear_psn` value exists
		 *   that is greater than the RX bitmap's current `base_psn`.
		 * - If such a `clear_psn` is found, the `base_psn` is updated
		 *   to match the `clear_psn`, ensuring proper synchronization
		 *   and preventing test failures.
		 *
		 * Note for Review:
		 * - Refer to the Packet Delivery Sublayer documentation,
		 *   Section 1.1.9.4.2, for additional context.
		 */

		/*
		 * Extracting the last settled PDC packet PSN from the RX bitmap
		 */
		max_rx_psn_offset = bm_max(pdc->rx_bm);
		if (!bm_get(pdc->rx_bm, max_rx_psn_offset, (void **)&pdc_pkt))
			break;

		clear_to_base_diff =
			pdc_pkt->pkt_pp.pds_clear_psn - pdc->rx_bm_base_psn;

		if ((clear_to_base_diff > UET_DEFAULT_MPR) ||
		    (clear_to_base_diff < -UET_DEFAULT_MPR)) {
			UET_PDS_WARN("invalid CLEAR PSN %u on PDC %u "
				     "(outside MPR %u[+-%u])",
				     pdc_pkt->pkt_pp.pds_clear_psn,
				     pdc_pkt->pkt_pp.pds_dpdcid,
				     pdc->rx_bm_base_psn, UET_DEFAULT_MPR);
			return -EINVAL;
		}

		if (clear_to_base_diff > 0) {
			bm_shift_right(pdc->rx_bm, clear_to_base_diff);
			pdc->rx_bm_base_psn += clear_to_base_diff;
		}

		if (!bm_get(pdc->rx_bm, 0, (void **)&pdc_pkt))
			break;

		if (is_rod && !pdc_pkt->reordered) { /* reorder using rx_bm */
			rc = uet_pds_upcall_ses_rx_req(uet, pdc, pdc_pkt);
			if (rc != 0)
				return rc;

			pdc_pkt->reordered = true;
		}

		/* packet requires a clear that hasn't been received yet */
		if (pdc_pkt->needs_clear)
			break;

		shifted = true;
		bm_shift_right(pdc->rx_bm, 1);
		pdc->rx_bm_base_psn++;

		if (pdc_pkt->ack_buf)
			free(pdc_pkt->ack_buf);
		if (pdc_pkt->pkt_buf)
			free(pdc_pkt->pkt_buf);
		free(pdc_pkt);
	}

#if 0
	if (shifted) {
		UET_PDS_DBG("PDC %d rx_bm (base %u):",
			    pdc->pdc_id, pdc->rx_bm_base_psn);
		bm_print_bits(pdc->rx_bm, uet_pdc_rx_bit_char);
	}
#endif
	(void)shifted;

	return 0;
}

static int uet_pds_shift_tx_window(struct uet_instance *uet,
				   struct uet_pdc *pdc)
{
	struct uet_pdc_pkt *pdc_pkt;
	bool shifted = false;
	int rc;

	while (true) {
		if (!bm_get(pdc->tx_bm, 0, (void **)&pdc_pkt))
			break;

		if (!pdc_pkt->tx_pkt_acked)
			break;

		/*
		 * This transmitted packet has been ACK'ed. Note that when
		 * the ACK was processed, the packet was removed from the
		 * PDC's tx list that is managed for retransmissions.
		 */

		shifted = true;
		bm_shift_right(pdc->tx_bm, 1);
		pdc->tx_bm_base_psn++;

		if (pdc_pkt->ack_buf)
			free(pdc_pkt->ack_buf);
		if (pdc_pkt->pkt_buf)
			free(pdc_pkt->pkt_buf);
		free(pdc_pkt);
	}

#if 0
	if (shifted) {
		UET_PDS_DBG("PDC %d tx_bm (base %u):",
			    pdc->pdc_id, pdc->tx_bm_base_psn);
		bm_print_bits(pdc->tx_bm, uet_pdc_tx_bit_char);
	}
#endif
	(void)shifted;

	return 0;
}

static int uet_pds_process_ack(struct uet_instance *uet,
			       struct uet_parsed_pkt *pp)
{
	struct uet_pdc *pdc;
	struct uet_pdc_pkt *pdc_pkt;
	int rc;

	/* TODO:
	 * [x] fetch the PDC (from dpdcid)
	 * [x] verify PDC is in an active state (not UNALLOC)
	 *     [x] if not then drop the ACK
	 * [x] verify the spdcid PDC is the correct peer
	 *     [x] if not then drop the Request
	 * [x] verify the PSN is within the MPR
	 *     [x] if not then drop the ACK
	 * [x] fetch the PSN/packet from the tx_bm
	 *     [x] if not found/set then drop the ACK
	 * [x] verify the PSN/packet has not been ACK'ed
	 *     [x] if already ACK'ed then drop the ACK
	 * [x] mark the PSN/packet as ACK'ed
	 * [x] call SES upcall/rx_rsp
	 * [x] if in the SYN state then move to establed (save spdcid)
	 * [x] move the tx_bm PSN window for all contiguous ACK'ed PSN
	 */

	pdc = uet_pdsm_get_pdc(pp->pds_dpdcid, false);
	if (pdc == NULL)
		return -ENODEV;

	if ((pdc->state != PDC_STATE_SYN) &&
	    (pdc->dpdcid != pp->pds_spdcid)) {
		UET_PDS_WARN("invalid PDC %u (dpdcid %u != spdcid %u)",
			     pdc->pdc_id, pdc->dpdcid, pp->pds_spdcid);
		return -EINVAL;
	}

	if (!PSN_IN_MPR(pp->pds_psn, pdc->tx_bm_base_psn)) {
		UET_PDS_WARN("invalid ACK PSN %u on PDC %u "
			     "(outside MPR %u[+%u])",
			     pp->pds_psn, pp->pds_dpdcid,
			     pdc->tx_bm_base_psn, UET_DEFAULT_MPR);
		return -EINVAL;
	}

	if (!bm_get(pdc->tx_bm, (pp->pds_psn - pdc->tx_bm_base_psn),
		    (void **)&pdc_pkt)) {
		UET_PDS_WARN("invalid ACK PSN %u on PDC %u (packet not found)",
			     pp->pds_psn, pp->pds_dpdcid);
		return -EINVAL;
	}

	if (pdc_pkt->tx_pkt_acked) {
		UET_PDS_WARN("duplicate ACK PSN %u on PDC %u",
			     pp->pds_psn, pp->pds_dpdcid);
		return -EINVAL;
	}

	pdc_pkt->tx_pkt_acked = true;
	dlist_remove(&pdc_pkt->node); /* remove from Tx list */

	if (UET_LOG_LVL >= UET_LOG_DBG) {
		UET_PDS_DBG("PDC %d tx_bm (base %u):",
			    pdc->pdc_id, pdc->tx_bm_base_psn);
		bm_print_bits(pdc->tx_bm, uet_pdc_tx_bit_char);
	}

	/* check if this is an ACK for the close command */
	if ((pdc->state == PDC_STATE_CLOSING) &&
	    (pp->pds_psn == pdc->close_cmd_psn)) {
		UET_PDS_DBG("PDC %u received ACK for close command (psn=%u)",
			    pdc->pdc_id, pp->pds_psn);

		/* shift the tx_bm window for all left edge ACK'ed PSNs */
		rc = uet_pds_shift_tx_window(uet, pdc);
		if (rc != 0)
			return rc;

		/* FIXME, make sure there are no more pending packets */

		/* free the PDC */
		uet_pdsm_free_pdc(pdc);

		return 0;
	}

	if (pdc->state == PDC_STATE_SYN) {
		UET_PDS_DBG("PDC %u transitioned to the ESTABLISHED state",
			    pdc->pdc_id);
		pdc->state  = PDC_STATE_ESTABLISHED;
		pdc->dpdcid = pp->pds_spdcid;
	}

	/* upcall for SES processing */
	if (pp->next_hdr != UET_HDR_NONE) {
		rc = uet->pds.upcall.rx_rsp(pdc_pkt->tx_pkt_handle, pp);
		if (rc != 0) {
			UET_PDS_ERR("PDC %u ACK PSN %u SES upcall "
				    "failed (rx_rsp=%d)",
				    pp->pds_dpdcid, pp->pds_psn, rc);
			return rc;
		}
	}

	/* shift the tx_bm window for all left edge ACK'ed PSNs */
	rc = uet_pds_shift_tx_window(uet, pdc);
	if (rc != 0)
		return rc;

	/* TODO:
	 * If the UET_PDS_ACK_FLAGS_REQ_TGT_CLR flag was set on the ACK,
	 * immediately send a PDS CLEAR control packet now. This allows the
	 * CLEAR to be acknowledged right away instead of waiting for the
	 * next request to be sent that would contain a cumulative clear PSN.
	 */

	/*
	 * Check if PDC has close_requested set and all messages have drained.
	 * This handles the case where messages don't use MAINTAIN_PDC flag.
	 *
	 * FIXME Remove this code block, not sure it's possible to hit.
	 */
	if ((pdc->state == PDC_STATE_ESTABLISHED) && pdc->is_initiator &&
	    pdc->close_requested && !pdc->close_started &&
	    !pdc->active_msg_id_valid) {
		rc = uet_pds_initiate_pdc_close(uet, pdc);
		if ((rc != 0) && (rc != -EAGAIN)) {
			UET_PDS_WARN("PDC %u failed to initiate close (rc=%d)",
				     pdc->pdc_id, rc);
		}
	}

	return 0;
}

static int uet_pds_process_syn_pkt(struct uet_instance *uet,
				   struct uet_pdc_pkt *pdc_pkt)
{
	struct uet_parsed_pkt *pp = &pdc_pkt->pkt_pp;
	struct uet_pdc *pdc;
	bool rtx;
	int rc;

	/* TODO:
	 * [x] find PDC (possibly created from previous SYN)
	 * [x] if not found
	 *     [x] create and init PDC
	 * [x] if duplicate
	 *     [x] send previous response / or default response
	 *     [x] done
	 * [x] place packet with SYN offset
	 * [x] process packet with SES (rx_req)
	 * [x] send ACK
	 *     [ ] or NACK
	 * [x] save response packet and mark if non-default
	 */

	pdc = uet_pdsm_assign_tgt_pdc(pp);
	if (pdc == NULL)
		return -ENODEV;

	/* check if this packet is a duplicate */
	rc = uet_pds_check_duplicate_and_rtx(uet, pdc, pdc_pkt, &rtx);
	/* TODO: if error, free PDC if allocated with this SYN */
	if (rc != 0)
		return rc;
	else if (rtx)
		return 0;

	UET_PDS_DBG("PDC %u rx_bm: base=%u psn=%u SET bit=%u",
		    pdc->pdc_id, pdc->rx_bm_base_psn, pp->pds_psn,
		    (pp->pds_psn - pdc->rx_bm_base_psn));

	bm_set(pdc->rx_bm, (pp->pds_psn - pdc->rx_bm_base_psn), pdc_pkt);

	if (UET_LOG_LVL >= UET_LOG_DBG) {
		UET_PDS_DBG("PDC %d rx_bm (base %u):",
			    pdc->pdc_id, pdc->rx_bm_base_psn);
		bm_print_bits(pdc->rx_bm, uet_pdc_rx_bit_char);
	}

	if (pp->pds_type == UET_PDS_TYPE_RUD_REQ) {
		/* for RUD, call into SES immediately ignoring order */
		rc = uet_pds_upcall_ses_rx_req(uet, pdc, pdc_pkt);
		if (rc != 0)
			return rc;

		rc = uet_pds_shift_rx_window(uet, pdc, false);
		if (rc != 0)
			return rc;
	} else if (pp->pds_type == UET_PDS_TYPE_ROD_REQ) {
		/* for ROD, reorder before calling into SES */
		rc = uet_pds_shift_rx_window(uet, pdc, true);
		if (rc != 0)
			return rc;
	}

	return 0;
}

static int uet_pds_process_control(struct uet_instance *uet,
				   struct uet_parsed_pkt *pp,
				   uint8_t *pkt,
				   int pkt_len)
{
	struct uet_pdc *pdc;
	bool send_ack = false;
	int rc;

	/* check if ACK is requested */
	if (pp->pds_flags & UET_PDS_CTRL_FLAGS_AR)
		send_ack = true;

	switch (pp->pds_ctrl_type) {
	case UET_PDS_CTRL_TYPE_CLOSE:
		UET_PDS_DBG("Received CLOSE command (spdcid=%u dpdcid=%u)",
			    pp->pds_spdcid, pp->pds_dpdcid);

		/* find the target PDC */
		pdc = uet_pdsm_get_pdc(pp->pds_dpdcid, false);
		if (!pdc) {
			UET_PDS_WARN("CLOSE command for unknown PDC %u",
				     pp->pds_dpdcid);
			return -EINVAL;
		}

		/* verify the PDC is in correct state */
		if (pdc->state != PDC_STATE_ESTABLISHED) {
			UET_PDS_WARN("PDC %u not ESTABLISHED (state=%d)",
				     pdc->pdc_id, pdc->state);
			return -EINVAL;
		}

		/* verify dpdcid matches spdcid */
		if (pdc->dpdcid != pp->pds_spdcid) {
			UET_PDS_WARN("PDC %u dpdcid mismatch (%u != %u)",
				     pdc->pdc_id, pdc->dpdcid, pp->pds_spdcid);
			return -EINVAL;
		}

		/* send ACK if requested */
		if (send_ack) {
			struct uet_pdc_pkt temp_pkt;

			UET_PDS_DBG("PDC %u Tx ACK for CLOSE command",
				    pdc->pdc_id);

			/* set up temp pdc_pkt with parsed control packet */
			memset(&temp_pkt, 0, sizeof(temp_pkt));
			memcpy(&temp_pkt.pkt_pp, pp, sizeof(*pp));

			/* build and send an ACK packet */
			rc = uet_pds_tx_ack_pkt(uet, pdc, &temp_pkt,
						UET_HDR_NONE, 0,
						NULL, false);
			if (rc != 0) {
				UET_PDS_ERR("failed to send ACK for CLOSE");
				return rc;
			}

			/* FIXME Is the control packet freed here? */
		}

		/* free the PDC */
		uet_pdsm_free_pdc(pdc);

		break;

	case UET_PDS_CTRL_TYPE_PROBE:
	case UET_PDS_CTRL_TYPE_CREDIT:
	case UET_PDS_CTRL_TYPE_CREDIT_REQ:
	case UET_PDS_CTRL_TYPE_NEGOTIATION:
		UET_PDS_ERR("Control type %d not yet supported",
			     pp->pds_ctrl_type);
		return -EINVAL;

	default:
		UET_PDS_ERR("Unknown control type %d", pp->pds_ctrl_type);
		return -EINVAL;
	}

	return 0;
}

static int uet_pds_process_request(struct uet_instance *uet,
				   struct uet_parsed_pkt *pp,
				   uint8_t *pkt,
				   int pkt_len)
{
	struct uet_pdc_pkt *pdc_pkt;
	struct uet_pdc *pdc;
	bool rtx;
	int rc;

	/* TODO:
	 * [ ] if RUDI/UUD...
	 *     [ ] process request
	 *     [ ] send ACK (or NACK)
	 *     [ ] done
	 */

	if ((pp->pds_type != UET_PDS_TYPE_RUD_REQ) &&
	    (pp->pds_type != UET_PDS_TYPE_ROD_REQ)) {
		UET_PDS_WARN("Rx packet type not supported %d",
			     pp->pds_type);
		return -EINVAL;
	}

	pdc_pkt = calloc(1, sizeof(struct uet_pdc_pkt));
	if (pdc_pkt == NULL) {
		UET_PDS_ERR("failed to alloc PDC packet");
		return -ENOMEM;
	}

	pdc_pkt->psn = pp->pds_psn;
	pdc_pkt->msg_id = pp->ses_msg_id;
	pdc_pkt->pkt = pkt;
	pdc_pkt->pkt_len = pkt_len;
	memcpy(&pdc_pkt->pkt_pp, pp, sizeof(*pp));
	pdc_pkt->pkt_parsed = true;

	/* if this is a SYN packet then a new PDC might be needed */
	if (pdc_pkt->pkt_pp.pds_flags & UET_PDS_REQ_FLAGS_SYN) {
		rc = uet_pds_process_syn_pkt(uet, pdc_pkt);
		if (rc != 0)
			goto exit_err;
		return 0;
	}

	/* TODO:
	 * [x] fetch the PDC (from dpdcid)
	 * [x] verify PDC is in an active state (not UNALLOC)
	 *     [x] if not then drop the Request
	 * [x] verify the spdcid PDC is the correct peer
	 *     [x] if not then drop the Request
	 * [x] verify the PSN is within the +/- MPR
	 *     [x] if not then drop the Request
	 * [x] if duplicate
	 *     [x] send previous response / or default response
	 *     [x] done
	 * [x] place packet in the Rx bitmap
	 * [x] process packet with SES (rx_req)
	 * [x] send ACK (or NACK)
	 * [x] save response packet and mark if non-default
	 * [x] move the rx_bm PSN window for all contiguous PSNs
	 */

	pdc = uet_pdsm_get_pdc(pdc_pkt->pkt_pp.pds_dpdcid, false);
	if (pdc == NULL) {
		rc = -ENODEV;
		goto exit_err;
	}

	if (pdc_pkt->pkt_pp.pds_spdcid != pdc->dpdcid) {
		UET_PDS_WARN("invalid PDC %u (spdcid %u != dpdcid %u)",
			     pdc->pdc_id, pdc_pkt->pkt_pp.pds_spdcid,
			     pdc->dpdcid);
		rc = -EINVAL;
		goto exit_err;
	}

	/* check if this packet is a duplicate */
	rc = uet_pds_check_duplicate_and_rtx(uet, pdc, pdc_pkt, &rtx);
	if (rc != 0)
		goto exit_err;
	else if (rtx)
		return 0;

	UET_PDS_DBG("PDC %u rx_bm: base=%u psn=%u SET bit=%u",
		    pdc->pdc_id, pdc->rx_bm_base_psn, pdc_pkt->pkt_pp.pds_psn,
		    (pdc_pkt->pkt_pp.pds_psn - pdc->rx_bm_base_psn));

	bm_set(pdc->rx_bm, (pdc_pkt->pkt_pp.pds_psn - pdc->rx_bm_base_psn),
	       pdc_pkt);

	if (UET_LOG_LVL >= UET_LOG_DBG) {
		UET_PDS_DBG("PDC %d rx_bm (base %u):",
			    pdc->pdc_id, pdc->rx_bm_base_psn);
		bm_print_bits(pdc->rx_bm, uet_pdc_rx_bit_char);
	}

	if (pp->pds_type == UET_PDS_TYPE_RUD_REQ) {
		/* for RUD, call into SES immediately ignoring order */
		rc = uet_pds_upcall_ses_rx_req(uet, pdc, pdc_pkt);
		if (rc != 0)
			return rc;

		rc = uet_pds_shift_rx_window(uet, pdc, false);
		if (rc != 0)
			return rc;
	} else if (pp->pds_type == UET_PDS_TYPE_ROD_REQ) {
		/* for ROD, reorder before calling into SES */
		rc = uet_pds_shift_rx_window(uet, pdc, true);
		if (rc != 0)
			return rc;
	}

	return 0;

exit_err:
	free(pdc_pkt);
	return rc;
}

int uet_pds_progress_rx(struct uet_instance *uet)
{
	uint8_t *pkt;
	size_t pkt_len;
	struct uet_parsed_pkt pp;
	bool pkt_is_ack, pkt_is_rd_rsp, pkt_is_ctrl;
	struct uet_pdc_pkt *pdc_pkt = NULL;
	struct uet_pdc *pdc;
	uet_pds_next_hdr_t rsp_next_hdr;
	void *rsp_ses_hdr = NULL;
	size_t rsp_ses_hdr_len;
	bool ses_nack, gtd_del, rtx;
	uint32_t crc;
	uint8_t *crc_start;
	int rc = 0;

	PDS_GO();

	rc = uet_pds_sec_rx_pkt(uet, &pkt, &pkt_len);
	if (rc != 1)
		return rc;

	/* validate the packet */
	if (!uet_pds_rx_pkt_chk(uet, pkt, pkt_len,
				&pkt_is_ack,
				&pkt_is_rd_rsp,
				&pkt_is_ctrl)) {
		UET_PDS_WARN("invalid Rx packet (len=%ld)", pkt_len);
		rc = -EINVAL;
		goto exit_err;
	}

	/* parse the packet */
	rc = uet_parse_pkt(uet, pkt, pkt_len, &pp);
	if (rc != 0) {
		UET_PDS_ERR("malformed Rx packet");
		goto exit_err;
	}

	if (!pp.sec) {
		/* calculate the CRC (include src/dst IP and UDP) */
		/* TODO: IPv6 support */
		crc_start = ((uint8_t *)pp.ip + 12);
		crc = crc32c(crc_start, (8 + pp.ip_payload_len - CRC_LEN));

		/* verify the CRC */
		if (memcmp(&crc,
			   ((uint8_t *)pp.ip + pp.ip_len +
			    pp.ip_payload_len - CRC_LEN),
			   CRC_LEN) != 0) {
			UET_PDS_WARN("Rx packet CRC mismatch");
			rc = -EINVAL;
			goto exit_err;
		}
	}

	uet_pds_pkt_dbg(uet, &pp, false, "RX PACKET");

	if (pkt_is_ack) {

		rc = uet_pds_process_ack(uet, &pp);
		if (rc != 0)
			goto exit_err;

	} else if (pkt_is_ctrl) {

		rc = uet_pds_process_control(uet, &pp, pkt, pkt_len);
		if (rc != 0)
			goto exit_err;

	} else { /* request packet */

		rc = uet_pds_process_request(uet, &pp, pkt, pkt_len);
		if (rc != 0)
			goto exit_err;

	}

	return 0;

exit_err:
	free(pkt);
	return rc;
}

void uet_pds_ep_close_wait(struct uet_ep *uet_ep)
{
	struct uet_instance *uet;
	time_t start_time, now;

	uet_ep->ep_state = UET_EP_CLOSE_WAIT;

	uet = uet_ep->uet_domain->uet;

	/*
	 * Continue receiving packets for max segment lifetime after the
	 * EP is closed. This gives time to retransmit any lost ACKs but
	 * no other packet Rx processing is performed.
	 */

	if (uet_gettime(&start_time)) {
		UET_PDS_ERR("aborting endpoint close wait state");
		return;
	}

	while (1) {
		if (uet_gettime(&now)) {
			UET_PDS_ERR("aborting endpoint close wait state");
			break;
		}

		if ((now - start_time) > uet->pds.msl)
			break;

		uet->pds.downcall.progress_rx(uet);
	}
}

