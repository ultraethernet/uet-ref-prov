/*
 * Copyright (c) 2024,2025,2026 Broadcom. All rights reserved. The term
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
#include "uet_pds_rudi.h"
#include "uet_pds_uud.h"
#include "imp_shim.h"
#include "bitmap.h"
#include "crc32c.h"

#define UET_DEFAULT_TC          0
#define UET_PDS_MPR_GRANULARITY 128U
#define UET_DEFAULT_MP_RANGE    128U
#define UET_DEFAULT_MPR         (UET_DEFAULT_MP_RANGE / UET_PDS_MPR_GRANULARITY)
#define UET_DEFAULT_ENTROPY     0x4242

#define UET_PDC_MAX 64

/*
 * These random thresholds can be overridden with the UET_PDC_CLOSE_THRESH
 * and the UET_PKT_DROP_THRESH environment variables. The values are
 * represented in hundredths of a percent (1=0.01%, 100=1%, etc).
 */
#define UET_PDC_CLOSE_THRESH 0
#define UET_PKT_DROP_THRESH  0

/*
 * New_PDC_Time DoS timer. A PENDING target PDC is reaped if the initiator
 * does not re-drive with the assigned Start_PSN within New_PDC_Time ms.
 * New_PDC_Time is set well above the network RTT, so a normal establishment
 * (one RTT) never trips it, only a dead/malicious initiator does.
 */
#define UET_DEFAULT_NEW_PDC_TIME_MS 1000

/*
 * Close_REQ_Time. When a target requests a PDC close by sending a Close Request
 * CP, this timer bounds how long the target waits for the initiator to respond
 * with a Close Command CP. If the initiator does not issue a Close Command CP
 * within Close_REQ_Time, the target MUST close the PDC in error.
 */
#define UET_DEFAULT_CLOSE_REQ_TIME_MS 1000

/*
 * PSN-range based close. An encrypted PDC MUST close once its PSN reaches
 * Start_PSN + 2^31 (and then re-establishes on the next send). This bounds
 * how far a single Start_PSN's anti-replay window travels. This is always
 * enabled on secured PDCs.
 */
#define UET_PSN_RANGE_LIMIT 0x80000000U

#define UET_PDS_UPDATE_PSN(old, new)			\
	do {						\
		if ((int32_t)((new) - (old)) > 0)	\
			(old) = (new);			\
	} while (0)

#define UET_PDS_PSN_OFFSET(a, b)      ((int32_t)((a) - (b)))
#define UET_PDS_PSN_AFTER(a, b)       ((int32_t)((a) - (b)) > 0)
#define UET_PDS_PSN_AFTER_EQ(a, b)    ((int32_t)((a) - (b)) >= 0)

typedef enum {
	PDC_STATE_UNALLOC,
	PDC_STATE_SYN,
	PDC_STATE_PENDING,
	PDC_STATE_ESTABLISHED,
	PDC_STATE_CLOSING,
	PDC_STATE_ERROR,
} pdc_state_t;

typedef enum {
	PDC_TYPE_NONE,
	PDC_TYPE_RUD,
	PDC_TYPE_ROD,
} pdc_type_t;

/* action to take when a NACK is received on the initiator side */
enum {
	UET_NACK_ACTION_DROP = 0,   /* drop the NACK packet */
	UET_NACK_ACTION_RETX,       /* retransmit the NACKed PSN */
	UET_NACK_ACTION_CLOSE,      /* close PDC */
};
struct uet_pdc_pkt {
	struct dlist_entry    node;
	uint32_t              psn;
	uint16_t              msg_id;

	uint8_t              *pkt_buf;
	int                   pkt_buf_len;
	uint8_t              *pkt;
	int                   pkt_len;
	time_t                tx_time; /* tx time for detecting timeout */
	int                   tx_retry_cnt;  /* number of retransmissions */
	uet_pkt_handle_t      tx_pkt_handle;
	bool                  tx_pkt_acked; /* this packet has been acked */
	bool                  dst_recvd; /* this packet has arrived at dst */
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
	bool                 is_ipv6;
	uint16_t             syn_offset; /* initiator SYN offset until ACK */
	uint32_t             start_psn; /* PDC start PSN (random base) */
	time_t               pending_time; /* PENDING state entry time */
	uint32_t             next_psn; /* next Tx pkt seq number */
	struct bitmap       *tx_bm;
	uint32_t             tx_bm_base_psn; /* start PSN for initiator MPR */
	uint32_t             max_cack_psn; /* highest cack PSN received */
	uint32_t             peer_mp_range; /* 0 means peer ignores MP_RANGE */
	uint32_t             mpr_update_cack_psn;
	bool                 mpr_update_valid;

	/* target side fields */
	struct bitmap      *rx_bm;
	uint32_t            rx_bm_base_psn; /* start PSN for target MPR */
	uint32_t            cack_psn; /* coalesced ack PSN */
	uint32_t            max_clear_psn; /* highest clear PSN */
	uint32_t            prev_ar_psn; /* highest PSN received with ar flag */
	uint32_t            max_rcvd_psn; /* highest PSN received */
	uint32_t            accepted_bytes; /* bytes received between ACKs */
	uint32_t            sack_base_track; /* track SACK bitmap base PSN */
	time_t              close_req_time; /* Close_REQ_Timer */

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

	/* PDS statistics */
	uint32_t              new_pdc_timeout_cnt; /* PENDING PDCs reaped */
	uint32_t              psn_range_close_cnt; /* PDCs closed PSN range */
	uint32_t              pdc_close_in_err_cnt; /* PDCs closed in error */
};

static struct uet_pds_state pds_state;

static int pds_pdc_close_thresh = UET_PDC_CLOSE_THRESH;
static int pds_pkt_drop_thresh = UET_PKT_DROP_THRESH;

/* New_PDC_Time DoS timer, how long a half-open (PENDING) PDC is held */
static int pds_new_pdc_time_ms = UET_DEFAULT_NEW_PDC_TIME_MS;
/* Close_REQ_Time, how long target waits for the initiator's Close Command CP */
static int pds_close_req_time_ms = UET_DEFAULT_CLOSE_REQ_TIME_MS;
/* Secure PDC establishment method. Default is EXPECTED_0RTT_START. The
 * environment variable UET_PDS_PSN_METHOD=1rtt selects RANDOM_1RTT_START,
 * where the target ignores the initiator's Start_PSN, mints its own, and
 * returns it in a NACK.
 */
typedef enum {
	UET_PDS_PSN_METHOD_0RTT = 0,
	UET_PDS_PSN_METHOD_1RTT,
} uet_pds_psn_method_t;

static uet_pds_psn_method_t pds_psn_method = UET_PDS_PSN_METHOD_0RTT;

/*
 * Test if a random event should occur based on a threshold. Threshold is in
 * hundredths of a percent (0.01% granularity). Returns true if event should
 * occur.
 */
static inline bool uet_pds_random_check(int thresh)
{
	return ((rand() % 10000) < thresh);
}

/*
 * Random/pseudo-random PDC Start_PSN (MUST be random, at least 2^16 from the
 * last PSN used on that PDC). Kept in [2^16, 2^31) so it is >= 2^16 and
 * Start_PSN + 2^31 does not wrap a uint32. RAND_MAX may be only 15 bits, so
 * two rand() calls are mixed.
 */
static inline uint32_t uet_pds_rand_start_psn(void)
{
	uint32_t psn = (((uint32_t)rand() << 16) ^ (uint32_t)rand());

	psn &= 0x7fffffff;      /* < 2^31 */
	if (psn < 0x10000)      /* >= 2^16 */
		psn += 0x10000;

	return psn;
}

#define PDS_GO()                                          \
	do {                                              \
		if (pds_state.ready != true) {            \
			UET_PDS_ERR("PDS is not ready!"); \
			exit(1);                          \
		}                                         \
	} while (0)

#define PSN_IN_MPR(psn, base_psn) \
	((uint32_t)((psn) - (base_psn)) < UET_DEFAULT_MP_RANGE)

#define PSN_IN_PRIOR_MPR(psn, base_psn)                             \
	PSN_IN_MPR((psn), (uint32_t)((base_psn) - UET_DEFAULT_MP_RANGE))

static inline uint32_t uet_pds_decode_mpr(uint8_t mpr)
{
	return (uint32_t)mpr * UET_PDS_MPR_GRANULARITY;
}

static inline bool uet_pds_tx_psn_allowed(const struct uet_pdc *pdc,
					   uint32_t psn)
{
	if (!PSN_IN_MPR(psn, pdc->tx_bm_base_psn))
		return false;

	return !pdc->peer_mp_range ||
	       !UET_PDS_PSN_AFTER(psn, pdc->max_cack_psn + pdc->peer_mp_range);
}

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

#define PDS_CTRL_TYPE_TO_STR(n)                                   \
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

#define PDS_DBG_TX(pp, msg)                                          \
	UET_PDS_DBG("PDC %u [Tx %u] [PSN %u] [%s/%s] - %s (%d)",     \
		    (pp)->pds_spdcid, (pp)->pds_dpdcid,              \
		    (pp)->pds_psn,                                   \
		    PDS_TYPE_TO_STR((pp)->pds_type),                 \
		    ((pp)->pds_type == UET_PDS_TYPE_CTRL)            \
			? PDS_CTRL_TYPE_TO_STR((pp)->pds_ctrl_type)  \
			: NEXT_HDR_TO_STR((pp)->next_hdr),           \
		    (msg),                                           \
		    (pp)->pkt_len)

#define PDS_DBG_RX(pp, msg)                                          \
	UET_PDS_DBG("PDC %u [Rx %u] [PSN %u] [%s/%s] - %s (%d)",     \
		    (pp)->pds_dpdcid, (pp)->pds_spdcid,              \
		    (pp)->pds_psn,                                   \
		    PDS_TYPE_TO_STR((pp)->pds_type),                 \
		    ((pp)->pds_type == UET_PDS_TYPE_CTRL)            \
			? PDS_CTRL_TYPE_TO_STR((pp)->pds_ctrl_type)  \
			: NEXT_HDR_TO_STR((pp)->next_hdr),           \
		    (msg),                                           \
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

/* forward decl: called by uet_pds_progress_tx_pkt() before its definition */
static void uet_pds_close_pdc_in_error(struct uet_instance *uet,
				       struct uet_pdc *pdc);

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
	bool update_ip_len = false;
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
		crc_start = (pp->is_ipv6) ?
			    ((uint8_t *)pp->ip + 8) : /* IPv6 src offset */
			    ((uint8_t *)pp->ip + 12); /* IPv4 src offset */
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
			UET_PDS_ERR("PDC %u PSN %u random drop %s packet!",
				    pdc->pdc_id, pp->pds_psn,
				    (tx_pkt) ? "Tx" : "ACK");
			return 0;
		}

		if (imp_shim_is_enabled())
			return imp_shim_tx_pkt(UET_NIC(uet), *pkt, pp->ip,
					       new_pkt_len);

		return uet_nic_tx_pkt(UET_NIC(uet), *pkt, pp->ip, new_pkt_len);
	}

	/* inject/build the security header and encrypt the packet */

	if (is_rtx) {
		rc = uet_sec_update_hdr_tsc(*pkt, pdc->is_ipv6);
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
				       &new_pkt_len,
				       pdc->is_ipv6);
		if (rc != 0)
			return rc;

		*pkt     = new_pkt;
		*pkt_len = (new_pkt_len + UET_SEC_TAG_LEN);

		/* IP length fields need fixing after security header injection */
		update_ip_len = true;
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

	if (update_ip_len) {
		if (pp->is_ipv6)
			uet_update_ipv6_pl(pp->ip,
					   (*pkt_len - uet->nic.l2_hdr_size -
					    sizeof(struct ipv6hdr)));
		else
			uet_update_ipv4_tl(pp->ip,
					   (*pkt_len - uet->nic.l2_hdr_size));
	}

	rc = uet_sec_enc_pkt(uet,
			     pkt_buf,
			     pkt_buf_len,
			     *pkt,
			     *pkt_len,
			     &new_pkt,
			     &new_pkt_len,
			     pdc->is_ipv6);
	if (rc != 0)
		return rc;

	if (tx_pkt)
		uet_gettime(&pdc_pkt->tx_time);

	/* randomly drop packets for testing retransmit logic */
	if (pds_pkt_drop_thresh &&
	    uet_pds_random_check(pds_pkt_drop_thresh)) {
		UET_PDS_ERR("PDC %u PSN %u random drop %s packet!",
			    pdc->pdc_id, pp->pds_psn,
			    (tx_pkt) ? "Tx" : "ACK");
		return 0;
	}

	if (imp_shim_is_enabled())
		return imp_shim_tx_pkt(UET_NIC(uet), new_pkt, pp->ip,
				       new_pkt_len);

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
	pdc->close_req_time = 0;

	pdc->pending_time = 0;

	dlist_init(&pdc->tx_pkt_list_head);

	memset(pdc->src_mac_addr, 0, ETH_ALEN);
	memset(pdc->dst_mac_addr, 0, ETH_ALEN);
	memset(&pdc->src_addr, 0, sizeof(struct uet_fa));
	memset(&pdc->dst_addr, 0, sizeof(struct uet_fa));

	pdc->syn_offset = 0;
	pdc->next_psn = 0;
	bm_clear(pdc->tx_bm);
	pdc->tx_bm_base_psn = 0;
	pdc->max_cack_psn = 0;
	pdc->peer_mp_range = UET_DEFAULT_MP_RANGE;
	pdc->mpr_update_cack_psn = 0;
	pdc->mpr_update_valid = false;

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
	pdc->close_req_time = 0;

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
	struct uet_nic *nic = &uet_ep->uet_domain->uet->nic;
	bool dst_is_ipv6 = uet_addr_is_ipv6(av_entry->addr);
	struct uet_fa local_ip;

	PDS_GO();

	memset(&local_ip, 0, sizeof(local_ip));
	if (dst_is_ipv6)
		memcpy(local_ip.v6, nic->ipv6_addr, 16);
	else
		local_ip.v4 = nic->ipv4_addr;

	/* get the PDC if it already exists */
	memset(&pdc_key, 0, sizeof(pdc_key));
	pdc_key.type = ((mode == UET_PDS_MODE_ROD) ? PDC_TYPE_ROD :
			(mode == UET_PDS_MODE_RUD) ? PDC_TYPE_RUD :
						     PDC_TYPE_NONE);
	pdc_key.job_id = uet_ep->job_id;
	pdc_key.tc = UET_DEFAULT_TC;
	memcpy(&pdc_key.src_ip, &local_ip, sizeof(struct uet_fa));
	memcpy(&pdc_key.dst_ip, &av_entry->addr->fa, sizeof(struct uet_fa));

	HASH_FIND(pdc_ini_hh, pds_state.pdc_ini_ht, &pdc_key,
		  sizeof(pdc_key), pdc);
	if (pdc) {
		/* if the PDC is in the error state, don't use it */
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

	/* initialze this initiator PDC */
	uet_init_pdc(pdc, PDC_STATE_SYN, true);

	memcpy(pdc->src_mac_addr, uet_ep->uet_domain->uet->nic.mac_addr,
	       ETH_ALEN);
	memcpy(pdc->dst_mac_addr, av_entry->nh_mac_addr,
	       ETH_ALEN);

	memcpy(&pdc->src_addr, &local_ip, sizeof(struct uet_fa));
	memcpy(&pdc->dst_addr, &av_entry->addr->fa, sizeof(struct uet_fa));
	pdc->is_ipv6 = dst_is_ipv6;

	uet_pdsm_get_sdi(pdc); /* sets sec_enabled / sdi */

	/* Choose the Start_PSN for the PDC. Non-secured PDCs and secured PDCs
	 * (before any close has advanced the SDI's ini_start_psn), a random
	 * value is chosen. For secured PDCs the SDI's ini_start_psn is used
	 * when it is >0.
	 *
	 * FIXME: For a fresh SD and a new 0-RTT PDC, a full-range random
	 * seed is chosen. On PDC close the target sets its floor to
	 * tgt_start_psn = start_psn + 1 and that floor is per-SD (shared by
	 * all initiators to that target). Therefore, a very high seed pins a
	 * high floor for every other co-initiator on the SD where each will
	 * need a 1-RTT NACK to sync. Seeding the 0-RTT case to a low value
	 * would localize this. The local initiator is more likely to fall
	 * below tgt_start_psn and self-correct via the NACK, rather than
	 * overshoot and raise the shared floor affecting all initiators.
	 */
	if (pdc->sec_enabled && (uet_sec_sd_get_ini_start_psn(pdc->sdi) != 0))
		pdc->start_psn = uet_sec_sd_get_ini_start_psn(pdc->sdi);
	else
		pdc->start_psn = uet_pds_rand_start_psn();

	pdc->next_psn       = pdc->start_psn;
	pdc->tx_bm_base_psn = pdc->start_psn;
	pdc->rx_bm_base_psn = pdc->start_psn;
	pdc->max_cack_psn   = (pdc->start_psn - 1);

	/* stick this PDC in the initiator hash table */
	memcpy(&pdc->ini_hkey, &pdc_key, sizeof(pdc_key));
	HASH_ADD(pdc_ini_hh, pds_state.pdc_ini_ht, ini_hkey,
		 sizeof(pdc_key), pdc);

	UET_PDS_DBG("allocated initiator PDC %u %s(state=SYN, start_psn=%u)",
		    pdc->pdc_id,
		    (!pdc->sec_enabled) ?
		        "" :
		        (pds_psn_method == UET_PDS_PSN_METHOD_1RTT) ?
		            "1rtt" : "0rtt",
		    pdc->start_psn);

	return pdc;
}

static int uet_pdsm_assign_tgt_pdc(struct uet_parsed_pkt *pp,
				   struct uet_pdc **out_pdc,
				   uet_pds_nack_code_t *nack_code,
				   uint32_t *nack_payload)
{
	struct uet_ses_req_cmn *ses_cmn = (struct uet_ses_req_cmn *)pp->ses;
	struct ethhdr *eth = (struct ethhdr *)pp->eth;
	struct uet_pdc_tgt_key pdc_key;
	struct uet_pdc *pdc;
	uint32_t expected_psn;
	uint32_t start_psn;
	uint32_t base;
	bool reject_pending = false;

	*out_pdc = NULL;
	*nack_code = UET_NACK_NONE;
	*nack_payload = 0;

	if ((pp->pds_type != UET_PDS_TYPE_RUD_REQ) &&
	    (pp->pds_type != UET_PDS_TYPE_ROD_REQ)) {
		*nack_code = UET_NACK_PDC_MODE_MISMATCH;
		return -EINVAL;
	}

	if ((pp->next_hdr != UET_HDR_REQ_SMALL) &&
	    (pp->next_hdr != UET_HDR_REQ_MEDIUM) &&
	    (pp->next_hdr != UET_HDR_REQ_STD)) {
		*nack_code = UET_NACK_PDC_HDR_MISMATCH;
		return -EINVAL;
	}

	memset(&pdc_key, 0, sizeof(pdc_key));
	if (pp->is_ipv6) {
		struct ipv6hdr *ipv6 = (struct ipv6hdr *)pp->ip;
		memcpy(pdc_key.src_ip.v6, &ipv6->saddr, 16);
		memcpy(pdc_key.dst_ip.v6, &ipv6->daddr, 16);
	} else {
		struct iphdr *ipv4 = (struct iphdr *)pp->ip;
		pdc_key.src_ip.v4 = ntohl(ipv4->saddr);
		pdc_key.dst_ip.v4 = ntohl(ipv4->daddr);
	}
	pdc_key.spdcid = pp->pds_spdcid; /* target side needs spdcid */

	HASH_FIND(pdc_tgt_hh, pds_state.pdc_tgt_ht, &pdc_key,
		  sizeof(pdc_key), pdc);
	if (pdc) {
		UET_PDS_DBG("lookup found target PDC %u", pdc->pdc_id);

		/* can't receive a SYN on an initiator PDC */
		if (pdc->is_initiator) {
			UET_PDS_ERR("PDC %u is initiator and received SYN",
				    pdc->pdc_id);
			*nack_code = UET_NACK_INVALID_SYN;
			return -EINVAL;
		}

		/* PENDING target PDC is awaiting the initiator to re-drive
		 * with the minted Start_PSN. Accept only when it matches,
		 * otherwise NACK and drop the packet.
		 */
		if (pdc->state == PDC_STATE_PENDING) {
			start_psn = (pp->pds_psn - pp->pds_syn_off);

			if (start_psn == pdc->start_psn) {
				pdc->state = PDC_STATE_ESTABLISHED;

				UET_PDS_DBG("target PDC %u %sPENDING->ESTABLISHED "
					    "(Start_PSN %u)",
					    pdc->pdc_id,
					    (!pdc->sec_enabled) ?
					        "" :
					        (pds_psn_method ==
					         UET_PDS_PSN_METHOD_1RTT) ?
					            "1rtt" : "0rtt",
					    start_psn);

				*out_pdc = pdc;
				return 0;
			}

			UET_PDS_WARN("target PDC %u PENDING: wrong Start_PSN %u "
				     "(want %u), re-NACK",
				     pdc->pdc_id, start_psn, pdc->start_psn);

			*nack_code = UET_NACK_NEW_START_PSN;
			*nack_payload = pdc->start_psn;
			return -EINVAL;
		}

		UET_PDS_DBG("SYN request for PDC %u (PSN %u offset %u)",
			    pdc->pdc_id, pp->pds_psn, pp->pds_syn_off);

		*out_pdc = pdc;
		return 0;
	}

	UET_PDS_DBG("first SYN request from PDC %u (PSN %u offset %u)",
		    pp->pds_spdcid, pp->pds_psn, pp->pds_syn_off);

	/* allocate a new PDC from the head of the free list */
	pdc = uet_pdsm_alloc_pdc();
	if (!pdc) {
		UET_PDS_ERR("no free PDCs available for target");
		*nack_code = UET_NACK_NO_PDC_AVAIL;
		return -ENOSPC;
	}

	/* initialze this target PDC */
	uet_init_pdc(pdc, PDC_STATE_ESTABLISHED, false);

	memcpy(pdc->src_mac_addr, eth->h_dest, ETH_ALEN);
	memcpy(pdc->dst_mac_addr, eth->h_source, ETH_ALEN);

	if (pp->is_ipv6) {
		struct ipv6hdr *ipv6 = (struct ipv6hdr *)pp->ip;
		memcpy(pdc->src_addr.v6, &ipv6->daddr, 16);
		memcpy(pdc->dst_addr.v6, &ipv6->saddr, 16);
	} else {
		struct iphdr *ipv4 = (struct iphdr *)pp->ip;
		pdc->src_addr.v4 = ntohl(ipv4->daddr);
		pdc->dst_addr.v4 = ntohl(ipv4->saddr);
	}

	pdc->is_ipv6        = pp->is_ipv6;
	pdc->dpdcid         = pp->pds_spdcid;
	pdc->accepted_bytes = 0;

	uet_pdsm_get_sdi(pdc); /* sets sec_enabled / sdi */

	start_psn = (pp->pds_psn - pp->pds_syn_off);
	base = start_psn;

	/* Secure PDC establishment validation. Pick the PSN base this target
	 * will use and whether to reject as pending:
	 *   - Non-secure: use the initiator's Start_PSN
	 *   - RANDOM_1RTT_START: always NACK a new random Start_PSN
	 *   - EXPECTED_0RTT_START: reject a Start_PSN older than the SDI's
	 *     Expected_PSN, NACK with the Expected_PSN as the base
	 * When rejected, the PDC is placed in the PENDING state and the
	 * required Start_PSN is returned in a UET_NEW_START_PSN NACK. The
	 * PDC moves to ESTABLISHED only once the initiator re-drives with
	 * that new Start_PSN.
	 */
	if (pdc->sec_enabled) {
		if (pds_psn_method == UET_PDS_PSN_METHOD_1RTT) {
			base = uet_pds_rand_start_psn();
			reject_pending = true;
		} else { /* UET_PDS_PSN_METHOD_0RTT */
			expected_psn = uet_sec_sd_get_tgt_start_psn(pdc->sdi);

			if (!UET_PDS_PSN_AFTER_EQ(start_psn, expected_psn)) {
				base = expected_psn;
				reject_pending = true;
			}
		}
	}

	/* seed all PSN bases from the chosen base (accept or PENDING) */
	pdc->start_psn       = base;
	pdc->rx_bm_base_psn  = base;
	pdc->tx_bm_base_psn  = base;
	pdc->next_psn        = base;
	pdc->max_cack_psn    = (base - 1);
	pdc->cack_psn        = (base - 1);
	pdc->max_clear_psn   = (base - 1);
	pdc->prev_ar_psn     = (base - 1);
	pdc->max_rcvd_psn    = (base - 1);
	pdc->sack_base_track = pdc->cack_psn;

	/* stick this PDC in the target hash table */
	memcpy(&pdc->tgt_hkey, &pdc_key, sizeof(pdc_key));
	HASH_ADD(pdc_tgt_hh, pds_state.pdc_tgt_ht, tgt_hkey,
		 sizeof(pdc_key), pdc);

	if (reject_pending) {
		pdc->state = PDC_STATE_PENDING;
		uet_gettime(&pdc->pending_time);

		UET_PDS_WARN("target PDC %u %sPENDING: NACK Start_PSN %u (rx %u)",
			     pdc->pdc_id,
			     (!pdc->sec_enabled) ?
			         "" :
			         (pds_psn_method == UET_PDS_PSN_METHOD_1RTT) ?
			             "1rtt" : "0rtt",
			     base, start_psn);
		*nack_code = UET_NACK_NEW_START_PSN;
		*nack_payload = base;
		return -EINVAL;
	}

	UET_PDS_DBG("allocated target PDC %u %s(state=ESTABLISHED) (dpdcid=%u)",
		    pdc->pdc_id,
		    (!pdc->sec_enabled) ?
		        "" :
		        (pds_psn_method == UET_PDS_PSN_METHOD_1RTT) ?
		            "1rtt" : "0rtt",
		    pdc->dpdcid);

	*out_pdc = pdc;
	return 0;
}

static int uet_pdsm_get_pdc(uint16_t pdc_id,
			    bool for_fwd,
			    struct uet_pdc **out_pdc)
{
	struct uet_pdc *pdc;
	*out_pdc = NULL;

	if (pdc_id == 0) {
		UET_PDS_ERR("invalid PDC %u (reserved)", pdc_id);
		return -EINVAL;
	}

	if (pdc_id >= UET_PDC_MAX) {
		UET_PDS_ERR("invalid PDC %u (range)", pdc_id);
		return -EINVAL;
	}

	pdc = &pds_state.pdc[pdc_id];

	if (pdc->state == PDC_STATE_UNALLOC) {
		UET_PDS_ERR("invalid PDC %u (unalloc)", pdc_id);
		return -EINVAL;
	}

	if (pdc->state == PDC_STATE_ERROR) {
		UET_PDS_ERR("invalid PDC %u (error)", pdc_id);
		return -EINVAL;
	}

	if (for_fwd && pdc->is_initiator) {
		UET_PDS_ERR("invalid forward PDC %u (initiator)", pdc_id);
		return -EINVAL;
	}

	*out_pdc = pdc;
	return 0;
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
/*            PDC Initiator and Target Common APIs                          */
/****************************************************************************/

static int uet_pds_send_ctrl_pkt(struct uet_instance *uet,
				 struct uet_pdc *pdc,
				 uet_pds_ctrl_type_t ctrl_type,
				 uint32_t payload,
				 void *private_data)
{
	struct uet_pdc_pkt *pdc_pkt, *orig_pdc_pkt;
	struct uet_pds_ctrl *ctrl_hdr;
	struct uet_entropy *entropy_hdr;
	size_t ip_hdr_size;
	uint32_t cp_psn;
	uint16_t ctrl_flags;
	bool need_track = true;
	int rc, tx_bm_idx;

	/* allocate the packet descriptor */
	pdc_pkt = calloc(1, sizeof(struct uet_pdc_pkt));
	if (pdc_pkt == NULL) {
		UET_PDS_ERR("failed to alloc PDC packet for ctrl packet");
		return -ENOMEM;
	}

	/* allocate the packet buffer */
	pdc_pkt->pkt_buf_len = (uet->nic.max_pkt_size *
				((pdc->sec_enabled) ? 2 : 1));
	pdc_pkt->pkt_buf = calloc(1, pdc_pkt->pkt_buf_len);
	if (pdc_pkt->pkt_buf == NULL) {
		UET_PDS_ERR("failed to alloc packet buffer for ctrl packet");
		free(pdc_pkt);
		return -ENOMEM;
	}

	/* reserve head space for security header if needed */
	pdc_pkt->pkt = (pdc->sec_enabled)
			? (pdc_pkt->pkt_buf + UET_SEC_MAX_HDR_LEN)
			: pdc_pkt->pkt_buf;

	ip_hdr_size = (pdc->is_ipv6) ? sizeof(struct ipv6hdr) :
				       sizeof(struct iphdr);

	/* build Ethernet header */
	uet_build_eth_hdr((struct ethhdr *)pdc_pkt->pkt,
			  pdc->dst_mac_addr, pdc->src_mac_addr,
			  pdc->is_ipv6);

	/* set up pointers to headers */
	entropy_hdr = (struct uet_entropy *)(pdc_pkt->pkt +
					     sizeof(struct ethhdr) +
					     ip_hdr_size);
	ctrl_hdr = (struct uet_pds_ctrl *)(pdc_pkt->pkt +
					   sizeof(struct ethhdr) +
					   ip_hdr_size +
					   sizeof(struct uet_entropy));

	pdc_pkt->pkt_len = (sizeof(struct ethhdr) +
			    ip_hdr_size +
			    sizeof(struct uet_entropy) +
			    sizeof(struct uet_pds_ctrl));

	/* fill in the entropy header */
	entropy_hdr->entropy = htons(UET_DEFAULT_ENTROPY);

	/* fill in the control packet header */
	ctrl_flags = ((UET_PDS_TYPE_CTRL << UET_PDS_TYPE_SHIFT) |
		      (ctrl_type << UET_PDS_CTRL_TYPE_SHIFT));

	switch (ctrl_type) {
	case UET_PDS_CTRL_TYPE_CLOSE:
		ctrl_flags |= UET_PDS_CTRL_FLAGS_AR;
		pdc->close_cmd_psn = pdc->next_psn;
		cp_psn = pdc->close_cmd_psn;
		break;
	case UET_PDS_CTRL_TYPE_CLOSE_REQ:
		ctrl_flags |= UET_PDS_CTRL_FLAGS_AR;
		cp_psn = pdc->next_psn;
		break;
	case UET_PDS_CTRL_TYPE_ACK_REQ:
		if (private_data == NULL) {
			UET_PDS_ERR("private data is NULL for ACK request");
			free(pdc_pkt->pkt_buf);
			free(pdc_pkt);
			return -EINVAL;
		}
		orig_pdc_pkt = (struct uet_pdc_pkt *)private_data;
		cp_psn = orig_pdc_pkt->psn;
		need_track = false;
		break;
	case UET_PDS_CTRL_TYPE_CLEAR:
		cp_psn = 0;
		need_track = false;
		break;
	default:
		UET_PDS_ERR("invalid control type %u", ctrl_type);
		free(pdc_pkt->pkt_buf);
		free(pdc_pkt);
		return -EINVAL;
	}

	ctrl_hdr->prlg.type_ctrl_flags = htons(ctrl_flags);
	ctrl_hdr->rsvd = 0;

	/*
	 * Only tracked control packets (CLOSE/CLOSE_REQ) consume a new PSN from
	 * the tx window and must respect the MPR / peer window. Fire-and-forget
	 * types (ACK_REQ reuses an already-sent PSN, CLEAR uses psn=0) are not
	 * bound by this check.
	 */
	if (need_track && !uet_pds_tx_psn_allowed(pdc, cp_psn)) {
		free(pdc_pkt->pkt_buf);
		free(pdc_pkt);
		return -EAGAIN;
	}

	/* assign PSN for control packet */
	pdc_pkt->psn = cp_psn;
	ctrl_hdr->psn = htonl(pdc_pkt->psn);
	ctrl_hdr->spdcid = htons(pdc->pdc_id);
	ctrl_hdr->dpdcid = htons(pdc->dpdcid);
	ctrl_hdr->payload = htonl(payload);

	/* build the IP header */
	if (pdc->is_ipv6) {
		uet_build_ipv6_hdr(uet,
				   (struct ipv6hdr *)(pdc_pkt->pkt +
						      sizeof(struct ethhdr)),
				   pdc->dst_addr.v6,
				   pdc->src_addr.v6,
				   (pdc_pkt->pkt_len - uet->nic.l2_hdr_size -
				    ip_hdr_size),
				   uet->pds.ack_ip_tos,
				   !pdc->sec_enabled);
	} else {
		uet_build_ipv4_hdr(uet,
				   (struct iphdr *)(pdc_pkt->pkt +
						    sizeof(struct ethhdr)),
				   htonl(pdc->dst_addr.v4),
				   htonl(pdc->src_addr.v4),
				   (pdc_pkt->pkt_len - uet->nic.l2_hdr_size),
				   uet->pds.ack_ip_tos,
				   !pdc->sec_enabled);
	}

	/* save packet params */
	pdc_pkt->msg_id = 0; /* control packets have no msg_id */
	pdc_pkt->tx_retry_cnt = 0;
	pdc_pkt->tx_pkt_handle = NULL; /* no SES handle for control packets */
	pdc_pkt->tx_pkt_acked = false;
	pdc_pkt->flags = 0;

	if (need_track) {
		tx_bm_idx = pdc_pkt->psn - pdc->tx_bm_base_psn;
		if (bm_get(pdc->tx_bm, tx_bm_idx, NULL) ||
		    !bm_set(pdc->tx_bm, tx_bm_idx, pdc_pkt)) {
			UET_PDS_ERR("PDC %u can't track PSN %u at tx bm idx %d",
				    pdc->pdc_id, pdc_pkt->psn, tx_bm_idx);
			free(pdc_pkt->pkt_buf);
			free(pdc_pkt);
			return -EIO;
		}
	}

	/* send the packet */
	rc = uet_pds_sec_tx_pkt(uet, pdc, pdc_pkt, true, false);
	if (rc != 0) {
		UET_PDS_ERR("failed to send %s for PDC %u",
			    PDS_CTRL_TYPE_TO_STR(ctrl_type), pdc->pdc_id);
		if (need_track) {
			bm_unset(pdc->tx_bm, tx_bm_idx);
		}
		free(pdc_pkt->pkt_buf);
		free(pdc_pkt);
		return rc;
	}

	/* the packet was sent successfully */
	UET_PDS_DBG("PDC %u send ctrl packet (psn=%u, type=%s)",
		    pdc->pdc_id, pdc_pkt->psn, PDS_CTRL_TYPE_TO_STR(ctrl_type));

	if (need_track) {
		pdc->next_psn++;
		/* insert the packet to the end of the timeout queue for retries */
		dlist_insert_tail(&pdc_pkt->node, &pdc->tx_pkt_list_head);
	} else {
		free(pdc_pkt->pkt_buf);
		free(pdc_pkt);
	}

	return 0;
}
/****************************************************************************/
/*                            PDC Initiator APIs                            */
/****************************************************************************/

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
	rc = uet_pds_send_ctrl_pkt(uet, pdc, UET_PDS_CTRL_TYPE_CLOSE, 0, NULL);
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

static int uet_pds_target_pdc_close(struct uet_instance *uet,
				    struct uet_pdc *pdc)
{
	int rc;

	if (pdc->close_started)
		return 0;

	if (pdc->state != PDC_STATE_ESTABLISHED) {
		UET_PDS_DBG("PDC %u not established (state %d), skip close",
			    pdc->pdc_id, pdc->state);
		return -EINVAL;
	}

	/* Check if all outstanding packets have been ACK'ed. */
	if (!dlist_empty(&pdc->tx_pkt_list_head)) {
		UET_PDS_DBG("PDC %u has un-ACK'ed packets (cannot close PDC)",
			    pdc->pdc_id);
		return -EAGAIN;
	}

	/* all packets have drained, send the close request */
	rc = uet_pds_send_ctrl_pkt(uet, pdc, UET_PDS_CTRL_TYPE_CLOSE_REQ,
				   0, NULL);
	if (rc != 0) {
		UET_PDS_ERR("PDC %u failed to send close request command",
			    pdc->pdc_id);
		return rc;
	}

	/* set close_started if not already set */
	pdc->close_started = true;

	/* start the Close_REQ_Timer */
	uet_gettime(&pdc->close_req_time);

	return 0;
}

/****************************************************************************/
/*                             SES->PDS APIs                                */
/****************************************************************************/

int uet_pds_initialize(struct uet_instance *uet)
{
	struct uet_pdc *pdc;
	char *pds_ack_type;
	char *method;
	int i;

	/* seed random number generator for PDC close and packet drop */
	srand(time(NULL));

	/* configure the random PDC close threshold */
	if (getenv("UET_PDC_CLOSE_THRESH")) {
		pds_pdc_close_thresh =
			strtoul(getenv("UET_PDC_CLOSE_THRESH"), NULL, 10);
	}

	/* configure the packet drop threshold, this is ignored when the
	 * impairment shim is enabled as that provides its own drop/delay
	 * mechanisms
	 */
	if (!imp_shim_is_enabled() && getenv("UET_PKT_DROP_THRESH")) {
		pds_pkt_drop_thresh =
			strtoul(getenv("UET_PKT_DROP_THRESH"), NULL, 10);
	}

	/* New_PDC_Time DoS timer for PENDING PDCs */
	if (getenv("UET_NEW_PDC_TIME")) {
		pds_new_pdc_time_ms =
			strtoul(getenv("UET_NEW_PDC_TIME"), NULL, 10);
	}

	/* secure PDC establishment method */
	method = getenv("UET_PDS_PSN_METHOD");
	if (method) {
		if (strcmp(method, "1rtt") == 0) {
			pds_psn_method = UET_PDS_PSN_METHOD_1RTT;
		} else if (strcmp(method, "0rtt") == 0) {
			pds_psn_method = UET_PDS_PSN_METHOD_0RTT;
		} else {
			UET_PDS_WARN("unknown UET_PDS_PSN_METHOD=%s", method);
			return -EINVAL;
		}
	}

	uet->pds.tx_timeout     = UET_DEFAULT_TX_TIMEOUT;
	uet->pds.max_tx_retries = UET_DEFAULT_MAX_TX_RETRIES;
	uet->pds.msl            = UET_DEFAULT_MSL;

	/* configure the tx timeout (in millisecs) */
	if (getenv("UET_PDS_TX_TIMEOUT")) {
		uet->pds.tx_timeout =
			strtoul(getenv("UET_PDS_TX_TIMEOUT"), NULL, 10);
	}

	/* configure the max tx retries */
	if (getenv("UET_PDS_MAX_TX_RETRIES")) {
		uet->pds.max_tx_retries =
			strtoul(getenv("UET_PDS_MAX_TX_RETRIES"), NULL, 10);
	}

	uet->pds.ack_ip_tos     = uet_dscp_to_tos(UET_IP_DEFAULT_ACK_DSCP);
	uet->pds.max_ack_data	= UET_DEFAULT_PDS_MAX_ACK_DATA;
	uet->pds.per_pkt_ack_enabled = UET_DEFAULT_PDS_PER_PKT_ACK_ENABLED;
	uet->pds.ack_gen_min_pkt_add = UET_DEFAULT_PDS_ACK_GEN_MIN_PKT_ADD;
	uet->pds.ack_gen_trigger = UET_DEFAULT_PDS_ACK_GEN_PKT_TRIGGER;

	/* configure ack mode */
	if (getenv("UET_PDS_PER_PKT_ACK_ENB")) {
		uet->pds.per_pkt_ack_enabled =
			strtoul(getenv("UET_PDS_PER_PKT_ACK_ENB"), NULL, 10);
	}

	/* configure ack type */
	pds_ack_type = getenv("UET_PDS_ACK_TYPE");
	if (pds_ack_type == NULL || strcmp(pds_ack_type, "ack") == 0) {
		uet->pds.ack_type = UET_PDS_TYPE_ACK;
	} else if (strcmp(pds_ack_type, "ack_cc") == 0) {
		uet->pds.ack_type = UET_PDS_TYPE_ACK_CC;
	} else if (strcmp(pds_ack_type, "ack_ccx") == 0) {
		uet->pds.ack_type = UET_PDS_TYPE_ACK_CCX;
	} else {
		UET_PDS_ERR("Invalid env variable UET_PDS_ACK_TYPE=%s",
			    pds_ack_type);
		return -EINVAL;
	}

	memset(&pds_state, 0, sizeof(struct uet_pds_state));

	/* initialize the PDCs */

	dlist_init(&pds_state.pdc_alloc_head);
	dlist_init(&pds_state.pdc_free_head);
	pds_state.pdc_ini_ht = NULL;
	pds_state.pdc_tgt_ht = NULL;
	pds_state.pdc_msgid_ht = NULL;

	/*
	 * Reserve PDCID=0 according to UET spec 3.5.8.2.
	 * Only PDCID [1, UET_PDC_MAX-1] are initialized and inserted into the
	 * allocatable pools.
	 */
	for (i = 1; i < UET_PDC_MAX; i++) {
		pdc = &pds_state.pdc[i];
		pdc->state = PDC_STATE_UNALLOC;
		pdc->pdc_id = i;

		pdc->tx_bm = bm_create(UET_DEFAULT_MP_RANGE);
		if (!pdc->tx_bm) {
			UET_PDS_ERR("failed to create Tx bitmap");
			uet_pdsm_free_pdc(pdc);
			return -ENOMEM; /* FIXME unwind and free PDCs */
		}

		pdc->rx_bm = bm_create(UET_DEFAULT_MP_RANGE);
		if (!pdc->rx_bm) {
			UET_PDS_ERR("failed to create Rx bitmap");
			bm_destroy(pdc->tx_bm);
			return -ENOMEM; /* FIXME unwind and free PDCs */
		}

		dlist_insert_tail(&pdc->node, &pds_state.pdc_free_head);
	}

	/* initialize the connectionless RUDI engine */
	uet_pds_rudi_init();

	/* good to go... */
	pds_state.ready = true;

	return 0;
}

void uet_pds_finalize(struct uet_instance *uet)
{
	struct uet_pdc *pdc;
	struct uet_pdc_pkt *pdc_pkt;

	PDS_GO();

	/* PDS health stats: DoS-reaped PENDING PDCs + PSN-range-driven closes */
	UET_PDS_INFO("%-30s : %u", "new_pdc_timeout_cnt",
		     pds_state.new_pdc_timeout_cnt);
	UET_PDS_INFO("%-30s : %u", "psn_range_close_cnt",
		     pds_state.psn_range_close_cnt);
	UET_PDS_INFO("%-30s : %u", "pdc_close_in_err_cnt",
		     pds_state.pdc_close_in_err_cnt);

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

	/* free any outstanding RUDI requests */
	uet_pds_rudi_finalize();

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

static int uet_pds_tx_nack(struct uet_instance *uet,
			   struct uet_pdc *pdc,
			   struct uet_parsed_pkt *orig_pp,
			   uet_pds_nack_code_t nack_code,
			   uint32_t payload)
{
	struct uet_pdc tx_pdc;
	struct uet_pdc_pkt *pdc_pkt;
	struct uet_pds_nack *nack_hdr;
	struct uet_entropy *entropy_hdr;
	size_t ip_hdr_size;
	uint16_t nack_flags;
	int rc;

	if (pdc == NULL) {
		memset(&tx_pdc, 0, sizeof(tx_pdc));
		tx_pdc.pdc_id = 0;
		tx_pdc.is_ipv6 = orig_pp->is_ipv6;
		tx_pdc.sec_enabled = false;
		pdc = &tx_pdc;
	}

	/* allocate the packet descriptor */
	pdc_pkt = calloc(1, sizeof(struct uet_pdc_pkt));
	if (pdc_pkt == NULL) {
		UET_PDS_ERR("failed to alloc PDC packet for NACK pkt");
		return -ENOMEM;
	}

	pdc_pkt->pkt_buf_len = (uet->nic.max_pkt_size *
				((pdc->sec_enabled) ? 2 : 1));
	pdc_pkt->pkt_buf = calloc(1, pdc_pkt->pkt_buf_len);
	if (pdc_pkt->pkt_buf == NULL) {
		UET_PDS_ERR("failed to alloc packet buffer for NACK");
		free(pdc_pkt);
		return -ENOMEM;
	}
	pdc_pkt->pkt = (pdc->sec_enabled)
			? (pdc_pkt->pkt_buf + UET_SEC_MAX_HDR_LEN)
			: pdc_pkt->pkt_buf;

	ip_hdr_size = (pdc->is_ipv6) ? sizeof(struct ipv6hdr) :
				       sizeof(struct iphdr);

	uet_build_eth_hdr((struct ethhdr *)pdc_pkt->pkt,
			  ((struct ethhdr *)orig_pp->eth)->h_source,
			  ((struct ethhdr *)orig_pp->eth)->h_dest,
			  orig_pp->is_ipv6);

	entropy_hdr = (struct uet_entropy *)(pdc_pkt->pkt +
					     sizeof(struct ethhdr) +
					     ip_hdr_size);
	nack_hdr = (struct uet_pds_nack *)(pdc_pkt->pkt +
					   sizeof(struct ethhdr) +
					   ip_hdr_size +
					   sizeof(struct uet_entropy));

	pdc_pkt->pkt_len = (sizeof(struct ethhdr) +
			    ip_hdr_size +
			    sizeof(struct uet_entropy) +
			    sizeof(struct uet_pds_nack));

	entropy_hdr->entropy = htons(orig_pp->entropy_val);

	nack_flags = UET_PDS_NACK_FLAGS_NONE;
	if (orig_pp->pds_flags & UET_PDS_REQ_FLAGS_RETX)
		nack_flags |= UET_PDS_NACK_FLAGS_RETX;

	nack_hdr->prlg.type_next_flags =
		htons((UET_PDS_TYPE_NACK << UET_PDS_TYPE_SHIFT) |
		      (UET_HDR_NONE << UET_PDS_NEXT_HDR_SHIFT) |
		      (nack_flags << UET_PDS_FLAGS_SHIFT));
	nack_hdr->nack_code = nack_code;
	nack_hdr->vendor_code = 0;
	nack_hdr->nack_psn = htonl(orig_pp->pds_psn);
	nack_hdr->spdcid = htons(pdc->pdc_id);
	nack_hdr->dpdcid = htons(orig_pp->pds_spdcid);
	nack_hdr->payload = htonl(payload);

	UET_PDS_WARN("PDC %u TX NACK nack_code=0x%x psn=%u dpdcid=%u",
		     pdc->pdc_id, nack_code, orig_pp->pds_psn,
		     orig_pp->pds_spdcid);

	if (pdc->is_ipv6) {
		struct ipv6hdr *rx_ipv6 = (struct ipv6hdr *)orig_pp->ip;
		uet_build_ipv6_hdr(uet,
				   (struct ipv6hdr *)(pdc_pkt->pkt +
						      sizeof(struct ethhdr)),
				   (const uint8_t *)&rx_ipv6->saddr,
				   (const uint8_t *)&rx_ipv6->daddr,
				   (pdc_pkt->pkt_len - uet->nic.l2_hdr_size -
				    ip_hdr_size),
				   uet->pds.ack_ip_tos,
				   !pdc->sec_enabled);
	} else {
		struct iphdr *rx_ipv4 = (struct iphdr *)orig_pp->ip;
		uet_build_ipv4_hdr(uet,
				   (struct iphdr *)(pdc_pkt->pkt +
						    sizeof(struct ethhdr)),
				   ((struct iphdr *)orig_pp->ip)->saddr,
				   ((struct iphdr *)orig_pp->ip)->daddr,
				   (pdc_pkt->pkt_len - uet->nic.l2_hdr_size),
				   uet->pds.ack_ip_tos,
				   !pdc->sec_enabled);
	}

	rc = uet_pds_sec_tx_pkt(uet, pdc, pdc_pkt, true, false);
	if (rc != 0) {
		UET_PDS_ERR("failed to send NACK packet for PDC %u",
			    pdc->pdc_id);
		free(pdc_pkt->pkt_buf);
		free(pdc_pkt);
		return rc;
	}

	uet_pds_pkt_dbg(uet, &pdc_pkt->pkt_pp, true, "TX NACK PACKET");

	free(pdc_pkt->pkt_buf);
	free(pdc_pkt);
	return rc;
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
	size_t ip_hdr_size;
	void *ses_hdr, *payload;
	uint16_t pds_flags;
	int rc, hdr_len, tx_bm_idx;
	bool map_msg_id = false;
	bool mapped_msg_id = false;

	PDS_GO();

	uet = uet_ep->uet_domain->uet;
	av_entry = (struct uet_av_entry *)dst_addr_handle;

	/* RUDI is connectionless: hand off to the RUDI engine before any PDC
	 * assignment. None of the PDC/PSN/ACK machinery below applies.
	 */
	if (mode == UET_PDS_MODE_RUDI)
		return uet_pds_rudi_tx_pkt(tx_pkt_handle, pkt_cnt, uet_ep,
					   dst_addr_handle, mode, flags,
					   pds_info, msg_id, next_hdr, ses,
					   ses_len, pkt, pkt_len, dma_rdy);

	/* UUD is connectionless: hand off to the UUD engine before any PDC
	 * assignment. None of the PDC/PSN/ACK machinery below applies.
	 */
	if (mode == UET_PDS_MODE_UUD)
		return uet_pds_uud_tx_pkt(tx_pkt_handle, pkt_cnt, uet_ep,
					  dst_addr_handle, mode, flags,
					  pds_info, msg_id, next_hdr, ses,
					  ses_len, pkt, pkt_len, dma_rdy);

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
		rc = uet_pdsm_get_pdc(pds_info->pdcid, true, &pdc);
		if (rc != 0) {
			return rc;
		}
	} else if (flags & UET_PDS_FLAG_SOM) {
		UET_PDS_DBG("SES Tx %p msg_id %u [SOM]%s",
			    tx_pkt_handle, msg_id,
			    ((flags & UET_PDS_FLAG_EOM) ? " [EOM]" : ""));
		pdc = uet_pdsm_assign_ini_pdc(uet_ep, av_entry, mode);
		if (!pdc) {
			UET_PDS_DBG("failed to get PDC for SOM %p "
				    "msg_id %u (EAGAIN)",
				    tx_pkt_handle, msg_id);
			return -EAGAIN;
		}

		/* verify PDC has no active message */
		if (pdc->active_msg_id_valid) {
			UET_PDS_DBG("PDC %u active msg_id %u blocks SOM msg_id %u (EAGAIN)",
				    pdc->pdc_id, pdc->active_msg_id, msg_id);
			return -EAGAIN;
		}

		/* Commit this mapping only when the first packet can be sent. */
		map_msg_id = true;
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

	if (memcmp(&pdc->dst_addr, &av_entry->addr->fa,
		   sizeof(struct uet_fa)) != 0) {
		UET_PDS_ERR("PDC %u dst_addr does not match AV for Tx pkt %p",
			    pdc->pdc_id, tx_pkt_handle);
		return -EINVAL;
	}

	/*
	 * tx_bm owns all state required to acknowledge or retransmit a PSN.
	 * Returning -EAGAIN leaves the SES descriptor at its current payload
	 * offset; ACK progress advances tx_bm_base_psn before SES retries it.
	 */
	if (!uet_pds_tx_psn_allowed(pdc, pdc->next_psn)) {
		UET_PDS_DBG("PDC %u Tx window full: base=%u next=%u local=%u peer=%u",
			    pdc->pdc_id, pdc->tx_bm_base_psn, pdc->next_psn,
			    UET_DEFAULT_MP_RANGE, pdc->peer_mp_range);
		return -EAGAIN;
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

	ip_hdr_size = (pdc->is_ipv6) ? sizeof(struct ipv6hdr) :
				       sizeof(struct iphdr);

	uet_build_eth_hdr((struct ethhdr *)pdc_pkt->pkt,
			  pdc->dst_mac_addr, pdc->src_mac_addr,
			  pdc->is_ipv6);

	entropy_hdr = (struct uet_entropy *)(pdc_pkt->pkt +
					     sizeof(struct ethhdr) +
					     ip_hdr_size);
	pds_hdr = (struct uet_pds_req *)(pdc_pkt->pkt +
					 sizeof(struct ethhdr) +
					 ip_hdr_size +
					 sizeof(struct uet_entropy));
	ses_hdr = (pds_hdr + 1);
	payload = ((uint8_t *)ses_hdr + ses_len);

	hdr_len = (sizeof(struct ethhdr) +
		   ip_hdr_size +
		   sizeof(struct uet_entropy) +
		   sizeof(struct uet_pds_req) +
		   ses_len);

	pdc_pkt->pkt_len = (hdr_len + pkt_len);

	/* fill in the entropy header */
	/* TODO: UDP support */
	entropy_hdr->entropy = htons(uet_ep->entropy);

	/* fill in the PDS header */

	pds_flags = ((pds_pkt_type << UET_PDS_TYPE_SHIFT) |
		     (next_hdr << UET_PDS_NEXT_HDR_SHIFT));
	if (pdc->state == PDC_STATE_SYN) {
		pds_flags |= (UET_PDS_REQ_FLAGS_SYN <<
			      UET_PDS_FLAGS_SHIFT);
	}

	if (uet->pds.per_pkt_ack_enabled || (flags & UET_PDS_FLAG_EOM)) {
		pds_flags |= (UET_PDS_REQ_FLAGS_AR <<
			      UET_PDS_FLAGS_SHIFT);
	}

	pds_hdr->prlg.type_next_flags = htons(pds_flags);

	pdc_pkt->psn = pdc->next_psn;
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
	} else {
		pds_hdr->dpdcid = htons(pdc->dpdcid);
	}

	/* copy in the SES header and payload */
	/* TODO: support for gather iov send */

	memcpy(ses_hdr, ses, ses_len);
	memcpy(payload, pkt, pkt_len);

	/* build the IP header */
	if (pdc->is_ipv6) {
		uet_build_ipv6_hdr(uet,
				   (struct ipv6hdr *)(pdc_pkt->pkt +
						      sizeof(struct ethhdr)),
				   pdc->dst_addr.v6,
				   pdc->src_addr.v6,
				   (pdc_pkt->pkt_len - uet->nic.l2_hdr_size -
				    ip_hdr_size),
				   uet_ep->msg_ip_tos,
				   !pdc->sec_enabled);
	} else {
		uet_build_ipv4_hdr(uet,
				   (struct iphdr *)(pdc_pkt->pkt +
						    sizeof(struct ethhdr)),
				   htonl(pdc->dst_addr.v4),
				   htonl(pdc->src_addr.v4),
				   (pdc_pkt->pkt_len - uet->nic.l2_hdr_size),
				   uet_ep->msg_ip_tos,
				   !pdc->sec_enabled);
	}

	/* save some params specific for this packet */
	pdc_pkt->msg_id        = msg_id;
	pdc_pkt->tx_retry_cnt  = 0;
	pdc_pkt->tx_pkt_handle = tx_pkt_handle;
	pdc_pkt->tx_pkt_acked  = false;
	pdc_pkt->flags         = flags;
	tx_bm_idx = pdc_pkt->psn - pdc->tx_bm_base_psn;

	if (bm_get(pdc->tx_bm, tx_bm_idx, NULL) ||
	    !bm_set(pdc->tx_bm, tx_bm_idx, pdc_pkt)) {
		UET_PDS_ERR("PDC %u cannot track PSN %u at tx_bm index %d",
			    pdc->pdc_id, pdc_pkt->psn, tx_bm_idx);
		free(pdc_pkt->pkt_buf);
		free(pdc_pkt);
		return -EIO;
	}

	if (map_msg_id) {
		rc = uet_pdsm_map_msgid_pdc(msg_id, pdc);
		if (rc != 0) {
			bm_unset(pdc->tx_bm, tx_bm_idx);
			free(pdc_pkt->pkt_buf);
			free(pdc_pkt);
			return rc;
		}

		pdc->active_msg_id = msg_id;
		pdc->active_msg_id_valid = true;
		mapped_msg_id = true;
	}

	/* send the packet */
	rc = uet_pds_sec_tx_pkt(uet, pdc, pdc_pkt, true, false);
	if (rc != 0) {
		bm_unset(pdc->tx_bm, tx_bm_idx);
		if (mapped_msg_id) {
			pdc->active_msg_id = 0;
			pdc->active_msg_id_valid = false;
			if (uet_pdsm_unmap_msgid_pdc(msg_id) != 0)
				UET_PDS_ERR("PDC %u failed to roll back msg_id %u",
					    pdc->pdc_id, msg_id);
		}
		free(pdc_pkt->pkt_buf);
		free(pdc_pkt);
		return rc;
	}

	pdc->next_psn++;
	if (pdc->state == PDC_STATE_SYN)
		pdc->syn_offset++;

	/* the packet was sent successfully */
	uet_pds_pkt_dbg(uet, &pdc_pkt->pkt_pp, true, "TX PACKET");

	/* set this packet in the tx_bm */
	UET_PDS_DBG("PDC %u tx_bm: base=%u clear_psn=%u psn=%u SET bit=%u",
		    pdc->pdc_id, pdc->tx_bm_base_psn,
		    pdc_pkt->pkt_pp.pds_clear_psn, pdc_pkt->psn,
		    (pdc_pkt->psn - pdc->tx_bm_base_psn));

	if (UET_LOG_LVL >= UET_LOG_DBG) {
		UET_PDS_DBG("PDC %u tx_bm (base %u):",
			    pdc->pdc_id, pdc->tx_bm_base_psn);
		bm_print_bits(pdc->tx_bm, uet_pdc_tx_bit_char);
	}

	/* insert the packet to the end of the timeout queue */
	dlist_insert_tail(&pdc_pkt->node, &pdc->tx_pkt_list_head);

	/* Commit end-of-message state only after the EOM packet was sent. */
	if (!pds_info && (flags & UET_PDS_FLAG_EOM)) {
		if (flags & UET_PDS_FLAG_MAINTAIN_PDC) {
			UET_PDS_DBG("PDC %u flagged with MAINTAIN_PDC on EOM",
				    pdc->pdc_id);
		} else {
			pdc->active_msg_id = 0;
			pdc->active_msg_id_valid = false;

			rc = uet_pdsm_unmap_msgid_pdc(msg_id);
			if (rc != 0)
				UET_PDS_ERR("PDC %u failed to unmap completed msg_id %u",
					    pdc->pdc_id, msg_id);

			if (pds_pdc_close_thresh && pdc->is_initiator &&
			    !pdc->close_requested &&
			    uet_pds_random_check(pds_pdc_close_thresh)) {
				UET_PDS_ERR("PDC %u random marked for close!",
					    pdc->pdc_id);
				pdc->close_requested = true;
			}

			if (pdc->sec_enabled && pdc->is_initiator &&
			    !pdc->close_requested &&
			    ((uint32_t)(pdc->next_psn - pdc->start_psn) >=
			     UET_PSN_RANGE_LIMIT)) {
				UET_PDS_ERR("PDC %u PSN range exhausted; marked for close!",
					    pdc->pdc_id);
				pdc->close_requested = true;
				pds_state.psn_range_close_cnt++;
			}
		}
	}

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
	int rc;

	if (pdc_pkt->dst_recvd &&
	    pdc_pkt->tx_retry_cnt < uet->pds.max_tx_retries) {
		rc = uet_pds_send_ctrl_pkt(uet, pdc, UET_PDS_CTRL_TYPE_ACK_REQ,
					   pdc_pkt->msg_id, (void *)pdc_pkt);
		if (rc != 0)
			return rc;

		pdc_pkt->tx_retry_cnt++;
		uet_gettime(&pdc_pkt->tx_time);
		return 0;
	}

	/* A reduced peer MPR also gates retransmissions. */
	if (!uet_pds_tx_psn_allowed(pdc, pdc_pkt->psn))
		return -EAGAIN;

	/* set the retransmit flag in the PDS header */
	pds_hdr = (struct uet_pds_req *)pdc_pkt->pkt_pp.pds;
	pds_hdr->prlg.type_next_flags |=
		htons((UET_PDS_REQ_FLAGS_RETX << UET_PDS_FLAGS_SHIFT) |
		      (UET_PDS_REQ_FLAGS_AR << UET_PDS_FLAGS_SHIFT));
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

/* returns 0, -EIO, or -EAGAIN */
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

	if (!pdc_pkt->dst_recvd &&
	    !uet_pds_tx_psn_allowed(pdc, pdc_pkt->psn))
		return 0; /* wait for CACK to advance the peer window */

	if (pdc_pkt->tx_retry_cnt >= uet->pds.max_tx_retries) {
		UET_PDS_ERR("PDC %u PSN %u retry exceeded",
			    pdc->pdc_id, pdc_pkt->psn);
		return -EIO; /* assume this PDC is dead */
	}

	UET_PDS_WARN("PDC %u PSN %u retransmit", pdc->pdc_id, pdc_pkt->psn);

	rc = uet_pds_rtx_pkt(uet, pdc, pdc_pkt);
	if (rc == -EAGAIN)
		return 0; /* wait for CACK to advance the peer window */

	if (rc != 0) {
		UET_PDS_ERR("PDC %u PSN %u retransmit failed",
			    pdc->pdc_id, pdc_pkt->psn);
		return -EIO; /* assume this PDC is dead */
	}

	return -EAGAIN; /* pkt retransmitted, could be more */
}

int uet_pds_progress_tx_pkt(struct uet_instance *uet,
			    uet_pkt_handle_t *err_pkt_handle,
			    struct uet_pdc *pdc,
			    struct uet_pdc_pkt *pdc_pkt)
{
	int rc;

	rc = uet_pds_check_rtx_pkt(uet, pdc, pdc_pkt);
	if (rc == 0)
		return 0; /* no retransmit, done with this PDC */

	if (rc == -EIO) {
		/*
		 * Max retries exceeded - transition this PDC to the error
		 * state and notify the SES layer.
		 */
		UET_PDS_ERR("PDC %u transitioning to ERROR state "
			    "(max retries exceeded)",
			    pdc->pdc_id);
		uet_pds_close_pdc_in_error(uet, pdc);

		/*
		 * Will return immediately to give the SES layer a chance to
		 * handle this error before checking other PDCs.
		 */
		return -EPROTO;
	}

	/* (rc == -EAGAIN)
	 * This packet was retransmitted so it's moved to the end of
	 * the pending list. Continue to the next packet.
	 */
	dlist_remove(&pdc_pkt->node);
	dlist_insert_tail(&pdc_pkt->node,
			  &pdc->tx_pkt_list_head);
	return -EAGAIN;
}

int uet_pds_progress_tx(struct uet_ep *uet_ep,
			uet_pkt_handle_t *err_pkt_handle)
{
	struct uet_instance *uet;
	struct uet_pdc *pdc;
	struct dlist_entry *tmp1, *tmp2;
	struct uet_pdc_pkt *pdc_pkt;
	time_t now;
	int rc;

	PDS_GO();

	uet = uet_ep->uet_domain->uet;

	/* drive RUDI initiator reliability (per-packet RTO) */
	rc = uet_pds_rudi_progress_tx(uet_ep, err_pkt_handle);
	if (rc != 0)
		return rc;

	dlist_foreach_container_safe(&pds_state.pdc_alloc_head,
				     struct uet_pdc, pdc, node, tmp1) {
		/* New_PDC_Time DoS timer that reaps PDCs in the PENDING state
		 * that have waited past New_PDC_Time for the initiator to
		 * re-drive with the assigned Start_PSN. A PENDING PDC has no
		 * queued Tx packets so it is handled here.
		 */
		if (pdc->state == PDC_STATE_PENDING) {
			uet_gettime(&now);

			if ((now - pdc->pending_time) > pds_new_pdc_time_ms) {
				UET_PDS_WARN("PENDING PDC %u reaped",
					     pdc->pdc_id);
				uet_pdsm_free_pdc(pdc);
				pds_state.new_pdc_timeout_cnt++;
			}

			continue; /* PDC is still PENDING */
		}

		/*
		 * If the initiator does not respond within Close_REQ_Time,
		 * target close the PDC in error.
		 */
		if (!pdc->is_initiator && pdc->close_started &&
		    (pdc->close_req_time != 0)) {
			uet_gettime(&now);

			if ((now - pdc->close_req_time) >
			    pds_close_req_time_ms) {
				UET_PDS_WARN("PDC %u Close_REQ_Timer expired, "
					     "closing in error", pdc->pdc_id);
				uet_pds_close_pdc_in_error(uet, pdc);
				continue;
			}
		}

		dlist_foreach_container_safe(&pdc->tx_pkt_list_head,
					     struct uet_pdc_pkt, pdc_pkt,
					     node, tmp2) {
			rc = uet_pds_progress_tx_pkt(uet, err_pkt_handle,
						     pdc, pdc_pkt);

			/* no retransmit, done with this PDC */
			if (rc == 0)
				break;

			/* max retransmits were exceeded for the packet */
			if (rc == -EPROTO)
				return -EPROTO;

			/* packet was retransmitted, check the next packet */
			if (rc == -EAGAIN)
				continue;
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

	/* RUDI and UUD are connectionless so there is no PDC/msgid state to
	 * complete. SES calls this for every READ_REQ completion (RUDI) and
	 * has no PDC for UUD datagrams.
	 */
	if ((mode == UET_PDS_MODE_RUDI) || (mode == UET_PDS_MODE_UUD))
		return 0;

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

static void uet_pds_update_sack_base(struct uet_pdc *pdc,
				     struct uet_pdc_pkt *pdc_pkt,
				     bool is_sack_trigger)
{
	if (is_sack_trigger) {
		if (UET_PDS_PSN_AFTER(pdc->max_rcvd_psn,
				      pdc->sack_base_track + 63)) {
			pdc->sack_base_track += 64;
		}
		return;
	}

	if (UET_PDS_PSN_AFTER(pdc->cack_psn, pdc->sack_base_track))
		pdc->sack_base_track = pdc->cack_psn;
	else if (UET_PDS_PSN_AFTER(pdc_pkt->pkt_pp.pds_psn, pdc->cack_psn) &&
		 UET_PDS_PSN_AFTER(pdc->sack_base_track,
				   pdc_pkt->pkt_pp.pds_psn)) {
		pdc->sack_base_track = pdc_pkt->pkt_pp.pds_psn;
	}
}

static void uet_pds_build_ack_cc_ext(struct uet_instance *uet,
				     struct uet_pdc *pdc,
				     struct uet_pdc_pkt *pdc_pkt,
				     struct uet_pds_ack *ack_pds,
				     uet_pds_pkt_type_t ack_type)
{
	struct uet_pds_ack_cc *ack_cc;
	struct uet_pds_ack_ccx *ack_ccx;
	uint32_t sack_base_psn;
	int bm_start_idx;

	/*
	 * Selection of sack_base_psn:
	 *   - Per-packet ACKs, the SACK bitmap base PSN is the PSN that
	 *     triggered this ACK
	 *   - Coalesced ACKs, the SACK bitmap base PSN is the sack_base_track
	 */
	if (uet->pds.per_pkt_ack_enabled)
		sack_base_psn = pdc_pkt->pkt_pp.pds_psn;
	else {
		sack_base_psn = pdc->sack_base_track;
		uet_pds_update_sack_base(pdc, pdc_pkt, true);
	}

	bm_start_idx = UET_PDS_PSN_OFFSET(sack_base_psn, pdc->rx_bm_base_psn);
	ack_cc = (struct uet_pds_ack_cc *)ack_pds;
	ack_cc->cc_type_flags = 0;
	ack_cc->mpr = UET_DEFAULT_MPR;
	ack_cc->sack_psn_offset =
		htons(psn_2c_offset(pdc->cack_psn, sack_base_psn));
	ack_cc->sack_bitmap = htonll(bm_extract64(pdc->rx_bm, bm_start_idx));
	ack_cc->ack_cc_state = 0;

	if (ack_type == UET_PDS_TYPE_ACK_CCX) {
		ack_ccx = (struct uet_pds_ack_ccx *)ack_pds;
		ack_ccx->ack_ccx_state = 0;
	}
}

static void uet_pds_build_ack_pkt(struct uet_instance *uet,
				  struct uet_pdc *pdc,
				  struct uet_pdc_pkt *pdc_pkt,
				  uet_pds_next_hdr_t next_hdr,
				  void *ses_hdr,
				  size_t ses_hdr_len,
				  size_t pds_ack_hdr_len)
{
	uint8_t flags;
	struct uet_entropy *entropy_hdr;
	struct uet_pds_ack *ack_pds;
	uint8_t *ack_ses;
	size_t ip_hdr_size = (pdc->is_ipv6) ? sizeof(struct ipv6hdr) :
					      sizeof(struct iphdr);

	entropy_hdr = (struct uet_entropy *)(pdc_pkt->ack +
					     sizeof(struct ethhdr) +
					     ip_hdr_size);
	ack_pds = (struct uet_pds_ack *)(pdc_pkt->ack +
					 sizeof(struct ethhdr) +
					 ip_hdr_size +
					 sizeof(struct uet_entropy));

	uet_build_eth_hdr((struct ethhdr *)pdc_pkt->ack,
			  ((struct ethhdr *)pdc_pkt->pkt_pp.eth)->h_source,
			  ((struct ethhdr *)pdc_pkt->pkt_pp.eth)->h_dest,
			  pdc->is_ipv6);

	if (pdc->is_ipv6) {
		struct ipv6hdr *rx_ipv6 =
			(struct ipv6hdr *)pdc_pkt->pkt_pp.ip;
		uet_build_ipv6_hdr(uet,
				   (struct ipv6hdr *)(pdc_pkt->ack +
						      sizeof(struct ethhdr)),
				   (const uint8_t *)&rx_ipv6->saddr,
				   (const uint8_t *)&rx_ipv6->daddr,
				   (pdc_pkt->ack_len - uet->nic.l2_hdr_size -
				    ip_hdr_size),
				   uet->pds.ack_ip_tos,
				   !pdc->sec_enabled);
	} else {
		uet_build_ipv4_hdr(uet,
				   (struct iphdr *)(pdc_pkt->ack +
						    sizeof(struct ethhdr)),
				   ((struct iphdr *)pdc_pkt->pkt_pp.ip)->saddr,
				   ((struct iphdr *)pdc_pkt->pkt_pp.ip)->daddr,
				   (pdc_pkt->ack_len - uet->nic.l2_hdr_size),
				   uet->pds.ack_ip_tos,
				   !pdc->sec_enabled);
	}

	/* TODO: UDP support */
	entropy_hdr->entropy = htons(pdc_pkt->pkt_pp.entropy_val);

	flags = (pdc_pkt->needs_clear) ? UET_PDS_ACK_FLAGS_REQ_CLR
				       : UET_PDS_ACK_FLAGS_NONE;
	ack_pds->prlg.type_next_flags =
		htons((uet->pds.ack_type << UET_PDS_TYPE_SHIFT) |
		      (next_hdr << UET_PDS_NEXT_HDR_SHIFT) |
		      (flags << UET_PDS_FLAGS_SHIFT));

	/* Get the cumulative ack value */
	ack_pds->ack_psn_offset =
		htons(psn_2c_offset(pdc->cack_psn,
				    pdc_pkt->pkt_pp.pds_psn));
	ack_pds->cack_psn = htonl(pdc->cack_psn);

	ack_pds->spdcid = htons(pdc->pdc_id);
	ack_pds->dpdcid = htons(pdc->dpdcid);

	if ((uet->pds.ack_type == UET_PDS_TYPE_ACK_CC) ||
	    (uet->pds.ack_type == UET_PDS_TYPE_ACK_CCX)) {
		uet_pds_build_ack_cc_ext(uet, pdc, pdc_pkt, ack_pds,
					 uet->pds.ack_type);
	}

	/* only copy SES header if needed */
	if (ses_hdr && ses_hdr_len > 0) {
		ack_ses = (uint8_t *)(ack_pds) + pds_ack_hdr_len;
		memcpy(ack_ses, ses_hdr, ses_hdr_len);
	}
}

static void uet_pds_update_cack(struct uet_pdc *pdc,
				uint32_t pds_clear_psn)
{
	struct uet_pdc_pkt *temp;
	int max_rx_bm_idx;
	int i = 0;

	UET_PDS_UPDATE_PSN(pdc->max_clear_psn, pds_clear_psn);

	max_rx_bm_idx = bm_max(pdc->rx_bm);
	for (i = 0; i <= max_rx_bm_idx; i++) {
		if (!bm_get(pdc->rx_bm, i, (void **)&temp))
			break;

		if (temp->needs_clear &&
		    UET_PDS_PSN_AFTER(temp->psn, pdc->max_clear_psn))
			break;
	}

	pdc->cack_psn = pdc->rx_bm_base_psn + i - 1;
}

static size_t uet_pds_ack_hdr_len(struct uet_instance *uet)
{
	switch (uet->pds.ack_type) {
	case UET_PDS_TYPE_ACK_CC:
		return sizeof(struct uet_pds_ack_cc);
	case UET_PDS_TYPE_ACK_CCX:
		return sizeof(struct uet_pds_ack_ccx);
	case UET_PDS_TYPE_ACK:
	default:
		return sizeof(struct uet_pds_ack);
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
	uint16_t ack_data_len;
	size_t pds_ack_hdr_len;
	int rc;
	size_t ip_hdr_size = (pdc->is_ipv6) ? sizeof(struct ipv6hdr) :
					      sizeof(struct iphdr);

	pds_ack_hdr_len = uet_pds_ack_hdr_len(uet);

	if (next_hdr == UET_HDR_NONE) {
		pdc_pkt->ack_len = (sizeof(struct ethhdr) +
				    ip_hdr_size +
				    sizeof(struct uet_entropy) +
				    pds_ack_hdr_len);
	} else if (next_hdr == UET_HDR_RSP) {
		pdc_pkt->ack_len = (sizeof(struct ethhdr) +
				    ip_hdr_size +
				    sizeof(struct uet_entropy) +
				    pds_ack_hdr_len +
				    sizeof(struct uet_ses_rsp));
	} else { /* response w/ data */
		ack_data_len = (ses_hdr_len - sizeof(struct uet_ses_rsp_d));
		pdc_pkt->ack_len = (sizeof(struct ethhdr) +
				    ip_hdr_size +
				    sizeof(struct uet_entropy) +
				    pds_ack_hdr_len +
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

	/* build the ACK packet */
	uet_pds_build_ack_pkt(uet, pdc, pdc_pkt, next_hdr, ses_hdr,
			      ses_hdr_len, pds_ack_hdr_len);

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

/* Send a closing ACK that carries the SDI's Expected_PSN. Uses the
 * uet_pds_ack_epsn header with the UET_PDS_ACK_FLAGS_EPSN flag set, so the
 * initiator can process the Expected_PSN before it frees the PDC.
 */
static int uet_pds_tx_close_ack_epsn(struct uet_instance *uet,
				     struct uet_pdc *pdc,
				     struct uet_pdc_pkt *pdc_pkt,
				     uint32_t payload)
{
	struct uet_entropy *entropy_hdr;
	struct uet_pds_ack_epsn *ack_epsn;
	struct uet_pds_ack *ack;
	size_t ip_hdr_size = (pdc->is_ipv6) ? sizeof(struct ipv6hdr) :
					      sizeof(struct iphdr);
	int rc;

	pdc_pkt->ack_len = (sizeof(struct ethhdr) +
			    ip_hdr_size +
			    sizeof(struct uet_entropy) +
			    sizeof(struct uet_pds_ack_epsn));

	pdc_pkt->ack_buf_len = ((pdc_pkt->ack_len +
				 (pdc->sec_enabled
				  ? (UET_SEC_MAX_HDR_LEN + UET_SEC_TAG_LEN)
				  : CRC_LEN)) *
				(pdc->sec_enabled ? 2 : 1));
	pdc_pkt->ack_buf = calloc(1, pdc_pkt->ack_buf_len);
	if (pdc_pkt->ack_buf == NULL) {
		UET_PDS_ERR("failed to alloc closing ACK packet buffer");
		return -ENOMEM;
	}

	/* reserve head space for security header if needed */
	pdc_pkt->ack = (pdc->sec_enabled)
			? (pdc_pkt->ack_buf + UET_SEC_MAX_HDR_LEN)
			: pdc_pkt->ack_buf;

	uet_build_eth_hdr((struct ethhdr *)pdc_pkt->ack,
			  ((struct ethhdr *)pdc_pkt->pkt_pp.eth)->h_source,
			  ((struct ethhdr *)pdc_pkt->pkt_pp.eth)->h_dest,
			  pdc->is_ipv6);

	if (pdc->is_ipv6) {
		struct ipv6hdr *rx = (struct ipv6hdr *)pdc_pkt->pkt_pp.ip;
		uet_build_ipv6_hdr(uet,
				   (struct ipv6hdr *)(pdc_pkt->ack +
						      sizeof(struct ethhdr)),
				   (const uint8_t *)&rx->saddr,
				   (const uint8_t *)&rx->daddr,
				   (pdc_pkt->ack_len - uet->nic.l2_hdr_size -
				    ip_hdr_size),
				   uet->pds.ack_ip_tos, !pdc->sec_enabled);
	} else {
		struct iphdr *rx = (struct iphdr *)pdc_pkt->pkt_pp.ip;
		uet_build_ipv4_hdr(uet,
				   (struct iphdr *)(pdc_pkt->ack +
						    sizeof(struct ethhdr)),
				   rx->saddr, rx->daddr,
				   (pdc_pkt->ack_len - uet->nic.l2_hdr_size),
				   uet->pds.ack_ip_tos, !pdc->sec_enabled);
	}

	/* TODO: UDP support */
	entropy_hdr = (struct uet_entropy *)(pdc_pkt->ack +
					     sizeof(struct ethhdr) +
					     ip_hdr_size);
	entropy_hdr->entropy = htons(pdc_pkt->pkt_pp.entropy_val);

	ack_epsn = (struct uet_pds_ack_epsn *)(pdc_pkt->ack +
					       sizeof(struct ethhdr) +
					       ip_hdr_size +
					       sizeof(struct uet_entropy));
	ack = &ack_epsn->ack;

	/* base ACK type + expected-PSN flag */
	ack->prlg.type_next_flags =
		htons((UET_PDS_TYPE_ACK << UET_PDS_TYPE_SHIFT) |
		      (UET_HDR_NONE << UET_PDS_NEXT_HDR_SHIFT) |
		      (UET_PDS_ACK_FLAGS_EPSN << UET_PDS_FLAGS_SHIFT));

	/* Get the cumulative ack value */
	ack->ack_psn_offset = htons(psn_2c_offset(pdc->cack_psn,
						  pdc_pkt->pkt_pp.pds_psn));
	ack->cack_psn = htonl(pdc->cack_psn);

	ack->spdcid = htons(pdc->pdc_id);
	ack->dpdcid = htons(pdc->dpdcid);

	/* new Expected_PSN */
	ack_epsn->payload = htonl(payload);

	/* send the ACK packet */
	rc = uet_pds_sec_tx_pkt(uet, pdc, pdc_pkt, false, false);
	if (rc != 0) {
		pdc_pkt->ack_len = 0;
		free(pdc_pkt->ack_buf);
		return rc;
	}

	uet_pds_pkt_dbg(uet, &pdc_pkt->ack_pp, true, "TX CLOSING ACK (epsn)");

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
	size_t pds_ack_hdr_len;
	int rc;
	size_t ip_hdr_size = (pdc->is_ipv6) ? sizeof(struct ipv6hdr) :
					      sizeof(struct iphdr);

	pds_ack_hdr_len = uet_pds_ack_hdr_len(uet);
	def_rsp_len = (sizeof(struct ethhdr) +
		       ip_hdr_size +
		       sizeof(struct uet_entropy) +
		       pds_ack_hdr_len +
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

	entropy_hdr = (struct uet_entropy *)(def_rsp +
					     sizeof(struct ethhdr) +
					     ip_hdr_size);
	ack_pds = (struct uet_pds_ack *)(def_rsp +
					 sizeof(struct ethhdr) +
					 ip_hdr_size +
					 sizeof(struct uet_entropy));

	/* TODO: UDP support */
	entropy_hdr->entropy = htons(pdc_pkt->pkt_pp.entropy_val);

	uet_build_eth_hdr((struct ethhdr *)def_rsp,
			  ((struct ethhdr *)pdc_pkt->pkt_pp.eth)->h_source,
			  ((struct ethhdr *)pdc_pkt->pkt_pp.eth)->h_dest,
			  pdc->is_ipv6);

	if (pdc->is_ipv6) {
		struct ipv6hdr *rx_ipv6 =
			(struct ipv6hdr *)pdc_pkt->pkt_pp.ip;
		uet_build_ipv6_hdr(uet,
				   (struct ipv6hdr *)(def_rsp +
						      sizeof(struct ethhdr)),
				   (const uint8_t *)&rx_ipv6->saddr,
				   (const uint8_t *)&rx_ipv6->daddr,
				   (def_rsp_len - uet->nic.l2_hdr_size -
				    ip_hdr_size),
				   uet->pds.ack_ip_tos,
				   !pdc->sec_enabled);
	} else {
		uet_build_ipv4_hdr(uet,
				   (struct iphdr *)(def_rsp +
						    sizeof(struct ethhdr)),
				   ((struct iphdr *)pdc_pkt->pkt_pp.ip)->saddr,
				   ((struct iphdr *)pdc_pkt->pkt_pp.ip)->daddr,
				   (def_rsp_len - uet->nic.l2_hdr_size),
				   uet->pds.ack_ip_tos,
				   !pdc->sec_enabled);
	}

	/* TODO: add SACK header, UET_PDS_ACK_FLAGS_AX */
	ack_pds->prlg.type_next_flags =
		htons((uet->pds.ack_type << UET_PDS_TYPE_SHIFT) |
		      (UET_HDR_RSP << UET_PDS_NEXT_HDR_SHIFT) |
		      (UET_PDS_ACK_FLAGS_NONE << UET_PDS_FLAGS_SHIFT));

	/* Get the cumulative ack value */
	ack_pds->ack_psn_offset =
		htons(psn_2c_offset(pdc->cack_psn,
				    pdc_pkt->pkt_pp.pds_psn));
	ack_pds->cack_psn = htonl(pdc->cack_psn);

	ack_pds->spdcid = htons(pdc->pdc_id);
	ack_pds->dpdcid = htons(pdc->dpdcid);

	if ((uet->pds.ack_type == UET_PDS_TYPE_ACK_CC) ||
	    (uet->pds.ack_type == UET_PDS_TYPE_ACK_CCX)) {
		uet_pds_build_ack_cc_ext(uet, pdc, pdc_pkt, ack_pds,
					 uet->pds.ack_type);
	}

	ack_ses = (struct uet_pds_def_rsp *)((uint8_t *)ack_pds +
					     pds_ack_hdr_len);
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
	uet_pds_nack_code_t nack_code;
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
			     pdc->rx_bm_base_psn, UET_DEFAULT_MP_RANGE);
		nack_code = (pdc_pkt->pkt_pp.pds_flags &
			     UET_PDS_REQ_FLAGS_SYN) ? UET_NACK_INVALID_SYN :
			    UET_NACK_PSN_OOR_WINDOW;
		uet_pds_tx_nack(uet, pdc, &pdc_pkt->pkt_pp, nack_code, 0);
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
		rc = uet_pds_tx_nack(uet, pdc, &pdc_pkt->pkt_pp,
				     UET_NACK_RCVD_SES_PROCG, 0);
		if (rc != 0)
			return rc;

		*rtx = true;
	}

	return 0;
}

static bool uet_pds_should_sack(struct uet_instance *uet,
				struct uet_pdc *pdc,
				struct uet_pdc_pkt *pdc_pkt)
{
	if ((pdc_pkt->pkt_pp.pds_flags & UET_PDS_REQ_FLAGS_AR) ||
	    (pdc_pkt->pkt_pp.pds_flags & UET_PDS_REQ_FLAGS_SYN) ||
	    pdc_pkt->needs_clear) {
		return true;
	}

	if (pdc->accepted_bytes >= uet->pds.ack_gen_trigger)
		return true;

	if (pdc->prev_ar_psn == pdc->max_rcvd_psn)
		return true;

	return false;
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
		uet_pds_tx_nack(uet, pdc, &pdc_pkt->pkt_pp,
				UET_NACK_NO_SES_MSG_AVAIL, 0);
		return -ENOMEM;
	}

	rc = uet->pds.upcall.rx_req((uet_pkt_handle_t)pdc_pkt, uet,
				    &pdc_pkt->pkt_pp, &pds_info,
				    &rsp_next_hdr, rsp_ses_hdr,
				    &rsp_ses_hdr_len, &ses_nack,
				    &gtd_del);
	if (rc == 0) {
		if (ses_nack) {
			UET_PDS_ERR("PDC %u PSN %u SES NACK",
				    pdc->pdc_id, pdc_pkt->pkt_pp.pds_psn);
			uet_pds_tx_nack(uet, pdc, &pdc_pkt->pkt_pp,
					UET_NACK_NO_SES_MSG_AVAIL, 0);
			rc = -EINVAL;
		} else {
			pdc_pkt->needs_clear = gtd_del;
			pdc->accepted_bytes +=
				uet_max(pdc_pkt->pkt_pp.pkt_payload_len,
					uet->pds.ack_gen_min_pkt_add);
			uet_pds_update_cack(pdc, pdc_pkt->pkt_pp.pds_clear_psn);
			uet_pds_update_sack_base(pdc, pdc_pkt, false);
			/* transmit ACK */
			if (uet_pds_should_sack(uet, pdc, pdc_pkt)) {
				rc = uet_pds_tx_ack_pkt(uet, pdc, pdc_pkt,
							rsp_next_hdr,
							rsp_ses_hdr_len,
							rsp_ses_hdr, gtd_del);
				pdc->accepted_bytes = 0;
			}
		}
	} else {
		UET_PDS_ERR("PDC %u PSN %u SES upcall failed (rx_req=%d)",
			    pdc_pkt->pkt_pp.pds_dpdcid,
			    pdc_pkt->pkt_pp.pds_psn, rc);
		uet_pds_tx_nack(uet, pdc, &pdc_pkt->pkt_pp,
				UET_NACK_UNEXP_EVENT, 0);
	}

	free(rsp_ses_hdr);
	return rc;
}

static int uet_pds_shift_rx_window(struct uet_instance *uet,
				   struct uet_pdc *pdc)
{
	struct uet_pdc_pkt *pdc_pkt;
	int shift_count;
	int i;
	int rc;

	/* Shift the Rx window forward from rx_bm_base_psn to cack_psn + 1 */
	shift_count = UET_PDS_PSN_OFFSET(pdc->cack_psn + 1,
					 pdc->rx_bm_base_psn);
	if (shift_count <= 0)
		return 0;

	/* Free all packets being shifted out of the window */
	for (i = 0; i < shift_count; i++) {
		if (!bm_get(pdc->rx_bm, i, (void **)&pdc_pkt))
			continue;

		if (pdc_pkt->ack_buf)
			free(pdc_pkt->ack_buf);
		if (pdc_pkt->pkt_buf)
			free(pdc_pkt->pkt_buf);
		free(pdc_pkt);
	}

	/* Shift the bitmap and update base PSN */
	bm_shift_right(pdc->rx_bm, shift_count);
	pdc->rx_bm_base_psn += shift_count;

	UET_PDS_DBG("PDC %d rx_bm shifted %d (new base %u):",
		    pdc->pdc_id, shift_count, pdc->rx_bm_base_psn);

	if (UET_LOG_LVL >= UET_LOG_DBG)
		bm_print_bits(pdc->rx_bm, uet_pdc_rx_bit_char);

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

static void uet_pds_process_sack_bitmap(struct uet_instance *uet,
					struct uet_pdc *pdc,
					struct uet_parsed_pkt *pp)
{
	struct uet_pdc_pkt *pdc_pkt;
	uint32_t psn;
	int i, idx;

	for (i = 0; i < 64; i++) {
		psn = pp->pds_sack_base_psn + i;
		if (UET_PDS_PSN_AFTER_EQ(pdc->max_cack_psn, psn))
			continue;

		if (!(pp->pds_sack_bitmap & (1ULL << i)))
			continue;

		idx = UET_PDS_PSN_OFFSET(psn, pdc->tx_bm_base_psn);
		if (idx < 0)
			continue;

		if (!bm_get(pdc->tx_bm, idx, (void **)&pdc_pkt))
			continue;

		/* The packet has arrived at the target side */
		pdc_pkt->dst_recvd = true;
	}
}

static void uet_pds_process_cack(struct uet_instance *uet,
				 struct uet_pdc *pdc,
				 struct uet_parsed_pkt *pp)
{
	struct uet_pdc_pkt *pdc_pkt;
	int shift_count;
	int i;

	UET_PDS_UPDATE_PSN(pdc->max_cack_psn, pp->pds_cack_psn);

	shift_count = UET_PDS_PSN_OFFSET(pdc->max_cack_psn + 1,
					 pdc->tx_bm_base_psn);
	if (shift_count <= 0)
		return;

	/* Free all packets being shifted out of the window */
	for (i = 0; i < shift_count; i++) {
		if (!bm_get(pdc->tx_bm, i, (void **)&pdc_pkt))
			continue;

		if (!pdc_pkt->tx_pkt_acked) {
			pdc_pkt->tx_pkt_acked = true;
			dlist_remove(&pdc_pkt->node);
			uet->pds.upcall.rx_rsp(pdc_pkt->tx_pkt_handle, NULL);
		}
	}
}

static int uet_pds_nack_action(uet_pds_nack_code_t code)
{
	switch (code) {
	case UET_NACK_TRIMMED:
	case UET_NACK_TRIMMED_LAST_HOP:
	case UET_NACK_TRIMMED_ACK:
	case UET_NACK_NO_PDC_AVAIL:
	case UET_NACK_NO_CCC_AVAIL:
	case UET_NACK_NO_BITMAP:
	case UET_NACK_NO_PKT_BUF:
	case UET_NACK_NO_GTD_DEL_AVAIL:
	case UET_NACK_NO_SES_MSG_AVAIL:
	case UET_NACK_NO_RESOURCE:
	case UET_NACK_PSN_OOR_WINDOW:
	case UET_NACK_ROD_OOO:
	case UET_NACK_PKT_NOT_RCVD:
	case UET_NACK_ACK_WITH_DATA:
	case UET_NACK_NEW_START_PSN:
	case UET_NACK_RCVR_INFER_LESS:
	case UET_NACK_EXP_NACK_NORMAL:
	case UET_NACK_EXP_NACK_ERR:
		return UET_NACK_ACTION_RETX;

	case UET_NACK_INV_DPDCID:
	case UET_NACK_PDC_HDR_MISMATCH:
	case UET_NACK_CLOSING:
	case UET_NACK_CLOSING_IN_ERR:
	case UET_NACK_GTD_RESP_UNAVAIL:
	case UET_NACK_INVALID_SYN:
	case UET_NACK_PDC_MODE_MISMATCH:
	case UET_NACK_UNEXP_EVENT:
	case UET_NACK_EXP_NACK_FATAL:
		return UET_NACK_ACTION_CLOSE;

	/*
	 * RCVD_SES_PROCG means the target received the packet but the SES
	 * layer has not yet produced a response. Retransmitting/ACK-req
	 * probing here only produces a NACK storm on the tail PSN and can
	 * exhaust the retry budget on the wrong packet. Drop it and let the
	 * RTO path recover any real gap.
	 */
	case UET_NACK_RCVD_SES_PROCG:
		return UET_NACK_ACTION_DROP;

	default:
		return UET_NACK_ACTION_DROP;
	}
}

/*
 * Close a PDC in error. All outstanding Tx packets are reported to SES as
 * unrecoverable failures, and start PDC close procedure.
 */
static void uet_pds_close_pdc_in_error(struct uet_instance *uet,
				       struct uet_pdc *pdc)
{
	struct uet_pdc_pkt *pdc_pkt;
	struct dlist_entry *tmp;
	int rc;

	UET_PDS_ERR("PDC %u closing in error", pdc->pdc_id);
	pds_state.pdc_close_in_err_cnt++;

	/* fail and free all outstanding Tx packets, notifying SES */
	dlist_foreach_container_safe(&pdc->tx_pkt_list_head,
				     struct uet_pdc_pkt, pdc_pkt,
				     node, tmp) {
		if (PSN_IN_MPR(pdc_pkt->psn, pdc->tx_bm_base_psn))
			bm_unset(pdc->tx_bm,
				 (pdc_pkt->psn - pdc->tx_bm_base_psn));

		dlist_remove(&pdc_pkt->node);

		if (uet->pds.upcall.pds_err && pdc_pkt->tx_pkt_handle)
			uet->pds.upcall.pds_err(pdc_pkt->tx_pkt_handle,
						UET_PDS_ERR_NONE);

		if (pdc_pkt->ack_buf)
			free(pdc_pkt->ack_buf);
		if (pdc_pkt->pkt_buf)
			free(pdc_pkt->pkt_buf);
		free(pdc_pkt);
	}

	/*
	 * The Close Command/Request sent on the first pass has itself
	 * exhausted retries (or an error hit while already closing).
	 * Free the PDC to break the retry loop.
	 */
	if (pdc->close_started) {
		UET_PDS_ERR("PDC %u close already started", pdc->pdc_id);
		uet_pdsm_free_pdc(pdc);
		return;
	}

	if (pdc->is_initiator)
		uet_pds_initiate_pdc_close(uet, pdc);
	else
		uet_pds_target_pdc_close(uet, pdc);
}

/*
 * Initiator adopts the Start_PSN carried in a UET_NEW_START_PSN NACK from the
 * target and re-drives the (not-yet-established) PDC. All queued un-ACK'ed
 * packets are shifted by the same PSN delta. Packets are retransmitted.
 */
static int uet_pds_reestablish_start_psn(struct uet_instance *uet,
					 struct uet_pdc *pdc,
					 uint32_t new_start_psn)
{
	struct uet_pdc_pkt *pdc_pkt;
	struct dlist_entry *tmp;
	struct uet_pds_req *pds_hdr;
	uint32_t delta;

	/* only meaningful before the PDC is established */
	if (pdc->state != PDC_STATE_SYN)
		return 0;

	delta = (new_start_psn - pdc->start_psn);
	if (delta == 0)
		return 0; /* already driving this Start_PSN */

	UET_PDS_WARN("PDC %u adopt new Start_PSN %u (was %u)",
		     pdc->pdc_id, new_start_psn, pdc->start_psn);

	/* uniform shift of the PDC PSN bases */
	pdc->start_psn      += delta;
	pdc->next_psn       += delta;
	pdc->tx_bm_base_psn += delta;
	pdc->rx_bm_base_psn += delta;
	pdc->max_cack_psn   += delta;

	/* re-stamp and retransmit each un-ACK'ed packet at its shifted PSN */
	dlist_foreach_container_safe(&pdc->tx_pkt_list_head,
				     struct uet_pdc_pkt, pdc_pkt, node, tmp) {
		if (pdc_pkt->tx_pkt_acked)
			continue;

		pdc_pkt->psn += delta;
		pdc_pkt->pkt_pp.pds_psn = pdc_pkt->psn;

		pds_hdr = (struct uet_pds_req *)pdc_pkt->pkt_pp.pds;
		pds_hdr->psn = htonl(pdc_pkt->psn);

		pdc_pkt->tx_retry_cnt = 0;

		if (uet_pds_sec_tx_pkt(uet, pdc, pdc_pkt, true, true) != 0)
			UET_PDS_ERR("PDC %u re-drive Tx failed (PSN %u)",
				    pdc->pdc_id, pdc_pkt->psn);
	}

	return 0;
}

static int uet_pds_process_nack(struct uet_instance *uet,
				struct uet_parsed_pkt *pp)
{
	struct uet_pdc *pdc;
	struct uet_pdc_pkt *pdc_pkt;
	int nack_action;
	int rc;

	rc = uet_pdsm_get_pdc(pp->pds_dpdcid, false, &pdc);
	if (rc != 0) {
		UET_PDS_WARN("NACK for unknown/invalid PDC %u (nack_code=0x%x)",
			     pp->pds_dpdcid, pp->pds_nack_code);
		return rc;
	}

	UET_PDS_WARN("PDC %u received NACK (code=0x%x psn=%u spdcid=%u)",
		     pdc->pdc_id, pp->pds_nack_code, pp->pds_psn,
		     pp->pds_spdcid);

	/* Secure PDC establishment, adopt the target Start_PSN and re-drive */
	if (pp->pds_nack_code == UET_NACK_NEW_START_PSN)
		return uet_pds_reestablish_start_psn(uet, pdc, pp->pds_payload);

	nack_action = uet_pds_nack_action(pp->pds_nack_code);
	if (nack_action == UET_NACK_ACTION_DROP) {
		UET_PDS_WARN("NACK PSN %u on PDC %u dropped",
			     pp->pds_psn, pdc->pdc_id);
		return -EINVAL;
	}

	/*
	 * A NACK that arrives with an out-of-range pds.nack_psn MUST NOT be
	 * used to update PDC state.
	 */
	if (UET_PDS_PSN_AFTER(pdc->tx_bm_base_psn, pp->pds_psn) ||
	    UET_PDS_PSN_AFTER(pp->pds_psn, pdc->next_psn - 1)) {
		UET_PDS_WARN("Invalid NACK PSN %u on PDC %u",
			     pp->pds_psn, pdc->pdc_id);
		return -EINVAL;
	}

	if (nack_action == UET_NACK_ACTION_CLOSE) {
		uet_pds_close_pdc_in_error(uet, pdc);
		return 0;
	}

	/* UET_NACK_ACTION_RETX: retransmit the NACKed PSN */
	if (!bm_get(pdc->tx_bm, (pp->pds_psn - pdc->tx_bm_base_psn),
		    (void **)&pdc_pkt)) {
		UET_PDS_WARN("NACK PSN %u on PDC %u packet not found",
			     pp->pds_psn, pdc->pdc_id);
		return -EINVAL;
	}

	if (pdc_pkt->tx_pkt_acked)
		return 0;

	if (!pdc_pkt->dst_recvd &&
	    !uet_pds_tx_psn_allowed(pdc, pdc_pkt->psn))
		return 0; /* wait for CACK to advance the peer window */

	if (pdc_pkt->tx_retry_cnt >= uet->pds.max_tx_retries) {
		UET_PDS_ERR("PDC %u PSN %u NACK retries exhausted",
			    pdc->pdc_id, pp->pds_psn);
		uet_pds_close_pdc_in_error(uet, pdc);
		return 0;
	}

	rc = uet_pds_rtx_pkt(uet, pdc, pdc_pkt);
	if (rc == -EAGAIN)
		return 0; /* wait for CACK to advance the peer window */

	if (rc != 0) {
		UET_PDS_ERR("PDC %u PSN %u NACK-triggered retransmit failed",
			    pdc->pdc_id, pp->pds_psn);
		return rc;
	}

	dlist_remove(&pdc_pkt->node);
	dlist_insert_tail(&pdc_pkt->node, &pdc->tx_pkt_list_head);
	return 0;
}

static void uet_pds_process_mpr(struct uet_pdc *pdc,
				const struct uet_parsed_pkt *pp)
{
	uint32_t mp_range;

	if (pdc->mpr_update_valid &&
	    !UET_PDS_PSN_AFTER(pp->pds_cack_psn, pdc->mpr_update_cack_psn)) {
		UET_PDS_DBG("PDC %u ignored stale MPR %u at CACK %u",
			    pdc->pdc_id, pp->pds_mpr, pp->pds_cack_psn);
		return;
	}

	mp_range = uet_pds_decode_mpr(pp->pds_mpr);
	pdc->peer_mp_range = mp_range;
	pdc->mpr_update_cack_psn = pp->pds_cack_psn;
	pdc->mpr_update_valid = true;

	UET_PDS_DBG("PDC %u peer MPR %u -> MP_RANGE %u at CACK %u",
		    pdc->pdc_id, pp->pds_mpr, mp_range, pp->pds_cack_psn);
}

static int uet_pds_process_ack(struct uet_instance *uet,
			       struct uet_parsed_pkt *pp)
{
	struct uet_pdc *pdc;
	struct uet_pdc_pkt *pdc_pkt = NULL;
	uint32_t start_psn;
	bool duplicate = false;
	int rc;

	rc = uet_pdsm_get_pdc(pp->pds_dpdcid, false, &pdc);
	if (rc != 0) {
		return rc;
	}

	if ((pdc->state != PDC_STATE_SYN) &&
	    (pdc->dpdcid != pp->pds_spdcid)) {
		UET_PDS_WARN("invalid PDC %u (dpdcid %u != spdcid %u)",
			     pdc->pdc_id, pdc->dpdcid, pp->pds_spdcid);
		return -EINVAL;
	}

	if (UET_PDS_PSN_AFTER(pp->pds_cack_psn, pdc->next_psn - 1)) {
		UET_PDS_WARN("invalid CACK PSN %u on PDC %u (next PSN %u)",
			     pp->pds_cack_psn, pp->pds_dpdcid, pdc->next_psn);
		return -EINVAL;
	}

	/*
	 * The explicit PSN may already have left the local bitmap when ACKs
	 * are reordered.  Its newer CACK, MPR, or SACK state is still useful,
	 * but its SES response must not be delivered twice.
	 */
	if (UET_PDS_PSN_AFTER(pdc->tx_bm_base_psn, pp->pds_psn)) {
		duplicate = true;
	} else if (!PSN_IN_MPR(pp->pds_psn, pdc->tx_bm_base_psn)) {
		UET_PDS_WARN("invalid ACK PSN %u on PDC %u "
			     "(outside MPR %u[+%u])",
			     pp->pds_psn, pp->pds_dpdcid,
			     pdc->tx_bm_base_psn, UET_DEFAULT_MP_RANGE);
		return -EINVAL;
	} else if (!bm_get(pdc->tx_bm,
			   (pp->pds_psn - pdc->tx_bm_base_psn),
			   (void **)&pdc_pkt)) {
		UET_PDS_WARN("invalid ACK PSN %u on PDC %u (packet not found)",
			     pp->pds_psn, pp->pds_dpdcid);
		return -EINVAL;
	} else if (pdc_pkt->tx_pkt_acked) {
		duplicate = true;
	}

	/*
	 * The packets explicitly acknowledged and implicitly acknowledged
	 * by coalesced ack are processed separately.
	 */
	if (!duplicate) {
		pdc_pkt->tx_pkt_acked = true;
		dlist_remove(&pdc_pkt->node); /* remove from Tx list */
	}

	if (pp->pds_type == UET_PDS_TYPE_ACK_CC ||
	    pp->pds_type == UET_PDS_TYPE_ACK_CCX)
		uet_pds_process_mpr(pdc, pp);
	uet_pds_process_cack(uet, pdc, pp);
	if (pp->pds_type == UET_PDS_TYPE_ACK_CC ||
	    pp->pds_type == UET_PDS_TYPE_ACK_CCX) {
		uet_pds_process_sack_bitmap(uet, pdc, pp);
	}

	if (duplicate)
		return uet_pds_shift_tx_window(uet, pdc);

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

		/* EXPECTED_0RTT_START, if the closing ACK carries an
		 * Expected_PSN, adopt it as the SDI's Start_PSN for future
		 * outgoing PDCs when it is newer than the current one.
		 */
		if (pdc->sec_enabled &&
		    (pds_psn_method == UET_PDS_PSN_METHOD_0RTT) &&
		    (pp->pds_flags & UET_PDS_ACK_FLAGS_EPSN)) {
			start_psn = uet_sec_sd_get_ini_start_psn(pdc->sdi);

			if (UET_PDS_PSN_AFTER(pp->pds_payload, start_psn)) {
				uet_sec_sd_set_ini_start_psn(pdc->sdi,
							     pp->pds_payload);
				UET_PDS_INFO("PDC %u close ACK: SDI %u "
					     "Start_PSN -> %u", pdc->pdc_id,
					     pdc->sdi, pp->pds_payload);
			}
		}

		/* shift the tx_bm window for all left edge ACK'ed PSNs */
		rc = uet_pds_shift_tx_window(uet, pdc);
		if (rc != 0)
			return rc;

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

	/*
	 * If the UET_PDS_ACK_FLAGS_REQ_CLR flag was set on the ACK,
	 * immediately send a PDS CLEAR control packet now.
	 * Note: the UET spec only requires a standalone clear CP when no PDS
	 * request is pending to carry clear_psn_offset
	 */
	if (pdc->is_initiator &&
	    (pp->pds_flags & UET_PDS_ACK_FLAGS_REQ_CLR)) {
		rc = uet_pds_send_ctrl_pkt(uet, pdc, UET_PDS_CTRL_TYPE_CLEAR,
				      pdc->tx_bm_base_psn - 1, NULL);
		if ((rc != 0) && (rc != -EAGAIN)) {
			UET_PDS_WARN("PDC %u failed to send clear cp (rc=%d)",
				     pdc->pdc_id, rc);
		}
	}

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

static int uet_pds_process_data_pkt(struct uet_instance *uet,
				    struct uet_pdc *pdc,
				    struct uet_pdc_pkt *pdc_pkt)
{
	struct uet_pdc_pkt *temp_pdc_pkt;
	int max_rx_bm_idx;
	int i = 0;
	int rc;

	UET_PDS_UPDATE_PSN(pdc->max_rcvd_psn, pdc_pkt->pkt_pp.pds_psn);

	if (pdc_pkt->pkt_pp.pds_flags & UET_PDS_REQ_FLAGS_AR)
		UET_PDS_UPDATE_PSN(pdc->prev_ar_psn, pdc_pkt->pkt_pp.pds_psn);

	/*
	 * The processing logic of PDS request packet is as follows:
	 * 1. Place the packet into rx bitmap.
	 * 2. For RUD, pass the packet to SES layer immediately;
	 *    for ROD, check whether the packet PSN is consecutive;
	 *    if so, deliver all packets that have consecutive PSNs and
	 *    have not been processed by SES to SES layer.
	 * 3. Update cack.
	 * 4. Determin whether to reply with an ACK.
	 * 5. Advance the rx_bm_base_psn according to cack and free unused
	 *    pdc packets.
	 */
	if (pdc_pkt->pkt_pp.pds_type == UET_PDS_TYPE_RUD_REQ) {
		/* for RUD, call into SES immediately ignoring order */
		rc = uet_pds_upcall_ses_rx_req(uet, pdc, pdc_pkt);
		if (rc != 0)
			return rc;
	} else if (pdc_pkt->pkt_pp.pds_type == UET_PDS_TYPE_ROD_REQ) {
		/* for ROD, reorder before calling into SES */
		max_rx_bm_idx = bm_max(pdc->rx_bm);
		while (i <= max_rx_bm_idx) {
			if (!bm_get(pdc->rx_bm, i, (void **)&temp_pdc_pkt))
				break;

			if (!temp_pdc_pkt->reordered) {
				rc = uet_pds_upcall_ses_rx_req(uet, pdc,
							       temp_pdc_pkt);
				if (rc != 0)
					return rc;

				temp_pdc_pkt->reordered = true;
			}
			i++;
		}
	}

	rc = uet_pds_shift_rx_window(uet, pdc);
	if (rc != 0)
		return rc;

	return 0;
}

static int uet_pds_process_syn_pkt(struct uet_instance *uet,
				   struct uet_pdc_pkt *pdc_pkt)
{
	struct uet_parsed_pkt *pp = &pdc_pkt->pkt_pp;
	struct uet_pdc *pdc;
	bool rtx;
	uet_pds_nack_code_t nack_code;
	uint32_t nack_payload = 0;
	int rc;

	rc = uet_pdsm_assign_tgt_pdc(pp, &pdc, &nack_code, &nack_payload);
	if (rc != 0) {
		uet_pds_tx_nack(uet, NULL, pp, nack_code, nack_payload);
		return rc;
	}

	/* check if this packet is a duplicate */
	rc = uet_pds_check_duplicate_and_rtx(uet, pdc, pdc_pkt, &rtx);
	/* TODO: if error, free PDC if allocated with this SYN */
	if (rc != 0)
		return rc;
	else if (rtx) {
		/*
		 * This packet was already consumed by duplicate/retransmit
		 * handling. However, it is not inserted into rx_bm, so it
		 * needs to be freed by the caller.
		 */
		return -EEXIST;
	}

	UET_PDS_DBG("PDC %u rx_bm: base=%u psn=%u SET bit=%u",
		    pdc->pdc_id, pdc->rx_bm_base_psn, pp->pds_psn,
		    (pp->pds_psn - pdc->rx_bm_base_psn));

	if (!bm_set(pdc->rx_bm,
		    (pp->pds_psn - pdc->rx_bm_base_psn), pdc_pkt)) {
		UET_PDS_ERR("PDC %u cannot track RX PSN %u",
			    pdc->pdc_id, pp->pds_psn);
		return -ERANGE;
	}

	if (UET_LOG_LVL >= UET_LOG_DBG) {
		UET_PDS_DBG("PDC %d rx_bm (base %u):",
			    pdc->pdc_id, pdc->rx_bm_base_psn);
		bm_print_bits(pdc->rx_bm, uet_pdc_rx_bit_char);
	}

	rc = uet_pds_process_data_pkt(uet, pdc, pdc_pkt);
	if (rc != 0) {
		bm_unset(pdc->rx_bm, (pp->pds_psn - pdc->rx_bm_base_psn));
		return rc;
	}

	return 0;
}

static int uet_pds_process_ack_req_cp(struct uet_instance *uet,
				      struct uet_pdc *pdc,
				      struct uet_parsed_pkt *pp)
{
	struct uet_pdc_pkt *orig_pdc_pkt = NULL;
	int rc;

	UET_PDS_DBG("Received ACK_REQ cp (spdcid=%u dpdcid=%u)",
		     pp->pds_spdcid, pp->pds_dpdcid);

	/* check the psn is within MPR, if not, drop the packet */
	if (!PSN_IN_MPR(pp->pds_psn, pdc->rx_bm_base_psn)) {
		UET_PDS_WARN("ACK REQ cp PDC %u PSN %u outside MPR",
			     pp->pds_dpdcid, pp->pds_psn);
		return -EINVAL;
	}

	if (!bm_get(pdc->rx_bm, (pp->pds_psn - pdc->rx_bm_base_psn),
		    (void **)&orig_pdc_pkt)) {
		UET_PDS_WARN("ACK REQ cp PDC %u PSN %u original pkt not found",
			     pp->pds_dpdcid, pp->pds_psn);
		uet_pds_tx_nack(uet, pdc, pp, UET_NACK_PKT_NOT_RCVD, 0);
		return 0;
	}

	/* find previous ACK/response */
	if (orig_pdc_pkt->ack == NULL) {
		UET_PDS_WARN("ACK REQ cp PDC %u PSN %u original ack not found",
			     pp->pds_dpdcid, pp->pds_psn);
		uet_pds_tx_nack(uet, pdc, pp, UET_NACK_RCVD_SES_PROCG, 0);
		return 0;
	}

	/* resend previous ACK/response */
	rc = uet_pds_sec_tx_pkt(uet, pdc, orig_pdc_pkt, false, true);
	if (rc != 0)
		return rc;

	uet_pds_pkt_dbg(uet, &orig_pdc_pkt->ack_pp, true,
			"TX ACK PACKET (duplicate)");

	return 0;
}

static int uet_pds_process_close_req_cp(struct uet_instance *uet,
					struct uet_pdc *pdc,
					struct uet_parsed_pkt *pp)
{
	struct uet_pdc_pkt temp_pkt;

	UET_PDS_DBG("Received CLOSE_REQ cp (spdcid=%u dpdcid=%u)",
		    pp->pds_spdcid, pp->pds_dpdcid);
	pdc->close_requested = true;

	memset(&temp_pkt, 0, sizeof(temp_pkt));
	memcpy(&temp_pkt.pkt_pp, pp, sizeof(*pp));
	uet_pds_tx_ack_pkt(uet, pdc, &temp_pkt, UET_HDR_NONE, 0, NULL, false);
	uet_pds_initiate_pdc_close(uet, pdc);

	return 0;
}

static int uet_pds_process_close_command_cp(struct uet_instance *uet,
					    struct uet_pdc *pdc,
					    struct uet_parsed_pkt *pp)
{
	struct uet_pdc_pkt temp_pkt;
	struct uet_pdc_pkt *pdc_pkt;
	struct dlist_entry *tmp;
	uint32_t expected_psn;
	int rc;

	UET_PDS_DBG("Received CLOSE command (spdcid=%u dpdcid=%u)",
		    pp->pds_spdcid, pp->pds_dpdcid);

	pdc->close_started = true;

	/* target transitions to CLOSING state */
	pdc->state = PDC_STATE_CLOSING;

	/* ALL PSNs on forward direction are implicitly cleared */
	pdc->max_clear_psn = pdc->max_rcvd_psn;
	pdc->cack_psn = pdc->max_clear_psn;
	uet_pds_shift_rx_window(uet, pdc);

	/*
	 * Verify the PDC is idle with no outstanding TX packets.
	 * There should be no active PSNs in the return direction
	 * when a close command is received.
	 */
	if (bm_count(pdc->tx_bm) > 0) {
		UET_PDS_WARN("PDC %u PDC_CLOSE_IN_ERR: received CLOSE "
			     "with %d outstanding TX packets",
			     pdc->pdc_id, bm_count(pdc->tx_bm));
		uet_pds_tx_nack(uet, pdc, pp, UET_NACK_CLOSING_IN_ERR,
				bm_count(pdc->tx_bm));
		uet_pds_close_pdc_in_error(uet, pdc);
		return -EINVAL;
	}

	/* set up temp pdc_pkt with parsed control packet */
	memset(&temp_pkt, 0, sizeof(temp_pkt));
	memcpy(&temp_pkt.pkt_pp, pp, sizeof(*pp));

	if (pdc->sec_enabled && (pds_psn_method == UET_PDS_PSN_METHOD_0RTT)) {
		/* EXPECTED_0RTT_START, advance the SDI's
		 * Expected_PSN past this PDC's Start_PSN and
		 * return it in the closing ACK.
		 */
		expected_psn = uet_sec_sd_get_tgt_start_psn(pdc->sdi);

		if (UET_PDS_PSN_AFTER_EQ(pdc->start_psn, expected_psn)) {
			expected_psn = (pdc->start_psn + 1);
			uet_sec_sd_set_tgt_start_psn(pdc->sdi, expected_psn);
		}

		UET_PDS_INFO("PDC %u close: SDI %u Expected_PSN -> %u",
			     pdc->pdc_id, pdc->sdi, expected_psn);

		rc = uet_pds_tx_close_ack_epsn(uet, pdc, &temp_pkt,
					       expected_psn);
	} else {
		/* build and send a plain ACK packet */
		rc = uet_pds_tx_ack_pkt(uet, pdc, &temp_pkt, UET_HDR_NONE, 0,
					NULL, false);
	}
	if (rc != 0) {
		UET_PDS_ERR("failed to send ACK for CLOSE");
		return rc;
	}

	uet_pdsm_free_pdc(pdc);

	return 0;
}

static int uet_pds_process_clear_cp(struct uet_instance *uet,
				    struct uet_pdc *pdc,
				    struct uet_parsed_pkt *pp)
{
	UET_PDS_DBG("Received CLEAR cp (spdcid=%u dpdcid=%u)",
		    pp->pds_spdcid, pp->pds_dpdcid);

	uet_pds_update_cack(pdc, pp->pds_ctrl_payload);
	return uet_pds_shift_rx_window(uet, pdc);
}

static int uet_pds_process_control(struct uet_instance *uet,
				   struct uet_parsed_pkt *pp,
				   uint8_t *pkt,
				   int pkt_len)
{
	struct uet_pdc *pdc;
	uint32_t expected_psn;
	int rc;

	/* find the target PDC */
	rc = uet_pdsm_get_pdc(pp->pds_dpdcid, false, &pdc);
	if (rc != 0) {
		UET_PDS_WARN("CP type %d for unknown PDC %u",
			     pp->pds_ctrl_type, pp->pds_dpdcid);
		uet_pds_tx_nack(uet, NULL, pp, UET_NACK_INV_DPDCID, 0);
		return rc;
	}

	/* verify dpdcid matches spdcid */
	if (pdc->dpdcid != pp->pds_spdcid) {
		UET_PDS_WARN("PDC %u dpdcid mismatch (%u != %u)",
			     pdc->pdc_id, pdc->dpdcid, pp->pds_spdcid);
		uet_pds_tx_nack(uet, pdc, pp, UET_NACK_PDC_HDR_MISMATCH, 0);
		return -EINVAL;
	}

	/* verify the PDC is in the correct state */
	if (pdc->state != PDC_STATE_ESTABLISHED &&
	    pdc->state != PDC_STATE_CLOSING) {
		UET_PDS_WARN("PDC %u not in ESTABLISHED or CLOSING "
			     "(state=%d)",
			     pdc->pdc_id, pdc->state);
		uet_pds_tx_nack(uet, pdc, pp, UET_NACK_UNEXP_EVENT, 0);
		return -EINVAL;
	}

	switch (pp->pds_ctrl_type) {
	case UET_PDS_CTRL_TYPE_ACK_REQ:
		return uet_pds_process_ack_req_cp(uet, pdc, pp);

	case UET_PDS_CTRL_TYPE_CLOSE_REQ:
		return uet_pds_process_close_req_cp(uet, pdc, pp);

	case UET_PDS_CTRL_TYPE_CLOSE:
		return uet_pds_process_close_command_cp(uet, pdc, pp);

	case UET_PDS_CTRL_TYPE_CLEAR:
		return uet_pds_process_clear_cp(uet, pdc, pp);

	case UET_PDS_CTRL_TYPE_PROBE:
	case UET_PDS_CTRL_TYPE_CREDIT:
	case UET_PDS_CTRL_TYPE_CREDIT_REQ:
	case UET_PDS_CTRL_TYPE_NEGOTIATION:
		UET_PDS_ERR("Control type %d not yet supported",
			     pp->pds_ctrl_type);
		uet_pds_tx_nack(uet, NULL, pp, UET_NACK_UNEXP_EVENT, 0);
		return -EINVAL;

	default:
		UET_PDS_ERR("Unknown control type %d", pp->pds_ctrl_type);
		uet_pds_tx_nack(uet, NULL, pp, UET_NACK_UNEXP_EVENT, 0);
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

	if ((pp->pds_type != UET_PDS_TYPE_RUD_REQ) &&
	    (pp->pds_type != UET_PDS_TYPE_ROD_REQ)) {
		UET_PDS_WARN("Rx packet type not supported %d",
			     pp->pds_type);
		uet_pds_tx_nack(uet, NULL, pp, UET_NACK_PDC_MODE_MISMATCH, 0);
		return -EINVAL;
	}

	pdc_pkt = calloc(1, sizeof(struct uet_pdc_pkt));
	if (pdc_pkt == NULL) {
		UET_PDS_ERR("failed to alloc PDC packet");
		uet_pds_tx_nack(uet, NULL, pp, UET_NACK_NO_PKT_BUF, 0);
		return -ENOMEM;
	}

	pdc_pkt->psn = pp->pds_psn;
	pdc_pkt->msg_id = pp->ses_msg_id;
	pdc_pkt->pkt = pkt;
	pdc_pkt->pkt_len = pkt_len;
	pdc_pkt->pkt_buf = pkt;
	pdc_pkt->pkt_buf_len = pkt_len;
	memcpy(&pdc_pkt->pkt_pp, pp, sizeof(*pp));
	pdc_pkt->pkt_parsed = true;

	/* if this is a SYN packet then a new PDC might be needed */
	if (pdc_pkt->pkt_pp.pds_flags & UET_PDS_REQ_FLAGS_SYN) {
		rc = uet_pds_process_syn_pkt(uet, pdc_pkt);
		if (rc != 0)
			goto exit_err;
		return 0;
	}

	rc = uet_pdsm_get_pdc(pdc_pkt->pkt_pp.pds_dpdcid, false, &pdc);
	if (rc != 0) {
		uet_pds_tx_nack(uet, NULL, &pdc_pkt->pkt_pp,
				UET_NACK_INV_DPDCID, 0);
		rc = -ENODEV;
		goto exit_err;
	}

	if (pdc_pkt->pkt_pp.pds_spdcid != pdc->dpdcid) {
		UET_PDS_WARN("invalid PDC %u (spdcid %u != dpdcid %u)",
			     pdc->pdc_id, pdc_pkt->pkt_pp.pds_spdcid,
			     pdc->dpdcid);
		uet_pds_tx_nack(uet, pdc, &pdc_pkt->pkt_pp,
				UET_NACK_PDC_HDR_MISMATCH, 0);
		rc = -EINVAL;
		goto exit_err;
	}

	/*
	 * If a close command was already received and a packet with a higher
	 * PSN is received, transmit a NACK with UET_CLOSING.
	 */
	if (pdc->state == PDC_STATE_CLOSING) {
		if (UET_PDS_PSN_AFTER(pdc_pkt->pkt_pp.pds_psn,
				      pdc->close_cmd_psn)) {
			UET_PDS_WARN("PDC %u is CLOSING, received PSN %u "
				     "after CLOSE (close_cmd_psn=%u)",
				     pdc->pdc_id, pdc_pkt->pkt_pp.pds_psn,
				     pdc->close_cmd_psn);
			uet_pds_tx_nack(uet, pdc, &pdc_pkt->pkt_pp,
					UET_NACK_CLOSING, 0);
			rc = -EINVAL;
			goto exit_err;
		}
	}

	/* check if this packet is a duplicate */
	rc = uet_pds_check_duplicate_and_rtx(uet, pdc, pdc_pkt, &rtx);
	if (rc != 0)
		goto exit_err;
	else if (rtx) {
		/*
		 * This packet was already consumed by duplicate/retransmit
		 * handling. However, it is not inserted into rx_bm, so it
		 * needs to be freed by this caller.
		 */
		rc = -EEXIST;
		goto exit_err;
	}

	UET_PDS_DBG("PDC %u rx_bm: base=%u clear psn=%u psn=%u SET bit=%u",
		    pdc->pdc_id, pdc->rx_bm_base_psn,
		    pdc_pkt->pkt_pp.pds_clear_psn,
		    pdc_pkt->pkt_pp.pds_psn,
		    (pdc_pkt->pkt_pp.pds_psn - pdc->rx_bm_base_psn));

	if (!bm_set(pdc->rx_bm,
		    (pdc_pkt->pkt_pp.pds_psn - pdc->rx_bm_base_psn),
		    pdc_pkt)) {
		UET_PDS_ERR("PDC %u cannot track RX PSN %u",
			    pdc->pdc_id, pdc_pkt->pkt_pp.pds_psn);
		rc = -ERANGE;
		goto exit_err;
	}

	if (UET_LOG_LVL >= UET_LOG_DBG) {
		UET_PDS_DBG("PDC %d rx_bm (base %u):",
			    pdc->pdc_id, pdc->rx_bm_base_psn);
		bm_print_bits(pdc->rx_bm, uet_pdc_rx_bit_char);
	}

	rc = uet_pds_process_data_pkt(uet, pdc, pdc_pkt);
	if (rc != 0) {
		bm_unset(pdc->rx_bm,
			 (pdc_pkt->pkt_pp.pds_psn - pdc->rx_bm_base_psn));
		goto exit_err;
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
	bool pkt_is_ack, pkt_is_rd_rsp, pkt_is_ctrl, pkt_is_nack;
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
				&pkt_is_ctrl,
				&pkt_is_nack)) {
		UET_PDS_WARN("invalid Rx packet (len=%ld)", pkt_len);
		rc = -EINVAL;
		goto exit;
	}

	/* parse the packet */
	rc = uet_parse_pkt(uet, pkt, pkt_len, &pp);
	if (rc != 0) {
		UET_PDS_ERR("malformed Rx packet");
		goto exit;
	}

	if (!pp.sec) {
		/* calculate the CRC (include src/dst IP and UDP) */
		if (pp.is_ipv6) {
			crc_start = ((uint8_t *)pp.ip + 8);
			crc = crc32c(crc_start,
				     (32 + pp.ip_payload_len - CRC_LEN));
		} else {
			crc_start = ((uint8_t *)pp.ip + 12);
			crc = crc32c(crc_start,
				     (8 + pp.ip_payload_len - CRC_LEN));
		}

		/* verify the CRC */
		if (memcmp(&crc,
			   ((uint8_t *)pp.ip + pp.ip_len +
			    pp.ip_payload_len - CRC_LEN),
			   CRC_LEN) != 0) {
			UET_PDS_WARN("Rx packet CRC mismatch");
			rc = -EINVAL;
			goto exit;
		}
	}

	uet_pds_pkt_dbg(uet, &pp, false, "RX PACKET");

	/* RUDI is connectionless and demuxed here by pds_type. The RUDI
	 * engine takes ownership of pkt.
	 */
	if ((pp.pds_type == UET_PDS_TYPE_RUDI_REQ) ||
	    (pp.pds_type == UET_PDS_TYPE_RUDI_RESP))
		return uet_pds_rudi_rx(uet, &pp, pkt, pkt_len);

	/* UUD is connectionless and demuxed here by pds_type. The UUD
	 * engine takes ownership of pkt.
	 */
	if (pp.pds_type == UET_PDS_TYPE_UUD_REQ)
		return uet_pds_uud_rx(uet, &pp, pkt, pkt_len);

	if (pkt_is_ack) {

		rc = uet_pds_process_ack(uet, &pp);

	} else if (pkt_is_nack) {

		rc = uet_pds_process_nack(uet, &pp);

	} else if (pkt_is_ctrl) {

		rc = uet_pds_process_control(uet, &pp, pkt, pkt_len);

	} else { /* request packet */

		rc = uet_pds_process_request(uet, &pp, pkt, pkt_len);
		if (rc == 0)
			return 0;

	}

exit:
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
