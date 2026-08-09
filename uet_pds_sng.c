/*
 * Copyright (c) 2024,2025,2026 Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* SES-PDS APIs */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/if_ether.h>

#include "uet_pkt_hdr.h"
#include "uet_api.h"
#include "uet_pds.h"
#include "uet_api_private.h"
#include "uet_pkt_chk.h"
#include "uet_nic.h"
#include "crc32c.h"

/* pds transmit state */
struct uet_pds_sng_tx_state {
	bool tx_active;      /* transmit in progress */
	uint32_t psn;        /* next pkt sequence number */
	time_t start_time;   /* tx start time for detecting timeout */
	int    retry_cnt;    /* number of tx retransmissions */
	struct {             /* parms needed for pkt retransmit */
		uet_pkt_handle_t tx_pkt_handle;
		uint64_t pkt_cnt;
		uet_addr_handle_t dst_addr_handle;
		uet_pds_mode_t mode;
		uet_pds_tx_flags_t flags;
		bool pds_info_valid;
		struct uet_pds_info pds_info;
		uint16_t msg_id;
		uet_pds_next_hdr_t next_hdr;
		void *pkt;
		size_t pkt_len;
		bool dma_rdy;
		uint8_t ses_hdr[UET_MAX_SES_HDR_BYTES];
		size_t ses_hdr_len;
	} pkt_parms;
};

/* pds state structure                                                 */
/*   - embedded in uet_ep struct                                       */
/*   - will be removed from uet_ep struct when real pds is implemented */
struct uet_pds_sng_state {
	struct dlist_entry ack_state_list_head;
	struct uet_pds_sng_tx_state tx;
};

/*
 * overlay struct for fields in pds headers
 *
 * the stop-and-go reliability layer is simpler if the sequence number
 * state is maintained between endpoints (rather than between
 * FEPs as is done in the real pds reliability layer), so to enable that
 * a couple of fields in the pds headers are repurposed as follows:
 *
 *   - the spdcid field is repurposed to carry the pid_on_fep of the
 *     source endpoint that sent the request
 *   - the dpdcid field is repurposed to carry the index of the
 *     source endpoint that sent the request
 *
 * the fields are repurposed in both the pds request and the pds ack headers
 */
struct UET_PACKED uet_pds_hdr_overlay {
	uint16_t pid_on_fep;
	uint16_t index;
};

/* pds ack state */
struct uet_pds_ack_state {
	struct dlist_entry list_entry; /* for list of ack's sent */
	time_t ack_time;               /* time ack was sent */
	size_t ack_len;                /* length of ack pkt in bytes */
	uint8_t ack[];                 /* ack packet that was sent */
};

/* determine if tx is active for an endpoint */
static bool uet_pds_ep_tx_active(struct uet_ep *uet_ep)
{
	struct uet_pds_sng_state *pds_state =
		(struct uet_pds_sng_state *)uet_ep->pds;

	return pds_state->tx.tx_active;
}

/* determine the address family from a received frame's ethertype */
static inline bool uet_pkt_is_ipv6(const void *pkt)
{
	const struct ethhdr *eth = (const struct ethhdr *)pkt;

	return (eth->h_proto == htons(ETH_P_IPV6));
}

/* determine if pkt is destined for endpoint */
static bool uet_pds_ep_addr_match(
	struct uet_ep *uet_ep, void *pkt, bool pkt_is_ack,
	bool pkt_is_rd_rsp, struct uet_msg_match_info *match_info)
{
	uint16_t msg_id, pid_on_fep, index;
	uint32_t job_id;
	struct uet_pds_sng_state *pds_state =
		(struct uet_pds_sng_state *)uet_ep->pds;
	struct uet_rx_desc *rx_desc;
	struct uet_instance *uet = uet_ep->uet_domain->uet;
	bool is_ipv6 = uet_pkt_is_ipv6(pkt);
	size_t ip_hdr_size = (is_ipv6) ? sizeof(struct ipv6hdr) :
					 sizeof(struct iphdr);

	if (is_ipv6) {
		struct ipv6hdr *ipv6 =
			(struct ipv6hdr *)((uint8_t *)pkt +
					   sizeof(struct ethhdr));
		if (memcmp(&ipv6->daddr, uet->nic.ipv6_addr, 16) != 0)
			return false;
	} else {
		struct iphdr *ipv4 =
			(struct iphdr *)((uint8_t *)pkt +
					 sizeof(struct ethhdr));
		if (ntohl(ipv4->daddr) != uet->nic.ipv4_addr)
			return false;
	}

	match_info->ip_addr_match = true;

	if (pkt_is_ack) {
		struct uet_ses_rsp *ses_rsp =
			(struct uet_ses_rsp *)((uint8_t *)pkt +
					       sizeof(struct ethhdr) +
					       ip_hdr_size +
					       sizeof(struct uet_entropy) +
					       sizeof(struct uet_pds_ack));

		if (!pds_state->tx.tx_active)
			return false;

		job_id = ((ntohl(ses_rsp->cmn.ri_gen_job_id) &
			   UET_SES_RSP_JOB_ID_MASK) >>
			  UET_SES_RSP_JOB_ID_SHIFT);
		if (job_id != uet_ep->job_id)
			return false;
		match_info->job_id_match = true;

		msg_id = ntohs(ses_rsp->cmn.msg_id);
		if (msg_id != pds_state->tx.pkt_parms.msg_id)
			return false;
		match_info->msg_id_match = true;
	} else if (pkt_is_rd_rsp) {
		struct uet_ses_rsp_d *ses_rsp_d =
			(struct uet_ses_rsp_d *)((uint8_t *)pkt +
						 sizeof(struct ethhdr) +
						 ip_hdr_size +
						 sizeof(struct uet_entropy) +
						 sizeof(struct uet_pds_ack));

		job_id = ((ntohl(ses_rsp_d->cmn.ri_gen_job_id) &
			   UET_SES_RSP_JOB_ID_MASK) >>
			  UET_SES_RSP_JOB_ID_SHIFT);
		if (job_id != uet_ep->job_id)
			return false;
		match_info->job_id_match = true;

		match_info->pid_on_fep_match = true;
		match_info->index_match = true;

		msg_id = ntohs(ses_rsp_d->cmn.msg_id);
		rx_desc = uet->msg_id_cb.rx_desc[msg_id];
		if (rx_desc == NULL)
			return false;
		if (rx_desc->uet_ep != uet_ep)
			return false;
		match_info->msg_id_match = true;
	} else {
		struct uet_ses_req_std *ses_req =
			(struct uet_ses_req_std *)((uint8_t *)pkt +
						   sizeof(struct ethhdr) +
						   ip_hdr_size +
						   sizeof(struct uet_entropy) +
						   sizeof(struct uet_pds_req));

		job_id = ((ntohl(ses_req->cmn.ri_gen_job_id) &
			   UET_SES_REQ_JOB_ID_MASK) >>
			  UET_SES_REQ_JOB_ID_SHIFT);
		if (job_id != uet_ep->job_id)
			return false;
		match_info->job_id_match = true;

		pid_on_fep = ((ntohs(ses_req->cmn.rsvd_pid_on_fep) &
			       UET_SES_REQ_PID_ON_FEP_MASK) >>
			      UET_SES_REQ_PID_ON_FEP_SHIFT);
		if (pid_on_fep != uet_ep->uet_addr.pid_on_fep)
			return false;
		match_info->pid_on_fep_match = true;

		index = ((ntohs(ses_req->cmn.rsvd_res_index) &
			  UET_SES_REQ_RES_INDEX_MASK) >>
			 UET_SES_REQ_RES_INDEX_SHIFT);
		if (index != uet_ep->uet_addr.start_index)
			return false;
		match_info->index_match = true;
	}

	return true;
}

/* find endpoint that packet is destined for */
static struct uet_ep *uet_pds_find_dst_ep(
	struct uet_instance *uet, void *pkt, bool pkt_is_ack,
	bool pkt_is_rd_rsp, struct uet_msg_match_info *match_info)
{
	struct dlist_entry *dom_head, *dom_item, *ep_head, *ep_item;
	struct uet_domain *uet_dom;
	struct uet_ep *uet_ep;

	dom_head = &uet->domain_list_head;
	dlist_foreach(dom_head, dom_item) {
		uet_dom = container_of(dom_item, struct uet_domain,
				       domain_list_entry);
		uet_rw_lock(&uet_dom->ep_lock, UET_RW_LOCK_RD_ACCESS);
		ep_head = &uet_dom->ep_list_head;
		dlist_foreach(ep_head, ep_item) {
			uet_ep = container_of(ep_item, struct uet_ep,
					      ep_list_entry);
			if (uet_pds_ep_addr_match(uet_ep, pkt, pkt_is_ack,
						  pkt_is_rd_rsp, match_info)) {
				uet_rw_unlock(&uet_dom->ep_lock,
					      UET_RW_LOCK_RD_ACCESS);
				return uet_ep;
			}
		}
		uet_rw_unlock(&uet_dom->ep_lock, UET_RW_LOCK_RD_ACCESS);
	}

	return NULL;
}

/* determine if pds request is a duplicate that has already been received */
static bool uet_pds_is_dup_req(struct uet_ep *uet_ep, void *pkt,
			       struct uet_pds_ack_state **dup_ack_state)
{
	struct dlist_entry *head, *item, *tmp;
	struct uet_pds_ack_state *ack_state;
	struct uet_pds_hdr_overlay *ack_overlay, *pkt_overlay;
	time_t now;
	struct uet_pds_sng_state *pds_state =
		(struct uet_pds_sng_state *) uet_ep->pds;
	struct uet_instance *uet = uet_ep->uet_domain->uet;
	bool is_ipv6 = uet_pkt_is_ipv6(pkt);
	size_t ip_hdr_size = (is_ipv6) ? sizeof(struct ipv6hdr) :
					 sizeof(struct iphdr);
	/* PDS spdcid offset from start of packet */
	size_t pds_spdcid_off = (sizeof(struct ethhdr) +
				 ip_hdr_size +
				 sizeof(struct uet_entropy) +
				 sizeof(struct uet_pds_prlg) +
				 sizeof(uint16_t) + /* clear/ack_psn_offset */
				 sizeof(uint32_t)); /* psn */
	/* PDS psn offset from start of packet */
	size_t pds_psn_off = (sizeof(struct ethhdr) +
			      ip_hdr_size +
			      sizeof(struct uet_entropy) +
			      sizeof(struct uet_pds_prlg) +
			      sizeof(uint16_t)); /* clear/ack_psn_offset */
	uint8_t *ack;

	*dup_ack_state = NULL;
	uet_gettime(&now);

	head = &pds_state->ack_state_list_head;
	dlist_foreach_safe(head, item, tmp) {
		uint32_t *ack_psn, *pkt_psn;
		bool ip_match;

		ack_state = container_of(item, struct uet_pds_ack_state,
					 list_entry);
		ack = ack_state->ack;
		ack_overlay =
			(struct uet_pds_hdr_overlay *)((uint8_t *)ack +
						       pds_spdcid_off);
		pkt_overlay =
			(struct uet_pds_hdr_overlay *)((uint8_t *)pkt +
						       pds_spdcid_off);
		ack_psn = (uint32_t *)((uint8_t *)ack + pds_psn_off);
		pkt_psn = (uint32_t *)((uint8_t *)pkt + pds_psn_off);

		if (is_ipv6) {
			struct ipv6hdr *ack_ip =
				(struct ipv6hdr *)((uint8_t *)ack +
						   sizeof(struct ethhdr));
			struct ipv6hdr *pkt_ip =
				(struct ipv6hdr *)((uint8_t *)pkt +
						   sizeof(struct ethhdr));
			ip_match = (memcmp(&ack_ip->daddr,
					   &pkt_ip->saddr, 16) == 0);
		} else {
			struct iphdr *ack_ipv4 =
				(struct iphdr *)(ack +
						 sizeof(struct ethhdr));
			struct iphdr *pkt_ipv4 =
				(struct iphdr *)((uint8_t *)pkt +
						 sizeof(struct ethhdr));
			ip_match = (ack_ipv4->daddr == pkt_ipv4->saddr);
		}

		if (ip_match &&
		    (ack_overlay->pid_on_fep == pkt_overlay->pid_on_fep) &&
		    (ack_overlay->index == pkt_overlay->index)) {
			if (*ack_psn == *pkt_psn) {
				*dup_ack_state = ack_state;
				return true;
			}
			/* free saved ack, sender has received it and */
			/* moved on to a new psn                      */
			dlist_remove(item);
			free(ack_state);
			return false;
		}
		/* check if ack should be aged out */
		if ((now - ack_state->ack_time) >
		    uet_ep->uet_domain->uet->pds.msl) {
			dlist_remove(item);
			free(ack_state);
		}
	}

	return false;
}

/*
 * build a uet ack packet
 *
 * parms:
 *      uet         - ptr to uet instance struct
 *      pkt         - ptr to packet that is being acknowledged
 *      ack         - ptr to buffer where ack packet is to be built
 *      ack_pkt_len - size of ack packet in bytes
 *      next_hdr    - ses header format identifier
 *      ses_hdr_len - length of ses header in bytes
 *      ses_hdr     - ptr to ses header
 */
static void uet_pds_build_ack_pkt(struct uet_instance *uet, void *pkt,
				  void *ack, uint16_t ack_pkt_len,
				  uet_pds_next_hdr_t next_hdr,
				  size_t ses_hdr_len, void *ses_hdr)
{
	bool is_ipv6 = uet_pkt_is_ipv6(pkt);
	size_t ip_hdr_size = (is_ipv6) ? sizeof(struct ipv6hdr) :
					 sizeof(struct iphdr);
	void *ack_ip = (uint8_t *)ack + sizeof(struct ethhdr);
	struct uet_pds_ack *ack_pds =
		(struct uet_pds_ack *)((uint8_t *)ack +
				       sizeof(struct ethhdr) +
				       ip_hdr_size +
				       sizeof(struct uet_entropy));
	struct uet_pds_req *pkt_pds =
		(struct uet_pds_req *)((uint8_t *)pkt +
				       sizeof(struct ethhdr) +
				       ip_hdr_size +
				       sizeof(struct uet_entropy));
	struct uet_pds_hdr_overlay *pkt_overlay, *ack_overlay;
	void *ack_ses = (uint8_t *)(ack_pds + 1);
	struct uet_entropy *ack_entropy =
		(struct uet_entropy *)((uint8_t *)ack +
				       sizeof(struct ethhdr) +
				       ip_hdr_size);

	/* copy entropy from request */
	ack_entropy->entropy =
		((struct uet_entropy *)((uint8_t *)pkt +
					sizeof(struct ethhdr) +
					ip_hdr_size))->entropy;

	uet_build_eth_hdr((struct ethhdr *)ack,
			  ((struct ethhdr *)pkt)->h_source,
			  ((struct ethhdr *)pkt)->h_dest, is_ipv6);

	if (is_ipv6) {
		struct ipv6hdr *pkt_ipv6 =
			(struct ipv6hdr *)((uint8_t *)pkt +
					   sizeof(struct ethhdr));
		uet_build_ipv6_hdr(uet,
				   (struct ipv6hdr *)ack_ip,
				   (const uint8_t *)&pkt_ipv6->saddr,
				   (const uint8_t *)&pkt_ipv6->daddr,
				   (ack_pkt_len - uet->nic.l2_hdr_size -
				    ip_hdr_size),
				   uet->pds.ack_ip_tos, true);
	} else {
		struct iphdr *pkt_ipv4 =
			(struct iphdr *)((uint8_t *)pkt +
					 sizeof(struct ethhdr));
		uet_build_ipv4_hdr(uet,
				   (struct iphdr *)ack_ip,
				   pkt_ipv4->saddr,
				   pkt_ipv4->daddr,
				   (ack_pkt_len -
				    (uint16_t)uet->nic.l2_hdr_size),
				   uet->pds.ack_ip_tos, true);
	}

	ack_pds->prlg.type_next_flags =
		htons((UET_PDS_TYPE_ACK << UET_PDS_TYPE_SHIFT) |
		      (next_hdr << UET_PDS_NEXT_HDR_SHIFT) |
		      (UET_PDS_ACK_FLAGS_NONE << UET_PDS_FLAGS_SHIFT));
	ack_pds->cack_psn = pkt_pds->psn;
	pkt_overlay = (struct uet_pds_hdr_overlay *)&pkt_pds->spdcid;
	ack_overlay = (struct uet_pds_hdr_overlay *)&ack_pds->spdcid;
	ack_overlay->pid_on_fep = pkt_overlay->pid_on_fep;
	ack_overlay->index = pkt_overlay->index;

	memcpy(ack_ses, ses_hdr, ses_hdr_len);
}

/*
 * build and transmit a uet ack packet
 *
 * parms:
 *      uet_ep      - ptr to uet endpoint struct
 *      pkt         - ptr to packet that is being acknowledged
 *      next_hdr    - ses header format identifier
 *      ses_hdr_len - length of ses header in bytes
 *      ses_hdr     - ptr to ses header
 *
 * returns:
 *      0 on success,
 *      negative value corresponding to errno on error
 */
static int uet_pds_tx_ack_pkt(struct uet_ep *uet_ep, void *pkt,
			      uet_pds_next_hdr_t next_hdr, size_t ses_hdr_len,
			      void *ses_hdr)
{
	int rc;
	uint16_t ack_pkt_len, ack_data_len;
	time_t now;
	struct uet_instance *uet;
	struct uet_pds_ack_state *ack_state;
	struct uet_pds_sng_state *pds_state =
		(struct uet_pds_sng_state *)uet_ep->pds;
	uint8_t *ack;
	uint32_t crc;
	uint8_t *crc_start;
	bool is_ipv6;
	size_t ip_hdr_size;

	uet = uet_ep->uet_domain->uet;
	is_ipv6 = uet_pkt_is_ipv6(pkt);
	ip_hdr_size = (is_ipv6) ? sizeof(struct ipv6hdr) :
				  sizeof(struct iphdr);

	if (next_hdr == UET_HDR_RSP)
		ack_pkt_len = (sizeof(struct ethhdr) +
			       ip_hdr_size +
			       sizeof(struct uet_entropy) +
			       sizeof(struct uet_pds_ack) +
			       sizeof(struct uet_ses_rsp));
	else {
		ack_data_len = (ses_hdr_len - sizeof(struct uet_ses_rsp_d));
		ack_pkt_len = (sizeof(struct ethhdr) +
			       ip_hdr_size +
			       sizeof(struct uet_entropy) +
			       sizeof(struct uet_pds_ack) +
			       sizeof(struct uet_ses_rsp_d) +
			       ack_data_len);
	}

	/* allocate buffer for ack packet */
	ack_state = calloc(1, sizeof(struct uet_pds_ack_state) + ack_pkt_len +
			      CRC_LEN);
	if (ack_state == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		return -ENOMEM;
	}
	ack = ack_state->ack;
	ack_state->ack_len = ack_pkt_len;

	/* build ack packet */
	uet_pds_build_ack_pkt(uet, pkt, ack, ack_pkt_len, next_hdr,
			      ses_hdr_len, ses_hdr);

	/* calculate the CRC (include src/dst IP) */
	if (is_ipv6)
		crc_start = (ack + sizeof(struct ethhdr) + 8);
	else
		crc_start = (ack + sizeof(struct ethhdr) + 12);
	crc = crc32c(crc_start, (ack_pkt_len - (crc_start - ack)));

	/* append the CRC and adjust the transmit length */
	memcpy((ack + ack_pkt_len), &crc, CRC_LEN);
	ack_pkt_len += CRC_LEN;

	/* send ack packet */
	UET_PDS_PKT_HDR_TRACE(uet, NULL, ack, ack_pkt_len, "TX ACK PACKET");
	rc = uet_nic_tx_pkt(UET_NIC(uet), ack,
			    (ack + sizeof(struct ethhdr)),
			    (size_t) ack_pkt_len);
	if (rc == 0) {
		uet_gettime(&now);
		ack_state->ack_time = now;
		dlist_insert_head(&ack_state->list_entry,
				  &pds_state->ack_state_list_head);
	} else
		free(ack_state);

	return rc;
}

/*
 * build and transmit a uet ack packet with ses error code,
 * specifically for case where the packet is not deliverable because
 * there is no endpoint with the uet address in the request
 *
 * parms:
 *      uet    - ptr to uet instance struct
 *      pkt    - ptr to packet that is being acknowledged with ses err
 *      ses_rc - ses return code
 *
 * returns:
 *      0 on success,
 *      negative value corresponding to errno on error
 */
static int uet_pds_tx_err_ack_pkt(struct uet_instance *uet,
				  void *pkt, struct uet_parsed_pkt *pp,
				  uet_ses_rc_t ses_rc)
{
	int rc;
	uint16_t ack_pkt_len;
	uint8_t *ack;
	struct uet_ses_rsp ses;
	struct uet_ses_req_std *pkt_ses;
	uint32_t crc;
	uint8_t *crc_start;
	bool is_ipv6 = pp->is_ipv6;
	size_t ip_hdr_size = (is_ipv6) ? sizeof(struct ipv6hdr) :
					 sizeof(struct iphdr);

	ack_pkt_len = (sizeof(struct ethhdr) +
		       ip_hdr_size +
		       sizeof(struct uet_entropy) +
		       sizeof(struct uet_pds_ack) +
		       sizeof(struct uet_ses_rsp));

	/* allocate buffer for ack packet */
	ack = calloc(1, ack_pkt_len + CRC_LEN);
	if (ack == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		return -ENOMEM;
	}

	/* build ses header */
	pkt_ses = (struct uet_ses_req_std *)pp->ses;
	ses.cmn.list_opcode = ((UET_EXPECTED << UET_SES_RSP_LIST_SHIFT) |
			       (UET_RESPONSE << UET_SES_OPCODE_SHIFT));
	ses.cmn.ver_ret_code = ((UET_SES_VER << UET_SES_VER_SHIFT) |
				(ses_rc << UET_SES_RSP_RET_CODE_SHIFT));
	ses.cmn.msg_id = pkt_ses->cmn.msg_id;
	ses.mod_len = 0;
	ses.cmn.ri_gen_job_id = pkt_ses->cmn.ri_gen_job_id;

	/* build ack packet */
	uet_pds_build_ack_pkt(uet, pkt, ack, ack_pkt_len,
			      UET_HDR_RSP, sizeof(struct uet_ses_rsp), &ses);

	/* calculate the CRC (include src/dst IP) */
	if (is_ipv6)
		crc_start = (ack + sizeof(struct ethhdr) + 8);
	else
		crc_start = (ack + sizeof(struct ethhdr) + 12);
	crc = crc32c(crc_start, (ack_pkt_len - (crc_start - ack)));

	/* append the CRC and adjust the transmit length */
	memcpy((ack + ack_pkt_len), &crc, CRC_LEN);
	ack_pkt_len += CRC_LEN;

	/* send ack packet */
	UET_PDS_PKT_HDR_TRACE(uet, NULL, ack, ack_pkt_len, "TX ACK PACKET");
	rc = uet_nic_tx_pkt(UET_NIC(uet), ack,
			    (ack + sizeof(struct ethhdr)),
			    (size_t)ack_pkt_len);
	free(ack);
	return rc;
}

/*********************************************************************
 * Below functions implement SES-PDS APIs
 *********************************************************************/

/* init pds resources for uet instance */
int uet_pds_sng_initialize(struct uet_instance *uet)
{
	uet->pds.tx_timeout = UET_DEFAULT_TX_TIMEOUT;
	uet->pds.max_tx_retries = UET_DEFAULT_MAX_TX_RETRIES;
	uet->pds.msl = UET_DEFAULT_MSL;
	uet->pds.ack_ip_tos = uet_dscp_to_tos(UET_IP_DEFAULT_ACK_DSCP);
	uet->pds.max_ack_data = UET_DEFAULT_PDS_MAX_ACK_DATA;
	return 0;
}

/* free pds resources for uet instance */
void uet_pds_sng_finalize(struct uet_instance *uet)
{
}

/* init pds resources for endpoint */
int uet_pds_sng_ep_initialize(struct uet_ep *uet_ep)
{
	struct uet_pds_sng_state *pds_state;

	pds_state = calloc(1, sizeof(struct uet_pds_sng_state));
	if (pds_state == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		return -ENOMEM;
	}

	uet_ep->pds = pds_state;

	dlist_init(&pds_state->ack_state_list_head);
	return 0;
}

/* free pds resources for endpoint */
void uet_pds_sng_ep_finalize(struct uet_ep *uet_ep)
{
	struct dlist_entry *head, *item;
	struct uet_pds_ack_state *pds_rx;
	struct uet_pds_sng_state *pds_state =
		(struct uet_pds_sng_state *)uet_ep->pds;

	head = &pds_state->ack_state_list_head;
	dlist_foreach(head, item) {
		pds_rx = container_of(item, struct uet_pds_ack_state,
				      list_entry);
		dlist_remove(item);
		item = head;
		free(pds_rx);
	}

	free(pds_state);
	uet_ep->pds = NULL;
}

/* pds packet transmission */
int uet_pds_sng_tx_pkt(uet_pkt_handle_t tx_pkt_handle, uint64_t pkt_cnt,
		       struct uet_ep *uet_ep,
		       uet_addr_handle_t dst_addr_handle, uet_pds_mode_t mode,
		       uet_pds_tx_flags_t flags, struct uet_pds_info *pds_info,
		       uint16_t msg_id, uet_pds_next_hdr_t next_hdr, void *ses,
		       size_t ses_len, void *pkt, size_t pkt_len, bool dma_rdy)
{
	int rc;
	uint8_t tos;
	size_t uet_hdr_len, uet_pkt_len;
	void *ses_hdr, *payload;
	uet_pds_pkt_type_t pds_pkt_type;
	struct uet_instance *uet;
	uint8_t *uet_pkt;
	struct uet_av_entry *av_entry;
	struct uet_addr *dst_addr;
	struct uet_pds_req *pds;
	struct uet_pds_sng_tx_state *state;
	struct uet_pds_hdr_overlay *pds_overlay;
	struct uet_pds_sng_state *pds_state =
		(struct uet_pds_sng_state *)uet_ep->pds;
	uint32_t crc;
	uint8_t *crc_start;
	void *ip_hdr;
	bool is_ipv6;
	size_t ip_hdr_size;

	uet = uet_ep->uet_domain->uet;
	av_entry = (struct uet_av_entry *) dst_addr_handle;
	dst_addr = av_entry->addr;
	state = &pds_state->tx;
	is_ipv6 = uet_addr_is_ipv6(dst_addr);
	ip_hdr_size = (is_ipv6) ? sizeof(struct ipv6hdr) :
				  sizeof(struct iphdr);

	/* done for now if transmit in progress and not retry */
	if (uet_pds_ep_tx_active(uet_ep) &&
	    !(flags & UET_PDS_FLAG_RETRANSMIT))
		return -EAGAIN;

	/* allocate buffer to build packet   */
	/* TODO: add support for gather send */
	uet_pkt = calloc(1, uet->nic.max_pkt_size);
	if (uet_pkt == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		return -ENOMEM;
	}

	uet_build_eth_hdr((struct ethhdr *)uet_pkt, av_entry->nh_mac_addr,
			  uet->nic.mac_addr, is_ipv6);

	switch (next_hdr) {
	case UET_HDR_REQ_STD:
	case UET_HDR_RSP_DATA:
		switch (mode) {
		case UET_PDS_MODE_ROD:
			pds_pkt_type = UET_PDS_TYPE_ROD_REQ;
			break;
		case UET_PDS_MODE_RUD:
			pds_pkt_type = UET_PDS_TYPE_RUD_REQ;
			break;
		default:
			UET_API_ERR("Unsupported packet delivery mode = %d",
				    mode);
			return -EINVAL;
		}

		uet_hdr_len = (sizeof(struct ethhdr) +
			       ip_hdr_size +
			       sizeof(struct uet_entropy) +
			       sizeof(struct uet_pds_req) +
			       ses_len);

		pds = (struct uet_pds_req *)(uet_pkt +
					     sizeof(struct ethhdr) +
					     ip_hdr_size +
					     sizeof(struct uet_entropy));
		ses_hdr = (void *)(pds + 1);
		payload = ((uint8_t *)ses_hdr + ses_len);
		pds->prlg.type_next_flags =
			htons((pds_pkt_type << UET_PDS_TYPE_SHIFT) |
			      (UET_PDS_REQ_FLAGS_AR << UET_PDS_FLAGS_SHIFT) |
			      (next_hdr << UET_PDS_NEXT_HDR_SHIFT));
		if (flags & UET_PDS_FLAG_RETRANSMIT)
			pds->prlg.type_next_flags |= htons(
				(UET_PDS_REQ_FLAGS_RETX << UET_PDS_FLAGS_SHIFT));
		pds->psn = htonl(pds_state->tx.psn);
		pds_overlay = (struct uet_pds_hdr_overlay *) &pds->spdcid;
		pds_overlay->pid_on_fep = htons(uet_ep->uet_addr.pid_on_fep);
		pds_overlay->index = htons(uet_ep->uet_addr.start_index);

		tos = uet_ep->msg_ip_tos;

		uet_pkt_len = pkt_len + uet_hdr_len;
		break;
	default:
		UET_API_ERR("Unsupported next header type  = %d", next_hdr);
		return -EINVAL;
	};

	ip_hdr = (void *)(uet_pkt + sizeof(struct ethhdr));
	if (is_ipv6) {
		uint16_t payload_len = (uint16_t)(pkt_len +
						  (uet_hdr_len -
						   uet->nic.l2_hdr_size -
						   ip_hdr_size));
		uet_build_ipv6_hdr(uet, (struct ipv6hdr *)ip_hdr,
				   dst_addr->fa.v6,
				   uet->nic.ipv6_addr,
				   payload_len, tos, true);
	} else {
		uint16_t tot_len = (uint16_t)(pkt_len +
					      (uet_hdr_len -
					       uet->nic.l2_hdr_size));
		uet_build_ipv4_hdr(uet, (struct iphdr *)ip_hdr,
				   htonl(dst_addr->fa.v4),
				   htonl(uet->nic.ipv4_addr),
				   tot_len, tos, true);
	}

	if (!(flags & UET_PDS_FLAG_RETRANSMIT)) {
		memcpy(state->pkt_parms.ses_hdr, ses, ses_len);
		state->pkt_parms.ses_hdr_len = ses_len;
	}
	memcpy(ses_hdr, ses, ses_len);

	memcpy(payload, pkt, pkt_len);

	if (!(flags & UET_PDS_FLAG_RETRANSMIT))
		pds_state->tx.retry_cnt = 0;

	uet_gettime(&pds_state->tx.start_time);

	/* save parms needed for pkt retransmission */
	state->pkt_parms.tx_pkt_handle = tx_pkt_handle;
	state->pkt_parms.pkt_cnt = pkt_cnt;
	state->pkt_parms.dst_addr_handle = dst_addr_handle;
	state->pkt_parms.mode = mode;
	state->pkt_parms.flags = flags;
	if (pds_info) {
		state->pkt_parms.pds_info_valid = true;
		state->pkt_parms.pds_info = *pds_info;
	} else
		state->pkt_parms.pds_info_valid = false;
	state->pkt_parms.msg_id = msg_id;
	state->pkt_parms.next_hdr = next_hdr;
	state->pkt_parms.pkt = pkt;
	state->pkt_parms.pkt_len = pkt_len;
	state->pkt_parms.dma_rdy = dma_rdy;

	/* calculate the CRC (include src/dst IP) */
	if (is_ipv6)
		crc_start = (uet_pkt + sizeof(struct ethhdr) + 8);
	else
		crc_start = (uet_pkt + sizeof(struct ethhdr) + 12);
	crc = crc32c(crc_start, (uet_pkt_len - (crc_start - uet_pkt)));

	/* append the CRC and adjust the transmit length */
	memcpy(((uint8_t *)uet_pkt + uet_pkt_len), &crc, CRC_LEN);
	uet_pkt_len += CRC_LEN;

	UET_PDS_PKT_HDR_TRACE(uet, NULL, uet_pkt, uet_pkt_len, "TX PACKET");
	rc = uet_nic_tx_pkt(UET_NIC(uet), uet_pkt,
			    (uet_pkt + sizeof(struct ethhdr)),
			    uet_pkt_len);
	if (rc == 0)
		pds_state->tx.tx_active = true;
	free(uet_pkt);
	return rc;
}

/* indicate message completion */
int uet_pds_sng_msg_cmpl_ind(struct uet_ep *uet_ep,
			     uet_addr_handle_t dst_addr_handle,
			     uet_pds_mode_t mode, uint16_t msg_id)
{
	return 0;
}

/* progress tx operations for endpoint */
int uet_pds_sng_progress_tx(struct uet_ep *uet_ep,
			    uet_pkt_handle_t *err_pkt_handle)
{
	struct uet_instance *uet;
	struct uet_pds_sng_tx_state *pds_tx;
	struct uet_pds_info *pds_info;
	time_t now, delta;
	struct uet_pds_sng_state *pds_state =
		(struct uet_pds_sng_state *)uet_ep->pds;

	uet = uet_ep->uet_domain->uet;

	/* check if tx is active on endpoint */
	if (!uet_pds_ep_tx_active(uet_ep))
		return -EAGAIN;

	pds_tx = &pds_state->tx;
	*err_pkt_handle = pds_tx->pkt_parms.tx_pkt_handle;

	/* check if packet retransmission is needed */
	uet_gettime(&now);
	delta = now - pds_tx->start_time;
	if (delta < uet->pds.tx_timeout)
		return 0;

	if (pds_tx->retry_cnt >= uet->pds.max_tx_retries) {
		/* retries exhausted */
		pds_state->tx.tx_active = false;
		return -EIO;
	}

	/* retransmit the packet */
	pds_tx->retry_cnt++;
	uet_gettime(&pds_tx->start_time);
	if (pds_tx->pkt_parms.pds_info_valid)
		pds_info = &pds_tx->pkt_parms.pds_info;
	else
		pds_info = NULL;
	return uet->pds.downcall.tx_pkt(pds_tx->pkt_parms.tx_pkt_handle,
	                                pds_tx->pkt_parms.pkt_cnt,
					uet_ep,
					pds_tx->pkt_parms.dst_addr_handle,
					pds_tx->pkt_parms.mode,
					(pds_tx->pkt_parms.flags |
					 UET_PDS_FLAG_RETRANSMIT),
					pds_info,
					pds_tx->pkt_parms.msg_id,
					pds_tx->pkt_parms.next_hdr,
					pds_tx->pkt_parms.ses_hdr,
					pds_tx->pkt_parms.ses_hdr_len,
					pds_tx->pkt_parms.pkt,
					pds_tx->pkt_parms.pkt_len,
					pds_tx->pkt_parms.dma_rdy);
}

/* find endpoint via restart token lookup */
static struct uet_ep *uet_pds_rtr_lookup(struct uet_instance *uet,
					 struct uet_parsed_pkt *pp)
{
	uint32_t local_token;
	uint64_t full_token;
	struct uet_ses_req_std *ses;
	struct uet_tx_desc *tx_desc;

	ses = (struct uet_ses_req_std *) pp->ses;

	full_token = ntohll(ses->restart_token_rtr);
	local_token = (full_token & UET_SES_REQ_STD_DST_TOKEN_MASK) >>
		UET_SES_REQ_STD_DST_TOKEN_SHIFT;

	if (local_token > UET_MAX_RTR_TOKEN)
		goto err_exit;

	tx_desc = uet->tx_rtr_token_cb.tx_desc[local_token];
	if (tx_desc == NULL)
		goto err_exit;

	return tx_desc->uet_ep;

err_exit:
	return NULL;

}

/* progress rx operations */
int uet_pds_sng_progress_rx(struct uet_instance *uet)
{
	int rc;
	uet_ses_rc_t ses_rc;
	size_t rx_pkt_size;
	bool pkt_is_ack, pkt_is_rd_rsp, pkt_is_ctrl, pkt_is_nack;
	bool ses_nack, gtd_del;
	uint8_t *pkt;
	struct uet_parsed_pkt pp;
	struct uet_ep *dst_uet_ep;
	struct uet_msg_match_info match_info;
	struct uet_pds_to_ses_funcs *ses_upcall;
	struct uet_pds_sng_tx_state *pds_tx;
	struct uet_pds_ack_state *ack_state;
	struct uet_pds_info pds_info;
	void *rsp_ses_hdr;
	size_t rsp_ses_hdr_len;
	uet_pds_next_hdr_t rsp_next_hdr;
	struct uet_pds_sng_state *pds_state;

	/* check if packet is available */
	rc = uet_nic_rx_poll(UET_NIC(uet));
	if (rc != 1)
		return rc;

	/* allocate temporary packet buffer                                */
	/*  - need temp buffer to parse packet and determine what endpoint */
	/*    the packet is destined for                                   */
	pkt = malloc(uet->nic.max_pkt_size);
	if (pkt == NULL) {
		UET_API_PRINT_ERRNO("malloc");
		return -ENOMEM;
	}

	/* allocate space for ses response header + ack data for read */
	rsp_ses_hdr = malloc(sizeof(struct uet_ses_rsp_d) +
			     uet->pds.max_ack_data);
	if (rsp_ses_hdr == NULL) {
		UET_API_PRINT_ERRNO("malloc");
		rc = -ENOMEM;
		goto exit;
	}

	/* receive the packet */
	rc = uet_nic_rx_pkt(UET_NIC(uet), pkt, uet->nic.max_pkt_size,
			    &rx_pkt_size);
	if (rc != 1)
		goto exit;

	/* validate the packet */
	if (!uet_pds_rx_pkt_chk(uet, (uint8_t *)pkt, rx_pkt_size,
				&pkt_is_ack, &pkt_is_rd_rsp, &pkt_is_ctrl,
				&pkt_is_nack))
		goto exit;

	if (pkt_is_nack) {
		UET_API_ERR("NACK packets not supported in pds sng mode");
		goto exit;
	}

	/* parse the packet */
	rc = uet_parse_pkt(uet, pkt, rx_pkt_size, &pp);
	if (rc != 0) {
		if (rc == -EFAULT)
			UET_API_ERR("RX of malformed UET packet");
		goto exit;
	}

	UET_PDS_PKT_HDR_TRACE(uet, &pp, pp.eth, pp.pkt_len, "RX PACKET");

	/* find the endpoint the packet is for */
	if (pp.ses_opcode == UET_DEFER_RTR) {
		dst_uet_ep = uet_pds_rtr_lookup(uet, &pp);
		if (dst_uet_ep == NULL) {
			rc = uet_pds_tx_err_ack_pkt(uet, pkt, &pp,
						    UET_RC_UNDELIVERABLE);
			goto exit;
		}
	} else {
		memset(&match_info, 0, sizeof(struct uet_msg_match_info));
		dst_uet_ep = uet_pds_find_dst_ep(uet, pkt, pkt_is_ack,
						 pkt_is_rd_rsp, &match_info);
		if (dst_uet_ep == NULL) {
			if (pkt_is_ack)
				goto exit;
			if (!match_info.ip_addr_match)
				ses_rc = UET_RC_UNDELIVERABLE;
			else if (!match_info.job_id_match)
				ses_rc = UET_RC_BAD_JOB_ID;
			else if (!match_info.pid_on_fep_match)
				ses_rc = UET_RC_BAD_PID;
			else if (!match_info.index_match)
				ses_rc = UET_RC_BAD_INDEX;
			else
				ses_rc = UET_RC_UNDELIVERABLE;
			rc = uet_pds_tx_err_ack_pkt(uet, pkt, &pp,
						    ses_rc);
			goto exit;
		}
	}

	pds_state = (struct uet_pds_sng_state *) dst_uet_ep->pds;

	pds_tx = &pds_state->tx;
	ses_upcall = &uet->pds.upcall;

	/* process the packet */
	if (pkt_is_ack) {

		/* packet is ack => process ack */
		if (dst_uet_ep->ep_state == UET_EP_CLOSE_WAIT)
			goto exit;

		if (!uet_pds_ep_tx_active(dst_uet_ep))
			goto exit;

		if (((struct uet_pds_ack *)pp.pds)->cack_psn !=
		    htonl(pds_tx->psn))
			goto exit;

		/* upcall for ses processing */
		rc = ses_upcall->rx_rsp(pds_tx->pkt_parms.tx_pkt_handle, &pp);
		if (rc == 0) {
			/* update seq num for transmission of next packet */
			pds_tx->psn++;
			pds_tx->tx_active = false;
		}
	} else {  /* process message packet */

		/* check if we have received this message pkt before */
		/* (i.e., if ack was dropped)                        */
		if (uet_pds_is_dup_req(dst_uet_ep, pkt, &ack_state)) {
			/* retransmit ack */
			UET_PDS_PKT_HDR_TRACE(uet, NULL, ack_state->ack,
					      ack_state->ack_len,
					      "RETRANSMIT ACK PACKET");
			rc = uet_nic_tx_pkt(UET_NIC(uet),
					    ack_state->ack,
					    (ack_state->ack +
					     sizeof(struct ethhdr)),
					    (ack_state->ack_len + CRC_LEN));
			goto exit;
		}

		/* done if endpoint close wait state */
		if (dst_uet_ep->ep_state == UET_EP_CLOSE_WAIT)
			goto exit;

		/* upcall for ses processing */
		memset(&pds_info, 0, sizeof(struct uet_pds_info));
		pds_info.opsn = ((struct uet_pds_req *)pp.pds)->psn;
		rc = ses_upcall->rx_req((uet_pkt_handle_t)pkt,
					uet, &pp, &pds_info,
					&rsp_next_hdr, rsp_ses_hdr,
					&rsp_ses_hdr_len, &ses_nack, &gtd_del);
		if (rc == 0) {
			/* TODO: add support for pds nack               */
			/*   - for now, just don't send ack, which will */
			/*     retrigger retransmit, similar to nack    */
			if (!ses_nack)
				/* transmit ack */
				rc = uet_pds_tx_ack_pkt(
						dst_uet_ep, pkt, rsp_next_hdr,
						rsp_ses_hdr_len, rsp_ses_hdr);
		}
	}

exit:
	if (rsp_ses_hdr)
		free(rsp_ses_hdr);
	free(pkt);
	return rc;
}

/* implement endpoint close wait state */
void uet_pds_sng_ep_close_wait(struct uet_ep *uet_ep)
{
	struct uet_instance *uet;
	time_t start_time, now;

	uet_ep->ep_state = UET_EP_CLOSE_WAIT;

	uet = uet_ep->uet_domain->uet;

	/* continue receiving packets for max segment lifetime after */
	/* ep close                                                  */
	/*   - this gives time to retransmit any lost acks,          */
	/*     no other packet rx processing is performed            */
	if (uet_gettime(&start_time)) {
		UET_API_ERR("Aborting endpoint close wait state");
		return;
	}

	while (1) {
		if (uet_gettime(&now)) {
			UET_API_ERR("Aborting endpoint close wait state");
			break;
		}
		if ((now - start_time) > uet->pds.msl)
			break;
		uet->pds.downcall.progress_rx(uet);
	}
}
