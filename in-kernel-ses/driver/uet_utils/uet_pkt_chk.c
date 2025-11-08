/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#include <arpa/inet.h>
#include <linux/ip.h>

#include "uet_pkt_chk.h"

/* determine if uet packet type is valid */
static bool uet_pds_pkt_type_valid(uint8_t *pkt,
				   bool *pkt_is_ack,
				   bool *pkt_is_rd_rsp)
{
	struct uet_sec *sec_hdr;
	struct uet_pds_req *pds_hdr;
	uint16_t pds_type, next_hdr;
	bool pds_req;

	*pkt_is_ack = false;
	*pkt_is_rd_rsp = false;

	/* TODO: IPv6 support */
	pds_hdr = (struct uet_pds_req *)(pkt +
					 sizeof(struct ethhdr) +
					 sizeof(struct iphdr));

	pds_type = ((ntohs(pds_hdr->prlg.type_next_flags) &
		     UET_PDS_TYPE_MASK) >> UET_PDS_TYPE_SHIFT);
	next_hdr = ((ntohs(pds_hdr->prlg.type_next_flags) &
		     UET_PDS_NEXT_HDR_MASK) >> UET_PDS_NEXT_HDR_SHIFT);

	if (pds_type == UET_PDS_TYPE_SECURITY) {
		if (next_hdr != UET_HDR_PDS)
			return false;

		/* TODO: IPv6 support */
		sec_hdr = (struct uet_sec *)pds_hdr;
		if (ntohs(sec_hdr->type_next_flags) & UET_SEC_SP_MASK) {
			pds_hdr =
				(struct uet_pds_req *)((uint8_t *)sec_hdr +
						       sizeof(struct uet_sec_ssi));
		} else {
			pds_hdr =
				(struct uet_pds_req *)((uint8_t *)sec_hdr +
						        sizeof(struct uet_sec));
		}

		pds_type = ((ntohs(pds_hdr->prlg.type_next_flags) &
			     UET_PDS_TYPE_MASK) >> UET_PDS_TYPE_SHIFT);
		next_hdr = ((ntohs(pds_hdr->prlg.type_next_flags) &
			     UET_PDS_NEXT_HDR_MASK) >> UET_PDS_NEXT_HDR_SHIFT);
	}

	switch (pds_type) {
	case UET_PDS_TYPE_ROD_REQ:
	case UET_PDS_TYPE_RUD_REQ:
		pds_req = true;
		break;
	case UET_PDS_TYPE_ACK:
		pds_req = false;
		next_hdr = UET_HDR_RSP;
		break;
	default:
		return false;
	}

	switch (next_hdr) {
	case UET_HDR_REQ_SMALL:
	case UET_HDR_REQ_MEDIUM:
	case UET_HDR_REQ_STD:
		if (pds_req)
			return true;
		break;
	case UET_HDR_RSP:
		if (pds_req == false) {
			*pkt_is_ack = true;
			return true;
		}
		break;
	case UET_HDR_RSP_DATA:
	case UET_HDR_RSP_DATA_SMALL:
		if (pds_req == false) {
			*pkt_is_ack = true;
			return true;
		}
		*pkt_is_rd_rsp = true;
		return true;
	default:
		break;
	}

	return false;
}

bool uet_pds_rx_pkt_chk(struct uet_nic *nic,
			uint8_t *pkt,
			size_t pkt_size,
			bool *pkt_is_ack,
			bool *pkt_is_rd_rsp)
{
	struct ethhdr *eth = (struct ethhdr *)pkt;
	struct iphdr *ipv4 = (struct iphdr *)(eth + 1);

	/* TODO: IPv6 support */
	if (!memcmp(eth->h_dest, nic->mac_addr, ETH_ALEN) &&
	    (eth->h_proto == htons(ETH_P_IP)) &&
	    (ipv4->version == IPVERSION) &&
	    (ipv4->ihl == UET_IPV4_IHL_NO_OPTIONS) &&
	    (ipv4->protocol == UET_IPPROTO) &&
	    (ipv4->tot_len >= htons(nic->min_ip_pkt_size)) &&
	    (ipv4->tot_len <=
	     htons((pkt_size - nic->l2_hdr_size))) &&
	    (uet_ipv4_csum(ipv4) == 0) &&
	    (uet_pds_pkt_type_valid(pkt, pkt_is_ack, pkt_is_rd_rsp)))
		return true;

	return false;
}

