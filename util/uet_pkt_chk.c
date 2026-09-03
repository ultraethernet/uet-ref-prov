/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#include <arpa/inet.h>
#include <linux/ip.h>

#include "uet_pkt_chk.h"
#include "uet_log.h"

/* determine if uet packet type is valid */
static bool uet_pds_pkt_type_valid(uint8_t *pkt,
				   size_t pkt_size,
				   bool is_ipv6,
				   bool *pkt_is_ack,
				   bool *pkt_is_rd_rsp,
				   bool *pkt_is_ctrl,
				   bool *pkt_is_nack)
{
	struct uet_sec *sec_hdr;
	struct uet_pds_req *pds_hdr;
	uint16_t pds_type, next_hdr;
	bool pds_req;
	size_t ip_hdr_size = (is_ipv6) ? sizeof(struct ipv6hdr) :
					 sizeof(struct iphdr);

	*pkt_is_ack = false;
	*pkt_is_rd_rsp = false;
	*pkt_is_ctrl = false;
	*pkt_is_nack = false;

	pds_hdr = (struct uet_pds_req *)(pkt +
					 sizeof(struct ethhdr) +
					 ip_hdr_size +
					 sizeof(struct uet_entropy));

	pds_type = ((ntohs(pds_hdr->prlg.type_next_flags) &
		     UET_PDS_TYPE_MASK) >> UET_PDS_TYPE_SHIFT);

	if (pds_type == UET_PDS_TYPE_SECURITY) {
		sec_hdr = (struct uet_sec *)pds_hdr;
		if (ntohl(sec_hdr->type_flags_sdi) & UET_SEC_SP_MASK) {
			pds_hdr = (struct uet_pds_req *)
				      ((uint8_t *)sec_hdr +
				       sizeof(struct uet_sec_ssi));
		} else {
			pds_hdr = (struct uet_pds_req *)
				      ((uint8_t *)sec_hdr +
				       sizeof(struct uet_sec));
		}

		pds_type = ((ntohs(pds_hdr->prlg.type_next_flags) &
			     UET_PDS_TYPE_MASK) >> UET_PDS_TYPE_SHIFT);
	}

	next_hdr = ((ntohs(pds_hdr->prlg.type_next_flags) &
		     UET_PDS_NEXT_HDR_MASK) >> UET_PDS_NEXT_HDR_SHIFT);

	switch (pds_type) {
	case UET_PDS_TYPE_ROD_REQ:
	case UET_PDS_TYPE_RUD_REQ:
		pds_req = true;
		break;
	case UET_PDS_TYPE_UUD_REQ:
		/* UUD is connectionless and demuxed by pds_type in
		 * uet_pds_progress_rx(). Simply accept it here.
		 */
		return true;
	case UET_PDS_TYPE_ACK:
	case UET_PDS_TYPE_ACK_CC:
	case UET_PDS_TYPE_ACK_CCX:
		pds_req = false;
		break;
	case UET_PDS_TYPE_NACK:
		*pkt_is_nack = true;
		return true;
	case UET_PDS_TYPE_CTRL:
		*pkt_is_ctrl = true;
		return true;
	case UET_PDS_TYPE_RUDI_REQ:
	case UET_PDS_TYPE_RUDI_RESP:
		/* RUDI is connectionless and demuxed by pds_type in
		 * uet_pds_progress_rx(). Simply accept it here.
		 */
		return true;
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
	case UET_HDR_NONE:
		/* closing ACK */
		if (pds_req == false) {
			*pkt_is_ack = true;
			return true;
		}
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

bool uet_pds_rx_pkt_chk(struct uet_instance *uet,
			uint8_t *pkt,
			size_t pkt_size,
			bool *pkt_is_ack,
			bool *pkt_is_rd_rsp,
			bool *pkt_is_ctrl,
			bool *pkt_is_nack)
{
	struct ethhdr *eth = (struct ethhdr *)pkt;
	bool is_ipv6;

	if (memcmp(eth->h_dest, uet->nic.mac_addr, ETH_ALEN) != 0) {
		UET_PDS_WARN("dest MAC mismatch");
		return false;
	}

	if (eth->h_proto == htons(ETH_P_IPV6)) {
		struct ipv6hdr *ipv6 = (struct ipv6hdr *)(eth + 1);

		is_ipv6 = true;

		if (ipv6->version != 6) {
			UET_PDS_WARN("invalid IPv6 header version");
			return false;
		}

		if (ipv6->nexthdr != uet->uet_ipproto) {
			UET_PDS_WARN("unsupported IP protocol");
			return false;
		}

		if (ntohs(ipv6->payload_len) + sizeof(struct ipv6hdr) +
		    sizeof(struct ethhdr) > pkt_size) {
			UET_PDS_WARN("IPv6 payload length too large");
			return false;
		}

		/* IPv6 has no header checksum */

	} else if (eth->h_proto == htons(ETH_P_IP)) {
		struct iphdr *ipv4 = (struct iphdr *)(eth + 1);

		is_ipv6 = false;

		if (ipv4->version != IPVERSION) {
			UET_PDS_WARN("invalid IPv4 header version");
			return false;
		}

		if (ipv4->ihl != UET_IPV4_IHL_NO_OPTIONS) {
			UET_PDS_WARN("IPv4 header options not supported");
			return false;
		}

		if (ipv4->protocol != uet->uet_ipproto) {
			UET_PDS_WARN("unsupported IP protocol");
			return false;
		}

		if (ipv4->tot_len < htons(uet->nic.min_ip_pkt_size)) {
			UET_PDS_WARN("IPv4 total length too small");
			return false;
		}

		if (ipv4->tot_len > htons((pkt_size - uet->nic.l2_hdr_size))) {
			UET_PDS_WARN("IPv4 total length too large");
			return false;
		}

		if (uet_ipv4_csum(ipv4) != 0) {
			UET_PDS_WARN("IPv4 header checksum invalid");
			return false;
		}
	} else {
		UET_PDS_WARN("unsupported ethertype");
		return false;
	}

	if (!uet_pds_pkt_type_valid(pkt, pkt_size, is_ipv6, pkt_is_ack,
				    pkt_is_rd_rsp, pkt_is_ctrl, pkt_is_nack)) {
		UET_PDS_WARN("invalid UET PDS packet type");
		return false;
	}

	return true;
}

