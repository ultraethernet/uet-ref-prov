/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* UET Utilities */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include "uet_addr.h"
#include "uet_pkt_hdr.h"
#include "uet_api_private.h"
#include "uet_sec.h"
#include "crc32c.h"

/* get current time in milliseconds */
int uet_gettime(time_t *time_ms)
{
	struct timespec s;

	if (clock_gettime(CLOCK_REALTIME, &s)) {
		*time_ms = 0;
		return -1;
	}

	*time_ms = ((time_t) (s.tv_sec  * UET_MSEC_PER_SEC)) +
		   ((time_t) (s.tv_nsec / UET_NSEC_PER_MSEC));
	return 0;
}

/* convert mac address to string */
void uet_mac_addr_to_str(char *mac_addr_str, uint8_t *mac_addr)
{
	sprintf(mac_addr_str, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3],
		mac_addr[4], mac_addr[5]);
}

/* convert ipv4 address to string */
void uet_ipv4_addr_to_str(uint32_t ipv4_addr, char *ipv4_addr_str)
{
	uint32_t net_order;

	net_order = htonl(ipv4_addr);
	inet_ntop(AF_INET, (char *) &net_order, ipv4_addr_str, INET_ADDRSTRLEN);
}

/* convert ipv6 address to string */
void uet_ipv6_addr_to_str(const uint8_t *ipv6_addr, char *ipv6_addr_str)
{
	inet_ntop(AF_INET6, ipv6_addr, ipv6_addr_str, INET6_ADDRSTRLEN);
}

/* convert ip address (v4 or v6) to string */
void uet_ip_addr_to_str(const struct uet_fa *fa, bool is_ipv6, char *str)
{
	if (is_ipv6)
		uet_ipv6_addr_to_str(fa->v6, str);
	else
		uet_ipv4_addr_to_str(fa->v4, str);
}

/* convert ses return code to string */
char *uet_ses_rc_to_str(uet_ses_rc_t rc)
{
	char *s;

	switch (rc) {
	case UET_RC_NULL:
		s = "UET_RC_NULL";
		break;
	case UET_RC_OK:
		s = "UET_RC_OK";
		break;
	case UET_RC_BAD_GENERATION:
		s = "UET_RC_BAD_GENERATION";
		break;
	case UET_RC_DISABLED:
		s = "UET_RC_DISABLED";
		break;
	case UET_RC_DISABLED_GEN:
		s = "UET_RC_DISABLED_GEN";
		break;
	case UET_RC_NO_MATCH:
		s = "UET_RC_NO_MATCH";
		break;
	case UET_RC_UNSUPPORTED_OP:
		s = "UET_RC_UNSUPPORTED_OP";
		break;
	case UET_RC_UNSUPPORTED_SIZE:
		s = "UET_RC_UNSUPPORTED_SIZE";
		break;
	case UET_RC_AT_INVALID:
		s = "UET_RC_AT_INVALID";
		break;
	case UET_RC_AT_PERM:
		s = "UET_RC_AT_PERM";
		break;
	case UET_RC_AT_ATS_ERROR:
		s = "UET_RC_AT_ATS_ERROR";
		break;
	case UET_RC_AT_NO_TRANS:
		s = "UET_RC_AT_NO_TRANS";
		break;
	case UET_RC_AT_OUT_OF_RANGE:
		s = "UET_RC_AT_OUT_OF_RANGE";
		break;
	case UET_RC_HOST_POISONED:
		s = "UET_RC_HOST_POISONED";
		break;
	case UET_RC_HOST_UNSUCCESS_CMPL:
		s = "UET_RC_HOST_UNSUCCESS_CMPL";
		break;
	case UET_RC_AMO_UNSUPPORTED_OP:
		s = "UET_RC_AMO_UNSUPPORTED_OP";
		break;
	case UET_RC_AMO_UNSUPPORTED_DT:
		s = "UET_RC_AMO_UNSUPPORTED_DT";
		break;
	case UET_RC_AMO_UNSUPPORTED_SIZE:
		s = "UET_RC_AMO_UNSUPPORTED_SIZE";
		break;
	case UET_RC_AMO_UNALIGNED:
		s = "UET_RC_AMO_UNALIGNED";
		break;
	case UET_RC_AMO_FP_NAN:
		s = "UET_RC_AMO_FP_NAN";
		break;
	case UET_RC_AMO_FP_UNDERFLOW:
		s = "UET_RC_AMO_FP_UNDERFLOW";
		break;
	case UET_RC_AMO_FP_OVERFLOW:
		s = "UET_RC_AMO_FP_OVERFLOW";
		break;
	case UET_RC_AMO_FP_INEXACT:
		s = "UET_RC_AMO_FP_INEXACT";
		break;
	case UET_RC_PERM_VIOLATION:
		s = "UET_RC_PERM_VIOLATION";
		break;
	case UET_RC_OP_VIOLATION:
		s = "UET_RC_OP_VIOLATION";
		break;
	case UET_RC_BAD_INDEX:
		s = "UET_RC_BAD_INDEX";
		break;
	case UET_RC_BAD_PID:
		s = "UET_RC_BAD_PID";
		break;
	case UET_RC_BAD_JOB_ID:
		s = "UET_RC_BAD_JOB_ID";
		break;
	case UET_RC_BAD_MKEY:
		s = "UET_RC_BAD_MKEY";
		break;
	case UET_RC_BAD_ADDR:
		s = "UET_RC_BAD_ADDR";
		break;
	case UET_RC_CANCELLED:
		s = "UET_RC_CANCELLED";
		break;
	case UET_RC_UNDELIVERABLE:
		s = "UET_RC_UNDELIVERABLE";
		break;
	case UET_RC_UNCOR:
		s = "UET_RC_UNCOR";
		break;
	case UET_RC_UNCOR_TRNSNT:
		s = "UET_RC_UNCOR_TRNSNT";
		break;
	case UET_RC_TOO_LONG:
		s = "UET_RC_TOO_LONG";
		break;
	case UET_RC_INITIATOR_ERR:
		s = "UET_RC_INITIATOR_ERR";
		break;
	case UET_RC_DROPPED:
		s = "UET_RC_DROPPED";
		break;
	case UET_RC_DEFER_SEND:
		s = "UET_RC_DEFER_SEND";
		break;
	default:
		s = "UNKNOWN";
		break;
	}

	return s;
}

/* print mac address */
void uet_print_mac_addr(uint8_t *mac)
{
	printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
	       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* print ipv4 address */
void uet_print_ipv4_addr(uint32_t ipv4_addr)
{
	printf("%d.%d.%d.%d\n",
	       (ipv4_addr >> 24) & 0xff, (ipv4_addr >> 16) & 0xff,
	       (ipv4_addr >> 8)  & 0xff, ipv4_addr & 0xff);
}

/* print ipv6 address */
void uet_print_ipv6_addr(const uint8_t *ipv6_addr)
{
	char str[INET6_ADDRSTRLEN];

	uet_ipv6_addr_to_str(ipv6_addr, str);
	printf("%s\n", str);
}

/* print uet address */
void uet_print_uet_addr(struct uet_addr *uet_addr)
{
	char ip_addr_str[INET6_ADDRSTRLEN];

	uet_ip_addr_to_str(&uet_addr->fa, uet_addr_is_ipv6(uet_addr),
			   ip_addr_str);

	printf("UET Address\n");
	printf("  IP Address:      %s\n", ip_addr_str);
	printf("  PIDonFEP:        %u\n", uet_addr->pid_on_fep);
	printf("  Index:           %u\n", uet_addr->start_index);
	printf("  Initiator ID:    %u\n", uet_addr->initiator_id);
	printf("  Profiles:      ");
	if (uet_addr->fep_cap & UET_FEP_CAP_AI_MIN)
		printf("  AI Min");
	if (uet_addr->fep_cap & UET_FEP_CAP_AI_FULL)
		printf("  AI Full");
	if (uet_addr->fep_cap & UET_FEP_CAP_HPC)
		printf("  HPC");
	printf("\n");
}

/* print mac header */
void uet_print_mac_hdr(struct ethhdr *eth)
{
	printf("  MAC Header (%lu)\n", sizeof(struct ethhdr));
	printf("    Destination MAC Addr: ");
	uet_print_mac_addr(eth->h_dest);
	printf("    Source MAC Addr:      ");
	uet_print_mac_addr(eth->h_source);
	printf("    Ethertype:            0x%.4x\n", ntohs(eth->h_proto));
}

/* print ipv4 header */
void uet_print_ipv4_hdr(struct iphdr *ipv4)
{
	printf("  IPv4 Header (%lu)\n", sizeof(struct iphdr));
	printf("    IP Version:           %u\n", ipv4->version);
	printf("    IHL:                  %u\n", ipv4->ihl);
	printf("    TOS:                  0x%x\n", ipv4->tos);
	printf("    Tot Len:              %u\n", ntohs(ipv4->tot_len));
	printf("    ID:                   %u\n", ntohs(ipv4->id));
	printf("    Frag Offset:          0x%x\n", ntohs(ipv4->frag_off));
	printf("    TTL:                  %u\n", ipv4->ttl);
	printf("    Protocol:             0x%x\n", ipv4->protocol);
	printf("    Checksum:             0x%x\n", ntohs(ipv4->check));
	printf("    Destination Addr:     ");
	uet_print_ipv4_addr(ntohl(ipv4->daddr));
	printf("    Source Addr:          ");
	uet_print_ipv4_addr(ntohl(ipv4->saddr));
}

/* print ipv6 header */
void uet_print_ipv6_hdr(struct ipv6hdr *ipv6)
{
	printf("  IPv6 Header (%lu)\n", sizeof(struct ipv6hdr));
	printf("    IP Version:           %u\n", ipv6->version);
	printf("    Traffic Class:        0x%x\n",
	       (ipv6->priority << 4) | (ipv6->flow_lbl[0] >> 4));
	printf("    Flow Label:           0x%x%02x%02x\n",
	       ipv6->flow_lbl[0] & 0x0f,
	       ipv6->flow_lbl[1],
	       ipv6->flow_lbl[2]);
	printf("    Payload Length:       %u\n", ntohs(ipv6->payload_len));
	printf("    Next Header:          0x%x\n", ipv6->nexthdr);
	printf("    Hop Limit:            %u\n", ipv6->hop_limit);
	printf("    Destination Addr:     ");
	uet_print_ipv6_addr((const uint8_t *)&ipv6->daddr);
	printf("    Source Addr:          ");
	uet_print_ipv6_addr((const uint8_t *)&ipv6->saddr);
}

/* print uet header */
void uet_print_uet_hdr(struct uet_parsed_pkt *pp)
{
	uint8_t opcode, gen, rc;
	uint16_t pds_type, index, pid_on_fep;
	uint16_t psn_off, spdcid, dpdcid;
	uint32_t psn, job_id;
	uint64_t msg_off, payload_len;
	bool eom, som, hd;
	struct uet_ses_req_std *ses_req_std;
	struct uet_ses_rsp *ses_rsp;
	struct uet_ses_rsp_d *ses_rsp_d;

	if (pp->entropy) {
		printf("  Entropy Header (%d)\n", pp->entropy_len);
		printf("    Entropy:              0x%04x\n", pp->entropy_val);
	}

	if (pp->sec) {
		printf("  TSS Header (%d)\n", pp->sec_len);
		printf("    TSS AN:               %d\n", pp->sec_an);
		printf("    TSS SDI:              0x%08x\n", pp->sec_sdi);
		if (pp->sec_ssi_valid) {
			printf("    TSS SSI:              0x%08x\n",
			       pp->sec_ssi);
		}
		printf("    TSS EPOCH:            0x%04x\n", pp->sec_epoch);
		printf("    TSS TSC:              0x%016lx\n", pp->sec_tsc);
	}

	printf("  PDS Header (%d)\n", pp->pds_len);
	printf("    PDS Packet Type:      ");

	switch (pp->pds_type) {
	case UET_PDS_TYPE_ROD_REQ:
	case UET_PDS_TYPE_RUD_REQ:
		printf("%s Request\n",
		       (pp->pds_type == UET_PDS_TYPE_ROD_REQ) ? "ROD" : "RUD");
		break;
	case UET_PDS_TYPE_RUDI_REQ:
		printf("RUDI Request\n");
		break;
	case UET_PDS_TYPE_RUDI_RESP:
		printf("RUDI Response\n");
		break;
	case UET_PDS_TYPE_UUD_REQ:
		printf("UUD Request\n");
		break;
	case UET_PDS_TYPE_ACK:
		printf("ACK\n");
		break;
	case UET_PDS_TYPE_NACK:
		printf("NACK\n");
		break;
	case UET_PDS_TYPE_CTRL:
		printf("CTRL\n");
		break;
	default:
		printf("Unknown (0x%x)\n", pp->pds_type);
		return;
	}

	printf("    PDS Next Header:      ");
	switch (pp->next_hdr) {
	case UET_HDR_REQ_SMALL:
		printf("SES Standard Request Small\n");
		break;
	case UET_HDR_REQ_MEDIUM:
		printf("SES Standard Request Medium\n");
		break;
	case UET_HDR_REQ_STD:
		printf("SES Standard Request\n");
		break;
	case UET_HDR_RSP:
		printf("SES Response\n");
		break;
	case UET_HDR_RSP_DATA:
		printf("SES Response with Data\n");
		break;
	case UET_HDR_RSP_DATA_SMALL:
		printf("SES Response with Data Small\n");
		break;
	default:
		printf("Unknown (0x%x)\n", pp->next_hdr);
		return;
	}

	printf("    PDS Flags:            0x%02x\n", pp->pds_flags);
	printf("    PDS PSN:              %u\n", pp->pds_psn);
	printf("    PDS Source PDCID:     %u\n", pp->pds_spdcid);

	if ((pp->next_hdr == UET_HDR_REQ_SMALL) ||
	    (pp->next_hdr == UET_HDR_REQ_MEDIUM) ||
	    (pp->next_hdr == UET_HDR_REQ_STD)) {
		if (pp->pds_flags & UET_PDS_REQ_FLAGS_SYN)
			printf("    PDS SYN Offset:       %u\n", pp->pds_syn_off);
		else
			printf("    PDS Dest PDCID:       %u\n", pp->pds_dpdcid);
		printf("    PDS Clear PSN:        %u\n", pp->pds_clear_psn);
	} else if ((pp->next_hdr == UET_HDR_RSP) ||
		   (pp->next_hdr == UET_HDR_RSP_DATA) ||
		   (pp->next_hdr == UET_HDR_RSP_DATA_SMALL)) {
		printf("    PDS Dest PDCID:       %u\n", pp->pds_dpdcid);
	}

	printf("  SES Header (%d)\n", pp->ses_len);
	switch (pp->next_hdr) {
	case UET_HDR_REQ_STD:
		printf("    SES Opcode:           ");
		ses_req_std = (struct uet_ses_req_std *) pp->ses;
		opcode = ((ses_req_std->cmn.rsvd_opcode &
			   UET_SES_OPCODE_MASK) >> UET_SES_OPCODE_SHIFT);
		if (ses_req_std->cmn.ver_flags & UET_SES_REQ_FLAG_EOM)
			eom = true;
		else
			eom = false;
		if (ses_req_std->cmn.ver_flags & UET_SES_REQ_FLAG_SOM)
			som = true;
		else
			som = false;
		if (ses_req_std->cmn.ver_flags & UET_SES_REQ_FLAG_HD)
			hd = true;
		else
			hd = false;

		switch (opcode) {
		case UET_SEND:
			printf("SEND, SOM = %d, EOM = %d\n", som, eom);
			break;
		case UET_DEFER_SEND:
			printf("DEFERRED SEND, SOM = %d, EOM = %d\n", som, eom);
			break;
		case UET_TAGGED_SEND:
			printf("TAGGED SEND, SOM = %d, EOM = %d\n", som, eom);
			break;
		case UET_DEFER_TSEND:
			printf("DEFERRED TAGGED SEND, SOM = %d, EOM = %d\n",
			       som, eom);
			break;
		case UET_DEFER_RTR:
			printf("DEFERRED RTR, SOM = %d, EOM = %d\n", som, eom);
			break;
		case UET_WRITE:
			printf("WRITE, SOM = %d, EOM = %d\n", som, eom);
			break;
		case UET_SYNC_WRITE:
			printf("SYNC WRITE, SOM = %d, EOM = %d\n", som, eom);
			break;
		case UET_READ:
			printf("READ, SOM = %d, EOM = %d\n", som, eom);
			break;
		case UET_ATOMIC:
			printf("ATOMIC, SOM = %d, EOM = %d\n", som, eom);
			break;
		case UET_SYNC_ATOMIC:
			printf("SYNC ATOMIC, SOM = %d, EOM = %d\n", som, eom);
			break;
		case UET_FETCH_ATOMIC:
			printf("FETCH ATOMIC, SOM = %d, EOM = %d\n", som, eom);
			break;
		default:
			printf("Unknown (0x%x), SOM = %d, EOM = %d\n",
			       opcode, som, eom);
			return;
		}
		printf("    SES Flags:            0x%x\n",
		       ses_req_std->cmn.ver_flags);
		index = ((ntohs(ses_req_std->cmn.rsvd_res_index) &
			  UET_SES_REQ_RES_INDEX_MASK) >>
			 UET_SES_REQ_RES_INDEX_SHIFT);
		printf("    SES Index:            %u\n", index);
		job_id = ((ntohl(ses_req_std->cmn.ri_gen_job_id) &
			   UET_SES_REQ_JOB_ID_MASK) >>
			  UET_SES_REQ_JOB_ID_SHIFT);
		printf("    SES Job ID:           %u\n", job_id);
		gen = (uint8_t)((ntohl(ses_req_std->cmn.ri_gen_job_id) &
				 UET_SES_REQ_RI_GEN_MASK) >>
				UET_SES_REQ_RI_GEN_SHIFT);
		printf("    SES Generation:       %u\n", gen);
		pid_on_fep = ((ntohl(ses_req_std->cmn.rsvd_pid_on_fep) &
			       UET_SES_REQ_PID_ON_FEP_MASK) >>
			      UET_SES_REQ_PID_ON_FEP_SHIFT);
		printf("    SES PIDonFEP:         %u\n", pid_on_fep);
		printf("    SES Message ID:       %u\n", pp->ses_msg_id);
		printf("    SES Initiator ID:     %u\n",
		       ntohl(ses_req_std->initiator));
		printf("    SES Request Length:   %u\n",
		       ntohl(ses_req_std->req_len));
		if ((opcode != UET_DEFER_SEND) && (opcode != UET_DEFER_TSEND))
			printf("    SES Buffer Offset:    %lu\n",
			       ntohll(ses_req_std->buf_off));
		else
			printf("    SES Restart Token:    0x%016lx\n",
			       ntohll(ses_req_std->restart_token));
		if (som && hd)
			printf("    SES Header Data:      %lu\n",
			       ntohll(ses_req_std->cmpl_data));
		else if (!som) {
			msg_off = (ntohll(ses_req_std->payload_len_msg_off)
				   & UET_SES_REQ_STD_MSG_OFF_MASK) >>
				  UET_SES_REQ_STD_MSG_OFF_SHIFT;
			payload_len =
				(ntohll(ses_req_std->payload_len_msg_off) &
				 UET_SES_REQ_STD_PAYLOAD_LEN_MASK) >>
				UET_SES_REQ_STD_PAYLOAD_LEN_SHIFT;
			printf("    SES Message Offset:   %lu\n", msg_off);
			printf("    SES Payload Length:   %lu\n", payload_len);
		}
		if (opcode != UET_DEFER_RTR)
			printf("    SES Match Bits:       0x%lx\n",
			       ntohll(ses_req_std->match_bits));
		else
			printf("    SES RTR Token:        0x%016lx\n",
			       ntohll(ses_req_std->restart_token_rtr));
		break;
	case UET_HDR_RSP:
		printf("    SES Opcode:           ");
		ses_rsp = (struct uet_ses_rsp *) pp->ses;
		opcode = ((ses_rsp->cmn.list_opcode &
			   UET_SES_OPCODE_MASK) >> UET_SES_OPCODE_SHIFT);
		switch (opcode) {
		case UET_DEFAULT_RESPONSE:
			printf("DEFAULT RESPONSE\n");
			break;
		case UET_RESPONSE:
			printf("RESPONSE\n");
			break;
		default:
			printf("Unknown (0x%x)\n", opcode);
			return;
		}
		rc = ((ses_rsp->cmn.ver_ret_code &
		       UET_SES_RSP_RET_CODE_MASK) >>
		      UET_SES_RSP_RET_CODE_SHIFT);
		printf("    SES Return Code:      %u (%s)\n",
		       rc, uet_ses_rc_to_str(rc));
		gen = (uint8_t)((ntohl(ses_rsp->cmn.ri_gen_job_id) &
				 UET_SES_RSP_RI_GEN_MASK) >>
				UET_SES_RSP_RI_GEN_SHIFT);
		printf("    SES Generation:       %u\n", gen);
		job_id = ((ntohl(ses_rsp->cmn.ri_gen_job_id) &
			   UET_SES_RSP_JOB_ID_MASK) >>
			  UET_SES_RSP_JOB_ID_SHIFT);
		printf("    SES Job ID:           %u\n", job_id);
		printf("    SES Message ID:       %u\n", pp->ses_msg_id);
		printf("    SES Modified Length:  %u\n",
		       ntohl(ses_rsp->mod_len));
		break;
	case UET_HDR_RSP_DATA:
		ses_rsp_d = (struct uet_ses_rsp_d *) pp->ses;
		printf("    SES Opcode:           ");
		opcode = ((ses_rsp_d->cmn.list_opcode &
			   UET_SES_OPCODE_MASK) >> UET_SES_OPCODE_SHIFT);
		switch (opcode) {
		case UET_RESPONSE_W_DATA:
			printf("RESPONSE WITH DATA\n");
			break;
		default:
			printf("Unknown (0x%x)\n", opcode);
			return;
		}
		rc = ((ses_rsp_d->cmn.ver_ret_code &
		       UET_SES_RSP_RET_CODE_MASK) >>
		      UET_SES_RSP_RET_CODE_SHIFT);
		printf("    SES Return Code:      %u\n", rc);
		gen = (uint8_t)
			((ntohl(ses_rsp_d->cmn.ri_gen_job_id) &
			  UET_SES_RSP_RI_GEN_MASK) >>
			 UET_SES_RSP_RI_GEN_SHIFT);
		printf("    SES Generation:       %u\n", gen);
		job_id = ((ntohl(ses_rsp_d->cmn.ri_gen_job_id) &
			   UET_SES_RSP_JOB_ID_MASK) >>
			  UET_SES_RSP_JOB_ID_SHIFT);
		printf("    SES Job ID:           %u\n", job_id);
		printf("    SES Message ID:       %u\n", pp->ses_msg_id);
		printf("    SES Modified Length:  %u\n",
		       ntohl(ses_rsp_d->mod_len));
		printf("    SES Message Offset:   %u\n",
		       ntohl(ses_rsp_d->msg_off));
		printf("    SES Payload Length:   %u\n",
		       (ntohl(ses_rsp_d->rd_msg_id_payload_len) &
			UET_SES_RSP_D_PAYLOAD_LEN_MASK) >>
		       UET_SES_RSP_D_PAYLOAD_LEN_SHIFT);
		break;
	default:
		break;
	}
}

/* print packet headers */
void uet_print_pkt_hdrs(struct uet_parsed_pkt *pp)

{
	printf("UET Packet Headers (pkt_len=%d)\n", pp->pkt_len);
	uet_print_mac_hdr((struct ethhdr *) pp->eth);
	if (pp->is_ipv6)
		uet_print_ipv6_hdr((struct ipv6hdr *) pp->ip);
	else
		uet_print_ipv4_hdr((struct iphdr *) pp->ip);
	/* TODO: UDP support */
	uet_print_uet_hdr(pp);
}

/* round up to next multiple of 8 */
size_t uet_roundup_8(size_t val)
{
	return (((val + 7) >> 3) << 3);
}

/* convert dscp value to ip tos value */
uint8_t uet_dscp_to_tos(uint8_t dscp)
{
	return (dscp << 2);
}

/*
 * compute internet checksum
 *
 * parms:
 *      buf - ptr to buffer that checksum is to be computed over
 *      cnt - number of 16b words in buf
 *
 * returns:
 *      computed checksum
 */
uint16_t uet_csum(uint16_t *buf, int cnt)
{
	unsigned long sum;

	for (sum = 0; cnt > 0; cnt--)
		sum += htons(*(buf)++);
	do {
		sum = ((sum >> 16) + (sum & 0xFFFF));
	} while (sum & 0xFFFF0000);

	return (~sum);
}

/*
 * compute ipv4 header checksum
 *
 * parms:
 *      ipv4 - ptr to ipv4 header for which checksum is to be computed
 *
 * returns:
 *      computed checksum
 */
uint16_t uet_ipv4_csum(struct iphdr *ipv4)
{
	return htons(uet_csum((uint16_t *)ipv4, ipv4->ihl * 2));
}

/*
 * build ipv4 header
 *
 * parms:
 *      uet     - ptr to uet instance struct
 *      ipv4    - ptr to location where ipv4 header is to be built
 *      dip     - destination ipv4 address
 *      sip     - source ipv4 address
 *      tot_len - value for total length field of ipv4 header
 *      tos     - value for tos field of ipv4 header
 *      crc_en  - CRC will or will not be appended to the frame
 */
void uet_build_ipv4_hdr(struct uet_instance *uet, struct iphdr *ipv4,
			uint32_t dip, uint32_t sip, uint16_t tot_len,
			uint8_t tos, bool crc_en)
{
	ipv4->version = IPVERSION;
	ipv4->ihl = UET_IPV4_IHL_NO_OPTIONS;
	ipv4->tos = tos;
	ipv4->tot_len = htons(tot_len + (crc_en ? CRC_LEN : 0));
	ipv4->id = 0;
	ipv4->frag_off = htons(UET_IPV4_FRAG_OFF_DF);
	ipv4->ttl = IPDEFTTL;
	ipv4->protocol = uet->uet_ipproto;
	ipv4->saddr = sip;
	ipv4->daddr = dip;
	ipv4->check = 0;
	ipv4->check = uet_ipv4_csum(ipv4);
}

/*
 * update ipv4 total length and checksum fields
 *
 * parms:
 *      ipv4    - ptr to location where ipv4 header is located
 *      tot_len - value for total length field of ipv4 header
 */
void uet_update_ipv4_tl(struct iphdr *ipv4, uint16_t tot_len)
{
	ipv4->tot_len = htons(tot_len);
	ipv4->check = 0;
	ipv4->check = uet_ipv4_csum(ipv4);
}

/*
 * build ipv6 header
 *
 * parms:
 *      uet         - ptr to uet instance struct
 *      ipv6        - ptr to location where ipv6 header is to be built
 *      dip         - destination ipv6 address (16 bytes, network order)
 *      sip         - source ipv6 address (16 bytes, network order)
 *      payload_len - value for payload length field of ipv6 header
 *      tc          - value for traffic class field of ipv6 header
 *      crc_en      - CRC will or will not be appended to the frame
 */
void uet_build_ipv6_hdr(struct uet_instance *uet, struct ipv6hdr *ipv6,
			const uint8_t *dip, const uint8_t *sip,
			uint16_t payload_len, uint8_t tc, bool crc_en)
{
	memset(ipv6, 0, sizeof(*ipv6));
	ipv6->version = 6;
	ipv6->priority = (tc >> 4);
	ipv6->flow_lbl[0] = (tc << 4);
	ipv6->payload_len = htons(payload_len + (crc_en ? CRC_LEN : 0));
	ipv6->nexthdr = uet->uet_ipproto;
	ipv6->hop_limit = IPDEFTTL;
	memcpy(&ipv6->saddr, sip, 16);
	memcpy(&ipv6->daddr, dip, 16);
}

/*
 * update ipv6 payload length field
 *
 * parms:
 *      ipv6        - ptr to location where ipv6 header is located
 *      payload_len - value for payload length field of ipv6 header
 */
void uet_update_ipv6_pl(struct ipv6hdr *ipv6, uint16_t payload_len)
{
	ipv6->payload_len = htons(payload_len);
}

/*
 * build ethernet header
 *
 * parms:
 *      eth  - ptr to location where ethernet header is to be built
 *      dmac - ptr to destination mac address
 *      smac - ptr to source mac address
 */
void uet_build_eth_hdr(struct ethhdr *eth, uint8_t *dmac, uint8_t *smac,
		       bool is_ipv6)
{
	eth->h_proto = htons(is_ipv6 ? ETH_P_IPV6 : ETH_P_IP);
	memcpy(eth->h_dest, dmac, ETH_ALEN);
	memcpy(eth->h_source, smac, ETH_ALEN);
}

void uet_pkt_hex_dump(void *pkt, uint32_t length, uint64_t addr, bool is_tx)
{
	const uint8_t *address = (uint8_t *)pkt;
	const uint8_t *line = address;
	size_t line_size = 16;
	uint64_t offset = 0;
	uint8_t c;
	int i = 0;

	printf("%s addr = 0x%lx / length = %u\n",
	       (is_tx ? "TX -->" : "RX <--"), addr, length);

	printf("%08lu: ", offset);

	while (length-- > 0) {
		printf("%02X ", *address++);

		if (!(++i % line_size) ||
		    ((length == 0) && (i % line_size))) {
			if (length == 0) {
				while (i++ % line_size)
					printf("__ ");
			}

			printf(" | ");	/* right close */

			while (line < address) {
				c = *line++;
				printf("%c", ((c < 33) ||
					      (c > 127) ||
					      (c == 255)) ? 0x2E : c);
			}

			printf("\n");

			if (length > 0) {
				offset += line_size;
				printf("%08lu: ", offset);
			}
		}
	}

	printf("\n");
}

/* initialize read-write lock */
void uet_rw_lock_init(struct uet_rw_lock *lock)
{
	lock->val = UET_RW_LOCK_IDLE_VAL;
}

/* get read access to read-write lock */
static void uet_rw_lock_rd(struct uet_rw_lock *lock)
{
	uet_rw_lock_val_t expected, new;

	expected = UET_RW_LOCK_IDLE_VAL;
	new = UET_RW_LOCK_RD_ACQUIRED_VAL;

	while (1) {
		if (__atomic_compare_exchange_n(
			&lock->val, &expected, new, false,
			__ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
			return;
		if (new != UET_RW_LOCK_WR_ACQUIRED_VAL) {
			expected = new;
			new = expected + 1;
		}
	}
}

/* get write access to read-write lock */
static void uet_rw_lock_wr(struct uet_rw_lock *lock)
{
	uet_rw_lock_val_t expected, new;

	expected = UET_RW_LOCK_IDLE_VAL;
	new = UET_RW_LOCK_WR_ACQUIRED_VAL;

	while (1) {
		if (__atomic_compare_exchange_n(
			&lock->val, &expected, new, false,
			__ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
			return;
	}
}

/* access read-write lock */
void uet_rw_lock(struct uet_rw_lock *lock, uet_rw_lock_access_t access)
{
	if (access == UET_RW_LOCK_RD_ACCESS)
		return uet_rw_lock_rd(lock);
	uet_rw_lock_wr(lock);
}

/* unlock read-write lock */
void uet_rw_unlock(struct uet_rw_lock *lock, uet_rw_lock_access_t access)
{
	if (access == UET_RW_LOCK_RD_ACCESS)
		__atomic_fetch_sub(&lock->val, 1, __ATOMIC_SEQ_CST);
	else
		__atomic_fetch_add(&lock->val, 1, __ATOMIC_SEQ_CST);
}

/*
 * determine if next packet field to be parsed fits within packet
 *   - checks for malformed packet headers that indicate a packet
 *     length that extends beyond the end of the packet)
 *
 * parms:
 *      pp - ptr to struct containing packet parsing results,
 *           the following fields of the pp struct must be valid on input:
 *             - pkt_len
 *      field_offset - offset of the packet field to be checked from the
 *                     beginning of the packet
 *      field_len    - length of the packet field to be checked in bytes
 *
 * returns:
 *	 0: field is within packet bounds
 *	-EFAULT: packet is malformed
 */
static int uet_parse_chk_next_field(struct uet_parsed_pkt *pp,
				    uint16_t field_offset, uint16_t field_len)
{
	if ((field_offset + field_len) > pp->pkt_len)
		return -EFAULT;
	return 0;
}

/* determine if ip protocol is associated with a supported ipv6 ext hdr */
static bool uet_is_valid_ipv6_ext_hdr(uint8_t ipproto)
{
	switch (ipproto) {
	case UET_IPPROTO_EXT_HDR_HOP_BY_HOP:
	case UET_IPPROTO_EXT_HDR_ROUTING:
	case UET_IPPROTO_EXT_HDR_DEST_OPTS:
	case UET_IPPROTO_EXT_HDR_MOBILITY:
		return true;
	default:
		break;
	}

	return false;
}

/*
 * get ipv6 hdr length and ip protocol of next hdr from ipv6 hdr of packet
 *
 * parms:
 *      uet - ptr to uet instance struct
 *      pp  - ptr to struct containing packet parsing results,
 *            the following fields of the pp struct must be valid on input:
 *              - pkt_len
 *              - ip (must point to ipv6 header)
 *            the following fields of the pp struct are set on
 *            output when the return code indicates success:
 *              - ip_len
 *              - ip_protocol
 *
 * returns:
 *	 0: packet successfully parsed
 *	-EINVAL: packet is not a properly encapsulated UET packet
 *	-EFAULT: malformed packet
 */
static int uet_get_ipv6_nexthdr(struct uet_instance *uet,
				struct uet_parsed_pkt *pp)
{
	int rc;
	struct ipv6hdr *ipv6;
	struct ipv6_opt_hdr *opt_hdr;

	ipv6 = (struct ipv6hdr *) pp->ip;
	pp->ip_len = sizeof(struct ipv6hdr);
	pp->ip_payload_len = ntohs(ipv6->payload_len);
	pp->ip_protocol = ipv6->nexthdr;

	while (1) {
		if ((pp->ip_protocol == uet->uet_ipproto) ||
		    (pp->ip_protocol == IPPROTO_UDP))
			break;
		if (!uet_is_valid_ipv6_ext_hdr(pp->ip_protocol))
			return -EINVAL;
		opt_hdr = (struct ipv6_opt_hdr *)
			(((uint8_t *) pp->ip) + pp->ip_len);
		rc = uet_parse_chk_next_field(pp, pp->eth_len + pp->ip_len,
				sizeof(struct ipv6_opt_hdr));
		if (rc != 0)
			return rc;
		pp->ip_protocol = opt_hdr->nexthdr;
		pp->ip_len += ((opt_hdr->hdrlen + 1) << 3);
	}

	return 0;
}

/*
 * get payload length of ses request
 *
 * parms:
 *      pp - ptr to packet parsing results struct,
 *           the following fields of the pp struct must be valid:
 *             - pkt_len
 *             - hdr_len
 *             - ses
 *             - ses_opcode
 *     max_payload_len - maximum payload length in bytes
 *
 * returns:
 *	ses request payload length in bytes
 */
uint16_t uet_get_ses_req_payload_len(struct uet_parsed_pkt *pp,
				     uint16_t max_payload_len)
{
	uint16_t hdr_len, payload_len;
	uint32_t req_len;
	uint64_t payload_len_msg_off;
	struct uet_ses_req_std *ses;

	ses = (struct uet_ses_req_std *) pp->ses;
	req_len = ntohl(ses->req_len);

	if (ses->cmn.ver_flags & UET_SES_REQ_FLAG_SOM) {
		if (pp->ses_opcode == UET_READ)
			payload_len = max_payload_len;
		else
			payload_len = pp->pkt_payload_len;
		if (payload_len > req_len)
			payload_len = req_len;
	} else {
		payload_len_msg_off = ntohll(ses->payload_len_msg_off);
		payload_len = ((payload_len_msg_off &
				UET_SES_REQ_STD_PAYLOAD_LEN_MASK) >>
			       UET_SES_REQ_STD_PAYLOAD_LEN_SHIFT);
	}

	return payload_len;
}

/*
 * parse uet packet
 *
 * parms:
 *      uet     - ptr to uet instance struct
 *      pkt     - ptr to packet to be parsed
 *      pkt_len - length of packet in bytes
 *      pp      - ptr to struct where packet parsing results are returned
 *
 * returns:
 *	 0: packet successfully parsed
 *	-EINVAL: packet is not a properly encapsulated UET packet
 *	-EFAULT: malformed packet
 */
int uet_parse_pkt(struct uet_instance *uet, void *pkt, size_t pkt_len,
		  struct uet_parsed_pkt *pp)
{
	int rc, num_vlan_tags = 0;
	uint8_t *p, ip_ver;
	uint16_t cur_len, *etype_p, ethertype, pds_type_next_flags;
	uint32_t sec_type_flags_sdi;
	bool done = false;
	struct iphdr *ipv4;
	struct udphdr *udp;
	struct uet_entropy *entropy;
	struct uet_sec *sec;
	struct uet_sec_ssi *sec_ssi;
	struct uet_pds_prlg *pds_prlg;
	struct uet_pds_req *pds_req;
	struct uet_pds_ack *pds_ack;
	struct uet_pds_ack_cc *pds_ack_cc;
	struct uet_pds_ack_ccx *pds_ack_ccx;
	struct uet_pds_nack *pds_nack;
	struct uet_pds_ctrl *pds_ctrl;
	struct uet_pds_rudi_req *pds_rudi;
	struct uet_ses_req_std *ses_req;
	struct uet_ses_rsp *ses_rsp;
	struct uet_ses_rsp_d *ses_rsp_d;

	memset(pp, 0, sizeof(struct uet_parsed_pkt));

	p = (uint8_t *)pkt;
	pp->pkt_len = pkt_len;

	/* parse ethernet header */
	pp->eth = p;
	pp->eth_len = sizeof(struct ethhdr);
	etype_p = &(((struct ethhdr *)p)->h_proto);
	while (!done) {
		pp->ethertype = ntohs(*etype_p);
		switch (pp->ethertype) {
		case ETH_P_IP:
		case ETH_P_IPV6:
			done = true;
			break;
		case ETH_P_8021Q:
			num_vlan_tags++;
			if (num_vlan_tags > UET_MAX_VLAN_TAGS)
				goto err_exit;
			pp->eth_len += sizeof(struct uet_vlan_tag);
			etype_p = (uint16_t *)
				(((uint8_t *) etype_p) +
				 sizeof(struct uet_vlan_tag));
			break;
		default:
			if (pp->ethertype == uet->uet_ipproto)
				done = true;
			else
				goto err_exit;
			break;
		}
	}

	cur_len = pp->eth_len;
	p = ((uint8_t *) pkt) + cur_len;

	/* parse ip header */
	pp->ip = p;
	if (pp->ethertype == uet->uet_ipproto) {
		ip_ver = ((*((uint8_t *) pp->ip)) & UET_IP_VER_MASK) >>
			 UET_IP_VER_SHIFT;
		switch (ip_ver) {
		case UET_IPV4_VER:
			ethertype = ETH_P_IP;
			break;
		case UET_IPV6_VER:
			ethertype = ETH_P_IPV6;
			break;
		default:
			goto err_exit;
		}
	} else {
		ethertype = pp->ethertype;
	}
	switch (ethertype) {
	case ETH_P_IP:
		pp->is_ipv6 = false;
		ipv4 = (struct iphdr *) p;
		pp->ip_protocol = ipv4->protocol;
		pp->ip_len = (ipv4->ihl << 2);
		pp->ip_payload_len = (ntohs(ipv4->tot_len) -
				      sizeof(struct iphdr));
		break;
	case ETH_P_IPV6:
		pp->is_ipv6 = true;
		rc = uet_get_ipv6_nexthdr(uet, pp);
		if (rc != 0)
			return rc;
		break;
	default:
		goto err_exit;
	}

	cur_len += pp->ip_len;
	p = ((uint8_t *) pkt) + cur_len;

	/* parse the entropy or udp header */
	if (pp->ip_protocol == uet->uet_ipproto) {
		pp->entropy = p;
		entropy = (struct uet_entropy *) p;
		pp->entropy_val = ntohs(entropy->entropy);
		pp->entropy_len = sizeof(struct uet_entropy);
		cur_len += pp->entropy_len;
		p = ((uint8_t *) pkt) + cur_len;
	} else {
		switch (pp->ip_protocol) {
		case IPPROTO_UDP:
			udp = (struct udphdr *) p;
			rc = uet_parse_chk_next_field(
				pp, cur_len, sizeof(struct udphdr));
			if (rc != 0)
				return rc;
			if (ntohs(udp->dest) != uet->uet_udp_port)
				goto err_exit;
			pp->entropy_val = ntohs(udp->source);
			pp->udp = p;
			pp->udp_len = sizeof(struct udphdr);
			cur_len += pp->udp_len;
			p = ((uint8_t *) pkt) + cur_len;
			break;
		default:
			goto err_exit;
		}
	}

	/* parse security header */
	pds_prlg = (struct uet_pds_prlg *)p;
	rc = uet_parse_chk_next_field(pp, cur_len, sizeof(struct uet_pds_prlg));
	if (rc != 0)
		return rc;
	pds_type_next_flags = ntohs(pds_prlg->type_next_flags);
	pp->pds_type = ((pds_type_next_flags & UET_PDS_TYPE_MASK) >>
			UET_PDS_TYPE_SHIFT);
	if (pp->pds_type == UET_PDS_TYPE_SECURITY) {
		pp->sec = pds_prlg;
		sec = (struct uet_sec *)pds_prlg;
		sec_type_flags_sdi = ntohl(sec->type_flags_sdi);
		pp->sec_an = !!(sec_type_flags_sdi & UET_SEC_AN_MASK);
		pp->sec_sdi = (sec_type_flags_sdi & UET_SEC_SDI_MASK);
		if (sec_type_flags_sdi & UET_SEC_SP_MASK) {
			sec_ssi = (struct uet_sec_ssi *)sec;
			pp->sec_ssi_valid = true;
			pp->sec_ssi = ntohl(sec_ssi->ssi);
			pp->sec_tsc = ntohll(sec_ssi->epoch_tsc);
			pp->sec_len = sizeof(struct uet_sec_ssi);
		} else {
			pp->sec_ssi_valid = false;
			pp->sec_tsc = ntohll(sec->epoch_tsc);
			pp->sec_len = sizeof(struct uet_sec);
		}
		pp->sec_epoch = (uint16_t)((pp->sec_tsc &
					    UET_SEC_EPOCH_MASK) >>
					   UET_SEC_EPOCH_SHIFT);
		pp->sec_tsc = ((pp->sec_tsc & UET_SEC_TSC_MASK) >>
			       UET_SEC_TSC_SHIFT);
		cur_len += pp->sec_len;
		p = ((uint8_t *) pkt) + cur_len;
		pds_prlg = (struct uet_pds_prlg *) p;
		rc = uet_parse_chk_next_field(
				pp, cur_len, sizeof(struct uet_pds_prlg));
		if (rc != 0)
			return rc;
		pds_type_next_flags = ntohs(pds_prlg->type_next_flags);
		pp->pds_type = (pds_type_next_flags & UET_PDS_TYPE_MASK) >>
			       UET_PDS_TYPE_SHIFT;
		pp->trailer_len = UET_SEC_TAG_LEN;
	} else {
		/* CRC is auto enabled when security is not used */
		pp->trailer_len = CRC_LEN;
	}

	/* parse pds header */
	pp->pds = pds_prlg;
	pp->next_hdr = ((pds_type_next_flags & UET_PDS_NEXT_HDR_MASK) >>
			UET_PDS_NEXT_HDR_SHIFT);
	pp->pds_flags = ((pds_type_next_flags & UET_PDS_FLAGS_MASK) >>
			 UET_PDS_FLAGS_SHIFT);
	switch (pp->pds_type) {
	case UET_PDS_TYPE_RUD_REQ:
	case UET_PDS_TYPE_ROD_REQ:
		pds_req = (struct uet_pds_req *)pp->pds;
		pp->pds_len = sizeof(struct uet_pds_req);
		pp->pds_psn = ntohl(pds_req->psn);
		pp->pds_spdcid = ntohs(pds_req->spdcid);
		pp->pds_clear_psn = ((int16_t)ntohs(pds_req->clear_psn_offset) +
				     pp->pds_psn);
		if (pp->pds_flags & UET_PDS_REQ_FLAGS_SYN) {
			pp->pds_syn_off = ((ntohs(pds_req->pdc_info_psn_offset) &
					    UET_PDS_REQ_PSN_OFFSET_MASK) >>
					   UET_PDS_REQ_PSN_OFFSET_SHIFT);
		} else {
			pp->pds_dpdcid = ntohs(pds_req->dpdcid);
		}
		break;
	case UET_PDS_TYPE_UUD_REQ:
		pp->pds_len = sizeof(struct uet_pds_uud_req);
		break;
	case UET_PDS_TYPE_ACK:
	case UET_PDS_TYPE_ACK_CC:
	case UET_PDS_TYPE_ACK_CCX:
		pds_ack = (struct uet_pds_ack *)pp->pds;
		pp->pds_len = sizeof(struct uet_pds_ack);
		pp->pds_cack_psn = ntohl(pds_ack->cack_psn);
		pp->pds_psn = ((int16_t)ntohs(pds_ack->ack_psn_offset) +
			       pp->pds_cack_psn);
		pp->pds_spdcid = ntohs(pds_ack->spdcid);
		pp->pds_dpdcid = ntohs(pds_ack->dpdcid);

		if (pp->pds_type == UET_PDS_TYPE_ACK_CC ||
		    pp->pds_type == UET_PDS_TYPE_ACK_CCX) {
			pds_ack_cc = (struct uet_pds_ack_cc *)pp->pds;
			pp->pds_len = sizeof(struct uet_pds_ack_cc);
			pp->pds_cc_type = (pds_ack_cc->cc_type_flags &
					   UET_PDS_ACK_CC_TYPE_MASK) >>
					  UET_PDS_ACK_CC_TYPE_SHIFT;
			pp->pds_cc_flags = (pds_ack_cc->cc_type_flags &
					    UET_PDS_ACK_CC_FLAGS_MASK) >>
					   UET_PDS_ACK_CC_FLAGS_SHIFT;
			pp->pds_mpr = pds_ack_cc->mpr;
			pp->pds_sack_base_psn =
				((int16_t)ntohs(pds_ack_cc->sack_psn_offset) +
				 pp->pds_cack_psn);
			pp->pds_sack_bitmap = ntohll(pds_ack_cc->sack_bitmap);
			pp->pds_cc_state = ntohll(pds_ack_cc->ack_cc_state);
		}

		if (pp->pds_type == UET_PDS_TYPE_ACK_CCX) {
			pds_ack_ccx = (struct uet_pds_ack_ccx *)pp->pds;
			pp->pds_len = sizeof(struct uet_pds_ack_ccx);
			pp->pds_ccx_state = ntohll(pds_ack_ccx->ack_ccx_state);
		}

		/* closing ACK with expected PSN payload for 0-RTT */
		if ((pp->pds_type == UET_PDS_TYPE_ACK) &&
		    (pp->pds_flags & UET_PDS_ACK_FLAGS_EPSN)) {
			struct uet_pds_ack_epsn *epsn =
				(struct uet_pds_ack_epsn *)pp->pds;
			pp->pds_payload = ntohl(epsn->payload);
			pp->pds_len = sizeof(struct uet_pds_ack_epsn);
		}
		break;
	case UET_PDS_TYPE_NACK:
		pds_nack = (struct uet_pds_nack *)pp->pds;
		pp->pds_len = sizeof(struct uet_pds_nack);
		pp->pds_psn = ntohl(pds_nack->nack_psn);
		pp->pds_spdcid = ntohs(pds_nack->spdcid);
		pp->pds_dpdcid = ntohs(pds_nack->dpdcid);
		pp->pds_nack_code = pds_nack->nack_code;
		pp->pds_payload = ntohl(pds_nack->payload);
		return 0;
	case UET_PDS_TYPE_CTRL:
		pds_ctrl = (struct uet_pds_ctrl *)pp->pds;
		pp->pds_len = sizeof(struct uet_pds_ctrl);
		pp->pds_ctrl_type = pp->next_hdr;
		pp->pds_psn = ntohl(pds_ctrl->psn);
		pp->pds_spdcid = ntohs(pds_ctrl->spdcid);
		if (pp->pds_ctrl_type == UET_PDS_CTRL_TYPE_PROBE)
			pp->pds_probe_opaque = ntohs(pds_ctrl->probe_opaque);
		if (pp->pds_flags & UET_PDS_CTRL_FLAGS_SYN) {
			pp->pds_pdc_info =
				((ntohs(pds_ctrl->pdc_info_psn_offset) &
				  UET_PDS_CTRL_PDC_INFO_MASK) >>
				 UET_PDS_CTRL_PDC_INFO_SHIFT);
			pp->pds_syn_off =
				((ntohs(pds_ctrl->pdc_info_psn_offset) &
				  UET_PDS_CTRL_PSN_OFFSET_MASK) >>
				 UET_PDS_CTRL_PSN_OFFSET_SHIFT);
		} else {
			pp->pds_dpdcid = ntohs(pds_ctrl->dpdcid);
		}
		pp->pds_ctrl_payload = ntohl(pds_ctrl->payload);
		return 0;
	case UET_PDS_TYPE_RUDI_REQ:
	case UET_PDS_TYPE_RUDI_RESP:
		pds_rudi = (struct uet_pds_rudi_req *)pp->pds;
		pp->pds_len = sizeof(struct uet_pds_rudi_req);
		pp->pds_rudi_pkt_id = ntohl(pds_rudi->pkt_id);
		break;
	default:
		goto err_exit;
	}

	cur_len += pp->pds_len;
	p = ((uint8_t *) pkt) + cur_len;

	/* parse ses header */
	pp->ses = p;
	switch (pp->next_hdr) {
	case UET_HDR_NONE:
		pp->ses_len = 0;
		pp->ses_payload_len = 0;
		break;
	case UET_HDR_REQ_STD:
		rc = uet_parse_chk_next_field(
			pp, cur_len, sizeof(struct uet_ses_req_std));
		if (rc != 0)
			return rc;
		pp->ses_len = sizeof(struct uet_ses_req_std);
		ses_req = (struct uet_ses_req_std *) pp->ses;
		pp->ses_opcode = (ses_req->cmn.rsvd_opcode &
				  UET_SES_OPCODE_MASK) >> UET_SES_OPCODE_SHIFT;
		pp->ses_msg_id = ntohs(ses_req->cmn.msg_id);
		switch (pp->ses_opcode) {
		case UET_ATOMIC:
		case UET_FETCH_ATOMIC:
		case UET_TSEND_ATOMIC:
		case UET_TSEND_FETCH_ATOMIC:
			pp->ses_len += sizeof(struct uet_ses_atomic_ext);
			break;
		case UET_RNDV_SEND:
		case UET_RNDV_TSEND:
			pp->ses_len += sizeof(struct uet_ses_rndv_ext);
			break;
		case UET_SYNC_WRITE:
			pp->ses_len += sizeof(struct uet_ses_sync_ext);
			break;
		case UET_SYNC_ATOMIC:
			pp->ses_len += sizeof(struct uet_ses_atomic_ext) +
				       sizeof(struct uet_ses_sync_ext);
			break;
		default:
			break;
		}
		cur_len += pp->ses_len;
		p = ((uint8_t *) pkt) + cur_len;
		pp->payload = p;
		pp->hdr_len = cur_len;

		pp->pkt_payload_len =
			pp->pkt_len - (pp->hdr_len + pp->trailer_len);

		pp->ses_payload_len = uet_get_ses_req_payload_len(
						pp, uet->max_payload_len);

		if (pp->ses_opcode != UET_READ) {
			rc = uet_parse_chk_next_field(
					pp, cur_len, pp->ses_payload_len);
			if (rc != 0)
				return rc;
			cur_len += pp->ses_payload_len;
		}
		break;
	case UET_HDR_RSP:
		ses_rsp = (struct uet_ses_rsp *) pp->ses;
		pp->ses_opcode = (ses_rsp->cmn.list_opcode &
				  UET_SES_OPCODE_MASK) >> UET_SES_OPCODE_SHIFT;
		pp->ses_msg_id = ntohs(ses_rsp->cmn.msg_id);

		if (pp->ses_opcode == UET_DEFAULT_RESPONSE) {
			rc = uet_parse_chk_next_field(
					pp, cur_len,
					sizeof(struct uet_pds_def_rsp));
			if (rc != 0)
				return rc;
			pp->ses_len = sizeof(struct uet_pds_def_rsp);
		} else {
			rc = uet_parse_chk_next_field(
					pp, cur_len,
					sizeof(struct uet_ses_rsp));
			if (rc != 0)
				return rc;
			pp->ses_len = sizeof(struct uet_ses_rsp);
		}

		cur_len += pp->ses_len;
		pp->hdr_len = cur_len;
		break;
	case UET_HDR_RSP_DATA:
		rc = uet_parse_chk_next_field(
				pp, cur_len, sizeof(struct uet_ses_rsp_d));
		if (rc != 0)
			return rc;
		pp->ses_len = sizeof(struct uet_ses_rsp_d);
		ses_rsp_d = (struct uet_ses_rsp_d *) pp->ses;
		p = ((uint8_t *) ses_rsp_d) + pp->ses_len;
		pp->payload = p;
		pp->hdr_len = cur_len;
		pp->ses_opcode = (ses_rsp_d->cmn.list_opcode &
				  UET_SES_OPCODE_MASK) >> UET_SES_OPCODE_SHIFT;
		pp->ses_msg_id = ntohs(ses_rsp_d->cmn.msg_id);
		pp->pkt_payload_len =
			pp->pkt_len - (pp->hdr_len + pp->trailer_len);
		pp->ses_payload_len =
			(ntohl(ses_rsp_d->rd_msg_id_payload_len) &
			 UET_SES_RSP_D_PAYLOAD_LEN_MASK) >>
			UET_SES_RSP_D_PAYLOAD_LEN_SHIFT;
		rc = uet_parse_chk_next_field(pp, cur_len, pp->ses_payload_len);
		if (rc != 0)
			return rc;
		cur_len += pp->ses_payload_len;
		break;
	case UET_HDR_REQ_SMALL:
	case UET_HDR_REQ_MEDIUM:
	case UET_HDR_RSP_DATA_SMALL:
	default:
		goto err_exit;
	}

	return 0;

err_exit:
	return -EINVAL;
}
