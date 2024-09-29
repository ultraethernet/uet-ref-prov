/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

#include <linux/types.h>
#include <linux/kstrtox.h>
#include <asm-generic/errno-base.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/ip.h>

#include "uthash.h"

#include "uet_uapi.h"
#include "uet_pds.h"
#include "uet_log.h"
#include "uet_sec.h"
#include "bitmap.h"
#include "uet_api_private.h"

#define UET_DEFAULT_TC        0
#define UET_DEFAULT_MPR       128
#define UET_DEFAULT_START_PSN 13
#define UET_DEFAULT_ENTROPY   0

#define UET_PDC_MAX 64

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
	struct uet_list_entry    node;
	int                   psn;
	uint16_t              msg_id;

	uint8_t              *pkt_buf;
	int                   pkt_buf_len;
	uint8_t              *pkt;
	int                   pkt_len;
	uint64_t                tx_time; /* tx time for detecting timeout */
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
struct uet_pdc_key {
	pdc_type_t    type;
	uint32_t      job_id;
	struct uet_fa dst_ip;
	uint8_t       tc;
	uint16_t      spdcid; /* only used for receive side lookups */
};

struct uet_pdc {
	struct uet_list_entry  node;

	pdc_state_t         state;
	bool                is_initiator;

	uint16_t            pdc_id; /* local PDC identifier */
	uint16_t            dpdcid; /* peer PDC identifier */
	uint32_t            open_msg_cnt; /* can only free the PDC if zero */

	struct uet_pdc_key  hkey;
	UT_hash_handle      pdc_hh; /* hash handle for the PDC */

	struct uet_list_entry  tx_pkt_list_head; /* 'tx_time' order (for rtx) */

	/* initiator side fields (and target side reverse direction) */
	uint16_t            syn_offset; /* initiator SYN offset until ACK */
	uint32_t            next_psn; /* next Tx pkt seq number */
	struct bitmap      *tx_bm;
	struct bitmap      *ack_bm;
	uint32_t            tx_bm_base_psn; /* start PSN for initiator MPR */

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
	struct uet_list_entry    pdc_alloc_head;
	struct uet_list_entry    pdc_free_head;
	struct uet_pdc       *pdc_ht; /* key = "type|job_id|dst_ip|tc" */
	struct uet_msgid_map *pdc_msgid_ht; /* key = "msg_id" */
	struct uet_list_entry    pending_pkts_head; /* TODO: not implemented yet */
};

static struct uet_pds_state pds_state;

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
	printk("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
	       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* print ipv4 address */
void uet_print_ipv4_addr(uint32_t ipv4_addr)
{
	printk("%d.%d.%d.%d\n",
	       (ipv4_addr >> 24) & 0xff, (ipv4_addr >> 16) & 0xff,
	       (ipv4_addr >> 8)  & 0xff, ipv4_addr & 0xff);
}

/* print uet address */
void uet_print_uet_addr(struct uet_addr *uet_addr)
{
	char ip_addr_str[INET_ADDRSTRLEN];

	uet_ipv4_addr_to_str(uet_addr->fa.v4, ip_addr_str);

	printk("UET Address\n");
	printk("  IP Address:      %s\n", ip_addr_str);
	printk("  PIDonFEP:        %u\n", uet_addr->pid_on_fep);
	printk("  Index:           %u\n", uet_addr->start_index);
	printk("  Initiator ID:    %u\n", uet_addr->initiator_id);
	printk("  Profiles:      ");
	if (uet_addr->fep_cap & UET_FEP_CAP_AI_MIN)
		printk("  AI Min");
	if (uet_addr->fep_cap & UET_FEP_CAP_AI_FULL)
		printk("  AI Full");
	if (uet_addr->fep_cap & UET_FEP_CAP_HPC)
		printk("  HPC");
	printk("\n");
}

/* print mac header */
void uet_print_mac_hdr(struct ethhdr *eth)
{
	printk("  MAC Header (%lu)\n", sizeof(struct ethhdr));
	printk("    Destination MAC Addr: ");
	uet_print_mac_addr(eth->h_dest);
	printk("    Source MAC Addr:      ");
	uet_print_mac_addr(eth->h_source);
	printk("    Ethertype:            0x%.4x\n", ntohs(eth->h_proto));
}

/* print ipv4 header */
void uet_print_ipv4_hdr(struct iphdr *ipv4)
{
	printk("  IPv4 Header (%lu)\n", sizeof(struct iphdr));
	printk("    IP Version:           %u\n", ipv4->version);
	printk("    IHL:                  %u\n", ipv4->ihl);
	printk("    TOS:                  0x%x\n", ipv4->tos);
	printk("    Tot Len:              %u\n", ntohs(ipv4->tot_len));
	printk("    ID:                   %u\n", ntohs(ipv4->id));
	printk("    Frag Offset:          0x%x\n", ntohs(ipv4->frag_off));
	printk("    TTL:                  %u\n", ipv4->ttl);
	printk("    Protocol:             0x%x\n", ipv4->protocol);
	printk("    Checksum:             0x%x\n", ntohs(ipv4->check));
	printk("    Destination Addr:     ");
	uet_print_ipv4_addr(ntohl(ipv4->daddr));
	printk("    Source Addr:          ");
	uet_print_ipv4_addr(ntohl(ipv4->saddr));
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

	if (pp->sec) {
		printk("  USP Header (%d)\n", pp->sec_len);
		printk("    USP AN:               %d\n", pp->sec_an);
		printk("    USP SDI:              0x%08x\n", pp->sec_sdi);
		if (pp->sec_ssi_valid) {
			printk("    USP SSI:              0x%08x\n",
			        pp->sec_ssi);
		}
		printk("    USP TSC:              0x%016lx\n", pp->sec_tsc);
	}

	printk("  PDS Header (%d)\n", pp->pds_len);
	printk("    PDS Packet Type:      ");

	switch (pp->pds_type) {
	case UET_PDS_TYPE_ROD_REQ:
	case UET_PDS_TYPE_RUD_REQ:
		printk("%s Request\n",
		       (pp->pds_type == UET_PDS_TYPE_ROD_REQ) ? "ROD" : "RUD");
		break;
	case UET_PDS_TYPE_RUDI_REQ:
		printk("RUDI Request\n");
		break;
	case UET_PDS_TYPE_RUDI_RESP:
		printk("RUDI Response\n");
		break;
	case UET_PDS_TYPE_UUD_REQ:
		printk("UUD Request\n");
		break;
	case UET_PDS_TYPE_ACK:
		printk("ACK\n");
		break;
	case UET_PDS_TYPE_NACK:
		printk("NACK\n");
		break;
	case UET_PDS_TYPE_CTRL:
		printk("CTRL\n");
		break;
	default:
		printk("Unknown (0x%x)\n", pp->pds_type);
		return;
	}

	printk("    PDS Next Header:      ");
	switch (pp->next_hdr) {
	case UET_HDR_REQ_SMALL:
		printk("SES Standard Request Small\n");
		break;
	case UET_HDR_REQ_MEDIUM:
		printk("SES Standard Request Medium\n");
		break;
	case UET_HDR_REQ_STD:
		printk("SES Standard Request\n");
		break;
	case UET_HDR_RSP:
		printk("SES Response\n");
		break;
	case UET_HDR_RSP_DATA:
		printk("SES Response with Data\n");
		break;
	case UET_HDR_RSP_DATA_SMALL:
		printk("SES Response with Data Small\n");
		break;
	default:
		printk("Unknown (0x%x)\n", pp->next_hdr);
		return;
	}

	printk("    PDS Flags:            0x%02x\n", pp->pds_flags);
	printk("    PDS PSN:              %u\n", pp->pds_psn);
	printk("    PDS Source PDCID:     %u\n", pp->pds_spdcid);

	if ((pp->next_hdr == UET_HDR_REQ_SMALL) ||
	    (pp->next_hdr == UET_HDR_REQ_MEDIUM) ||
	    (pp->next_hdr == UET_HDR_REQ_STD)) {
		if (pp->pds_flags & UET_PDS_REQ_FLAGS_SYN)
			printk("    PDS SYN Offset:       %u\n", pp->pds_syn_off);
		else
			printk("    PDS Dest PDCID:       %u\n", pp->pds_dpdcid);
		printk("    PDS Clear PSN:        %u\n", pp->pds_clear_fwd_psn);
	} else if ((pp->next_hdr == UET_HDR_RSP_DATA) ||
		   (pp->next_hdr == UET_HDR_RSP_DATA_SMALL)) {
		printk("    PDS Dest PDCID:       %u\n", pp->pds_dpdcid);
		printk("    PDS Forward PSN:      %u\n", pp->pds_clear_fwd_psn);
	} else { /* UET_HDR_RSP */
		printk("    PDS Dest PDCID:       %u\n", pp->pds_dpdcid);
	}

	printk("  SES Header (%d)\n", pp->ses_len);
	switch (pp->next_hdr) {
	case UET_HDR_REQ_STD:
		printk("    SES Opcode:           ");
		ses_req_std = (struct uet_ses_req_std *) pp->ses;
		opcode = ((ses_req_std->cmn.eom_opcode &
			   UET_SES_OPCODE_MASK) >> UET_SES_OPCODE_SHIFT);
		if (ses_req_std->cmn.eom_opcode & UET_SES_EOM_MASK)
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
			printk("SEND, SOM = %d, EOM = %d\n", som, eom);
			break;
		case UET_DEFER_SEND:
			printk("DEFERRED SEND, SOM = %d, EOM = %d\n", som, eom);
			break;
		case UET_TAGGED_SEND:
			printk("TAGGED SEND, SOM = %d, EOM = %d\n", som, eom);
			break;
		case UET_DEFER_TSEND:
			printk("DEFERRED TAGGED SEND, SOM = %d, EOM = %d\n",
			       som, eom);
			break;
		case UET_DEFER_RTR:
			printk("DEFERRED RTR, SOM = %d, EOM = %d\n", som, eom);
			break;
		case UET_WRITE:
			printk("WRITE, SOM = %d, EOM = %d\n", som, eom);
			break;
		case UET_READ:
			printk("READ, SOM = %d, EOM = %d\n", som, eom);
			break;
		default:
			printk("Unknown (0x%x), SOM = %d, EOM = %d\n",
			       opcode, som, eom);
			return;
		}
		printk("    SES Flags:            0x%x\n",
		       ses_req_std->cmn.ver_flags);
		index = ((ntohs(ses_req_std->cmn.rsvd_res_index) &
			  UET_SES_REQ_RES_INDEX_MASK) >>
			 UET_SES_REQ_RES_INDEX_SHIFT);
		printk("    SES Index:            %u\n", index);
		job_id = ((ntohl(ses_req_std->cmn.index_gen_job_id) &
			   UET_SES_REQ_JOB_ID_MASK) >>
			  UET_SES_REQ_JOB_ID_SHIFT);
		printk("    SES Job ID:           %u\n", job_id);
		gen = (uint8_t)((ntohl(ses_req_std->cmn.index_gen_job_id) &
				 UET_SES_REQ_INDEX_GEN_MASK) >>
				UET_SES_REQ_INDEX_GEN_SHIFT);
		printk("    SES Generation:       %u\n", gen);
		pid_on_fep = ((ntohl(ses_req_std->cmn.rsvd_pid_on_fep) &
			       UET_SES_REQ_PID_ON_FEP_MASK) >>
			      UET_SES_REQ_PID_ON_FEP_SHIFT);
		printk("    SES PIDonFEP:         %u\n", pid_on_fep);
		printk("    SES Message ID:       %u\n", pp->ses_msg_id);
		printk("    SES Initiator ID:     %u\n",
		       ntohl(ses_req_std->initiator));
		printk("    SES Request Length:   %u\n",
		       ntohl(ses_req_std->req_len));
		if ((opcode != UET_DEFER_SEND) && (opcode != UET_DEFER_TSEND))
			printk("    SES Buffer Offset:    %lu\n",
			       ntohll(ses_req_std->buf_off));
		else
			printk("    SES Restart Token:    0x%016lx\n",
			       ntohll(ses_req_std->restart_token));
		if (som && hd)
			printk("    SES Header Data:      %lu\n",
			       ntohll(ses_req_std->cmpl_data));
		else if (!som) {
			msg_off = (ntohll(ses_req_std->msg_off_payload_len)
				   & UET_SES_REQ_STD_MSG_OFF_MASK) >>
				  UET_SES_REQ_STD_MSG_OFF_SHIFT;
			payload_len =
				(ntohll(ses_req_std->msg_off_payload_len) &
				 UET_SES_REQ_STD_PAYLOAD_LEN_MASK) >>
				UET_SES_REQ_STD_PAYLOAD_LEN_SHIFT;
			printk("    SES Message Offset:   %lu\n", msg_off);
			printk("    SES Payload Length:   %lu\n", payload_len);
		}
		if (opcode != UET_DEFER_RTR)
			printk("    SES Match Bits:       0x%lx\n",
			       ntohll(ses_req_std->match_bits));
		else
			printk("    SES RTR Token:        0x%016lx\n",
			       ntohll(ses_req_std->restart_token_rtr));
		break;
	case UET_HDR_RSP:
		printk("    SES Opcode:           ");
		ses_rsp = (struct uet_ses_rsp *) pp->ses;
		opcode = ((ses_rsp->cmn.list_opcode &
			   UET_SES_OPCODE_MASK) >> UET_SES_OPCODE_SHIFT);
		switch (opcode) {
		case UET_RESPONSE:
			printk("RESPONSE\n");
			break;
		default:
			printk("Unknown (0x%x)\n", opcode);
			return;
		}
		rc = ((ses_rsp->cmn.ver_ret_code &
		       UET_SES_RSP_RET_CODE_MASK) >>
		      UET_SES_RSP_RET_CODE_SHIFT);
		printk("    SES Return Code:      %u (%s)\n",
		       rc, uet_ses_rc_to_str(rc));
		gen = (uint8_t)((ntohl(ses_rsp->cmn.index_gen_job_id) &
				 UET_SES_RSP_INDEX_GEN_MASK) >>
				UET_SES_RSP_INDEX_GEN_SHIFT);
		printk("    SES Generation:       %u\n", gen);
		job_id = ((ntohl(ses_rsp->cmn.index_gen_job_id) &
			   UET_SES_RSP_JOB_ID_MASK) >>
			  UET_SES_RSP_JOB_ID_SHIFT);
		printk("    SES Job ID:           %u\n", job_id);
		printk("    SES Message ID:       %u\n", pp->ses_msg_id);
		printk("    SES Modified Length:  %u\n",
		       ntohl(ses_rsp->mod_len));
		break;
	case UET_HDR_RSP_DATA:
		ses_rsp_d = (struct uet_ses_rsp_d *) pp->ses;
		printk("    SES Opcode:           ");
		opcode = ((ses_rsp_d->cmn.list_opcode &
			   UET_SES_OPCODE_MASK) >> UET_SES_OPCODE_SHIFT);
		switch (opcode) {
		case UET_RESPONSE_W_DATA:
			printk("RESPONSE WITH DATA\n");
			break;
		default:
			printk("Unknown (0x%x)\n", opcode);
			return;
		}
		rc = ((ses_rsp_d->cmn.ver_ret_code &
		       UET_SES_RSP_RET_CODE_MASK) >>
		      UET_SES_RSP_RET_CODE_SHIFT);
		printk("    SES Return Code:      %u\n", rc);
		gen = (uint8_t)
			((ntohl(ses_rsp_d->cmn.index_gen_job_id) &
			  UET_SES_RSP_INDEX_GEN_MASK) >>
			 UET_SES_RSP_INDEX_GEN_SHIFT);
		printk("    SES Generation:       %u\n", gen);
		job_id = ((ntohl(ses_rsp_d->cmn.index_gen_job_id) &
			   UET_SES_RSP_JOB_ID_MASK) >>
			  UET_SES_RSP_JOB_ID_SHIFT);
		printk("    SES Job ID:           %u\n", job_id);
		printk("    SES Message ID:       %u\n", pp->ses_msg_id);
		printk("    SES Modified Length:  %u\n",
		       ntohl(ses_rsp_d->mod_len));
		printk("    SES Message Offset:   %u\n",
		       ntohl(ses_rsp_d->msg_off));
		printk("    SES Payload Length:   %u\n",
		       (ntohl(ses_rsp_d->rsvd_payload_len) &
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
	printk("UET Packet Headers (pkt_len=%d)\n", pp->pkt_len);
	uet_print_mac_hdr((struct ethhdr *) pp->eth);
	uet_print_ipv4_hdr((struct iphdr *) pp->ip); /* TODO: IPv6 support */
	uet_print_uet_hdr(pp);
}


#define PDS_GO()                                          \
	do {                                              \
		if (pds_state.ready != true) {            \
			UET_PDS_ERR("PDS is not ready!"); \
			BUG_ON(1);                          \
		}                                         \
	} while (0)

#define PSN_IN_MPR(psn, base_psn)                            \
	(((uint32_t)((psn) - (base_psn)) >= 0) &&            \
	 ((uint32_t)((psn) - (base_psn)) < UET_DEFAULT_MPR))

#define PSN_IN_PRIOR_MPR(psn, base_psn)                             \
	PSN_IN_MPR((psn), (uint32_t)((base_psn) - UET_DEFAULT_MPR))

#define PDS_TYPE_TO_STR(t)                              \
	(((t) == UET_PDS_TYPE_RUD_REQ)   ? "RUD_REQ" :  \
	 ((t) == UET_PDS_TYPE_ROD_REQ)   ? "ROD_REQ" :  \
	 ((t) == UET_PDS_TYPE_RUDI_REQ)  ? "RUDI_REQ" : \
	 ((t) == UET_PDS_TYPE_UUD_REQ)   ? "UUD_REQ" :  \
	 ((t) == UET_PDS_TYPE_RUDI_RESP) ? "RUDI_RSP" : \
	 ((t) == UET_PDS_TYPE_ACK)       ? "ACK" :      \
	 ((t) == UET_PDS_TYPE_NACK)      ? "NACK" :     \
	 ((t) == UET_PDS_TYPE_CTRL)      ? "CTRL" :     \
					   "UNKNOWN")
#define NEXT_HDR_TO_STR(n)                                    \
	(((n) == UET_HDR_REQ_SMALL)      ? "REQ_SMALL" :      \
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
		    NEXT_HDR_TO_STR((pp)->next_hdr),             \
		    (msg),                                       \
		    (pp)->pkt_len)

#define PDS_DBG_RX(pp, msg)                                      \
	UET_PDS_DBG("PDC %u [Rx %u] [PSN %u] [%s/%s] - %s (%d)", \
		    (pp)->pds_dpdcid, (pp)->pds_spdcid,          \
		    (pp)->pds_psn,                               \
		    PDS_TYPE_TO_STR((pp)->pds_type),             \
		    NEXT_HDR_TO_STR((pp)->next_hdr),             \
		    (msg),                                       \
		    (pp)->pkt_len)

static int uet_parse_pkt(void *pkt, size_t pkt_len, struct uet_parsed_pkt *pp, 
		  uint16_t uet_udp_port, size_t max_payload_len);

#define UET_PDS_PKT_HDR_TRACE_ENABLED

#ifdef UET_PDS_PKT_HDR_TRACE_ENABLED
#define UET_PDS_PKT_HDR_TRACE(UET, PP, PKT, PKT_LEN, MSG)            \
	do {                                                         \
		struct uet_parsed_pkt _pp;                           \
		if ((PP) == NULL) {                                  \
			if (uet_parse_pkt((PKT),                     \
					  (PKT_LEN), &_pp,           \
					  (UET)->uet_udp_port,       \
					  (UET)->max_payload_len) == \
			    0) {                                     \
				printk("\n%s\n\n", (MSG));           \
				uet_print_pkt_hdrs((&_pp));          \
				printk("\n");                        \
			}                                            \
		} else {                                             \
			printk("\n%s\n\n", (MSG));                   \
			uet_print_pkt_hdrs((PP));                    \
			printk("\n");                                \
		}                                                    \
	} while (0)
#else
#define UET_PDS_PKT_HDR_TRACE(...)
#endif

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

/****************************************************************************/
/*                       Security and NIC Shim APIs                         */
/****************************************************************************/

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

static int uet_parse_chk_next_field(struct uet_parsed_pkt *pp,
				    uint16_t field_offset, uint16_t field_len)
{
	if ((field_offset + field_len) > pp->pkt_len)
		return -EFAULT;
	return 0;
}

static int uet_get_ipv6_nexthdr(struct uet_parsed_pkt *pp)
{
	int rc;
	struct ipv6hdr *ipv6;
	struct ipv6_opt_hdr *opt_hdr;

	ipv6 = (struct ipv6hdr *) pp->ip;
	pp->ip_len = sizeof(struct ipv6hdr);
	pp->ip_protocol = ipv6->nexthdr;

	while (1) {
		if ((pp->ip_protocol == UET_IPPROTO) ||
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

static int uet_parse_pkt(void *pkt, size_t pkt_len, struct uet_parsed_pkt *pp, 
		  uint16_t uet_udp_port, size_t max_payload_len)
{
	int rc, num_vlan_tags = 0;
	uint8_t *p, ip_ver;
	uint16_t cur_len, *etype_p, ethertype, pds_type_next_flags;
	bool done = false;
	struct iphdr *ipv4;
	struct udphdr *udp;
	struct uet_sec *sec;
	struct uet_sec_ssi *sec_ssi;
	struct uet_pds_prlg *pds_prlg;
	struct uet_pds_req *pds_req;
	struct uet_pds_ack *pds_ack;
	struct uet_pds_nack *pds_nack;
	struct uet_pds_ctrl *pds_ctrl;
	struct uet_ses_req_std *ses_req;
	struct uet_ses_rsp *ses_rsp;
	struct uet_ses_rsp_d *ses_rsp_d;

	memset(pp, 0, sizeof(struct uet_parsed_pkt));

	p = (uint8_t *) pkt;
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
			if (pp->ethertype == UET_IPPROTO)
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
	if (pp->ethertype == UET_IPPROTO) {
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
	} else
		ethertype = pp->ethertype;
	switch (ethertype) {
	case ETH_P_IP:
		ipv4 = (struct iphdr *) p;
		pp->ip_protocol = ipv4->protocol;
		pp->ip_len = ipv4->ihl << 2;
		break;
	case ETH_P_IPV6:
		rc = uet_get_ipv6_nexthdr(pp);
		if (rc != 0)
			return rc;
		break;
	default:
		goto err_exit;
	}

	cur_len += pp->ip_len;
	p = ((uint8_t *) pkt) + cur_len;

	/* parse udp header */
	if (pp->ip_protocol != UET_IPPROTO) {
		switch (pp->ip_protocol) {
		case IPPROTO_UDP:
			udp = (struct udphdr *) p;
			rc = uet_parse_chk_next_field(
				pp, cur_len, sizeof(struct udphdr));
			if (rc != 0)
				return rc;
			if (ntohs(udp->dest) != uet_udp_port)
				goto err_exit;
			pp->entropy = ntohs(udp->source);
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
	pds_prlg = (struct uet_pds_prlg *) p;
	rc = uet_parse_chk_next_field(pp, cur_len, sizeof(struct uet_pds_prlg));
	if (rc != 0)
		return rc;
	if (pp->udp_len == 0)
		pp->entropy = ntohs(pds_prlg->entropy);
	pds_type_next_flags = ntohs(pds_prlg->type_next_flags);
	pp->pds_type = ((pds_type_next_flags & UET_PDS_TYPE_MASK) >>
			UET_PDS_TYPE_SHIFT);
	if (pp->pds_type == UET_PDS_TYPE_SECURITY) {
		if (((pds_type_next_flags & UET_PDS_NEXT_HDR_MASK) >>
		      UET_PDS_NEXT_HDR_SHIFT) != UET_HDR_PDS)
			goto err_exit;
		pp->sec = pds_prlg;
		if (pds_type_next_flags & UET_SEC_SP_MASK) {
			sec_ssi = (struct uet_sec_ssi *)pds_prlg;
			pp->sec_an = !!(ntohl(sec_ssi->an_sdi) &
					UET_SEC_AN_MASK);
			pp->sec_sdi = (ntohl(sec_ssi->an_sdi) &
				       UET_SEC_SDI_MASK);
			pp->sec_ssi_valid = true;
			pp->sec_ssi = ntohl(sec_ssi->ssi);
			pp->sec_tsc = ntohll(sec_ssi->tsc);
			pp->sec_len = sizeof(struct uet_sec_ssi);
		} else {
			sec = (struct uet_sec *)pds_prlg;
			pp->sec_an = !!(ntohl(sec->an_sdi) &
					UET_SEC_AN_MASK);
			pp->sec_sdi = (ntohl(sec->an_sdi) &
				       UET_SEC_SDI_MASK);
			pp->sec_ssi_valid = false;
			pp->sec_tsc = ntohll(sec->tsc);
			pp->sec_len = sizeof(struct uet_sec);
		}
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
		pp->trailer_len = UET_SEC_ICV_SIZE;
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
		pp->pds_clear_fwd_psn = ntohl(pds_req->clear_psn);
		if (pp->pds_flags & UET_PDS_REQ_FLAGS_SYN)
			pp->pds_syn_off = ((ntohs(pds_req->mode_psn_off) &
					    UET_PDS_REQ_PSN_OFF_MASK) >>
					   UET_PDS_REQ_PSN_OFF_SHIFT);
		else
			pp->pds_dpdcid = ntohs(pds_req->dpdcid);
		break;
	case UET_PDS_TYPE_UUD_REQ:
		pp->pds_len = sizeof(struct uet_pds_uud_req);
		return 0;
	case UET_PDS_TYPE_ACK:
		pds_ack = (struct uet_pds_ack *)pp->pds;
		pp->pds_len = sizeof(struct uet_pds_ack);
		pp->pds_psn = ntohl(pds_ack->psn);
		pp->pds_spdcid = ntohs(pds_ack->spdcid);
		pp->pds_dpdcid = ntohs(pds_ack->dpdcid);
		if (pp->pds_flags & UET_PDS_ACK_FLAGS_AX)
			pp->pds_len += sizeof(struct uet_pds_ack_ext);
		/* TODO: support for parsing the extended ACK header */
		break;
	case UET_PDS_TYPE_NACK:
		pds_nack = (struct uet_pds_nack *)pp->pds;
		pp->pds_len = sizeof(struct uet_pds_nack);
		pp->pds_psn = ntohl(pds_nack->nack_psn);
		pp->pds_spdcid = ntohs(pds_nack->spdcid);
		pp->pds_dpdcid = ntohs(pds_nack->dpdcid);
		pp->pds_nack_code = pds_nack->nack_code;
		if (pp->pds_flags & UET_PDS_NACK_FLAGS_AX)
			pp->pds_len += (sizeof(struct uet_pds_ack_ext) - 4);
		/* TODO: support for parsing the extended ACK header */
		return 0;
	case UET_PDS_TYPE_CTRL:
		pds_ctrl = (struct uet_pds_ctrl *)pp->pds;
		pp->pds_len = sizeof(struct uet_pds_ctrl);
		pp->pds_ctrl_payload = ntohl(pds_ctrl->payload);
		/* TODO: support for parsing control messages */
		return 0;
	case UET_PDS_TYPE_RUDI_REQ:
	case UET_PDS_TYPE_RUDI_RESP:
		/* TODO: support for parsing RUDI */
	default:
		goto err_exit;
	}

	cur_len += pp->pds_len;
	p = ((uint8_t *) pkt) + cur_len;

	/* parse ses header */
	pp->ses = p;
	switch (pp->next_hdr) {
	case UET_HDR_REQ_STD:
		rc = uet_parse_chk_next_field(
			pp, cur_len, sizeof(struct uet_ses_req_std));
		if (rc != 0)
			return rc;
		pp->ses_len = sizeof(struct uet_ses_req_std);
		ses_req = (struct uet_ses_req_std *) pp->ses;
		pp->ses_opcode = (ses_req->cmn.eom_opcode &
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
		default:
			break;
		}
		cur_len += pp->ses_len;
		p = ((uint8_t *) pkt) + cur_len;
		pp->payload = p;
		pp->hdr_len = cur_len;

		if (ses_req->cmn.ver_flags & UET_SES_REQ_FLAG_CRC)
			pp->trailer_len += UET_SES_CRC_SIZE;

		pp->pkt_payload_len =
			pp->pkt_len - (pp->hdr_len + pp->trailer_len);

		pp->ses_payload_len = uet_get_ses_req_payload_len(
						pp, max_payload_len);

		if (pp->ses_opcode != UET_READ) {
			rc = uet_parse_chk_next_field(
					pp, cur_len, pp->ses_payload_len);
			if (rc != 0)
				return rc;
			cur_len += pp->ses_payload_len;
		}

		if (ses_req->cmn.ver_flags & UET_SES_REQ_FLAG_CRC) {
			rc = uet_parse_chk_next_field(
					pp, cur_len, UET_SES_CRC_SIZE);
			if (rc != 0)
				return rc;
			pp->ses_crc = ((uint8_t *) pkt) + cur_len;
			cur_len += UET_SES_CRC_SIZE;
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
		cur_len += pp->ses_len;
		pp->hdr_len = cur_len;
		ses_rsp_d = (struct uet_ses_rsp_d *) pp->ses;
		pp->ses_opcode = (ses_rsp_d->cmn.list_opcode &
				  UET_SES_OPCODE_MASK) >> UET_SES_OPCODE_SHIFT;
		pp->ses_msg_id = ntohs(ses_rsp_d->cmn.msg_id);
		pp->pkt_payload_len =
			pp->pkt_len - (pp->hdr_len + pp->trailer_len);
		pp->ses_payload_len =
			(ntohl(ses_rsp_d->rsvd_payload_len) &
			 UET_SES_RSP_D_PAYLOAD_LEN_MASK) >>
			UET_SES_RSP_D_PAYLOAD_LEN_SHIFT;
		pr_info("[%s][%d] rsvd_payload_len: %u ses_payload_len: %u\n",
			__func__, __LINE__, ses_rsp_d->rsvd_payload_len, 
			pp->ses_payload_len);
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

	if (pdc->sec_enabled == false) {
		if (*pp_parsed == false) {
			rc = uet_parse_pkt(*pkt, *pkt_len, pp, 
				uet->uet_udp_port, uet->max_payload_len);
			if (rc != 0) {
				UET_PDS_ERR("malformed %s packet",
					    (tx_pkt) ? "Tx" : "ACK");
				return rc;
			}

			*pp_parsed = true;
		}

		if (tx_pkt)
			uet_gettime(&pdc_pkt->tx_time);

		/* TODO: IPv6 support */
		return uet_nic_tx_pkt(UET_NIC(uet), *pkt, pp->ip, *pkt_len);
	}

	/* inject/build the security header and encrypt the packet */

#if 0
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
		*pkt_len = new_pkt_len;
	}

	if (*pp_parsed == false) {
		rc = uet_parse_pkt(*pkt, *pkt_len, pp, 
				   uet->uet_udp_port, uet->max_payload_len);
		if (rc != 0) {
			UET_PDS_ERR("malformed %s packet with security",
				    (tx_pkt) ? "Tx" : "ACK");
			return rc;
		}

		*pp_parsed = true;
	}

	rc = uet_sec_enc_pkt(pkt_buf,
			     pkt_buf_len,
			     *pkt,
			     *pkt_len,
			     &new_pkt,
			     &new_pkt_len);
	if (rc != 0)
		return rc;

	if (tx_pkt)
		uet_gettime(&pdc_pkt->tx_time);

	/* TODO: IPv6 support */
	return uet_nic_tx_pkt(UET_NIC(uet), new_pkt, pp->ip, new_pkt_len);
#else
	return -EPERM;
#endif
}

/*
 * Returns:
 *   0, no valid packet available
 *   1, read a packet
 *   negative value corresponding to fabric errno, err reading packet
 */
static int uet_pds_sec_rx_pkt(struct uet_instance *uet,
			      uint8_t **pkt,
			      int *pkt_len)
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
	*pkt = kcalloc(1, uet->nic.max_pkt_size, GFP_KERNEL);
	if (*pkt == NULL) {
		UET_PDS_ERR("failed to alloc Rx packet buffer");
		return -ENOMEM;
	}

	/* receive the packet */
	rc = uet_nic_rx_pkt(UET_NIC(uet),
			    *pkt,
			    uet->nic.max_pkt_size,
			    (size_t *)pkt_len);
	if (rc != 1)
		goto err_exit;

	/* decrypt the packet if the security header is present */
	rc = uet_sec_dec_pkt(*pkt, *pkt_len, &tag_len);
	if (rc != 0)
		goto err_exit;

	return 1;

err_exit:
	kfree(*pkt);
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
	/* initialze this PDC and stick it in the hashtable */
	pdc->state = state;
	pdc->is_initiator = is_initiator;

	pdc->dpdcid = 0;
	pdc->open_msg_cnt = 0;

	uet_list_init(&pdc->tx_pkt_list_head);

	pdc->syn_offset = 0;
	pdc->next_psn = 0;
	bm_clear(pdc->tx_bm);
	bm_clear(pdc->ack_bm);
	pdc->tx_bm_base_psn = 0;

	bm_clear(pdc->rx_bm);
	pdc->rx_bm_base_psn = 0;
}

static struct uet_pdc *uet_pdsm_alloc_pdc(void)
{
	struct uet_pdc *pdc;

	PDS_GO();

	/* allocate a new PDC from the head of the free list */
	pdc = uet_list_first_entry_or_null(&pds_state.pdc_free_head,
					struct uet_pdc, node);
	if (pdc == NULL)
		return NULL;

	uet_list_remove(&pdc->node);

	uet_list_insert_tail(&pdc->node, &pds_state.pdc_alloc_head);

	return pdc;
}

static void uet_pdsm_free_pdc(struct uet_pdc *pdc)
{
	PDS_GO();

	pdc->state = PDC_STATE_UNALLOC;

	/* free a PDC by inserting to the tail of the free list */
	uet_list_remove(&pdc->node);
	uet_list_insert_tail(&pdc->node, &pds_state.pdc_free_head);
}

/* FIXME: get the security SDI/SSI based on JobID */
static void uet_pdsm_get_sdi(struct uet_pdc *pdc)
{
	char *sec_ssi;

	pdc->sec_enabled = false /* FIXME: !!getenv(UET_SEC_MODE) */;
	pdc->sdi = 1; /* fixed SDI for now... */
	pdc->ssi = 0;

	sec_ssi = NULL /* FIXME: getenv(UET_SEC_SSI) */;
	if (sec_ssi)
		pdc->ssi = kstrtoul(sec_ssi, 10, NULL);
}

static struct uet_pdc *uet_pdsm_assign_ini_pdc(struct uet_ep *uet_ep,
					       struct uet_addr *dst_addr,
					       uet_pds_mode_t mode)
{
	struct uet_pdc_key pdc_key;
	struct uet_pdc *pdc;

	PDS_GO();

	/* get the PDC if it already exists */
	memset(&pdc_key, 0, sizeof(pdc_key));
	pdc_key.type = ((mode == UET_PDS_MODE_ROD) ? PDC_TYPE_ROD :
			(mode == UET_PDS_MODE_RUD) ? PDC_TYPE_RUD :
						     PDC_TYPE_NONE);
	pdc_key.job_id = uet_ep->job_id;
	pdc_key.tc = UET_DEFAULT_TC;
	memcpy(&pdc_key.dst_ip, &dst_addr->fa, sizeof(struct uet_fa));

	HASH_FIND(pdc_hh, pds_state.pdc_ht, &pdc_key,
		  sizeof(struct uet_pdc_key), pdc);
	if (pdc) {
		UET_PDS_DBG("lookup found initiator PDC %u", pdc->pdc_id);
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
	pdc->next_psn       = UET_DEFAULT_START_PSN;
	pdc->tx_bm_base_psn = UET_DEFAULT_START_PSN;
	pdc->rx_bm_base_psn = UET_DEFAULT_START_PSN;
	memcpy(&pdc->hkey, &pdc_key, sizeof(struct uet_pdc_key));
	HASH_ADD(pdc_hh, pds_state.pdc_ht, hkey,
		 sizeof(struct uet_pdc_key), pdc);

	uet_pdsm_get_sdi(pdc);

	UET_PDS_DBG("allocated initiator PDC %u", pdc->pdc_id);

	return pdc;
}

static struct uet_pdc *uet_pdsm_assign_tgt_pdc(struct uet_parsed_pkt *pp)
{
	struct uet_ses_req_cmn *ses_cmn = (struct uet_ses_req_cmn *)pp->ses;
	struct iphdr *ipv4 = (struct iphdr *)pp->ip; /* TODO: IPv6 support */
	struct uet_pdc_key pdc_key;
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

	pdc_key.type =
		((pp->pds_type == UET_PDS_TYPE_RUD_REQ) ? PDC_TYPE_RUD :
		 (pp->pds_type == UET_PDS_TYPE_ROD_REQ) ? PDC_TYPE_ROD :
							  PDC_TYPE_NONE);
	pdc_key.job_id = uet_get_std_req_job_id(
		(struct uet_ses_req_std *)ses_cmn);

	pdc_key.tc = UET_DEFAULT_TC;

	/* TODO: IPv6 support */
	pdc_key.dst_ip.v4 = ntohl(ipv4->daddr);

	pdc_key.spdcid = pp->pds_spdcid; /* target side needs spdcid */

	HASH_FIND(pdc_hh, pds_state.pdc_ht, &pdc_key,
		  sizeof(struct uet_pdc_key), pdc);
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

	UET_PDS_DBG("First SYN request from PDC %u (PSN %u offset %u)",
		    pp->pds_spdcid, pp->pds_psn, pp->pds_syn_off);

	/* allocate a new PDC from the head of the free list */
	pdc = uet_pdsm_alloc_pdc();
	if (!pdc) {
		UET_PDS_ERR("no free PDCs available for target");
		return NULL;
	}

	/* initialze this target PDC and stick it in the hashtable */
	uet_init_pdc(pdc, PDC_STATE_ESTABLISHED, false);
	pdc->dpdcid         = pp->pds_spdcid;
	pdc->rx_bm_base_psn = (pp->pds_psn - pp->pds_syn_off);
	pdc->tx_bm_base_psn = pdc->rx_bm_base_psn;
	pdc->next_psn       = pdc->tx_bm_base_psn;
	memcpy(&pdc->hkey, &pdc_key, sizeof(struct uet_pdc_key));
	HASH_ADD(pdc_hh, pds_state.pdc_ht, hkey,
		 sizeof(struct uet_pdc_key), pdc);

	uet_pdsm_get_sdi(pdc);

	UET_PDS_DBG("allocated target PDC %u (established with PDC %u)",
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
	msgid_map = kcalloc(1, sizeof(*msgid_map), GFP_KERNEL);
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
		return -ENOENT;
	}

	HASH_DELETE(msgid_hh, pds_state.pdc_msgid_ht, msgid_map);
	kfree(msgid_map);

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
static int uet_pdsm_insert_pend_pkt(struct uet_pdc_pkt *pdc_pkt)
{
	PDS_GO();

	/* TODO: not implemented yet */
	return -FI_ENOSYS;
}

static struct uet_pdc_pkt *uet_pdsm_remove_pend_pkt(void)
{
	PDS_GO();

	/* TODO: not implemented yet */
	return NULL;
}

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
	return -FI_ENOSYS;
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
	return -FI_ENOSYS;
}
#endif

/****************************************************************************/
/*                            PDC Initiator APIs                            */
/****************************************************************************/

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

	uet->pds.tx_timeout     = UET_DEFAULT_TX_TIMEOUT;
	uet->pds.max_tx_retries = UET_DEFAULT_MAX_TX_RETRIES;
	uet->pds.msl            = UET_DEFAULT_MSL;
	uet->pds.ack_ip_tos     = uet_dscp_to_tos(UET_IP_DEFAULT_ACK_DSCP);

	memset(&pds_state, 0, sizeof(struct uet_pds_state));

	/* initialize the PDCs */

	uet_list_init(&pds_state.pdc_alloc_head);
	uet_list_init(&pds_state.pdc_free_head);
	pds_state.pdc_ht = NULL;
	pds_state.pdc_msgid_ht = NULL;

	for (i = 0; i < UET_PDC_MAX; i++) {
		pdc = &pds_state.pdc[i];
		pdc->state = PDC_STATE_UNALLOC;
		pdc->pdc_id = i;

		pdc->tx_bm = bm_create(UET_DEFAULT_MPR);
		if (!pdc->tx_bm) {
			UET_PDS_ERR("failed to create Tx bitmap");
			uet_pdsm_free_pdc(pdc);
			return -ENOMEM; /* TODO: unwind and free PDCs */
		}

		pdc->ack_bm = bm_create(UET_DEFAULT_MPR);
		if (!pdc->ack_bm) {
			UET_PDS_ERR("failed to create ACK bitmap");
			bm_destroy(pdc->tx_bm);
			return -ENOMEM; /* TODO: unwind and free PDCs */
		}

		pdc->rx_bm = bm_create(UET_DEFAULT_MPR);
		if (!pdc->rx_bm) {
			UET_PDS_ERR("failed to create Rx bitmap");
			bm_destroy(pdc->tx_bm);
			bm_destroy(pdc->ack_bm);
			return -ENOMEM; /* TODO: unwind and free PDCs */
		}

		uet_list_insert_tail(&pdc->node, &pds_state.pdc_free_head);
	}

	/* initialize the pending packets list */

	uet_list_init(&pds_state.pending_pkts_head);

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
	while (!uet_list_empty(&pds_state.pdc_alloc_head)) {
		uet_list_pop_front(&pds_state.pdc_alloc_head,
				struct uet_pdc, pdc, node);
		HASH_DELETE(pdc_hh, pds_state.pdc_ht, pdc);
		if (pdc->tx_bm)
			bm_destroy(pdc->tx_bm);
		if (pdc->ack_bm)
			bm_destroy(pdc->ack_bm);
		if (pdc->rx_bm)
			bm_destroy(pdc->rx_bm);
	}

	/* destroy all free PDCs */
	while (!uet_list_empty(&pds_state.pdc_free_head)) {
		uet_list_pop_front(&pds_state.pdc_free_head,
				struct uet_pdc, pdc, node);
		if (pdc->tx_bm)
			bm_destroy(pdc->tx_bm);
		if (pdc->ack_bm)
			bm_destroy(pdc->ack_bm);
		if (pdc->rx_bm)
			bm_destroy(pdc->rx_bm);
	}

	/* free all the packets in the pending list */
	while (!uet_list_empty(&pds_state.pending_pkts_head)) {
		uet_list_pop_front(&pds_state.pending_pkts_head,
				struct uet_pdc_pkt, pdc_pkt, node);
		if (pdc_pkt->pkt_buf)
			kfree(pdc_pkt->pkt_buf);
		if (pdc_pkt->ack_buf)
			kfree(pdc_pkt->ack_buf);
		kfree(pdc_pkt);
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
		   struct uet_ep *uet_ep,
		   uet_addr_handle_t dst_addr_handle,
		   uet_pds_mode_t mode,
		   uet_pds_tx_flags_t flags,
		   struct uet_pds_info *pds_info,
		   uint16_t msg_id,
		   uet_next_hdr_t next_hdr,
		   void *ses,
		   size_t ses_len,
		   void *pkt,
		   size_t pkt_len,
		   bool dma_rdy)
{
	struct uet_instance *uet;
	struct uet_av_entry *av_entry;
	struct uet_addr *dst_addr;
	struct uet_pdc_pkt *pdc_pkt;
	uet_pds_pkt_type_t pds_pkt_type;
	struct uet_pdc *pdc;
	struct uet_pds_req *pds_hdr;
	void *ses_hdr, *payload;
	uint16_t pds_flags;
	int rc, hdr_len;

	PDS_GO();

	pr_info("uet: [%s] dst_addr_handle: %llx\n", __func__, (uint64_t)dst_addr_handle);

	uet = uet_ep->uet_domain->uet;
	av_entry = (struct uet_av_entry *)dst_addr_handle;
	dst_addr = av_entry->addr;
	pr_info("uet: [%s] dst_addr_handle: %u.%u.%u.%u\n", __func__, UET_NIPQUAD(dst_addr->fa.v4));

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

	/* if pds_info is specified, take the PDC from its pdcid */
	if (pds_info) {
		UET_PDS_DBG("SES Tx %p (pds_info pdcid %u psn %u)",
			    tx_pkt_handle, pds_info->pdcid, pds_info->opsn);
		pdc = uet_pdsm_get_pdc(pds_info->pdcid, true);
		if (pdc == NULL)
			return -ENODEV;
	} else if (flags & UET_PDS_FLAG_SOM) {
		UET_PDS_DBG("SES Tx %p SOM", tx_pkt_handle);
		pdc = uet_pdsm_assign_ini_pdc(uet_ep, dst_addr, mode);
		if (pdc) {
			rc = uet_pdsm_map_msgid_pdc(msg_id, pdc);
			if (rc != 0)
				return rc;
			pdc->open_msg_cnt++;
		}
	} else {
		UET_PDS_DBG("SES Tx %p", tx_pkt_handle);
		pdc = uet_pdsm_get_msgid_pdc(msg_id);
	}

	if (!pdc) {
		UET_PDS_ERR("failed to get PDC, put on pending list %p",
			    tx_pkt_handle);
		/* TODO: put this packet on the PDS pending pkt list */
		return -ENODEV;
	}

	if (!pds_info && (flags & UET_PDS_FLAG_EOM)) {
		UET_PDS_DBG("SES Tx %p EOM%s", tx_pkt_handle,
			    (flags & UET_PDS_FLAG_MAINTAIN_PDC)
				? " (maintain PDC)" : "");
		if (!(flags & UET_PDS_FLAG_MAINTAIN_PDC)) {
			rc = uet_pdsm_unmap_msgid_pdc(msg_id);
			if (rc != 0)
				return rc;
			pdc->open_msg_cnt--;
		}
	}

	/* allocate descriptor and buffer to build packet */

	/* TODO:
	 * - pull packet descriptor and buffer from a pool (not malloc)
	 * - add support for gather iov send
	 */

	pdc_pkt = kcalloc(1, sizeof(struct uet_pdc_pkt), GFP_KERNEL);
	if (pdc_pkt == NULL) {
		UET_PDS_ERR("failed to alloc PDC packet");
		return -ENOMEM;
	}

	pdc_pkt->pkt_buf_len = (uet->nic.max_pkt_size *
				((pdc->sec_enabled) ? 2 : 1));
	pdc_pkt->pkt_buf = kcalloc(1, pdc_pkt->pkt_buf_len, GFP_KERNEL);
	if (pdc_pkt->pkt_buf == NULL) {
		UET_PDS_ERR("failed to alloc packet buffer");
		kfree(pdc_pkt);
		return -ENOMEM;
	}

	pdc_pkt->pkt = (pdc->sec_enabled)
			? (pdc_pkt->pkt_buf + UET_SEC_MAX_HDR_LEN)
			: pdc_pkt->pkt_buf;

	uet_build_eth_hdr((struct ethhdr *)pdc_pkt->pkt,
			  av_entry->nh_mac_addr,
			  uet->nic.mac_addr);

	/* TODO: IPv6 support */
	pds_hdr = (struct uet_pds_req *)(pdc_pkt->pkt +
					 sizeof(struct ethhdr) +
					 sizeof(struct iphdr));
	ses_hdr = (pds_hdr + 1);
	payload = ((uint8_t *)ses_hdr + ses_len);

	/* TODO: IPv6 support */
	hdr_len = (sizeof(struct ethhdr) +
		   sizeof(struct iphdr) +
		   sizeof(struct uet_pds_req) +
		   ses_len);

	pdc_pkt->pkt_len = (hdr_len + pkt_len);

	/* fill in the PDS header */

	pds_hdr->prlg.entropy = htons(UET_DEFAULT_ENTROPY);

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
	pds_hdr->spdcid = htons(pdc->pdc_id);

	if (pdc->state == PDC_STATE_SYN) {
		pds_hdr->mode_psn_off =
			htons((pdc->syn_offset &
			       UET_PDS_REQ_PSN_OFF_MASK) <<
			      UET_PDS_REQ_PSN_OFF_SHIFT);
		pdc->syn_offset++;
	} else {
		pds_hdr->dpdcid = htons(pdc->dpdcid);
	}

	if (pds_info) {
		pds_hdr->fwd_psn = htonl(pds_info->opsn);
	} else {
		/*
		 * Set the clear_psn to the left edge of the tx_bm
		 * which moves forward as ACKs are received. Note that
		 * this is considered a cumulative clear value.
		 */
		pds_hdr->clear_psn = htonl(pdc->tx_bm_base_psn);
	}

	/* copy in the SES header and payload */

	memcpy(ses_hdr, ses, ses_len);
	memcpy(payload, pkt, pkt_len);

	/* build the IP header */

	/* TODO: IPv6 support */
	uet_build_ipv4_hdr((struct iphdr *)(pdc_pkt->pkt +
					    sizeof(struct ethhdr)),
			   htonl(dst_addr->fa.v4),
			   uet_ep->ipv4_addr,
			   (pdc_pkt->pkt_len - uet->nic.l2_hdr_size),
			   uet_ep->msg_ip_tos);

	/* save some params specific for this packet */
	pdc_pkt->msg_id        = msg_id;
	pdc_pkt->tx_retry_cnt  = 0;
	pdc_pkt->tx_pkt_handle = tx_pkt_handle;
	pdc_pkt->tx_pkt_acked  = false;
	pdc_pkt->flags         = flags;

	/* send the packet */
	rc = uet_pds_sec_tx_pkt(uet, pdc, pdc_pkt, true, false);
	if (rc != 0) {
		kfree(pdc_pkt->pkt_buf);
		kfree(pdc_pkt);
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
		//bm_print_bits(pdc->tx_bm);
		UET_PDS_DBG("PDC %u ack_bm (base %u):",
			    pdc->pdc_id, pdc->tx_bm_base_psn);
		//bm_print_bits(pdc->ack_bm);
	}

	/* insert the packet to the end of the timeout queue */
	uet_list_insert_tail(&pdc_pkt->node, &pdc->tx_pkt_list_head);

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
	uint64_t now, delta;
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

int uet_pds_progress_tx(struct uet_instance *uet,
			uet_pkt_handle_t *err_pkt_handle)
{
	struct uet_pdc *pdc;
	struct uet_list_entry *tmp1, *tmp2;
	struct uet_pdc_pkt *pdc_pkt;
	uint64_t now, delta;
	int rc;

	/* TODO:
	 * [x] walk the allocated PDC list
	 *     [x] walk the tx_pkt_list (sorted in tx time order, oldest first)
	 *         [x] if the packet has not timed out
	 *             [x] done with this PDC, continue
	 *         [x] increment the retry count
	 *         [x] if the retry count has exceeeded the max
	 *             [x] set the error handle to the tx_handle
	 *             [ ] change PDC state(?)
	 *         [x] update the tx time
	 *         [x] move the packet to the end of the tx_pkt_list
	 *         [x] retransmit the pkt
	 */

	uet_list_foreach_container_safe(&pds_state.pdc_alloc_head,
				     struct uet_pdc, pdc, node, tmp1) {
		uet_list_foreach_container_safe(&pdc->tx_pkt_list_head,
					     struct uet_pdc_pkt, pdc_pkt,
					     node, tmp2) {
			rc = uet_pds_check_rtx_pkt(uet, pdc, pdc_pkt);
			if (rc == 0) {
				break; /* no retransmit, done with this PDC */
			} else if (rc == -EIO) {
				/* TODO: Need to destroy this PDC... */
				uet_list_remove(&pdc_pkt->node);
				break; /* done with this PDC */
			} else if (rc == -EAGAIN) {
				/*
				 * This packet was retransmitted, move this
				 * packet to the end of the list and continue.
				 */
				uet_list_remove(&pdc_pkt->node);
				uet_list_insert_tail(&pdc_pkt->node,
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

	rc = uet_pdsm_unmap_msgid_pdc(msg_id);
	if (rc != 0)
		return rc;

	UET_PDS_DBG("PDC %d complete indication for msg_id %u",
		    pdc->pdc_id, msg_id);
	pdc->open_msg_cnt--;

	return 0;
}

static void uet_pds_build_ack_pkt(struct uet_instance *uet,
				  struct uet_pdc *pdc,
				  struct uet_pdc_pkt *pdc_pkt,
				  uet_next_hdr_t next_hdr,
				  void *ses_hdr,
				  size_t ses_hdr_len)
{
	uint8_t flags;
	struct uet_pds_ack *ack_pds;
	uint8_t *ack_ses;

	/* TODO: IPv6 support */
	ack_pds = (struct uet_pds_ack *)(pdc_pkt->ack +
					 sizeof(struct ethhdr) +
					 sizeof(struct iphdr));
	ack_ses = (uint8_t *)(ack_pds + 1);

	uet_build_eth_hdr((struct ethhdr *)pdc_pkt->ack,
			  ((struct ethhdr *)pdc_pkt->pkt_pp.eth)->h_source,
			  ((struct ethhdr *)pdc_pkt->pkt_pp.eth)->h_dest);

	/* TODO: IPv6 support */
	uet_build_ipv4_hdr((struct iphdr *)(pdc_pkt->ack +
					    sizeof(struct ethhdr)),
			   ((struct iphdr *)pdc_pkt->pkt_pp.ip)->saddr,
			   ((struct iphdr *)pdc_pkt->pkt_pp.ip)->daddr,
			   (pdc_pkt->ack_len - uet->nic.l2_hdr_size),
			   uet->pds.ack_ip_tos);

	ack_pds->prlg.entropy = htons(pdc_pkt->pkt_pp.entropy);

	/* TODO: add SACK header, UET_PDS_ACK_FLAGS_AX */
	flags = (pdc_pkt->needs_clear) ? UET_PDS_ACK_FLAGS_REQ_TGT_CLR
				       : UET_PDS_ACK_FLAGS_NONE;
	ack_pds->prlg.type_next_flags =
		htons((UET_PDS_TYPE_ACK << UET_PDS_TYPE_SHIFT) |
		      (next_hdr << UET_PDS_NEXT_HDR_SHIFT) |
		      (flags << UET_PDS_FLAGS_SHIFT));

	ack_pds->psn    = htonl(pdc_pkt->pkt_pp.pds_psn);
	ack_pds->spdcid = htons(pdc->pdc_id);
	ack_pds->dpdcid = htons(pdc->dpdcid);

	memcpy(ack_ses, ses_hdr, ses_hdr_len);
}

static int uet_pds_tx_ack_pkt(struct uet_instance *uet,
			      struct uet_pdc *pdc,
			      struct uet_pdc_pkt *pdc_pkt,
			      uet_next_hdr_t next_hdr,
			      size_t ses_hdr_len,
			      void *ses_hdr,
			      bool gtd_del)
{
	uint16_t ack_pkt_len;
	uint16_t ack_data_len;
	int rc;

	/* TODO: IPv6 support */
	if (next_hdr == UET_HDR_RSP) {
		pdc_pkt->ack_len = (sizeof(struct ethhdr) +
				    sizeof(struct iphdr) +
				    sizeof(struct uet_pds_ack) +
				    sizeof(struct uet_ses_rsp));
	} else { /* response w/ data */
		ack_data_len = (ses_hdr_len - sizeof(struct uet_ses_rsp_d));
		pdc_pkt->ack_len = (sizeof(struct ethhdr) +
				    sizeof(struct iphdr) +
				    sizeof(struct uet_pds_ack) +
				    sizeof(struct uet_ses_rsp_d) +
				    ack_data_len);
	}

	/* allocate buffer for ack packet */
	pdc_pkt->ack_buf_len = ((pdc_pkt->ack_len +
				 ((pdc->sec_enabled)
				  ? (UET_SEC_MAX_HDR_LEN +
				     UET_SEC_TAG_LEN)
				  : 0)) *
				((pdc->sec_enabled) ? 2 : 1));
	pdc_pkt->ack_buf = kcalloc(1, pdc_pkt->ack_buf_len, GFP_KERNEL);
	if (pdc_pkt->ack_buf == NULL) {
		UET_PDS_ERR("failed to alloc ACK packet buffer");
		return -ENOMEM;
	}

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
		kfree(pdc_pkt->ack_buf);
		return rc;
	}

	/* the packet was sent successfully */

	pdc_pkt->ack_parsed = true;

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
	struct uet_pds_ack *ack_pds;
	struct uet_pds_def_rsp *ack_ses;
	int rc;

	def_rsp_len = (sizeof(struct ethhdr) +
		       sizeof(struct iphdr) +
		       sizeof(struct uet_pds_ack) +
		       sizeof(struct uet_pds_def_rsp));

	/* allocate buffer for ack packet */
	def_rsp_buf_len = ((def_rsp_len +
			     ((pdc->sec_enabled)
			      ? (UET_SEC_MAX_HDR_LEN +
				 UET_SEC_TAG_LEN)
			      : 0)) *
			   ((pdc->sec_enabled) ? 2 : 1));
	def_rsp_buf = kcalloc(1, def_rsp_buf_len, GFP_KERNEL);
	if (def_rsp_buf == NULL) {
		UET_PDS_ERR("failed to alloc DEF_RSP ACK packet buffer");
		return -ENOMEM;
	}

	def_rsp = (pdc->sec_enabled)
			? (def_rsp_buf + UET_SEC_MAX_HDR_LEN)
			: def_rsp_buf;

	memset(&tmp_pdc_pkt, 0, sizeof(tmp_pdc_pkt));
	tmp_pdc_pkt.ack_buf     = def_rsp_buf;
	tmp_pdc_pkt.ack_buf_len = def_rsp_buf_len;
	tmp_pdc_pkt.ack         = def_rsp;
	tmp_pdc_pkt.ack_len     = def_rsp_len;
	tmp_pdc_pkt.ack_parsed  = false;

	/* TODO: IPv6 support */
	ack_pds = (struct uet_pds_ack *)(def_rsp +
					 sizeof(struct ethhdr) +
					 sizeof(struct iphdr));
	ack_ses = (struct uet_pds_def_rsp *)(ack_pds + 1);

	uet_build_eth_hdr((struct ethhdr *)def_rsp,
			  ((struct ethhdr *)pdc_pkt->pkt_pp.eth)->h_source,
			  ((struct ethhdr *)pdc_pkt->pkt_pp.eth)->h_dest);

	/* TODO: IPv6 support */
	uet_build_ipv4_hdr((struct iphdr *)(def_rsp +
					    sizeof(struct ethhdr)),
			   ((struct iphdr *)pdc_pkt->pkt_pp.ip)->saddr,
			   ((struct iphdr *)pdc_pkt->pkt_pp.ip)->daddr,
			   (def_rsp_len - uet->nic.l2_hdr_size),
			   uet->pds.ack_ip_tos);

	ack_pds->prlg.entropy = htons(pdc_pkt->pkt_pp.entropy);

	/* TODO: add SACK header, UET_PDS_ACK_FLAGS_AX */
	ack_pds->prlg.type_next_flags =
		htons((UET_PDS_TYPE_ACK << UET_PDS_TYPE_SHIFT) |
		      (UET_HDR_RSP << UET_PDS_NEXT_HDR_SHIFT) |
		      (UET_PDS_ACK_FLAGS_NONE << UET_PDS_FLAGS_SHIFT));

	ack_pds->psn    = htonl(pdc_pkt->pkt_pp.pds_psn);
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
		kfree(def_rsp_buf);
		return rc;
	}

	uet_pds_pkt_dbg(uet, &tmp_pdc_pkt.ack_pp, true,
			"TX DEF_RSP ACK PACKET (duplicate)");

	kfree(def_rsp_buf);
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
	uet_next_hdr_t rsp_next_hdr;
	void *rsp_ses_hdr;
	size_t rsp_ses_hdr_len;
	bool ses_nack, gtd_del;
	int rc;

	/* upcall for ses processing */
	memset(&pds_info, 0, sizeof(struct uet_pds_info));
	pds_info.opsn  = pdc_pkt->pkt_pp.pds_psn;
	pds_info.pdcid = pdc->pdc_id;

	/* allocate a buffer for the SES reponse data */
	rsp_ses_hdr = kcalloc(1, (sizeof(struct uet_ses_rsp_d) +
				 uet->pds.max_ack_data), GFP_KERNEL);
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

	kfree(rsp_ses_hdr);
	return rc;
}

static int uet_pds_shift_rx_window(struct uet_instance *uet,
				   struct uet_pdc *pdc,
				   bool is_rod)
{
	struct uet_pdc_pkt *pdc_pkt;
	bool shifted = false;
	int rc;

	while (true) {
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
			kfree(pdc_pkt->ack_buf);
		if (pdc_pkt->pkt_buf)
			kfree(pdc_pkt->pkt_buf);
		kfree(pdc_pkt);
	}

#if 0
	if (shifted && (UET_LOG_LVL >= UET_LOG_DBG)) {
		UET_PDS_DBG("PDC %d rx_bm (base %u):",
			    pdc->pdc_id, pdc->rx_bm_base_psn);
		bm_print_bits(pdc->rx_bm);
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

		if (!bm_get(pdc->ack_bm, 0, NULL))
			break;

		 /*
		  * This transmitted packet has been ACK'ed. Note that when
		  * the ACK was processed, the packet was removed from the
		  * PDC's tx list that is managed for retransmissions.
		  */

		shifted = true;
		bm_shift_right(pdc->tx_bm, 1);
		bm_shift_right(pdc->ack_bm, 1);
		pdc->tx_bm_base_psn++;

		if (pdc_pkt->ack_buf)
			kfree(pdc_pkt->ack_buf);
		if (pdc_pkt->pkt_buf)
			kfree(pdc_pkt->pkt_buf);
		kfree(pdc_pkt);
	}

#if 0
	if (shifted && (UET_LOG_LVL >= UET_LOG_DBG)) {
		UET_PDS_DBG("PDC %d tx_bm (base %u):",
			    pdc->pdc_id, pdc->tx_bm_base_psn);
		bm_print_bits(pdc->tx_bm);
		UET_PDS_DBG("PDC %d ack_bm (base %u):",
			    pdc->pdc_id, pdc->tx_bm_base_psn);
		bm_print_bits(pdc->ack_bm);
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

	UET_PDS_DBG("PDC %u tx_bm: base=%u psn=%u SET bit=%u",
		    pdc->pdc_id, pdc->tx_bm_base_psn, pdc_pkt->psn,
		    (pdc_pkt->psn - pdc->tx_bm_base_psn));

	bm_set(pdc->ack_bm, (pdc_pkt->psn - pdc->tx_bm_base_psn), NULL);

	if (UET_LOG_LVL >= UET_LOG_DBG) {
		UET_PDS_DBG("PDC %d tx_bm (base %u):",
			    pdc->pdc_id, pdc->tx_bm_base_psn);
		//bm_print_bits(pdc->tx_bm);
		UET_PDS_DBG("PDC %d ack_bm (base %u):",
			    pdc->pdc_id, pdc->tx_bm_base_psn);
		//bm_print_bits(pdc->ack_bm);
	}

	pdc_pkt->tx_pkt_acked = true;
	uet_list_remove(&pdc_pkt->node); /* remove from Tx list */

	/* upcall for SES processing */
	rc = uet->pds.upcall.rx_rsp(pdc_pkt->tx_pkt_handle, pp);
	if (rc != 0) {
		UET_PDS_ERR("PDC %u ACK PSN %u SES upcall failed (rx_rsp=%d)",
			    pp->pds_dpdcid, pp->pds_psn, rc);
		return rc;
	}

	if (pdc->state == PDC_STATE_SYN) {
		pdc->state  = PDC_STATE_ESTABLISHED;
		pdc->dpdcid = pp->pds_spdcid;
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
		//bm_print_bits(pdc->rx_bm);
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

	pdc_pkt = kcalloc(1, sizeof(struct uet_pdc_pkt), GFP_KERNEL);
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
		//bm_print_bits(pdc->rx_bm);
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
	kfree(pdc_pkt);
	return rc;
}

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

static bool uet_pds_rx_pkt_chk(struct uet_nic *nic,
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

int uet_pds_progress_rx(struct uet_instance *uet)
{
	uint8_t *pkt;
	int pkt_len;
	struct uet_parsed_pkt pp;
	bool pkt_is_ack, pkt_is_rd_rsp;
	struct uet_pdc_pkt *pdc_pkt = NULL;
	struct uet_pdc *pdc;
	struct uet_pds_info pds_info;
	uet_next_hdr_t rsp_next_hdr;
	void *rsp_ses_hdr = NULL;
	size_t rsp_ses_hdr_len;
	bool ses_nack, gtd_del, rtx;
	int rc = 0;

	rc = uet_pds_sec_rx_pkt(uet, &pkt, &pkt_len);
	if (rc != 1)
		return rc;

	/* validate the packet */
	if (!uet_pds_rx_pkt_chk(&uet->nic, pkt, pkt_len,
				&pkt_is_ack,
				&pkt_is_rd_rsp)) {
		UET_PDS_WARN("invalid Rx packet");
		rc = -EINVAL;
		goto exit_err;
	}

	/* parse the packet */
	rc = uet_parse_pkt(pkt, pkt_len, &pp, 
			   uet->uet_udp_port, uet->max_payload_len);
	if (rc != 0) {
		UET_PDS_ERR("malformed Rx packet");
		goto exit_err;
	}

	uet_pds_pkt_dbg(uet, &pp, false, "RX PACKET");

	if (pkt_is_ack) {

		rc = uet_pds_process_ack(uet, &pp);
		if (rc != 0)
			goto exit_err;

	} else { /* request packet */

		rc = uet_pds_process_request(uet, &pp, pkt, pkt_len);
		if (rc != 0)
			goto exit_err;

	}

	return 0;

exit_err:
	kfree(pkt);
	return rc;
}

void uet_pds_ep_close_wait(struct uet_ep *uet_ep)
{
	struct uet_instance *uet;
	uint64_t start_time, now;

	uet_ep->ep_state = UET_EP_CLOSE_WAIT;

	uet = uet_ep->uet_domain->uet;

	/*
	 * Continue receiving packets for max segment lifetime after the
	 * EP is closed. This gives time to retransmit any lost ACKs but
	 * no other packet Rx processing is performed.
	 */

	if (uet_gettime(&start_time)) {
		UET_PDS_ERR("Aborting endpoint close wait state");
		return;
	}

	while (1) {
		if (uet_gettime(&now)) {
			UET_PDS_ERR("Aborting endpoint close wait state");
			break;
		}

		if ((now - start_time) > uet->pds.msl)
			break;

		uet->pds.downcall.progress_rx(uet);
	}
}

static int uet_pds_module_init(void)
{
	uet_pds_initialize_fn 			= uet_pds_initialize;
	uet_pds_finalize_fn 			= uet_pds_finalize;
	uet_pds_ep_initialize_fn 		= uet_pds_ep_initialize;
	uet_pds_ep_finalize_fn 			= uet_pds_ep_finalize;
	uet_pds_tx_pkt_fn 				= uet_pds_tx_pkt;
	uet_pds_progress_tx_fn 			= uet_pds_progress_tx;
	uet_pds_msg_cmpl_ind_fn 		= uet_pds_msg_cmpl_ind;
	uet_pds_progress_rx_fn 			= uet_pds_progress_rx;
	uet_pds_ep_close_wait_fn 		= uet_pds_ep_close_wait;

	uet_sec_init();

	return 0;
}

static void uet_pds_module_exit(void)
{
	uet_pds_initialize_fn 			= NULL;
	uet_pds_finalize_fn 			= NULL;
	uet_pds_ep_initialize_fn 		= NULL;
	uet_pds_ep_finalize_fn 			= NULL;
	uet_pds_tx_pkt_fn 				= NULL;
	uet_pds_progress_tx_fn 			= NULL;
	uet_pds_msg_cmpl_ind_fn 		= NULL;
	uet_pds_progress_rx_fn 			= NULL;
	uet_pds_ep_close_wait_fn 		= NULL;
}

module_init(uet_pds_module_init);
module_exit(uet_pds_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rakhahari Bhunia <rakhahari.bhunia@keysight.com>");
MODULE_DESCRIPTION("SoftUET Driver PDS Module");
MODULE_VERSION("0.1");
