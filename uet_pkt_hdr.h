/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* Definitions for UET Packet Headers */

#ifndef _UET_PKT_HDR_H_
#define _UET_PKT_HDR_H_

#include <netinet/if_ether.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <arpa/inet.h>

#define UET_MAX_VLAN_TAGS	2

#define UET_IP_VER_MASK		0xf0
#define UET_IP_VER_SHIFT	4
#define UET_IPV4_VER		4
#define UET_IPV6_VER		6
#define UET_IPV4_IHL_NO_OPTIONS	5
#define UET_IPV4_FRAG_OFF_DF	0x4000 /* don't fragment */
#define UET_DSCP_CS0		0
#define UET_DSCP_EF		46
#define UET_IP_DEFAULT_MSG_DSCP	UET_DSCP_CS0
#define UET_IP_DEFAULT_ACK_DSCP	UET_DSCP_EF
#define UET_IPPROTO		253    /* for UET over IP encap */

#define UET_IPPROTO_EXT_HDR_HOP_BY_HOP	0
#define UET_IPPROTO_EXT_HDR_ROUTING	43
#define UET_IPPROTO_EXT_HDR_FRAG	44
#define UET_IPPROTO_EXT_HDR_ESP		50
#define UET_IPPROTO_EXT_HDR_AUTH	51
#define UET_IPPROTO_EXT_HDR_NONE	55
#define UET_IPPROTO_EXT_HDR_DEST_OPTS	60
#define UET_IPPROTO_EXT_HDR_MOBILITY	135

#define UET_UDP_PORT	49150 /* for UET over UDP encap */

#define UET_DEFAULT_MAX_PAYLOAD_LEN	1024
#define UET_MAX_PAYLOAD_LEN		8192 /* upper bound */

#define UET_PACKED __attribute__((__packed__))

/* uet pds packet types (prologue) */
typedef enum {
	UET_PDS_TYPE_RESERVED   = 0x00,
	UET_PDS_TYPE_SECURITY   = 0x01,
	UET_PDS_TYPE_RUD_REQ    = 0x02,
	UET_PDS_TYPE_ROD_REQ    = 0x03,
	UET_PDS_TYPE_RUDI_REQ   = 0x04,
	UET_PDS_TYPE_RUDI_RESP  = 0x05,
	UET_PDS_TYPE_UUD_REQ    = 0x06,
	UET_PDS_TYPE_ACK        = 0x07,
	UET_PDS_TYPE_ACK_CC     = 0x08,
	UET_PDS_TYPE_ACK_CCX    = 0x09,
	UET_PDS_TYPE_NACK       = 0x0a,
	UET_PDS_TYPE_CTRL       = 0x0b,
	UET_PDS_TYPE_NACK_CCX   = 0x0c,
	UET_PDS_TYPE_RUD_CC_REQ = 0x0d,
	UET_PDS_TYPE_ROD_CC_REQ = 0x0e,
} uet_pds_pkt_type_t;

/* vlan tag */
struct uet_vlan_tag {
	uint16_t ethertype;
	uint16_t tag;
};

/****************************************************************************/
/*                               ENTROPY                                    */
/****************************************************************************/

/* uet entropy header - used when running directly over IPv4/IPv6 */
struct UET_PACKED uet_entropy {
	uint16_t entropy;
	uint16_t rsvd;
};

/****************************************************************************/
/*                              SECURITY                                    */
/****************************************************************************/

/* uet security header (w/o the ssi) */
struct UET_PACKED uet_sec {
#define UET_SEC_TYPE_MASK  0xf8000000 /* set to UET_PDS_TYPE_SECURITY */
#define UET_SEC_TYPE_SHIFT 27
#define UET_SEC_SP_MASK    0x04000000
#define UET_SEC_SP_SHIFT   26
#define UET_SEC_SP         1 /* ssi field exists */
#define UET_SEC_AN_MASK    0x01000000
#define UET_SEC_AN_SHIFT   24
#define UET_SEC_SDI_MASK   0x00ffffff
#define UET_SEC_SDI_SHIFT  0
	uint32_t type_flags_sdi;
#define UET_SEC_EPOCH_MASK  0xffff000000000000ULL
#define UET_SEC_EPOCH_SHIFT 48
#define UET_SEC_TSC_MASK    0x0000ffffffffffffULL
#define UET_SEC_TSC_SHIFT   0
	uint64_t epoch_tsc;
};

/* uet security header (w/ the ssi), same defines from uet_sec */
struct UET_PACKED uet_sec_ssi {
	uint32_t type_flags_sdi;
	uint32_t ssi; /* if UET_SEC_SP */
	uint64_t epoch_tsc;
};

/****************************************************************************/
/*                             RELIABLITY (PDS)                             */
/****************************************************************************/

/* uet next header types */
typedef enum {
	UET_HDR_NONE           = 0x0, /* no header follows */
	UET_HDR_REQ_SMALL      = 0x1, /* small SES request header */
	UET_HDR_REQ_MEDIUM     = 0x2, /* medium SES request header */
	UET_HDR_REQ_STD        = 0x3, /* standard SES request header */
	UET_HDR_RSP            = 0x4, /* SES response header */
	UET_HDR_RSP_DATA       = 0x5, /* SES response header with data */
	UET_HDR_RSP_DATA_SMALL = 0x6, /* SES tiny response header with data */
} uet_pds_next_hdr_t;

/* uet pds prologue header */
struct UET_PACKED uet_pds_prlg {
#define UET_PDS_TYPE_MASK       0xf800
#define UET_PDS_TYPE_SHIFT      11
#define UET_PDS_NEXT_HDR_MASK   0x0780 /* uet_pds_next_hdr_t */
#define UET_PDS_NEXT_HDR_SHIFT  7
#define UET_PDS_CTRL_TYPE_MASK  UET_PDS_NEXT_HDR_MASK /* uet_pds_ctrl_type_t */
#define UET_PDS_CTRL_TYPE_SHIFT UET_PDS_NEXT_HDR_SHIFT
#define UET_PDS_FLAGS_MASK      0x007f
#define UET_PDS_FLAGS_SHIFT     0
	union {
		/* flags are defined per-type */
		uint16_t type_next_flags; /* requests/responses */
		uint16_t type_ctrl_flags; /* control messages */
	};
};

/* uet pds rod/rud request header */
struct UET_PACKED uet_pds_req {
	/* uet pds request flags in prologue */
#define UET_PDS_REQ_FLAGS_RSV  0x60 /* Reserved */
#define UET_PDS_REQ_FLAGS_RETX 0x10 /* request is a retransmit */
#define UET_PDS_REQ_FLAGS_AR   0x08 /* ACK requested */
#define UET_PDS_REQ_FLAGS_SYN  0x04 /* connection setup request */
#define UET_PDS_REQ_FLAGS_RSV2 0x03 /* Reserved */
#define UET_PDS_REQ_FLAGS_NONE 0x00
	struct uet_pds_prlg prlg;
	int16_t             clear_psn_offset;
	uint32_t            psn;
	uint16_t            spdcid;
	union {
		uint16_t dpdcid; /* valid when UET_PDS_REQ_FLAGS_SYN=0 */
#define UET_PDS_REQ_PDC_INFO_MASK        0xf000
#define UET_PDS_REQ_PDC_INFO_SHIFT       12
#define UET_PDS_REQ_PDC_INFO_RSV         0x0e /* Reserved */
#define UET_PDS_REQ_PDC_INFO_USE_RSV_PDC 0x01 /* reserved PDC (e.g., INC) */
#define UET_PDS_REQ_PSN_OFFSET_MASK      0x0fff
#define UET_PDS_REQ_PSN_OFFSET_SHIFT     0
		uint16_t pdc_info_psn_offset;
	};
};

/*
 * uet cc data following uet_pds_req:
 *   type = UET_PDS_TYPE_RUD_CC_REQ or UET_PDS_TYPE_ROD_CC_REQ
 */
struct UET_PACKED uet_pds_req_cc_state {
	uint32_t req_cc_state;
};

/* uet pds rod/rud ack header */
struct UET_PACKED uet_pds_ack {
	/* uet pds ack flags in prologue */
#define UET_PDS_ACK_FLAGS_EPSN        0x40 /* 0-RTT closing ACK expected PSN */
#define UET_PDS_ACK_FLAGS_M           0x20 /* original pkt was ECN marked */
#define UET_PDS_ACK_FLAGS_RETX        0x10 /* ACK to a retransmit */
#define UET_PDS_ACK_FLAGS_P           0x08 /* ACK to a probe (PSN ignored) */
#define UET_PDS_ACK_FLAGS_REQ_CLS     0x04 /* target requests close */
#define UET_PDS_ACK_FLAGS_REQ_CLR     0x02 /* target requests clear */
#define UET_PDS_ACK_FLAGS_RSV         0x01 /* Reserved */
#define UET_PDS_ACK_FLAGS_NONE        0x00
	struct uet_pds_prlg prlg;
	union {
		int16_t  ack_psn_offset;
		uint16_t probe_opaque; /* valid when UET_PDS_ACK_FLAGS_P=1 */
	};
	uint32_t            cack_psn;
	uint16_t            spdcid;
	uint16_t            dpdcid;
};

struct UET_PACKED uet_pds_ack_epsn {
	struct uet_pds_ack ack;
	uint32_t           payload;
};

/* uet pds rod/rud ack w/ cc extension header */
struct UET_PACKED uet_pds_ack_cc {
	struct uet_pds_ack ack;
#define UET_PDS_ACK_CC_TYPE_MASK   0xf0
#define UET_PDS_ACK_CC_TYPE_SHIFT  4
#define UET_PDS_ACK_CC_FLAGS_MASK  0x0f
#define UET_PDS_ACK_CC_FLAGS_SHIFT 0
#define UET_PDS_ACK_CC_FLAGS_NONE  0x00
	uint8_t            cc_type_flags;
	uint8_t            mpr;
	int16_t            sack_psn_offset;
	uint64_t           sack_bitmap;
	uint64_t           ack_cc_state;
};

/* uet pds rod/rud ack w/ ccx extension header */
struct UET_PACKED uet_pds_ack_ccx {
	struct uet_pds_ack_cc ack_cc;
	uint64_t              ack_ccx_state;
};

/* uet pds nack codes */
typedef enum {
	UET_NACK_NONE              = 0x00,
	UET_NACK_TRIMMED           = 0x01,
	UET_NACK_TRIMMED_LAST_HOP  = 0x02,
	UET_NACK_TRIMMED_ACK       = 0x03,
	UET_NACK_NO_PDC_AVAIL      = 0x04,
	UET_NACK_NO_CCC_AVAIL      = 0x05,
	UET_NACK_NO_BITMAP         = 0x06,
	UET_NACK_NO_PKT_BUF        = 0x07,
	UET_NACK_NO_GTD_DEL_AVAIL  = 0x08,
	UET_NACK_NO_SES_MSG_AVAIL  = 0x09,
	UET_NACK_NO_RESOURCE       = 0x0a,
	UET_NACK_PSN_OOR_WINDOW    = 0x0b,
	/* 0x0c Reserved */
	UET_NACK_ROD_OOO           = 0x0d,
	UET_NACK_INV_DPDCID        = 0x0e,
	UET_NACK_PDC_HDR_MISMATCH  = 0x0f,
	UET_NACK_CLOSING           = 0x10,
	UET_NACK_CLOSING_IN_ERR    = 0x11,
	UET_NACK_PKT_NOT_RCVD      = 0x12,
	UET_NACK_GTD_RESP_UNAVAIL  = 0x13,
	UET_NACK_ACK_WITH_DATA     = 0x14,
	UET_NACK_INVALID_SYN       = 0x15,
	UET_NACK_PDC_MODE_MISMATCH = 0x16,
	UET_NACK_NEW_START_PSN     = 0x17,
	UET_NACK_RCVD_SES_PROCG    = 0x18,
	UET_NACK_UNEXP_EVENT       = 0x19,
	UET_NACK_RCVR_INFER_LESS   = 0x1a,
	/* 0x1b-0xfc Reserved */
	UET_NACK_EXP_NACK_NORMAL   = 0xfd, /* experimental */
	UET_NACK_EXP_NACK_ERR      = 0xfe, /* experimental */
	UET_NACK_EXP_NACK_FATAL    = 0xff, /* experimental */
} uet_pds_nack_code_t;

/* uet pds rod/rud/rudi nack header */
struct UET_PACKED uet_pds_nack {
	/* uet pds nack flags in prologue */
#define UET_PDS_NACK_FLAGS_RSV  0x40 /* Reserved */
#define UET_PDS_NACK_FLAGS_M    0x20 /* original pkt was ECN marked */
#define UET_PDS_NACK_FLAGS_RETX 0x10 /* NACK to a retransmit */
#define UET_PDS_NACK_FLAGS_NT   0x08 /* ROD/RUD=0, RUDI=1 */
#define UET_PDS_NACK_FLAGS_RSV2 0x07 /* Reserved */
#define UET_PDS_NACK_FLAGS_NONE 0x00
	struct uet_pds_prlg prlg;
	uint8_t             nack_code;
	uint8_t             vendor_code;
	union {
		uint32_t nack_psn;
		uint32_t nack_pkt_id; /* valid when UET_PDS_NACK_FLAGS_NT=1 */
	};
	uint16_t            spdcid; /* 0 when UET_PDS_NACK_FLAGS_NT=1 */
	uint16_t            dpdcid; /* 0 when UET_PDS_NACK_FLAGS_NT=1 */
	uint32_t            payload; /* specific to nack_code */
};

/* uet pds rod/rud/rudi nack w/ ccx extension header */
struct UET_PACKED uet_pds_nack_ccx {
	struct uet_pds_nack nack;
#define UET_PDS_NACK_CCX_NCCX_TYPE_MASK        0xf000000000000000ULL
#define UET_PDS_NACK_CCX_NCCX_TYPE_SHIFT       60
#define UET_PDS_NACK_CCX_NACK_CCX_STATE1_MASK  0x0fffffffffffffffULL
#define UET_PDS_NACK_CCX_NACK_CCX_STATE1_SHIFT 0
	uint64_t            nccx_type_nack_ccx_state1;
	uint64_t            nack_ccx_state2;
};

/* uet pds ctrl types */
typedef enum {
	UET_PDS_CTRL_TYPE_NOP         = 0x0, /* no-op */
	UET_PDS_CTRL_TYPE_ACK_REQ     = 0x1, /* request for ACK (at PSN) */
	UET_PDS_CTRL_TYPE_CLEAR       = 0x2, /* clear PDS ACK state */
	UET_PDS_CTRL_TYPE_CLEAR_REQ   = 0x3, /* request for clear */
	UET_PDS_CTRL_TYPE_CLOSE       = 0x4, /* initiator closing the PDC */
	UET_PDS_CTRL_TYPE_CLOSE_REQ   = 0x5, /* target request for close */
	UET_PDS_CTRL_TYPE_PROBE       = 0x6, /* probe to request for ACK */
	UET_PDS_CTRL_TYPE_CREDIT      = 0x7, /* CC credit */
	UET_PDS_CTRL_TYPE_CREDIT_REQ  = 0x8, /* request for CC credit */
	UET_PDS_CTRL_TYPE_NEGOTIATION = 0x9, /* negotiation */
} uet_pds_ctrl_type_t;

/* uet pds rod/rud ctrl header */
struct UET_PACKED uet_pds_ctrl {
	/* uet pds ctrl flags in prologue */
#define UET_PDS_CTRL_FLAGS_RSV   0x40 /* Reserved */
#define UET_PDS_CTRL_FLAGS_ISROD 0x20 /* RUD=0, ROD=1 */
#define UET_PDS_CTRL_FLAGS_RETX  0x10 /* control is a retransmit */
#define UET_PDS_CTRL_FLAGS_AR    0x08 /* ACK requested */
#define UET_PDS_CTRL_FLAGS_SYN   0x04 /* connection setup request */
#define UET_PDS_CTRL_FLAGS_RSV2  0x03 /* Reserved */
#define UET_PDS_CTRL_FLAGS_NONE  0x00
	struct uet_pds_prlg prlg;
	union {
		uint16_t rsvd;
		uint16_t probe_opaque; /* valid for UET_PDS_CTRL_TYPE_PROBE */
	};
	uint32_t            psn;
	uint16_t            spdcid;
	union {
		uint16_t dpdcid; /* valid when UET_PDS_CTRL_FLAGS_SYN=0 */
#define UET_PDS_CTRL_PDC_INFO_MASK        0xf000
#define UET_PDS_CTRL_PDC_INFO_SHIFT       12
#define UET_PDS_CTRL_PDC_INFO_RSV         0x0e /* Reserved */
#define UET_PDS_CTRL_PDC_INFO_USE_RSV_PDC 0x01 /* reserved PDC (e.g., INC) */
#define UET_PDS_CTRL_PSN_OFFSET_MASK      0x0fff
#define UET_PDS_CTRL_PSN_OFFSET_SHIFT     0
		uint16_t pdc_info_psn_offset;
	};
	/*
	 * The payload field is based on the CTRL_TYPE:
	 * - ack request
	 *     -> message ID or zero
	 * - clear
	 *     -> clear sequence number
	 * - clear request
	 *     -> PSN to clear
	 * - probe
	 *     -> SACK bitmap base PSN
	 * - credit
	 *     -> credit
	 * - credit request
	 *     -> target credit
	 * - all others
	 *     -> zero
	 */
	uint32_t            payload;
};

/* uet pds rudi request header */
struct UET_PACKED uet_pds_rudi_req {
	/* uet pds rudi request flags in prologue */
#define UET_PDS_RUDI_FLAGS_RSV  0x40 /* Reserved */
#define UET_PDS_RUDI_FLAGS_M    0x20 /* original request pkt was ECN marked */
#define UET_PDS_RUDI_FLAGS_RETX 0x10 /* request is a retransmit */
#define UET_PDS_RUDI_FLAGS_RSV2 0x0f /* Reserved */
#define UET_PDS_RUDI_FLAGS_NONE 0x00
	struct uet_pds_prlg prlg;
	uint16_t            rsvd;
	uint32_t            pkt_id;
};

/* uet pds rudi response header */
#define uet_pds_rudi_rsp uet_pds_rudi_req

/* uet pds uud request header */
struct UET_PACKED uet_pds_uud_req {
	/* uet pds uud request flags in prologue */
#define UET_PDS_UUD_FLAGS_NONE 0x00
	struct uet_pds_prlg prlg;
	uint16_t            rsvd;
};

/* uet pds ses default/no response header */
struct UET_PACKED uet_pds_def_rsp {
#define UET_PDS_SES_DEF_RSP_LIST_MASK    0xc0
#define UET_PDS_SES_DEF_RSP_LIST_SHIFT   6
#define UET_PDS_SES_DEF_RSP_LIST         0
#define UET_PDS_SES_DEF_RSP_OPCODE_MASK  0x3f /* UET_[DEFAULT|NO]_RESPONSE */
#define UET_PDS_SES_DEF_RSP_OPCODE_SHIFT 0
	uint8_t  list_opcode;
#define UET_PDS_SES_DEF_RSP_VER_MASK      0xc0
#define UET_PDS_SES_DEF_RSP_VER_SHIFT     6
#define UET_PDS_SES_DEF_RSP_VER           0
#define UET_PDS_SES_DEF_RSP_RETCODE_MASK  0x3f /* RC_[NULL|OKAY] */
#define UET_PDS_SES_DEF_RSP_RETCODE_SHIFT 0
	uint8_t  ver_return_code;
	uint16_t msg_id;
#define UET_PDS_SES_DEF_RI_GEN_MASK  0xff000000
#define UET_PDS_SES_DEF_RI_GEN_SHIFT 24
#define UET_PDS_SES_DEF_RI_GEN       0
#define UET_PDS_SES_DEF_JOB_ID_MASK  0x00ffffff
#define UET_PDS_SES_DEF_JOB_ID_SHIFT 0
	uint32_t ri_gen_job_id;
	uint32_t mod_len;
};

/****************************************************************************/
/*                              SEMANTIC (SES)                              */
/****************************************************************************/

/* uet ses request opcodes */
typedef enum {
	UET_NO_OP              = 0x00,
	UET_WRITE              = 0x01,
	UET_READ               = 0x02,
	UET_ATOMIC             = 0x03,
	UET_FETCH_ATOMIC       = 0x04,
	UET_SEND               = 0x05,
	UET_RNDV_SEND          = 0x06,
	UET_DGRAM_SEND         = 0x07,
	UET_DEFER_SEND         = 0x08,
	UET_TAGGED_SEND        = 0x09,
	UET_RNDV_TSEND         = 0x0a,
	UET_DEFER_TSEND        = 0x0b,
	UET_DEFER_RTR          = 0x0c,
	UET_TSEND_ATOMIC       = 0x0d,
	UET_TSEND_FETCH_ATOMIC = 0x0e,
	UET_MSG_ERR            = 0x0f,
	UET_SYNC_WRITE	       = 0x10,
	UET_SYNC_ATOMIC        = 0x11
} uet_ses_req_opcode_t;

#define UET_SES_OPCODE_MASK	0x3f
#define UET_SES_OPCODE_SHIFT	0

#define UET_SES_VER_MASK  0xc0
#define UET_SES_VER_SHIFT 6
#define UET_SES_VER       0

/* uet ses request common header fields */
struct UET_PACKED uet_ses_req_cmn {
	/* see UET_SES_OPCODE_MASK|SHIFT */
	uint8_t  rsvd_opcode;
	/* see UET_SES_VER_MASK|SHIFT */
#define UET_SES_REQ_FLAG_DC  0x20 /* delivery complete */
#define UET_SES_REQ_FLAG_IE  0x10 /* initiator error */
#define UET_SES_REQ_FLAG_REL 0x08 /* relative addressing */
#define UET_SES_REQ_FLAG_HD  0x04 /* header data is present */
#define UET_SES_REQ_FLAG_EOM 0x02 /* end of message */
#define UET_SES_REQ_FLAG_SOM 0x01 /* start of message */
	uint8_t  ver_flags;
	union {
		uint16_t msg_id; /* UET_HDR_REQ_STD */
#define UET_SES_REQ_LEN_MASK  0x3fff
#define UET_SES_REQ_LEN_SHIFT 0
		uint16_t rsvd_req_len; /* UET_HDR_REQ_[SMALL|MEDIUM] */
	};
#define UET_SES_REQ_RI_GEN_MASK  0xff000000
#define UET_SES_REQ_RI_GEN_SHIFT 24
#define UET_SES_REQ_JOB_ID_MASK  0x00ffffff
#define UET_SES_REQ_JOB_ID_SHIFT 0
	uint32_t ri_gen_job_id;
#define UET_SES_REQ_PID_ON_FEP_MASK  0x0fff
#define UET_SES_REQ_PID_ON_FEP_SHIFT 0
	uint16_t rsvd_pid_on_fep;
#define UET_SES_REQ_RES_INDEX_MASK  0x0fff
#define UET_SES_REQ_RES_INDEX_SHIFT 0
	uint16_t rsvd_res_index;
};

/* uet ses standard request header (UET_HDR_REQ_STD) */
struct UET_PACKED uet_ses_req_std {
	struct uet_ses_req_cmn cmn;
	union {
		uint64_t buf_off;
#define UET_SES_REQ_STD_SRC_TOKEN_MASK	0xffffffff00000000ULL
#define UET_SES_REQ_STD_SRC_TOKEN_SHIFT	32
#define UET_SES_REQ_STD_DST_TOKEN_MASK	0x00000000ffffffffULL
#define UET_SES_REQ_STD_DST_TOKEN_SHIFT	0
		uint64_t restart_token; /* valid for UET_DEFER_SEND */
	};
	uint32_t initiator;
	union {
		uint64_t mem_key;
		uint64_t match_bits;
#define UET_SES_REQ_STD_INI_TOKEN_MASK  0xffffffff00000000ULL
#define UET_SES_REQ_STD_INI_TOKEN_SHIFT 32
#define UET_SES_REQ_STD_TGT_TOKEN_MASK  0x00000000ffffffffULL
#define UET_SES_REQ_STD_TGT_TOKEN_SHIFT 0
		uint64_t restart_token_rtr; /* valid for UET_DEFER_RTR */
	};
	union { /* header data valid if UET_SES_REQ_FLAG_HD */
		uint64_t cmpl_data; /* if UET_SES_REQ_FLAG_SOM */
#define UET_SES_REQ_STD_PAYLOAD_LEN_MASK  0x00003fff00000000ULL
#define UET_SES_REQ_STD_PAYLOAD_LEN_SHIFT 32
#define UET_SES_REQ_STD_MSG_OFF_MASK      0x00000000ffffffffULL
#define UET_SES_REQ_STD_MSG_OFF_SHIFT     0
		uint64_t payload_len_msg_off;
	};
	uint32_t req_len;
};

/* uet ses optimized non-matching request header (UET_HDR_REQ_SMALL) */
struct UET_PACKED uet_ses_req_onm {
	struct uet_ses_req_cmn cmn;
	uint64_t buf_off;
};

/* uet ses small message request header (UET_HDR_REQ_MEDIUM) */
struct UET_PACKED uet_ses_req_smsg {
	struct uet_ses_req_cmn cmn;
	union { /* header data valid if UET_SES_REQ_FLAG_HD */
		uint64_t hdr_data;
		uint64_t buf_off;
	};
	uint32_t initiator;
	union {
		uint64_t mem_key;
		uint64_t match_bits;
	};
};

/* uet ses rendezvous extension header */
struct UET_PACKED uet_ses_rndv_ext {
	uint32_t eager_len;
#define UET_SES_RNDV_RD_RI_GEN_MASK         0xff000000
#define UET_SES_RNDV_RD_RI_GEN_SHIFT        24
#define UET_SES_RNDV_RD_PID_ON_FEP_MASK  0x00fff000
#define UET_SES_RNDV_RD_PID_ON_FEP_SHIFT 12
#define UET_SES_RNDV_RD_RES_INDEX_MASK   0x00000fff
#define UET_SES_RNDV_RD_RES_INDEX_SHIFT  0
	uint32_t rd_ri_gen_pid_on_fep_res_index;
	uint64_t rd_offset;
	uint64_t rd_mem_key;
};

typedef enum {
	UET_AMO_MIN      = 0x00,
	UET_AMO_MAX      = 0x01,
	UET_AMO_SUM      = 0x02,
	UET_AMO_DIFF     = 0x03,
	UET_AMO_PROD     = 0x04,
	UET_AMO_LOR      = 0x05,
	UET_AMO_LAND     = 0x06,
	UET_AMO_BOR      = 0x07,
	UET_AMO_BAND     = 0x08,
	UET_AMO_LXOR     = 0x09,
	UET_AMO_BXOR     = 0x0a,
	UET_AMO_READ     = 0x0b,
	UET_AMO_WRITE    = 0x0c,
	UET_AMO_CSWAP    = 0x0d,
	UET_AMO_CSWAP_NE = 0x0e,
	UET_AMO_CSWAP_LE = 0x0f,
	UET_AMO_CSWAP_LT = 0x10,
	UET_AMO_CSWAP_GE = 0x11,
	UET_AMO_CSWAP_GT = 0x12,
	UET_AMO_MSWAP    = 0x13,
	UET_AMO_INVAL    = 0x14,
} uet_ses_atomic_opcode_t;

typedef enum {
	UET_TYPE_INT8                = 0x00,
	UET_TYPE_UINT8               = 0x01,
	UET_TYPE_INT16               = 0x02,
	UET_TYPE_UINT16              = 0x03,
	UET_TYPE_INT32               = 0x04,
	UET_TYPE_UINT32              = 0x05,
	UET_TYPE_INT64               = 0x06,
	UET_TYPE_UINT64              = 0x07,
	UET_TYPE_INT128              = 0x08,
	UET_TYPE_UINT128             = 0x09,
	UET_TYPE_FLOAT               = 0x0a,
	UET_TYPE_DOUBLE              = 0x0b,
	UET_TYPE_FLOAT_COMPLEX       = 0x0c,
	UET_TYPE_DOUBLE_COMPLEX      = 0x0d,
	UET_TYPE_LONG_DOUBLE         = 0x0e,
	UET_TYPE_LONG_DOUBLE_COMPLEX = 0x0f,
	UET_TYPE_BF16                = 0x10,
	UET_TYPE_FP16                = 0x11,
} uet_ses_atomic_dt_t;

#define UET_VERBS_ATOMIC_DATA_BYTES	8
#define UET_CSWAP_DATA_BYTES		32

/* uet ses atomic extension header */
struct UET_PACKED uet_ses_atomic_ext {
	uint8_t atomic_opcode;
	uint8_t atomic_dt;
#define UET_AMO_CTRL_CACHEABLE 0x01
#define UET_AMO_CPU_COHERENT   0x02
	uint8_t sem_ctrl;
	uint8_t rsvd;
};

/* uet ses sync group extension header */
struct UET_PACKED uet_ses_sync_ext {
	uint16_t group;
	uint16_t cnt;
};

/* uet ses standard request header with atomic extension header */
struct UET_PACKED uet_ses_req_std_atomic {
	struct uet_ses_req_std base;
	struct uet_ses_atomic_ext ext;
	uint8_t data[];
};

/* uet ses standard request header with atomic and sync extension headers */
struct UET_PACKED uet_ses_req_std_atomic_sync {
	struct uet_ses_req_std base;
	struct uet_ses_sync_ext sync_ext;
	struct uet_ses_atomic_ext atomic_ext;
	uint8_t data[];
};

/* uet ses atomic compare/swap extension header */
struct UET_PACKED uet_ses_atomic_cmpswp_ext {
	struct uet_ses_atomic_ext cmn;
	uint64_t cmp_val_hi;
	uint64_t cmp_val_lo;
	uint64_t swp_val_hi;
	uint64_t swp_val_lo;
};

/* uet ses standard request header with atomic compare/swap extension header */
struct UET_PACKED uet_ses_req_std_cswap {
	struct uet_ses_req_std base;
	struct uet_ses_atomic_cmpswp_ext ext;
};

/* uet ses standard request header with sync group extension header */
struct UET_PACKED uet_ses_req_std_sync {
	struct uet_ses_req_std base;
	struct uet_ses_sync_ext ext;
};

/* union of ses request structs */
union UET_PACKED uet_ses_req {
	struct uet_ses_req_std std;
	struct uet_ses_req_std_sync std_sync;
	struct uet_ses_req_std_atomic atomic;
	struct uet_ses_req_std_atomic_sync atomic_sync;
	struct uet_ses_req_std_cswap cswap;
};

#define UET_MAX_SES_HDR_BYTES	sizeof(union uet_ses_req)

/* uet ses response opcodes */
typedef enum {
	UET_DEFAULT_RESPONSE = 0x00,
	UET_RESPONSE         = 0x01,
	UET_RESPONSE_W_DATA  = 0x02,
	UET_NO_RESPONSE      = 0x03,
} uet_ses_rsp_opcode_t;

/* uet ses return codes */
typedef enum {
	UET_RC_NULL                 = 0x00,
	UET_RC_OK                   = 0x01,
	UET_RC_BAD_GENERATION       = 0x02,
	UET_RC_DISABLED             = 0x03,
	UET_RC_DISABLED_GEN         = 0x04,
	UET_RC_NO_MATCH             = 0x05,
	UET_RC_UNSUPPORTED_OP       = 0x06,
	UET_RC_UNSUPPORTED_SIZE     = 0x07,
	UET_RC_AT_INVALID           = 0x08,
	UET_RC_AT_PERM              = 0x09,
	UET_RC_AT_ATS_ERROR         = 0x0a,
	UET_RC_AT_NO_TRANS          = 0x0b,
	UET_RC_AT_OUT_OF_RANGE      = 0x0c,
	UET_RC_HOST_POISONED        = 0x0d,
	UET_RC_HOST_UNSUCCESS_CMPL  = 0x0e,
	UET_RC_AMO_UNSUPPORTED_OP   = 0x0f,
	UET_RC_AMO_UNSUPPORTED_DT   = 0x10,
	UET_RC_AMO_UNSUPPORTED_SIZE = 0x11,
	UET_RC_AMO_UNALIGNED        = 0x12,
	UET_RC_AMO_FP_NAN           = 0x13,
	UET_RC_AMO_FP_UNDERFLOW     = 0x14,
	UET_RC_AMO_FP_OVERFLOW      = 0x15,
	UET_RC_AMO_FP_INEXACT       = 0x16,
	UET_RC_PERM_VIOLATION       = 0x17,
	UET_RC_OP_VIOLATION         = 0x18,
	UET_RC_BAD_INDEX            = 0x19,
	UET_RC_BAD_PID              = 0x1a,
	UET_RC_BAD_JOB_ID           = 0x1b,
	UET_RC_BAD_MKEY             = 0x1c,
	UET_RC_BAD_ADDR             = 0x1d,
	UET_RC_CANCELLED            = 0x1e,
	UET_RC_UNDELIVERABLE        = 0x1f,
	UET_RC_UNCOR                = 0x20,
	UET_RC_UNCOR_TRNSNT         = 0x21,
	UET_RC_TOO_LONG             = 0x22,
	UET_RC_INITIATOR_ERR        = 0x23,
	UET_RC_DROPPED              = 0x24,
	UET_RC_DEFER_SEND           = 0xff  /* internal use */
} uet_ses_rc_t;

typedef enum {
	UET_EXPECTED = 0x00,
	UET_OVERFLOW = 0x01,
} uet_ses_list_t;

/* uet ses response common header fields */
struct UET_PACKED uet_ses_rsp_cmn {
#define UET_SES_RSP_LIST_MASK  0xc0
#define UET_SES_RSP_LIST_SHIFT 6
	/* see UET_SES_OPCODE_MASK|SHIFT */
	uint8_t  list_opcode;
	/* see UET_SES_VER_MASK|SHIFT */
#define UET_SES_RSP_RET_CODE_MASK  0x3f
#define UET_SES_RSP_RET_CODE_SHIFT 0
	uint8_t  ver_ret_code;
	union {
		uint16_t msg_id;
#define UET_SES_RSP_DS_PAYLOAD_LEN_MASK  0x3fff
#define UET_SES_RSP_DS_PAYLOAD_LEN_SHIFT 0
		uint16_t rsvd_payload_len; /* valid for UET_HDR_RSP_DATA_SMALL*/
	};
#define UET_SES_RSP_RI_GEN_MASK  0xff000000 /* valid for UET_HDR_RSP */
#define UET_SES_RSP_RI_GEN_SHIFT 24
#define UET_SES_RSP_JOB_ID_MASK  0x00ffffff
#define UET_SES_RSP_JOB_ID_SHIFT 0
	uint32_t ri_gen_job_id;
};

/* uet ses response header (UET_HDR_RSP) */
struct UET_PACKED uet_ses_rsp {
	struct uet_ses_rsp_cmn cmn;
	uint32_t mod_len;
};

/* uet ses response header w/ data (UET_HDR_RSP_DATA) */
struct UET_PACKED uet_ses_rsp_d {
	struct uet_ses_rsp_cmn cmn;
#define UET_SES_RSP_D_PAYLOAD_LEN_MASK  0x0000003fff
#define UET_SES_RSP_D_PAYLOAD_LEN_SHIFT 0
	union UET_PACKED {
		uint32_t rd_msg_id_payload_len;
		struct UET_PACKED {
			uint16_t rd_msg_id;
			uint16_t payload_len;
		};
	};
	uint32_t mod_len;
	uint32_t msg_off;
	uint8_t payload[];
};

/* uet ses small response header w/ data (UET_HDR_RSP_DATA_SMALL) */
struct UET_PACKED uet_ses_rsp_ds {
	struct uet_ses_rsp_cmn cmn;
	uint32_t orig_req_psn;
};

#define UET_MIN_PKT_SIZE_V4 (sizeof(struct ethhdr) + \
			     sizeof(struct iphdr) + \
			     sizeof(struct uet_pds_ctrl))
#define UET_MIN_PKT_SIZE_V6 (sizeof(struct ethhdr) + \
			     sizeof(struct ipv6hdr) + \
			     sizeof(struct uet_pds_ctrl))
#define UET_MIN_PKT_SIZE UET_MIN_PKT_SIZE_V4

/* get job id from standard request packet */
static inline uint32_t uet_get_std_req_job_id(struct uet_ses_req_std *ses)
{
	uint32_t ri_gen_job_id;

	ri_gen_job_id = ntohl(ses->cmn.ri_gen_job_id);

	return ((ri_gen_job_id & UET_SES_REQ_JOB_ID_MASK) <<
		UET_SES_REQ_JOB_ID_SHIFT);
}

#endif /* _UET_PKT_HDR_H_ */
