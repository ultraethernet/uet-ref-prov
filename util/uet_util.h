/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* Definitions for UET Utilities */

#ifndef _UET_UTIL_H_
#define _UET_UTIL_H_

#include <stdint.h>
#include <stdbool.h>

#include "uet_addr.h"
#include "uet_pkt_hdr.h"

#define UET_MSEC_PER_SEC  1000
#define UET_NSEC_PER_MSEC 1000000

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define htonll(x) (x)
# define ntohll(x) (x)
#else
# define htonll(x) (((uint64_t)htonl((x)&0xFFFFFFFF) << 32) | \
		    htonl((x) >> 32))
# define ntohll(x) (((uint64_t)ntohl((x)&0xFFFFFFFF) << 32) | \
		    ntohl((x) >> 32))
#endif

#define uet_max(a, b)           \
({                              \
	__typeof__(a) _a = (a); \
	__typeof__(b) _b = (b); \
	_a > _b ? _a : _b;      \
})

#define uet_min(a, b)           \
({                              \
	__typeof__(a) _a = (a); \
	__typeof__(b) _b = (b); \
	_a < _b ? _a : _b;      \
})

/* read-write lock data structs */
typedef enum {
	UET_RW_LOCK_RD_ACCESS,
	UET_RW_LOCK_WR_ACCESS
} uet_rw_lock_access_t;

typedef enum {
	UET_RW_LOCK_WR_ACQUIRED_VAL = -1,
	UET_RW_LOCK_IDLE_VAL = 0,
	UET_RW_LOCK_RD_ACQUIRED_VAL = 1,
} uet_rw_lock_val_t;

struct uet_rw_lock {
	uet_rw_lock_val_t val;
};

/* parsed uet packet                                         */
/*   - ptr's to headers can be NULL if header is not present */
struct uet_parsed_pkt {
	uint16_t pkt_len;                  /* total length of received packet */
	void *eth;
	uint16_t eth_len;
	uint16_t ethertype;
	void *ip;                         /* can point to ipv4 or ipv6 header */
	uint16_t ip_len;
	uint16_t ip_payload_len;
	uint8_t ip_protocol;                        /* next protocol after ip */
	bool is_ipv6;                      /* true if ip points to ipv6 header */
	void *udp;
	uint16_t udp_len;
	void *entropy;                                  /* uet entropy header */
	uint16_t entropy_len;
	uint16_t entropy_val;
	void *sec;                                     /* uet security header */
	uint16_t sec_len;
	uint8_t sec_an;
	uint32_t sec_sdi;
	bool sec_ssi_valid;
	uint32_t sec_ssi;
	uint16_t sec_epoch;
	uint64_t sec_tsc;
	void *pds;
	uint16_t pds_len;
	uint8_t pds_type;
	uint8_t pds_flags;
	uint32_t pds_cack_psn;
	uint32_t pds_psn;
	uint32_t pds_rudi_pkt_id;
	uint16_t pds_spdcid;
	uint16_t pds_dpdcid;
	uint8_t pds_cc_type;
	uint8_t pds_cc_flags;
	uint8_t pds_mpr;
	uint32_t pds_sack_base_psn;
	uint64_t pds_sack_bitmap;
	uint64_t pds_cc_state;
	uint64_t pds_ccx_state;
	uint8_t pds_syn_off;
	uint32_t pds_clear_psn;
	uint8_t pds_nack_code;
	uint32_t pds_payload;             /* NACK payload or closing ACK EPSN */
	uint16_t pds_probe_opaque;
	uint8_t pds_pdc_info;
	uint32_t pds_ctrl_payload;
	uint8_t pds_ctrl_type;
	uint8_t next_hdr;        /* identifies format of header following pds */
	void *ses;
	uint16_t ses_len;
	uint8_t ses_opcode;
	uint16_t ses_msg_id;
	uint16_t hdr_len;                              /* total header length */
	uint16_t trailer_len;           /* total trailer length (crc and icv) */
	void *payload;                                         /* ses payload */
	uint16_t ses_payload_len;                          /* from ses header */
	uint16_t pkt_payload_len;        /* pkt_len - (hdr_len + trailer_len) */
	void *ses_crc;
};

//#define UET_PDS_PKT_HDR_TRACE_ENABLED

#ifdef UET_PDS_PKT_HDR_TRACE_ENABLED
#define UET_PDS_PKT_HDR_TRACE(UET, PP, PKT, PKT_LEN, MSG)          \
	do {                                                       \
		struct uet_parsed_pkt _pp;                         \
		if ((PP) == NULL) {                                \
			if (uet_parse_pkt((UET), (PKT),            \
					  (PKT_LEN), &_pp) == 0) { \
				printf("\n%s\n\n", (MSG));         \
				uet_print_pkt_hdrs((&_pp));        \
				printf("\n");                      \
			}                                          \
		} else {                                           \
			printf("\n%s\n\n", (MSG));                 \
			uet_print_pkt_hdrs((PP));                  \
			printf("\n");                              \
		}                                                  \
	} while (0)
#else
#define UET_PDS_PKT_HDR_TRACE(...)
#endif

struct uet_instance; /* forward reference */

int uet_gettime(time_t *time_ms);
void uet_mac_addr_to_str(char *mac_addr_str, uint8_t *mac_addr);
void uet_ipv4_addr_to_str(uint32_t ipv4_addr, char *ipv4_addr_str);
void uet_ipv6_addr_to_str(const uint8_t *ipv6_addr, char *ipv6_addr_str);
void uet_ip_addr_to_str(const struct uet_fa *fa, bool is_ipv6, char *str);
char *uet_ses_rc_to_str(uet_ses_rc_t rc);
void uet_print_mac_addr(uint8_t *mac);
void uet_print_ipv4_addr(uint32_t ipv4_addr);
void uet_print_ipv6_addr(const uint8_t *ipv6_addr);
void uet_print_uet_addr(struct uet_addr *uet_addr);
void uet_print_mac_hdr(struct ethhdr *eth);
void uet_print_ipv4_hdr(struct iphdr *ipv4);
void uet_print_ipv6_hdr(struct ipv6hdr *ipv6);
void uet_print_uet_hdr(struct uet_parsed_pkt *pp);
void uet_print_pkt_hdrs(struct uet_parsed_pkt *pp);
size_t uet_roundup_8(size_t val);
uint8_t uet_dscp_to_tos(uint8_t dscp);
uint16_t uet_csum(uint16_t *buf, int cnt);
uint16_t uet_ipv4_csum(struct iphdr *ipv4);
void uet_build_ipv4_hdr(struct uet_instance *uet, struct iphdr *ipv4,
			uint32_t dip, uint32_t sip, uint16_t tot_len,
			uint8_t tos, bool crc_en);
void uet_build_ipv6_hdr(struct uet_instance *uet, struct ipv6hdr *ipv6,
			const uint8_t *dip, const uint8_t *sip,
			uint16_t payload_len, uint8_t tc, bool crc_en);
void uet_update_ipv4_tl(struct iphdr *ipv4, uint16_t tot_len);
void uet_update_ipv6_pl(struct ipv6hdr *ipv6, uint16_t payload_len);
void uet_build_eth_hdr(struct ethhdr *eth, uint8_t *dmac, uint8_t *smac,
		       bool is_ipv6);
void uet_pkt_hex_dump(void *pkt, uint32_t length, uint64_t addr, bool is_tx);
void uet_rw_lock_init(struct uet_rw_lock *lock);
void uet_rw_lock(struct uet_rw_lock *lock, uet_rw_lock_access_t access);
void uet_rw_unlock(struct uet_rw_lock *lock, uet_rw_lock_access_t access);
uint16_t uet_get_ses_req_payload_len(struct uet_parsed_pkt *pp,
				     uint16_t max_payload_len);
int uet_parse_pkt(struct uet_instance *uet, void *pkt, size_t pkt_len,
		  struct uet_parsed_pkt *pp);

#endif /* _UET_UTIL_H_ */
