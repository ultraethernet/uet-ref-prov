/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* Definitions for UET Utilities */

#ifndef _UET_UTIL_H_
#define _UET_UTIL_H_

#include <linux/spinlock_types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

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

/* read-write lock data structs */
typedef enum {
	UET_RW_LOCK_RD_ACCESS,
	UET_RW_LOCK_WR_ACCESS
} uet_rw_lock_access_t;

#if 0
typedef enum {
	UET_RW_LOCK_WR_ACQUIRED_VAL = -1,
	UET_RW_LOCK_IDLE_VAL = 0,
	UET_RW_LOCK_RD_ACQUIRED_VAL = 1,
} uet_rw_lock_val_t;

struct uet_rw_lock {
	uet_rw_lock_val_t val;
};
#else

struct uet_rw_lock {
	rwlock_t lock;
};

#endif

/* parsed uet packet                                         */
/*   - ptr's to headers can be NULL if header is not present */
struct uet_parsed_pkt {
	uint16_t pkt_len;                  /* total length of received packet */
	void *eth;
	uint16_t eth_len;
	uint16_t ethertype;
	void *ip;                         /* can point to ipv4 or ipv6 header */
	uint16_t ip_len;
	uint8_t ip_protocol;                        /* next protocol after ip */
	void *udp;
	uint16_t udp_len;
	void *sec;                                     /* uet security header */
	uint16_t sec_len;
	uint8_t sec_an;
	uint32_t sec_sdi;
	bool sec_ssi_valid;
	uint32_t sec_ssi;
	uint64_t sec_tsc;
	void *pds;
	uint16_t pds_len;
	uint16_t entropy;             /* from udp source port or pds_prologue */
	uint8_t pds_type;
	uint8_t pds_flags;
	uint32_t pds_psn;
	uint16_t pds_spdcid;
	uint16_t pds_dpdcid;
	uint8_t pds_syn_off;
	uint32_t pds_clear_fwd_psn;
	uint8_t pds_nack_code;
	uint8_t pds_ctrl_payload;
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
#define UET_PDS_PKT_HDR_TRACE(UET, PP, PKT, PKT_LEN, MSG)            \
	do {                                                         \
		struct uet_parsed_pkt _pp;                           \
		if ((PP) == NULL) {                                  \
			if (uet_parse_pkt((PKT),                     \
					  (PKT_LEN), &_pp,           \
					  (UET)->uet_udp_port,       \
					  (UET)->max_payload_len) == \
			    0) {                                     \
				printf("\n%s\n\n", (MSG));           \
				uet_print_pkt_hdrs((&_pp));          \
				printf("\n");                        \
			}                                            \
		} else {                                             \
			printf("\n%s\n\n", (MSG));                   \
			uet_print_pkt_hdrs((PP));                    \
			printf("\n");                                \
		}                                                    \
	} while (0)
#else
#define UET_PDS_PKT_HDR_TRACE(...)
#endif

struct uet_instance; /* forward reference */

static inline uint64_t uet_gettime(uint64_t *time_ms)
{
	return (*time_ms = jiffies);
}
void uet_mac_addr_to_str(char *mac_addr_str, uint8_t *mac_addr);
void uet_ipv4_addr_to_str(uint32_t ipv4_addr, char *ipv4_addr_str);
char *uet_ses_rc_to_str(uet_ses_rc_t rc);
void uet_print_mac_addr(uint8_t *mac);
void uet_print_ipv4_addr(uint32_t ipv4_addr);
void uet_print_uet_addr(struct uet_addr *uet_addr);
void uet_print_mac_hdr(struct ethhdr *eth);
void uet_print_ipv4_hdr(struct iphdr *ipv4);
void uet_print_uet_hdr(struct uet_parsed_pkt *pp);
void uet_print_pkt_hdrs(struct uet_parsed_pkt *pp);
size_t uet_roundup_8(size_t val);

static inline uint8_t uet_dscp_to_tos(uint8_t dscp)
{
	return (dscp << 2);
}

uint16_t uet_csum(uint16_t *buf, int cnt);
uint16_t uet_ipv4_csum(struct iphdr *ipv4);
void uet_build_ipv4_hdr(struct iphdr *ipv4, uint32_t dip, 
			uint32_t sip, uint16_t tot_len, uint8_t tos);
void uet_build_eth_hdr(struct ethhdr *eth, uint8_t *dmac, uint8_t *smac);
void uet_pkt_hex_dump(void *pkt, uint32_t length, uint64_t addr, bool is_tx);

static inline void uet_rw_lock(struct uet_rw_lock *lock, uet_rw_lock_access_t access)
{
	switch(access) {
		case UET_RW_LOCK_RD_ACCESS:
			read_lock(&lock->lock);
			break;
		case UET_RW_LOCK_WR_ACCESS:
			write_lock(&lock->lock);
			break;
		default:
			BUG_ON(1);
	}
}

static inline void uet_rw_unlock(struct uet_rw_lock *lock, uet_rw_lock_access_t access)
{
	switch(access) {
		case UET_RW_LOCK_RD_ACCESS:
			read_unlock(&lock->lock);
			break;
		case UET_RW_LOCK_WR_ACCESS:
			write_unlock(&lock->lock);
			break;
		default:
			BUG_ON(1);
	}
}

static inline void uet_rw_lock_init(struct uet_rw_lock *lock)
{
	rwlock_init(&lock->lock);
}

uint16_t uet_get_ses_req_payload_len(struct uet_parsed_pkt *pp,
				     uint16_t max_payload_len);
int uet_parse_pkt(void *pkt, size_t pkt_len, struct uet_parsed_pkt *pp, 
		  uint16_t uet_udp_port, size_t max_payload_len);

#endif /* _UET_UTIL_H_ */
