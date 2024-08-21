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
#include "uet_nic.h"
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

struct uet_instance; /* forward reference */

static inline int uet_gettime(uint64_t *time_ms)
{
	*time_ms = jiffies;
	return 0;
}

static inline void uet_ipv4_addr_to_str(uint32_t ipv4_addr, char *ipv4_addr_str)
{
	uint32_t net_order;

	net_order = htonl(ipv4_addr);
	snprintf(ipv4_addr_str, 16, "%u.%u.%u.%u", UET_NIPQUAD(net_order));
}

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
static inline uint16_t uet_csum(uint16_t *buf, int cnt)
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
static inline uint16_t uet_ipv4_csum(struct iphdr *ipv4)
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
 */
static inline void uet_build_ipv4_hdr(struct iphdr *ipv4, uint32_t dip, 
			uint32_t sip, uint16_t tot_len, uint8_t tos)
{
	ipv4->version = IPVERSION;
	ipv4->ihl = UET_IPV4_IHL_NO_OPTIONS;
	ipv4->tos = tos;
	ipv4->tot_len = htons(tot_len);
	ipv4->id = 0;
	ipv4->frag_off = htons(UET_IPV4_FRAG_OFF_DF);
	ipv4->ttl = IPDEFTTL;
	ipv4->protocol = UET_IPPROTO;
	ipv4->saddr = sip;
	ipv4->daddr = dip;
	ipv4->check = 0;
	ipv4->check = uet_ipv4_csum(ipv4);
}

static inline void uet_build_eth_hdr(struct ethhdr *eth, uint8_t *dmac, uint8_t *smac)
{
	eth->h_proto = htons(ETH_P_IP);
	memcpy(eth->h_dest, dmac, ETH_ALEN);
	memcpy(eth->h_source, smac, ETH_ALEN);
}

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

static inline uint16_t uet_get_ses_req_payload_len(struct uet_parsed_pkt *pp,
				     uint16_t max_payload_len)
{
	uint16_t hdr_len, payload_len;
	uint32_t req_len;
	uint64_t msg_off_payload_len;
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
		msg_off_payload_len = ntohll(ses->msg_off_payload_len);
		payload_len = ((msg_off_payload_len &
				UET_SES_REQ_STD_PAYLOAD_LEN_MASK) >>
			       UET_SES_REQ_STD_PAYLOAD_LEN_SHIFT);
	}

	return payload_len;
}

/* convert mac address to string */
static inline void uet_mac_addr_to_str(char *mac_addr_str, uint8_t *mac_addr)
{
	sprintf(mac_addr_str, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3],
		mac_addr[4], mac_addr[5]);
}

#endif /* _UET_UTIL_H_ */
