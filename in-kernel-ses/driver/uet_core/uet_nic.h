/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* Definitions for NIC Interface to UET API's */

#ifndef _UET_NIC_H_
#define _UET_NIC_H_

#include <linux/if.h>
#include <linux/inet.h>

#include "uet_uapi.h"

#define UET_MAX_SYS_CMD_OCTETS  256

#define UET_NIC(uet) (&(uet)->nic)
#define UET_INSTANCE_FROM_NIC(nic) container_of(nic, struct uet_instance, nic)

typedef void *uet_nic_mr_handle_t;      /* nic handle for memory region */

struct uet_mr_buf_desc;
struct uet_instance;
struct uet_nic;

struct uet_nic_ops {
	/* function pointers supporting different NIC interfaces */
	int (*nic_getinfo)(struct uet_nic *nic,
			   struct uet_nic_info *nic_info);
	int (*nic_get_ipv4_nh)(struct uet_nic *nic,
			       uint32_t dst_ip,
			       uint8_t *mac);
	int (*nic_tx_pkt)(struct uet_nic *nic,
			  void *pkt,
			  void *iphdr,
			  size_t pkt_size);
	int (*nic_rx_pkt)(struct uet_nic *nic,
			  void *pkt,
			  size_t pkt_buf_size,
			  size_t *rx_pkt_size);
	int (*nic_mr_reg)(struct uet_nic *nic,
			  struct uet_mr_buf_desc *desc,
			  uet_nic_mr_handle_t *handle);
	int (*nic_mr_dereg)(struct uet_nic *nic,
			    uet_nic_mr_handle_t handle);
	int (*nic_rx_poll)(struct uet_nic *nic);
	void (*nic_finalize)(struct uet_nic *nic);
	int (*nic_initialize)(struct uet_nic *nic);
};

/* nic control block structure - field of struct uet_instance */
struct uet_nic {
	char ifname[IFNAMSIZ];                              /* interface name */
	char network_type[UET_NET_TYPE_SIZE];

	uint8_t mac_addr[ETH_ALEN];
	char mac_addr_str[ETH_ALEN*3];

	__be32 ipv4_addr;                            /* host order */
	char ip_addr_str[INET6_ADDRSTRLEN];            /* local addr */
	char dst_ip_addr_str[INET6_ADDRSTRLEN];  /* destination addr */
	char nh_ip_addr_str[INET6_ADDRSTRLEN];      /* next hop addr */

	size_t mtu;                                 /* interface mtu */
	size_t l2_hdr_size;            /* size of l2 header in bytes */
	size_t min_pkt_size;             /* min packet size in bytes */
	size_t min_ip_pkt_size;       /* min ip packet size in bytes */
	size_t max_pkt_size;             /* max packet size in bytes */

	uint8_t uet_ipproto;           /* ip protocol number for uet */

	void *nic_priv_data;
	struct uet_nic_ops ops;
};

/*********************************************************************
 * NIC APIs
 *********************************************************************/

/*
 * initialize nic resources
 *
 * parms:
 *      uet - ptr to uet nic struct
 *
 * returns:
 *      FI_SUCCESS on success
 *      negative value corresponding to fabric errno on error
 */
int uet_nic_initialize(struct uet_nic *nic);

/*
 * free nic resources
 *
 * parms:
 *      uet - ptr to uet nic struct
 */
static inline void uet_nic_finalize(struct uet_nic *nic)
{
	if (!nic || !nic->ops.nic_finalize)
		BUG();

	return nic->ops.nic_finalize(nic);
}

/*
 * get nic info for libfabric fid_nic struct
 *
 * parms:
 *      uet - ptr to uet nic struct
 *      nic - ptr to nic info struct to be init
 *
 * returns:
 *      FI_SUCCESS on success
 *      negative value corresponding to fabric errno on error
 */
static inline int uet_nic_getinfo(struct uet_nic *nic,
				  struct uet_nic_info *nic_info)
{
	if (!nic || !nic_info || !nic->ops.nic_getinfo)
		BUG();

	return nic->ops.nic_getinfo(nic, nic_info);
}

/*
 * get next-hop info for ipv4 destination address
 *
 * parms:
 *      uet    - ptr to uet nic struct
 *      dst_ip - destination IPv4 address for which info is requested
 *      mac    - ptr to location where mac address is to be returned
 *
 * returns:
 *      FI_SUCCESS on success
 *      negative value corresponding to fabric errno on error
 */
static inline int uet_nic_get_ipv4_nh(struct uet_nic *nic,
				      uint32_t dst_ip,
				      uint8_t *mac)
{
	if (!nic || !mac || !nic->ops.nic_get_ipv4_nh)
		BUG();

	return nic->ops.nic_get_ipv4_nh(nic, dst_ip, mac);
}

/*
 * transmit a packet
 *
 * parms:
 *      uet      - ptr to uet nic struct
 *      pkt      - ptr to packet to send
 *      iphdr    - ptr to ip header in packet to send
 *      pkt_size - size of packet to send in bytes
 *
 * returns:
 *      FI_SUCCESS on success,
 *      negative value corresponding to fabric errno on error
 */
static inline int uet_nic_tx_pkt(struct uet_nic *nic,
				 void *pkt,
				 void *iphdr,
				 size_t pkt_size)
{
	if (!nic || !pkt || !pkt_size || !nic->ops.nic_tx_pkt)
		BUG();

	return nic->ops.nic_tx_pkt(nic, pkt, iphdr, pkt_size);
}

/*
 * receive a packet
 *
 * parms:
 *      uet - ptr to uet nic struct
 *      pkt - ptr to receive packet buffer
 *      pkt_buf_size - size of receive packet buffer in bytes
 *      rx_pkt_size  - ptr to location where size of received packet
 *                     in bytes is to be returned
 *
 * returns:
 *      0, no valid packet available
 *      1, read a packet
 *      negative value corresponding to fabric errno, err reading packet
 */
static inline int uet_nic_rx_pkt(struct uet_nic *nic,
				 void *pkt,
				 size_t pkt_buf_size,
				 size_t *rx_pkt_size)
{
	if (!nic || !pkt || !pkt_buf_size || 
	    !rx_pkt_size || !nic->ops.nic_rx_pkt)
		BUG();

	return nic->ops.nic_rx_pkt(nic, pkt, pkt_buf_size, rx_pkt_size);
}

/*
 * poll to determine if rx packet is available
 *
 * parms:
 *      ctx - ptr to uet nic struct
 *
 * returns:
 *      0, no packet is available
 *      1, packet is available
 *      negative value corresponding to fabric errno, poll err
 */
static inline int uet_nic_rx_poll(struct uet_nic *nic)
{
	if (!nic || !nic->ops.nic_rx_poll)
		BUG();

	return nic->ops.nic_rx_poll(nic);
}

/*
 * register a memory region with nic
 *
 * parms:
 *      uet    - ptr to uet nic struct
 *      desc   - ptr to buffer info struct for memory region
 *      handle - ptr to location where nic handle for registered
 *               memory region is to be returned
 *
 * returns:
 *      FI_SUCCESS on success,
 *      negative value corresponding to fabric errno on error
 */
static inline int uet_nic_mr_reg(struct uet_nic *nic,
				 struct uet_mr_buf_desc *desc,
				 uet_nic_mr_handle_t *handle)
{
	if (!nic || !desc || !handle || !nic->ops.nic_mr_reg)
		BUG();

	return nic->ops.nic_mr_reg(nic, desc, handle);
}

/*
 * deregister memory region that was registered with nic
 *
 * parms:
 *      uet    - ptr to uet nic struct
 *      handle - nic handle for registered memory region
 *
 * returns:
 *      FI_SUCCESS on success,
 *      negative value corresponding to fabric errno on error
 */
static inline int uet_nic_mr_dereg(struct uet_nic *nic,
				   uet_nic_mr_handle_t handle)
{
	if (!nic || !handle || !nic->ops.nic_mr_dereg)
		BUG();

	return nic->ops.nic_mr_dereg(nic, handle);
}

extern void uet_nic_set_ops(struct uet_nic_ops *ops);

#define UET_NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#define UET_NIP6(addr) \
	ntohs((addr).s6_addr16[0]), \
	ntohs((addr).s6_addr16[1]), \
	ntohs((addr).s6_addr16[2]), \
	ntohs((addr).s6_addr16[3]), \
	ntohs((addr).s6_addr16[4]), \
	ntohs((addr).s6_addr16[5]), \
	ntohs((addr).s6_addr16[6]), \
	ntohs((addr).s6_addr16[7])

#endif /* _UET_NIC_H_ */
