/*
 * Copyright (c) 2024,2025,2026 Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* Definitions for NIC Interface to UET API's */

#ifndef _UET_NIC_H_
#define _UET_NIC_H_

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>

#include "uet_addr.h"

//#define UET_NIC_DEBUG_HEXDUMP

/* environment variables to control the NIC interface */
#define UET_NIC_SHIM  "UET_NIC_SHIM"
#define UET_IFNAME    "UET_IFNAME"
#define UET_VPP_SEGMENT     "UET_VPP_SEGMENT"
#define UET_VPP_DMA_SOCKET  "UET_VPP_DMA_SOCKET"
#define UET_VPP_IPV4_ADDR   "UET_VPP_IPV4_ADDR"
#define UET_VPP_IPV6_ADDR   "UET_VPP_IPV6_ADDR"
#define UET_VPP_MTU         "UET_VPP_MTU"

#define UET_MAX_SYS_CMD_OCTETS  256
#define UET_NET_TYPE_SIZE 32

#define UET_NIC(uet) (&(uet)->nic)

struct uet_mr_buf_desc;
struct uet_instance;
struct uet_ep;
struct fi_info;

enum uet_nic_link_state {
	UET_NIC_LINK_STATE_UNKNOWN = 0,
	UET_NIC_LINK_STATE_DOWN    = 1,
	UET_NIC_LINK_STATE_UP      = 2
};

struct uet_nic_info {
	char *ifname;
	char *network_type;
	char *mac_addr_str;
	size_t mtu;
	enum uet_nic_link_state link_state;
};

/* nic control block structure - field of struct uet_instance */
struct uet_nic {
	char ifname[IFNAMSIZ];
	char network_type[UET_NET_TYPE_SIZE];

	uint8_t mac_addr[ETH_ALEN];
	char mac_addr_str[ETH_ALEN*3];

	/*
	 * Dual-stack: Both the IPv4 and IPv6 local addresses are populated at
	 * init (whichever are present). The address family is selected per
	 * destination/packet at runtime, so there is no single active family.
	 */
	uint32_t ipv4_addr;                            /* host order */
	char ipv4_addr_str[INET_ADDRSTRLEN];
	bool has_ipv4;
	uint8_t ipv6_addr[16];
	char ipv6_addr_str[INET6_ADDRSTRLEN];
	bool has_ipv6;

	char dst_ip_addr_str[INET6_ADDRSTRLEN];  /* destination addr */
	char nh_ip_addr_str[INET6_ADDRSTRLEN];      /* next hop addr */

	size_t mtu;                                 /* interface mtu */
	size_t l2_hdr_size;            /* size of l2 header in bytes */
	size_t min_pkt_size;             /* min packet size in bytes */
	size_t min_ip_pkt_size;       /* min ip packet size in bytes */
	size_t max_pkt_size;             /* max packet size in bytes */

	uint8_t uet_ipproto;           /* ip protocol number for uet */

	int sock_fd;                    /* socket fd for ioctl calls */
	void *nic_priv_data;

	/* function pointers supporting different NIC interfaces */
	int (*nic_getinfo)(struct uet_nic *nic,
			   struct uet_nic_info *nic_info);
	int (*nic_configure_info)(struct uet_nic *nic,
				  struct fi_info *info);
	int (*nic_ep_register)(struct uet_nic *nic,
			       struct uet_ep *ep,
			       void **context);
	void (*nic_ep_unregister)(struct uet_nic *nic, void *context);
	int (*nic_get_nh)(struct uet_nic *nic,
			  const struct uet_fa *fa,
			  bool is_ipv6,
			  uint8_t *mac);
	int (*nic_tx_pkt)(struct uet_nic *nic,
			  void *pkt,
			  void *iphdr,
			  size_t pkt_size);
	int (*nic_rx_pkt)(struct uet_nic *nic,
			  void *pkt,
			  size_t pkt_buf_size,
			  size_t *rx_pkt_size);
	int (*nic_rx_poll)(struct uet_nic *nic);
	void (*nic_finalize)(struct uet_nic *nic);
	int (*nic_initialize)(struct uet_nic *nic);
};

/*********************************************************************
 * NIC APIs
 *********************************************************************/

/*
 * helper to get IPv4 address of interface
 *
 * parms:
 *      sock_fd       - socket file descriptor for ioctl
 *      ifr           - ptr to ifreq struct (ifr_name must be set)
 *      ipv4_addr     - ptr to location where IPv4 addr is returned
 *      ipv4_addr_str - ptr to buffer for IPv4 addr string
 *
 * returns:
 *      0 on success
 *      negative value corresponding to errno on error
 */
int uet_nic_get_ipv4_addr(int sock_fd,
			  struct ifreq *ifr,
			  uint32_t *ipv4_addr,
			  char *ipv4_addr_str);

/*
 * helper to get IPv6 address of interface from /proc/net/if_inet6
 *
 * parms:
 *      ifname        - interface name
 *      ipv6_addr     - ptr to 16-byte buffer for IPv6 addr
 *      ipv6_addr_str - ptr to buffer for IPv6 addr string
 *
 * returns:
 *      0 on success
 *      negative value corresponding to errno on error
 */
int uet_nic_get_ipv6_addr(const char *ifname,
			  uint8_t *ipv6_addr,
			  char *ipv6_addr_str);

/*
 * helper to resolve IPv4 next-hop MAC address
 *
 * parms:
 *      nic     - ptr to uet nic struct
 *      sock_fd - socket file descriptor for ioctl
 *      dst_ip  - destination IPv4 address
 *      mac     - ptr to location where MAC address is returned
 *
 * returns:
 *      0 on success
 *      negative value corresponding to errno on error
 */
int uet_nic_resolve_ipv4_nh(struct uet_nic *nic,
			    int sock_fd,
			    uint32_t dst_ip,
			    uint8_t *mac);

/*
 * helper to resolve IPv6 next-hop MAC address
 *
 * parms:
 *      nic      - ptr to uet nic struct
 *      dst_ip6  - destination IPv6 address
 *      mac      - ptr to location where MAC address is returned
 *
 * returns:
 *      0 on success
 *      negative value corresponding to errno on error
 */
int uet_nic_resolve_ipv6_nh(struct uet_nic *nic,
			    const uint8_t *dst_ip6,
			    uint8_t *mac);

/*
 * initialize nic resources
 *
 * parms:
 *      uet - ptr to uet nic struct
 *
 * Discovers both IPv4 and IPv6 local addresses (whichever are present);
 * the address family is selected per destination/packet at runtime.
 *
 * returns:
 *      0 on success
 *      negative value corresponding to errno on error
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
	if (!nic)
		assert(0);

	return nic->nic_finalize(nic);
}

/*
 * get nic info
 *
 * parms:
 *      nic - ptr to uet nic struct
 *      nic_info - ptr to uet nic info struct to be filled in
 *
 * returns:
 *      0 on success
 *      negative value corresponding to errno on error
 */
int uet_nic_getinfo(struct uet_nic *nic,
		    struct uet_nic_info *nic_info);

static inline int uet_nic_configure_info(struct uet_nic *nic,
					 struct fi_info *info)
{
	if (!nic || !info)
		assert(0);

	if (!nic->nic_configure_info)
		return 0;
	return nic->nic_configure_info(nic, info);
}

static inline int uet_nic_ep_register(struct uet_nic *nic,
				      struct uet_ep *ep,
				      void **context)
{
	if (!nic || !ep || !context)
		assert(0);

	if (!nic->nic_ep_register)
		return 0;
	return nic->nic_ep_register(nic, ep, context);
}

static inline void uet_nic_ep_unregister(struct uet_nic *nic, void *context)
{
	if (!nic)
		assert(0);
	if (!context)
		return;

	if (nic->nic_ep_unregister)
		nic->nic_ep_unregister(nic, context);
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
 *      0 on success
 *      negative value corresponding to errno on error
 */
static inline int uet_nic_get_ipv4_nh(struct uet_nic *nic,
				      uint32_t dst_ip,
				      uint8_t *mac)
{
	if (!nic || !mac)
		assert(0);

	return uet_nic_resolve_ipv4_nh(nic, nic->sock_fd, dst_ip, mac);
}

/*
 * get next-hop info for ipv6 destination address
 *
 * parms:
 *      nic     - ptr to uet nic struct
 *      dst_ip6 - destination IPv6 address for which info is requested
 *      mac     - ptr to location where mac address is to be returned
 *
 * returns:
 *      0 on success
 *      negative value corresponding to errno on error
 */
static inline int uet_nic_get_ipv6_nh(struct uet_nic *nic,
				      const uint8_t *dst_ip6,
				      uint8_t *mac)
{
	if (!nic || !dst_ip6 || !mac)
		assert(0);

	return uet_nic_resolve_ipv6_nh(nic, dst_ip6, mac);
}

/*
 * get next-hop info for destination address (v4 or v6)
 *
 * parms:
 *      nic     - ptr to uet nic struct
 *      fa      - ptr to fabric address (contains v4 or v6 address)
 *      is_ipv6 - true if fa contains an IPv6 address
 *      mac     - ptr to location where mac address is to be returned
 *
 * returns:
 *      0 on success
 *      negative value corresponding to errno on error
 */
static inline int uet_nic_get_nh(struct uet_nic *nic,
				 const struct uet_fa *fa,
				 bool is_ipv6,
				 uint8_t *mac)
{
	if (!nic || !fa || !mac)
		assert(0);

	if (nic->nic_get_nh)
		return nic->nic_get_nh(nic, fa, is_ipv6, mac);
	if (is_ipv6)
		return uet_nic_get_ipv6_nh(nic, fa->v6, mac);
	else
		return uet_nic_get_ipv4_nh(nic, fa->v4, mac);
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
 *      0 on success,
 *      negative value corresponding to errno on error
 */
static inline int uet_nic_tx_pkt(struct uet_nic *nic,
				 void *pkt,
				 void *iphdr,
				 size_t pkt_size)
{
	if (!nic || !pkt || !pkt_size)
		assert(0);

	return nic->nic_tx_pkt(nic, pkt, iphdr, pkt_size);
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
 *      negative value corresponding to errno, err reading packet
 */
static inline int uet_nic_rx_pkt(struct uet_nic *nic,
				 void *pkt,
				 size_t pkt_buf_size,
				 size_t *rx_pkt_size)
{
	if (!nic || !pkt || !pkt_buf_size || !rx_pkt_size)
		assert(0);

	return nic->nic_rx_pkt(nic, pkt, pkt_buf_size, rx_pkt_size);
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
 *      negative value corresponding to errno, poll err
 */
static inline int uet_nic_rx_poll(struct uet_nic *nic)
{
	if (!nic)
		assert(0);

	return nic->nic_rx_poll(nic);
}

#endif /* _UET_NIC_H_ */
