/*
 * Copyright (c) 2024,2025,2026 Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* NIC Interface common functions */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "uet_api_private.h"
#include "uet_nic.h"

/* helper to get IPv4 address of interface */
int uet_nic_get_ipv4_addr(int sock_fd,
			  struct ifreq *ifr,
			  uint32_t *ipv4_addr,
			  char *ipv4_addr_str)
{
	char *ip;
	struct in_addr in;
	const char *ip_override;

	/* When this instance runs behind a PCIe device model, the guest owns
	 * the network identity and the host interface carries no address at
	 * all. The ioctl below would fail and leave the instance with no
	 * source address for UET headers. The UET_LOCAL_IP env var supplies
	 * it.
	 */
	ip_override = getenv("UET_LOCAL_IP");
	if ((ip_override != NULL) && (*ip_override != '\0')) {
		if (inet_pton(AF_INET, ip_override, &in) != 1) {
			UET_API_ERR("UET_LOCAL_IP is not an IPv4 address: %s",
				    ip_override);
			return -EINVAL;
		}

		*ipv4_addr = ntohl(in.s_addr);
		strncpy(ipv4_addr_str, ip_override, INET_ADDRSTRLEN - 1);
		ipv4_addr_str[INET_ADDRSTRLEN - 1] = '\0';

		return 0;
	}

	ifr->ifr_addr.sa_family = AF_INET;
	if ((ioctl(sock_fd, SIOCGIFADDR, ifr)) < 0)
		return -ENOENT;

	ip = &ifr->ifr_addr.sa_data[2];
	*ipv4_addr = ntohl(*((uint32_t *)ip));
	inet_ntop(AF_INET, ip, ipv4_addr_str, INET_ADDRSTRLEN);
	return 0;
}

/* helper to get IPv6 address of interface from /proc/net/if_inet6 */
int uet_nic_get_ipv6_addr(const char *ifname,
			  uint8_t *ipv6_addr,
			  char *ipv6_addr_str)
{
	FILE *f;
	char line[128];
	char addr_hex[33];
	char if_name[IFNAMSIZ];
	int scope, prefix, flags, if_idx;
	unsigned int addr_bytes[16];
	int i;
	bool found_link_local = false;
	uint8_t link_local_addr[16];
	char link_local_str[INET6_ADDRSTRLEN];

	f = fopen("/proc/net/if_inet6", "r");
	if (!f)
		return -ENOENT;

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%32s %x %x %x %x %s",
			   addr_hex, &if_idx, &prefix, &scope, &flags,
			   if_name) != 6)
			continue;

		if (strcmp(if_name, ifname) != 0)
			continue;

		/* skip loopback (scope 0x10) */
		if (scope == 0x10)
			continue;

		/* parse hex address */
		for (i = 0; i < 16; i++) {
			if (sscanf(&addr_hex[i * 2], "%2x", &addr_bytes[i]) != 1) {
				fclose(f);
				return -EINVAL;
			}
		}

		/* save link-local (scope 0x20) as fallback */
		if (scope == 0x20) {
			if (!found_link_local) {
				for (i = 0; i < 16; i++)
					link_local_addr[i] = (uint8_t)addr_bytes[i];
				inet_ntop(AF_INET6, link_local_addr,
					  link_local_str, INET6_ADDRSTRLEN);
				found_link_local = true;
			}
			continue;
		}

		/* found non-link-local address - use it */
		for (i = 0; i < 16; i++)
			ipv6_addr[i] = (uint8_t)addr_bytes[i];
		inet_ntop(AF_INET6, ipv6_addr, ipv6_addr_str, INET6_ADDRSTRLEN);
		fclose(f);
		return 0;
	}

	fclose(f);

	/* fallback to link-local if no global/site-local found */
	if (found_link_local) {
		memcpy(ipv6_addr, link_local_addr, 16);
		strncpy(ipv6_addr_str, link_local_str, INET6_ADDRSTRLEN);
		return 0;
	}

	return -ENOENT;
}

/*
 * Read an entry out of the kernel's neighbour cache.
 *
 * Returns 1 when an entry with a link-layer address was found, 0 when
 * there is none, and a negative errno on failure. With permanent_only the
 * entry must also be PERMANENT - one an operator configured rather than
 * one the kernel learned - which is the only kind safe to trust without
 * re-probing.
 */
static int uet_nic_neigh_lookup(const char *ifname,
				const char *nh_str,
				bool ipv6,
				bool permanent_only,
				uint8_t *mac)
{
	char sys_cmd[UET_MAX_SYS_CMD_OCTETS];
	char line[256];
	FILE *cmd_stream;
	char *lladdr;
	unsigned int m[6];
	int i;

	snprintf(sys_cmd, sizeof(sys_cmd),
		 "ip %s neigh show %s dev %s 2>/dev/null",
		 ipv6 ? "-6" : "-4", nh_str, ifname);

	cmd_stream = popen(sys_cmd, "r");
	if (cmd_stream == NULL)
		return -EIO;

	memset(line, 0, sizeof(line));

	if (fgets(line, sizeof(line), cmd_stream) == NULL) {
		pclose(cmd_stream);
		return 0;
	}

	pclose(cmd_stream);

	if (permanent_only && (strstr(line, "PERMANENT") == NULL))
		return 0;

	lladdr = strstr(line, "lladdr ");
	if (lladdr == NULL)
		return 0;

	lladdr += 7;

	if (sscanf(lladdr, "%x:%x:%x:%x:%x:%x",
		   &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) {
		return 0;
	}

	for (i = 0; i < ETH_ALEN; i++)
		mac[i] = (uint8_t)m[i];

	return 1;
}

/*
 * Load the neighbour cache for a next hop by probing it.
 *
 * The existing entry is dropped first so a stale one cannot be picked up,
 * then a single echo request makes the kernel resolve the address.
 */
static void uet_nic_neigh_probe(const char *ifname,
				const char *nh_str,
				bool ipv6)
{
	char sys_cmd[UET_MAX_SYS_CMD_OCTETS];

	snprintf(sys_cmd, sizeof(sys_cmd),
		 "ip %s neigh del %s dev %s 2>/dev/null 1>/dev/null",
		 ipv6 ? "-6" : "-4", nh_str, ifname);

	if (system(sys_cmd) == -1)
		UET_API_ERR("Error clearing neighbor cache entry");

	snprintf(sys_cmd, sizeof(sys_cmd),
		 "ping %s -c 1 -W 1 -I %s %s 2>/dev/null 1>/dev/null",
		 ipv6 ? "-6" : "-4", ifname, nh_str);

	if (system(sys_cmd) == -1)
		UET_API_ERR("Error probing next hop");
}

/* resolve next-hop info for ipv4 destination address */
int uet_nic_resolve_ipv4_nh(struct uet_nic *nic,
			    int sock_fd,
			    uint32_t dst_ip,
			    uint8_t *mac)
{
	char sys_cmd[UET_MAX_SYS_CMD_OCTETS];
	int i, rc;
	uint32_t net_order;
	FILE *cmd_stream;
	struct in_addr nh_ipv4;
	struct arpreq areq;
	struct sockaddr_in *sin;
	uint8_t invalid_mac[ETH_ALEN];

	/* convert ipv4 addr to string */
	net_order = htonl(dst_ip);
	inet_ntop(AF_INET, (char *)&net_order, nic->dst_ip_addr_str,
		  INET_ADDRSTRLEN);

	/*
	 * Our own address resolves to our own MAC, and the frame is then
	 * looped back rather than transmitted.
	 *
	 * The kernel cannot answer this: a local address is not a
	 * neighbour, so the route and neighbour lookups below find nothing
	 * and resolution fails. Answering it here is what lets two queue
	 * pairs on one device reach each other.
	 */
	if (nic->has_ipv4 && (dst_ip == nic->ipv4_addr)) {
		memcpy(mac, nic->mac_addr, ETH_ALEN);
		strncpy(nic->nh_ip_addr_str, nic->dst_ip_addr_str,
			INET6_ADDRSTRLEN - 1);
		nic->nh_ip_addr_str[INET6_ADDRSTRLEN - 1] = '\0';

		printf("Next-Hop Address Resolution\n");
		printf("  Destination IPv4 Addr: %s\n", nic->dst_ip_addr_str);
		printf("  Next-Hop IPv4 Addr:    %s (loopback)\n",
		       nic->nh_ip_addr_str);
		printf("  Next-Hop MAC Addr:     ");
		uet_print_mac_addr(mac);

		return 0;
	}

	/* find next-hop ipv4 address */
	strcpy(sys_cmd, "ip route get to ");
	strcat(sys_cmd, nic->dst_ip_addr_str);
	strcat(sys_cmd, " oif ");
	strcat(sys_cmd, nic->ifname);
	cmd_stream = popen(sys_cmd, "r");
	if (cmd_stream == NULL) {
		UET_API_PRINT_ERRNO("popen");
		UET_API_ERR("Error getting next-hop IP address");
		return -EIO;
	}
	for (i = 0; i < INET_ADDRSTRLEN; i++) {
		nic->nh_ip_addr_str[i] = getc(cmd_stream);
		if (isspace((int)nic->nh_ip_addr_str[i])) {
			nic->nh_ip_addr_str[i] = '\0';
			break;
		}
	}
	if (i == INET_ADDRSTRLEN) {
		UET_API_ERR("Error parsing next-hop IP address");
		pclose(cmd_stream);
		return -EIO;
	}
	inet_pton(AF_INET, nic->nh_ip_addr_str, &nh_ipv4);
	pclose(cmd_stream);

	/* an operator-configured entry is the answer */
	if (uet_nic_neigh_lookup(nic->ifname, nic->nh_ip_addr_str, false,
				 true, mac) == 1) {
		printf("Next-Hop Address Resolution\n");
		printf("  Destination IPv4 Addr: %s\n", nic->dst_ip_addr_str);
		printf("  Next-Hop IPv4 Addr:    %s (permanent)\n",
		       nic->nh_ip_addr_str);
		printf("  Next-Hop MAC Addr:     ");
		uet_print_mac_addr(mac);
		return 0;
	}

	uet_nic_neigh_probe(nic->ifname, nic->nh_ip_addr_str, false);

	/* read next-hop mac address from arp cache */
	memset(&areq, 0, sizeof(areq));
	sin = (struct sockaddr_in *)&areq.arp_pa;
	sin->sin_family = AF_INET;
	sin->sin_port = nic->uet_ipproto;
	sin->sin_addr = nh_ipv4;
	sin = (struct sockaddr_in *)&areq.arp_ha;
	sin->sin_family = ARPHRD_ETHER;
	strcpy(areq.arp_dev, nic->ifname);
	if (ioctl(sock_fd, SIOCGARP, (caddr_t)&areq) < 0) {
		UET_API_PRINT_ERRNO("socket ioctl");
		UET_API_ERR("Error getting ARP entry");
		return -EIO;
	}
	memcpy(mac, areq.arp_ha.sa_data, ETH_ALEN);

	rc = 0;
	memset(invalid_mac, 0, ETH_ALEN);
	if (memcmp(mac, invalid_mac, ETH_ALEN) == 0) {
		UET_API_ERR("Unable to resolve next-hop MAC addr");
		rc = -ENETUNREACH;
	}

	printf("Next-Hop Address Resolution\n");
	printf("  Destination IPv4 Addr: %s\n", nic->dst_ip_addr_str);
	printf("  Next-Hop IPv4 Addr:    %s\n", nic->nh_ip_addr_str);
	printf("  Next-Hop MAC Addr:     ");
	uet_print_mac_addr(mac);

	return rc;
}

/* resolve next-hop info for ipv6 destination address */
int uet_nic_resolve_ipv6_nh(struct uet_nic *nic,
			    const uint8_t *dst_ip6,
			    uint8_t *mac)
{
	char sys_cmd[UET_MAX_SYS_CMD_OCTETS];
	char line[256];
	int i, rc;
	FILE *cmd_stream;
	uint8_t invalid_mac[ETH_ALEN];

	/* convert ipv6 addr to string */
	inet_ntop(AF_INET6, dst_ip6, nic->dst_ip_addr_str, INET6_ADDRSTRLEN);

	/* our own address for loopback, see the IPv4 path above */
	if (nic->has_ipv6 && (memcmp(dst_ip6, nic->ipv6_addr, 16) == 0)) {
		memcpy(mac, nic->mac_addr, ETH_ALEN);
		strncpy(nic->nh_ip_addr_str, nic->dst_ip_addr_str,
			INET6_ADDRSTRLEN - 1);
		nic->nh_ip_addr_str[INET6_ADDRSTRLEN - 1] = '\0';

		printf("Next-Hop Address Resolution\n");
		printf("  Destination IPv6 Addr: %s\n", nic->dst_ip_addr_str);
		printf("  Next-Hop IPv6 Addr:    %s (loopback)\n",
		       nic->nh_ip_addr_str);
		printf("  Next-Hop MAC Addr:     ");
		uet_print_mac_addr(mac);

		return 0;
	}

	/* find next-hop ipv6 address using ip -6 route get */
	snprintf(sys_cmd, sizeof(sys_cmd),
		 "ip -6 route get %s oif %s 2>/dev/null | head -1",
		 nic->dst_ip_addr_str, nic->ifname);
	cmd_stream = popen(sys_cmd, "r");
	if (cmd_stream == NULL) {
		UET_API_PRINT_ERRNO("popen");
		UET_API_ERR("Error getting next-hop IPv6 address");
		return -EIO;
	}

	/* parse: "<dst> from <src> via <nexthop> ..." or "<dst> from <src> dev ..." */
	memset(line, 0, sizeof(line));
	if (fgets(line, sizeof(line), cmd_stream) == NULL) {
		UET_API_ERR("Error reading route output");
		pclose(cmd_stream);
		return -EIO;
	}
	pclose(cmd_stream);

	/* look for "via <nexthop>" in output, otherwise use dst as nexthop */
	char *via = strstr(line, " via ");
	if (via) {
		via += 5; /* skip " via " */
		for (i = 0; i < INET6_ADDRSTRLEN - 1 && via[i] && !isspace(via[i]); i++)
			nic->nh_ip_addr_str[i] = via[i];
		nic->nh_ip_addr_str[i] = '\0';
	} else {
		/* on-link destination, next-hop is the destination itself */
		strncpy(nic->nh_ip_addr_str, nic->dst_ip_addr_str,
			INET6_ADDRSTRLEN);
	}

	/* an operator-configured entry is the answer */
	if (uet_nic_neigh_lookup(nic->ifname, nic->nh_ip_addr_str, true,
				 true, mac) == 1) {
		printf("Next-Hop Address Resolution\n");
		printf("  Destination IPv6 Addr: %s\n", nic->dst_ip_addr_str);
		printf("  Next-Hop IPv6 Addr:    %s (permanent)\n",
		       nic->nh_ip_addr_str);
		printf("  Next-Hop MAC Addr:     ");
		uet_print_mac_addr(mac);
		return 0;
	}

	uet_nic_neigh_probe(nic->ifname, nic->nh_ip_addr_str, true);

	/* read next-hop mac address from neighbor cache */
	snprintf(sys_cmd, sizeof(sys_cmd),
		 "ip -6 neigh show %s dev %s 2>/dev/null",
		 nic->nh_ip_addr_str, nic->ifname);
	cmd_stream = popen(sys_cmd, "r");
	if (cmd_stream == NULL) {
		UET_API_PRINT_ERRNO("popen");
		UET_API_ERR("Error reading neighbor cache");
		return -EIO;
	}

	/* parse: "<addr> dev <if> lladdr <mac> ..." */
	memset(line, 0, sizeof(line));
	memset(mac, 0, ETH_ALEN);
	if (fgets(line, sizeof(line), cmd_stream) != NULL) {
		char *lladdr = strstr(line, "lladdr ");
		if (lladdr) {
			lladdr += 7; /* skip "lladdr " */
			/* parse MAC address aa:bb:cc:dd:ee:ff */
			unsigned int m[6];
			if (sscanf(lladdr, "%x:%x:%x:%x:%x:%x",
				   &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
				for (i = 0; i < 6; i++)
					mac[i] = (uint8_t)m[i];
			}
		}
	}
	pclose(cmd_stream);

	rc = 0;
	memset(invalid_mac, 0, ETH_ALEN);
	if (memcmp(mac, invalid_mac, ETH_ALEN) == 0) {
		UET_API_ERR("Unable to resolve next-hop MAC addr for IPv6");
		rc = -ENETUNREACH;
	}

	printf("Next-Hop Address Resolution\n");
	printf("  Destination IPv6 Addr: %s\n", nic->dst_ip_addr_str);
	printf("  Next-Hop IPv6 Addr:    %s\n", nic->nh_ip_addr_str);
	printf("  Next-Hop MAC Addr:     ");
	uet_print_mac_addr(mac);

	return rc;
}

/*
 * Loopback. A frame whose destination is this device's own MAC is
 * delivered to this device's loopback channel rather than transmitted.
 *
 * Handled at the shim rather than in either backend, so raw sockets and
 * XDP behave the same way and neither has to know about it.
 *
 * The queue is bounded. A device that loops back faster than it receives
 * would otherwise grow it without limit, and dropping is what the wire
 * would do to a peer that stopped reading.
 */

#define UET_NIC_LO_MAX_DEPTH 1024

bool uet_nic_is_loopback(const struct uet_nic *nic,
			 const void *pkt)
{
	const struct ethhdr *eth = pkt;

	if ((nic == NULL) || (pkt == NULL))
		return false;

	return (memcmp(eth->h_dest, nic->mac_addr, ETH_ALEN) == 0);
}

int uet_nic_loopback_tx(struct uet_nic *nic,
			const void *pkt,
			size_t len)
{
	struct uet_nic_lo_pkt *lo;

	if (nic->lo_depth >= UET_NIC_LO_MAX_DEPTH)
		return -ENOBUFS;

	lo = malloc(sizeof(*lo) + len);
	if (lo == NULL)
		return -ENOMEM;

	lo->next = NULL;
	lo->len  = len;
	memcpy(lo->data, pkt, len);

	if (nic->lo_tail != NULL)
		nic->lo_tail->next = lo;
	else
		nic->lo_head = lo;

	nic->lo_tail = lo;
	nic->lo_depth++;

	return 0;
}

/* returns 1 when a frame was delivered, 0 when there is none */
int uet_nic_loopback_rx(struct uet_nic *nic,
			void *pkt,
			size_t buf_size,
			size_t *rx_len)
{
	struct uet_nic_lo_pkt *lo = nic->lo_head;

	if (lo == NULL)
		return 0;

	nic->lo_head = lo->next;

	if (nic->lo_head == NULL)
		nic->lo_tail = NULL;

	nic->lo_depth--;

	/* a frame too big for the caller's buffer is dropped */
	if (lo->len > buf_size) {
		free(lo);
		return 0;
	}

	memcpy(pkt, lo->data, lo->len);
	*rx_len = lo->len;

	free(lo);

	return 1;
}

void uet_nic_loopback_drain(struct uet_nic *nic)
{
	struct uet_nic_lo_pkt *lo;

	if (nic == NULL)
		return;

	while ((lo = nic->lo_head) != NULL) {
		nic->lo_head = lo->next;
		free(lo);
	}

	nic->lo_tail = NULL;
	nic->lo_depth = 0;
}

int uet_nic_getinfo(struct uet_nic *nic,
		    struct uet_nic_info *nic_info)
{
	if (!nic || !nic_info)
		assert(0);

	memset(nic_info, 0, sizeof(struct uet_nic_info));

	return nic->nic_getinfo(nic, nic_info);
}

/* Raw Socket NIC protocol callbacks */
extern int nic_rawsock_getinfo(struct uet_nic *nic,
			       struct uet_nic_info *nic_info);
extern int nic_rawsock_tx_pkt(struct uet_nic *nic,
			      void *pkt,
			      void *iphdr,
			      size_t pkt_size);
extern int nic_rawsock_rx_pkt(struct uet_nic *nic,
			      void *pkt,
			      size_t pkt_buf_size,
			      size_t *rx_pkt_size);
extern int nic_rawsock_rx_poll(struct uet_nic *nic);
extern void nic_rawsock_finalize(struct uet_nic *nic);
extern int nic_rawsock_initialize(struct uet_nic *nic);

#if ENABLE_XDP
/* XDP NIC protocol callbacks */
extern int nic_xdp_getinfo(struct uet_nic *nic,
			   struct uet_nic_info *nic_info);
extern int nic_xdp_tx_pkt(struct uet_nic *nic,
			  void *pkt,
			  void *iphdr,
			  size_t pkt_size);
extern int nic_xdp_rx_pkt(struct uet_nic *nic,
			  void *pkt,
			  size_t pkt_buf_size,
			  size_t *rx_pkt_size);
extern int nic_xdp_rx_poll(struct uet_nic *nic);
extern void nic_xdp_finalize(struct uet_nic *nic);
extern int nic_xdp_initialize(struct uet_nic *nic);
#endif

#if ENABLE_VPP
/* VPP NIC protocol callbacks remain private to the shim implementation. */
extern int nic_vpp_getinfo(struct uet_nic *nic,
			   struct uet_nic_info *nic_info);
extern int nic_vpp_configure_info(struct uet_nic *nic,
				  struct fi_info *info);
extern int nic_vpp_ep_register(struct uet_nic *nic,
			       struct uet_ep *ep, void **context);
extern void nic_vpp_ep_unregister(struct uet_nic *nic, void *context);
extern int nic_vpp_get_nh(struct uet_nic *nic, const struct uet_fa *fa,
			  bool is_ipv6, uint8_t *mac);
extern int nic_vpp_tx_pkt(struct uet_nic *nic, void *pkt, void *iphdr,
			  size_t pkt_size);
extern int nic_vpp_rx_pkt(struct uet_nic *nic, void *pkt,
			  size_t pkt_buf_size, size_t *rx_pkt_size);
extern int nic_vpp_rx_poll(struct uet_nic *nic);
extern void nic_vpp_finalize(struct uet_nic *nic);
extern int nic_vpp_initialize(struct uet_nic *nic);
#endif

/* init nic resources */
int uet_nic_initialize(struct uet_nic *nic)
{
	char *nic_shim;

	/* get interface name from environment variable */
	nic_shim = getenv(UET_NIC_SHIM);

#if ENABLE_VPP
	/* The dedicated VPP build uses VPP unless explicitly overridden. */
	if (nic_shim == NULL)
		nic_shim = "vpp";
#elif ENABLE_XDP
	/* for an XDP build, make its shim the default */
	if (nic_shim == NULL)
		nic_shim = "xdp";
#endif

	if ((nic_shim == NULL) || (strcmp(nic_shim, "rawsock") == 0)) {
		nic->nic_getinfo     = nic_rawsock_getinfo;
		nic->nic_tx_pkt      = nic_rawsock_tx_pkt;
		nic->nic_rx_pkt      = nic_rawsock_rx_pkt;
		nic->nic_rx_poll     = nic_rawsock_rx_poll;
		nic->nic_finalize    = nic_rawsock_finalize;
		nic->nic_initialize  = nic_rawsock_initialize;
#if ENABLE_XDP
	} else if (strcmp(nic_shim, "xdp") == 0) {
		nic->nic_getinfo     = nic_xdp_getinfo;
		nic->nic_tx_pkt      = nic_xdp_tx_pkt;
		nic->nic_rx_pkt      = nic_xdp_rx_pkt;
		nic->nic_rx_poll     = nic_xdp_rx_poll;
		nic->nic_finalize    = nic_xdp_finalize;
		nic->nic_initialize  = nic_xdp_initialize;
#endif
#if ENABLE_VPP
	} else if (strcmp(nic_shim, "vpp") == 0) {
		nic->nic_getinfo       = nic_vpp_getinfo;
		nic->nic_configure_info = nic_vpp_configure_info;
		nic->nic_ep_register   = nic_vpp_ep_register;
		nic->nic_ep_unregister = nic_vpp_ep_unregister;
		nic->nic_get_nh        = nic_vpp_get_nh;
		nic->nic_tx_pkt        = nic_vpp_tx_pkt;
		nic->nic_rx_pkt        = nic_vpp_rx_pkt;
		nic->nic_rx_poll       = nic_vpp_rx_poll;
		nic->nic_finalize      = nic_vpp_finalize;
		nic->nic_initialize    = nic_vpp_initialize;
#endif
	} else {
		UET_API_ERR("invalid UET_NIC_SHIM environment variable");
		return -ENODEV;
	}

	return nic->nic_initialize(nic);
}

