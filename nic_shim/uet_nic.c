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

#include "uet_api_private.h"
#include "uet_nic.h"

/* helper to get IPv4 address of interface */
int uet_nic_get_ipv4_addr(int sock_fd,
			  struct ifreq *ifr,
			  uint32_t *ipv4_addr,
			  char *ipv4_addr_str)
{
	char *ip;

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

	/* delete any entry for next-hop already in arp cache */
	strcpy(sys_cmd, "arp -d ");
	strcat(sys_cmd, nic->nh_ip_addr_str);
	strcat(sys_cmd, " 2> /dev/null 1> /dev/null");
	system(sys_cmd);

	/* ping next hop to load arp cache using our interface */
	strcpy(sys_cmd, "ping -c 1 -I ");
	strcat(sys_cmd, nic->ifname);
	strcat(sys_cmd, " ");
	strcat(sys_cmd, nic->nh_ip_addr_str);
	strcat(sys_cmd, " 2> /dev/null 1> /dev/null");
	system(sys_cmd);

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

	/* delete any entry for next-hop already in neighbor cache */
	snprintf(sys_cmd, sizeof(sys_cmd),
		 "ip -6 neigh del %s dev %s 2>/dev/null 1>/dev/null",
		 nic->nh_ip_addr_str, nic->ifname);
	system(sys_cmd);

	/* ping6 next hop to trigger NDP */
	snprintf(sys_cmd, sizeof(sys_cmd),
		 "ping -6 -c 1 -I %s %s 2>/dev/null 1>/dev/null",
		 nic->ifname, nic->nh_ip_addr_str);
	system(sys_cmd);

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

