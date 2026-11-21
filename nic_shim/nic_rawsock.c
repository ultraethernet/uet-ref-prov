/*
 * Copyright (c) 2024,2025,2026 Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* NIC Interface using Raw Sockets */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>

#include "uet_api.h"
#include "uet_nic.h"
#include "uet_api_private.h"

#define UET_NETWORK_TYPE_RAWSOCK "Ethernet(rawsock)"

struct rawsock_data {
	struct pollfd sock_fd;             /* socket file descriptor */
	struct ifreq ifr;	  /* socket interface request struct */
	struct sockaddr_ll sadr;           /* link-level socket addr */
};

/* get nic info */
int nic_rawsock_getinfo(struct uet_nic *nic,
			struct uet_nic_info *nic_info)
{
	struct rawsock_data *rdata =
		(struct rawsock_data *)nic->nic_priv_data;

	/* get interface flags */
	if ((ioctl(rdata->sock_fd.fd, SIOCGIFFLAGS, &rdata->ifr)) < 0) {
		UET_API_PRINT_ERRNO("socket ioctl");
		UET_API_ERR("Error getting interface flags");
		return -ENODEV;
	}

	nic_info->ifname = nic->ifname;
	nic_info->network_type = nic->network_type;
	nic_info->mac_addr_str = nic->mac_addr_str;
	nic_info->mtu = nic->mtu;

	nic_info->link_state =
		(rdata->ifr.ifr_flags & IFF_UP)
			? UET_NIC_LINK_STATE_UP : UET_NIC_LINK_STATE_DOWN;

	return 0;
}

/* transmit a packet */
int nic_rawsock_tx_pkt(struct uet_nic *nic,
		       void *pkt,
		       void *iphdr,
		       size_t pkt_size)
{
	struct ethhdr *eth = (struct ethhdr *)pkt;
	struct rawsock_data *rdata =
		(struct rawsock_data *)nic->nic_priv_data;
	size_t len;

	struct sockaddr_ll destination = rdata->sadr;

	memcpy(destination.sll_addr, eth->h_dest, ETH_ALEN);

#ifdef UET_NIC_DEBUG_HEXDUMP
	uet_pkt_hex_dump(pkt, pkt_size, 0, true);
#endif

	len = sendto(rdata->sock_fd.fd, pkt, pkt_size, 0,
		     (const struct sockaddr *)&destination,
		     sizeof(destination));
	if (len != pkt_size) {
		if (len == -1)
			UET_API_PRINT_ERRNO("sendto");
		else
			UET_API_ERR("Error transmitting packet, "
				    "sent %ld of %ld bytes",
				    len, pkt_size);
		return -EIO;
	}

	return 0;
}

/* receive a packet */
int nic_rawsock_rx_pkt(struct uet_nic *nic,
		       void *pkt,
		       size_t pkt_buf_size,
		       size_t *rx_pkt_size)
{
	struct rawsock_data *rdata =
		(struct rawsock_data *)nic->nic_priv_data;
	size_t len;

	len = recvfrom(rdata->sock_fd.fd, pkt, pkt_buf_size, 0, NULL, NULL);
	if (len == -1) {
		UET_API_PRINT_ERRNO("recvfrom");
		return -EIO;
	} else if (len > pkt_buf_size) {
		UET_API_DEBUG("Error receiving packet: too big: "
			      "%ld bytes", len);
		return 0;
	} else if (len < nic->min_pkt_size) {
		UET_API_DEBUG("Error receiving packet: too small: "
			      "%ld bytes", len);
		return 0;
	}

#ifdef UET_NIC_DEBUG_HEXDUMP
	uet_pkt_hex_dump(pkt, len, 0, false);
#endif

	*rx_pkt_size = len;
	return 1;
}

/* poll to determine if rx packet is available */
int nic_rawsock_rx_poll(struct uet_nic *nic)
{
	struct rawsock_data *rdata =
		(struct rawsock_data *)nic->nic_priv_data;
	int ret;

	/* check if packet is available */
	ret = poll(&rdata->sock_fd, 1, 0);
	switch (ret) {
	case 0:
		return 0;
	case 1:
		if (rdata->sock_fd.revents & POLLIN)
			return 1;
		return 0;
	case -1:
		UET_API_PRINT_ERRNO("poll");
		return -EIO;
	default:
		break;
	}

	UET_API_ERR("unexpected val from poll: %d", ret);
	return -EIO;
}

/* free nic resources */
void nic_rawsock_finalize(struct uet_nic *nic)
{
	struct rawsock_data *rdata =
		(struct rawsock_data *)nic->nic_priv_data;

	if (!rdata)
		return;

	if (rdata->sock_fd.fd != -1) {
		close(rdata->sock_fd.fd);
		rdata->sock_fd.fd = -1;
	}

	free(rdata);
	nic->nic_priv_data = NULL;
}

/* init nic resources */
int nic_rawsock_initialize(struct uet_nic *nic)
{
	struct rawsock_data *rdata = NULL;
	int rc;
	char *ifname;

	nic->min_pkt_size = UET_MIN_PKT_SIZE;
	nic->l2_hdr_size = sizeof(struct ethhdr);
	nic->min_ip_pkt_size = (nic->min_pkt_size - nic->l2_hdr_size);

	rdata = calloc(1, sizeof(struct rawsock_data));
	if (rdata == NULL) {
		UET_API_ERR("ERROR: Failed to alloc RAWSOCK priv data");
		return -ENOMEM;
	}

	nic->nic_priv_data = (void *)rdata;
	rdata->sock_fd.fd = -1;

	strncpy(nic->network_type, UET_NETWORK_TYPE_RAWSOCK,
		UET_NET_TYPE_SIZE);

	/* get interface name from environment variable */
	ifname = getenv(UET_IFNAME);
	if (ifname == NULL) {
		UET_API_ERR("err reading UET_IFNAME environment variable");
		rc = -ENODEV;
		goto err_return;
	}

	strncpy(nic->ifname, ifname, IFNAMSIZ);

	/* open transport raw socket - use ETH_P_ALL to receive both v4/v6 */
	rdata->sock_fd.fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (rdata->sock_fd.fd == -1) {
		UET_API_PRINT_ERRNO("socket");
		rc = -EIO;
		goto err_return;
	}

	rdata->sock_fd.events = POLLIN;
	nic->sock_fd = rdata->sock_fd.fd;

	/* get index of interface */
	strcpy(rdata->ifr.ifr_name, nic->ifname);
	if ((ioctl(rdata->sock_fd.fd, SIOCGIFINDEX, &rdata->ifr)) < 0) {
		UET_API_PRINT_ERRNO("socket ioctl");
		UET_API_ERR("bad interface device name");
		rc = -ENODEV;
		goto err_return;
	}

	/* init link-level socket addr struct and bind to socket */
	rdata->sadr.sll_family   = AF_PACKET;
	rdata->sadr.sll_ifindex  = rdata->ifr.ifr_ifindex;
	rdata->sadr.sll_halen    = ETH_ALEN;
	rdata->sadr.sll_protocol = htons(ETH_P_ALL);

	if (bind(rdata->sock_fd.fd, (struct sockaddr *) &rdata->sadr,
		 sizeof(struct sockaddr_ll)) < 0) {
		UET_API_PRINT_ERRNO("socket bind");
		rc = -EIO;
		goto err_return;
	}

	/* get IPv4 address of interface (optional) */
	nic->has_ipv4 = (uet_nic_get_ipv4_addr(rdata->sock_fd.fd,
					       &rdata->ifr,
					       &nic->ipv4_addr,
					       nic->ipv4_addr_str) == 0);

	/* get IPv6 address of interface (optional) */
	nic->has_ipv6 = (uet_nic_get_ipv6_addr(nic->ifname,
					       nic->ipv6_addr,
					       nic->ipv6_addr_str) == 0);

	/* dual-stack: both families are kept, require at least one address */
	if (!nic->has_ipv4 && !nic->has_ipv6) {
		UET_API_ERR("Error: interface has no IPv4 or IPv6 address");
		rc = -ENODEV;
		goto err_return;
	}

	/* get mac address of interface */
	if ((ioctl(rdata->sock_fd.fd, SIOCGIFHWADDR, &rdata->ifr)) < 0) {
		UET_API_PRINT_ERRNO("socket ioctl");
		UET_API_ERR("Error getting MAC addr of local device");
		rc = -EIO;
		goto err_return;
	}
	memcpy(nic->mac_addr, rdata->ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	uet_mac_addr_to_str(nic->mac_addr_str, nic->mac_addr);

	/* get MTU of interface */
	if ((ioctl(rdata->sock_fd.fd, SIOCGIFMTU, &rdata->ifr)) < 0) {
		UET_API_PRINT_ERRNO("socket ioctl");
		UET_API_ERR("Error getting MTU of local device");
		goto err_return;
	}
	nic->mtu = (size_t)rdata->ifr.ifr_mtu;
	nic->max_pkt_size = (nic->mtu + nic->l2_hdr_size);

	return 0;

err_return:
	nic_rawsock_finalize(nic);
	return rc;
}

