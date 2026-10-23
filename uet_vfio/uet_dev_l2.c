/*
 * Copyright (c) 2026 Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/*
 * UET reference device model - the L2 rings
 *
 * Ordinary Ethernet frames between the guest's netdev and the wire. The
 * device demultiplexes its interface: UET traffic goes to the uet instance
 * and everything else (i.e., ARP, ICMP, neighbour discovery, DHCP, etc.)
 * crosses these two rings.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <linux/if_ether.h>

#include "uet_pkt_hdr.h"
#include "uet_dev_priv.h"
#include "uet_dev_l2.h"

/* Drop UET packets. UET is carried either directly over IP with its own
 * protocol number, or over UDP on its own port. Both of these are reported
 * to the guest in BAR0's PORT_PROTO register. Anything else (i.e., ARP, ICMP,
 * neighbour discovery, DHCP, etc.) is consumed and will be sent to the
 * guest's netdev.
 */
static bool uet_dev_frame_is_uet(const struct uet_dev *dev,
				 const uint8_t *frame,
				 size_t len)
{
	uint16_t uet_port = (uint16_t)(dev->port_proto & 0xffff);
	uint8_t uet_proto = (uint8_t)((dev->port_proto >> 16) & 0xff);
	size_t off = sizeof(struct ethhdr);
	uint16_t ethertype;
	uint8_t nexthdr;
	uint16_t dport;
	size_t ihl;

	if (len < sizeof(struct ethhdr))
		return false;

	ethertype = (uint16_t)((frame[12] << 8) | frame[13]);

	if (ethertype == ETH_P_IP) {
		if (len < (off + 20))
			return false;

		ihl = ((size_t)(frame[off] & 0x0f) * 4);
		if ((ihl < 20) || (len < (off + ihl)))
			return false;

		nexthdr = frame[off + 9];
		off += ihl;
	} else if (ethertype == ETH_P_IPV6) {
		if (len < (off + 40))
			return false;

		nexthdr = frame[off + 6];
		off += 40;
	} else {
		return false;
	}

	if (nexthdr == uet_proto)
		return true;

	if ((nexthdr == IPPROTO_UDP) && (len >= (off + 4))) {
		dport = (uint16_t)((frame[off + 2] << 8) | frame[off + 3]);

		if (dport == uet_port)
			return true;
	}

	return false;
}

/* read one descriptor out of a ring, ring_lock must be held */
static int uet_dev_desc_read(struct uet_dev *dev,
			     uint64_t base,
			     uint32_t entries,
			     uint32_t index,
			     struct uet_dev_desc *desc)
{
	uint64_t addr;

	if (dev->backend.dma_read == NULL)
		return -1;

	addr = base + ((uint64_t)(index % entries) * sizeof(*desc));

	return dev->backend.dma_read(dev->backend.ctx, addr, desc,
				     sizeof(*desc));
}

/* Hand one received packet to the guest, consuming a posted RX buffer.
 * Returns true if the guest was given the frame.
 */
static bool uet_dev_rx_deliver(struct uet_dev *dev,
			       const uint8_t *frame,
			       size_t len)
{
	struct uet_dev_desc desc;
	uint64_t slot;
	bool ok = false;

	pthread_mutex_lock(&dev->ring_lock);

	if (!(dev->rx_ring_ctrl & UET_DEV_RING_CTRL_ENABLE) ||
	    (dev->rx_ring_entries == 0) || (dev->rx_cons == dev->rx_prod)) {
		dev->rx_dropped++;
		goto out;
	}

	if (uet_dev_desc_read(dev, dev->rx_ring_base, dev->rx_ring_entries,
			      dev->rx_cons, &desc) != 0) {
		dev->rx_dropped++;
		dev->rx_cons++;
		goto out;
	}

	/* a frame that does not fit in the posted buffer is dropped */
	if ((desc.len < len) || (dev->backend.dma_write == NULL) ||
	    (dev->backend.dma_write(dev->backend.ctx, desc.addr, frame,
				    len) != 0)) {
		dev->rx_dropped++;
		dev->rx_cons++;
		goto out;
	}

	desc.len = (uint32_t)len;
	desc.flags |= UET_DEV_DESC_DONE;

	slot = (dev->rx_ring_base +
		((uint64_t)(dev->rx_cons % dev->rx_ring_entries) *
		 sizeof(desc)));

	if (dev->backend.dma_write(dev->backend.ctx, slot, &desc,
				   sizeof(desc)) != 0) {
		dev->rx_dropped++;
		dev->rx_cons++;
		goto out;
	}

	dev->rx_cons++;
	dev->rx_frames++;
	ok = true;

out:
	pthread_mutex_unlock(&dev->ring_lock);

	if (ok && (dev->backend.raise_irq != NULL)) {
		dev->backend.raise_irq(dev->backend.ctx, UET_DEV_RX_VECTOR);
		dev->irqs_fired++;
	}

	return ok;
}

/* The transport and guest netdev may use different host interfaces. With
 * VPP, this socket can attach to a veth peer of the Linux control gateway.
 */
int uet_dev_l2_open(struct uet_dev *dev)
{
	const char *ifname = getenv("UET_DEV_L2_IFNAME");
	struct sockaddr_ll sll;
	int fd, error;

	dev->l2_fd = -1;
	if (ifname == NULL)
		ifname = dev->ifname;

	/* A VPP channel name is not a Linux netdev. Require its L2 endpoint
	 * explicitly so a typo cannot send control traffic elsewhere.
	 */
	if (dev->nic_shim == UET_DEV_NIC_SHIM_VPP &&
	    (getenv("UET_DEV_L2_IFNAME") == NULL || ifname[0] == '\0')) {
		fprintf(stderr,
			"uet_dev: VPP requires UET_DEV_L2_IFNAME (Linux guest L2 endpoint)\n");
		return -EINVAL;
	}
	if (ifname[0] == '\0')
		return 0;

	fd = socket(AF_PACKET, (SOCK_RAW | SOCK_NONBLOCK), htons(ETH_P_ALL));
	if (fd < 0) {
		error = errno;
		fprintf(stderr, "uet_dev: L2 socket: %s\n", strerror(error));
		return -error;
	}

	dev->l2_ifindex = (int)if_nametoindex(ifname);
	if (dev->l2_ifindex == 0) {
		error = errno ? errno : ENODEV;
		fprintf(stderr, "uet_dev: if_nametoindex(%s): %s\n",
			ifname, strerror(error));
		close(fd);
		return -error;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = dev->l2_ifindex;

	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		error = errno;
		fprintf(stderr, "uet_dev: L2 bind: %s\n", strerror(error));
		close(fd);
		return -error;
	}

	dev->l2_fd = fd;
	return 0;
}

/* close the L2 socket */
void uet_dev_l2_close(struct uet_dev *dev)
{
	if (dev->l2_fd >= 0) {
		close(dev->l2_fd);
		dev->l2_fd = -1;
	}
}

/* Drain whatever packets the L2 socket has. Runs in the progress thread
 * which is already sweeping the uet-ref-prov instance. So the guest's netdev
 * and the UET datapath share one thread.
 */
void uet_dev_l2_poll(struct uet_dev *dev)
{
	uint8_t frame[UET_DEV_MAX_FRAME];
	unsigned int budget = 32;
	struct sockaddr_ll sll;
	socklen_t slen = sizeof(sll);
	ssize_t n;

	if (dev->l2_fd < 0)
		return;

	while (budget-- > 0) {
		n = recvfrom(dev->l2_fd, frame, sizeof(frame), 0,
			     (struct sockaddr *)&sll, &slen);
		if (n <= 0)
			return;

		/* our own transmissions come back on an ETH_P_ALL socket */
		if (sll.sll_pkttype == PACKET_OUTGOING)
			continue;

		if (uet_dev_frame_is_uet(dev, frame, (size_t)n)) {
			dev->rx_uet_frames++;
			continue;
		}

		uet_dev_rx_deliver(dev, frame, (size_t)n);
	}
}

/* Drain the TX ring sending a packet for every slot the guest has produced
 * and the device has not yet consumed. Called from the doorbell write, with
 * ring_lock held.
 */
void uet_dev_tx_drain_locked(struct uet_dev *dev)
{
	uint8_t frame[UET_DEV_MAX_FRAME];
	bool sent = false;
	struct uet_dev_desc desc;
	ssize_t n;

	if (!(dev->tx_ring_ctrl & UET_DEV_RING_CTRL_ENABLE) ||
	    (dev->tx_ring_entries == 0))
		return;

	while (dev->tx_cons != dev->tx_prod) {
		if (uet_dev_desc_read(dev, dev->tx_ring_base,
				      dev->tx_ring_entries,
				      dev->tx_cons, &desc) != 0) {
			dev->tx_errors++;
			dev->tx_cons++;
			continue;
		}

		if ((desc.len == 0) || (desc.len > sizeof(frame)) ||
		    (dev->backend.dma_read(dev->backend.ctx, desc.addr,
					   frame, desc.len) != 0)) {
			dev->tx_errors++;
			dev->tx_cons++;
			continue;
		}

		n = send(dev->l2_fd, frame, desc.len, 0);
		if (n != (ssize_t)desc.len)
			dev->tx_errors++;
		else
			dev->tx_frames++;

		dev->tx_cons++;
		sent = true;
	}

	if (sent && (dev->backend.raise_irq != NULL)) {
		dev->backend.raise_irq(dev->backend.ctx, UET_DEV_TX_VECTOR);
		dev->irqs_fired++;
	}
}

