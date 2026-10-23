/*
 * Copyright (c) 2026 Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/*
 * UET reference device model - the register interface
 *
 * What the guest sees. BAR0 is a snapshot of live device state, BAR2 is the
 * kernel's control region, and BAR3 is the userspace doorbell page. The
 * configuration those registers report is read here as well.
 *
 * uet_vfio/REGISTERS.md documents every offset.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "uet_pkt_hdr.h"
#include "uet_dev_priv.h"
#include "uet_dev_regs.h"
#include "uet_dev_objs.h"
#include "uet_dev_admin.h"
#include "uet_dev_l2.h"

/* get an environment variable 32b value, or default */
static uint32_t uet_dev_env_u32(const char *name,
				uint32_t dflt)
{
	const char *v = getenv(name);
	return (v != NULL) ? (uint32_t)strtoul(v, NULL, 0) : dflt;
}

/* Resolve what the uet-ref-prov instance was instantiated with. */
void uet_dev_read_config(struct uet_dev *dev)
{
	const char *pds = getenv("UET_PDS");
	const char *sec = getenv("UET_SEC_MODE");
	const char *shim = getenv("UET_NIC_SHIM");
	const char *ifname = getenv("UET_IFNAME");

	dev->pds_mode = ((pds != NULL) && (strcmp(pds, "sng") == 0))
		? UET_DEV_PDS_MODE_SNG : UET_DEV_PDS_MODE_PDS;

	dev->sec_mode = UET_DEV_SEC_MODE_NONE;
	if (sec != NULL) {
		if (strcmp(sec, "direct") == 0)
			dev->sec_mode = UET_DEV_SEC_MODE_DIRECT;
		else if (strcmp(sec, "cluster") == 0)
			dev->sec_mode = UET_DEV_SEC_MODE_CLUSTER;
		else if (strcmp(sec, "server") == 0)
			dev->sec_mode = UET_DEV_SEC_MODE_SERVER;
	}

	dev->nic_shim = UET_DEV_NIC_SHIM_RAWSOCK;
	if (shim != NULL) {
		if (strcmp(shim, "xdp") == 0)
			dev->nic_shim = UET_DEV_NIC_SHIM_XDP;
		else if (strcmp(shim, "vpp") == 0)
			dev->nic_shim = UET_DEV_NIC_SHIM_VPP;
	}

	/* A starting value only. Once the domain exists this is replaced
	 * with what the library actually uses.
	 */
	dev->max_payload = UET_DEFAULT_MAX_PAYLOAD_LEN;

	/* Fixed by the implementation rather than by the instance. There is
	 * nothing to revise once the domain exists.
	 */
	dev->max_msg_size = (uint32_t)uet_max_msg_size();

	/* A starting value, revised once the domain exists. The library is
	 * what knows which encapsulation it transmits.
	 */
	dev->gid_type = UET_DEV_GID_TYPE_IP;

	dev->port_proto = ((uint32_t)UET_UDP_PORT |
			   ((uint32_t)UET_IPPROTO << 16));

	dev->max_tx_retries = uet_dev_env_u32("UET_PDS_MAX_TX_RETRIES", 0);
	dev->tx_timeout = uet_dev_env_u32("UET_PDS_TX_TIMEOUT", 0);
	dev->pkt_drop_thresh = uet_dev_env_u32("UET_PKT_DROP_THRESH", 0);
	dev->sec_ssi = uet_dev_env_u32("UET_SEC_SSI", 0);

	memset(dev->ifname, 0, sizeof(dev->ifname));
	if (ifname != NULL)
		strncpy(dev->ifname, ifname, sizeof(dev->ifname) - 1);

	if (dev->sec_mode != UET_DEV_SEC_MODE_NONE)
		dev->caps |= UET_DEV_CAP_SECURITY;

	if (getenv("UET_IMPAIRMENT_SHIM") != NULL)
		dev->caps |= UET_DEV_CAP_IMPAIRMENT;

	if (getenv("UET_FORCE_RUDI") != NULL)
		dev->caps |= UET_DEV_CAP_FORCE_RUDI;

	if (getenv("UET_FORCE_UUD") != NULL)
		dev->caps |= UET_DEV_CAP_FORCE_UUD;
}

/* Record the local address the instance came up with so the guest can see
 * which interface and address the device is actually attached to.
 */
void uet_dev_read_identity(struct uet_dev *dev)
{
	struct fi_info *info = dev->info;
	int i;

	if ((info == NULL) || (info->nic == NULL))
		return;

	if ((info->nic->link_attr != NULL) &&
	    (info->nic->link_attr->address != NULL)) {
		unsigned int m[6];

		if (sscanf(info->nic->link_attr->address,
			   "%x:%x:%x:%x:%x:%x",
			   &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
			for (i = 0; i < 6; i++)
				dev->mac[i] = (uint8_t)m[i];
		}
	}

	if (info->src_addr != NULL) {
		const struct uet_addr *ua = info->src_addr;

		if (ua->flags & UET_ADDR_IPV6) {
			dev->ip_ver = 6;
			/* v6 is already an octet array, in order */
			memcpy(dev->ipaddr, ua->fa.v6, 16);
		} else {
			/*
			 * fa.v4 is a uint32_t in host byte order, so its raw
			 * bytes are reversed on a little endian host. The
			 * register holds octets in address order, which is
			 * what a driver formatting an address expects.
			 */
			uint32_t be = htonl(ua->fa.v4);

			dev->ip_ver = 4;
			memcpy(dev->ipaddr, &be, 4);
		}
	}
}

/* a ring must be a power of two of slots, and not absurd */
static bool uet_dev_ring_entries_ok(uint32_t entries)
{
	return ((entries != 0) && (entries <= UET_DEV_RING_MAX_ENTRIES) &&
		((entries & (entries - 1)) == 0));
}

static uint32_t uet_dev_uptime_ms(const struct uet_dev *dev)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);

	return (uint32_t)(((now.tv_sec - dev->started.tv_sec) * 1000) +
			  ((now.tv_nsec - dev->started.tv_nsec) / 1000000));
}

/*
 * Build the whole region on demand. It is only 4KB and reads are rare.
 * Composing it in one place keeps the offsets in a single readable block
 * rather than scattered through a switch statement.
 */
static void uet_dev_bar0_snapshot(struct uet_dev *dev,
				  uint8_t *bar)
{
	uint64_t iters = dev->progress_iters;

#define PUT32(off, val) \
	do { \
		uint32_t _v = (uint32_t)(val); \
		memcpy(&bar[(off)], &_v, sizeof(_v)); \
	} while (0)

	memset(bar, 0, UET_DEV_BAR0_SIZE);

	PUT32(UET_DEV_REG_MAGIC, UET_DEV_MAGIC);
	PUT32(UET_DEV_REG_ABI_VERSION, UET_DEV_ABI_VERSION);
	PUT32(UET_DEV_REG_CAPS, dev->caps);
	PUT32(UET_DEV_REG_STATE, dev->state);

	PUT32(UET_DEV_REG_PDS_MODE, dev->pds_mode);
	PUT32(UET_DEV_REG_SEC_MODE, dev->sec_mode);
	PUT32(UET_DEV_REG_NIC_SHIM, dev->nic_shim);
	PUT32(UET_DEV_REG_MAX_PAYLOAD, dev->max_payload);
	PUT32(UET_DEV_REG_MAX_MSG_SIZE, dev->max_msg_size);
	PUT32(UET_DEV_REG_GID_TYPE, dev->gid_type);
	PUT32(UET_DEV_REG_PORT_PROTO, dev->port_proto);
	PUT32(UET_DEV_REG_MAX_TX_RETRIES, dev->max_tx_retries);
	PUT32(UET_DEV_REG_TX_TIMEOUT, dev->tx_timeout);
	PUT32(UET_DEV_REG_PKT_DROP_THRESH, dev->pkt_drop_thresh);
	PUT32(UET_DEV_REG_SEC_SSI, dev->sec_ssi);
	PUT32(UET_DEV_REG_IOV_LIMIT, dev->iov_limit);

	memcpy(&bar[UET_DEV_REG_IFNAME], dev->ifname, UET_DEV_IFNAME_LEN);
	memcpy(&bar[UET_DEV_REG_MAC_LO], &dev->mac[0], 4);
	PUT32(UET_DEV_REG_MAC_HI,
	      ((uint32_t)dev->mac[4] | ((uint32_t)dev->mac[5] << 8)));
	PUT32(UET_DEV_REG_IP_VER, dev->ip_ver);
	memcpy(&bar[UET_DEV_REG_IPADDR], dev->ipaddr, UET_DEV_IPADDR_LEN);

	PUT32(UET_DEV_REG_PROGRESS_ALIVE, dev->progress_running ? 1 : 0);
	PUT32(UET_DEV_REG_PROGRESS_ITERS_LO, (uint32_t)iters);
	PUT32(UET_DEV_REG_PROGRESS_ITERS_HI, (uint32_t)(iters >> 32));
	PUT32(UET_DEV_REG_UPTIME_MS, uet_dev_uptime_ms(dev));
	PUT32(UET_DEV_REG_BAR0_READS, dev->bar0_reads);
	PUT32(UET_DEV_REG_BAR0_WRITES, dev->bar0_writes);
	PUT32(UET_DEV_REG_DOORBELLS, dev->doorbells);
	PUT32(UET_DEV_REG_IRQS_FIRED, dev->irqs_fired);
	PUT32(UET_DEV_REG_TX_CONS, dev->tx_cons);
	PUT32(UET_DEV_REG_RX_CONS, dev->rx_cons);
	PUT32(UET_DEV_REG_TX_FRAMES, dev->tx_frames);
	PUT32(UET_DEV_REG_TX_ERRORS, dev->tx_errors);
	PUT32(UET_DEV_REG_RX_FRAMES, dev->rx_frames);
	PUT32(UET_DEV_REG_RX_DROPPED, dev->rx_dropped);
	PUT32(UET_DEV_REG_RX_UET_FRAMES, dev->rx_uet_frames);
	PUT32(UET_DEV_REG_ADMIN_SQ_CONS, dev->admin_sq_cons);
	PUT32(UET_DEV_REG_ADMIN_CQ_PROD, dev->admin_cq_prod);
	PUT32(UET_DEV_REG_ADMIN_CMDS, dev->admin_cmds);
	PUT32(UET_DEV_REG_ADMIN_ERRORS, dev->admin_errors);
	PUT32(UET_DEV_REG_JOBS_LIVE, dev->jobs_live);
	PUT32(UET_DEV_REG_JKEYS_LIVE, dev->jkeys_live);
	PUT32(UET_DEV_REG_MRS_LIVE, dev->mrs_live);
	PUT32(UET_DEV_REG_QPS_LIVE, dev->qps_live);
	PUT32(UET_DEV_REG_CQS_LIVE, dev->cqs_live);
	PUT32(UET_DEV_REG_SQ_POSTED, dev->sq_posted);
	PUT32(UET_DEV_REG_RQ_POSTED, dev->rq_posted);
	PUT32(UET_DEV_REG_CQ_POSTED, dev->cq_posted);
	PUT32(UET_DEV_REG_CQ_OVERRUNS, dev->cq_overruns);
	PUT32(UET_DEV_REG_DB_REJECTED, dev->db_rejected);
	PUT32(UET_DEV_REG_QPS_CLOSING, dev->qps_closing);
	PUT32(UET_DEV_REG_SQ_ERRORS, dev->sq_errors);
	PUT32(UET_DEV_REG_RQ_ERRORS, dev->rq_errors);
	PUT32(UET_DEV_REG_CQ_ERRORS, dev->cq_errors);
	PUT32(UET_DEV_REG_FLUSHED, dev->flushed);

#undef PUT32
}

ssize_t uet_dev_bar0_read(struct uet_dev *dev,
			  uint64_t offset,
			  void *buf,
			  size_t len)
{
	uint8_t bar[UET_DEV_BAR0_SIZE];

	if ((dev == NULL) || (offset > UET_DEV_BAR0_SIZE) ||
	    (len > (UET_DEV_BAR0_SIZE - offset))) {
		errno = EINVAL;
		return -1;
	}

	dev->bar0_reads++;

	uet_dev_bar0_snapshot(dev, bar);
	memcpy(buf, &bar[offset], len);

	return (ssize_t)len;
}

ssize_t uet_dev_bar0_write(struct uet_dev *dev, uint64_t offset,
			   const void *buf, size_t len)
{
	(void)buf;

	if ((dev == NULL) || (offset > UET_DEV_BAR0_SIZE) ||
	    (len > (UET_DEV_BAR0_SIZE - offset))) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * The status region is read only in this revision. A write is not an
	 * error - a driver may legitimately probe so we keep a counter to
	 * see write activity.
	 */
	dev->bar0_writes++;

	return (ssize_t)len;
}

/* the BAR2 control region reads back as zero */
ssize_t uet_dev_bar2_read(struct uet_dev *dev,
			  uint64_t offset,
			  void *buf,
			  size_t len)
{
	if ((dev == NULL) || (offset > UET_DEV_BAR2_SIZE) ||
	    (len > (UET_DEV_BAR2_SIZE - offset))) {
		errno = EINVAL;
		return -1;
	}

	memset(buf, 0, len);

	return (ssize_t)len;
}

/* Every register in BAR2 is 32 bits wide and write-only. The doorbells act
 * on write. The rest are configuration a driver sets before enabling a ring.
 */
ssize_t uet_dev_bar2_write(struct uet_dev *dev,
			   uint64_t offset,
			   const void *buf,
			   size_t len)
{
	uint32_t v;

	if ((dev == NULL) || (offset > UET_DEV_BAR2_SIZE) ||
	    (len > (UET_DEV_BAR2_SIZE - offset))) {
		errno = EINVAL;
		return -1;
	}

	if (len < sizeof(uint32_t))
		return (ssize_t)len;

	memcpy(&v, buf, sizeof(v));

	switch (offset) {
	case UET_DEV_TX_RING_BASE_LO:
		pthread_mutex_lock(&dev->ring_lock);
		dev->tx_ring_base = ((dev->tx_ring_base & ~0xffffffffULL) | v);
		pthread_mutex_unlock(&dev->ring_lock);
		break;

	case UET_DEV_TX_RING_BASE_HI:
		pthread_mutex_lock(&dev->ring_lock);
		dev->tx_ring_base = ((dev->tx_ring_base & 0xffffffffULL) |
				     ((uint64_t)v << 32));
		pthread_mutex_unlock(&dev->ring_lock);
		break;

	case UET_DEV_TX_RING_ENTRIES:
		pthread_mutex_lock(&dev->ring_lock);
		dev->tx_ring_entries = uet_dev_ring_entries_ok(v) ? v : 0;
		pthread_mutex_unlock(&dev->ring_lock);
		break;

	case UET_DEV_TX_RING_CTRL:
		pthread_mutex_lock(&dev->ring_lock);
		dev->tx_ring_ctrl = v;
		if (!(v & UET_DEV_RING_CTRL_ENABLE))
			dev->tx_prod = dev->tx_cons = 0;
		pthread_mutex_unlock(&dev->ring_lock);
		break;

	case UET_DEV_TX_PROD:
		pthread_mutex_lock(&dev->ring_lock);
		dev->tx_prod = v;
		uet_dev_tx_drain_locked(dev); /* send L2 packets */
		pthread_mutex_unlock(&dev->ring_lock);
		break;

	case UET_DEV_RX_RING_BASE_LO:
		pthread_mutex_lock(&dev->ring_lock);
		dev->rx_ring_base = ((dev->rx_ring_base & ~0xffffffffULL) | v);
		pthread_mutex_unlock(&dev->ring_lock);
		break;

	case UET_DEV_RX_RING_BASE_HI:
		pthread_mutex_lock(&dev->ring_lock);
		dev->rx_ring_base = ((dev->rx_ring_base & 0xffffffffULL) |
				     ((uint64_t)v << 32));
		pthread_mutex_unlock(&dev->ring_lock);
		break;

	case UET_DEV_RX_RING_ENTRIES:
		pthread_mutex_lock(&dev->ring_lock);
		dev->rx_ring_entries = uet_dev_ring_entries_ok(v) ? v : 0;
		pthread_mutex_unlock(&dev->ring_lock);
		break;

	case UET_DEV_RX_RING_CTRL:
		pthread_mutex_lock(&dev->ring_lock);
		dev->rx_ring_ctrl = v;
		if (!(v & UET_DEV_RING_CTRL_ENABLE))
			dev->rx_prod = dev->rx_cons = 0;
		pthread_mutex_unlock(&dev->ring_lock);
		break;

	case UET_DEV_RX_PROD:
		pthread_mutex_lock(&dev->ring_lock);
		dev->rx_prod = v;
		pthread_mutex_unlock(&dev->ring_lock);
		break;

	case UET_DEV_ADMIN_SQ_BASE_LO:
		pthread_mutex_lock(&dev->ring_lock);
		dev->admin_sq_base = ((dev->admin_sq_base & ~0xffffffffULL) | v);
		pthread_mutex_unlock(&dev->ring_lock);
		break;

	case UET_DEV_ADMIN_SQ_BASE_HI:
		pthread_mutex_lock(&dev->ring_lock);
		dev->admin_sq_base = ((dev->admin_sq_base & 0xffffffffULL) |
				      ((uint64_t)v << 32));
		pthread_mutex_unlock(&dev->ring_lock);
		break;

	case UET_DEV_ADMIN_SQ_ENTRIES:
		pthread_mutex_lock(&dev->ring_lock);
		dev->admin_sq_entries =
			(uet_dev_ring_entries_ok(v) &&
			 (v <= UET_DEV_ADMIN_MAX_ENTRIES)) ? v : 0;
		pthread_mutex_unlock(&dev->ring_lock);
		break;

	case UET_DEV_ADMIN_SQ_CTRL:
		pthread_mutex_lock(&dev->ring_lock);
		dev->admin_sq_ctrl = v;
		if (!(v & UET_DEV_RING_CTRL_ENABLE))
			dev->admin_sq_prod = dev->admin_sq_cons = 0;
		pthread_mutex_unlock(&dev->ring_lock);
		break;

	case UET_DEV_ADMIN_SQ_PROD:
		pthread_mutex_lock(&dev->ring_lock);
		dev->admin_sq_prod = v;
		uet_dev_admin_drain_locked(dev); /* process admin commands */
		pthread_mutex_unlock(&dev->ring_lock);
		break;

	case UET_DEV_ADMIN_CQ_BASE_LO:
		pthread_mutex_lock(&dev->ring_lock);
		dev->admin_cq_base = ((dev->admin_cq_base & ~0xffffffffULL) | v);
		pthread_mutex_unlock(&dev->ring_lock);
		break;

	case UET_DEV_ADMIN_CQ_BASE_HI:
		pthread_mutex_lock(&dev->ring_lock);
		dev->admin_cq_base = ((dev->admin_cq_base & 0xffffffffULL) |
				      ((uint64_t)v << 32));
		pthread_mutex_unlock(&dev->ring_lock);
		break;

	case UET_DEV_ADMIN_CQ_ENTRIES:
		pthread_mutex_lock(&dev->ring_lock);
		dev->admin_cq_entries =
			(uet_dev_ring_entries_ok(v) &&
			 (v <= UET_DEV_ADMIN_MAX_ENTRIES)) ? v : 0;
		pthread_mutex_unlock(&dev->ring_lock);
		break;

	case UET_DEV_ADMIN_CQ_CTRL:
		pthread_mutex_lock(&dev->ring_lock);
		dev->admin_cq_ctrl = v;
		if (!(v & UET_DEV_RING_CTRL_ENABLE))
			dev->admin_cq_prod = dev->admin_cq_cons = 0;
		pthread_mutex_unlock(&dev->ring_lock);
		break;

	case UET_DEV_ADMIN_CQ_CONS:
		/* the driver reclaimed entries; more commands may now run */
		pthread_mutex_lock(&dev->ring_lock);
		dev->admin_cq_cons = v;
		uet_dev_admin_drain_locked(dev); /* process admin responses */
		pthread_mutex_unlock(&dev->ring_lock);
		break;

	default:
		break;
	}

	return (ssize_t)len;
}

/* the BAR3 doorbell region reads back as zero */
ssize_t uet_dev_bar3_read(struct uet_dev *dev,
			  uint64_t offset,
			  void *buf,
			  size_t count)
{
	(void)dev;
	(void)offset;

	memset(buf, 0, count);

	return (ssize_t)count;
}

/* A BAR3 doorbell page belongs to one ucontext. The page a write lands on
 * is what identifies the writer. The handle in the value is what it claims
 * to be ringing. The device compares the two as a process that maps its page
 * and then rings another context's queue pair is refused here. Each doorbell
 * is a single 64-bit write.
 */
ssize_t uet_dev_bar3_write(struct uet_dev *dev,
			   uint64_t offset,
			   const void *buf,
			   size_t count)
{
	uint32_t page = (uint32_t)(offset / UET_DEV_DB_PAGE_SIZE);
	uint64_t reg = (offset % UET_DEV_DB_PAGE_SIZE);
	uint32_t handle, prod, cons;
	struct uet_dev_qp *qp;
	struct uet_dev_cq *cq;
	uint64_t val;

	if ((count != sizeof(uint64_t)) || (page >= UET_DEV_MAX_DB_PAGES))
		return -1;

	memcpy(&val, buf, sizeof(val));
	dev->doorbells++;

	uet_dev_trace("doorbell: page %u reg 0x%llx value 0x%llx", page,
		      (unsigned long long)reg, (unsigned long long)val);

	switch (reg) {
	case UET_DEV_DB_SQ:
	case UET_DEV_DB_RQ: {
		handle = (uint32_t)(val >> UET_DEV_DB_HANDLE_SHIFT);
		prod = (uint32_t)(val & UET_DEV_DB_INDEX_MASK);
		qp = uet_dev_qp_get(dev, handle);

		if ((qp == NULL) || (qp->db_page != page)) {
			dev->db_rejected++;
			return -1;
		}

		if (reg == UET_DEV_DB_SQ)
			qp->sq.prod = prod;
		else
			qp->rq.prod = prod;
		break;
	}

	case UET_DEV_DB_CQ: {
		handle = (uint32_t)((val >> UET_DEV_DB_HANDLE_SHIFT) &
				    UET_DEV_DB_CQ_HANDLE_MASK);
		cons = (uint32_t)(val & UET_DEV_DB_INDEX_MASK);
		cq = uet_dev_cq_get(dev, handle);

		if ((cq == NULL) || (cq->db_page != page)) {
			dev->db_rejected++;
			return -1;
		}

		cq->ring.cons = cons;
		if (val & UET_DEV_DB_CQ_ARM)
			cq->armed = true;
		break;
	}

	default:
		return -1;
	}

	return (ssize_t)count;
}

