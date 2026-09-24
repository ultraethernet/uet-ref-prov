// SPDX-License-Identifier: MIT

/* Functional UET NIC shim over the out-of-tree VPP termination plugin. */

#if ENABLE_VPP

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <uet_vpp_client.h>

#include "uet_api.h"
#include "uet_api_private.h"
#include "uet_pkt_hdr.h"
#include "uet_nic.h"
#include "crc32c.h"

#define UET_NETWORK_TYPE_VPP "VPP"
#define UET_VPP_TX_BATCH_SIZE 64
#define UET_VPP_DEFAULT_MTU 1500
#define UET_VPP_MAX_CHANNELS 256
#define UET_VPP_CHANNEL_ALIGNMENT 64
#define UET_VPP_CLOSE_TIMEOUT_NS (5ULL * 1000 * 1000 * 1000)
#define UET_VPP_INITIATOR_LOCAL_BITS 22
#define UET_VPP_INITIATOR_LOCAL_MASK \
	((1U << UET_VPP_INITIATOR_LOCAL_BITS) - 1)

struct vpp_endpoint_registration {
	struct vpp_data *vdata;
	uet_vpp_client_endpoint_t endpoint;
};

struct __attribute__((aligned(UET_VPP_CHANNEL_ALIGNMENT))) vpp_channel {
	uet_vpp_client_t *client;
	uint32_t channel_index;
	uet_vpp_client_rx_t pending_rx;
	bool rx_pending;
	uint64_t next_request_id;
	uint64_t tx_inflight;
	pthread_mutex_t lock;
	bool lock_initialized;
};

struct vpp_data {
	uet_vpp_client_t *client;
	struct vpp_channel *channels;
	size_t channel_count;
	size_t rx_cursor;
	size_t pending_channel;
	pthread_mutex_t rx_lock;
	bool rx_lock_initialized;
	bool dma_mapped;
	bool pds_sng;
	uet_vpp_client_info_t info;
	_Atomic uint64_t rudi_last_sequence_plus_one;
};

struct nic_vpp_packet_view {
	uint8_t *ip;
	uint8_t *pds;
	size_t ip_length;
	size_t pds_length;
	uint8_t type;
	uint8_t next_header;
	uint8_t flags;
	bool is_ipv6;
};

static int nic_vpp_monotonic_ns(uint64_t *now)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return -errno;
	*now = (uint64_t)ts.tv_sec * 1000000000ULL +
	       (uint64_t)ts.tv_nsec;
	return 0;
}

static int nic_vpp_completion_error(int32_t status)
{
	switch (status) {
	case UET_VPP_CLIENT_STATUS_OK:
		return 0;
	case UET_VPP_CLIENT_STATUS_INVALID_PACKET:
		return -EINVAL;
	case UET_VPP_CLIENT_STATUS_TX_NOT_CONFIGURED:
		return -ENETDOWN;
	case UET_VPP_CLIENT_STATUS_SLOT_BUSY:
		return -EBUSY;
	case UET_VPP_CLIENT_STATUS_NO_BUFFERS:
		return -ENOBUFS;
	default:
		return -EPROTO;
	}
}

static int nic_vpp_poll_tx(struct vpp_channel *channel,
			   int *completion_error)
{
	uet_vpp_client_completion_t completions[UET_VPP_TX_BATCH_SIZE];
	int error = 0;
	int i, rc;

	rc = uet_vpp_client_poll_batch(channel->client,
				       channel->channel_index, completions,
				       UET_VPP_TX_BATCH_SIZE);
	if (rc < 0)
		return rc;
	for (i = 0; i < rc; i++) {
		int status_error =
			nic_vpp_completion_error(completions[i].status);

		if (channel->tx_inflight)
			channel->tx_inflight--;
		else if (!error)
			error = -EPROTO;
		if (!error && status_error)
			error = status_error;
	}
	*completion_error = error;
	return rc;
}

static int nic_vpp_progress_tx(struct vpp_channel *channel)
{
	int completion_error;
	int rc;

	rc = nic_vpp_poll_tx(channel, &completion_error);
	if (rc < 0)
		return rc;
	return completion_error ? completion_error : rc;
}

static int nic_vpp_release_pending_rx(struct vpp_data *vdata)
{
	struct vpp_channel *channel;
	int rc;

	if (vdata->pending_channel >= vdata->channel_count)
		return 0;
	channel = &vdata->channels[vdata->pending_channel];
	rc = uet_vpp_client_release_rx(channel->client,
				       channel->channel_index,
				       &channel->pending_rx);
	if (!rc) {
		channel->rx_pending = false;
		vdata->pending_channel = SIZE_MAX;
	}
	return rc;
}

static int nic_vpp_ip_length(void *iphdr, size_t available,
			     size_t *ip_length)
{
	uint8_t version;

	if (!iphdr || available < sizeof(struct iphdr))
		return -EINVAL;
	version = (*(uint8_t *)iphdr) >> 4;
	if (version == 4) {
		struct iphdr *ipv4 = iphdr;
		size_t header_length = ipv4->ihl << 2;

		if (header_length < sizeof(*ipv4))
			return -EINVAL;
		*ip_length = ntohs(ipv4->tot_len);
	} else if (version == 6) {
		struct ipv6hdr *ipv6 = iphdr;

		if (available < sizeof(*ipv6))
			return -EINVAL;
		*ip_length = sizeof(*ipv6) + ntohs(ipv6->payload_len);
	} else {
		return -EINVAL;
	}

	if (*ip_length > available)
		return -EMSGSIZE;
	return 0;
}

static int nic_vpp_packet_view(struct uet_nic *nic, void *iphdr,
			       size_t available,
			       struct nic_vpp_packet_view *view)
{
	struct uet_pds_prlg *prologue;
	uint16_t type_next_flags;
	uint8_t protocol;
	size_t offset;
	int rc;

	memset(view, 0, sizeof(*view));
	rc = nic_vpp_ip_length(iphdr, available, &view->ip_length);
	if (rc)
		return rc;
	view->ip = iphdr;
	view->is_ipv6 = (view->ip[0] >> 4) == 6;
	if (view->is_ipv6) {
		struct ipv6hdr *ipv6 = iphdr;

		protocol = ipv6->nexthdr;
		offset = sizeof(*ipv6);
	} else {
		struct iphdr *ipv4 = iphdr;

		protocol = ipv4->protocol;
		offset = ipv4->ihl << 2;
	}
	if (protocol == nic->uet_ipproto)
		offset += sizeof(struct uet_entropy);
	else if (protocol == IPPROTO_UDP)
		offset += sizeof(struct udphdr);
	else
		return -EPROTONOSUPPORT;
	if (offset + sizeof(*prologue) > view->ip_length)
		return -EINVAL;

	view->pds = view->ip + offset;
	prologue = (struct uet_pds_prlg *)view->pds;
	type_next_flags = ntohs(prologue->type_next_flags);
	view->type = (type_next_flags & UET_PDS_TYPE_MASK) >>
		     UET_PDS_TYPE_SHIFT;
	view->next_header = (type_next_flags & UET_PDS_NEXT_HDR_MASK) >>
			    UET_PDS_NEXT_HDR_SHIFT;
	view->flags = type_next_flags & UET_PDS_FLAGS_MASK;

	switch (view->type) {
	case UET_PDS_TYPE_RUD_REQ:
	case UET_PDS_TYPE_ROD_REQ:
		view->pds_length = sizeof(struct uet_pds_req);
		break;
	case UET_PDS_TYPE_RUD_CC_REQ:
	case UET_PDS_TYPE_ROD_CC_REQ:
		view->pds_length = sizeof(struct uet_pds_req) +
				   sizeof(struct uet_pds_req_cc_state);
		break;
	case UET_PDS_TYPE_ACK:
		view->pds_length = sizeof(struct uet_pds_ack);
		break;
	case UET_PDS_TYPE_ACK_CC:
		view->pds_length = sizeof(struct uet_pds_ack_cc);
		break;
	case UET_PDS_TYPE_ACK_CCX:
		view->pds_length = sizeof(struct uet_pds_ack_ccx);
		break;
	case UET_PDS_TYPE_NACK:
		view->pds_length = sizeof(struct uet_pds_nack);
		break;
	case UET_PDS_TYPE_NACK_CCX:
		view->pds_length = sizeof(struct uet_pds_nack_ccx);
		break;
	case UET_PDS_TYPE_CTRL:
		view->pds_length = sizeof(struct uet_pds_ctrl);
		break;
	case UET_PDS_TYPE_RUDI_REQ:
	case UET_PDS_TYPE_RUDI_RESP:
		view->pds_length = sizeof(struct uet_pds_rudi_req);
		break;
	case UET_PDS_TYPE_UUD_REQ:
		view->pds_length = sizeof(struct uet_pds_uud_req);
		break;
	case UET_PDS_TYPE_SECURITY:
		/* Endpoint demultiplexing cannot inspect encrypted transport
		 * headers yet. Preserve the historical single-client behavior.
		 */
		return -EOPNOTSUPP;
	default:
		return -EINVAL;
	}
	if (offset + view->pds_length > view->ip_length)
		return -EINVAL;
	return 0;
}

static int nic_vpp_pdc_to_wire(const struct vpp_data *vdata,
			       uint16_t local_id, uint16_t *wire_id)
{
	if (!local_id || local_id > UET_VPP_CLIENT_PDC_LOCAL_MASK)
		return -ERANGE;
	*wire_id = ((uint16_t)vdata->info.client_namespace <<
		    UET_VPP_CLIENT_PDC_LOCAL_BITS) | local_id;
	return 0;
}

static int nic_vpp_pdc_from_wire(const struct vpp_data *vdata,
				 uint16_t wire_id, uint16_t *local_id)
{
	if ((wire_id >> UET_VPP_CLIENT_PDC_LOCAL_BITS) !=
	    vdata->info.client_namespace)
		return -EPROTO;
	*local_id = wire_id & UET_VPP_CLIENT_PDC_LOCAL_MASK;
	return 0;
}

static int nic_vpp_rudi_to_wire(struct vpp_data *vdata, uint32_t local_id,
				uint32_t *wire_id)
{
	const uint64_t wrap = (uint64_t)UINT32_MAX + 1;
	uint64_t observed, desired, last, sequence;

	/* The software RUDI allocator is a monotonic uint32_t counter. Keep its
	 * logical epoch so a response can recover the full ID after only the low
	 * 22 bits crossed the VPP boundary. No per-packet state is added here.
	 */
	observed = atomic_load_explicit(&vdata->rudi_last_sequence_plus_one,
					memory_order_relaxed);
	for (;;) {
		if (!observed) {
			sequence = local_id;
			desired = sequence + 1;
		} else {
			last = observed - 1;
			sequence = (last & ~(wrap - 1)) | local_id;
			if (sequence < last && last - sequence > wrap / 2)
				sequence += wrap;
			else if (sequence > last && sequence - last > wrap / 2 &&
				 sequence >= wrap)
				sequence -= wrap;
			if (sequence <= last)
				break;
			desired = sequence + 1;
		}
		if (atomic_compare_exchange_weak_explicit(
			    &vdata->rudi_last_sequence_plus_one, &observed,
			    desired, memory_order_relaxed, memory_order_relaxed))
			break;
	}
	*wire_id = (vdata->info.client_namespace <<
		    UET_VPP_CLIENT_RUDI_LOCAL_BITS) |
		   (local_id & UET_VPP_CLIENT_RUDI_LOCAL_MASK);
	return 0;
}

static int nic_vpp_rudi_from_wire(struct vpp_data *vdata,
				  uint32_t wire_id, uint32_t *local_id)
{
	const uint64_t span = (uint64_t)1 << UET_VPP_CLIENT_RUDI_LOCAL_BITS;
	uint64_t last_plus_one, last, sequence;

	if ((wire_id >> UET_VPP_CLIENT_RUDI_LOCAL_BITS) !=
	    vdata->info.client_namespace)
		return -EPROTO;
	last_plus_one = atomic_load_explicit(
		&vdata->rudi_last_sequence_plus_one, memory_order_relaxed);
	if (!last_plus_one)
		return -ENOENT;
	last = last_plus_one - 1;
	/* Reconstruction is unambiguous while fewer than one 22-bit span of
	 * requests are outstanding. The engine queue limits are far below that.
	 */
	sequence = (last & ~(span - 1)) |
		   (wire_id & UET_VPP_CLIENT_RUDI_LOCAL_MASK);
	if (sequence > last) {
		if (sequence < span)
			return -ENOENT;
		sequence -= span;
	}
	*local_id = (uint32_t)sequence;
	return 0;
}

static void nic_vpp_update_crc(const struct nic_vpp_packet_view *view)
{
	size_t start_offset = view->is_ipv6 ? 8 : 12;
	uint32_t crc;

	if (view->ip_length < start_offset + CRC_LEN)
		return;
	crc = crc32c(view->ip + start_offset,
		     view->ip_length - start_offset - CRC_LEN);
	memcpy(view->ip + view->ip_length - CRC_LEN, &crc, CRC_LEN);
}

static int nic_vpp_translate_ids(struct uet_nic *nic, void *iphdr,
				 size_t available, bool tx)
{
	struct vpp_data *vdata = nic->nic_priv_data;
	struct nic_vpp_packet_view view;
	uint16_t value16;
	uint32_t value32;
	bool changed = false;
	int rc;

	rc = nic_vpp_packet_view(nic, iphdr, available, &view);
	if (rc == -EOPNOTSUPP)
		return 0;
	if (rc)
		return rc;

	/* SNG repurposes spdcid/dpdcid as an endpoint-address overlay. */
	if (vdata->pds_sng)
		return 0;

	switch (view.type) {
	case UET_PDS_TYPE_RUD_REQ:
	case UET_PDS_TYPE_ROD_REQ:
	case UET_PDS_TYPE_RUD_CC_REQ:
	case UET_PDS_TYPE_ROD_CC_REQ: {
		struct uet_pds_req *request = (struct uet_pds_req *)view.pds;

		if (tx) {
			rc = nic_vpp_pdc_to_wire(vdata,
					     ntohs(request->spdcid), &value16);
			if (rc)
				return rc;
			request->spdcid = htons(value16);
			changed = true;
		} else if (!(view.flags & UET_PDS_REQ_FLAGS_SYN)) {
			rc = nic_vpp_pdc_from_wire(vdata,
						ntohs(request->dpdcid), &value16);
			if (rc)
				return rc;
			request->dpdcid = htons(value16);
			changed = true;
		}
		break;
	}
	case UET_PDS_TYPE_ACK:
	case UET_PDS_TYPE_ACK_CC:
	case UET_PDS_TYPE_ACK_CCX: {
		struct uet_pds_ack *ack = (struct uet_pds_ack *)view.pds;

		if (tx) {
			rc = nic_vpp_pdc_to_wire(vdata, ntohs(ack->spdcid),
					     &value16);
			if (rc)
				return rc;
			ack->spdcid = htons(value16);
		} else {
			rc = nic_vpp_pdc_from_wire(vdata, ntohs(ack->dpdcid),
						&value16);
			if (rc)
				return rc;
			ack->dpdcid = htons(value16);
		}
		changed = true;
		break;
	}
	case UET_PDS_TYPE_NACK:
	case UET_PDS_TYPE_NACK_CCX: {
		struct uet_pds_nack *nack = (struct uet_pds_nack *)view.pds;

		if (view.flags & UET_PDS_NACK_FLAGS_NT) {
			if (!tx) {
				rc = nic_vpp_rudi_from_wire(
					vdata, ntohl(nack->nack_pkt_id), &value32);
				if (rc)
					return rc;
				nack->nack_pkt_id = htonl(value32);
				changed = true;
			}
		} else if (tx) {
			rc = nic_vpp_pdc_to_wire(vdata, ntohs(nack->spdcid),
					     &value16);
			if (rc)
				return rc;
			nack->spdcid = htons(value16);
			changed = true;
		} else {
			rc = nic_vpp_pdc_from_wire(vdata, ntohs(nack->dpdcid),
						&value16);
			if (rc)
				return rc;
			nack->dpdcid = htons(value16);
			changed = true;
		}
		break;
	}
	case UET_PDS_TYPE_CTRL: {
		struct uet_pds_ctrl *control = (struct uet_pds_ctrl *)view.pds;

		if (tx) {
			rc = nic_vpp_pdc_to_wire(vdata,
					     ntohs(control->spdcid), &value16);
			if (rc)
				return rc;
			control->spdcid = htons(value16);
			changed = true;
		} else if (!(view.flags & UET_PDS_CTRL_FLAGS_SYN)) {
			rc = nic_vpp_pdc_from_wire(vdata,
						ntohs(control->dpdcid), &value16);
			if (rc)
				return rc;
			control->dpdcid = htons(value16);
			changed = true;
		}
		break;
	}
	case UET_PDS_TYPE_RUDI_REQ:
		if (tx) {
			struct uet_pds_rudi_req *rudi =
				(struct uet_pds_rudi_req *)view.pds;

			rc = nic_vpp_rudi_to_wire(vdata, ntohl(rudi->pkt_id),
						&value32);
			if (rc)
				return rc;
			rudi->pkt_id = htonl(value32);
			changed = true;
		}
		break;
	case UET_PDS_TYPE_RUDI_RESP:
		if (!tx) {
			struct uet_pds_rudi_req *rudi =
				(struct uet_pds_rudi_req *)view.pds;

			rc = nic_vpp_rudi_from_wire(vdata, ntohl(rudi->pkt_id),
						&value32);
			if (rc)
				return rc;
			rudi->pkt_id = htonl(value32);
			changed = true;
		}
		break;
	default:
		break;
	}

	if (changed)
		nic_vpp_update_crc(&view);
	return 0;
}

static uint32_t nic_vpp_hash_mix(uint32_t hash, uint32_t value)
{
	hash ^= value + 0x9e3779b9U + (hash << 6) + (hash >> 2);
	return hash;
}

static uint32_t nic_vpp_hash_finalize(uint32_t hash)
{
	hash ^= hash >> 16;
	hash *= 0x7feb352dU;
	hash ^= hash >> 15;
	hash *= 0x846ca68bU;
	return hash ^ (hash >> 16);
}

/*
 * Select a stable worker channel from the fields normally used as network
 * entropy.  Native UET places EV at the start of its entropy header; UDP uses
 * the source port.  Keeping one EV on one channel avoids introducing packet
 * reordering while allowing future per-endpoint/per-message EV selection to
 * spread traffic across VPP workers.
 */
static size_t nic_vpp_select_channel(const struct vpp_data *vdata,
				     const void *iphdr, size_t ip_length)
{
	const uint8_t *ip = iphdr;
	const uint8_t *l4;
	uint32_t hash = 0x811c9dc5U;
	uint16_t entropy;
	uint8_t protocol;
	size_t l4_length;

	if (vdata->channel_count == 1)
		return 0;
	if ((ip[0] >> 4) == 4) {
		const struct iphdr *ipv4 = iphdr;
		size_t header_length = ipv4->ihl << 2;

		if (header_length > ip_length)
			return 0;
		hash = nic_vpp_hash_mix(hash, ntohl(ipv4->saddr));
		hash = nic_vpp_hash_mix(hash, ntohl(ipv4->daddr));
		protocol = ipv4->protocol;
		l4 = ip + header_length;
		l4_length = ip_length - header_length;
	} else {
		const struct ipv6hdr *ipv6 = iphdr;
		uint32_t word;

		if (ip_length < sizeof(*ipv6))
			return 0;
		for (size_t i = 0; i < sizeof(ipv6->saddr); i += sizeof(word)) {
			memcpy(&word, (const uint8_t *)&ipv6->saddr + i,
			       sizeof(word));
			hash = nic_vpp_hash_mix(hash, ntohl(word));
			memcpy(&word, (const uint8_t *)&ipv6->daddr + i,
			       sizeof(word));
			hash = nic_vpp_hash_mix(hash, ntohl(word));
		}
		protocol = ipv6->nexthdr;
		l4 = ip + sizeof(*ipv6);
		l4_length = ip_length - sizeof(*ipv6);
	}

	hash = nic_vpp_hash_mix(hash, protocol);
	if (l4_length >= sizeof(entropy)) {
		memcpy(&entropy, l4, sizeof(entropy));
		hash = nic_vpp_hash_mix(hash, ntohs(entropy));
	}
	return nic_vpp_hash_finalize(hash) % vdata->channel_count;
}

int nic_vpp_getinfo(struct uet_nic *nic, struct uet_nic_info *nic_info)
{
	nic_info->ifname = nic->ifname;
	nic_info->network_type = nic->network_type;
	nic_info->mac_addr_str = nic->mac_addr_str;
	nic_info->mtu = nic->mtu;
	nic_info->link_state = UET_NIC_LINK_STATE_UP;
	return 0;
}

static void nic_vpp_endpoint_init(uet_vpp_client_endpoint_t *endpoint,
				  const struct uet_addr *addr,
				  uint32_t job_id, bool absolute)
{
	*endpoint = (uet_vpp_client_endpoint_t) {
		.ip_version = uet_addr_is_ipv6(addr) ? 6 : 4,
		.absolute = absolute,
		.pid_on_fep = addr->pid_on_fep,
		.resource_index = addr->start_index,
		.job_id = job_id,
	};

	if (endpoint->ip_version == 6)
		memcpy(endpoint->ip_address, addr->fa.v6,
		       sizeof(endpoint->ip_address));
	else {
		uint32_t address = htonl(addr->fa.v4);

		memcpy(endpoint->ip_address, &address, sizeof(address));
	}
}

int nic_vpp_configure_info(struct uet_nic *nic, struct fi_info *info)
{
	struct vpp_data *vdata;
	struct uet_addr *addr;
	uint32_t client_namespace;

	if (!nic || !info || !info->src_addr ||
	    info->src_addrlen != sizeof(*addr))
		return -FI_EINVAL;
	vdata = nic->nic_priv_data;
	if (!vdata || !vdata->client)
		return -FI_EOPBADSTATE;
	client_namespace = vdata->info.client_namespace;
	if (!client_namespace ||
	    client_namespace > UET_VPP_CLIENT_NAMESPACE_MAX)
		return -FI_EIO;

	addr = info->src_addr;
	addr->pid_on_fep = (uint16_t)client_namespace;
	addr->initiator_id =
		(client_namespace << UET_VPP_INITIATOR_LOCAL_BITS) |
		(UET_ADDR_DEF_INITIATOR_ID & UET_VPP_INITIATOR_LOCAL_MASK);
	addr->flags |= UET_ADDR_PID_ON_FEP_V | UET_ADDR_INITIATOR_V;
	return FI_SUCCESS;
}

int nic_vpp_ep_register(struct uet_nic *nic, struct uet_ep *ep,
			void **context)
{
	struct vpp_endpoint_registration *registration;
	struct vpp_data *vdata;
	int rc;

	if (!nic || !ep || !context)
		return -FI_EINVAL;
	vdata = nic->nic_priv_data;
	if (!vdata || !vdata->client)
		return -FI_EOPBADSTATE;
	registration = calloc(1, sizeof(*registration));
	if (!registration)
		return -FI_ENOMEM;
	registration->vdata = vdata;
	nic_vpp_endpoint_init(&registration->endpoint, &ep->uet_addr,
			      ep->job_id, ep->absolute);
	rc = uet_vpp_client_endpoint_add(vdata->client,
					 &registration->endpoint);
	if (rc) {
		free(registration);
		return rc == -EADDRINUSE ? -FI_EADDRINUSE : -FI_EIO;
	}
	*context = registration;
	return FI_SUCCESS;
}

void nic_vpp_ep_unregister(struct uet_nic *nic, void *context)
{
	struct vpp_endpoint_registration *registration = context;
	int rc;

	(void)nic;
	if (!registration)
		return;
	rc = uet_vpp_client_endpoint_del(registration->vdata->client,
					 &registration->endpoint);
	if (rc)
		UET_API_ERR("failed to unregister VPP endpoint: %d", rc);
	free(registration);
}

int nic_vpp_get_nh(struct uet_nic *nic, const struct uet_fa *fa,
		   bool is_ipv6, uint8_t *mac)
{
	/* VPP owns FIB lookup, adjacency resolution and the Ethernet rewrite.
	 * The existing transport still builds an Ethernet header, so give it a
	 * stable placeholder which the VPP shim discards on transmit.
	 */
	(void)nic;
	(void)fa;
	(void)is_ipv6;
	memset(mac, 0, ETH_ALEN);
	mac[0] = 0x02;
	mac[3] = 0x55;
	mac[4] = 0x45;
	mac[5] = 0x54;
	return 0;
}

int nic_vpp_tx_pkt(struct uet_nic *nic, void *pkt, void *iphdr,
		   size_t pkt_size)
{
	struct vpp_data *vdata = nic->nic_priv_data;
	struct vpp_channel *channel;
	uet_vpp_client_tx_request_t request;
	uint8_t *packet = pkt;
	uint8_t *ip = iphdr;
	void *dma_data;
	size_t channel_index;
	size_t available, capacity, ip_length;
	int rc;

	if (!vdata || ip < packet || (size_t)(ip - packet) > pkt_size)
		return -EINVAL;
	available = pkt_size - (size_t)(ip - packet);
	rc = nic_vpp_ip_length(ip, available, &ip_length);
	if (rc)
		return rc;
	channel_index = nic_vpp_select_channel(vdata, ip, ip_length);
	channel = &vdata->channels[channel_index];
	rc = pthread_mutex_lock(&channel->lock);
	if (rc)
		return -rc;

	for (;;) {
		rc = uet_vpp_client_acquire_dma(channel->client,
						channel->channel_index,
						&request.dma_slot,
						&dma_data, &capacity);
		if (rc != -EAGAIN)
			break;
		rc = nic_vpp_progress_tx(channel);
		if (rc < 0)
			goto out_unlock;
	}
	if (rc)
		goto out_unlock;
	if (ip_length > capacity) {
		uet_vpp_client_release_dma(channel->client,
					   channel->channel_index,
					   request.dma_slot);
		rc = -EMSGSIZE;
		goto out_unlock;
	}

	memcpy(dma_data, ip, ip_length);
	rc = nic_vpp_translate_ids(nic, dma_data, ip_length, true);
	if (rc) {
		uet_vpp_client_release_dma(channel->client,
					   channel->channel_index,
					   request.dma_slot);
		goto out_unlock;
	}
	request.packet_length = ip_length;
	request.request_id = ++channel->next_request_id;
	request.user_context = 0;
	for (;;) {
		rc = uet_vpp_client_submit_ip_batch(channel->client,
						channel->channel_index,
						&request, 1);
		if (rc != -EAGAIN)
			break;
		rc = nic_vpp_progress_tx(channel);
		if (rc < 0)
			break;
	}
	if (rc) {
		uet_vpp_client_release_dma(channel->client,
					   channel->channel_index,
					   request.dma_slot);
		goto out_unlock;
	}
	channel->tx_inflight++;

out_unlock:
	pthread_mutex_unlock(&channel->lock);
	return rc;
}

static int nic_vpp_rx_poll_locked(struct vpp_data *vdata)
{
	int lock_rc, rc;

	if (vdata->pending_channel < vdata->channel_count)
		return 1;

	for (size_t i = 0; i < vdata->channel_count; i++) {
		size_t index = (vdata->rx_cursor + i) % vdata->channel_count;
		struct vpp_channel *channel = &vdata->channels[index];

		lock_rc = pthread_mutex_lock(&channel->lock);
		if (lock_rc)
			return -lock_rc;
		rc = nic_vpp_progress_tx(channel);
		if (rc >= 0 && !channel->rx_pending) {
			rc = uet_vpp_client_poll_rx(channel->client,
						channel->channel_index,
						&channel->pending_rx);
			channel->rx_pending = rc == 1;
		}
		if (rc >= 0 && channel->rx_pending) {
			vdata->pending_channel = index;
			vdata->rx_cursor = (index + 1) % vdata->channel_count;
			pthread_mutex_unlock(&channel->lock);
			return 1;
		}
		pthread_mutex_unlock(&channel->lock);
		if (rc < 0)
			return rc;
	}
	return 0;
}

int nic_vpp_rx_poll(struct uet_nic *nic)
{
	struct vpp_data *vdata = nic->nic_priv_data;
	int lock_rc, rc;

	if (!vdata)
		return -EINVAL;
	lock_rc = pthread_mutex_lock(&vdata->rx_lock);
	if (lock_rc)
		return -lock_rc;
	rc = nic_vpp_rx_poll_locked(vdata);
	pthread_mutex_unlock(&vdata->rx_lock);
	return rc;
}

int nic_vpp_rx_pkt(struct uet_nic *nic, void *pkt, size_t pkt_buf_size,
		   size_t *rx_pkt_size)
{
	struct vpp_data *vdata = nic->nic_priv_data;
	struct vpp_channel *channel;
	struct ethhdr *eth = pkt;
	size_t frame_length, offset = sizeof(*eth);
	uint16_t i;
	int lock_rc, rc;

	if (!vdata)
		return -EINVAL;
	lock_rc = pthread_mutex_lock(&vdata->rx_lock);
	if (lock_rc)
		return -lock_rc;
	if (vdata->pending_channel >= vdata->channel_count) {
		rc = nic_vpp_rx_poll_locked(vdata);
		if (rc <= 0)
			goto out_unlock_rx;
	}
	channel = &vdata->channels[vdata->pending_channel];
	lock_rc = pthread_mutex_lock(&channel->lock);
	if (lock_rc) {
		rc = -lock_rc;
		goto out_unlock_rx;
	}

	frame_length = sizeof(*eth) + channel->pending_rx.packet_length;
	if (frame_length < nic->min_pkt_size)
		frame_length = nic->min_pkt_size;
	if (frame_length > pkt_buf_size) {
		rc = nic_vpp_release_pending_rx(vdata);
		if (!rc)
			rc = -EMSGSIZE;
		goto out_unlock_channel;
	}

	memset(pkt, 0, frame_length);
	memcpy(eth->h_dest, nic->mac_addr, ETH_ALEN);
	eth->h_source[0] = 0x02;
	eth->h_source[3] = 0x50;
	eth->h_source[4] = 0x45;
	eth->h_source[5] = 0x45;
	eth->h_proto = htons((channel->pending_rx.flags &
			      UET_VPP_CLIENT_RX_F_IP6) ?
			     ETH_P_IPV6 : ETH_P_IP);
	for (i = 0; i < channel->pending_rx.iov_count; i++) {
		memcpy((uint8_t *)pkt + offset,
		       channel->pending_rx.iov[i].base,
		       channel->pending_rx.iov[i].length);
		offset += channel->pending_rx.iov[i].length;
	}
	rc = nic_vpp_translate_ids(nic, (uint8_t *)pkt + sizeof(*eth),
				   channel->pending_rx.packet_length, false);
	if (rc) {
		int release_rc = nic_vpp_release_pending_rx(vdata);

		if (release_rc)
			rc = release_rc;
		goto out_unlock_channel;
	}

	rc = nic_vpp_release_pending_rx(vdata);
	if (!rc) {
		*rx_pkt_size = frame_length;
		rc = 1;
	}

out_unlock_channel:
	pthread_mutex_unlock(&channel->lock);
out_unlock_rx:
	pthread_mutex_unlock(&vdata->rx_lock);
	return rc;
}

static int nic_vpp_discard_rx(struct vpp_channel *channel)
{
	int rc;

	if (!channel->rx_pending) {
		rc = uet_vpp_client_poll_rx(channel->client,
					    channel->channel_index,
					    &channel->pending_rx);
		if (rc <= 0)
			return rc;
		channel->rx_pending = true;
	}
	rc = uet_vpp_client_release_rx(channel->client,
				       channel->channel_index,
				       &channel->pending_rx);
	if (!rc)
		channel->rx_pending = false;
	return rc ? rc : 1;
}

void nic_vpp_finalize(struct uet_nic *nic)
{
	struct vpp_data *vdata = nic->nic_priv_data;
	uint64_t deadline = 0, now = 0;
	int drain_error = 0;
	int close_error = 0;
	bool timed = true;

	if (!vdata)
		return;
	if (nic_vpp_monotonic_ns(&now)) {
		timed = false;
		drain_error = -EIO;
	} else {
		deadline = now + UET_VPP_CLOSE_TIMEOUT_NS;
	}
	while (timed && vdata->client && vdata->dma_mapped) {
		bool drained = true;
		bool progressed = false;

		for (size_t i = 0; i < vdata->channel_count; i++) {
			struct vpp_channel *channel = &vdata->channels[i];
			int completion_error = 0;
			int rx_rc, tx_rc;

			tx_rc = nic_vpp_poll_tx(channel, &completion_error);
			if (tx_rc < 0) {
				if (!drain_error)
					drain_error = tx_rc;
				timed = false;
				break;
			}
			progressed |= tx_rc > 0;
			if (completion_error && !drain_error)
				drain_error = completion_error;

			rx_rc = nic_vpp_discard_rx(channel);
			if (rx_rc < 0 && rx_rc != -EAGAIN) {
				if (!drain_error)
					drain_error = rx_rc;
				timed = false;
				break;
			}
			progressed |= rx_rc > 0;
			drained &= !channel->tx_inflight &&
				   !channel->rx_pending && rx_rc == 0;
		}

		if (!timed)
			break;
		if (drained) {
			close_error = uet_vpp_client_close(vdata->client);
			if (!close_error) {
				vdata->client = NULL;
				break;
			}
			if (close_error != -EBUSY)
				break;
		}
		if (nic_vpp_monotonic_ns(&now)) {
			if (!drain_error)
				drain_error = -EIO;
			break;
		}
		if (now >= deadline)
			break;
		if (!progressed)
			usleep(50);
	}
	if (vdata->client) {
		close_error = uet_vpp_client_close(vdata->client);
		if (!close_error)
			vdata->client = NULL;
	}
	if (close_error)
		UET_API_ERR("VPP client close failed: %d", close_error);
	if (drain_error)
		UET_API_ERR("VPP channel-set drain failed: %d", drain_error);
	for (size_t i = 0; i < vdata->channel_count; i++)
		if (vdata->channels[i].lock_initialized)
			pthread_mutex_destroy(&vdata->channels[i].lock);
	if (vdata->rx_lock_initialized)
		pthread_mutex_destroy(&vdata->rx_lock);
	free(vdata->channels);
	free(vdata);
	nic->nic_priv_data = NULL;
}

static int nic_vpp_configure_mtu(struct uet_nic *nic,
				 struct vpp_data *vdata)
{
	const char *text = getenv(UET_VPP_MTU);
	unsigned long long mtu = UET_VPP_DEFAULT_MTU;
	char *end = NULL;

	if (text) {
		errno = 0;
		mtu = strtoull(text, &end, 10);
		if (errno || end == text || *end != '\0' || text[0] == '-')
			return -EINVAL;
	}
	if (mtu < nic->min_ip_pkt_size ||
	    mtu > vdata->info.dma_buffer_data_size)
		return -ERANGE;
	nic->mtu = (size_t)mtu;
	nic->max_pkt_size = nic->mtu + nic->l2_hdr_size;
	return 0;
}

static int nic_vpp_parse_addresses(struct uet_nic *nic)
{
	const char *ipv4_text = getenv(UET_VPP_IPV4_ADDR);
	const char *ipv6_text = getenv(UET_VPP_IPV6_ADDR);
	struct in_addr ipv4;

	if (ipv4_text) {
		if (inet_pton(AF_INET, ipv4_text, &ipv4) != 1)
			return -EINVAL;
		nic->ipv4_addr = ntohl(ipv4.s_addr);
		snprintf(nic->ipv4_addr_str, sizeof(nic->ipv4_addr_str),
			 "%s", ipv4_text);
		nic->has_ipv4 = true;
	}
	if (ipv6_text) {
		if (inet_pton(AF_INET6, ipv6_text, nic->ipv6_addr) != 1)
			return -EINVAL;
		snprintf(nic->ipv6_addr_str, sizeof(nic->ipv6_addr_str),
			 "%s", ipv6_text);
		nic->has_ipv6 = true;
	}
	return (nic->has_ipv4 || nic->has_ipv6) ? 0 : -EINVAL;
}

static void nic_vpp_initialize_cleanup(struct vpp_data *vdata)
{
	if (!vdata)
		return;
	for (size_t i = 0; i < vdata->channel_count; i++) {
		struct vpp_channel *channel = &vdata->channels[i];

		if (channel->lock_initialized)
			pthread_mutex_destroy(&channel->lock);
	}
	if (vdata->client)
		uet_vpp_client_close(vdata->client);
	if (vdata->rx_lock_initialized)
		pthread_mutex_destroy(&vdata->rx_lock);
	free(vdata->channels);
	free(vdata);
}

int nic_vpp_initialize(struct uet_nic *nic)
{
	const char *segment_name = getenv(UET_VPP_SEGMENT);
	const char *dma_socket = getenv(UET_VPP_DMA_SOCKET);
	const char *ifname = getenv(UET_IFNAME);
	const char *pds = getenv(UET_PDS);
	struct vpp_data *vdata;
	int rc;

	if (!segment_name || !dma_socket) {
		UET_API_ERR("%s and %s are required for the VPP shim",
			    UET_VPP_SEGMENT, UET_VPP_DMA_SOCKET);
		return -EINVAL;
	}
	vdata = calloc(1, sizeof(*vdata));
	if (!vdata)
		return -ENOMEM;
	vdata->pds_sng = !pds || strcmp(pds, "sng") == 0;
	atomic_init(&vdata->rudi_last_sequence_plus_one, 0);
	vdata->pending_channel = SIZE_MAX;
	rc = uet_vpp_client_open(&vdata->client, segment_name,
				 &vdata->info);
	if (rc) {
		UET_API_ERR("could not open VPP channel-set %s: %d",
			    segment_name, rc);
		goto err_cleanup;
	}
	rc = uet_vpp_client_set_pds_sng(vdata->client, vdata->pds_sng);
	if (rc)
		goto err_cleanup;
	if (!vdata->info.channel_count ||
	    vdata->info.channel_count > UET_VPP_MAX_CHANNELS) {
		rc = -EPROTO;
		goto err_cleanup;
	}
	vdata->channel_count = vdata->info.channel_count;
	if (!vdata->info.client_namespace ||
	    vdata->info.client_namespace > UET_VPP_CLIENT_NAMESPACE_MAX) {
		rc = -EPROTO;
		goto err_cleanup;
	}
	rc = uet_vpp_client_map_dma(vdata->client, dma_socket);
	if (rc)
		goto err_cleanup;
	vdata->dma_mapped = true;
	rc = posix_memalign((void **)&vdata->channels,
			    UET_VPP_CHANNEL_ALIGNMENT,
			    vdata->channel_count * sizeof(*vdata->channels));
	if (rc) {
		rc = rc == ENOMEM ? -ENOMEM : -EINVAL;
		goto err_cleanup;
	}
	memset(vdata->channels, 0,
	       vdata->channel_count * sizeof(*vdata->channels));
	rc = pthread_mutex_init(&vdata->rx_lock, NULL);
	if (rc)
		goto err_cleanup;
	vdata->rx_lock_initialized = true;
	for (size_t i = 0; i < vdata->channel_count; i++) {
		struct vpp_channel *channel = &vdata->channels[i];

		rc = pthread_mutex_init(&channel->lock, NULL);
		if (rc)
			goto err_cleanup;
		channel->lock_initialized = true;
		channel->client = vdata->client;
		channel->channel_index = (uint32_t)i;
		channel->next_request_id = (uint64_t)i << 56;
	}

	nic->nic_priv_data = vdata;
	nic->min_pkt_size = UET_MIN_PKT_SIZE;
	nic->l2_hdr_size = sizeof(struct ethhdr);
	nic->min_ip_pkt_size = nic->min_pkt_size - nic->l2_hdr_size;
	rc = nic_vpp_configure_mtu(nic, vdata);
	if (rc) {
		UET_API_ERR("%s must be between %zu and %u (default %u)",
			    UET_VPP_MTU, nic->min_ip_pkt_size,
			    vdata->info.dma_buffer_data_size,
			    UET_VPP_DEFAULT_MTU);
		goto err_finalize;
	}
	nic->sock_fd = -1;
	snprintf(nic->network_type, sizeof(nic->network_type), "%s",
		 UET_NETWORK_TYPE_VPP);
	snprintf(nic->ifname, sizeof(nic->ifname), "%s",
		 ifname ? ifname : "vpp0");
	nic->mac_addr[0] = 0x02;
	nic->mac_addr[3] = 0x55;
	nic->mac_addr[4] = 0x45;
	nic->mac_addr[5] = 0x54;
	uet_mac_addr_to_str(nic->mac_addr_str, nic->mac_addr);
	rc = nic_vpp_parse_addresses(nic);
	if (rc) {
		UET_API_ERR("set %s and/or %s for the VPP shim",
			    UET_VPP_IPV4_ADDR, UET_VPP_IPV6_ADDR);
		goto err_finalize;
	}
	return 0;

err_finalize:
	nic_vpp_finalize(nic);
	return rc;
err_cleanup:
	if (rc > 0)
		rc = -rc;
	nic_vpp_initialize_cleanup(vdata);
	return rc;
}

#endif /* ENABLE_VPP */
