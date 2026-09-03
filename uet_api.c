/*
 * Copyright (c) 2024,2025,2026 Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/*
 * Reference implementation of UET APIs over simple reliable
 * datagram protocol
 *
 * The simple reliable datagram protocol is being used to enable
 * software development progress and will eventually be replaced by a
 * software implementation of the real UET protocol once the
 * specification matures.
 *
 * Characteristics of the current implementation include:
 *   - support for a single network interface, defined by the UET_IFNAME
 *     environment variable
 *   - support for one endpoint per process
 *   - support for a single address vector space
 *   - support for synchronous control operations
 *   - support for 1 send completion queue and 1 receive completion
 *     queue per endpoint
 *   - support for ipv4 and ipv6
 *   - no support for selective completion
 *   - manual progress required
 *   - FI_TRANSMIT_COMPLETE and FI_DELIVERY_COMPLETE are the only transmit
 *     completion semantics supported
 *   - minimal precautions taken to make code thread safe
 *   - does not perform extensive error checking
 *   - not designed for high performance
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include "uet_addr.h"
#include "uet_pkt_hdr.h"
#include "uet_api.h"
#include "uet_util.h"
#include "uet_sec.h"
#include "uet_pds.h"
#include "uet_api_private.h"
#include "imp_shim.h"

#define UET_NO_TAG                0
#define UET_NO_IGNORE_BITS        0
#define UET_NO_IMM_DATA           NULL
#define UET_NO_REMOTE_MEM_ADDR    0
#define UET_NO_REMOTE_KEY         0

static size_t scatter_flat_to_iov(const struct iovec *iov, size_t iov_count,
				  const void *payload, size_t payload_len,
				  size_t payload_offset);
static size_t gather_iov_to_flat(const struct iovec *iov, size_t iov_count,
				 void *dst, size_t len, size_t offset);
static inline bool uet_mr_is_scattered(const struct uet_mr_desc *mr_desc);
static bool uet_mr_addr_to_offset(const struct uet_mr_desc *mr_desc,
				  uint64_t addr, size_t len, size_t *offset);
static size_t uet_seg_total_len(const struct uet_mr_seg *seg, size_t seg_count);
static bool uet_seg_validate(const struct uet_mr_seg *seg, size_t seg_count);
static size_t scatter_flat_to_seg(const struct uet_mr_seg *seg,
				  size_t seg_count, const void *payload,
				  size_t payload_len, size_t payload_offset);
static size_t gather_seg_to_flat(const struct uet_mr_seg *seg,
				 size_t seg_count, void *dst, size_t len,
				 size_t offset);
static size_t uet_mr_scatter(const struct uet_mr_desc *mr_desc, size_t offset,
			     const void *src, size_t len);
static size_t uet_mr_gather(const struct uet_mr_desc *mr_desc, size_t offset,
			    void *dst, size_t len);
static void *uet_mr_atomic_addr(const struct uet_mr_desc *mr_desc,
				size_t offset, size_t len);
static void *uet_rx_desc_cq_buf(const struct uet_rx_desc *rx_desc);

/* receive api types */
typedef enum {
	UET_RECV_API,
	UET_TRECV_API,
} uet_recv_api_t;

/* send request api types */
typedef enum {
	UET_SEND_API,
	UET_TSEND_API,
	UET_WRITE_API,
	UET_WRITE_SYNC_API,
	UET_READ_API,
	UET_ATOMIC_API,
	UET_ATOMIC_SYNC_API,
	UET_FETCH_ATOMIC_API,
	UET_COMPARE_ATOMIC_API
} uet_send_req_api_t;

/* init portions of uet address with fabric address */
static void uet_init_uet_addr(struct uet_addr *uet_addr,
			      const struct uet_fa *ip_addr,
			      bool is_ipv6)
{
	uet_addr->ver = UET_ADDR_VERSION;
	uet_addr->flags = (UET_ADDR_FEP_CAP_V     |
			   UET_ADDR_FA_V          |
			   UET_ADDR_RELATIVE_MODE |
			   UET_ADDR_BIG_MSG_SIZE);

	if (is_ipv6)
		uet_addr->flags |= UET_ADDR_IPV6;
	else
		uet_addr->flags |= UET_ADDR_IPV4;

	/* advertise HPC profile so peers may select RUDI (MUST for HPC) */
	uet_addr->fep_cap = (UET_FEP_CAP_AI_FULL | UET_FEP_CAP_HPC);

	memcpy(&uet_addr->fa, ip_addr, sizeof(struct uet_fa));
}

/* get pds mode for an endpoint */
static uet_pds_mode_t uet_get_pds_mode(struct uet_ep *uet_ep, bool rma_op)
{
	if (uet_ep->info->tx_attr->msg_order & UET_ORDERING)
			return UET_PDS_MODE_ROD;

	return UET_PDS_MODE_RUD;
}

/*
 * allocate memory region descriptor
 *
 * parms:
 *      uet_dom  - ptr to uet domain struct
 *      mr_index - ptr to location where index of allocated memory region
 *                 descriptor is returned
 *
 * returns:
 *      FI_SUCCESS on success
 *      negative value corresponding to fabric errno on error
 */
static int uet_alloc_mr_desc(struct uet_domain *uet_dom, size_t *mr_index)
{
	size_t cnt, next_mr_index;
	uint8_t *state, prev_state;

	next_mr_index = uet_dom->mr_desc_alloc_cb.next_mr_index;
	for (cnt = 0, state = &uet_dom->mr_desc_alloc_cb.state[next_mr_index];
	     cnt < uet_dom->num_mr; cnt++) {
		prev_state = __atomic_exchange_n(
				state, UET_MR_DESC_ALLOCATED, __ATOMIC_SEQ_CST);
		if (prev_state == UET_MR_DESC_AVAILABLE) {
			*mr_index = next_mr_index;
			if ((next_mr_index + 1) == uet_dom->num_mr)
				uet_dom->mr_desc_alloc_cb.next_mr_index = 0;
			else
				uet_dom->mr_desc_alloc_cb.next_mr_index =
							      next_mr_index + 1;
			return FI_SUCCESS;
		}
		if (++next_mr_index == uet_dom->num_mr)
			next_mr_index = 0;
		state = &uet_dom->mr_desc_alloc_cb.state[next_mr_index];
	}

	UET_API_ERR("Mem Region Descriptor Unavailable");
	return -FI_EBUSY;
}

/*
 * allocate memory region descriptor with index in range of optimized format
 *
 * parms:
 *      uet_dom  - ptr to uet domain struct
 *      mr_index - ptr to location where index of allocated memory region
 *                 descriptor is returned
 *
 * returns:
 *      FI_SUCCESS on success
 *      negative value corresponding to fabric errno on error
 */
static int uet_alloc_opt_mr_desc(struct uet_domain *uet_dom, size_t *mr_index)
{
	size_t cnt, max_index, next_mr_index;
	uint8_t *state, prev_state;

	next_mr_index = uet_dom->mr_desc_alloc_cb.next_opt_mr_index;

	if (uet_dom->num_mr <= UET_MR_KEY_OPTIMIZED_MAX_RKEY)
		max_index = uet_dom->num_mr - 1;
	else
		max_index = UET_MR_KEY_OPTIMIZED_MAX_RKEY;

	for (cnt = 0, state = &uet_dom->mr_desc_alloc_cb.state[next_mr_index];
	     cnt <= max_index; cnt++) {
		prev_state = __atomic_exchange_n(
				state, UET_MR_DESC_ALLOCATED, __ATOMIC_SEQ_CST);
		if (prev_state == UET_MR_DESC_AVAILABLE) {
			*mr_index = next_mr_index;
			if (next_mr_index == max_index)
				uet_dom->mr_desc_alloc_cb.next_opt_mr_index = 0;
			else
				uet_dom->mr_desc_alloc_cb.next_opt_mr_index =
							      next_mr_index + 1;
			return FI_SUCCESS;
		}
		if (next_mr_index == max_index)
			next_mr_index = 0;
		else
			next_mr_index++;
		state = &uet_dom->mr_desc_alloc_cb.state[next_mr_index];
	}

	UET_API_ERR("Optimized Mem Region Descriptor Unavailable");
	return -FI_EBUSY;
}

/*
 * deallocate memory region descriptor
 *
 * parms:
 *      uet_dom  - ptr to uet domain struct
 *      mr_index - index of memory region descriptor to be deallocated
 */
static void uet_dealloc_mr_desc(struct uet_domain *uet_dom,
				struct uet_mr_desc *mr_desc)
{
	size_t offset;
	size_t mr_index;

	if ((mr_desc->state != UET_MR_DESC_STATE_INACTIVE) &&
	    (mr_desc->buf_desc.type == UET_MR_BUF_TYPE_IOV))
		free((void *)mr_desc->buf_desc.iov.iov);

	memset(mr_desc, 0, sizeof(*mr_desc));
	mr_desc->state = UET_MR_DESC_STATE_INACTIVE;

	offset = ((uint8_t *) mr_desc) - ((uint8_t *) uet_dom->mr_desc);
	mr_index = offset / sizeof(struct uet_mr_desc);
	uet_dom->mr_desc_alloc_cb.state[mr_index] = UET_MR_DESC_AVAILABLE;
}

/*
 * allocate sync group
 *
 * parms:
 *      uet      - ptr to uet instance struct
 *      sync_grp - ptr to location where allocated sync group is returned
 *
 * returns:
 *      FI_SUCCESS on success
 *      negative value corresponding to fabric errno on error
 */
static int uet_alloc_sync_grp(struct uet_instance *uet, uint16_t *sync_grp)
{
	int cnt;
	uint16_t next_sync_grp;
	uint8_t *state, prev_state;

	next_sync_grp = uet->sync_grp_cb.next_sync_grp;
	for (cnt = 0, state = &uet->sync_grp_cb.state[next_sync_grp];
	     cnt <= UET_MAX_SYNC_GRP; cnt++) {
		prev_state = __atomic_exchange_n(
			state, UET_SYNC_GRP_ALLOCATED, __ATOMIC_SEQ_CST);
		if (prev_state == UET_SYNC_GRP_AVAILABLE) {
			*sync_grp = next_sync_grp;
			uet->sync_grp_cb.next_sync_grp = next_sync_grp + 1;
			if (uet->sync_grp_cb.next_sync_grp > UET_MAX_SYNC_GRP)
				uet->sync_grp_cb.next_sync_grp = 0;
			memset(&uet->sync_grp_cb.cnts[next_sync_grp], 0,
			       sizeof(struct uet_sync_grp_cnts));
			return FI_SUCCESS;
		}
		if (++next_sync_grp > UET_MAX_SYNC_GRP)
			next_sync_grp = 0;
		state = &uet->sync_grp_cb.state[next_sync_grp];
	}

	UET_API_ERR("No Sync Group Available");
	return -FI_EBUSY;
}

/*
 * deallocate sync group
 *
 * parms:
 *      uet      - ptr to uet instance struct
 *      sync_grp - sync grp to be deallocated
 */
static void uet_dealloc_sync_grp(struct uet_instance *uet, uint16_t sync_grp)
{
	uet->sync_grp_cb.state[sync_grp] = UET_SYNC_GRP_AVAILABLE;
}

/* init key for sync group av lookup */
static void uet_sync_grp_av_key_init(uint64_t av_handle,
				     struct uet_sync_grp_av_key *key)
{
	memset(key, 0, sizeof(struct uet_sync_grp_av_key));
	key->av_handle = av_handle;
}

/* insert entry in sync group av hash table */
void uet_sync_grp_av_hash_insert(struct uet_ep *uet_ep,
                                 struct uet_sync_grp_av_entry *entry)
{
	HASH_ADD(sync_grp_av_hh, uet_ep->sync_grp_av_hash_table,
		 sync_grp_av_key, sizeof(struct uet_sync_grp_av_key), entry);
}

/* remove entry from sync group av hash table */
static void uet_sync_grp_av_hash_remove(struct uet_ep *uet_ep,
                                        struct uet_sync_grp_av_entry *entry)
{
	HASH_DELETE(sync_grp_av_hh, uet_ep->sync_grp_av_hash_table, entry);
	free(entry);
}

/* remove all entries from sync group av hash table and free associated mem */
static void uet_sync_grp_av_hash_finalize(struct uet_ep *uet_ep)
{
	struct uet_sync_grp_av_entry *current, *tmp;

	HASH_ITER(sync_grp_av_hh, uet_ep->sync_grp_av_hash_table,
		  current, tmp) {
		uet_sync_grp_av_hash_remove(uet_ep, current);
	}
}

/* sync group av hash table lookup */
static struct uet_sync_grp_av_entry *uet_sync_grp_av_hash_lookup(
		struct uet_ep *uet_ep, struct uet_sync_grp_av_key *key)
{
	struct uet_sync_grp_av_entry *sync_grp_av_entry;

	HASH_FIND(sync_grp_av_hh, uet_ep->sync_grp_av_hash_table, key,
		  sizeof(struct uet_sync_grp_av_key), sync_grp_av_entry);

	return sync_grp_av_entry;
}

/* increment current count for sync group at initiator */
static void uet_inc_sync_grp_cur_cnt_initiator(struct uet_instance *uet,
				     	       uint16_t sync_grp)
{
	uet->sync_grp_cb.cnts[sync_grp].cur_cnt++;
}

/* set total count for sync group at initiator */
static void uet_set_sync_grp_tot_cnt_initiator(struct uet_instance *uet,
				               uint16_t sync_grp)
{
	uet->sync_grp_cb.cnts[sync_grp].tot_cnt =
		uet->sync_grp_cb.cnts[sync_grp].cur_cnt;
}

/*
 * get sync group for destination associated with av
 *  - allocate a sync group if one is not already active for av
 *  - active sync groups are maintained in a hash table anchored in
 *    the endpoint
 *
 * parms:
 *      uet_ep            - ptr to uet endpoint struct
 *      av_handle         - handle identifying the av
 *      sync_grp_av_entry - ptr to location where ptr to sync group av entry
 *                          is returned
 *
 * returns:
 *      FI_SUCCESS on success
 *      negative value corresponding to fabric errno on error
 */
static int uet_get_sync_grp_av(struct uet_ep *uet_ep, uint64_t av_handle,
			       struct uet_sync_grp_av_entry **sync_grp_av_entry)
{
	int rc;
	uint16_t new_sync_grp;
	struct uet_sync_grp_av_entry *entry;
	struct uet_sync_grp_av_key key;

	uet_sync_grp_av_key_init(av_handle, &key);
	entry = uet_sync_grp_av_hash_lookup(uet_ep, &key);
	if (entry == NULL) {
		entry = (struct uet_sync_grp_av_entry *)
				calloc(1, sizeof(struct uet_sync_grp_av_entry));
		if (entry == NULL)
			return -FI_ENOMEM;

		rc = uet_alloc_sync_grp(uet_ep->uet_domain->uet, &new_sync_grp);
		if (rc != FI_SUCCESS) {
			free(entry);
			return rc;
		}

		uet_sync_grp_av_key_init(av_handle, &entry->sync_grp_av_key);
		entry->sync_grp = new_sync_grp;
		uet_sync_grp_av_hash_insert(uet_ep, entry);
	}

	uet_inc_sync_grp_cur_cnt_initiator(uet_ep->uet_domain->uet,
				   	   entry->sync_grp);

	*sync_grp_av_entry = entry;

	return FI_SUCCESS;
}

/* free initiator resources associated with sync group */
static void uet_sync_grp_free_initiator(struct uet_ep *uet_ep,
			                uint16_t sync_grp,
			                struct uet_sync_grp_av_entry *entry)
{
	if (entry != NULL)
		uet_sync_grp_av_hash_remove(uet_ep, entry);

	uet_dealloc_sync_grp(uet_ep->uet_domain->uet, sync_grp);
}

/* terminate an active sync group at initiator */
static void uet_sync_grp_end_initiator(struct uet_ep *uet_ep,
			               struct uet_sync_grp_av_entry *entry)
{
	uet_set_sync_grp_tot_cnt_initiator(uet_ep->uet_domain->uet,
					   entry->sync_grp);
	uet_sync_grp_av_hash_remove(uet_ep, entry);
}

/* handle sync group completion at initiator */
static void uet_sync_grp_completion_initiator(struct uet_tx_desc *tx_desc)
{
	struct uet_sync_grp_cnts *sync_grp_cnts;
	struct uet_instance *uet;

	uet = tx_desc->uet_ep->uet_domain->uet;

	sync_grp_cnts = &uet->sync_grp_cb.cnts[tx_desc->sync_grp];
	sync_grp_cnts->cmpl_cnt++;
	if (sync_grp_cnts->cmpl_cnt >= sync_grp_cnts->tot_cnt)
		uet_dealloc_sync_grp(uet, tx_desc->sync_grp);
}

/* init key for sync group src fep lookup at target */
static void uet_sync_grp_src_fep_key_init(uint16_t sync_grp,
					  struct uet_sync_grp_src_fep_key *key,
					  struct uet_parsed_pkt *pp)
{
	memset(key, 0, sizeof(struct uet_sync_grp_src_fep_key));

	if (pp->is_ipv6) {
		key->ipv6_addr = true;
		struct ipv6hdr *ipv6 = (struct ipv6hdr *)pp->ip;
		memcpy(key->src_ip.v6, &ipv6->saddr, UET_IPV6_ADDR_OCTETS);
	} else {
		struct iphdr *ipv4 = (struct iphdr *)pp->ip;
		key->src_ip.v4 = ntohl(ipv4->saddr);
	}

	key->sync_grp = sync_grp;
}

/* insert entry in sync group src fep hash table */
void uet_sync_grp_src_fep_hash_insert(struct uet_ep *uet_ep,
                                      struct uet_sync_grp_src_fep_entry *entry)
{
	time_t now;

	HASH_ADD(sync_grp_src_fep_hh, uet_ep->sync_grp_src_fep_hash_table,
		 sync_grp_src_fep_key, sizeof(struct uet_sync_grp_src_fep_key),
		 entry);
	uet_gettime(&now);
	entry->timeout = now +
			 uet_ep->uet_domain->uet->max_rx_sync_grp_lifetime;
}

/* remove entry from sync group src fep hash table */
static void uet_sync_grp_src_fep_hash_remove(
	struct uet_ep *uet_ep,
	struct uet_sync_grp_src_fep_entry *entry)
{
	HASH_DELETE(sync_grp_src_fep_hh, uet_ep->sync_grp_src_fep_hash_table,
		    entry);
	free(entry);
}

/* remove all entries from sync group src fep hash table and free associated mem */
static void uet_sync_grp_src_fep_hash_finalize(struct uet_ep *uet_ep)
{
	struct uet_sync_grp_src_fep_entry *current, *tmp;

	HASH_ITER(sync_grp_src_fep_hh, uet_ep->sync_grp_src_fep_hash_table,
		  current, tmp) {
		uet_sync_grp_src_fep_hash_remove(uet_ep, current);
	}
}

/* sync group src fep hash table lookup */
static struct uet_sync_grp_src_fep_entry *uet_sync_grp_src_fep_hash_lookup(
		struct uet_ep *uet_ep, struct uet_sync_grp_src_fep_key *key)
{
	struct uet_sync_grp_src_fep_entry *sync_grp_src_fep_entry;

	HASH_FIND(sync_grp_src_fep_hh, uet_ep->sync_grp_src_fep_hash_table, key,
		  sizeof(struct uet_sync_grp_src_fep_key),
		  sync_grp_src_fep_entry);

	return sync_grp_src_fep_entry;
}

/*
 * get sync group entry for src fep
 *  - allocate a sync group entry if one is not already active for src fep
 *  - sync groups are maintained in a hash table anchored in the endpoint
 *
 * parms:
 *      rx_desc - ptr to rx descriptor for message
 *      pp      - ptr to parsed packet struct
 *      new_msg - true => start of new message
 *
 * returns:
 *      UET_RC_OK on success, ptr to sync group entry returned in rx_desc struct
 *      otherwise, ses error code
 */
static int uet_get_sync_grp_src_fep(struct uet_rx_desc *rx_desc,
				    struct uet_parsed_pkt *pp,
				    bool new_msg)
{
	uet_ses_rc_t ses_rc;
	union uet_ses_req *ses;
	struct uet_ses_sync_ext *ext;
	struct uet_sync_grp_src_fep_key key;
	struct uet_sync_grp_src_fep_entry *entry;
	struct uet_ep *uet_ep;
	bool terminating_op = false;
	uint16_t ext_group, ext_cnt;

	uet_ep = rx_desc->uet_ep;

	ses = (union uet_ses_req *) pp->ses;
	ext = &ses->std_sync.ext;
	ext_group = ntohs(ext->group);
	ext_cnt = ntohs(ext->cnt);

	if (ses->std_sync.base.cmn.ver_flags & UET_SES_REQ_FLAG_HD)
		terminating_op = true;

	if (rx_desc->sync_grp_src_fep_entry != NULL) {
		entry = rx_desc->sync_grp_src_fep_entry;
		goto update_cnt;
	}

	uet_sync_grp_src_fep_key_init(ext_group, &key, pp);
	entry = uet_sync_grp_src_fep_hash_lookup(uet_ep, &key);
	if (entry == NULL) {
		entry = (struct uet_sync_grp_src_fep_entry *)
			calloc(1,
			       sizeof(struct uet_sync_grp_src_fep_entry));
		if (entry == NULL) {
			UET_API_ERR("RX: No Sync Group for RMA Write");
			return UET_RC_UNCOR_TRNSNT;
		}

		entry->sync_grp_src_fep_key = key;
		uet_sync_grp_src_fep_hash_insert(uet_ep, entry);
	}

	rx_desc->sync_grp_src_fep_entry = entry;

update_cnt:
	if (terminating_op) {
		if (entry->cnts.tot_cnt) {
			UET_API_ERR("RX: Multiple Terminating Ops for Sync "
				    "Group");
			return UET_RC_OP_VIOLATION;
		}
		if (ext_cnt == 0) {
			UET_API_ERR("RX: Invalid Sync Group Count");
			return UET_RC_OP_VIOLATION;
		}
		entry->cnts.tot_cnt = ext_cnt;
		entry->terminating_rx_desc = rx_desc;
	}

	if (new_msg) {
		if (entry->cnts.tot_cnt &&
		    ((entry->cnts.cur_cnt + 1) > entry->cnts.tot_cnt)) {
			UET_API_ERR("RX: Too Many Messages for Sync Group");
			if (!terminating_op)
				return UET_RC_OP_VIOLATION;

			entry->terminating_err = true;
			entry->terminating_err_code = FI_EIO;
			entry->cnts.tot_cnt = entry->cnts.cur_cnt + 1;
		}
		entry->cnts.cur_cnt++;
	}

	return UET_RC_OK;
}

/*
 * allocate message id
 *
 * parms:
 *      uet    - ptr to uet instance struct
 *      msg_id - ptr to location where allocated message id is returned
 *
 * returns:
 *      FI_SUCCESS on success
 *      negative value corresponding to fabric errno on error
 */
static int uet_alloc_msg_id(struct uet_instance *uet, uint16_t *msg_id)
{
	int cnt;
	uint16_t next_msg_id;
	uint8_t *state, prev_state;

	next_msg_id = uet->msg_id_cb.next_msg_id;
	for (cnt = 0, state = &uet->msg_id_cb.state[next_msg_id];
	     cnt <= UET_MAX_MSG_ID; cnt++) {
		prev_state = __atomic_exchange_n(
				state, UET_MSG_ID_ALLOCATED, __ATOMIC_SEQ_CST);
		if (prev_state == UET_MSG_ID_AVAILABLE) {
			*msg_id = next_msg_id;
			uet->msg_id_cb.next_msg_id = next_msg_id + 1;
			if (uet->msg_id_cb.next_msg_id > UET_MAX_MSG_ID)
				uet->msg_id_cb.next_msg_id = 0;
			return FI_SUCCESS;
		}
		if (++next_msg_id > UET_MAX_MSG_ID)
			next_msg_id = 0;
		state = &uet->msg_id_cb.state[next_msg_id];
	}

	UET_API_ERR("No Msg ID Available");
	return -FI_EBUSY;
}

/*
 * set rx descriptor associated with message id
 *
 * parms:
 *      uet     - ptr to uet instance struct
 *      msg_id  - message id
 *      rx_desc - ptr to rx descriptor
 */
static void uet_set_msg_id_rx_desc(struct uet_instance *uet, uint16_t msg_id,
				   struct uet_rx_desc *rx_desc)
{
	uet->msg_id_cb.rx_desc[msg_id] = rx_desc;
}

/*
 * get rx descriptor associated with message id
 *
 * parms:
 *      uet    - ptr to uet instance struct
 *      msg_id - message id
 *
 * returns:
 *      ptr to rx descriptor
 */
static struct uet_rx_desc *uet_get_msg_id_rx_desc(struct uet_instance *uet,
						  uint16_t msg_id)
{
	return uet->msg_id_cb.rx_desc[msg_id];
}

/*
 * deallocate message id
 *
 * parms:
 *      uet    - ptr to uet instance struct
 *      msg_id - message id to be deallocated
 */
static void uet_dealloc_msg_id(struct uet_instance *uet, uint16_t msg_id)
{
	uet->msg_id_cb.state[msg_id] = UET_MSG_ID_AVAILABLE;
	uet->msg_id_cb.rx_desc[msg_id] = NULL;
}

/* insert entry into list of buffered rtr tx descriptors for an endpoint */
static void uet_tx_desc_buf_rtr_list_insert(struct uet_tx_desc *tx_desc)
{
	if (tx_desc->cq_flags & FI_TAGGED)
		dlist_insert_tail(
			&tx_desc->list_entry,
			&tx_desc->uet_ep->tx_desc_buf_tag_rtr_list_head);
	else
		dlist_insert_tail(
			&tx_desc->list_entry,
			&tx_desc->uet_ep->tx_desc_buf_rtr_list_head);
	tx_desc->uet_ep->num_buf_rtr_list_entries++;
}

/* remove entry from list of buffered rtr tx descriptors for an endpoint */
static void uet_tx_desc_buf_rtr_list_remove(struct uet_tx_desc *tx_desc)
{
	if (tx_desc->desc_flags & UET_TX_DESC_FLAG_RTR_REQ) {
		dlist_remove(&tx_desc->list_entry);
		tx_desc->uet_ep->num_buf_rtr_list_entries--;
	}
}

/* insert entry into list of deferred tx descriptors for an endpoint */
static void uet_tx_desc_defer_list_insert(struct uet_tx_desc *tx_desc)
{
	tx_desc->desc_flags |= UET_TX_DESC_FLAG_IN_DSEND_LIST;
	uet_gettime(&tx_desc->defer_time);
	dlist_insert_tail(&tx_desc->list_entry,
			  &tx_desc->uet_ep->tx_desc_defer_list_head);
}

/* remove entry from list of deferred tx descriptors for an endpoint */
static void uet_tx_desc_defer_list_remove(struct uet_tx_desc *tx_desc)
{
	if (tx_desc->desc_flags & UET_TX_DESC_FLAG_IN_DSEND_LIST) {
		dlist_remove(&tx_desc->list_entry);
		tx_desc->desc_flags &= ~UET_TX_DESC_FLAG_IN_DSEND_LIST;
	}
}

/*
 * allocate transmit restart token for deferred send
 *
 * parms:
 *      uet   - ptr to uet instance struct
 *      token - ptr to location where allocated token is returned
 *
 * returns:
 *      FI_SUCCESS on success
 *      negative value corresponding to fabric errno on error
 */
static int uet_alloc_tx_rtr_token(struct uet_instance *uet, uint16_t *token)
{
	int cnt;
	uint16_t next_token;
	uint8_t *state, prev_state;
	struct uet_tx_rtr_token_cb *cb;

	cb = &uet->tx_rtr_token_cb;
	next_token = cb->next_token;
	for (cnt = 0, state = &cb->state[next_token];
	     cnt <= UET_MAX_RTR_TOKEN; cnt++) {
		prev_state = __atomic_exchange_n(
			state, UET_TX_RTR_TOKEN_ALLOCATED, __ATOMIC_SEQ_CST);
		if (prev_state == UET_TX_RTR_TOKEN_AVAILABLE) {
			*token = next_token;
			cb->next_token = next_token + 1;
			if (cb->next_token > UET_MAX_RTR_TOKEN)
				cb->next_token = 0;
			return FI_SUCCESS;
		}
		if (++next_token > UET_MAX_RTR_TOKEN)
			next_token = 0;
		state = &cb->state[next_token];
	}

	UET_API_ERR("No TX Restart Token Available");
	return -FI_EBUSY;
}

/*
 * init tx rtr token associated data
 *
 * parms:
 *      uet     - ptr to uet instance struct
 *      tx_desc - ptr to tx descriptor
 */
static void uet_init_tx_rtr_token(struct uet_instance *uet,
				  struct uet_tx_desc *tx_desc)
{
	uet->tx_rtr_token_cb.tx_desc[tx_desc->local_rtr_token] = tx_desc;
	uet->tx_rtr_token_cb.uet_ep[tx_desc->local_rtr_token] = tx_desc->uet_ep;
	uet->tx_rtr_token_cb.initiator_id[tx_desc->local_rtr_token] =
					tx_desc->uet_ep->uet_addr.initiator_id;
	tx_desc->desc_flags |= UET_TX_DESC_FLAG_DSEND;
}

/*
 * get tx descriptor associated with restart token
 *
 * parms:
 *      uet   - ptr to uet instance struct
 *      token - restart token
 *
 * returns:
 *      ptr to tx descriptor
 */
static struct uet_tx_desc *uet_get_rtr_token_tx_desc(struct uet_instance *uet,
						     uint16_t token)
{
	return uet->tx_rtr_token_cb.tx_desc[token];
}

/*
 * get ptr to endpoint associated with restart token
 *
 * parms:
 *      uet   - ptr to uet instance struct
 *      token - restart token
 *
 * returns:
 *	ptr to endpoint
 */
static struct uet_ep *uet_get_rtr_token_ep(struct uet_instance *uet,
					   uint16_t token)
{
	return uet->tx_rtr_token_cb.uet_ep[token];
}

/*
 * get initiator id associated with restart token
 *
 * parms:
 *      uet   - ptr to uet instance struct
 *      token - restart token
 *
 * returns:
 *      initiator id
 */
static uint32_t uet_get_rtr_token_initiator(struct uet_instance *uet,
					    uint16_t token)
{
	return uet->tx_rtr_token_cb.initiator_id[token];
}

/*
 * deallocate restart token associated with tx descriptor
 *
 * parms:
 *      tx_desc - ptr to tx descriptor
 */
static void uet_dealloc_tx_rtr_token(struct uet_tx_desc *tx_desc)
{
	struct uet_instance *uet;

	uet = tx_desc->uet_ep->uet_domain->uet;

	if (tx_desc->desc_flags & UET_TX_DESC_FLAG_DSEND) {
		uet_tx_desc_defer_list_remove(tx_desc);
		uet->tx_rtr_token_cb.state[tx_desc->local_rtr_token] =
						UET_TX_RTR_TOKEN_AVAILABLE;
		uet->tx_rtr_token_cb.tx_desc[tx_desc->local_rtr_token] = NULL;
		tx_desc->desc_flags &= ~UET_TX_DESC_FLAG_DSEND;
	}
}

/* allocate next msg sequence number for address vector */
static uint64_t uet_alloc_av_msg_seq_num(struct uet_av_entry *av_entry)
{
	uint64_t seq_num;

	seq_num = __atomic_fetch_add(&av_entry->seq_num, 1,  __ATOMIC_SEQ_CST);
	return seq_num;
}

/* determine if sequence number is next to be transmitted for av */
static bool uet_is_next_av_msg_tx_seq_num(struct uet_av_entry *av_entry,
					  uint64_t seq_num)
{
	return (av_entry->next_tx_seq_num == seq_num);
}

/* increment next msg sequence number for address vector */
static void uet_inc_av_msg_next_tx_seq_num(struct uet_av_entry *av_entry)
{
	__atomic_fetch_add(&av_entry->next_tx_seq_num, 1,  __ATOMIC_SEQ_CST);
}

/* set next transmit sequence number for address vector */
static void uet_set_av_msg_tx_seq_num(struct uet_av_entry *av_entry,
				      uint64_t new_tx_seq_num)
{
	uint64_t next_tx_seq_num;

	while (1) {
		next_tx_seq_num = av_entry->next_tx_seq_num;
		if (new_tx_seq_num < next_tx_seq_num) {
			if (__atomic_compare_exchange_n(
				&av_entry->next_tx_seq_num, &next_tx_seq_num,
				new_tx_seq_num, false, __ATOMIC_SEQ_CST,
				__ATOMIC_SEQ_CST))
				break;
		} else
			break;
	}
}

/* init key for endpoint lookup from packet contents */
static void uet_ep_key_init(struct uet_ep_key *key,
			    struct uet_parsed_pkt *pp)
{
	struct uet_ses_req_std *ses;

	ses = (struct uet_ses_req_std *) pp->ses;

	memset(key, 0, sizeof(struct uet_ep_key));

	if (pp->is_ipv6) {
		key->ipv6_addr = true;
		struct ipv6hdr *ipv6 = (struct ipv6hdr *)pp->ip;
		memcpy(key->ip_addr.v6, &ipv6->daddr, UET_IPV6_ADDR_OCTETS);
	} else {
		struct iphdr *ipv4 = (struct iphdr *)pp->ip;
		key->ip_addr.v4 = ntohl(ipv4->daddr);
	}

	key->pid_on_fep =
		(ntohs(ses->cmn.rsvd_pid_on_fep) & UET_SES_REQ_PID_ON_FEP_MASK)
		>> UET_SES_REQ_PID_ON_FEP_SHIFT;
	key->index =
		(ntohs(ses->cmn.rsvd_res_index) & UET_SES_REQ_RES_INDEX_MASK) >>
		UET_SES_REQ_RES_INDEX_SHIFT;
}

static uint16_t uet_ep_entropy_init(const struct uet_ep *uet_ep)
{
	uint32_t hash = 2166136261U;
	uint16_t entropy;

	hash = (hash ^ uet_ep->uet_addr.pid_on_fep) * 16777619U;
	hash = (hash ^ uet_ep->uet_addr.start_index) * 16777619U;
	hash = (hash ^ uet_ep->uet_addr.initiator_id) * 16777619U;
	hash = (hash ^ uet_ep->job_id) * 16777619U;
	entropy = (uint16_t)(hash ^ (hash >> 16));
	return entropy ? entropy : 1;
}

/* insert entry into ip endpoint hash table */
static void uet_ep_hash_insert(struct uet_ep *uet_ep)
{
	struct uet_instance *uet;

	uet = uet_ep->uet_domain->uet;

	uet_rw_lock(&uet->ep_lkup_lock, UET_RW_LOCK_WR_ACCESS);
	HASH_ADD(ep_hh, uet->ep_hash_table, ep_key,
		 sizeof(struct uet_ep_key), uet_ep);
	uet_rw_unlock(&uet->ep_lkup_lock, UET_RW_LOCK_WR_ACCESS);
}

/* remove entry from ip endpoint hash table */
static void uet_ep_hash_remove(struct uet_ep *uet_ep)
{
	struct uet_instance *uet;

	uet = uet_ep->uet_domain->uet;

	uet_rw_lock(&uet->ep_lkup_lock, UET_RW_LOCK_WR_ACCESS);
	HASH_DELETE(ep_hh, uet->ep_hash_table, uet_ep);
	uet_rw_unlock(&uet->ep_lkup_lock, UET_RW_LOCK_WR_ACCESS);
}

/* remove all entries from ip endpoint hash table and free associated mem */
static void uet_ep_hash_finalize(struct uet_instance *uet)
{
	uet_rw_lock(&uet->ep_lkup_lock, UET_RW_LOCK_WR_ACCESS);
	HASH_CLEAR(ep_hh, uet->ep_hash_table);
	uet_rw_unlock(&uet->ep_lkup_lock, UET_RW_LOCK_WR_ACCESS);
}

/* ip endpoint hash table lookup */
static struct uet_ep *uet_ep_hash_lookup(struct uet_instance *uet,
					      struct uet_ep_key *key)
{
	struct uet_ep *uet_ep;

	uet_rw_lock(&uet->ep_lkup_lock, UET_RW_LOCK_RD_ACCESS);
	HASH_FIND(ep_hh, uet->ep_hash_table, key,
		  sizeof(struct uet_ep_key), uet_ep);
	uet_rw_unlock(&uet->ep_lkup_lock, UET_RW_LOCK_RD_ACCESS);

	return uet_ep;
}

/* init key for rx msg lookup from packet contents */
static void uet_rx_msg_key_init(struct uet_rx_msg_key *key,
				struct uet_parsed_pkt *pp)
{
	struct uet_ses_req_std *ses;

	ses = (struct uet_ses_req_std *) pp->ses;

	memset(key, 0, sizeof(struct uet_rx_msg_key));

	if (pp->is_ipv6) {
		key->ipv6_addr = true;
		struct ipv6hdr *ipv6 = (struct ipv6hdr *)pp->ip;
		memcpy(key->src_ip.v6, &ipv6->saddr, UET_IPV6_ADDR_OCTETS);
	} else {
		struct iphdr *ipv4 = (struct iphdr *)pp->ip;
		key->src_ip.v4 = ntohl(ipv4->saddr);
	}

	key->spdcid = pp->pds_spdcid;
	key->msg_id = ses->cmn.msg_id;
}

/* insert entry into rx msg hash table */
static void uet_rx_msg_hash_insert(struct uet_ep *uet_ep,
				   struct uet_rx_desc *rx_desc)
{
	rx_desc->desc_flags |= UET_RX_DESC_FLAG_IN_HASH_TBL;
	HASH_ADD(msg_hh, uet_ep->rx_msg_hash_table, msg_key,
		 sizeof(struct uet_rx_msg_key), rx_desc);
}

/* remove entry from rx msg hash table */
static void uet_rx_msg_hash_remove(struct uet_ep *uet_ep,
				   struct uet_rx_desc *rx_desc)
{
	if (rx_desc->desc_flags & UET_RX_DESC_FLAG_IN_HASH_TBL) {
		HASH_DELETE(msg_hh, uet_ep->rx_msg_hash_table, rx_desc);
		rx_desc->desc_flags &= ~UET_RX_DESC_FLAG_IN_HASH_TBL;
	}
}

/* remove all entries from rx msg hash table and free associated memory */
static void uet_rx_msg_hash_finalize(struct uet_ep *uet_ep)
{
	HASH_CLEAR(msg_hh, uet_ep->rx_msg_hash_table);
}

/* rx msg hash table lookup */
static struct uet_rx_desc *uet_rx_msg_hash_lookup(struct uet_ep *uet_ep,
						  struct uet_rx_msg_key *key)
{
	struct uet_rx_desc *rx_desc;

	HASH_FIND(msg_hh, uet_ep->rx_msg_hash_table, key,
		  sizeof(struct uet_rx_msg_key), rx_desc);
	return rx_desc;
}

/* init key for hash lookup with {tag, initiator} key from packet contents */
static void uet_tag_initiator_key_init(struct uet_tag_initiator_key *key,
				       struct uet_parsed_pkt *pp)
{
	struct uet_ses_req_std *ses;

	ses = (struct uet_ses_req_std *) pp->ses;

	memset(key, 0, sizeof(struct uet_tag_initiator_key));
	key->tag = ses->match_bits;
	key->initiator = ses->initiator;
}

/* insert entry into hash table with {tag, initiator} key */
static void uet_tag_initiator_hash_insert(struct uet_ep *uet_ep,
					  struct uet_rx_desc *rx_desc)
{
	HASH_ADD(tag_hh, uet_ep->tag_initiator_hash_table, tag_key,
		 sizeof(struct uet_tag_initiator_key), rx_desc);
}

/* remove entry from hash table with {tag, initiator} key */
static void uet_tag_initiator_hash_remove(struct uet_ep *uet_ep,
					  struct uet_rx_desc *rx_desc)
{
	HASH_DELETE(tag_hh, uet_ep->tag_initiator_hash_table, rx_desc);
}

/* remove all entries from hash table with {tag, initiator} key and */
/* free associated memory                                           */
static void uet_tag_initiator_hash_finalize(struct uet_ep *uet_ep)
{
	HASH_CLEAR(tag_hh, uet_ep->tag_initiator_hash_table);
}

/* hash table lookup for {tag, initiator} key */
static struct uet_rx_desc *uet_tag_initiator_hash_lookup(
		struct uet_ep *uet_ep, struct uet_tag_initiator_key *key)
{
	struct uet_rx_desc *rx_desc;

	HASH_FIND(tag_hh, uet_ep->tag_initiator_hash_table, key,
		  sizeof(struct uet_tag_initiator_key), rx_desc);
	return rx_desc;
}

/* init key for mr lookup from packet contents */
static void uet_mr_key_init(struct uet_mr_key *key, struct uet_parsed_pkt *pp)
{
	struct uet_ses_req_std *ses;

	ses = (struct uet_ses_req_std *) pp->ses;
	key->rkey = ((ntohll(ses->match_bits) & UET_MR_KEY_RKEY_MASK) >>
		     UET_MR_KEY_RKEY_SHIFT);
}

/* insert entry into mr hash table */
static void uet_mr_hash_insert(struct uet_ep *uet_ep,
			       struct uet_mr_desc *mr_desc)
{
	HASH_ADD(mr_hh, uet_ep->mr_hash_table, hash_key,
		 sizeof(struct uet_mr_key), mr_desc);
}

/* remove a single entry from the mr hash table of its endpoint */
static void uet_mr_hash_remove(struct uet_mr_desc *mr_desc)
{
	HASH_DELETE(mr_hh, mr_desc->uet_ep->mr_hash_table, mr_desc);
}

/* remove all entries from mr hash table and free associated memory */
static void uet_mr_hash_finalize(struct uet_ep *uet_ep)
{
	struct uet_mr_desc *current, *tmp;

	HASH_ITER(mr_hh, uet_ep->mr_hash_table, current, tmp) {
		HASH_DELETE(mr_hh, uet_ep->mr_hash_table, current);
		current->state = UET_MR_DESC_STATE_DISABLED_REG;
		current->uet_ep = NULL;
	}
}

/* mr hash table lookup */
static struct uet_mr_desc *uet_mr_hash_lookup(
		struct uet_ep *uet_ep, struct uet_mr_key *key)
{
	struct uet_mr_desc *mr_desc;

	HASH_FIND(mr_hh, uet_ep->mr_hash_table, key,
		  sizeof(struct uet_mr_key), mr_desc);
	return mr_desc;
}

/* initialize ring */
static int uet_ring_init(struct uet_ring *ring, size_t entry_size,
			 size_t num_entries)
{
	ring->base = calloc(num_entries+1, entry_size);
	if (ring->base == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		return -FI_ENOMEM;
	}

	ring->num_entries = num_entries+1;
	ring->entry_size = entry_size;
	ring->head = 0;
	ring->tail = 0;
	return FI_SUCCESS;
}

/* advance head index of ring */
static void uet_ring_head_advance(struct uet_ring *ring)
{
	ring->head++;
	if (ring->head == ring->num_entries)
		ring->head = 0;
}

/* advance tail index */
static void uet_ring_tail_advance(struct uet_ring *ring)
{
	ring->tail++;
	if (ring->tail == ring->num_entries)
		ring->tail = 0;
}

/* get number of entries in a ring */
static ssize_t uet_ring_entry_cnt(struct uet_ring *ring)
{
	if (ring->head >= ring->tail)
		return (ring->head - ring->tail);
	return (ring->num_entries - (ring->tail - ring->head));
}

/* determine if ring is empty */
static bool uet_ring_empty(struct uet_ring *ring)
{
	return (uet_ring_entry_cnt(ring) == 0);
}

/* free ring entries memory */
static void uet_ring_free_entries(struct uet_ring *ring)
{
	if (ring->base != NULL) {
		free(ring->base);
		ring->base = NULL;
	}
}

/* insert entry in rx descriptor ring of an endpoint */
static void uet_rx_desc_ring_insert(struct uet_rx_desc *rx_desc)
{
	struct uet_ring *ring;
	struct uet_rx_desc_ring_entry *entry;

	ring = &rx_desc->uet_ep->rx_ring;
	entry = &(((struct uet_rx_desc_ring_entry *) (ring->base))[ring->head]);
	entry->rx_desc = rx_desc;
	uet_ring_head_advance(ring);
}

/* remove entry from rx descriptor ring */
static void uet_rx_desc_ring_remove(struct uet_rx_desc *rx_desc)
{
	uet_ring_tail_advance(&rx_desc->uet_ep->rx_ring);
}

/* insert entry in tx descriptor ring of an endpoint */
static void uet_tx_desc_ring_insert(struct uet_tx_desc *tx_desc)
{
	struct uet_ring *ring;
	struct uet_tx_desc_ring_entry *entry;

	tx_desc->state = UET_TX_DESC_STATE_ACTIVE;

	ring = &tx_desc->uet_ep->tx_ring;
	entry = &(((struct uet_tx_desc_ring_entry *) (ring->base))[ring->head]);
	entry->tx_desc = tx_desc;
	uet_ring_head_advance(ring);
}

/* remove entry from tx descriptor ring */
static void uet_tx_desc_ring_remove(struct uet_tx_desc *tx_desc)
{
	uet_ring_tail_advance(&tx_desc->uet_ep->tx_ring);
}

/* move entry at tail of tx descriptor ring to head */
static void uet_tx_desc_ring_rotate(struct uet_tx_desc *tail_tx_desc)
{
	struct uet_ep *uet_ep;
	struct uet_ring *ring;
	struct uet_tx_desc_ring_entry *head;

	uet_ep = tail_tx_desc->uet_ep;
	ring = &uet_ep->tx_ring;

	head = &(((struct uet_tx_desc_ring_entry *) (ring->base))[ring->head]);
	head->tx_desc = tail_tx_desc;
	uet_ring_tail_advance(ring);
	uet_ring_head_advance(ring);
}

/* insert entry into list of available rx descriptors for an endpoint */
static void uet_rx_desc_list_insert(struct uet_rx_desc *rx_desc)
{
	rx_desc->desc_flags = UET_RX_DESC_FLAG_NONE;
	dlist_insert_head(&rx_desc->list_entry,
			  &rx_desc->uet_ep->rx_desc_list_head);
}

/* remove entry from head of available rx descriptors list */
static struct uet_rx_desc *uet_rx_desc_list_pop(struct uet_ep *uet_ep)
{
	struct uet_rx_desc *rx_desc;

	if (dlist_empty(&uet_ep->rx_desc_list_head))
		return NULL;

	rx_desc = container_of(uet_ep->rx_desc_list_head.next,
			       struct uet_rx_desc, list_entry);
	dlist_remove(uet_ep->rx_desc_list_head.next);
	return rx_desc;
}

/* insert entry into list of active rx descriptors for an endpoint */
static void uet_rx_desc_active_list_insert(struct uet_rx_desc *rx_desc)
{
	rx_desc->desc_flags |= UET_RX_DESC_FLAG_ACTIVE;
	uet_gettime(&rx_desc->prev_pkt_time);
	dlist_insert_tail(&rx_desc->list_entry,
			  &rx_desc->uet_ep->rx_desc_active_list_head);
}

/* move entry to tail of active rx descriptors list */
static void uet_rx_desc_active_list_move_to_tail(struct uet_ep *uet_ep,
						 struct uet_rx_desc *rx_desc)
{
	dlist_remove(&rx_desc->list_entry);
	uet_gettime(&rx_desc->prev_pkt_time);
	dlist_insert_tail(&rx_desc->list_entry,
			  &uet_ep->rx_desc_active_list_head);
}

/* remove entry from active rx descriptors list */
static void uet_rx_desc_active_list_remove(struct uet_rx_desc *rx_desc)
{
	if (rx_desc->desc_flags & UET_RX_DESC_FLAG_ACTIVE) {
		dlist_remove(&rx_desc->list_entry);
		rx_desc->desc_flags &= ~UET_RX_DESC_FLAG_ACTIVE;
	}
}

/* prepare rx descriptor for reuse */
static void uet_rx_desc_recycle(struct uet_rx_desc *rx_desc,
				bool make_desc_available)
{
	/* remove rx descriptor from active list */
	uet_rx_desc_active_list_remove(rx_desc);

	/* remove rx descriptor from lookup table */
	uet_rx_msg_hash_remove(rx_desc->uet_ep, rx_desc);

	/* insert rx descriptor on available list */
	if (make_desc_available)
		uet_rx_desc_list_insert(rx_desc);
}

/* insert entry into list of available tx descriptors for an endpoint */
static void uet_tx_desc_list_insert(struct uet_tx_desc *tx_desc)
{
	/* release a read-response buffer gathered from a scattered memory
	 * region before the flags that record its ownership are cleared
	 */
	if (tx_desc->desc_flags & UET_TX_DESC_FLAG_OWNS_BUF) {
		free(tx_desc->buf_desc.buf);
		tx_desc->buf_desc.buf = NULL;
	}

	/* likewise a segment list this descriptor copied for itself */
	if (tx_desc->desc_flags & UET_TX_DESC_FLAG_OWNS_SEG) {
		free(tx_desc->buf_desc.seg.seg);
		tx_desc->buf_desc.seg.seg = NULL;
		tx_desc->buf_desc.seg.seg_count = 0;
	}

	tx_desc->state = UET_TX_DESC_STATE_INACTIVE;
	tx_desc->desc_flags = UET_TX_DESC_FLAG_NONE;
	tx_desc->pkt_cnt = 0;
	dlist_insert_head(&tx_desc->list_entry,
			  &tx_desc->uet_ep->tx_desc_list_head);
}

/* remove entry from head of available tx descriptors list */
static struct uet_tx_desc *uet_tx_desc_list_pop(struct uet_ep *uet_ep)
{
	struct uet_tx_desc *tx_desc;

	if (dlist_empty(&uet_ep->tx_desc_list_head))
		return NULL;

	tx_desc = container_of(uet_ep->tx_desc_list_head.next,
			       struct uet_tx_desc, list_entry);
	dlist_remove(uet_ep->tx_desc_list_head.next);
	return tx_desc;
}

/* prepare tx descriptor for reuse */
static void uet_tx_desc_recycle(struct uet_tx_desc *tx_desc,
				bool make_desc_available)
{
	/* clean up any associated rx descriptor */
	if (tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_REQ)
		uet_rx_desc_recycle(tx_desc->rx_desc, true);

	/* remove descriptor from tx ring */
	uet_tx_desc_ring_remove(tx_desc);

	/* deallocate msg id associated with descriptor */
	if (tx_desc->desc_flags & UET_TX_DESC_FLAG_MSG_ID_ALLOCATED) {
		tx_desc->desc_flags &= ~UET_TX_DESC_FLAG_MSG_ID_ALLOCATED;
		uet_dealloc_msg_id(tx_desc->uet_ep->uet_domain->uet,
				   tx_desc->msg_id);
	}

	/* deallocate restart token associated with descriptor */
	if (tx_desc->desc_flags & UET_TX_DESC_FLAG_DSEND)
		uet_dealloc_tx_rtr_token(tx_desc);

	/* insert tx descriptor on available list */
	if (make_desc_available)
		uet_tx_desc_list_insert(tx_desc);
}

/* insert entry into list of memory regions for an endpoint */
static void uet_mr_list_insert(struct uet_mr_desc *mr_desc)
{
	dlist_insert_head(&mr_desc->list_entry,
			  &mr_desc->uet_ep->mr_list_head);
}

/* remove a single entry from the memory region list of its endpoint */
static void uet_mr_list_remove(struct uet_mr_desc *mr_desc)
{
	dlist_remove(&mr_desc->list_entry);
}

/* remove entry from head of memory region list */
static struct uet_mr_desc *uet_mr_list_pop(struct uet_ep *uet_ep)
{
	struct uet_mr_desc *mr_desc;

	if (dlist_empty(&uet_ep->mr_list_head))
		return NULL;

	mr_desc = container_of(uet_ep->mr_list_head.next,
			       struct uet_mr_desc, list_entry);
	dlist_remove(uet_ep->mr_list_head.next);
	return mr_desc;
}

/* remove all entries from memory region list of endpoint */
static void uet_mr_list_finalize(struct uet_ep *uet_ep)
{
	struct uet_mr_desc *mr_desc;

	while ((mr_desc = uet_mr_list_pop(uet_ep)) != NULL) {
		mr_desc->state = UET_MR_DESC_STATE_DISABLED_REG;
		mr_desc->uet_ep = NULL;
	}
}

/* free descriptor ring resources associated with an endpoint */
static void uet_desc_ring_free(struct uet_ep *uet_ep)
{
	uet_ring_free_entries(&uet_ep->rx_ring);
	uet_ring_free_entries(&uet_ep->tx_ring);
}

/* free descriptor resources associated with an endpoint */
static void uet_desc_free(struct uet_ep *uet_ep)
{
	size_t i;
	struct uet_tx_desc *tx_desc;
	struct uet_rx_desc *rx_desc;
	struct iovec *iov;

	if (uet_ep == NULL)
		return;

	if (uet_ep->rx_desc) {
		for (i = 0; i < uet_ep->num_rx_desc; i++) {
			rx_desc = &uet_ep->rx_desc[i];
			/* Only release a vector this descriptor owns - an rma
			 * descriptor borrows the vector from the target memory
			 * region, which frees it with the domain.
			 */
			if (rx_desc->desc_flags & UET_RX_DESC_FLAG_OWNS_IOV) {
				iov = (struct iovec *)rx_desc->buf_desc.iov.iov;
				if (iov)
					free(iov);
			}

			if (rx_desc->desc_flags & UET_RX_DESC_FLAG_OWNS_SEG)
				free(rx_desc->buf_desc.seg.seg);
		}
		free(uet_ep->rx_desc);
	}

	if (uet_ep->tx_desc) {
		for (i = 0; i < uet_ep->num_tx_desc; i++) {
			tx_desc = &uet_ep->tx_desc[i];

			if (tx_desc->buf_desc.type == UET_MSG_BUF_TYPE_IOV) {
				iov = (struct iovec *)
					(tx_desc->buf_desc.iov.iov);
				if (iov)
					free(iov);
			} else if (tx_desc->buf_desc.type ==
				   UET_MSG_BUF_TYPE_SEG) {
				free(tx_desc->buf_desc.seg.seg);
			}

			if (tx_desc->desc_flags &
			    UET_TX_DESC_FLAG_MSG_ID_ALLOCATED)
				uet_dealloc_msg_id(uet_ep->uet_domain->uet,
						   tx_desc->msg_id);

			uet_dealloc_tx_rtr_token(tx_desc);
			uet_tx_desc_buf_rtr_list_remove(tx_desc);
		}
		free(uet_ep->tx_desc);
	}

	uet_desc_ring_free(uet_ep);
}

/* insert entry into list of endpoints */
static void uet_ep_insert(struct uet_ep *uet_ep)
{
	uet_rw_lock(&uet_ep->uet_domain->ep_lock, UET_RW_LOCK_WR_ACCESS);
	dlist_insert_head(&uet_ep->ep_list_entry,
			  &uet_ep->uet_domain->ep_list_head);
	uet_rw_unlock(&uet_ep->uet_domain->ep_lock, UET_RW_LOCK_WR_ACCESS);
}

/* determine if there is send completion q associated with endpoint */
static bool uet_ep_has_send_cq(struct uet_ep *uet_ep)
{
	if (uet_ep->send_cq.ring.base != NULL)
		return true;
	return false;
}

/* determine if a recv completion q is associated with endpoint */
static bool uet_ep_has_recv_cq(struct uet_ep *uet_ep)
{
	if (uet_ep->recv_cq.ring.base != NULL)
		return true;
	return false;
}

/* determine if cq is in error state */
static bool uet_cq_is_err_state(struct uet_ring *ring)
{
	struct uet_cq_ring_entry *ring_entry;

	ring_entry = &(((struct uet_cq_ring_entry *) (ring->base))[ring->tail]);
	return ring_entry->err;
}

/* read an entry from a tx completion queue */
static void uet_tx_cq_read_entry(void *buf, struct uet_ring *ring)
{
	struct uet_cq_ring_entry *ring_entry;
	struct uet_ep *uet_ep;

	ring_entry = &(((struct uet_cq_ring_entry *) (ring->base))[ring->tail]);
	uet_ep = ring_entry->desc.tx->uet_ep;

	memcpy(buf, ring_entry->cq_entry, uet_ep->send_cq.format_size);

	uet_tx_desc_list_insert(ring_entry->desc.tx);

	uet_ring_tail_advance(ring);
}

/* post an entry to a tx completion queue */
static void uet_tx_cq_post_entry(struct uet_tx_desc *tx_desc)
{
	struct uet_ep *uet_ep;
	struct uet_cq *cq;
	struct uet_ring *ring;
	struct uet_av_entry *av_entry;
	struct uet_cq_ring_entry *ring_entry;
	struct fi_cq_tagged_entry *cq_entry;

	uet_ep = tx_desc->uet_ep;
	cq = &uet_ep->send_cq;
	ring = &cq->ring;

	if (tx_desc->desc_flags & UET_TX_DESC_FLAG_SYNC_REQ)
		uet_sync_grp_completion_initiator(tx_desc);

	if ((tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_RSP) ||
	    (tx_desc->desc_flags & UET_TX_DESC_FLAG_RTR_REQ)) {
		uet_tx_desc_recycle(tx_desc, true);
		return;
	}

	av_entry = (struct uet_av_entry *) tx_desc->dst_addr_handle;
	if (tx_desc->pds_mode == UET_PDS_MODE_ROD)
		uet_inc_av_msg_next_tx_seq_num(av_entry);

	uet_ep->num_active_sends--;
	av_entry->num_active_ops--;

	if (!(tx_desc->desc_flags & UET_TX_DESC_FLAG_POST_CQ)) {
		uet_tx_desc_recycle(tx_desc, true);
		return;
	}

	ring_entry = &(((struct uet_cq_ring_entry *) (ring->base))[ring->head]);
	memset(ring_entry, 0, ring->entry_size);
	ring_entry->desc.tx = tx_desc;

	cq_entry = (struct fi_cq_tagged_entry *) ring_entry->cq_entry;
	cq_entry->op_context = tx_desc->context;
	if (cq->format_size > sizeof(struct fi_cq_entry))
		cq_entry->flags = tx_desc->cq_flags;

	uet_tx_desc_recycle(tx_desc, false);

	uet_ring_head_advance(ring);
}

/* set error for tx descriptor */
static void uet_tx_desc_set_err(struct uet_tx_desc *tx_desc, int err_code,
				uet_tx_desc_state_t desc_state)
{
	tx_desc->err_code = err_code;
	tx_desc->state = desc_state;
}

/* initiate message retransmission */
static int uet_retx_msg(struct uet_tx_desc *tx_desc, bool delay_retx)
{
	uint32_t max_retx;
	time_t backoff_range, backoff_delta;
	struct uet_av_entry *av_entry;

	/* check for max retransmits */
	tx_desc->retransmit_cnt++;
	max_retx = tx_desc->uet_ep->uet_domain->uet->max_msg_retransmits;
	if ((max_retx != UET_MSG_RETRANSMIT_MAX_INFINITY) &&
	    (tx_desc->retransmit_cnt > max_retx)) {
		uet_tx_desc_set_err(tx_desc, FI_EIO,
				    UET_TX_DESC_STATE_ERR_COMPLETE);
		return -FI_EIO;
	}

	/* set descriptor fields to retransmit message from start */
	tx_desc->remaining_bytes = tx_desc->buf_desc.len;
	tx_desc->transmitted = false;
	tx_desc->buf_desc.buf_off = 0;
	tx_desc->pkt_cnt = 0;

	/* set earliest retransmit time */
	uet_gettime(&tx_desc->tx_time);
	if (delay_retx) {
		if ((max_retx == UET_MSG_RETRANSMIT_MAX_INFINITY) ||
		    (tx_desc->retransmit_cnt == 1)) {
			backoff_range = (tx_desc->backoff_max -
					 tx_desc->backoff_min) + 1;
			backoff_delta = ((time_t) lrand48()) % backoff_range;
			tx_desc->backoff = tx_desc->backoff_min + backoff_delta;
		} else
			/* exponential backoff */
			tx_desc->backoff *= 2;
		tx_desc->tx_time += tx_desc->backoff;
	}

	if (tx_desc->pds_mode == UET_PDS_MODE_ROD) {
		av_entry = (struct uet_av_entry *) tx_desc->dst_addr_handle;
		uet_set_av_msg_tx_seq_num(av_entry, tx_desc->seq_num);
	}

	return FI_SUCCESS;
}

static bool uet_tx_desc_expects_amo_rsp_data(struct uet_tx_desc *tx_desc)
{
	if (tx_desc->desc_flags & (UET_TX_DESC_FLAG_ATOMIC_FETCH_REQ |
				   UET_TX_DESC_FLAG_ATOMIC_COMPARE_REQ)) {
		return true;
	}

	return false;
}

/* tx descriptor state transition */
static void uet_tx_desc_state_transition(struct uet_tx_desc *tx_desc)
{
	int rc;
	struct uet_ep *uet_ep;
	struct uet_pds *pds;

	uet_ep = tx_desc->uet_ep;
	pds = &uet_ep->uet_domain->uet->pds;

	switch (tx_desc->state) {
	case UET_TX_DESC_STATE_ACTIVE:
		if (tx_desc->remaining_bytes || !tx_desc->transmitted)
			break;
		if (tx_desc->unack_pkts)
			tx_desc->state = UET_TX_DESC_STATE_WAIT;
		else {
			if (tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_REQ) {
				if (tx_desc->rx_desc->expected_rd_rsp) {
					tx_desc->state = UET_TX_DESC_STATE_WAIT;
					break;
				}
				pds->downcall.msg_cmpl_ind(
					uet_ep, tx_desc->dst_addr_handle,
					tx_desc->pds_mode, tx_desc->msg_id);
			} else if (uet_tx_desc_expects_amo_rsp_data(tx_desc))
				pds->downcall.msg_cmpl_ind(
					uet_ep, tx_desc->dst_addr_handle,
					tx_desc->pds_mode, tx_desc->msg_id);
			tx_desc->state = UET_TX_DESC_STATE_COMPLETE;
		}
		break;
	case UET_TX_DESC_STATE_WAIT:
		if (tx_desc->unack_pkts == 0) {
			if (tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_REQ) {
				if (tx_desc->rx_desc->expected_rd_rsp)
					break;
				pds->downcall.msg_cmpl_ind(
					uet_ep, tx_desc->dst_addr_handle,
					tx_desc->pds_mode, tx_desc->msg_id);
			} else if (uet_tx_desc_expects_amo_rsp_data(tx_desc))
				pds->downcall.msg_cmpl_ind(
					uet_ep, tx_desc->dst_addr_handle,
					tx_desc->pds_mode, tx_desc->msg_id);
			tx_desc->state = UET_TX_DESC_STATE_COMPLETE;
		}
		break;
	case UET_TX_DESC_STATE_RETX:
		if (tx_desc->unack_pkts)
			break;
		if (tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_REQ) {
			if (tx_desc->rx_desc->expected_rd_rsp)
				break;
			pds->downcall.msg_cmpl_ind(
				uet_ep, tx_desc->dst_addr_handle,
				tx_desc->pds_mode, tx_desc->msg_id);
		} else if (uet_tx_desc_expects_amo_rsp_data(tx_desc))
			pds->downcall.msg_cmpl_ind(
				uet_ep, tx_desc->dst_addr_handle,
				tx_desc->pds_mode, tx_desc->msg_id);
		rc = uet_retx_msg(tx_desc, tx_desc->delay_retx);
		if (rc == FI_SUCCESS)
			tx_desc->state = UET_TX_DESC_STATE_ACTIVE;
		else
			tx_desc->state = UET_TX_DESC_STATE_ERR_COMPLETE;
		break;
	case UET_TX_DESC_STATE_DEFER:
		if (tx_desc->unack_pkts)
			break;
		tx_desc->state = UET_TX_DESC_STATE_RESTART_WAIT;
		break;
	case UET_TX_DESC_STATE_RESTART_WAIT:
		if (!(tx_desc->desc_flags & UET_TX_DESC_FLAG_GOT_RTR))
			break;
		tx_desc->desc_flags &= ~UET_TX_DESC_FLAG_GOT_RTR;
		rc = uet_retx_msg(tx_desc, false);
		if (rc == FI_SUCCESS)
			tx_desc->state = UET_TX_DESC_STATE_ACTIVE;
		else
			tx_desc->state = UET_TX_DESC_STATE_ERR_COMPLETE;
		break;
	case UET_TX_DESC_STATE_ERR:
		if (tx_desc->unack_pkts)
			break;
		if (tx_desc->remaining_bytes) {
			if (!(tx_desc->desc_flags &
			      UET_TX_DESC_FLAG_READ_RSP)) {
				pds->downcall.msg_cmpl_ind(
					uet_ep, tx_desc->dst_addr_handle,
					tx_desc->pds_mode, tx_desc->msg_id);
				tx_desc->remaining_bytes = 0;
			}
		}
		if (tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_REQ) {
			if (tx_desc->rx_desc->expected_rd_rsp) {
				uet_rx_desc_active_list_remove(
					tx_desc->rx_desc);
				tx_desc->rx_desc->expected_rd_rsp = 0;
			}
			pds->downcall.msg_cmpl_ind(
				uet_ep, tx_desc->dst_addr_handle,
				tx_desc->pds_mode, tx_desc->msg_id);
		} else if (uet_tx_desc_expects_amo_rsp_data(tx_desc))
			pds->downcall.msg_cmpl_ind(
				uet_ep, tx_desc->dst_addr_handle,
				tx_desc->pds_mode, tx_desc->msg_id);

		tx_desc->state = UET_TX_DESC_STATE_ERR_COMPLETE;
		break;
	default:
		break;
	}
}

/* post error entry in tx completion queue */
static void uet_tx_cq_post_err(struct uet_tx_desc *tx_desc, int err_code)
{
	struct uet_ep *uet_ep;
	struct uet_cq *cq;
	struct uet_ring *cq_ring;
	struct uet_av_entry *av_entry;
	struct uet_cq_ring_entry *cq_ring_entry;
	struct fi_cq_err_entry *err_entry;

	uet_ep = tx_desc->uet_ep;
	cq = &uet_ep->send_cq;
	cq_ring = &cq->ring;

	if (tx_desc->desc_flags & UET_TX_DESC_FLAG_SYNC_REQ)
		uet_sync_grp_completion_initiator(tx_desc);

	if ((tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_RSP) ||
	    (tx_desc->desc_flags & UET_TX_DESC_FLAG_RTR_REQ)) {
		uet_tx_desc_recycle(tx_desc, true);
		return;
	}

	av_entry = (struct uet_av_entry *) tx_desc->dst_addr_handle;
	if (tx_desc->pds_mode == UET_PDS_MODE_ROD)
		uet_inc_av_msg_next_tx_seq_num(av_entry);

	uet_ep->num_active_sends--;
	av_entry->num_active_ops--;

	cq_ring_entry = &(((struct uet_cq_ring_entry *)
				(cq_ring->base))[cq_ring->head]);
	memset(cq_ring_entry, 0, cq_ring->entry_size);
	cq_ring_entry->err = true;
	cq_ring_entry->desc.tx = tx_desc;

	err_entry = (struct fi_cq_err_entry *) cq_ring_entry->cq_entry;
	err_entry->op_context = tx_desc->context;
	err_entry->flags = tx_desc->cq_flags;
	err_entry->err = err_code;

	uet_tx_desc_recycle(tx_desc, false);

	uet_ring_head_advance(cq_ring);
}

/* read an entry from a rx completion queue */
static void uet_rx_cq_read_entry(void *buf, struct uet_ring *ring)
{
	struct uet_cq_ring_entry *ring_entry;
	struct uet_ep *uet_ep;

	ring_entry = &(((struct uet_cq_ring_entry *) (ring->base))[ring->tail]);
	uet_ep = ring_entry->desc.rx->uet_ep;

	memcpy(buf, ring_entry->cq_entry, uet_ep->recv_cq.format_size);

	/* stash the SourceID so it can be read alongside the completion */
	uet_ep->recv_cq.last_src_id = ring_entry->src_id;

	uet_rx_desc_list_insert(ring_entry->desc.rx);

	uet_ring_tail_advance(ring);
}

static void uet_rx_cq_post_err(struct uet_rx_desc *rx_desc, int err_code);

/* post an entry to a rx completion queue */
static void uet_rx_cq_post_entry(struct uet_rx_desc *rx_desc)
{
	struct uet_ep *uet_ep;
	struct uet_cq *cq;
	struct uet_ring *ring;
	struct uet_cq_ring_entry *ring_entry;
	struct fi_cq_tagged_entry *cq_entry;
	struct uet_sync_grp_src_fep_entry *sync_entry;
	struct uet_rx_desc *terminating_rx_desc;
	bool handle_terminating_desc = false, terminating_err;
	int terminating_err_code;

	uet_ep = rx_desc->uet_ep;

	sync_entry = rx_desc->sync_grp_src_fep_entry;
	if (sync_entry) {
		terminating_rx_desc = sync_entry->terminating_rx_desc;
		sync_entry->cnts.cmpl_cnt++;
		if (sync_entry->cnts.cmpl_cnt == sync_entry->cnts.tot_cnt) {
			if (sync_entry->terminating_atomic) {
				if (!sync_entry->terminating_err)
					/* deferred execution of atomic op,  */
					/* currently, only sum is supported, */
					/* appropriate atomic system call    */
					/* must be used if other ops are     */
					/* supported in the future           */
					__atomic_fetch_add(
						sync_entry->atomic_parms.addr,
						sync_entry->atomic_parms.data,
					 	__ATOMIC_SEQ_CST);
			} else if (terminating_rx_desc &&
				   (terminating_rx_desc != rx_desc)) {
				handle_terminating_desc = true;
				terminating_err = sync_entry->terminating_err;
				terminating_err_code =
					sync_entry->terminating_err_code;
			}
			uet_sync_grp_src_fep_hash_remove(uet_ep, sync_entry);
		} else if (terminating_rx_desc == rx_desc)
			return;
	}

	if (!(rx_desc->desc_flags & UET_RX_DESC_FLAG_POST_CQ)) {
		uet_rx_desc_recycle(rx_desc, true);
		if (handle_terminating_desc) {
			if (terminating_err) {
				uet_rx_cq_post_err(
					terminating_rx_desc,
					terminating_err_code);
				return;
			} else
				rx_desc = terminating_rx_desc;
		} else
			return;
	}

	cq = &uet_ep->recv_cq;
	ring = &cq->ring;

	ring_entry = &(((struct uet_cq_ring_entry *) (ring->base))[ring->head]);
	memset(ring_entry, 0, ring->entry_size);
	ring_entry->desc.rx = rx_desc;
	ring_entry->src_id = rx_desc->src_id;

	cq_entry = (struct fi_cq_tagged_entry *) ring_entry->cq_entry;
	cq_entry->op_context = rx_desc->context;
	if (cq->format_size >= sizeof(struct fi_cq_entry)) {
		cq_entry->flags = rx_desc->cq_flags;
		cq_entry->len = rx_desc->msg_len;
	}
	if (cq->format_size >= sizeof(struct fi_cq_msg_entry)) {
		cq_entry->buf = uet_rx_desc_cq_buf(rx_desc);
		if (rx_desc->desc_flags & UET_RX_DESC_FLAG_WRITE_IMM) {
			cq_entry->data = rx_desc->imm_data;
			cq_entry->flags |= FI_REMOTE_CQ_DATA;
		}
	}
	if ((cq->format_size >= sizeof(struct fi_cq_tagged_entry)) &&
	    (rx_desc->cq_flags & FI_TAGGED))
		cq_entry->tag = ntohll(rx_desc->tag_key.tag);

	uet_rx_desc_recycle(rx_desc, false);

	uet_ring_head_advance(ring);
}

/* post error entry in rx completion queue */
static void uet_rx_cq_post_err(struct uet_rx_desc *rx_desc, int err_code)
{
	struct uet_ep *uet_ep;
	struct uet_cq *cq;
	struct uet_ring *ring;
	struct uet_cq_ring_entry *ring_entry;
	struct fi_cq_err_entry *err_entry;
	struct uet_sync_grp_src_fep_entry *sync_entry;
	struct uet_rx_desc *terminating_rx_desc;
	bool handle_terminating_desc = false, terminating_err;
	int terminating_err_code;

	uet_ep = rx_desc->uet_ep;

	sync_entry = rx_desc->sync_grp_src_fep_entry;
	if (sync_entry) {
		if (!sync_entry->terminating_err) {
			sync_entry->terminating_err = true;
			sync_entry->terminating_err_code = err_code;
		}
		sync_entry->cnts.cmpl_cnt++;
		if (sync_entry->cnts.cmpl_cnt == sync_entry->cnts.tot_cnt) {
			terminating_rx_desc = sync_entry->terminating_rx_desc;
			if (terminating_rx_desc &&
			    (terminating_rx_desc != rx_desc)) {
				handle_terminating_desc = true;
				terminating_err = sync_entry->terminating_err;
				terminating_err_code =
					sync_entry->terminating_err_code;
			}
			uet_sync_grp_src_fep_hash_remove(uet_ep, sync_entry);
		}
	}

	if ((rx_desc->desc_flags & UET_RX_DESC_FLAG_WRITE) ||
	    (rx_desc->desc_flags & UET_RX_DESC_FLAG_ERR_TRACK) ||
	    (rx_desc->desc_flags & UET_RX_DESC_FLAG_DSEND)) {
		uet_rx_desc_recycle(rx_desc, true);
		if (handle_terminating_desc) {
			if (terminating_err) {
				rx_desc = terminating_rx_desc;
				err_code = terminating_err_code;
			} else {
				uet_rx_cq_post_entry(terminating_rx_desc);
				return;
			}
		} else
			return;
	}

	cq = &uet_ep->recv_cq;
	ring = &cq->ring;

	ring_entry = &(((struct uet_cq_ring_entry *) (ring->base))[ring->head]);
	memset(ring_entry, 0, ring->entry_size);
	ring_entry->err = true;
	ring_entry->desc.rx = rx_desc;

	err_entry = (struct fi_cq_err_entry *) ring_entry->cq_entry;
	err_entry->op_context = rx_desc->context;
	err_entry->flags = rx_desc->cq_flags;
	err_entry->err = err_code;
	if (rx_desc->desc_flags & UET_RX_DESC_FLAG_WRITE_IMM)
		err_entry->data = rx_desc->imm_data;
	if (rx_desc->cq_flags & FI_TAGGED)
		err_entry->tag = ntohll(rx_desc->tag_key.tag);
	err_entry->buf = uet_rx_desc_cq_buf(rx_desc);
	uet_rx_desc_recycle(rx_desc, false);

	uet_ring_head_advance(ring);
}

/*
 * buffer address to report on a completion
 *
 * A scattered buffer has no single base address and leaves buf_desc.buf
 * NULL, so report the first entry of the vector (the start of the region's
 * flattened address space) rather than a NULL pointer.
 */
static void *uet_rx_desc_cq_buf(const struct uet_rx_desc *rx_desc)
{
	if ((rx_desc->buf_desc.type == UET_MSG_BUF_TYPE_IOV) &&
	    (rx_desc->buf_desc.iov.iov != NULL) &&
	    (rx_desc->buf_desc.iov.iov_count > 0))
		return rx_desc->buf_desc.iov.iov[0].iov_base;

	if ((rx_desc->buf_desc.type == UET_MSG_BUF_TYPE_MR) &&
	    (rx_desc->mr_desc != NULL) &&
	    (rx_desc->mr_desc->buf_desc.type == UET_MR_BUF_TYPE_IOV) &&
	    (rx_desc->mr_desc->buf_desc.iov.iov != NULL) &&
	    (rx_desc->mr_desc->buf_desc.iov.iov_count > 0))
		return rx_desc->mr_desc->buf_desc.iov.iov[0].iov_base;

	return rx_desc->buf_desc.buf;
}

/* free completion queue resources associated with an endpoint */
static void uet_cq_free(struct uet_ep *uet_ep)
{
	uet_ring_free_entries(&uet_ep->send_cq.ring);
	uet_ring_free_entries(&uet_ep->recv_cq.ring);
}

/* free resources associated with an endpoint */
static void uet_ep_free(struct uet_ep *uet_ep)
{
	struct dlist_entry *item;
	struct uet_pds *pds = &uet_ep->uet_domain->uet->pds;

	uet_rx_msg_hash_finalize(uet_ep);
	uet_tag_initiator_hash_finalize(uet_ep);
	uet_sync_grp_av_hash_finalize(uet_ep);
	uet_sync_grp_src_fep_hash_finalize(uet_ep);

	uet_desc_free(uet_ep);

	uet_cq_free(uet_ep);

	pds->downcall.ep_finalize(uet_ep);

	item = &uet_ep->ep_list_entry;
	uet_rw_lock(&uet_ep->uet_domain->ep_lock, UET_RW_LOCK_WR_ACCESS);
	dlist_remove(item);
	uet_rw_unlock(&uet_ep->uet_domain->ep_lock, UET_RW_LOCK_WR_ACCESS);

	pthread_mutex_destroy(&uet_ep->data_lock);

	free(uet_ep);
	uet_ep = NULL; /* To prevent use after free */
}

/* free resources associated with all endpoints of a domain */
static void uet_ep_free_all(struct uet_domain *uet_dom)
{
	struct dlist_entry *head, *item;
	struct uet_ep *uet_ep;

	head = &uet_dom->ep_list_head;
	dlist_foreach(head, item) {
		uet_ep = container_of(item, struct uet_ep,
				      ep_list_entry);
		dlist_remove(item);
		item = head;
		uet_ep_free(uet_ep);
	}
}

/* insert entry into list of address vector entries for domain */
static void uet_av_entry_insert(struct uet_domain *uet_dom,
				struct uet_av_entry *av_entry)
{
	dlist_insert_head(&av_entry->av_list_entry,
			  &uet_dom->av_list_head);
}

/* free resources associated with an address vector entry */
static void uet_av_entry_free(struct uet_av_entry *av_entry)
{
	struct dlist_entry *item;

	item = &av_entry->av_list_entry;
	dlist_remove(item);
	free(av_entry);
}

/* free resources associated with all address vector entries of a domain */
static void uet_av_free_all(struct uet_domain *uet_dom)
{
	struct dlist_entry *head, *item;
	struct uet_av_entry *av_entry;

	head = &uet_dom->av_list_head;
	dlist_foreach(head, item) {
		av_entry = container_of(item, struct uet_av_entry,
					av_list_entry);
		dlist_remove(item);
		item = head;
		free(av_entry);
	}
}

/* insert entry into list of domains */
static void uet_domain_insert(struct uet_domain *uet_dom)
{
	dlist_insert_head(&uet_dom->domain_list_entry,
			  &uet_dom->uet->domain_list_head);
}

/* determine if there are endpoints associated with a domain */
static bool uet_domain_has_ep(struct uet_domain *uet_dom)
{
	return (!((bool) dlist_empty(&uet_dom->ep_list_head)));
}

/* free resources associated with a domain */
static void uet_domain_free(struct uet_domain *uet_dom)
{
	struct dlist_entry *item;
	size_t i;

	item = &uet_dom->domain_list_entry;
	dlist_remove(item);
	if (uet_dom->mr_desc_alloc_cb.state)
		free(uet_dom->mr_desc_alloc_cb.state);
	if (uet_dom->mr_desc) {
		/* Release the vector of every region that owns one. Only
		 * UET_MR_BUF_TYPE_IOV keeps an allocation here.
		 */
		for (i = 0; i < uet_dom->num_mr; i++) {
			struct uet_mr_desc *mr_desc = &uet_dom->mr_desc[i];

			if (mr_desc->buf_desc.type != UET_MR_BUF_TYPE_IOV)
				continue;

			free((struct iovec *) mr_desc->buf_desc.iov.iov);
			mr_desc->buf_desc.iov.iov = NULL;
		}

		free(uet_dom->mr_desc);
	}
	free(uet_dom);
}

/* free resources associated with all domains */
static void uet_domain_free_all(struct uet_instance *uet)
{
	struct dlist_entry *head, *item;
	struct uet_domain *uet_dom;

	head = &uet->domain_list_head;
	dlist_foreach(head, item) {
		uet_dom = container_of(item, struct uet_domain,
				       domain_list_entry);
		dlist_remove(item);
		item = head;
		uet_ep_free_all(uet_dom);
		uet_av_free_all(uet_dom);
		uet_domain_free(uet_dom);
	}
}

/* free most resources associated with uet instance */
static void uet_finalize_core(struct uet_instance *uet)
{
	uet_sec_finalize();
	uet_ep_hash_finalize(uet);
	imp_shim_finalize();
	uet_nic_finalize(UET_NIC(uet));
	uet_domain_free_all(uet);
	uet->pds.downcall.finalize(uet);
}

/* init rx descriptor used to track errored msg */
static void uet_init_err_rx_desc(
	struct uet_ep *uet_ep, struct uet_parsed_pkt *pp,
	struct uet_rx_desc *rx_desc, uet_ses_rc_t ses_rc)
{
	struct uet_ses_req_std *ses;
	uint32_t req_len;

	ses = (struct uet_ses_req_std *) pp->ses;
	req_len = ntohl(ses->req_len);

	rx_desc->uet_ep = uet_ep;
	rx_desc->ses_rc = ses_rc;
	rx_desc->desc_flags |= UET_RX_DESC_FLAG_ERR_TRACK;
	if (ses_rc == UET_RC_DEFER_SEND)
		rx_desc->desc_flags |= UET_RX_DESC_FLAG_DSEND;
	rx_desc->msg_len = req_len;
	rx_desc->remaining_bytes = req_len;
	uet_rx_desc_active_list_insert(rx_desc);
	uet_rx_msg_key_init(&rx_desc->msg_key, pp);
	uet_rx_msg_hash_insert(uet_ep, rx_desc);
}

/* truncate rx message */
static int uet_rx_msg_truncate(struct uet_parsed_pkt *pp,
			       struct uet_rx_desc *rx_desc,
			       bool *msg_complete)
{
	size_t msg_off, truncated_bytes;
	struct uet_ses_req_std *ses;

	ses = (struct uet_ses_req_std *) pp->ses;

	*msg_complete = false;

	msg_off = ((ntohll(ses->payload_len_msg_off) &
		    UET_SES_REQ_STD_MSG_OFF_MASK) >>
		   UET_SES_REQ_STD_MSG_OFF_SHIFT);
	if (msg_off < rx_desc->msg_len) {
		truncated_bytes = rx_desc->msg_len - msg_off;
		if (truncated_bytes > rx_desc->remaining_bytes)
			return -FI_ETRUNC;
		else if (truncated_bytes == rx_desc->remaining_bytes) {
			rx_desc->remaining_bytes = 0;
			*msg_complete = true;
		} else
			rx_desc->remaining_bytes -= truncated_bytes;
	} else
		return -FI_ETRUNC;

	return FI_SUCCESS;
}

/* handle rx message error */
static uet_ses_rc_t uet_rx_msg_err(
	struct uet_ep *uet_ep, struct uet_parsed_pkt *pp,
	struct uet_rx_desc *rx_desc, uet_ses_rc_t ses_rc)
{
	int rc;
	bool msg_complete;
	struct uet_ses_req_std *ses;

	ses = (struct uet_ses_req_std *) pp->ses;

	if (rx_desc == NULL) {
		rx_desc = uet_rx_desc_list_pop(uet_ep);
		if (rx_desc == NULL) {
			UET_API_ERR("RX: No Descriptor to Track Errored Msg");
			return ses_rc;
		}
		memset(rx_desc, 0, sizeof(struct uet_rx_desc));
		uet_init_err_rx_desc(uet_ep, pp, rx_desc, ses_rc);
	} else if (rx_desc->ses_rc == UET_RC_OK) {
		rx_desc->ses_rc = ses_rc;
	}

	if (rx_desc->desc_flags & UET_RX_DESC_FLAG_DSEND) {
		if ((ses->cmn.ver_flags & UET_SES_REQ_FLAG_EOM) &&
		    (pp->ses_payload_len == 0)) {
			rc = uet_rx_msg_truncate(pp, rx_desc, &msg_complete);
			if ((rc != FI_SUCCESS) || (msg_complete == true)) {
				if (rc != FI_SUCCESS)
					UET_API_ERR(
					   "RX: Invalid DSEND Cancel Offset");
				goto post_err_exit;
			}
		}
	}

	if (pp->ses_payload_len >= rx_desc->remaining_bytes) {
		rx_desc->remaining_bytes = 0;
		goto post_err_exit;
	} else
		rx_desc->remaining_bytes -= pp->ses_payload_len;

	return ses_rc;

post_err_exit:
	uet_rx_cq_post_err(rx_desc, FI_EIO);
	return ses_rc;
}

/* find mr descriptor associated with key */
struct uet_mr_desc *uet_get_mr_desc(struct uet_ep *uet_ep,
				    struct uet_parsed_pkt *pp)
{
	struct uet_domain *uet_dom;
	struct uet_mr_desc *mr_desc;
	struct uet_mr_key mr_key;
	struct uet_ses_req_std *ses;

	uet_dom = uet_ep->uet_domain;
	ses = (struct uet_ses_req_std *)pp->ses;
	uet_mr_key_init(&mr_key, pp);

	/* Select the lookup space from the VENDOR_SPECIFIC provider-space
	 * marker carried in the key: provider-assigned keys set it and
	 * resolve via the index space; user-assigned keys clear it and
	 * resolve via the hash space. The two spaces are independent, so
	 * the same RKEY value may map to different regions in each.
	 */
	if (ntohll(ses->match_bits) & UET_MR_KEY_VENDOR_PROV_SPACE) {
		if (mr_key.rkey >= uet_dom->num_mr)
			mr_desc = NULL;
		else {
			mr_desc = &uet_dom->mr_desc[mr_key.rkey];
			if ((mr_desc->state != UET_MR_DESC_STATE_ENABLED) ||
			    mr_desc->user_key)
				mr_desc = NULL;
		}
	} else
		mr_desc = uet_mr_hash_lookup(uet_ep, &mr_key);

	/* Enforce job-restricted access as a region bound to a JobID may only
	 * be accessed by requests within that job.
	 */
	if (mr_desc && mr_desc->job_restricted) {
		if (mr_desc->job_id != uet_get_std_req_job_id(ses)) {
			UET_API_ERR("MR access denied: JobID mismatch");
			mr_desc = NULL;
		}
	}

	return mr_desc;
}

/*
 * get rx descriptor for:
 *   - first packet of write message
 *   - non-first packets of message
 *   - errored messages
 *
 * does not find buffer for first packet of untagged/tagged message
 *
 * parms:
 *      uet_ep      - ptr to uet endpoint struct
 *      pp          - ptr to parsed packet struct
 *      write       - true => message is write message
 *      sync        - true => message is part of sync group
 *      ses_rc      - ses return code, UET_RC_OK => not errored message
 *      msg_key     - ptr to location where key from message lookup is
 *                    to be returned
 *      rx_desc     - ptr to location where ptr to rx descriptor is
 *                    to be returned
 *      first_msg_pkt - ptr to location where first message packet
 *                      indication is to be returned
 *
 * returns:
 *   - ses return code
 */
static uet_ses_rc_t uet_get_rx_desc(
	struct uet_ep *uet_ep, struct uet_parsed_pkt *pp, bool write, bool sync,
	uet_ses_rc_t ses_rc, struct uet_rx_msg_key *msg_key,
	struct uet_rx_desc **rx_desc, bool *first_msg_pkt)
{
	struct uet_mr_key mr_key;
	struct uet_mr_desc *mr_desc;

	/* lookup rx descriptor for msg */
	uet_rx_msg_key_init(msg_key, pp);
	*rx_desc = uet_rx_msg_hash_lookup(uet_ep, msg_key);
	if (*rx_desc != NULL) {
		if (sync)
			uet_get_sync_grp_src_fep(*rx_desc, pp, false);
		*first_msg_pkt = false;
		uet_rx_desc_active_list_move_to_tail(uet_ep, *rx_desc);
		if ((*rx_desc)->ses_rc != UET_RC_OK)
			ses_rc = (*rx_desc)->ses_rc;
		if (ses_rc != UET_RC_OK)
			return (uet_rx_msg_err(
					uet_ep, pp, *rx_desc, ses_rc));
		return ses_rc;
	}

	*first_msg_pkt = true;

	/* don't allocate rx descriptor for normal non-rma operations */
	if ((!write) && (ses_rc == UET_RC_OK))
		return UET_RC_OK;

	/* allocate rx descriptor */
	*rx_desc = uet_rx_desc_list_pop(uet_ep);
	if (*rx_desc == NULL) {
		if (write) {
			UET_API_ERR("RX: No RX Descriptor for RMA Op");
			ses_rc = UET_RC_UNCOR_TRNSNT;
		} else
			UET_API_ERR("RX: No Descriptor to Track Errored Msg");
		return ses_rc;
	}

	/* init base rx descriptor fields */
	memset(*rx_desc, 0, sizeof(struct uet_rx_desc));
	(*rx_desc)->uet_ep = uet_ep;
	if (write)
		(*rx_desc)->desc_flags = UET_RX_DESC_FLAG_WRITE;
	if (sync) {
		uet_ses_rc_t sync_ses_rc;

		sync_ses_rc = uet_get_sync_grp_src_fep(*rx_desc, pp, true);
		if (sync_ses_rc != UET_RC_OK)
			ses_rc = sync_ses_rc;
	}
	if (ses_rc != UET_RC_OK)
		goto err_exit;

	/* operation is rma, find mr associated with key */
	mr_desc = uet_get_mr_desc(uet_ep, pp);
	if (mr_desc == NULL) {
		UET_API_ERR("RX: Invalid RMA Key");
		ses_rc = UET_RC_BAD_MKEY;
		goto err_exit;
	}

	/* more init of rx descriptor for rma operation */
	if (mr_desc->buf_desc.type == UET_MR_BUF_TYPE_CONTIG)
		(*rx_desc)->buf_desc.type = UET_MSG_BUF_TYPE_CONTIG;
	else
		(*rx_desc)->buf_desc.type = UET_MSG_BUF_TYPE_MR;

	(*rx_desc)->buf_desc.buf = mr_desc->buf_desc.buf;
	(*rx_desc)->buf_desc.len = mr_desc->buf_desc.len;
	(*rx_desc)->context = mr_desc->context;
	(*rx_desc)->mr_desc = mr_desc;
	(*rx_desc)->ses_rc = ses_rc;

	return UET_RC_OK;

err_exit:
	uet_init_err_rx_desc(uet_ep, pp, *rx_desc, ses_rc);
	return uet_rx_msg_err(uet_ep, pp, *rx_desc, ses_rc);
}

/* init tx descriptor ephemeral address vector */
static void uet_init_tx_desc_ephemeral_av(struct uet_tx_desc *tx_desc,
					  struct uet_parsed_pkt *pp)
{
	struct ethhdr *eth;
	struct uet_av_entry *av;
	struct uet_fa src_ip;

	eth = (struct ethhdr *) pp->eth;

	memset(&src_ip, 0, sizeof(src_ip));

	if (pp->is_ipv6) {
		struct ipv6hdr *ipv6 = (struct ipv6hdr *) pp->ip;
		memcpy(src_ip.v6, &ipv6->saddr, 16);
	} else {
		struct iphdr *ipv4 = (struct iphdr *) pp->ip;
		src_ip.v4 = ntohl(ipv4->saddr);
	}

	uet_init_uet_addr(&tx_desc->ephemeral_av.uet_addr,
			  &src_ip, pp->is_ipv6);

	av = &tx_desc->ephemeral_av.av;
	av->addr = &tx_desc->ephemeral_av.uet_addr;
	av->flags = UET_NH_MAC_ADDR_V;
	memcpy(av->nh_mac_addr, eth->h_source, ETH_ALEN);
	tx_desc->dst_addr_handle = (uet_addr_handle_t) av;
}

/*
 * get tx descriptor for read request
 *
 * parms:
 *      uet_ep      - ptr to uet endpoint struct
 *      pp          - ptr to parsed packet struct
 *      req_len     - read message request length in bytes
 *      buf_off     - offset in target buffer
 *      msg_off     - offset within message
 *      mr_desc     - ptr descriptor for target memory region
 *      pds_info    - ptr to info that needs to be echoed back to pds when
 *                    read data is transmitted
 *      ret_tx_desc - ptr to location where tx descriptor for message
 *                    is to be returned, only valid when return code is
 *                    UET_RC_OK
 *
 * returns:
 *   - ses return code
 */
static uet_ses_rc_t uet_get_rd_tx_desc(
	struct uet_ep *uet_ep, struct uet_parsed_pkt *pp,
	uint32_t req_len, size_t buf_off, uint32_t msg_off,
	struct uet_mr_desc *mr_desc, struct uet_pds_info *pds_info,
	struct uet_tx_desc **ret_tx_desc)
{
	struct uet_tx_desc *tx_desc;
	struct uet_ses_req_std *ses;

	ses = (struct uet_ses_req_std *) pp->ses;

	/* allocate tx descriptor */
	tx_desc = uet_tx_desc_list_pop(uet_ep);
	if (tx_desc == NULL) {
		*ret_tx_desc = NULL;
		return UET_RC_UNCOR_TRNSNT;
	}
	*ret_tx_desc = tx_desc;

	/* init tx descriptor */
	memset(tx_desc, 0, sizeof(struct uet_tx_desc));
	tx_desc->cq_flags = FI_RMA | FI_REMOTE_READ;
	tx_desc->desc_flags = UET_TX_DESC_FLAG_READ_RSP;
	tx_desc->buf_desc.type = UET_MSG_BUF_TYPE_CONTIG;
	if (uet_mr_is_scattered(mr_desc)) {
		/* A scattered region offers no contiguous pointer to hand to
		 * the transmit path, and this descriptor outlives the call,
		 * so gather the requested range into a buffer owned by the
		 * descriptor that is released when it is recycled.
		 */
		void *rd_buf = malloc(pp->ses_payload_len);
		if (rd_buf == NULL) {
			UET_API_PRINT_ERRNO("malloc");
			uet_tx_desc_list_insert(tx_desc);
			*ret_tx_desc = NULL;
			return UET_RC_UNCOR_TRNSNT;
		}

		if (uet_mr_gather(mr_desc, buf_off, rd_buf,
				  pp->ses_payload_len) !=
		    pp->ses_payload_len) {
			UET_API_ERR("RX: Read Req: Invalid Buffer Offset");
			free(rd_buf);
			uet_tx_desc_list_insert(tx_desc);
			*ret_tx_desc = NULL;
			return UET_RC_BAD_ADDR;
		}

		tx_desc->buf_desc.buf = rd_buf;
		tx_desc->desc_flags |= UET_TX_DESC_FLAG_OWNS_BUF;
	} else {
		tx_desc->buf_desc.buf =
			(void *)(((uint8_t *)mr_desc->buf_desc.buf) + buf_off);
	}
	tx_desc->buf_desc.len = pp->ses_payload_len;
	tx_desc->remaining_bytes = pp->ses_payload_len;
	tx_desc->remote_msg_off = msg_off;
	tx_desc->mr_desc = mr_desc;

	tx_desc->rd_rsp.req_msg_id = pp->ses_msg_id;
	tx_desc->rd_rsp.mod_len = req_len;
	tx_desc->rd_rsp.pds_info = *pds_info;

	uet_init_tx_desc_ephemeral_av(tx_desc, pp);

	tx_desc->job_id = uet_get_std_req_job_id(ses);
	tx_desc->msg_id = ntohs(ses->cmn.msg_id);
	tx_desc->uet_ep = uet_ep;
	tx_desc->backoff_min = UET_INITIAL_BACKOFF_MIN;
	tx_desc->backoff_max = UET_INITIAL_BACKOFF_MAX;
	tx_desc->pds_mode = uet_get_pds_mode(uet_ep, true);
	if (tx_desc->pds_mode == UET_PDS_MODE_ROD)
		tx_desc->seq_num =
			uet_alloc_av_msg_seq_num(&tx_desc->ephemeral_av.av);
	uet_gettime(&tx_desc->tx_time);

	/* insert descriptor in tx ring of endpoint */
	uet_tx_desc_ring_insert(tx_desc);

	return UET_RC_OK;
}

/*
 * process a received message read request packet
 *
 * parms:
 *      uet_ep     - ptr to uet endpoint struct
 *      pp         - ptr to parsed packet struct
 *      list       - ptr to location where type of list pkt was
 *                   delivered to is to be returned
 *      pds_info   - ptr to info that needs to be echoed back to pds when
 *                   read data is transmitted
 *      ack_d_info - ptr to struct where info about data carried in ack
 *                   is to be returned
 *
 * returns:
 *   - ses return code
 */
static uet_ses_rc_t uet_rx_rd_req_pkt(
	struct uet_ep *uet_ep, struct uet_parsed_pkt *pp,
	uet_ses_list_t *list, struct uet_pds_info *pds_info,
	struct uet_ack_d_info *ack_d_info)
{
	uet_ses_rc_t ses_rc;
	uint16_t max_ack_data;
	size_t start_off, buf_off;
	uint32_t req_len, msg_off, rx_gen, ep_gen;
	uint64_t payload_len_msg_off;
	struct uet_ses_req_std *ses;
	struct uet_tx_desc *tx_desc;
	struct uet_mr_desc *mr_desc;

	ses = (struct uet_ses_req_std *) pp->ses;

	ack_d_info->valid = false;

	*list = UET_EXPECTED; /* overflow list not supported */
	req_len = ntohl(ses->req_len);
	start_off = ntohll(ses->buf_off);

	if (ses->cmn.ver_flags & UET_SES_REQ_FLAG_SOM)
		msg_off = 0;
	else {
		payload_len_msg_off = ntohll(ses->payload_len_msg_off);
		msg_off = (payload_len_msg_off &
			   UET_SES_REQ_STD_MSG_OFF_MASK) >>
			  UET_SES_REQ_STD_MSG_OFF_SHIFT;
	}
	buf_off = start_off + msg_off;

	/* check that payload length does not exceed request length */
	if (pp->ses_payload_len > req_len) {
		UET_API_ERR("RX: Read Req: Payload Len > Req Len");
		return UET_RC_OP_VIOLATION;
	}

	/* check for initiator error */
	if (ses->cmn.ver_flags & UET_SES_REQ_FLAG_IE) {
		UET_API_ERR("RX: Read Req: IE Set");
		return UET_RC_INITIATOR_ERR;
	}

	/* check that generation is enabled */
	if (uet_ep->untagged_gen_disabled) {
		UET_API_ERR("RX: Read Req: Disabled Generation");
		return UET_RC_DISABLED_GEN;
	}

	/* check for correct generation */
	rx_gen = (uint32_t)((ntohl(ses->cmn.ri_gen_job_id) &
			     UET_SES_REQ_RI_GEN_MASK) >>
			    UET_SES_REQ_RI_GEN_SHIFT);
	ep_gen = (uint32_t) uet_ep->untagged_gen;
	if (rx_gen != ep_gen) {
		UET_API_ERR("RX: Read Req: Bad Generation");
		return UET_RC_BAD_GENERATION;
	}

	/* find mr descriptor associated with key */
	mr_desc = uet_get_mr_desc(uet_ep, pp);
	if (mr_desc == NULL) {
		UET_API_ERR("RX: Read Req: Invalid Key");
		return UET_RC_BAD_MKEY;
	}

	/* check mr permissions */
	if (!(mr_desc->access & FI_REMOTE_READ)) {
		UET_API_ERR("RX: Read Req: No Remote Read Permission");
		return UET_RC_PERM_VIOLATION;
	}

	/* A RUDI read may only source from an IDEMPOTENT_SAFE memory region
	 * RUD/ROD reads are unaffected.
	 */
	if ((pp->pds_type == UET_PDS_TYPE_RUDI_REQ) &&
	    !(mr_desc->full_key & UET_MR_KEY_IDEMPOTENT_SAFE)) {
		UET_API_ERR("RX: RUDI Read: MR not IDEMPOTENT_SAFE");
		return UET_RC_OP_VIOLATION;
	}

	/* resolve the address against the region and validate the range */
	if (!uet_mr_addr_to_offset(mr_desc, buf_off, pp->ses_payload_len,
				   &buf_off)) {
		UET_API_ERR("RX: Read Req: Invalid Buffer Offset");
		return UET_RC_BAD_ADDR;
	}

	/* check if data is to be carried in ack */
	max_ack_data = uet_ep->uet_domain->uet->pds.max_ack_data;
	if ((pp->pds_type == UET_PDS_TYPE_RUDI_REQ) ||
	    (uet_ep->uet_domain->uet->max_payload_len == max_ack_data) ||
	    (req_len <= max_ack_data)) {
		ack_d_info->valid = true;
		ack_d_info->payload_len = pp->ses_payload_len;
		ack_d_info->msg_off = msg_off;

		if (uet_mr_is_scattered(mr_desc)) {
			/* A scattered region offers no contiguous pointer, so
			 * stage the data in the ack info struct. The staging
			 * area is sized for a maximum payload. Refuse anything
			 * larger rather than overrun it.
			 */
			if (pp->ses_payload_len >
			    sizeof(ack_d_info->gather_buf)) {
				UET_API_ERR("RX: Read Req: ack payload "
					    "exceeds gather buf");
				return UET_RC_BAD_ADDR;
			}

			if (uet_mr_gather(mr_desc, buf_off,
					  ack_d_info->gather_buf,
					  pp->ses_payload_len) !=
			    pp->ses_payload_len) {
				UET_API_ERR("RX: Read Req: Invalid Buffer "
					    "Offset");
				return UET_RC_BAD_ADDR;
			}

			ack_d_info->buf = ack_d_info->gather_buf;
		} else {
			ack_d_info->buf =
				((uint8_t *)mr_desc->buf_desc.buf + buf_off);
		}
	} else {
		/* get tx descriptor for sending read response */
		ses_rc = uet_get_rd_tx_desc(uet_ep, pp, req_len, buf_off,
					    msg_off, mr_desc, pds_info,
					    &tx_desc);
		if (ses_rc != UET_RC_OK)
			return ses_rc;
	}

	return UET_RC_OK;
}

/*
 * process a received non-fetching atomic request packet
 *
 * parms:
 *      uet_ep - ptr to uet endpoint struct
 *      pp     - ptr to parsed packet struct
 *      list   - ptr to location where type of list pkt was
 *               delivered to is to be returned
 *      sync   - atomic is associated with sync group
 *
 * returns:
 *   - ses return code
 */
static uet_ses_rc_t uet_rx_atomic_req_pkt(
	struct uet_ep *uet_ep, struct uet_parsed_pkt *pp,
	uet_ses_list_t *list, bool sync)
{
	uet_ses_rc_t ses_rc = UET_RC_OK;
	size_t start_off;
	uint8_t opcode, dt;
	uint32_t req_len, rx_gen, ep_gen;
	uint64_t data, *addr;
	struct uet_ses_req_std_atomic *ses;
	struct uet_ses_req_std_atomic_sync *ses_sync;
	struct uet_mr_desc *mr_desc;
	struct uet_sync_grp_src_fep_key key;
	struct uet_sync_grp_src_fep_entry *entry = NULL;
	bool sync_defer_atomic = false, bool_rx_msg_err;
	uint16_t sync_ext_group, sync_ext_cnt;

	ses = (struct uet_ses_req_std_atomic *) pp->ses;
	ses_sync = (struct uet_ses_req_std_atomic_sync *) pp->ses;

	*list = UET_EXPECTED; /* overflow list not supported */

	if (sync) {
		dt = ses_sync->atomic_ext.atomic_dt;
		opcode = ses_sync->atomic_ext.atomic_opcode;
		sync_ext_group = ntohs(ses_sync->sync_ext.group);
		sync_ext_cnt = ntohs(ses_sync->sync_ext.cnt);
		uet_sync_grp_src_fep_key_init(sync_ext_group, &key, pp);
		entry = uet_sync_grp_src_fep_hash_lookup(uet_ep, &key);
		if (entry != NULL) {
			if (entry->cnts.tot_cnt) {
				UET_API_ERR("RX: Multiple Terminating Ops for "
					    "Sync Group");
				ses_rc = UET_RC_OP_VIOLATION;
				goto err_exit;
			}
			entry->terminating_atomic = true;
			entry->cnts.cmpl_cnt++;
			entry->cnts.cur_cnt++;
			entry->cnts.tot_cnt = sync_ext_cnt;
			if (entry->cnts.cur_cnt > entry->cnts.tot_cnt) {
				UET_API_ERR("RX: Too Many Messages for Sync "
					    "Group");
				ses_rc = UET_RC_OP_VIOLATION;
				entry->cnts.tot_cnt = entry->cnts.cur_cnt;
			}
			if (entry->cnts.cmpl_cnt == entry->cnts.tot_cnt) {
				uet_sync_grp_src_fep_hash_remove(uet_ep, entry);
				entry = NULL;
			} else
				sync_defer_atomic = true;
			if (ses_rc != UET_RC_OK)
				goto err_exit;
		} else if (sync_ext_cnt == 0) {
			UET_API_ERR("RX: Invalid Sync Group Count");
			ses_rc = UET_RC_OP_VIOLATION;
			goto err_exit;
		} else if (sync_ext_cnt != 1) {
			entry = (struct uet_sync_grp_src_fep_entry *)
				calloc(1,
				     sizeof(struct uet_sync_grp_src_fep_entry));
			if (entry == NULL) {
				UET_API_ERR("RX: No Sync Group for RMA Atomic");
				ses_rc = UET_RC_UNCOR_TRNSNT;
				goto err_exit;
			}

			entry->terminating_atomic = true;
			entry->cnts.cur_cnt++;
			entry->cnts.cmpl_cnt++;
			entry->cnts.tot_cnt = sync_ext_cnt;
			entry->sync_grp_src_fep_key = key;
			uet_sync_grp_src_fep_hash_insert(uet_ep, entry);
			sync_defer_atomic = true;
		}
	} else {
		dt = ses->ext.atomic_dt;
		opcode = ses->ext.atomic_opcode;
	}

	req_len = ntohl(ses->base.req_len);
	start_off = ntohll(ses->base.buf_off);

	/* check for initiator error */
	if (ses->base.cmn.ver_flags & UET_SES_REQ_FLAG_IE) {
		UET_API_ERR("RX: Atomic Req: IE Set");
		ses_rc = UET_RC_INITIATOR_ERR;
		goto err_exit;
	}

	/* check that generation is enabled */
	if (uet_ep->untagged_gen_disabled) {
		UET_API_ERR("RX: Atomic Req: Disabled Generation");
		ses_rc = UET_RC_DISABLED_GEN;
		goto err_exit;
	}

	/* check for correct generation */
	rx_gen = (uint32_t)((ntohl(ses->base.cmn.ri_gen_job_id) &
			     UET_SES_REQ_RI_GEN_MASK) >>
			    UET_SES_REQ_RI_GEN_SHIFT);
	ep_gen = (uint32_t) uet_ep->untagged_gen;
	if (rx_gen != ep_gen) {
		UET_API_ERR("RX: Atomic Req: Bad Generation");
		ses_rc = UET_RC_BAD_GENERATION;
		goto err_exit;
	}

	/* check that atomic request is single packet message */
	if ((ses->base.cmn.ver_flags & (UET_SES_REQ_FLAG_SOM |
		  	   	        UET_SES_REQ_FLAG_EOM)) !=
	    (UET_SES_REQ_FLAG_SOM | UET_SES_REQ_FLAG_EOM)) {
		UET_API_ERR("RX: Atomic Req: SOM and EOM Not Set");
		ses_rc = UET_RC_OP_VIOLATION;
		goto err_exit;
	}

	/* check atomic datatype */
	if (dt != UET_TYPE_UINT64) {
		/* this is the only atomic datatype supported by uet verbs */
		UET_API_ERR("RX: Atomic Req: Unsupported Data Type 0x%x", dt);
		ses_rc = UET_RC_UNSUPPORTED_OP;
		goto err_exit;
	}

	/* check atomic opcode */
	switch (opcode) {
	case UET_AMO_SUM:
		/* check req len field of ses hdr */
		if (req_len != UET_VERBS_ATOMIC_DATA_BYTES) {
			UET_API_ERR("RX: Atomic Req: Bad Req Len %u", req_len);
			ses_rc = UET_RC_OP_VIOLATION;
			goto err_exit;
		}
		/* check actual payload len of packet */
		if (pp->ses_payload_len != req_len) {
			UET_API_ERR("RX: Atomic Req: "
			    	    "Bad Packet Payload Len %u",
				    pp->ses_payload_len);
			ses_rc = UET_RC_OP_VIOLATION;
			goto err_exit;
		}
		break;
	default:
		UET_API_ERR("RX: Atomic Req: Unsupported Opcode 0x%x",
			    opcode);
		ses_rc = UET_RC_UNSUPPORTED_OP;
		goto err_exit;
	}

	/* find mr descriptor associated with key */
	mr_desc = uet_get_mr_desc(uet_ep, pp);
	if (mr_desc == NULL) {
		UET_API_ERR("RX: Atomic Req: Invalid Key");
		ses_rc = UET_RC_BAD_MKEY;
		goto err_exit;
	}

	/* check mr permissions */
	if ((mr_desc->access &
	    (FI_ATOMIC | FI_REMOTE_READ | FI_REMOTE_WRITE)) !=
	    (FI_ATOMIC | FI_REMOTE_READ | FI_REMOTE_WRITE)) {
		UET_API_ERR("RX: Atomic Req: Insufficient Permission");
		ses_rc = UET_RC_PERM_VIOLATION;
		goto err_exit;
	}

	/* resolve the address against the region and validate the range */
	if (!uet_mr_addr_to_offset(mr_desc, start_off,
				   UET_VERBS_ATOMIC_DATA_BYTES, &start_off)) {
		UET_API_ERR("RX: Atomic Req: Invalid Buffer Offset");
		ses_rc = UET_RC_BAD_ADDR;
		goto err_exit;
	}

	/* An atomic needs a single naturally aligned location that the
	 * __atomic builtins can operate on in place. A scattered region has
	 * no such designation and the operand could straddle two entries.
	 * Verify that the address offset within the descriptor memory is
	 * contiguous based on a specific atomic data length.
	 */

	/* implement atomic operation                                  */
	/*   - atomic operation may be deferred by sync group protocol */
	addr = uet_mr_atomic_addr(mr_desc, start_off,
				  UET_VERBS_ATOMIC_DATA_BYTES);
	if (addr == NULL) {
		UET_API_ERR("RX: Atomic Req: operand misaligned or "
			    "spans a page boundary");
		ses_rc = UET_RC_BAD_ADDR;
		goto err_exit;
	}

	if (sync)
		data = ntohll(*((uint64_t *) ses_sync->data));
	else
		data = ntohll(*((uint64_t *) ses->data));

	/* currently, only sum of uint64 is supported                  */
	/*   - if additional atomic ops are supported:                 */
	/*     - parms for deferred op come from atomic ext hdr in pkt */
	/*     - appropriate atomic system calls must be used for      */
	/*       for non-deferred ops                                  */
	if (sync_defer_atomic) {
		entry->atomic_parms.opcode = UET_AMO_SUM;
		entry->atomic_parms.data_type = UET_TYPE_UINT64;
		entry->atomic_parms.addr = addr;
		entry->atomic_parms.data = data;
	} else
		__atomic_fetch_add(addr, data, __ATOMIC_SEQ_CST);

	return UET_RC_OK;

err_exit:
	if (entry)
		entry->terminating_err = true;
	return ses_rc;
}

/*
 * process a received fetching atomic request packet
 *
 * parms:
 *      uet_ep     - ptr to uet endpoint struct
 *      pp         - ptr to parsed packet struct
 *      list       - ptr to location where type of list pkt was
 *                   delivered to is to be returned
 *      payload    - ptr to payload of response
 *      ack_d_info - ptr to struct where info about data carried in ack
 *                   is to be returned
 *
 * returns:
 *   - ses return code
 */
static uet_ses_rc_t uet_rx_fetch_atomic_req_pkt(
	struct uet_ep *uet_ep, struct uet_parsed_pkt *pp, uet_ses_list_t *list,
	uint8_t *payload, struct uet_ack_d_info *ack_d_info) {
	size_t start_off;
	uint8_t opcode, dt;
	uint32_t req_len, rx_gen, ep_gen;
	uint64_t data, result, expected, desired, *addr;
	struct uet_ses_req_std_atomic *ses_atomic;
	struct uet_ses_req_std_cswap *ses_cswap;
	struct uet_mr_desc *mr_desc;

	ses_atomic = (struct uet_ses_req_std_atomic *) pp->ses;
	ses_cswap = (struct uet_ses_req_std_cswap *) pp->ses;

	*list = UET_EXPECTED; /* overflow list not supported */

	req_len = ntohl(ses_atomic->base.req_len);
	start_off = ntohll(ses_atomic->base.buf_off);

	/* check for initiator error */
	if (ses_atomic->base.cmn.ver_flags & UET_SES_REQ_FLAG_IE) {
		UET_API_ERR("RX: Fetching Atomic Req: IE Set");
		return UET_RC_INITIATOR_ERR;
	}

	/* check that generation is enabled */
	if (uet_ep->untagged_gen_disabled) {
		UET_API_ERR("RX: Fetching Atomic Req: Disabled Generation");
		return UET_RC_DISABLED_GEN;
	}

	/* check for correct generation */
	rx_gen = (uint32_t)((ntohl(ses_atomic->base.cmn.ri_gen_job_id) &
			     UET_SES_REQ_RI_GEN_MASK) >>
			    UET_SES_REQ_RI_GEN_SHIFT);
	ep_gen = (uint32_t) uet_ep->untagged_gen;
	if (rx_gen != ep_gen) {
		UET_API_ERR("RX: Fetching Atomic Req: Bad Generation");
		return UET_RC_BAD_GENERATION;
	}

	/* check that fetching atomic request is single packet message */
	if ((ses_atomic->base.cmn.ver_flags & (UET_SES_REQ_FLAG_SOM |
			  	   	       UET_SES_REQ_FLAG_EOM)) !=
	    (UET_SES_REQ_FLAG_SOM | UET_SES_REQ_FLAG_EOM)) {
		UET_API_ERR("RX: Fetching Atomic Req: SOM and EOM Not Set");
		return UET_RC_OP_VIOLATION;
	}

	/* check atomic datatype */
	dt = ses_atomic->ext.atomic_dt;
	if (dt != UET_TYPE_UINT64) {
		/* this is the only atomic datatype supported by uet verbs */
		UET_API_ERR("RX: Fetching Atomic Req: "
			    "Unsupported Data Type 0x%x", dt);
		return UET_RC_UNSUPPORTED_OP;
	}

	/* check atomic opcode */
	opcode = ses_atomic->ext.atomic_opcode;
	switch (opcode) {
	case UET_AMO_SUM:
		/* check req len field of ses hdr */
		if (req_len != UET_VERBS_ATOMIC_DATA_BYTES) {
			UET_API_ERR("RX: Fetching Atomic Req: "
			    	    "Bad Req Len %u", req_len);
			return UET_RC_OP_VIOLATION;
		}
		/* check actual payload len of packet */
		if (pp->ses_payload_len != req_len) {
			UET_API_ERR("RX: Fetching Atomic Req: "
			    	    "Bad Packet Payload Len %u",
				    pp->ses_payload_len);
			return UET_RC_OP_VIOLATION;
		}
		break;
	case UET_AMO_CSWAP:
		/* check req len fields of ses hdr */
		if (req_len != UET_CSWAP_DATA_BYTES) {
			UET_API_ERR("RX: CSWAP Req: Bad Req Len %u", req_len);
			return UET_RC_OP_VIOLATION;
		}
		/* check actual payload len of packet */
		if (pp->ses_payload_len != req_len) {
			UET_API_ERR("RX: CSWAP Atomic Req: "
			    	    "Bad Packet Payload Len %u",
				    pp->ses_payload_len);
			return UET_RC_OP_VIOLATION;
		}
		break;
	default:
		UET_API_ERR("RX: Fetching Atomic Req: Unsupported Opcode 0x%x",
			    opcode);
		return UET_RC_UNSUPPORTED_OP;
	}

	/* find mr descriptor associated with key */
	mr_desc = uet_get_mr_desc(uet_ep, pp);
	if (mr_desc == NULL) {
		UET_API_ERR("RX: Fetching Atomic Req: Invalid Key");
		return UET_RC_BAD_MKEY;
	}

	/* check mr permissions */
	if ((mr_desc->access &
	    (FI_ATOMIC | FI_REMOTE_READ | FI_REMOTE_WRITE)) !=
	    (FI_ATOMIC | FI_REMOTE_READ | FI_REMOTE_WRITE)) {
		UET_API_ERR("RX: Fetching Atomic Req: Insufficient Permission");
		return UET_RC_PERM_VIOLATION;
	}

	/* resolve the address against the region and validate the range */
	if (!uet_mr_addr_to_offset(mr_desc, start_off,
				   UET_VERBS_ATOMIC_DATA_BYTES, &start_off)) {
		UET_API_ERR("RX: Fetching Atomic Req: Invalid Buffer Offset");
		return UET_RC_BAD_ADDR;
	}

	/* implement atomic operation */
	ack_d_info->payload_len = UET_VERBS_ATOMIC_DATA_BYTES;
	ack_d_info->msg_off = 0;

	addr = uet_mr_atomic_addr(mr_desc, start_off,
				  UET_VERBS_ATOMIC_DATA_BYTES);
	if (addr == NULL) {
		UET_API_ERR("RX: Fetching Atomic Req: operand misaligned or "
			    "spans a page");
		return UET_RC_BAD_ADDR;
	}

	if (opcode == UET_AMO_SUM) {
		data = ntohll(*((uint64_t *) ses_atomic->data));
		result = __atomic_fetch_add(addr, data, __ATOMIC_SEQ_CST);
		*((uint64_t *) payload) = htonll(result);
	} else {
		expected = ntohll(ses_cswap->ext.cmp_val_lo);
		desired = ntohll(ses_cswap->ext.swp_val_lo);
		__atomic_compare_exchange_n(
			addr, &expected, desired, false,
			__ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
		/* return old value, always equal to expected variable */
		*((uint64_t *) payload) = htonll(expected);
	}

	return UET_RC_OK;
}

/*
 * process a received deferred send request packet when there is no buffer
 *
 * parms:
 *      uet_ep  - ptr to uet endpoint struct
 *      pp      - ptr to parsed packet structure
 *      list    - ptr to location where type of list pkt was
 *                delivered to is to be returned
 *      tagged  - true => message is tagged message
 *      tag_key - ptr to key for tag lookup, valid when 'tagged' = true
 *
 * returns:
 *   - ses return code
 *     UET_RC_DEFER_SEND if deferred
 *     UET_RC_NO_MATCH if not deferred
 */
static uet_ses_rc_t uet_rx_dsend(struct uet_ep *uet_ep,
				 struct uet_parsed_pkt *pp,
				 uet_ses_list_t *list, bool tagged,
				 struct uet_tag_initiator_key *tag_key)
{
	int rc;
	uint16_t allocated_token, msg_id;
	uint64_t remote_token;
	time_t now;
	struct uet_instance *uet;
	struct uet_ses_req_std *ses;
	struct uet_tx_desc *tx_desc;

	uet = uet_ep->uet_domain->uet;
	ses = (struct uet_ses_req_std *) pp->ses;

	/* only buffer dsend's for rud pdc's */
	if (uet_get_pds_mode(uet_ep, false) != UET_PDS_MODE_RUD)
		return UET_RC_NO_MATCH;

	/* check for max buffered dsend's */
	if (uet_ep->num_buf_rtr_list_entries == uet->max_rtr_q_entries)
		return UET_RC_NO_MATCH;

	/* allocate msg id for rtr */
	rc = uet_alloc_msg_id(uet, &msg_id);
	if (rc != FI_SUCCESS)
		return UET_RC_NO_MATCH;

	/* allocate tx descriptor for rtr */
	tx_desc = uet_tx_desc_list_pop(uet_ep);
	if (tx_desc == NULL) {
		uet_dealloc_msg_id(uet, msg_id);
		return UET_RC_NO_MATCH;
	}

	/* init tx descriptor */
	memset(tx_desc, 0, sizeof(struct uet_tx_desc));
	tx_desc->desc_flags = UET_TX_DESC_FLAG_MSG_ID_ALLOCATED |
			      UET_TX_DESC_FLAG_RTR_REQ;
	uet_init_tx_desc_ephemeral_av(tx_desc, pp);
	tx_desc->job_id = uet_ep->job_id;
	tx_desc->msg_id = msg_id;
	tx_desc->uet_ep = uet_ep;
	tx_desc->backoff_min = UET_INITIAL_BACKOFF_MIN;
	tx_desc->backoff_max = UET_INITIAL_BACKOFF_MAX;
	tx_desc->pds_mode = UET_PDS_MODE_RUD;
	uet_gettime(&now);
	tx_desc->tx_time = now;
	tx_desc->defer_time = now;
	tx_desc->local_rtr_token = UET_RTR_TOKEN_NONE;
	remote_token =
		(ntohll(ses->restart_token) & UET_SES_REQ_STD_SRC_TOKEN_MASK) >>
		UET_SES_REQ_STD_SRC_TOKEN_SHIFT;
	tx_desc->remote_rtr_token = (uint32_t) remote_token;
	if (tagged) {
		tx_desc->cq_flags = FI_TAGGED;
		tx_desc->ephemeral_av.uet_addr.flags |= UET_ADDR_INITIATOR_V;
		tx_desc->ephemeral_av.uet_addr.initiator_id =
						ntohl(tag_key->initiator);
		tx_desc->tag_or_immdata = ntohll(tag_key->tag);
	} else
		tx_desc->cq_flags = FI_MSG;

	/* insert tx desc in appropriate rtr list */
	uet_tx_desc_buf_rtr_list_insert(tx_desc);

	*list = UET_OVERFLOW;
	return UET_RC_DEFER_SEND;
}

/*
 * Assemble scatter list from a flat buffer. Scatters payload_len bytes of
 * payload into the scatter/gather list, starting payload_offset bytes into
 * the list's flattened address space.
 *
 * returns:
 *   The number of bytes actually placed. This is less than payload_len only
 *   when the scatter list is too short to hold the payload at that offset,
 *   which MUST be treated as an error.
 */
static size_t scatter_flat_to_iov(const struct iovec *iov, size_t iov_count,
				  const void *payload, size_t payload_len,
				  size_t payload_offset)
{
	size_t iov_index = 0;
	size_t remaining_bytes = payload_len;
	size_t buf_offset = 0;
	size_t iov_buf_offset = 0;

	/* walk forward to the entry containing payload_offset */
	while ((payload_offset > 0) && (iov_index < iov_count)) {
		if (iov[iov_index].iov_len <= payload_offset) {
			payload_offset -= iov[iov_index].iov_len;
			iov_index++;
		} else {
			iov_buf_offset = payload_offset;
			break;
		}
	}

	while ((remaining_bytes > 0) && (iov_index < iov_count)) {
		size_t avail = (iov[iov_index].iov_len - iov_buf_offset);

		if (avail < remaining_bytes) {
			memcpy((iov[iov_index].iov_base + iov_buf_offset),
			       (payload + buf_offset), avail);
			remaining_bytes -= avail;
			buf_offset += avail;
			iov_index++;
			iov_buf_offset = 0;
		} else {
			memcpy((iov[iov_index].iov_base + iov_buf_offset),
			       (payload + buf_offset), remaining_bytes);
			buf_offset += remaining_bytes;
			remaining_bytes = 0;
		}
	}

	return buf_offset;
}

/*
 * Gather from a scatter/gather list into a flat buffer. The mirror of
 * scatter_flat_to_iov(). Copies len bytes out of the list, starting offset
 * bytes into the list's flattened address space.
 *
 * returns:
 *   The number of bytes actually gathered. This is less than len only when
 *   the scatter list is too short to satisfy the request at that offset,
 *   which MUST be treated as an error.
 */
static size_t gather_iov_to_flat(
	const struct iovec *iov, size_t iov_count, void *dst,
	size_t len, size_t offset)
{
	size_t iov_index = 0;
	size_t remaining_bytes = len;
	size_t dst_offset = 0;
	size_t iov_buf_offset = 0;

	/* walk forward to the entry containing offset */
	while ((offset > 0) && (iov_index < iov_count)) {
		if (iov[iov_index].iov_len <= offset) {
			offset -= iov[iov_index].iov_len;
			iov_index++;
		} else {
			iov_buf_offset = offset;
			break;
		}
	}

	while ((remaining_bytes > 0) && (iov_index < iov_count)) {
		size_t avail = (iov[iov_index].iov_len - iov_buf_offset);
		size_t to_copy = (avail < remaining_bytes) ?
					avail : remaining_bytes;

		memcpy(((uint8_t *)dst + dst_offset),
		       ((uint8_t *)iov[iov_index].iov_base + iov_buf_offset),
		       to_copy);

		dst_offset += to_copy;
		remaining_bytes -= to_copy;
		iov_index++;
		iov_buf_offset = 0;
	}

	return dst_offset;
}

/*
 * Translate a dma address to something this process can dereference.
 *
 * FIXME: For future use with a device model does not own the memory its page
 * lists describe and only the device model can resolve them...
 */
static void *uet_dma_to_host(const struct uet_instance *uet,
			     uet_dma_addr_t addr, size_t len)
{
	(void)uet;
	(void)len;

	return (void *)(uintptr_t)addr;
}

/*
 * resolve a byte offset within a PBL region to a host address
 *
 * Directory and page entries are read in place through the translation
 * callback rather than being copied/stored in the descriptor.
 *
 * parms:
 *   mr_desc - the region
 *   offset  - byte offset into the region's flattened address space
 *   run_len - set to the number of bytes contiguously accessible from the
 *             returned address, never crossing a page boundary
 *
 * returns:
 *   a dereferenceable pointer, or NULL if the offset cannot be resolved
 */
static void *uet_mr_pbl_resolve(const struct uet_mr_desc *mr_desc,
				size_t offset, size_t *run_len)
{
	const struct uet_mr_desc_pbl *pbl = &mr_desc->buf_desc.pbl;
	const struct uet_instance *uet = mr_desc->uet_dom->uet;
	size_t abs, page_idx, page_off, per_dir, dir_idx, ent_idx;
	uet_dma_addr_t page_addr;
	uet_dma_addr_t *dir;

	abs = ((size_t)pbl->page_offset + offset);
	page_idx = (abs >> pbl->page_shift);
	page_off = (abs & ((size_t)pbl->page_size - 1));

	switch (pbl->level) {
	case UET_PBL_LEVEL_0:
		*run_len = (mr_desc->buf_desc.len - offset);
		return uet_dma_to_host(uet, (pbl->root + abs), *run_len);

	case UET_PBL_LEVEL_1:
		dir = uet_dma_to_host(uet, pbl->root,
				      ((page_idx + 1) * sizeof(*dir)));
		if (dir == NULL)
			return NULL;

		page_addr = dir[page_idx];
		break;

	case UET_PBL_LEVEL_2:
		per_dir = (pbl->page_size / sizeof(uet_dma_addr_t));
		dir_idx = (page_idx / per_dir);
		ent_idx = (page_idx % per_dir);

		dir = uet_dma_to_host(uet, pbl->root,
				      ((dir_idx + 1) * sizeof(*dir)));
		if (dir == NULL)
			return NULL;

		dir = uet_dma_to_host(uet, dir[dir_idx], pbl->page_size);
		if (dir == NULL)
			return NULL;

		page_addr = dir[ent_idx];
		break;

	default:
		return NULL;
	}

	*run_len = ((size_t)pbl->page_size - page_off);
	return uet_dma_to_host(uet, (page_addr + page_off), *run_len);
}

/*
 * copy into or out of a PBL region
 *
 * returns the number of bytes moved
 */
static size_t uet_mr_pbl_copy(const struct uet_mr_desc *mr_desc, size_t offset,
			      void *flat, size_t len, bool into_mr)
{
	void *p;
	size_t run;
	size_t done = 0;

	while (done < len) {
		p = uet_mr_pbl_resolve(mr_desc, (offset + done), &run);
		if (p == NULL)
			break;

		if (run > (len - done))
			run = (len - done);

		if (run == 0)
			break;

		if (into_mr)
			memcpy(p, ((const uint8_t *)flat + done), run);
		else
			memcpy(((uint8_t *)flat + done), p, run);

		done += run;
	}

	return done;
}

/*
 * Convert an address naming a memory region into an offset into it.
 *
 * A region's base_va selects the convention: 0 means addresses naming it are
 * offsets from zero, anything else means they are virtual addresses and the
 * base is subtracted.
 *
 * parms:
 *   mr_desc - the region
 *   addr    - address naming the region, in its own convention
 *   len     - number of bytes that must be within the region from there
 *   offset  - set to the resulting offset on success
 *
 * returns:
 *   true when the range lies wholly within the region
 */
static bool uet_mr_addr_to_offset(const struct uet_mr_desc *mr_desc,
				  uint64_t addr, size_t len, size_t *offset)
{
	uint64_t off;

	if (addr < mr_desc->base_va)
		return false;

	off = (addr - mr_desc->base_va);

	if ((off > mr_desc->buf_desc.len) ||
	    (len > (mr_desc->buf_desc.len - off)))
		return false;

	*offset = (size_t)off;
	return true;
}

/*
 * Total length of a segment list.
 */
static size_t uet_seg_total_len(const struct uet_mr_seg *seg,
				size_t seg_count)
{
	size_t i, total = 0;

	for (i = 0; i < seg_count; i++)
		total += seg[i].len;

	return total;
}

/*
 * Check that every segment names an enabled region and lies wholly within it.
 */
static bool uet_seg_validate(const struct uet_mr_seg *seg, size_t seg_count)
{
	size_t i, offset;

	if ((seg == NULL) || (seg_count == 0))
		return false;

	for (i = 0; i < seg_count; i++) {
		const struct uet_mr_desc *mr_desc =
			(const struct uet_mr_desc *)seg[i].mr;

		if (mr_desc == NULL)
			return false;

		if (mr_desc->state != UET_MR_DESC_STATE_ENABLED)
			return false;

		if (!uet_mr_addr_to_offset(mr_desc, seg[i].addr, seg[i].len,
					   &offset))
			return false;
	}

	return true;
}

/*
 * Move bytes between a flat buffer and a segment list.
 *
 * The list's flattened address space are the segments end to end, so an
 * offset locates a segment and a position within it. Each segment then
 * resolves through its own region, which is where any knowledge of
 * contiguous buffers, vectors, and page lists lives.
 *
 * returns:
 *   The number of bytes moved, less than len only when the list cannot
 *   satisfy the request, which callers MUST treat as an error.
 */
static size_t uet_seg_copy(const struct uet_mr_seg *seg, size_t seg_count,
			   void *flat, size_t len, size_t offset, bool to_seg)
{
	size_t i, within = offset, done = 0;

	/* locate the segment holding offset */
	for (i = 0; i < seg_count; i++) {
		if (within < seg[i].len)
			break;
		within -= seg[i].len;
	}

	for (; (i < seg_count) && (done < len); i++) {
		const struct uet_mr_desc *mr_desc =
			(const struct uet_mr_desc *)seg[i].mr;
		size_t avail = (seg[i].len - within);
		size_t run = (avail < (len - done)) ? avail : (len - done);
		size_t mr_off, moved;

		if (mr_desc == NULL)
			break;

		/* the segment's address is in its own region's convention */
		if (!uet_mr_addr_to_offset(mr_desc, (seg[i].addr + within), run,
					   &mr_off))
			break;

		if (to_seg)
			moved = uet_mr_scatter(mr_desc, mr_off,
					       ((const uint8_t *)flat + done),
					       run);
		else
			moved = uet_mr_gather(mr_desc, mr_off,
					      ((uint8_t *)flat + done), run);

		if (moved != run)
			break;

		done += run;
		within = 0;
	}

	return done;
}

/*
 * Scatter a flat payload into a segment list. The mirror of
 * scatter_flat_to_iov() one level up.
 */
static size_t scatter_flat_to_seg(const struct uet_mr_seg *seg,
				  size_t seg_count, const void *payload,
				  size_t payload_len, size_t payload_offset)
{
	return uet_seg_copy(seg, seg_count, (void *)payload, payload_len,
			    payload_offset, true);
}

/*
 * Gather from a segment list into a flat buffer. The mirror of
 * gather_iov_to_flat() one level up.
 */
static size_t gather_seg_to_flat(const struct uet_mr_seg *seg,
				 size_t seg_count, void *dst, size_t len,
				 size_t offset)
{
	return uet_seg_copy(seg, seg_count, dst, len, offset, false);
}

/*
 * True when a memory region has no single base address spanning its whole
 * length, so buf_desc.buf must not be used for address arithmetic. Such a
 * region can only be reached through uet_mr_scatter()/uet_mr_gather().
 */
static inline bool uet_mr_is_scattered(const struct uet_mr_desc *mr_desc)
{
	return (mr_desc->buf_desc.type != UET_MR_BUF_TYPE_CONTIG);
}

/*
 * resolve an atomic operand to a location that can be updated in place
 *
 * An atomic must act on a single naturally aligned location: the __atomic
 * builtins need a real address, and an operand split across two pages or
 * two vector entries cannot be made atomic at all.
 *
 * Natural alignment is what makes this workable on a scattered region: an
 * aligned operand can never straddle a power-of-two page boundary, so an
 * aligned offset resolves to exactly one page.
 *
 * parms:
 *   mr_desc - the region
 *   offset  - byte offset into the region's flattened address space
 *   len     - operand size in bytes, which must be a power of 2
 *
 * returns:
 *   The address of the operand, or NULL when it is not addressable that
 *   way (out of bounds, spanning a boundary, or not naturally aligned)
 */
static void *uet_mr_atomic_addr(const struct uet_mr_desc *mr_desc,
				size_t offset, size_t len)
{
	void *p = NULL;
	size_t run = 0;

	if ((offset > mr_desc->buf_desc.len) ||
	    (len > (mr_desc->buf_desc.len - offset)))
		return NULL;

	switch (mr_desc->buf_desc.type) {
	case UET_MR_BUF_TYPE_CONTIG:
		p = ((uint8_t *)mr_desc->buf_desc.buf + offset);
		run = (mr_desc->buf_desc.len - offset);
		break;

	case UET_MR_BUF_TYPE_IOV: {
		const struct iovec *iov = mr_desc->buf_desc.iov.iov;
		size_t count = mr_desc->buf_desc.iov.iov_count;
		size_t i, rem = offset;

		for (i = 0; i < count; i++) {
			if (rem < iov[i].iov_len)
				break;

			rem -= iov[i].iov_len;
		}

		if (i == count)
			return NULL;

		p = ((uint8_t *)iov[i].iov_base + rem);
		run = (iov[i].iov_len - rem);
		break;
	}

	case UET_MR_BUF_TYPE_PBL:
		p = uet_mr_pbl_resolve(mr_desc, offset, &run);
		break;

	default:
		return NULL;
	}

	/* the operand must lie wholly within one addressable run */
	if ((p == NULL) || (run < len))
		return NULL;

	/* and be naturally aligned; len is a power of 2 */
	if (((uintptr_t)p & (len - 1)) != 0)
		return NULL;

	return p;
}

/*
 * Copy into a memory region at a byte offset into its flattened address
 * space, whatever representation the region uses.
 *
 * returns:
 *   The number of bytes written, which is less than len only when the
 *   region cannot hold len bytes at that offset. Callers MUST treat a
 *   short result as an error.
 */
static size_t uet_mr_scatter(const struct uet_mr_desc *mr_desc, size_t offset,
			     const void *src, size_t len)
{
	if ((offset > mr_desc->buf_desc.len) ||
	    (len > (mr_desc->buf_desc.len - offset)))
		return 0;

	switch (mr_desc->buf_desc.type) {
	case UET_MR_BUF_TYPE_CONTIG:
		memcpy(((uint8_t *)mr_desc->buf_desc.buf + offset), src, len);
		return len;

	case UET_MR_BUF_TYPE_IOV:
		return scatter_flat_to_iov(mr_desc->buf_desc.iov.iov,
					   mr_desc->buf_desc.iov.iov_count,
					   src, len, offset);

	case UET_MR_BUF_TYPE_PBL:
		return uet_mr_pbl_copy(mr_desc, offset, (void *)src, len,
				       true);

	default:
		return 0;
	}
}

/*
 * Copy out of a memory region at a byte offset into its flattened address
 * space. The mirror of uet_mr_scatter() and the same short-result contract
 * applies.
 */
static size_t uet_mr_gather(const struct uet_mr_desc *mr_desc, size_t offset,
			    void *dst, size_t len)
{
	if ((offset > mr_desc->buf_desc.len) ||
	    (len > (mr_desc->buf_desc.len - offset)))
		return 0;

	switch (mr_desc->buf_desc.type) {
	case UET_MR_BUF_TYPE_CONTIG:
		memcpy(dst, ((uint8_t *)mr_desc->buf_desc.buf + offset), len);
		return len;

	case UET_MR_BUF_TYPE_IOV:
		return gather_iov_to_flat(mr_desc->buf_desc.iov.iov,
					  mr_desc->buf_desc.iov.iov_count,
					  dst, len, offset);

	case UET_MR_BUF_TYPE_PBL:
		return uet_mr_pbl_copy(mr_desc, offset, dst, len, false);

	default:
		return 0;
	}
}

/*
 * process a received message send/write request packet
 *
 * parms:
 *      uet_ep  - ptr to uet endpoint struct
 *      pp      - ptr to parsed packet structure
 *      list    - ptr to location where type of list pkt was
 *                delivered to is to be returned
 *      tagged  - true => message is tagged message
 *      write   - true => message is write message
 *      sync    - true => write is associated with sync group
 *
 * returns:
 *   - ses return code
 */
static uet_ses_rc_t uet_rx_req_pkt(
	struct uet_ep *uet_ep, struct uet_parsed_pkt *pp, uet_ses_list_t *list,
	bool tagged, bool write, bool sync)
{
	uet_ses_rc_t ses_rc;
	uint16_t max_payload_len;
	size_t start_off, buf_off;
	uint32_t req_len, rx_gen, ep_gen;
	uint64_t payload_len_msg_off;
	bool ep_gen_disabled, first_msg_pkt = false,
	     invalid_payload_len = false;
	void *buf_ptr;
	struct uet_ses_req_std *ses;
	struct uet_ring *ring;
	struct uet_rx_desc *rx_desc;
	struct uet_rx_msg_key msg_key;
	struct uet_tag_initiator_key tag_key, tag_only_key;
	struct uet_mr_desc *mr_desc;

	ses = (struct uet_ses_req_std *) pp->ses;

	*list = UET_EXPECTED; /* overflow list not supported */
	max_payload_len = uet_ep->uet_domain->uet->max_payload_len;
	req_len = ntohl(ses->req_len);
	if (write)
		start_off = ntohll(ses->buf_off);
	else
		start_off = 0;

	/* RUDI write: RUDI maintains NO SES state and NO message completion
	 * at the target. Each packet is placed directly into memory
	 * (idempotent, out of order) and answered with one response. Bypass
	 * the RUD message reassembly which relies on the PDC de-duplicating
	 * and therefore cannot tolerate the duplicate chunks that RUDI's
	 * no-dedup and retransmit produce. A duplicate chunk simply re-writes
	 * the same bytes (harmless), and there is no per-message state to
	 * corrupt or leave dangling. Message completion is at the initiator
	 * (after all RUDI responses received for a message).
	 */
	if (write && (pp->pds_type == UET_PDS_TYPE_RUDI_REQ)) {
		if (ses->cmn.ver_flags & UET_SES_REQ_FLAG_SOM) {
			buf_off = start_off;
		} else {
			payload_len_msg_off = ntohll(ses->payload_len_msg_off);
			buf_off = (start_off +
				   ((payload_len_msg_off &
				     UET_SES_REQ_STD_MSG_OFF_MASK) >>
				    UET_SES_REQ_STD_MSG_OFF_SHIFT));
		}

		mr_desc = uet_get_mr_desc(uet_ep, pp);
		if (mr_desc == NULL) {
			UET_API_ERR("RX: RUDI Write: Invalid Key");
			return UET_RC_BAD_MKEY;
		}

		if (!(mr_desc->access & FI_REMOTE_WRITE)) {
			UET_API_ERR("RX: RUDI Write: No Remote Write Permission");
			return UET_RC_PERM_VIOLATION;
		}

		/*
		 * RUDI may only target an IDEMPOTENT_SAFE memory region (spec
		 * Table 2-16): a RUDI packet can be applied to memory more than
		 * once (retransmit/replay), so the target MR must be marked safe
		 * for idempotent operations.
		 */
		if (!(mr_desc->full_key & UET_MR_KEY_IDEMPOTENT_SAFE)) {
			UET_API_ERR("RX: RUDI Write: MR not IDEMPOTENT_SAFE");
			return UET_RC_OP_VIOLATION;
		}

		if (!uet_mr_addr_to_offset(mr_desc, buf_off,
					   pp->ses_payload_len, &buf_off)) {
			UET_API_ERR("RX: RUDI Write: Invalid Buffer Offset");
			return UET_RC_BAD_ADDR;
		}

		if (uet_mr_scatter(mr_desc, buf_off, pp->payload,
				   pp->ses_payload_len) !=
		    pp->ses_payload_len) {
			UET_API_ERR("RX: RUDI Write: Invalid Buffer Offset");
			return UET_RC_BAD_ADDR;
		}

		return UET_RC_OK; /* caller will emit one RUDI response */
	}

	/* get rx descriptor for message */
	ses_rc = uet_get_rx_desc(uet_ep, pp, write, sync, UET_RC_OK, &msg_key,
				 &rx_desc, &first_msg_pkt);
	if (ses_rc != UET_RC_OK)
		return ses_rc;

	/* check for start of message */
	if (ses->cmn.ver_flags & UET_SES_REQ_FLAG_SOM) {
		/* check if rx completion queue is available */
		if (!(write) || (ses->cmn.ver_flags & UET_SES_REQ_FLAG_HD)) {
			if (uet_ep->recv_cq.cq_state == UET_CQ_DOWN) {
				UET_API_ERR("RX: Completion Q DOWN");
				return (uet_rx_msg_err(uet_ep, pp, rx_desc,
						UET_RC_DISABLED));
			}
		}

		payload_len_msg_off = 0;
		/* set buffer offset length and check payload length */
		buf_off = start_off;
		if (((pp->ses_payload_len != req_len) &&
		     (pp->ses_payload_len != max_payload_len)) ||
		    (pp->ses_payload_len > pp->pkt_payload_len))
			invalid_payload_len = true;
	} else {
		/* set buffer offset and check payload length */
		payload_len_msg_off = ntohll(ses->payload_len_msg_off);
		buf_off = (start_off + ((payload_len_msg_off &
					 UET_SES_REQ_STD_MSG_OFF_MASK) >>
					UET_SES_REQ_STD_MSG_OFF_SHIFT));
		if (pp->ses_payload_len > pp->pkt_payload_len)
			invalid_payload_len = true;
	}

	/* handle invalid payload length */
	if (invalid_payload_len) {
		UET_API_ERR("RX: Invalid Payload Len");
		return (uet_rx_msg_err(uet_ep, pp, rx_desc,
				       UET_RC_OP_VIOLATION));
	}

	/* handle first and non-first packets of message differently */
	if (!first_msg_pkt) {
		if (write) {
			/* check for proper mr key and permissions */
			if (rx_desc->mr_desc == NULL) {
				UET_API_ERR("RX: RMA Op for Non-RMA Message");
				return (uet_rx_msg_err(
					uet_ep, pp, rx_desc,
					UET_RC_OP_VIOLATION));
			}
			if (!(rx_desc->desc_flags & UET_RX_DESC_FLAG_WRITE)) {
				UET_API_ERR("RX: Write for Non-Write Message");
				return (uet_rx_msg_err(
					uet_ep, pp, rx_desc,
					UET_RC_OP_VIOLATION));
			}
			if (rx_desc->mr_desc->full_key !=
			    ntohll(ses->match_bits)) {
				UET_API_ERR("RX: RMA Op with Changed Key");
				return (uet_rx_msg_err(
					uet_ep, pp, rx_desc,
					UET_RC_PERM_VIOLATION));
			}
		}
	} else { /* first packet of message */
		/* UUD is connectionless and has no generation semantics */
		if (pp->pds_type != UET_PDS_TYPE_UUD_REQ) {
			/* check that generation is enabled */
			if (tagged) {
				ep_gen_disabled = uet_ep->tagged_gen_disabled;
				ep_gen = (uint32_t) uet_ep->tagged_gen;
			} else {
				ep_gen_disabled = uet_ep->untagged_gen_disabled;
				ep_gen = (uint32_t) uet_ep->untagged_gen;
			}

			if (ep_gen_disabled) {
				UET_API_ERR("RX: Disabled Generation");
				return (uet_rx_msg_err(uet_ep, pp, rx_desc,
						       UET_RC_DISABLED_GEN));
			}

			/* check for correct generation */
			rx_gen = (uint32_t)((ntohl(ses->cmn.ri_gen_job_id) &
					     UET_SES_REQ_RI_GEN_MASK) >>
					    UET_SES_REQ_RI_GEN_SHIFT);
			if (rx_gen != ep_gen) {
				UET_API_ERR("RX: Bad Generation");
				return (uet_rx_msg_err(uet_ep, pp, rx_desc,
						       UET_RC_BAD_GENERATION));
			}
		}

		/* find buffer */
		if (tagged) {
			/* check if there is a matching rx buffer */
			uet_tag_initiator_key_init(&tag_key, pp);
			rx_desc = uet_tag_initiator_hash_lookup(uet_ep,
								&tag_key);
			if (rx_desc == NULL) {
				/* lookup without initiator */
				memset(&tag_only_key, 0,
				       sizeof(struct uet_tag_initiator_key));
				tag_only_key.tag = tag_key.tag;
				tag_only_key.initiator_invalid = true;
				tag_only_key.initiator = UET_INITIATOR_NONE;
				rx_desc = uet_tag_initiator_hash_lookup(
							uet_ep, &tag_only_key);
			}

			if (rx_desc == NULL) {
				ses_rc = UET_RC_NO_MATCH;
				if (pp->ses_opcode == UET_DEFER_TSEND)
					ses_rc = uet_rx_dsend(uet_ep, pp, list,
							      true, &tag_key);
				if (ses_rc == UET_RC_NO_MATCH)
					UET_API_ERR(
					"RX: Unexpected Tagged Message");
				if (uet_get_pds_mode(uet_ep, false) ==
				    UET_PDS_MODE_ROD)
					uet_ep->tagged_gen_disabled = true;
				return (uet_rx_msg_err(uet_ep, pp, rx_desc,
						       ses_rc));
			}

			/* check if rx buffer is big enough for message */
			if ((start_off + req_len) > rx_desc->buf_desc.len) {
				UET_API_ERR("RX: Tagged Buffer Too Small");
				return (uet_rx_msg_err(uet_ep, pp, rx_desc,
						UET_RC_UNSUPPORTED_SIZE));
			}

			/* remove descriptor from tag hash table */
			uet_tag_initiator_hash_remove(uet_ep, rx_desc);
		} else if (!write) {
			/* check if there is a rx buffer available */
			ring = &uet_ep->rx_ring;
			if (uet_ring_empty(ring)) {
				ses_rc = UET_RC_NO_MATCH;
				if (pp->ses_opcode == UET_DEFER_SEND)
					ses_rc = uet_rx_dsend(uet_ep, pp, list,
							      false, NULL);
				if (ses_rc == UET_RC_NO_MATCH)
					UET_API_ERR("RX: Unexpected Message");
				/* UUD is stateless and an unexpected datagram
				 * is simply dropped (best effort). Generation
				 * is always disabled.
				 */
				if ((uet_get_pds_mode(uet_ep, false) ==
				     UET_PDS_MODE_ROD) &&
				    (pp->pds_type != UET_PDS_TYPE_UUD_REQ))
					uet_ep->untagged_gen_disabled = true;
				return (uet_rx_msg_err(uet_ep, pp, rx_desc,
						       ses_rc));
			}

			/* check if rx buffer is big enough for message */
			rx_desc = (struct uet_rx_desc *)
				  (((struct uet_rx_desc_ring_entry *)
				    (ring->base))[ring->tail].rx_desc);
			if ((start_off + req_len) > rx_desc->buf_desc.len) {
				UET_API_ERR("RX: Buffer Too Small");
				return (uet_rx_msg_err(uet_ep, pp, rx_desc,
						UET_RC_UNSUPPORTED_SIZE));
			}

			/* remove descriptor from ring */
			uet_rx_desc_ring_remove(rx_desc);
		} else { /* handle rma */
			/* check mr permissions */
			if (!(rx_desc->mr_desc->access & FI_REMOTE_WRITE)) {
				UET_API_ERR("RX: No Remote Write Permission");
				return (uet_rx_msg_err(uet_ep, pp, rx_desc,
						UET_RC_PERM_VIOLATION));
			}

			/* check if mr buffer is big enough for message */
			if ((start_off + req_len) >
			    rx_desc->mr_desc->buf_desc.len) {
				UET_API_ERR("RX: MR Buffer Too Small");
				return (uet_rx_msg_err(uet_ep, pp, rx_desc,
						UET_RC_UNSUPPORTED_SIZE));
			}
		}

		/* Enforce the posted buffer's job authorization: a buffer
		 * posted for a specific JobID (not UET_JOB_ID_ANY) may only
		 * be consumed by a message from that job. Sends only. RMA
		 * writes authorize per-MR, and relative endpoints are
		 * already demux'd by JobID.
		 */
		if (!write &&
		    (rx_desc->job_id != UET_JOB_ID_ANY) &&
		    (rx_desc->job_id != uet_get_std_req_job_id(ses))) {
			UET_API_ERR("RX: Buffer Job ID Mismatch");
			return (uet_rx_msg_err(uet_ep, pp, rx_desc,
					       UET_RC_BAD_JOB_ID));
		}

		/* insert rx desc into active list and rx msg lookup tbl */
		rx_desc->msg_len = req_len;
		rx_desc->remaining_bytes = req_len;
		uet_rx_desc_active_list_insert(rx_desc);
		uet_rx_msg_key_init(&rx_desc->msg_key, pp);
		uet_rx_msg_hash_insert(uet_ep, rx_desc);

		/* header (immediate/remote CQ) data is carried on the first
		 * packet by both write-with-immediate and send-with-immediate
		 */
		if (ses->cmn.ver_flags & UET_SES_REQ_FLAG_HD) {
			if (uet_ep->recv_cq.format_size <
			    sizeof(struct fi_cq_data_entry)) {
				UET_API_ERR(
				"RX: No CQ Support for Immediate Data");
				return (uet_rx_msg_err(
						uet_ep, pp, rx_desc,
						UET_RC_OP_VIOLATION));
			}

			rx_desc->imm_data = ntohll(ses->cmpl_data);
			rx_desc->desc_flags |= UET_RX_DESC_FLAG_WRITE_IMM;

			/* a write generates no completion on its own, so force
			 * one; a send completes via its posted receive, which
			 * already carries POST_CQ
			 */
			if (write)
				rx_desc->desc_flags |= UET_RX_DESC_FLAG_POST_CQ;
		}
	}

	/* validate pkt fits in buffer */
	if ((buf_off + pp->ses_payload_len) > rx_desc->buf_desc.len) {
		UET_API_ERR("RX: Invalid Buffer Offset");
		return (uet_rx_msg_err(uet_ep, pp, rx_desc,
				       UET_RC_BAD_ADDR));
	}

	/* validate payload length doesn't exceed request length */
	if (pp->ses_payload_len > rx_desc->remaining_bytes) {
		UET_API_ERR("RX: Payload Len Exceeds Request Len");
		return (uet_rx_msg_err(uet_ep, pp, rx_desc,
				       UET_RC_OP_VIOLATION));
	}

	/* check for initiator error */
	if (ses->cmn.ver_flags & UET_SES_REQ_FLAG_IE) {
		UET_API_ERR("RX: Initiator Error");
		return (uet_rx_msg_err(uet_ep, pp, rx_desc,
				       UET_RC_INITIATOR_ERR));
	}

	if (rx_desc->buf_desc.type == UET_MSG_BUF_TYPE_MR) {
		if (uet_mr_scatter(rx_desc->mr_desc, buf_off, pp->payload,
				   pp->pkt_payload_len) !=
		    pp->pkt_payload_len) {
			UET_API_ERR("RX: Invalid Buffer Offset");
			return (uet_rx_msg_err(uet_ep, pp, rx_desc,
					       UET_RC_BAD_ADDR));
		}
	} else if (rx_desc->buf_desc.type == UET_MSG_BUF_TYPE_SEG) {
		if (scatter_flat_to_seg(rx_desc->buf_desc.seg.seg,
					rx_desc->buf_desc.seg.seg_count,
					pp->payload, pp->pkt_payload_len,
					buf_off) != pp->pkt_payload_len) {
			UET_API_ERR("RX: Payload Exceeds Segment List");
			return (uet_rx_msg_err(uet_ep, pp, rx_desc,
					       UET_RC_BAD_ADDR));
		}
	} else if (rx_desc->buf_desc.type == UET_MSG_BUF_TYPE_IOV) {
		if (scatter_flat_to_iov(rx_desc->buf_desc.iov.iov,
					rx_desc->buf_desc.iov.iov_count,
					pp->payload, pp->pkt_payload_len,
					buf_off) != pp->pkt_payload_len) {
			UET_API_ERR("RX: Payload Exceeds Scatter List");
			return (uet_rx_msg_err(uet_ep, pp, rx_desc,
					       UET_RC_BAD_ADDR));
		}
	} else {
		buf_ptr =  (void *) (((size_t) rx_desc->buf_desc.buf) +
				     buf_off);
		memcpy(buf_ptr, pp->payload, pp->ses_payload_len);
	}

	/* capture the initiator (SourceID) to report on the completion */
	rx_desc->src_id = ntohl(ses->initiator);

	/* check for message completion */
	rx_desc->remaining_bytes -= pp->ses_payload_len;
	if (rx_desc->remaining_bytes == 0)
		/* post rx completion queue entry */
		uet_rx_cq_post_entry(rx_desc);

	return UET_RC_OK;
}

/*
 * process a received message cancel packet (UET_MSG_ERR opcode)
 *
 * parms:
 *      uet_ep  - ptr to uet endpoint struct
 *      pp      - ptr to parsed packet struct
 *
 * returns:
 *   - ses return code
 */
static uet_ses_rc_t uet_rx_cancel_pkt(
	struct uet_ep *uet_ep, struct uet_parsed_pkt *pp)
{
	int rc;
	uet_ses_rc_t ses_rc = UET_RC_OK;
	bool msg_complete;
	struct uet_ses_req_std *ses;
	struct uet_rx_msg_key msg_key;
	struct uet_rx_desc *rx_desc;

	ses = (struct uet_ses_req_std *) pp->ses;

	if (ses->cmn.ver_flags & UET_SES_REQ_FLAG_IE)
		UET_API_ERR("RX: Unexpected IE on UET_MSG_ERR");

	uet_rx_msg_key_init(&msg_key, pp);
	rx_desc = uet_rx_msg_hash_lookup(uet_ep, &msg_key);
	if (rx_desc == NULL)
		goto err_exit;
	uet_rx_desc_active_list_move_to_tail(uet_ep, rx_desc);
	if (rx_desc->ses_rc != UET_RC_OK)
		ses_rc = rx_desc->ses_rc;
	if (rx_desc->ses_rc == UET_RC_OK) {
		UET_API_ERR("RX: Unsolicited UET_MSG_ERR");
		pp->ses_payload_len = 0;
		uet_rx_msg_err(uet_ep, pp, rx_desc,
			       UET_RC_INITIATOR_ERR);
		ses_rc = UET_RC_INITIATOR_ERR;
	} else if (rx_desc->desc_flags & UET_RX_DESC_FLAG_CANCELLED) {
		UET_API_ERR("RX: Unexpected Multiple UET_MSG_ERR");
		goto post_err_exit;
	}
	rx_desc->desc_flags |= UET_RX_DESC_FLAG_CANCELLED;

	if (ses->cmn.ver_flags & UET_SES_REQ_FLAG_SOM) {
		UET_API_ERR("RX: Unexpected SOM on UET_MSG_ERR");
		goto post_err_exit;
	} else if (!(ses->cmn.ver_flags & UET_SES_REQ_FLAG_EOM)) {
		UET_API_ERR("RX: No EOM on UET_MSG_ERR");
		goto post_err_exit;
	} else {
		rc = uet_rx_msg_truncate(pp, rx_desc, &msg_complete);
		if ((rc != FI_SUCCESS) || (msg_complete == true)) {
			if (rc != FI_SUCCESS)
				UET_API_ERR("RX: Invalid UET_MSG_ERR Offset");
			goto post_err_exit;
		}
	}

	return ses_rc;

post_err_exit:
	uet_rx_cq_post_err(rx_desc, FI_EIO);

err_exit:
	return UET_RC_OP_VIOLATION;
}

/* process received ready to restart request */
static uet_ses_rc_t uet_rx_rtr_req_pkt(
	    struct uet_instance *uet, struct uet_parsed_pkt *pp, uint32_t job_id,
	    struct uet_ep **uet_ep)
{
	uint32_t local_token, token_initiator_id, req_initiator_id;
	uint64_t full_token;
	struct uet_tx_desc *tx_desc;
	struct uet_ep *token_uet_ep;
	struct uet_ses_req_std *ses;

	ses = (struct uet_ses_req_std *) pp->ses;

	full_token = ntohll(ses->restart_token_rtr);
	local_token = (full_token & UET_SES_REQ_STD_DST_TOKEN_MASK) >>
		UET_SES_REQ_STD_DST_TOKEN_SHIFT;

	if (local_token > UET_MAX_RTR_TOKEN)
		goto err_exit;

	tx_desc = uet_get_rtr_token_tx_desc(uet, (uint16_t) local_token);
	if (tx_desc == NULL)
		goto err_exit;

	token_initiator_id =
		uet_get_rtr_token_initiator(uet, (uint16_t) local_token);
	req_initiator_id = ntohl(ses->initiator);
	if (token_initiator_id != req_initiator_id)
		goto err_exit;

	token_uet_ep = uet_get_rtr_token_ep(uet, (uint16_t) local_token);
	if (tx_desc->uet_ep != token_uet_ep)
		return UET_RC_OP_VIOLATION;

	/*
	 * Validate all request identity before consuming the restart token.
	 * In particular, a request for another relative endpoint's JobID must
	 * not remove the descriptor from its deferred list or mark it ready.
	 */
	if (!token_uet_ep->absolute && token_uet_ep->job_id != job_id) {
		UET_API_ERR("RX: Bad Job ID on Restart Token");
		return UET_RC_BAD_JOB_ID;
	}

	tx_desc->remote_rtr_token =
		(full_token & UET_SES_REQ_STD_SRC_TOKEN_MASK) >>
		UET_SES_REQ_STD_SRC_TOKEN_SHIFT;
	uet_tx_desc_defer_list_remove(tx_desc);
	tx_desc->desc_flags |= UET_TX_DESC_FLAG_GOT_RTR;

	*uet_ep = token_uet_ep;
	return UET_RC_OK;

err_exit:
	UET_API_ERR("RX: Invalid Restart Token");
	return UET_RC_OP_VIOLATION;
}

/* process received read response data */
static uet_ses_rc_t uet_rx_read_data(
	    struct uet_ep *uet_ep, struct uet_rx_desc *rx_desc,
	    struct uet_parsed_pkt *pp)
{
	uint32_t msg_off;
	void *buf_ptr;
	struct uet_ses_rsp_d *ses;

	ses = (struct uet_ses_rsp_d *) pp->ses;

	/* check payload length */
	if ((pp->ses_payload_len > rx_desc->msg_len) ||
	    (pp->ses_payload_len > pp->pkt_payload_len)) {
		UET_API_ERR("Read Rsp: Invalid Payload Len");
		return UET_RC_OP_VIOLATION;
	}

	/* validate pkt fits in buffer */
	msg_off = ntohl(ses->msg_off);
	if ((msg_off + pp->ses_payload_len) > rx_desc->buf_desc.len) {
		UET_API_ERR("Read Rsp: Invalid Message Offset");
		return UET_RC_BAD_ADDR;
	}

	/* scatter the read response into the local buffer (which may be a
	 * multi-segment scatter/gather list)
	 */
	switch (rx_desc->buf_desc.type) {
	case UET_MSG_BUF_TYPE_SEG:
		if (scatter_flat_to_seg(rx_desc->buf_desc.seg.seg,
					rx_desc->buf_desc.seg.seg_count,
					ses->payload, pp->ses_payload_len,
					msg_off) != pp->ses_payload_len) {
			UET_API_ERR("Read Rsp: Payload Exceeds Segment List");
			return UET_RC_BAD_ADDR;
		}
		break;

	case UET_MSG_BUF_TYPE_IOV:
		if (scatter_flat_to_iov(rx_desc->buf_desc.iov.iov,
					rx_desc->buf_desc.iov.iov_count,
					ses->payload, pp->ses_payload_len,
					msg_off) != pp->ses_payload_len) {
			UET_API_ERR("Read Rsp: Payload Exceeds Scatter List");
			return UET_RC_BAD_ADDR;
		}
		break;

	case UET_MSG_BUF_TYPE_CONTIG:
		buf_ptr = (void *) (((size_t) rx_desc->buf_desc.buf) + msg_off);
		memcpy(buf_ptr, ses->payload, pp->ses_payload_len);
		break;

	default:
		/* A read response lands in the initiator's own buffer. Any
		 * other description of it is a bug rather than something to
		 * fall through into a raw pointer dereference.
		 */
		UET_API_ERR("Read Rsp: unexpected buffer type %d",
			    rx_desc->buf_desc.type);
		return UET_RC_BAD_ADDR;
	}

	return UET_RC_OK;
}

/* process received atomic response data */
static uet_ses_rc_t uet_rx_atomic_data(
	    struct uet_ep *uet_ep, struct uet_tx_desc *tx_desc,
	    uint32_t mod_len, struct uet_parsed_pkt *pp)
{
	uint64_t result, *buf_ptr;
	struct uet_ses_rsp_d *ses;

	ses = (struct uet_ses_rsp_d *) pp->ses;

	if (pp->ses_payload_len > pp->pkt_payload_len) {
		UET_API_ERR("Atomic Rsp: Invalid Payload Len");
		return UET_RC_OP_VIOLATION;
	}

	if (tx_desc->desc_flags & UET_TX_DESC_FLAG_ATOMIC_FETCH_REQ) {
		if (mod_len != tx_desc->buf_desc.len) {
			UET_API_ERR("Atomic Rsp: Truncated Message Len");
			return UET_RC_OP_VIOLATION;
		}
		if (pp->ses_payload_len != mod_len) {
			UET_API_ERR("Atomic Rsp: Invalid Payload Len");
			return UET_RC_OP_VIOLATION;
		}
	} else {
		if (mod_len != UET_CSWAP_DATA_BYTES) {
			UET_API_ERR("Atomic Rsp: Truncated Message Len");
			return UET_RC_OP_VIOLATION;
		}
		if (pp->ses_payload_len != UET_VERBS_ATOMIC_DATA_BYTES) {
			UET_API_ERR("Atomic Rsp: Invalid Payload Len");
			return UET_RC_OP_VIOLATION;
		}
	}

	/* copy the result */
	buf_ptr = (uint64_t *) (tx_desc->atomic_parms.result_buf);
	result = ntohll(*((uint64_t *) ses->payload));
	*buf_ptr = result;

	return UET_RC_OK;
}

/*
 * pds upcall to ses when request packet is received
 *
 * parms:
 *      rx_pkt_handle   - handle assigned to received packet by pds
 *      uet             - ptr to uet instance struct
 *      pp              - ptr to parsed packet struct
 *      pds_info        - ptr to info that needs to be echoed back to pds when
 *                        read data is transmitted
 *      req_ses_hdr     - ptr to ses header in request packet
 *      rsp_next_hdr    - address of location where identifer of ses header
 *                        format for response is to be returned, return
 *                        contents are only valid when function FI_SUCCESS
 *      rsp_ses_hdr     - ptr to buffer where ses header for response is to
 *                        be returned, return contents are only valid
 *                        when function returns FI_SUCCESS, buffer must be
 *                        large enough to hold maximum size ses response
 *      rsp_ses_hdr_len - address of location where length of ses header
 *                        for response is to be returned, return contents
 *                        are only valid when function returns FI_SUCCESS
 *      ses_nack        - ptr to location where ses indicates whether pds
 *                        should send pds nack instead of pds ack, return
 *                        contents are only valid when function returns
 *                        FI_SUCCESS, true => pds must send nack
 *                        ses response state
 *      gtd_del         - ptr to location where ses indicates whether pds
 *                        needs to maintain ses response state, return
 *                        contents are only valid when function returns
 *                        FI_SUCCESS, true => pds must guarantee delivery of
 *                        ses response state
 *
 * returns:
 *   - FI_SUCCESS when ses response is to be returned to initiator
 *   - negative value corresponding to fabric errno on error
 */
static int uet_pds_to_ses_rx_req(uet_pkt_handle_t rx_pkt_handle,
				 struct uet_instance *uet,
				 struct uet_parsed_pkt *pp,
				 struct uet_pds_info *pds_info,
				 uet_pds_next_hdr_t *rsp_next_hdr,
				 void *rsp_ses_hdr, size_t *rsp_ses_hdr_len,
				 bool *ses_nack, bool *gtd_del)
{
	uet_ses_rc_t ses_rc;
	uint8_t ver;
	uint16_t payload_len;
	uint32_t gen, ep_gen, job_id, resv_payload_len;
	bool first_msg_pkt;
	uet_ses_list_t list;
	struct uet_ep *uet_ep;
	struct uet_ses_req_std *ses_std_req;
	struct uet_ses_rsp *ses_rsp;
	struct uet_ses_rsp_d *rx_ses_rsp_d, *ses_rsp_d;
	struct uet_ep_key ep_key;
	struct uet_rx_msg_key msg_key;
	struct uet_rx_desc *rx_desc;
	struct uet_ack_d_info ack_d_info;

	ses_std_req = (struct uet_ses_req_std *) pp->ses;
	rx_ses_rsp_d = (struct uet_ses_rsp_d *) pp->ses;
	ses_rsp = (struct uet_ses_rsp *) rsp_ses_hdr;
	ses_rsp_d = (struct uet_ses_rsp_d *) rsp_ses_hdr;

	list = UET_EXPECTED;
	*ses_nack = false;
	ep_gen = 0;

	ses_rsp->cmn.msg_id = ses_std_req->cmn.msg_id;
	ses_rsp->cmn.ri_gen_job_id = ses_std_req->cmn.ri_gen_job_id;

	ver = (ses_std_req->cmn.ver_flags & UET_SES_VER_MASK) >>
		UET_SES_VER_SHIFT;

	if (ver != UET_SES_VER) {
		UET_API_ERR("RX: Bad SES Version = 0x%x", ver);
		/* no return code is defined for bad ses version */
		ses_rc = UET_RC_UNCOR;
		goto build_response;
	}

	switch (pp->next_hdr) {
	case UET_HDR_REQ_STD:
		ses_rsp->mod_len = ses_std_req->req_len;
		job_id = uet_get_std_req_job_id(ses_std_req);
		if (pp->ses_opcode != UET_DEFER_RTR) {
			uet_ep_key_init(&ep_key, pp);
			uet_ep = uet_ep_hash_lookup(uet, &ep_key);
			if (uet_ep == NULL) {
				UET_API_ERR("RX: Unknown Endpoint");
				ses_rc = UET_RC_UNDELIVERABLE;
				goto build_response;
			}
		} else {
			ses_rc = uet_rx_rtr_req_pkt(uet, pp, job_id, &uet_ep);
			if (ses_rc != UET_RC_OK)
				goto build_response;
		}
		/* Absolute endpoints receive from any JobID. Authorization
		 * is enforced per-MR (job-restricted regions). Relative
		 * endpoints demux/authorize by the endpoint JobID.
		 */
		if (!uet_ep->absolute && (uet_ep->job_id != job_id)) {
			UET_API_ERR("RX: Bad Job ID");
			ses_rc = UET_RC_BAD_JOB_ID;
			goto build_response;
		}
		break;
	case UET_HDR_RSP_DATA:
		rx_desc = uet_get_msg_id_rx_desc(
				uet, ntohs(rx_ses_rsp_d->cmn.msg_id));
		if (rx_desc == NULL) {
			UET_API_ERR("Read Rsp: Unknown Message ID");
			ses_rc = UET_RC_UNDELIVERABLE;
			goto build_response;
		}
		uet_ep = rx_desc->uet_ep;
		job_id = (ntohl(rx_ses_rsp_d->cmn.ri_gen_job_id) &
			  UET_SES_RSP_JOB_ID_MASK) >> UET_SES_RSP_JOB_ID_SHIFT;
		/* Absolute endpoints receive from any JobID. Authorization
		 * is enforced per-MR (job-restricted regions). Relative
		 * endpoints demux/authorize by the endpoint JobID.
		 */
		if (!uet_ep->absolute && (uet_ep->job_id != job_id)) {
			UET_API_ERR("RX: Bad Job ID");
			ses_rc = UET_RC_BAD_JOB_ID;
			goto build_response;
		}
		rx_desc->expected_rd_rsp--;
		ses_rc = uet_rx_read_data(uet_ep, rx_desc, pp);
		if (ses_rc == UET_RC_OK)
			ses_rsp->mod_len = htonl(rx_desc->msg_len);
		goto build_response;
	default:
		UET_API_ERR("RX: Unsupported Next Hdr Type = 0x%x",
			    pp->next_hdr);
		return -FI_EINVAL;
	}

	switch (pp->ses_opcode) {
	case UET_SEND:
	case UET_DEFER_SEND:
		ses_rc = uet_rx_req_pkt(uet_ep, pp, &list,
					false, false, false);
		ep_gen = (uint32_t) uet_ep->untagged_gen;
		break;
	case UET_TAGGED_SEND:
	case UET_DEFER_TSEND:
		ses_rc = uet_rx_req_pkt(uet_ep, pp, &list,
					true, false, false);
		ep_gen = (uint32_t) uet_ep->tagged_gen;
		break;
	case UET_DEFER_RTR:
		break;
	case UET_WRITE:
		ses_rc = uet_rx_req_pkt(uet_ep, pp, &list,
					false, true, false);
		if (ses_rc == UET_RC_UNCOR_TRNSNT)
			*ses_nack = true;
		ep_gen = (uint32_t) uet_ep->untagged_gen;
		break;
	case UET_SYNC_WRITE:
		ses_rc = uet_rx_req_pkt(uet_ep, pp, &list,
					false, true, true);
		if (ses_rc == UET_RC_UNCOR_TRNSNT)
			*ses_nack = true;
		ep_gen = (uint32_t) uet_ep->untagged_gen;
		break;
	case UET_READ:
		ses_rc = uet_rx_rd_req_pkt(uet_ep, pp, &list,
					   pds_info, &ack_d_info);
		if (ses_rc != UET_RC_OK) {
			if (ses_rc == UET_RC_UNCOR_TRNSNT)
				*ses_nack = true;
		} else if (ack_d_info.valid)
			goto build_response_w_data;
		ep_gen = (uint32_t) uet_ep->untagged_gen;
		break;
	case UET_MSG_ERR:
		ses_rc = uet_rx_cancel_pkt(uet_ep, pp);
		break;
	case UET_ATOMIC:
		ses_rc = uet_rx_atomic_req_pkt(uet_ep, pp, &list, false);
		ep_gen = (uint32_t) uet_ep->untagged_gen;
		break;
	case UET_SYNC_ATOMIC:
		ses_rc = uet_rx_atomic_req_pkt(uet_ep, pp, &list, true);
		ep_gen = (uint32_t) uet_ep->untagged_gen;
		break;
	case UET_FETCH_ATOMIC:
		ses_rc = uet_rx_fetch_atomic_req_pkt(uet_ep, pp, &list,
						     ses_rsp_d->payload,
					    	     &ack_d_info);
		if (ses_rc == UET_RC_OK)
			goto build_response_w_data;
		ep_gen = (uint32_t) uet_ep->untagged_gen;
		break;
	default:
		UET_API_ERR("RX: Unsupported Opcode = 0x%x", pp->ses_opcode);
		ses_rc = uet_get_rx_desc(
				uet_ep, pp, false, false, UET_RC_UNSUPPORTED_OP,
				&msg_key, &rx_desc, &first_msg_pkt);
		break;
	}

build_response:
	int opcode;
	if (ses_rc == UET_RC_OK) {
		opcode = UET_DEFAULT_RESPONSE;
		*gtd_del = false;
	} else {
		ses_rsp->mod_len = 0;
		if (ses_rc == UET_RC_DEFER_SEND)
			ses_rc = UET_RC_OK;
		opcode = UET_RESPONSE;
		*gtd_del = true;
	}
	ses_rsp->cmn.list_opcode = ((list << UET_SES_RSP_LIST_SHIFT) |
				    (opcode << UET_SES_OPCODE_SHIFT));
	ses_rsp->cmn.ver_ret_code = ((UET_SES_VER << UET_SES_VER_SHIFT) |
				     (ses_rc << UET_SES_RSP_RET_CODE_SHIFT));
	if (ses_rc == UET_RC_BAD_GENERATION) {
		/* return correct generation */
		gen = (ep_gen << UET_SES_RSP_RI_GEN_SHIFT);
		ses_rsp->cmn.ri_gen_job_id = htonl(gen | job_id);
	}

	*rsp_ses_hdr_len = sizeof(struct uet_ses_rsp);
	*rsp_next_hdr = UET_HDR_RSP;

	return FI_SUCCESS;

build_response_w_data:
	*gtd_del = true;
	ses_rsp_d->cmn.list_opcode =
		((list << UET_SES_RSP_LIST_SHIFT) |
		 (UET_RESPONSE_W_DATA << UET_SES_OPCODE_SHIFT));
	ses_rsp_d->cmn.ver_ret_code =
		((UET_SES_VER << UET_SES_VER_SHIFT) |
		 (ses_rc << UET_SES_RSP_RET_CODE_SHIFT));
	payload_len = (ack_d_info.payload_len &
		       UET_SES_RSP_D_PAYLOAD_LEN_MASK) >>
		      UET_SES_RSP_D_PAYLOAD_LEN_SHIFT;
	ses_rsp_d->rd_msg_id = ses_std_req->cmn.msg_id;
	ses_rsp_d->payload_len = htons(payload_len);
	ses_rsp_d->mod_len = ses_std_req->req_len;
	ses_rsp_d->msg_off = htonl(ack_d_info.msg_off);

	if (pp->ses_opcode != UET_FETCH_ATOMIC)
		memcpy(ses_rsp_d->payload, ack_d_info.buf,
		       ack_d_info.payload_len);

	*rsp_ses_hdr_len =
		sizeof(struct uet_ses_rsp_d) + ack_d_info.payload_len;
	*rsp_next_hdr = UET_HDR_RSP_DATA;

	return FI_SUCCESS;
}

/*
 * build read response ses header for packet to be transmitted
 *
 * parms:
 *      tx_desc     - transmit descriptor for message
 *      payload_len - ses payload length for packet in bytes
 *      ses         - ptr to location where ses header is to be built
 *
 * returns:
 *      FI_SUCCESS on success
 *      negative value corresponding to fabric errno on error
 */
static int uet_build_rd_rsp_ses_hdr(struct uet_tx_desc *tx_desc,
				    size_t payload_len,
				    struct uet_ses_rsp_d *ses)
{
	uet_ses_rsp_opcode_t opcode;
	uet_ses_list_t list;
	uet_ses_rc_t ses_rc;

	list = UET_EXPECTED;
	opcode = UET_RESPONSE_W_DATA;
	ses_rc = UET_RC_OK;

	ses->cmn.list_opcode = ((list << UET_SES_RSP_LIST_SHIFT) |
				(opcode << UET_SES_OPCODE_SHIFT));
	ses->cmn.ver_ret_code = ((UET_SES_VER << UET_SES_VER_SHIFT) |
				 (ses_rc << UET_SES_RSP_RET_CODE_SHIFT));
	ses->cmn.msg_id = htons(tx_desc->msg_id);
	ses->cmn.ri_gen_job_id = htonl(tx_desc->job_id <<
				       UET_SES_RSP_JOB_ID_SHIFT);
	ses->rd_msg_id = htons(tx_desc->rd_rsp.req_msg_id);
	ses->payload_len = htons(payload_len <<
				 UET_SES_RSP_D_PAYLOAD_LEN_SHIFT);
	ses->mod_len = htonl(tx_desc->rd_rsp.mod_len);
	ses->msg_off = htonl(tx_desc->remote_msg_off);

	return FI_SUCCESS;
}

/* build restart token for inclusion in ses header */
uint64_t uet_build_ses_rtr_token(uint64_t local_token, uint64_t remote_token)
{
	uint64_t token;

	token = ((local_token << UET_SES_REQ_STD_SRC_TOKEN_SHIFT) &
		 UET_SES_REQ_STD_SRC_TOKEN_MASK) |
		((remote_token << UET_SES_REQ_STD_DST_TOKEN_SHIFT) &
		 UET_SES_REQ_STD_DST_TOKEN_MASK);
	return htonll(token);
}

/*
 * SES rel flag for a message's destination addressing mode: set for relative
 * addressing, clear for absolute. The mode is taken from the destination
 * address. Defaults to relative when no address is available.
 */
static uint8_t uet_ses_rel_flag(struct uet_av_entry *av)
{
	if (av && av->addr && (av->addr->flags & UET_ADDR_ABSOLUTE_MODE))
		return 0;

	return UET_SES_REQ_FLAG_REL;
}

/*
 * build rtr request ses header for packet to be transmitted
 *
 * parms:
 *      tx_desc - transmit descriptor for message
 *      ses     - ptr to location where ses header is to be built
 *
 * returns:
 *      FI_SUCCESS on success
 *      negative value corresponding to fabric errno on error
 */
static int uet_build_rtr_req_ses_hdr(struct uet_tx_desc *tx_desc,
				     struct uet_ses_req_std *ses)
{
	uint64_t local_token, remote_token;
	struct uet_av_entry *av =
		(struct uet_av_entry *) tx_desc->dst_addr_handle;

	memset(ses, 0, sizeof(struct uet_ses_req_std));
	ses->cmn.rsvd_opcode = UET_DEFER_RTR << UET_SES_OPCODE_SHIFT;
	ses->cmn.ver_flags = ((UET_SES_VER << UET_SES_VER_SHIFT)	|
			      uet_ses_rel_flag(av)			|
			      UET_SES_REQ_FLAG_EOM			|
			      UET_SES_REQ_FLAG_SOM);
	ses->cmn.msg_id = htons(tx_desc->msg_id);
	ses->cmn.ri_gen_job_id =
		htonl(tx_desc->job_id << UET_SES_REQ_JOB_ID_SHIFT);
	ses->initiator = htonl(tx_desc->uet_ep->uet_addr.initiator_id);
	local_token = tx_desc->local_rtr_token;
	remote_token = tx_desc->remote_rtr_token;
	ses->restart_token_rtr = uet_build_ses_rtr_token(local_token,
							 remote_token);

	return FI_SUCCESS;
}

/*
 * build ses header for atomic operation request packet to be transmitted
 *
 * parms:
 *      tx_desc - ptr to tx descriptor for message
 *      ses_hdr - ptr to location where ses header is to be built
 *
 * returns:
 *      FI_SUCCESS on success
 *      negative value corresponding to fabric errno on error
 */
static int uet_build_atomic_req_ses_hdr(struct uet_tx_desc *tx_desc,
					void *ses_hdr)
{
	struct uet_ses_req_std_cswap *ses;
	struct uet_ses_req_std_atomic_sync *ses_sync;
	struct uet_av_entry *av;
	struct uet_ep *uet_ep;
	struct uet_instance *uet;
	uint8_t opcode;
	int dc = 0;
	uint64_t *data_val, *ses_atomic_data, *swap_val;

	ses =  (struct uet_ses_req_std_cswap *) ses_hdr;
	av = (struct uet_av_entry *) tx_desc->dst_addr_handle;
	uet_ep = tx_desc->uet_ep;

	if (tx_desc->desc_flags & UET_TX_DESC_FLAG_ATOMIC_REQ) {
		if (tx_desc->desc_flags & UET_TX_DESC_FLAG_SYNC_REQ)
			opcode = UET_SYNC_ATOMIC;
		else
			opcode = UET_ATOMIC;
	} else
		opcode = UET_FETCH_ATOMIC;

	ses->base.cmn.rsvd_opcode = opcode << UET_SES_OPCODE_SHIFT;

	if (tx_desc->op_flags & FI_DELIVERY_COMPLETE)
		dc = UET_SES_REQ_FLAG_DC;

	ses->base.cmn.ver_flags = ((UET_SES_VER << UET_SES_VER_SHIFT)	|
				   UET_SES_REQ_FLAG_SOM 		|
				   UET_SES_REQ_FLAG_EOM			|
				   dc					|
				   uet_ses_rel_flag(av));

	ses->base.cmn.msg_id = htons(tx_desc->msg_id);

	ses->base.cmn.ri_gen_job_id = htonl(
		(av->untagged_gen << UET_SES_REQ_RI_GEN_SHIFT) |
		(tx_desc->job_id << UET_SES_REQ_JOB_ID_SHIFT));

	ses->base.cmn.rsvd_pid_on_fep = htons(av->addr->pid_on_fep <<
					      UET_SES_REQ_PID_ON_FEP_SHIFT);

#if !ENABLE_VERBS
	ses->base.cmn.rsvd_res_index = htons(av->addr->start_index <<
					     UET_SES_REQ_RES_INDEX_SHIFT);
#else
	ses->base.cmn.rsvd_res_index = htons(tx_desc->resource_index <<
					     UET_SES_REQ_RES_INDEX_SHIFT);
#endif

	ses->base.buf_off = htonll(tx_desc->remote_start_off);

	ses->base.initiator = htonl(uet_ep->uet_addr.initiator_id);

	ses->base.mem_key = htonll(tx_desc->remote_key);

	ses->base.cmpl_data = 0;

	if (!(tx_desc->desc_flags & UET_TX_DESC_FLAG_SYNC_REQ)) {
		ses->ext.cmn.atomic_opcode = tx_desc->atomic_parms.opcode;
		ses->ext.cmn.atomic_dt = tx_desc->atomic_parms.data_type;
		ses->ext.cmn.sem_ctrl = UET_AMO_CPU_COHERENT;
		ses->ext.cmn.rsvd = 0;
	}

	if (tx_desc->desc_flags & UET_TX_DESC_FLAG_ATOMIC_COMPARE_REQ) {
		ses->base.req_len = htonl(UET_CSWAP_DATA_BYTES);
		ses->ext.cmp_val_hi = 0;
		ses->ext.cmp_val_lo = htonll(
			*((uint64_t *) tx_desc->atomic_parms.compare_buf));
		ses->ext.swp_val_hi = 0;
		swap_val = (uint64_t *) (((size_t) tx_desc->buf_desc.buf) +
					 tx_desc->buf_desc.buf_off);
		ses->ext.swp_val_lo = htonll(*swap_val);
	} else {
		ses->base.req_len = htonl(tx_desc->buf_desc.len);
		data_val = (uint64_t *) (((size_t) tx_desc->buf_desc.buf) +
				         tx_desc->buf_desc.buf_off);

		if (tx_desc->desc_flags & UET_TX_DESC_FLAG_SYNC_REQ) {
			ses_sync = (struct uet_ses_req_std_atomic_sync *) ses;
			uet = uet_ep->uet_domain->uet;
			ses_sync->sync_ext.group = htons(tx_desc->sync_grp);
			ses_sync->sync_ext.cnt = htons(
			      uet->sync_grp_cb.cnts[tx_desc->sync_grp].tot_cnt);
			ses_sync->atomic_ext.atomic_opcode =
				tx_desc->atomic_parms.opcode;
			ses_sync->atomic_ext.atomic_dt =
				tx_desc->atomic_parms.data_type;
			ses_sync->atomic_ext.sem_ctrl = UET_AMO_CPU_COHERENT;
			ses_sync->atomic_ext.rsvd = 0;
			ses_atomic_data =
				(uint64_t *) &ses_sync->data;
		} else
			ses_atomic_data = (uint64_t *) &ses->ext.cmp_val_hi;

		*ses_atomic_data = htonll(*data_val);
	}

	return FI_SUCCESS;
}

/*
 * build ses header for packet to be transmitted
 *
 * parms:
 *      tx_desc - ptr to tx descriptor for message
 *      pkt_len - ses payload length for packet in bytes
 *      ses_hdr - ptr to location where ses header is to be built
 *
 * returns:
 *      FI_SUCCESS on success
 *      negative value corresponding to fabric errno on error
 */
static int uet_build_ses_hdr(struct uet_tx_desc *tx_desc, size_t pkt_len,
			     void *ses_hdr)
{
	struct uet_ses_req_std *ses;
	struct uet_ses_req_std_sync *ses_sync;
	struct uet_av_entry *av;
	struct uet_ep *uet_ep;
	struct uet_instance *uet;
	uint8_t opcode;
	uint64_t local_token, remote_token;
	int som = 0, eom = 0, dc = 0;
	size_t req_len, payload_len, max_payload_len;

	ses =  (struct uet_ses_req_std *) ses_hdr;
	av = (struct uet_av_entry *) tx_desc->dst_addr_handle;
	uet_ep = tx_desc->uet_ep;

	if (tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_RSP)
		return uet_build_rd_rsp_ses_hdr(
			tx_desc, pkt_len, (struct uet_ses_rsp_d *) ses_hdr);

	if (tx_desc->desc_flags & UET_TX_DESC_FLAG_RTR_REQ)
		return uet_build_rtr_req_ses_hdr(tx_desc, ses);

	if (tx_desc->desc_flags & (UET_TX_DESC_FLAG_ATOMIC_REQ       |
		         	   UET_TX_DESC_FLAG_ATOMIC_FETCH_REQ |
		         	   UET_TX_DESC_FLAG_ATOMIC_COMPARE_REQ))
		return uet_build_atomic_req_ses_hdr(tx_desc, ses_hdr);

	req_len = tx_desc->buf_desc.len;
	if (tx_desc->remaining_bytes == req_len) {
		som = UET_SES_REQ_FLAG_SOM;
		ses->cmpl_data = 0;
		payload_len = pkt_len;
	} else {
		if (tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_REQ) {
			max_payload_len =
				uet_ep->uet_domain->uet->max_payload_len;
			if (tx_desc->remaining_bytes > max_payload_len)
				payload_len = max_payload_len;
			else
				payload_len = tx_desc->remaining_bytes;
		} else
			payload_len = pkt_len;
		ses->payload_len_msg_off =
			htonll(((tx_desc->buf_desc.buf_off <<
				 UET_SES_REQ_STD_MSG_OFF_SHIFT) &
				UET_SES_REQ_STD_MSG_OFF_MASK) |
			       ((payload_len <<
				 UET_SES_REQ_STD_PAYLOAD_LEN_SHIFT) &
				UET_SES_REQ_STD_PAYLOAD_LEN_MASK));
	}

	if ((som && (payload_len == req_len)) ||
	    (!som && (payload_len == tx_desc->remaining_bytes)))
		eom = UET_SES_REQ_FLAG_EOM;

	if (tx_desc->op_flags & FI_DELIVERY_COMPLETE)
		dc = UET_SES_REQ_FLAG_DC;

	ses->cmn.ver_flags = ((UET_SES_VER << UET_SES_VER_SHIFT)	|
			      dc					|
			      uet_ses_rel_flag(av)			|
			      som);

	ses->cmn.ri_gen_job_id = htonl(
		(av->untagged_gen << UET_SES_REQ_RI_GEN_SHIFT) |
		(tx_desc->job_id << UET_SES_REQ_JOB_ID_SHIFT));

	ses->buf_off = htonll(tx_desc->remote_start_off);

	if (tx_desc->cq_flags & FI_MSG) {
		if (tx_desc->desc_flags & UET_TX_DESC_FLAG_DSEND) {
			opcode = UET_DEFER_SEND;
			local_token = tx_desc->local_rtr_token;
			remote_token = tx_desc->remote_rtr_token;
			ses->restart_token =
				uet_build_ses_rtr_token(local_token,
							remote_token);
		} else
			opcode = UET_SEND;
		ses->match_bits = UET_NO_TAG;
		if (som &&
		    (tx_desc->desc_flags & UET_TX_DESC_FLAG_IMM_DATA_VALID)) {
			ses->cmn.ver_flags |= UET_SES_REQ_FLAG_HD;
			ses->cmpl_data = htonll(tx_desc->tag_or_immdata);
		}
	} else if (tx_desc->cq_flags & FI_TAGGED) {
		if (tx_desc->desc_flags & UET_TX_DESC_FLAG_DSEND) {
			opcode = UET_DEFER_TSEND;
			local_token = tx_desc->local_rtr_token;
			remote_token = tx_desc->remote_rtr_token;
			ses->restart_token =
				uet_build_ses_rtr_token(local_token,
							remote_token);
		} else
			opcode = UET_TAGGED_SEND;
		ses->match_bits = htonll(tx_desc->tag_or_immdata);
		ses->cmn.ri_gen_job_id =
			htonl((av->tagged_gen << UET_SES_REQ_RI_GEN_SHIFT) |
			      (tx_desc->job_id << UET_SES_REQ_JOB_ID_SHIFT));
	} else if (tx_desc->cq_flags & FI_WRITE) {
		if (tx_desc->desc_flags & UET_TX_DESC_FLAG_SYNC_REQ)
			opcode = UET_SYNC_WRITE;
		else
			opcode = UET_WRITE;
		ses->match_bits = htonll(tx_desc->remote_key);
		if (som &&
		    (tx_desc->desc_flags & UET_TX_DESC_FLAG_IMM_DATA_VALID)) {
			ses->cmn.ver_flags |= UET_SES_REQ_FLAG_HD;
			ses->cmpl_data = htonll(tx_desc->tag_or_immdata);
		}
	} else if (tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_REQ) {
		opcode = UET_READ;
		ses->match_bits = htonll(tx_desc->remote_key);
	}

	if (tx_desc->desc_flags & UET_TX_DESC_FLAG_CANCEL_PENDING) {
		if (tx_desc->desc_flags & UET_TX_DESC_FLAG_IN_DSEND_LIST) {
			if (tx_desc->cq_flags & FI_MSG)
				opcode = UET_DEFER_SEND;
			else
				opcode = UET_DEFER_TSEND;
			local_token = tx_desc->local_rtr_token;
			remote_token = tx_desc->remote_rtr_token;
			ses->restart_token =
				uet_build_ses_rtr_token(local_token,
							remote_token);
		} else
			opcode = UET_MSG_ERR;
		ses->payload_len_msg_off =
			htonll((tx_desc->buf_desc.buf_off <<
				UET_SES_REQ_STD_MSG_OFF_SHIFT) &
			       UET_SES_REQ_STD_MSG_OFF_MASK);
		eom = UET_SES_REQ_FLAG_EOM;
	}

	ses->cmn.rsvd_opcode = opcode << UET_SES_OPCODE_SHIFT;
	ses->cmn.ver_flags |= eom;
#if !ENABLE_VERBS
	ses->cmn.rsvd_res_index = htons(av->addr->start_index <<
					UET_SES_REQ_RES_INDEX_SHIFT);
#else
	ses->cmn.rsvd_res_index = htons(tx_desc->resource_index <<
					UET_SES_REQ_RES_INDEX_SHIFT);
#endif
	ses->cmn.rsvd_pid_on_fep = htons(av->addr->pid_on_fep <<
					 UET_SES_REQ_PID_ON_FEP_SHIFT);
	ses->cmn.msg_id = htons(tx_desc->msg_id);
	ses->initiator = htonl(uet_ep->uet_addr.initiator_id);
	ses->req_len = htonl((uint32_t) req_len);

	if (tx_desc->desc_flags & UET_TX_DESC_FLAG_SYNC_REQ) {
		ses_sync = (struct uet_ses_req_std_sync *) ses;
		uet = uet_ep->uet_domain->uet;
		ses_sync->ext.group = htons(tx_desc->sync_grp);
		ses_sync->ext.cnt = htons(
			uet->sync_grp_cb.cnts[tx_desc->sync_grp].tot_cnt);
	}

	return FI_SUCCESS;
}

/*
 * pds upcall to ses when response packet is received
 *
 * parms:
 *      tx_pkt_handle - handle assigned to packet by ses when associated
 *                      request packet transmission was initiated
 *      rsp_pp        - ptr to parsed packet struct for response
 *
 * returns:
 *      FI_SUCCESS when ack processed
 *      negative value corresponding to fabric errno on error
 */
static int uet_pds_to_ses_rx_rsp(uet_pkt_handle_t tx_pkt_handle,
				 struct uet_parsed_pkt *rsp_pp)
{
	int rc;
	uint8_t ver, opcode;
	uint32_t mod_len, rx_gen;
	size_t msg_len, expected_rd_rsp, max_payload_len;
	uet_ses_rc_t ses_rc;
	struct uet_ses_rsp *ses_rsp;
	struct uet_ses_rsp_d *ses_rsp_d;
	struct uet_ep *ep;
	struct uet_tx_desc *tx_desc;
	struct uet_av_entry *av_entry;

	tx_desc = (struct uet_tx_desc *) tx_pkt_handle;

	/* packets implicitly acknowledged by cack */
	if (!rsp_pp) {
		tx_desc->unack_pkts--;
		return 0;
	}

	ses_rsp = (struct uet_ses_rsp *) rsp_pp->ses;
	ses_rsp_d = (struct uet_ses_rsp_d *) rsp_pp->ses;
	opcode = rsp_pp->ses_opcode;

	ver = ((ses_rsp->cmn.ver_ret_code & UET_SES_VER_MASK) >>
		  UET_SES_VER_SHIFT);

	ses_rc = ((ses_rsp->cmn.ver_ret_code & UET_SES_RSP_RET_CODE_MASK) >>
		  UET_SES_RSP_RET_CODE_SHIFT);

	tx_desc->unack_pkts--;

	if (tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_REQ) {
		if ((opcode == UET_RESPONSE_W_DATA) ||
		    ((opcode == UET_RESPONSE) && (ses_rc != UET_RC_OK)))
			tx_desc->rx_desc->expected_rd_rsp--;
	}

	if (ver != UET_SES_VER) {
		UET_API_ERR("Msg Rsp: Bad SES Version = 0x%x", ver);
		goto err_exit;
	}

	switch (tx_desc->state) {
	case UET_TX_DESC_STATE_ACTIVE:
	case UET_TX_DESC_STATE_WAIT:
		break;
	default:
		return FI_SUCCESS;
	}

	/* check opcode */
	switch (opcode) {
        case UET_DEFAULT_RESPONSE:
		switch (ses_rc) {
		case UET_RC_NULL:
			return FI_SUCCESS;
		case UET_RC_OK:
			mod_len = ntohl(ses_rsp->mod_len);
			if (mod_len == 0)
				mod_len = tx_desc->buf_desc.len;
			break;
		default:
			UET_API_ERR("Msg Rsp: SES RC = 0x%x on "
				    "DEFAULT RESPONSE", ses_rc);
			goto err_exit;
		}
		break;
	case UET_RESPONSE:
		mod_len = ntohl(ses_rsp->mod_len);
		break;
	case UET_RESPONSE_W_DATA:
		mod_len = ntohl(ses_rsp_d->mod_len);
		break;
	case UET_NO_RESPONSE:
		return FI_SUCCESS;
	default:
		UET_API_ERR("Msg Rsp: Unsupported Opcode = 0x%x", opcode);
		goto err_exit;
	}

	/* check return code */
	switch (ses_rc) {
	case UET_RC_OK:
		if (opcode == UET_RESPONSE_W_DATA) {
			if (tx_desc->desc_flags &
			    (UET_TX_DESC_FLAG_ATOMIC_FETCH_REQ |
			     UET_TX_DESC_FLAG_ATOMIC_COMPARE_REQ)) {
				if (uet_rx_atomic_data(
					tx_desc->uet_ep, tx_desc, mod_len,
					rsp_pp) != UET_RC_OK)
					goto err_exit;
				return FI_SUCCESS;
			}
			if (mod_len != tx_desc->buf_desc.len) {
				UET_API_ERR("Read Rsp: "
					    "Truncated Message Length");
				goto err_exit;
			}
			if (uet_rx_read_data(tx_desc->uet_ep, tx_desc->rx_desc,
					     rsp_pp) != UET_RC_OK)
				goto err_exit;
		} else if (tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_RSP) {
			if (mod_len != tx_desc->rd_rsp.mod_len) {
				UET_API_ERR("Msg Rsp: Ack of Read Rsp: "
					    "Truncated Message Length");
				goto err_exit;
			}
		} else if (mod_len != tx_desc->buf_desc.len) {
			if ((tx_desc->desc_flags & UET_TX_DESC_FLAG_DSEND) &&
			    (mod_len == 0)) {
				uet_tx_desc_defer_list_insert(tx_desc);
				goto defer_exit;
			}
			UET_API_ERR("Msg Rsp: Truncated Message Length");
			goto err_exit;
		}
		break;
	case UET_RC_BAD_GENERATION:
		UET_API_ERR("Msg Rsp: Bad Generation");
		/* update generation for av and then retransmit */
		av_entry = (struct uet_av_entry *) tx_desc->dst_addr_handle;
		rx_gen = (uint32_t)
			((ntohl(ses_rsp->cmn.ri_gen_job_id) &
			  UET_SES_RSP_RI_GEN_MASK) >>
			 UET_SES_RSP_RI_GEN_SHIFT);

		if (tx_desc->cq_flags & FI_TAGGED)
			av_entry->tagged_gen = rx_gen;
		else
			av_entry->untagged_gen = rx_gen;

		tx_desc->delay_retx = false;
		goto retx_exit;
	case UET_RC_NO_MATCH:
		UET_API_ERR("Msg Rsp: No Match");
		tx_desc->delay_retx = true;
		goto retx_exit;
	case UET_RC_DISABLED_GEN:
		UET_API_ERR("Msg Rsp: Generation Disabled");
		tx_desc->delay_retx = true;
		goto retx_exit;
	case UET_RC_DISABLED:
		UET_API_ERR("Msg Rsp: Resource Disabled");
		goto err_exit;
	case UET_RC_UNSUPPORTED_OP:
		UET_API_ERR("Msg Rsp: Unsupported Operation");
		goto err_exit;
	case UET_RC_UNSUPPORTED_SIZE:
		UET_API_ERR("Msg Rsp: Unsupported Size");
		goto err_exit;
	case UET_RC_PERM_VIOLATION:
		UET_API_ERR("Msg Rsp: Permission Violation");
		goto err_exit;
	case UET_RC_OP_VIOLATION:
		UET_API_ERR("Msg Rsp: Operation Violation");
		goto err_exit;
	case UET_RC_BAD_INDEX:
		UET_API_ERR("Msg Rsp: Bad Index");
		goto err_exit;
	case UET_RC_BAD_PID:
		UET_API_ERR("Msg Rsp: Bad PID");
		goto err_exit;
	case UET_RC_BAD_JOB_ID:
		UET_API_ERR("Msg Rsp: Bad Job ID");
		goto err_exit;
	case UET_RC_BAD_MKEY:
		UET_API_ERR("Msg Rsp: Bad MKEY");
		goto err_exit;
	case UET_RC_BAD_ADDR:
		UET_API_ERR("Msg Rsp: Bad Address");
		goto err_exit;
	case UET_RC_UNDELIVERABLE:
		UET_API_ERR("Msg Rsp: Undeliverable");
		goto err_exit;
	case UET_RC_DROPPED:
		UET_API_ERR("Msg Rsp: Dropped by Dest");
		goto err_exit;
	case UET_RC_UNCOR:
		UET_API_ERR("Msg Rsp: Uncorrectable Error");
		goto err_exit;
	case UET_RC_UNCOR_TRNSNT:
		UET_API_ERR("Msg Rsp: Transient Error");
		goto err_exit;
	default:
		UET_API_ERR("Msg Rsp: SES RC = 0x%x", ses_rc);
		goto err_exit;
	}

	return FI_SUCCESS;

defer_exit:
	tx_desc->desc_flags |= UET_TX_DESC_FLAG_CANCEL_PENDING;
	tx_desc->state = UET_TX_DESC_STATE_DEFER;
	return FI_SUCCESS;

retx_exit:
	if ((tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_RSP) ||
	    (tx_desc->desc_flags & UET_TX_DESC_FLAG_RTR_REQ))
		goto err_exit;
	tx_desc->desc_flags |= UET_TX_DESC_FLAG_CANCEL_PENDING;
	tx_desc->state = UET_TX_DESC_STATE_RETX;
	return FI_SUCCESS;

err_exit:
	tx_desc->err_code = FI_EIO;
	if (!((tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_RSP) ||
	      (tx_desc->desc_flags & UET_TX_DESC_FLAG_RTR_REQ)))
		tx_desc->desc_flags |= UET_TX_DESC_FLAG_CANCEL_PENDING;
	tx_desc->state = UET_TX_DESC_STATE_ERR;
	return FI_SUCCESS;
}

/*
 * pds upcall to ses when unrecoverable error occurs
 *
 * parms:
 *      tx_pkt_handle - handle assigned to packet by ses when transmission
 *                      of packet associated with error  was initiated
 *      reason        - error reason code
 *
 * returns:
 *      FI_SUCCESS on success
 *      negative value corresponding to fabric errno on error
 */
static int uet_pds_to_ses_pds_err(uet_pkt_handle_t tx_pkt_handle,
				  uet_pds_err_code_t reason)
{
	struct uet_tx_desc *tx_desc;

	tx_desc = (struct uet_tx_desc *) tx_pkt_handle;

	UET_API_ERR("SES got indication of unrecoverable error from PDS");
	tx_desc->unack_pkts--;

	uet_tx_desc_set_err(tx_desc, FI_EIO, UET_TX_DESC_STATE_ERR);

	return FI_SUCCESS;
}

/*
 * uet address resolution
 *
 * parms:
 *      uet_addr - ptr to uet address struct, the following fields of the
 *                 uet address are set on return:
 *                   - pid_on_fep
 *                   - start_index
 *                   - num_indices
 *                   - initiator_id
 *      job_id   - ptr to location where job id is to be returned
 *
 * returns:
 *      FI_SUCCESS on success
 *      negative value corresponding to fabric errno on error
 */
#if !ENABLE_VERBS
static int uet_addr_resolution(struct uet_addr *uet_addr, uint32_t *job_id)
{
	/* Preserve fields supplied by an address-management layer. Software
	 * backends still receive the historical defaults for unresolved fields.
	 */
	if (!(uet_addr->flags & UET_ADDR_PID_ON_FEP_V)) {
		uet_addr->pid_on_fep = UET_ADDR_DEF_PID_ON_FEP;
		uet_addr->flags |= UET_ADDR_PID_ON_FEP_V;
	}
	if (!(uet_addr->flags & UET_ADDR_INDEX_V)) {
		uet_addr->num_indices = 1;
		uet_addr->start_index = UET_ADDR_DEF_INDEX;
		uet_addr->flags |= UET_ADDR_INDEX_V;
	}
	if (!(uet_addr->flags & UET_ADDR_INITIATOR_V)) {
		uet_addr->initiator_id = UET_ADDR_DEF_INITIATOR_ID;
		uet_addr->flags |= UET_ADDR_INITIATOR_V;
	}

	*job_id = UET_DEF_JOB_ID;

	return FI_SUCCESS;
}
#endif /* !ENABLE_VERBS */

/* send cancel message */
static int uet_tx_cancel(struct uet_tx_desc *tx_desc)
{
	int rc;
	struct uet_ses_req_std ses;
	struct uet_pds *pds = &tx_desc->uet_ep->uet_domain->uet->pds;

	if (tx_desc->remaining_bytes == 0) {
		tx_desc->desc_flags &= ~UET_TX_DESC_FLAG_CANCEL_PENDING;
		return FI_SUCCESS;
	}

	uet_build_ses_hdr(tx_desc, 0, &ses);

	rc = pds->downcall.tx_pkt((uet_pkt_handle_t) tx_desc,
				  tx_desc->pkt_cnt++,
				  tx_desc->uet_ep,
				  tx_desc->dst_addr_handle, tx_desc->pds_mode,
				  UET_PDS_FLAG_EOM, NULL, tx_desc->msg_id,
				  UET_HDR_REQ_STD, &ses,
				  sizeof(struct uet_ses_req_std),
				  NULL, 0, false);

	if (rc == FI_SUCCESS) {
		tx_desc->unack_pkts++;
		tx_desc->desc_flags &= ~UET_TX_DESC_FLAG_CANCEL_PENDING;

	} else if (rc != -FI_EAGAIN) {
		tx_desc->desc_flags &= ~UET_TX_DESC_FLAG_CANCEL_PENDING;
		uet_tx_desc_set_err(tx_desc, -rc,
				    UET_TX_DESC_STATE_ERR_COMPLETE);
	}

	return rc;
}

/* send ready to restart message */
static int uet_tx_rtr(struct uet_tx_desc *tx_desc)
{
	int rc;
	struct uet_ses_req_std ses;
	struct uet_pds *pds = &tx_desc->uet_ep->uet_domain->uet->pds;

	uet_build_ses_hdr(tx_desc, 0, &ses);

	rc = pds->downcall.tx_pkt((uet_pkt_handle_t) tx_desc,
				  tx_desc->pkt_cnt++,
				  tx_desc->uet_ep,
				  tx_desc->dst_addr_handle, tx_desc->pds_mode,
				  UET_PDS_FLAG_SOM | UET_PDS_FLAG_EOM, NULL,
				  tx_desc->msg_id, UET_HDR_REQ_STD, &ses,
				  sizeof(struct uet_ses_req_std),
				  NULL, 0, false);

	if (rc == FI_SUCCESS) {
		tx_desc->unack_pkts++;
		tx_desc->state = UET_TX_DESC_STATE_WAIT;
	} else if (rc != -FI_EAGAIN)
		uet_tx_desc_set_err(tx_desc, -rc,
				    UET_TX_DESC_STATE_ERR_COMPLETE);

	return rc;
}

/* initialize resources for deferred send if appropriate */
static void uet_dsend_init(struct uet_tx_desc *tx_desc)
{
	struct uet_instance *uet;
	size_t req_len;

	if (tx_desc->desc_flags & UET_TX_DESC_FLAG_DSEND)
		return;

	if (uet_get_pds_mode(tx_desc->uet_ep, false) != UET_PDS_MODE_RUD)
		return;

	if (!((tx_desc->cq_flags & FI_MSG) || (tx_desc->cq_flags & FI_TAGGED)))
		return;

	uet = tx_desc->uet_ep->uet_domain->uet;
	req_len = tx_desc->buf_desc.len;

	if (tx_desc->cq_flags & FI_MSG) {
		if (req_len < uet->msg_rndz_size)
			return;
	} else {
		if (req_len < uet->tag_rndz_size)
			return;
	}

	if (uet_alloc_tx_rtr_token(uet,
				   &tx_desc->local_rtr_token) != FI_SUCCESS)
		return;

	uet_init_tx_rtr_token(uet, tx_desc);
}

/* assemble packet from gather list */
static void *gather_iov_to_buffer(
	const struct iovec *iov, size_t iov_count, size_t payload_len,
	size_t payload_offset)
{
	uint8_t *pkt_buf = calloc(payload_len, sizeof(*pkt_buf));
	size_t iov_index = 0;
	size_t iov_offset;
	size_t remaining;
	size_t pkt_offset = 0;

	if (!pkt_buf)
		return NULL;

	while ((iov_index < iov_count) &&
	       (payload_offset >= iov[iov_index].iov_len)) {
		payload_offset -= iov[iov_index].iov_len;
		iov_index++;
	}

	iov_offset = payload_offset;
	remaining = payload_len;
	while (remaining && (iov_index < iov_count)) {
		size_t available = iov[iov_index].iov_len - iov_offset;
		size_t to_copy = (available < remaining) ? available : remaining;

		memcpy(pkt_buf + pkt_offset,
		       (uint8_t *)iov[iov_index].iov_base + iov_offset,
		       to_copy);
		pkt_offset += to_copy;
		remaining -= to_copy;
		iov_index++;
		iov_offset = 0;
	}

	if (remaining) {
		free(pkt_buf);
		return NULL;
	}

	return pkt_buf;
}

/* uet message transmission */
static int uet_tx_msg(struct uet_tx_desc *tx_desc)
{
	int rc;
	struct uet_ep *uet_ep;
	struct uet_pds *pds;
	union uet_ses_req ses_req;
	struct uet_ses_rsp_d ses_rsp_d;
	uet_pds_tx_flags_t flags;
	size_t payload_len, max_payload_len, ses_len, pkt_len;
	void *ses, *pkt_buf;
	uet_pds_next_hdr_t next_hdr;
	struct uet_pds_info *pds_info = NULL;

	uet_ep = tx_desc->uet_ep;
	pds = &uet_ep->uet_domain->uet->pds;

	if (tx_desc->remaining_bytes == tx_desc->buf_desc.len) {
		flags = UET_PDS_FLAG_SOM;
		uet_dsend_init(tx_desc);
	} else
		flags = UET_PDS_FLAG_NONE;

	max_payload_len = uet_ep->uet_domain->uet->max_payload_len;
	while (tx_desc->remaining_bytes || !tx_desc->transmitted) {
		if (tx_desc->remaining_bytes > max_payload_len)
			payload_len = max_payload_len;
		else {
			payload_len = tx_desc->remaining_bytes;
			flags |= UET_PDS_FLAG_EOM;
		}

		if (tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_REQ) {
			pkt_len = 0;
			flags |= UET_PDS_FLAG_MAINTAIN_PDC;
		} else
			pkt_len = payload_len;

		if (tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_RSP) {
			pds_info = &tx_desc->rd_rsp.pds_info;
			next_hdr = UET_HDR_RSP_DATA;
			flags |= (UET_PDS_FLAG_SOM | UET_PDS_FLAG_EOM);
			ses = &ses_rsp_d;
			ses_len = sizeof(struct uet_ses_rsp_d);
		} else {
			next_hdr = UET_HDR_REQ_STD;
			ses = &ses_req;

			if (tx_desc->desc_flags &
			    (UET_TX_DESC_FLAG_ATOMIC_REQ |
			     UET_TX_DESC_FLAG_ATOMIC_FETCH_REQ)) {
				ses_len = sizeof(struct uet_ses_req_std_atomic)
					  + UET_VERBS_ATOMIC_DATA_BYTES;
				pkt_len = 0;
			} else if (tx_desc->desc_flags &
			   	   UET_TX_DESC_FLAG_ATOMIC_COMPARE_REQ) {
				ses_len = sizeof(struct uet_ses_req_std_cswap);
				pkt_len = 0;
			} else
				ses_len = sizeof(struct uet_ses_req_std);

			if (tx_desc->desc_flags & UET_TX_DESC_FLAG_SYNC_REQ)
				ses_len += sizeof(struct uet_ses_sync_ext);
		}

		if (uet_tx_desc_expects_amo_rsp_data(tx_desc)) {
			flags |= UET_PDS_FLAG_MAINTAIN_PDC;
		}

		if (tx_desc->buf_desc.type == UET_MSG_BUF_TYPE_SEG) {
			/* The segment walk is positioned by absolute offset
			 * rather than by a saved offset, so it needs how far
			 * into the message this packet starts. buf_off is
			 * that, and is what the iov path uses too - it is
			 * advanced and reset alongside remaining_bytes.
			 */
			pkt_buf = calloc(payload_len, sizeof(char));
			if (pkt_buf &&
			    (gather_seg_to_flat(tx_desc->buf_desc.seg.seg,
						tx_desc->buf_desc.seg.seg_count,
						pkt_buf, payload_len,
						tx_desc->buf_desc.buf_off) !=
			     payload_len)) {
				free(pkt_buf);
				pkt_buf = NULL;
			}

			if (!pkt_buf) {
				UET_API_ERR("TX: Failed to gather segments");
				rc = -FI_ENOMEM;
				uet_tx_desc_set_err(tx_desc, -rc,
					UET_TX_DESC_STATE_ERR_COMPLETE);
				goto exit;
			}
		} else if (tx_desc->buf_desc.type == UET_MSG_BUF_TYPE_IOV) {
			pkt_buf = gather_iov_to_buffer(
					tx_desc->buf_desc.iov.iov,
					tx_desc->buf_desc.iov.iov_count,
					payload_len,
					tx_desc->buf_desc.buf_off);

			if (!pkt_buf) {
				UET_API_ERR("TX: Msg Buffer is null");
				UET_API_ERR("TX: Failed to gather iov");
				rc = -FI_ENOMEM;
				uet_tx_desc_set_err(tx_desc, -rc,
					UET_TX_DESC_STATE_ERR_COMPLETE);
				goto exit;
			}

		} else
			pkt_buf = (void *) (((size_t) tx_desc->buf_desc.buf) +
						tx_desc->buf_desc.buf_off);

		uet_build_ses_hdr(tx_desc, pkt_len, ses);

		rc = pds->downcall.tx_pkt((uet_pkt_handle_t) tx_desc,
					  tx_desc->pkt_cnt++,
					  uet_ep, tx_desc->dst_addr_handle,
					  tx_desc->pds_mode,
					  flags, pds_info, tx_desc->msg_id,
					  next_hdr, ses, ses_len,
					  pkt_buf, pkt_len, false);

		/* The iov and segment paths each build the packet payload in
		 * a buffer of their own; the contiguous path points straight
		 * into the caller's buffer and must not be freed.
		 */
		if ((tx_desc->buf_desc.type == UET_MSG_BUF_TYPE_IOV) ||
		    (tx_desc->buf_desc.type == UET_MSG_BUF_TYPE_SEG))
			free(pkt_buf);

		if (rc == FI_SUCCESS) {
			tx_desc->unack_pkts++;
			tx_desc->buf_desc.buf_off += payload_len;
			tx_desc->remaining_bytes -= payload_len;
			tx_desc->transmitted = true;
			if (tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_REQ)
				tx_desc->rx_desc->expected_rd_rsp++;
			/* clear SOM flag after first packet */
			flags &= ~UET_PDS_FLAG_SOM;
		} else {
			if (rc != -FI_EAGAIN)
				uet_tx_desc_set_err(tx_desc, -rc,
					UET_TX_DESC_STATE_ERR_COMPLETE);
			break;
		}
	}

exit:
	return rc;
}

/* transmit message data if available */
static void uet_tx_msg_try(struct uet_ep *uet_ep)
{
	int rc;
	size_t i;
	time_t now;
	uet_tx_desc_state_t prev_state;
	struct uet_ring *ring;
	struct uet_tx_desc *tx_desc, *start_tx_desc;
	struct uet_av_entry *av_entry;

	ring = &uet_ep->tx_ring;
	uet_gettime(&now);

	for (i = 0; i < uet_ep->num_tx_desc; i++) {
		if (uet_ring_empty(ring))
			return;
		tx_desc = ((struct uet_tx_desc_ring_entry *)
			   ring->base)[ring->tail].tx_desc;
		if (i == 0)
			start_tx_desc = tx_desc;
		else if (tx_desc == start_tx_desc)
			return;

		if (tx_desc->pds_mode == UET_PDS_MODE_ROD) {
			av_entry = (struct uet_av_entry *)
					tx_desc->dst_addr_handle;
			if (!uet_is_next_av_msg_tx_seq_num(
						av_entry, tx_desc->seq_num))
				goto rotate_and_continue;
		}

		if (tx_desc->tx_time > now)
			goto rotate_and_continue;

		if (tx_desc->desc_flags & UET_TX_DESC_FLAG_CANCEL_PENDING) {
			uet_tx_cancel(tx_desc);
			goto rotate_and_continue;
		}

		if ((tx_desc->desc_flags & UET_TX_DESC_FLAG_RTR_REQ) &&
		    (tx_desc->state == UET_TX_DESC_STATE_ACTIVE)) {
			uet_tx_rtr(tx_desc);
			goto rotate_and_continue;
		}

		prev_state = tx_desc->state;
		uet_tx_desc_state_transition(tx_desc);

		switch (tx_desc->state) {
		case UET_TX_DESC_STATE_ACTIVE:
			if (prev_state != UET_TX_DESC_STATE_ACTIVE)
				goto rotate_and_continue;
			rc = uet_tx_msg(tx_desc);
			if (rc == -FI_EAGAIN) {
				uet_tx_desc_ring_rotate(tx_desc);
				continue;
			} else if ((rc != FI_SUCCESS) &&
				 (tx_desc->state ==
				  UET_TX_DESC_STATE_ERR_COMPLETE))
				uet_tx_cq_post_err(tx_desc, tx_desc->err_code);
			else
				uet_tx_desc_ring_rotate(tx_desc);
			break;
		case UET_TX_DESC_STATE_ERR_COMPLETE:
			uet_tx_cq_post_err(tx_desc, tx_desc->err_code);
			break;
		case UET_TX_DESC_STATE_COMPLETE:
			uet_tx_cq_post_entry(tx_desc);
			break;
		default:
rotate_and_continue:
			uet_tx_desc_ring_rotate(tx_desc);
			break;
		}
	}
}

/* age out partially received messages that have gone idle */
static void uet_rx_msg_age(struct uet_ep *uet_ep, time_t now)
{
	struct uet_rx_desc *rx_desc;
	time_t idle_time;

	while (1) {
		if (dlist_empty(&uet_ep->rx_desc_active_list_head))
			return;
		rx_desc = container_of(uet_ep->rx_desc_active_list_head.next,
				       struct uet_rx_desc, list_entry);
		idle_time = now - rx_desc->prev_pkt_time;
		if (idle_time < uet_ep->uet_domain->uet->idle_rx_msg_timeout)
			break;
		if (rx_desc->desc_flags & UET_RX_DESC_FLAG_READ_RSP) {
			UET_API_ERR("Read Response Timeout");
			uet_rx_desc_active_list_remove(rx_desc);
			rx_desc->expected_rd_rsp = 0;
			uet_tx_desc_set_err(rx_desc->tx_desc, FI_EIO,
					    UET_TX_DESC_STATE_ERR);
		} else {
			UET_API_ERR("RX Message Timeout");
			uet_rx_cq_post_err(rx_desc, FI_EIO);
		}
	}
}

/* age out deferred send messages that have gone idle */
static void uet_dsend_msg_age(struct uet_ep *uet_ep, time_t now)
{
	struct uet_tx_desc *tx_desc;
	time_t idle_time;

	while (1) {
		if (dlist_empty(&uet_ep->tx_desc_defer_list_head))
			return;
		tx_desc = container_of(uet_ep->tx_desc_defer_list_head.next,
				       struct uet_tx_desc, list_entry);
		idle_time = now - tx_desc->defer_time;
		if (idle_time < uet_ep->uet_domain->uet->idle_dsend_msg_timeout)
			break;
		UET_API_ERR("Deferred Send Message Timeout");
		uet_tx_cq_post_err(tx_desc, FI_EIO);
	}
}

/* common code for aging list of rtr messages */
static void uet_rtr_msg_age_common(struct uet_ep *uet_ep,
				   struct dlist_entry *list_head, time_t now)
{
	struct uet_instance *uet;
	struct uet_tx_desc *tx_desc;
	time_t idle_time, timeout;

	uet = uet_ep->uet_domain->uet;
	timeout = uet->idle_rtr_msg_timeout;

	while (1) {
		if (dlist_empty(list_head))
			return;
		tx_desc = container_of(list_head->next,
				       struct uet_tx_desc, list_entry);
		idle_time = now - tx_desc->defer_time;
		if (idle_time < timeout)
			break;
		uet_tx_desc_buf_rtr_list_remove(tx_desc);
		uet_dealloc_msg_id(uet, tx_desc->msg_id);
		uet_tx_desc_list_insert(tx_desc);
		UET_API_ERR("Buffered RTR Message Timeout");
	}
}

/* age out buffered rtr messages that have gone idle */
static void uet_rtr_msg_age(struct uet_ep *uet_ep, time_t now)
{
	uet_rtr_msg_age_common(uet_ep,
			       &uet_ep->tx_desc_buf_rtr_list_head, now);
	uet_rtr_msg_age_common(uet_ep,
			       &uet_ep->tx_desc_buf_tag_rtr_list_head, now);
}

/* age out messages that have gone idle to reclaim stranded resources */
static void uet_msg_age(struct uet_ep *uet_ep)
{
	time_t now;

	uet_gettime(&now);

	uet_rx_msg_age(uet_ep, now);
	uet_dsend_msg_age(uet_ep, now);
	uet_rtr_msg_age(uet_ep, now);
}

/* age out partially received sync group that has gone idle */
static void uet_rx_sync_grp_age(struct uet_ep *uet_ep)
{
	struct uet_sync_grp_src_fep_entry *current, *tmp;
	time_t now;

	uet_gettime(&now);

	HASH_ITER(sync_grp_src_fep_hh, uet_ep->sync_grp_src_fep_hash_table,
		  current, tmp) {

		if (now > current->timeout) {
			if (current->cnts.cur_cnt == current->cnts.cmpl_cnt) {
				/* only age out sync groups for which no  */
				/* message is in progress		  */
				/*  - idle messages will be aged out      */
				/*    independently                       */
				UET_API_ERR("RX Sync Group Timeout");
				if (current->terminating_rx_desc)
					uet_rx_cq_post_err(
						current->terminating_rx_desc,
						FI_EIO);
				HASH_DELETE(sync_grp_src_fep_hh,
					    uet_ep->sync_grp_src_fep_hash_table,
					    current);
			}
		}
	}
}

/* initiate transmit of ready to restart if appropriate */
static void uet_tx_rtr_try(struct uet_ep *uet_ep, struct uet_rx_desc *rx_desc,
			   uet_recv_api_t recv_api)
{
	struct uet_tx_desc *tx_desc;
	struct dlist_entry *head, *item;

	switch (recv_api) {
	case UET_RECV_API:
		head = &uet_ep->tx_desc_buf_rtr_list_head;
		if (!dlist_empty(head)) {
			tx_desc = container_of(head->next, struct uet_tx_desc,
					       list_entry);
			goto initiate_rtr;
		}
		break;
	case UET_TRECV_API:
		head = &uet_ep->tx_desc_buf_tag_rtr_list_head;
		dlist_foreach(head, item) {
			tx_desc = container_of(item, struct uet_tx_desc,
					       list_entry);
			if (rx_desc->tag_key.initiator_invalid) {
				if (tx_desc->tag_or_immdata ==
				    ntohll(rx_desc->tag_key.tag))
					goto initiate_rtr;
			} else if ((tx_desc->ephemeral_av.uet_addr.initiator_id
				    == ntohl(rx_desc->tag_key.initiator)) &&
				   (tx_desc->tag_or_immdata ==
				    ntohll(rx_desc->tag_key.tag)))
				goto initiate_rtr;
		}
		break;
	default:
		break;
	}

	return;

initiate_rtr:
	uet_tx_desc_buf_rtr_list_remove(tx_desc);
	uet_tx_desc_ring_insert(tx_desc);
}

/*
 * common function for recv api's
 *   - the recv_api determines which parms are valid
 * This function supports both IO vector (iov) mode and buffer mode:
 *   - In **iov mode**, an array of `struct iovec` is provided to describe
 *     multiple non-contiguous memory regions for receiving data.
 *   - In **buffer mode**, a single buffer can be specified using one
 *     `struct iovec` with its base address and size.
 */
#if !ENABLE_VERBS
static ssize_t uet_recv_api_common(
	uet_recv_api_t recv_api, uet_ep_handle_t ep_handle, uint32_t job_id,
	const struct iovec *iov, size_t iov_count, uet_mr_handle_t mr_handle,
	uet_addr_handle_t src_addr_handle, uint64_t tag, uint64_t ignore,
	void *context, const struct uet_mr_seg *seg, size_t seg_count)
#else
static ssize_t uet_recv_api_common(
	uet_recv_api_t recv_api, uet_ep_handle_t ep_handle, uint32_t job_id,
	const struct iovec *iov, size_t iov_count, uet_mr_handle_t mr_handle,
	uet_addr_handle_t src_addr_handle, uint64_t tag, uint64_t ignore,
	void *context, const struct uet_mr_seg *seg, size_t seg_count)
#endif
{
	struct uet_ep *uet_ep;
	struct uet_rx_desc *rx_desc;
	struct uet_av_entry *av_entry;
	struct iovec *iov_handle;
	struct uet_mr_seg *seg_handle = NULL;
	size_t msg_len = 0;
	size_t i;

	uet_ep = (struct uet_ep *) ep_handle;

	/* check that rx completion queue is bound to endpoint */
	if (uet_ep->recv_cq.cq_state == UET_CQ_DOWN) {
		UET_API_ERR("No RX Completion Q");
		return -FI_EIO;
	}

	if (recv_api == UET_TRECV_API) {
		/* check that ignore bits are not specified */
		if (ignore != UET_EXACT_MATCH) {
			UET_API_ERR(
				"Wildcard Tags Not Supported for uet_trecv()");
			return -FI_EINVAL;
		}
	}

	/* A segment list describes the buffer with memory regions rather
	 * than with addresses in this process. Validate it once here so a
	 * malformed list is rejected at the call rather than partway
	 * through a transfer, then keep a copy so the caller's array need
	 * not outlive the operation.
	 */
	if (seg != NULL) {
		if (!uet_seg_validate(seg, seg_count)) {
			UET_API_ERR("Invalid segment list");
			return -FI_EINVAL;
		}

		msg_len = uet_seg_total_len(seg, seg_count);

		seg_handle = calloc(seg_count, sizeof(struct uet_mr_seg));
		if (seg_handle == NULL) {
			UET_API_ERR("Allocation of segment list failed");
			return -FI_ENOMEM;
		}

		memcpy(seg_handle, seg,
		       (seg_count * sizeof(struct uet_mr_seg)));
	}

	/* allocate iov and init */
	iov_handle = NULL;
	if (seg == NULL) {
		iov_handle = calloc(iov_count, sizeof(struct iovec));
		if (iov_handle == NULL) {
			UET_API_ERR("Allocation of iov memory failed");
			return -FI_ENOMEM;
		}

		for (i = 0; i < iov_count; i++) {
			msg_len += iov[i].iov_len;
			iov_handle[i] = iov[i];
		}
	}

	pthread_mutex_lock(&uet_ep->data_lock);

	/* allocate rx descriptor */
	rx_desc = uet_rx_desc_list_pop(uet_ep);
	if (rx_desc == NULL) {
		pthread_mutex_unlock(&uet_ep->data_lock);
		free(iov_handle);
		free(seg_handle);
		return -FI_EAGAIN;
	}

	/* init msg descriptor */
	memset(rx_desc, 0, sizeof(struct uet_rx_desc));
	rx_desc->desc_flags = UET_RX_DESC_FLAG_POST_CQ;
	if (seg_handle != NULL) {
		rx_desc->buf_desc.type = UET_MSG_BUF_TYPE_SEG;
		rx_desc->buf_desc.seg.seg = seg_handle;
		rx_desc->buf_desc.seg.seg_count = seg_count;
		rx_desc->desc_flags |= UET_RX_DESC_FLAG_OWNS_SEG;
	} else if (iov_count == 1) {
		rx_desc->buf_desc.type = UET_MSG_BUF_TYPE_CONTIG;
		rx_desc->buf_desc.buf = iov->iov_base;
	} else {
		rx_desc->buf_desc.type = UET_MSG_BUF_TYPE_IOV;
		rx_desc->buf_desc.iov.iov = iov_handle;
		rx_desc->buf_desc.iov.iov_count = iov_count;
		rx_desc->desc_flags |= UET_RX_DESC_FLAG_OWNS_IOV;
	}
	rx_desc->buf_desc.len = msg_len;
	rx_desc->context = context;
	rx_desc->ses_rc = UET_RC_OK;
	rx_desc->uet_ep = uet_ep;
	rx_desc->job_id = job_id;

	switch (recv_api) {
	case UET_RECV_API:
		rx_desc->cq_flags = FI_RECV | FI_MSG;

		/* insert msg descriptor in rx ring of endpoint */
		uet_rx_desc_ring_insert(rx_desc);

		if (uet_ep->untagged_gen_disabled) {
			/* re-enable generation */
			uet_ep->untagged_gen++;
			uet_ep->untagged_gen_disabled = false;
		}
		break;
	case UET_TRECV_API:
		rx_desc->cq_flags = FI_RECV | FI_TAGGED;

		/* insert msg descriptor in tag buffer hash table of endpoint */
		memset(&rx_desc->tag_key, 0,
		       sizeof(struct uet_tag_initiator_key));
		rx_desc->tag_key.tag = htonll(tag);
		if (src_addr_handle == UET_NULL_HANDLE) {
			rx_desc->tag_key.initiator_invalid = true;
			rx_desc->tag_key.initiator = UET_INITIATOR_NONE;
		} else {
			av_entry = (struct uet_av_entry *) src_addr_handle;
			rx_desc->tag_key.initiator_invalid = false;
			rx_desc->tag_key.initiator =
				htonl(av_entry->addr->initiator_id);
		}
		uet_tag_initiator_hash_insert(uet_ep, rx_desc);

		if (uet_ep->tagged_gen_disabled) {
			/* re-enable generation */
			uet_ep->tagged_gen++;
			uet_ep->tagged_gen_disabled = false;
		}
		break;
	default:
		break;
	}

	uet_tx_rtr_try(uet_ep, rx_desc, recv_api);

	pthread_mutex_unlock(&uet_ep->data_lock);
	return FI_SUCCESS;
}

/*
 * common function for api's that send requests
 *   - the send_req_api determines which parms are valid
 * This function supports both IO vector (iov) mode and buffer mode:
 *   - In **iov mode**, an array of `struct iovec` is provided to describe
 *     multiple non-contiguous memory regions for receiving data.
 *   - In **buffer mode**, a single buffer can be specified as single
 *     `struct iovec` with its base address and size.
 */
#if !ENABLE_VERBS
static ssize_t uet_send_req_api_common(
	uet_send_req_api_t send_req_api, uet_ep_handle_t ep_handle,
	uint32_t job_id, const struct iovec *iov, size_t iov_count,
	uet_mr_handle_t mr_handle, uet_addr_handle_t dst_addr_handle,
	uint64_t tag, uint64_t *imm_data, uint64_t remote_mem_addr,
	uint64_t remote_key, struct uet_atomic_parms *parms, void *context,
	const struct uet_mr_seg *seg, size_t seg_count)
#else
static ssize_t uet_send_req_api_common(
	uet_send_req_api_t send_req_api, uet_ep_handle_t ep_handle,
	uint32_t job_id, const struct iovec *iov, size_t iov_count,
	uet_mr_handle_t mr_handle, uet_addr_handle_t dst_addr_handle,
	uint64_t tag, uint64_t *imm_data, uint64_t remote_mem_addr,
	uint64_t remote_key, struct uet_atomic_parms *parms, void *context,
	uint16_t resource_index, const struct uet_mr_seg *seg, size_t seg_count)
#endif /* ENABLE_VERBS */
{
	int rc;
	size_t i;
	bool atomic_op = false, rma_op = false;
	uint16_t msg_id;
	uint32_t msg_len = 0;
	struct uet_instance *uet;
	struct uet_ep *uet_ep;
	struct uet_tx_desc *tx_desc;
	struct uet_rx_desc *rx_desc;
	struct uet_av_entry *av_entry;
	struct uet_sync_grp_av_entry *sync_grp_av_entry;
	struct iovec *iov_handle;
	struct uet_mr_seg *seg_handle = NULL;

	uet_ep = (struct uet_ep *) ep_handle;
	uet = uet_ep->uet_domain->uet;
	av_entry = (struct uet_av_entry *) dst_addr_handle;

	/* check that tx completion queue is bound to endpoint */
	if (uet_ep->send_cq.cq_state == UET_CQ_DOWN) {
		UET_API_ERR("No TX Completion Q");
		return -FI_EIO;
	}

	/* check next-hop mac address */
	if (!(av_entry->flags & UET_NH_MAC_ADDR_V)) {
		rc = uet_nic_get_ipv4_nh(UET_NIC(uet), av_entry->addr->fa.v4,
					 av_entry->nh_mac_addr);
		if (rc != FI_SUCCESS)
			return rc;
		av_entry->flags |= UET_NH_MAC_ADDR_V;
	}

	/* A segment list describes the buffer with memory regions rather
	 * than with addresses in this process. Validate it once here so a
	 * malformed list is rejected at the call rather than partway
	 * through a transfer.
	 */
	if (seg != NULL) {
		if (!uet_seg_validate(seg, seg_count)) {
			UET_API_ERR("Invalid segment list");
			return -FI_EINVAL;
		}

		msg_len = uet_seg_total_len(seg, seg_count);

		seg_handle = calloc(seg_count, sizeof(struct uet_mr_seg));
		if (seg_handle == NULL) {
			UET_API_ERR("Allocation of segment list failed");
			return -FI_ENOMEM;
		}

		memcpy(seg_handle, seg,
		       (seg_count * sizeof(struct uet_mr_seg)));
	}

	/* Total the length, and keep a private copy of the vector only when
	 * a descriptor will actually reference it. A single-entry buffer is
	 * recorded as contiguous and keeps no vector, and a segment list
	 * keeps no vector at all.
	 */
	iov_handle = NULL;
	if (seg == NULL) {
		for (i = 0; i < iov_count; i++)
			msg_len += iov[i].iov_len;

		if (iov_count > 1) {
			iov_handle = calloc(iov_count, sizeof(struct iovec));
			if (iov_handle == NULL) {
				UET_API_ERR("Allocation of iov memory failed");
				return -FI_ENOMEM;
			}

			for (i = 0; i < iov_count; i++)
				iov_handle[i] = iov[i];
		}
	}

	/* allocate msg id */
	rc = uet_alloc_msg_id(uet, &msg_id);
	if (rc != FI_SUCCESS) {
		free(iov_handle);
		free(seg_handle);
		return rc;
	}

	/* handle sync request */
	switch (send_req_api) {
	case UET_WRITE_SYNC_API:
	case UET_ATOMIC_SYNC_API:
		rc = uet_get_sync_grp_av(uet_ep, (uint64_t) av_entry,
					 &sync_grp_av_entry);
		if (rc != FI_SUCCESS) {
			uet_dealloc_msg_id(uet, msg_id);
			free(iov_handle);
			free(seg_handle);
			return rc;
		}
		break;
	default:
		sync_grp_av_entry = NULL;
		break;
	}

	pthread_mutex_lock(&uet_ep->data_lock);

	/* allocate tx descriptor */
	tx_desc = uet_tx_desc_list_pop(uet_ep);
	if (tx_desc == NULL) {
		pthread_mutex_unlock(&uet_ep->data_lock);
		free(iov_handle);
		free(seg_handle);
		uet_dealloc_msg_id(uet, msg_id);
		if (sync_grp_av_entry)
			uet_sync_grp_free_initiator(uet_ep,
						    sync_grp_av_entry->sync_grp,
						    sync_grp_av_entry);
		return -FI_EAGAIN;
	}

	switch (send_req_api) {
	case UET_WRITE_API:
	case UET_WRITE_SYNC_API:
	case UET_READ_API:
		rma_op = true;
		break;
	case UET_ATOMIC_API:
	case UET_ATOMIC_SYNC_API:
	case UET_FETCH_ATOMIC_API:
	case UET_COMPARE_ATOMIC_API:
		rma_op = true;
		atomic_op = true;
		break;
	default:
		break;
	}

	/* allocate rx descriptor for read */
	if (send_req_api == UET_READ_API) {
		rx_desc = uet_rx_desc_list_pop(uet_ep);
		if (rx_desc == NULL) {
			uet_tx_desc_list_insert(tx_desc);
			pthread_mutex_unlock(&uet_ep->data_lock);
			free(iov_handle);
			free(seg_handle);
			uet_dealloc_msg_id(uet, msg_id);
			if (sync_grp_av_entry)
				uet_sync_grp_free_initiator(
					uet_ep,
					sync_grp_av_entry->sync_grp,
					sync_grp_av_entry);
			return -FI_EAGAIN;
		}
		/* init rx descriptor */
		memset(rx_desc, 0, sizeof(struct uet_rx_desc));
		rx_desc->desc_flags =
			UET_RX_DESC_FLAG_POST_CQ | UET_RX_DESC_FLAG_READ_RSP;
		if (seg_handle != NULL) {
			/* The read response lands here while the request's
			 * transmit descriptor is recycled independently, so
			 * this descriptor gets its own copy of the list
			 * rather than sharing one with two owners.
			 */
			struct uet_mr_seg *rx_seg =
				calloc(seg_count, sizeof(struct uet_mr_seg));

			if (rx_seg == NULL) {
				pthread_mutex_unlock(&uet_ep->data_lock);
				free(iov_handle);
				free(seg_handle);
				return -FI_ENOMEM;
			}

			memcpy(rx_seg, seg_handle,
			       (seg_count * sizeof(struct uet_mr_seg)));

			rx_desc->buf_desc.type = UET_MSG_BUF_TYPE_SEG;
			rx_desc->buf_desc.seg.seg = rx_seg;
			rx_desc->buf_desc.seg.seg_count = seg_count;
			rx_desc->desc_flags |= UET_RX_DESC_FLAG_OWNS_SEG;
		} else if (iov_count == 1) {
			rx_desc->buf_desc.type = UET_MSG_BUF_TYPE_CONTIG;
			rx_desc->buf_desc.buf = iov->iov_base;
		} else {
			rx_desc->buf_desc.type = UET_MSG_BUF_TYPE_IOV;
			rx_desc->buf_desc.iov.iov = iov_handle;
			rx_desc->buf_desc.iov.iov_count = iov_count;
		}
		rx_desc->buf_desc.len = msg_len;
		rx_desc->msg_len = msg_len;
		rx_desc->remaining_bytes = msg_len;
		rx_desc->context = context;
		rx_desc->ses_rc = UET_RC_OK;
		rx_desc->uet_ep = uet_ep;
		rx_desc->tx_desc = tx_desc;
		rx_desc->msg_key.msg_id = msg_id;
		uet_set_msg_id_rx_desc(uet, msg_id, rx_desc);
		uet_rx_desc_active_list_insert(rx_desc);
	}

	/* init tx descriptor for msg */
	memset(tx_desc, 0, sizeof(struct uet_tx_desc));
	tx_desc->desc_flags = UET_TX_DESC_FLAG_MSG_ID_ALLOCATED |
			      UET_TX_DESC_FLAG_POST_CQ;
	if (seg_handle != NULL) {
		tx_desc->buf_desc.type = UET_MSG_BUF_TYPE_SEG;
		tx_desc->buf_desc.seg.seg = seg_handle;
		tx_desc->buf_desc.seg.seg_count = seg_count;
		tx_desc->desc_flags |= UET_TX_DESC_FLAG_OWNS_SEG;
	} else if (iov_count == 1) {
		tx_desc->buf_desc.type = UET_MSG_BUF_TYPE_CONTIG;
		tx_desc->buf_desc.buf = iov->iov_base;
	} else {
		tx_desc->buf_desc.type = UET_MSG_BUF_TYPE_IOV;
		tx_desc->buf_desc.iov.iov = iov_handle;
		tx_desc->buf_desc.iov.iov_count = iov_count;
	}
	tx_desc->buf_desc.len = msg_len;
	tx_desc->remaining_bytes = msg_len;
	tx_desc->context = context;
	tx_desc->dst_addr_handle = dst_addr_handle;
#if ENABLE_VERBS
	tx_desc->resource_index = resource_index;
#endif
	tx_desc->job_id = job_id;
	tx_desc->msg_id = msg_id;
	tx_desc->uet_ep = uet_ep;
	tx_desc->backoff_min = UET_INITIAL_BACKOFF_MIN;
	tx_desc->backoff_max = UET_INITIAL_BACKOFF_MAX;
	tx_desc->pds_mode = uet_get_pds_mode(uet_ep, rma_op);

	/* force RUDI when UET_FORCE_RUDI is set only for WRITE/READ */
	if ((((send_req_api == UET_WRITE_API) && (imm_data == NULL)) ||
	     (send_req_api == UET_READ_API)) &&
	    getenv("UET_FORCE_RUDI") &&
	    (remote_key & UET_MR_KEY_IDEMPOTENT_SAFE) &&
	    (av_entry->addr->fep_cap & UET_FEP_CAP_HPC))
		tx_desc->pds_mode = UET_PDS_MODE_RUDI;

	/* force UUD when UET_FORCE_UUD is set for a single-packet untagged
	 * SEND
	 */
	if ((send_req_api == UET_SEND_API) &&
	    getenv("UET_FORCE_UUD") &&
	    (msg_len <= uet_ep->uet_domain->uet->max_payload_len))
		tx_desc->pds_mode = UET_PDS_MODE_UUD;

	if (tx_desc->pds_mode == UET_PDS_MODE_ROD)
		tx_desc->seq_num = uet_alloc_av_msg_seq_num(av_entry);
	uet_gettime(&tx_desc->tx_time);
	if (rma_op) {
		tx_desc->remote_start_off = remote_mem_addr;
		tx_desc->remote_key = remote_key;
	}
	if (atomic_op) {
		tx_desc->cq_flags = FI_ATOMIC;
		tx_desc->atomic_parms = *parms;
	}

	switch (send_req_api) {
	case UET_SEND_API:
		if (imm_data) {
			tx_desc->desc_flags |= UET_TX_DESC_FLAG_IMM_DATA_VALID;
			tx_desc->tag_or_immdata = *imm_data;
		}
		tx_desc->cq_flags = FI_SEND | FI_MSG;
		break;
	case UET_TSEND_API:
		tx_desc->cq_flags = FI_SEND | FI_TAGGED;
		tx_desc->tag_or_immdata = tag;
		break;
	case UET_WRITE_API:
		if (imm_data) {
			tx_desc->desc_flags |= UET_TX_DESC_FLAG_IMM_DATA_VALID;
			tx_desc->tag_or_immdata = *imm_data;
		}
		tx_desc->cq_flags = FI_RMA | FI_WRITE;
		break;
	case UET_WRITE_SYNC_API:
		tx_desc->sync_grp = sync_grp_av_entry->sync_grp;
		tx_desc->desc_flags |= UET_TX_DESC_FLAG_SYNC_REQ;
		if (imm_data) {
			tx_desc->desc_flags |= UET_TX_DESC_FLAG_IMM_DATA_VALID;
			tx_desc->tag_or_immdata = *imm_data;
			uet_sync_grp_end_initiator(uet_ep, sync_grp_av_entry);
		}
		tx_desc->cq_flags = FI_RMA | FI_WRITE;
		break;
	case UET_READ_API:
		tx_desc->desc_flags |= UET_TX_DESC_FLAG_READ_REQ;
		tx_desc->cq_flags = FI_RMA | FI_READ;
		tx_desc->rx_desc = rx_desc;
		break;
	case UET_ATOMIC_API:
		tx_desc->desc_flags |= UET_TX_DESC_FLAG_ATOMIC_REQ;
		break;
	case UET_ATOMIC_SYNC_API:
		tx_desc->sync_grp = sync_grp_av_entry->sync_grp;
		tx_desc->desc_flags |= (UET_TX_DESC_FLAG_ATOMIC_REQ |
					UET_TX_DESC_FLAG_SYNC_REQ);
		uet_sync_grp_end_initiator(uet_ep, sync_grp_av_entry);
		break;
	case UET_FETCH_ATOMIC_API:
		tx_desc->desc_flags |= UET_TX_DESC_FLAG_ATOMIC_FETCH_REQ;
		break;
	case UET_COMPARE_ATOMIC_API:
		tx_desc->desc_flags |= UET_TX_DESC_FLAG_ATOMIC_COMPARE_REQ;
		break;
	default:
		break;
	}

	/* insert descriptor for msg in tx ring of endpoint */
	uet_tx_desc_ring_insert(tx_desc);

	/* do the send */
	if (uet_ring_entry_cnt(&uet_ep->tx_ring) == 1)
		uet_tx_msg(tx_desc);

	uet_ep->num_active_sends++;
	av_entry->num_active_ops++;

	pthread_mutex_unlock(&uet_ep->data_lock);
	return FI_SUCCESS;
}

#if ENABLE_VERBS
void uet_verbs_fi_freeinfo(struct fi_info *info)
{
	if (info) {
		if (info->tx_attr)
			free(info->tx_attr);
		if (info->rx_attr)
			free(info->rx_attr);
		if (info->ep_attr)
			free(info->ep_attr);
		if (info->domain_attr)
			free(info->domain_attr);
		if (info->fabric_attr)
			free(info->fabric_attr);
		if (info->nic) {
			if (info->nic->device_attr)
				free(info->nic->device_attr);
			if (info->nic->link_attr)
				free(info->nic->link_attr);
			free(info->nic);
		}
		free(info);
	}
}

struct fi_info *uet_verbs_fi_allocinfo(void)
{
	struct fi_info *info;

	info = calloc(1, sizeof(struct fi_info));
	if (info == NULL)
		goto err;

	info->tx_attr = calloc(1, sizeof(struct fi_tx_attr));
	if (info->tx_attr == NULL)
		goto err;

	info->rx_attr = calloc(1, sizeof(struct fi_rx_attr));
	if (info->rx_attr == NULL)
		goto err;

	info->ep_attr = calloc(1, sizeof(struct fi_ep_attr));
	if (info->ep_attr == NULL)
		goto err;

	info->domain_attr = calloc(1, sizeof(struct fi_domain_attr));
	if (info->domain_attr == NULL)
		goto err;

	info->fabric_attr = calloc(1, sizeof(struct fi_fabric_attr));
	if (info->fabric_attr == NULL)
		goto err;

	return info;

err:
	uet_verbs_fi_freeinfo(info);
	return NULL;
}

struct fi_info *uet_verbs_fi_dupinfo(struct fi_info *info)
{
	struct fi_info *dup;
	struct fi_tx_attr *tx_attr = NULL;
	struct fi_rx_attr *rx_attr = NULL;
	struct fi_ep_attr *ep_attr = NULL;
	struct fi_domain_attr *domain_attr = NULL;
	struct fi_fabric_attr *fabric_attr = NULL;
	struct fid_nic *nic = NULL;
	struct fi_device_attr *device_attr;
	struct fi_link_attr *link_attr;

	dup = calloc(1, sizeof(struct fi_info));
	if (dup == NULL)
		goto err;

	*dup = *info;

	if (info->tx_attr) {
		tx_attr = calloc(1, sizeof(struct fi_tx_attr));
		if (tx_attr == NULL)
			goto err;

		*tx_attr = *info->tx_attr;
		info->tx_attr = tx_attr;
	}

	if (info->rx_attr) {
		rx_attr = calloc(1, sizeof(struct fi_rx_attr));
		if (rx_attr == NULL)
			goto err;

		*rx_attr = *info->rx_attr;
		info->rx_attr = rx_attr;
	}

	if (info->ep_attr) {
		ep_attr = calloc(1, sizeof(struct fi_ep_attr));
		if (ep_attr == NULL)
			goto err;

		*ep_attr = *info->ep_attr;
		info->ep_attr = ep_attr;
	}

	if (info->domain_attr) {
		domain_attr = calloc(1, sizeof(struct fi_domain_attr));
		if (domain_attr == NULL)
			goto err;

		*domain_attr = *info->domain_attr;
		info->domain_attr = domain_attr;
	}

	if (info->fabric_attr) {
		fabric_attr = calloc(1, sizeof(struct fi_fabric_attr));
		if (fabric_attr == NULL)
			goto err;

		*fabric_attr = *info->fabric_attr;
		info->fabric_attr = fabric_attr;
	}

	if (info->nic) {
		nic = calloc(1, sizeof(struct fid_nic));
		if (nic == NULL)
			goto err;

		*nic = *info->nic;
		info->nic = nic;

		if (nic->device_attr) {
			device_attr = calloc(1, sizeof(struct fi_device_attr));
			if (device_attr == NULL)
				goto err;

			*device_attr = *info->nic->device_attr;
			info->nic->device_attr = device_attr;
		}

		if (nic->link_attr) {
			link_attr = calloc(1, sizeof(struct fi_link_attr));
			if (link_attr == NULL)
				goto err;

			*link_attr = *info->nic->link_attr;
			info->nic->link_attr = link_attr;
		}
	}

	return dup;

err:
	if (dup) {
		if (tx_attr)
			free(tx_attr);
		if (rx_attr)
			free(rx_attr);
		if (ep_attr)
			free(ep_attr);
		if (domain_attr)
			free(domain_attr);
		if (fabric_attr)
			free(fabric_attr);
		if (nic) {
			if (device_attr)
				free(device_attr);
			if (link_attr)
				free(link_attr);
			free(nic);
		}
		free(dup);
	}

	return NULL;
}

#endif /* ENABLE_VERBS */

/*********************************************************************
 * Below functions implement UET APIs
 *********************************************************************/

int uet_initialize(uet_handle_t *handle)
{
	int rc;
	time_t seed;
	struct uet_instance *uet;

	uet_gettime(&seed);
	srand48((long) seed);

	uet = calloc(1, sizeof(struct uet_instance));
	if (uet == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		rc = -FI_ENOMEM;
		goto err_return;
	}

	dlist_init(&uet->domain_list_head);

	uet->uet_ipproto = UET_IPPROTO;
	uet->uet_udp_port = UET_UDP_PORT;
	uet->idle_rx_msg_timeout = UET_IDLE_RX_MSG_TIMEOUT;
	uet->idle_dsend_msg_timeout = UET_IDLE_DSEND_MSG_TIMEOUT;
	uet->idle_rtr_msg_timeout = UET_IDLE_RTR_MSG_TIMEOUT;
	uet->max_rx_sync_grp_lifetime = UET_RX_SYNC_GRP_MAX_LIFETIME;
	uet->max_rtr_q_entries = UET_RTR_Q_ENTRIES_MAX;
	uet->max_msg_retransmits = UET_MSG_RETRANSMIT_MAX;
	uet->default_msg_ip_tos = uet_dscp_to_tos(UET_IP_DEFAULT_MSG_DSCP);
	uet->msg_rndz_size = UET_MSG_RENDEZVOUS_SIZE;
	uet->tag_rndz_size = UET_TAG_RENDEZVOUS_SIZE;

	uet->pds.upcall.rx_req = uet_pds_to_ses_rx_req;
	uet->pds.upcall.rx_rsp = uet_pds_to_ses_rx_rsp;
	uet->pds.upcall.pds_err = uet_pds_to_ses_pds_err;

	uet_rw_lock_init(&uet->ep_lkup_lock);

	rc = uet_pds_init(uet);
	if (rc != FI_SUCCESS)
		goto err_return;

	UET_NIC(uet)->uet_ipproto = uet->uet_ipproto;
	rc = uet_nic_initialize(UET_NIC(uet));
	if (rc != FI_SUCCESS)
		goto err_pds;

	rc = imp_shim_init(UET_NIC(uet));
	if (rc != 0)
		goto err_imp_shim;

	rc = uet_sec_init(&uet->nic);
	if (rc != FI_SUCCESS)
		goto err_sec;

	uet->max_payload_len = UET_DEFAULT_MAX_PAYLOAD_LEN;

	*handle = uet;
	return FI_SUCCESS;

err_sec:
	imp_shim_finalize();

err_imp_shim:
	uet_nic_finalize(UET_NIC(uet));

err_pds:
	uet->pds.downcall.finalize(uet);

err_return:
	if (uet != NULL)
		free(uet);
	return rc;
}

int uet_finalize(uet_handle_t handle)
{
	struct uet_instance *uet;

	uet = (struct uet_instance *) handle;
	uet_finalize_core(uet);
	free(uet);

	return FI_SUCCESS;
}

static int uet_fid_nic_close(struct fid *fid)
{
	struct fid_nic *nic = (struct fid_nic *)fid;

	if (nic == NULL)
		return 0;

	if (nic->device_attr != NULL) {
		free(nic->device_attr->name);
		free(nic->device_attr->device_id);
		free(nic->device_attr->device_version);
		free(nic->device_attr->vendor_id);
		free(nic->device_attr->driver);
		free(nic->device_attr->firmware);
		free(nic->device_attr);
	}
	free(nic->bus_attr);
	if (nic->link_attr != NULL) {
		free(nic->link_attr->network_type);
		free(nic->link_attr->address);
		free(nic->link_attr);
	}
	free(nic);

	return 0;
}

static int uet_fid_nic_control(struct fid *fid, int command, void *arg)
{
	struct fid_nic *nic = (struct fid_nic *)fid;
	struct fid_nic *dup;

	if (command != FI_DUP)
		return -FI_ENOSYS;
	if (arg == NULL)
		return -FI_EINVAL;

	dup = calloc(1, sizeof(*dup));
	if (dup == NULL)
		return -FI_ENOMEM;
	dup->fid = nic->fid;
	dup->prov_attr = nic->prov_attr;

	if (nic->device_attr != NULL) {
		dup->device_attr = calloc(1, sizeof(*dup->device_attr));
		if (dup->device_attr == NULL)
			goto err;
#define UET_DUP_NIC_STRING(_field)                                      \
		do {                                                        \
			if (nic->device_attr->_field != NULL) {              \
				dup->device_attr->_field =                      \
					strdup(nic->device_attr->_field);        \
				if (dup->device_attr->_field == NULL)            \
					goto err;                                 \
			}                                                   \
		} while (0)
		UET_DUP_NIC_STRING(name);
		UET_DUP_NIC_STRING(device_id);
		UET_DUP_NIC_STRING(device_version);
		UET_DUP_NIC_STRING(vendor_id);
		UET_DUP_NIC_STRING(driver);
		UET_DUP_NIC_STRING(firmware);
#undef UET_DUP_NIC_STRING
	}

	if (nic->bus_attr != NULL) {
		dup->bus_attr = malloc(sizeof(*dup->bus_attr));
		if (dup->bus_attr == NULL)
			goto err;
		*dup->bus_attr = *nic->bus_attr;
	}

	if (nic->link_attr != NULL) {
		dup->link_attr = calloc(1, sizeof(*dup->link_attr));
		if (dup->link_attr == NULL)
			goto err;
		*dup->link_attr = *nic->link_attr;
		dup->link_attr->network_type = NULL;
		dup->link_attr->address = NULL;
		if (nic->link_attr->network_type != NULL) {
			dup->link_attr->network_type =
				strdup(nic->link_attr->network_type);
			if (dup->link_attr->network_type == NULL)
				goto err;
		}
		if (nic->link_attr->address != NULL) {
			dup->link_attr->address = strdup(nic->link_attr->address);
			if (dup->link_attr->address == NULL)
				goto err;
		}
	}

	*(struct fid_nic **)arg = dup;
	return FI_SUCCESS;

err:
	uet_fid_nic_close(&dup->fid);
	return -FI_ENOMEM;
}

static struct fi_ops uet_fid_nic_ops = {
	.size = sizeof(struct fi_ops),
	.close = uet_fid_nic_close,
	.control = uet_fid_nic_control,
};

int uet_getinfo(uet_handle_t handle, struct uet_addr *node,
		const struct fi_info *hints, struct fi_info **info)
{
	int rc;
	struct uet_instance *uet;
	struct uet_nic_info nic_info;
	struct fi_info *new_info;
	struct fid_nic *nic = NULL;
	struct uet_addr *src_addr;
	struct uet_fa def_ip;
	bool def_ipv6;

	uet = (struct uet_instance *) handle;

#if ENABLE_VERBS
	new_info = uet_verbs_fi_allocinfo();
#else
	new_info = fi_allocinfo();
#endif
	if (new_info == NULL) {
		UET_API_ERR("fi_allocinfo");
		rc = -FI_ENOMEM;
		goto err_return;
	}

	nic = calloc(1, sizeof(struct fid_nic));
	if (nic == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		rc = -FI_ENOMEM;
		goto err_return;
	}

	nic->device_attr = calloc(1, sizeof(struct fi_device_attr));
	if (nic->device_attr == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		rc = -FI_ENOMEM;
		goto err_return;
	}

	nic->link_attr = calloc(1, sizeof(struct fi_link_attr));
	if (nic->link_attr == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		rc = -FI_ENOMEM;
		goto err_return;
	}

	nic->fid.fclass = FI_CLASS_NIC;
	nic->fid.context = uet;

	nic->fid.ops = &uet_fid_nic_ops;

	rc = uet_nic_getinfo(UET_NIC(uet), &nic_info);
	if (rc != FI_SUCCESS) {
		UET_API_ERR("uet_nic_getinfo");
		goto err_return;
	}

	nic->device_attr->name = strdup(nic_info.ifname);
	nic->link_attr->network_type = strdup(nic_info.network_type);
	nic->link_attr->address = strdup(nic_info.mac_addr_str);
	if (nic->device_attr->name == NULL ||
	    nic->link_attr->network_type == NULL ||
	    nic->link_attr->address == NULL) {
		UET_API_PRINT_ERRNO("strdup");
		rc = -FI_ENOMEM;
		goto err_return;
	}
	nic->link_attr->mtu          = nic_info.mtu;
	nic->link_attr->state        =
		(nic_info.link_state == UET_NIC_LINK_STATE_DOWN)
			? FI_LINK_DOWN
			: (nic_info.link_state == UET_NIC_LINK_STATE_UP)
				? FI_LINK_UP
				: FI_LINK_UNKNOWN;

	/*
	 * TODO:
	 *   - need to process hints
	 *   - for now, just do minimal init of fi_info fields
	 *   - need to add comprehensive init of other fi_info fields
	 */
	new_info->next = NULL;
	new_info->domain_attr->mr_key_size = UET_MR_KEY_MAX_RKEY;
	new_info->domain_attr->mr_mode = FI_MR_ENDPOINT;
	new_info->domain_attr->mr_cnt = UET_DEF_MR_CNT;
	new_info->ep_attr->max_msg_size = UET_MAX_MSG_SIZE;
	new_info->tx_attr->iov_limit = UET_IOV_LIMIT;
	new_info->tx_attr->rma_iov_limit = UET_RMA_IOV_LIMIT;
	new_info->rx_attr->iov_limit = UET_IOV_LIMIT;
	new_info->caps = FI_LOCAL_COMM | FI_REMOTE_COMM | FI_MSG | FI_SEND |
			 FI_RECV | FI_TAGGED | FI_DIRECTED_RECV | FI_RMA |
			 FI_READ | FI_WRITE | FI_REMOTE_READ |
			 FI_REMOTE_WRITE | FI_ATOMIC;

	src_addr = calloc(1, sizeof(struct uet_addr));
	if (src_addr == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		rc = -FI_ENOMEM;
		goto err_return;
	}

	/*
	 * Dual-stack: select the local address family. If the caller
	 * supplies a node address (non-VERBS path), honor its family.
	 * Otherwise default to an available family (prefer IPv4). On the
	 * VERBS path the per-endpoint family is (re)bound in uet_endpoint()
	 * from the QP's local GID, so the advertised address here is only
	 * a placeholder.
	 */
	if (node)
		def_ipv6 = uet_addr_is_ipv6(node);
	else
		def_ipv6 = (!uet->nic.has_ipv4 && uet->nic.has_ipv6);

	memset(&def_ip, 0, sizeof(def_ip));
	if (def_ipv6)
		memcpy(def_ip.v6, uet->nic.ipv6_addr, 16);
	else
		def_ip.v4 = uet->nic.ipv4_addr;

	uet_init_uet_addr(src_addr, &def_ip, def_ipv6);

	new_info->dest_addrlen = 0;
	new_info->src_addrlen = sizeof(struct uet_addr);
	new_info->src_addr = src_addr;

	new_info->nic = nic;

	*info = new_info;
	return FI_SUCCESS;

err_return:
	if (nic != NULL)
		uet_fid_nic_close(&nic->fid);
	if (new_info != NULL) {
#if ENABLE_VERBS
		uet_verbs_fi_freeinfo(new_info);
#else
		fi_freeinfo(new_info);
#endif
	}
	return rc;
}

int uet_domain(uet_handle_t handle, struct fid_fabric *fabric,
	       struct fi_info *info, struct fid_domain *domain,
	       void *context, uet_eq_callback_t eq_callback,
	       uet_eq_err_callback_t eq_err_callback,
	       uet_domain_handle_t *domain_handle)
{
	int rc;
	struct uet_instance *uet;
	struct uet_domain *uet_dom;

	uet = (struct uet_instance *) handle;

	/* check that memory regions are associated with endpoints */
	if (!(info->domain_attr->mr_mode & FI_MR_ENDPOINT)) {
		UET_API_ERR("FI_MR_ENDPOINT must be set");
		return -FI_EINVAL;
	}

	/* allocate memory for domain object */
	uet_dom = calloc(1, sizeof(struct uet_domain));
	if (uet_dom == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		rc = -FI_ENOMEM;
		goto err_exit;
	}

	/* check requested memory region count */
	if (info->domain_attr->mr_cnt > UET_MR_KEY_MAX_RKEY) {
		UET_API_ERR("Requested memory region count exceeds max");
		rc = -FI_EINVAL;
		goto err_exit;
	}

	/* allocate memory for memory region descriptors */
	if (info->domain_attr->mr_cnt > UET_DEF_MR_CNT)
		uet_dom->num_mr = info->domain_attr->mr_cnt;
	else
		uet_dom->num_mr = UET_DEF_MR_CNT;

	uet_dom->mr_desc = calloc(uet_dom->num_mr,
				 sizeof(struct uet_mr_desc));
	if (uet_dom->mr_desc == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		rc = -FI_ENOMEM;
		goto err_exit;
	}

	/* allocate memory for memory region allocation state */
	uet_dom->mr_desc_alloc_cb.state = calloc(uet_dom->num_mr,
						 sizeof(uint8_t));
	if (uet_dom->mr_desc_alloc_cb.state == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		rc = -FI_ENOMEM;
		goto err_exit;
	}

	/* init memory region allocation state */
	if (uet_dom->num_mr > (UET_MR_KEY_OPTIMIZED_MAX_RKEY + 1))
		uet_dom->mr_desc_alloc_cb.next_mr_index =
					UET_MR_KEY_OPTIMIZED_MAX_RKEY + 1;

	/* init domain object */
	uet_dom->uet = uet;
	uet_dom->fabric = fabric;
	uet_dom->info = info;
	uet_dom->domain = domain;
	uet_dom->context = context;
	uet_dom->eq_callback = eq_callback;
	uet_dom->eq_err_callback = eq_err_callback;
	dlist_init(&uet_dom->ep_list_head);
	dlist_init(&uet_dom->av_list_head);
	uet_rw_lock_init(&uet_dom->ep_lock);

	/* insert object into domain list */
	uet_domain_insert(uet_dom);

	*domain_handle = uet_dom;
	return FI_SUCCESS;

err_exit:
	if (uet_dom) {
		if (uet_dom->mr_desc_alloc_cb.state)
			free(uet_dom->mr_desc_alloc_cb.state);
		if (uet_dom->mr_desc)
			free(uet_dom->mr_desc);
		free(uet_dom);
	}
	return rc;
}

int uet_domain_close(uet_domain_handle_t domain_handle)
{
	struct uet_domain *uet_dom;

	uet_dom = (struct uet_domain *) domain_handle;

	if (uet_domain_has_ep(uet_dom)) {
		UET_API_ERR("EPs associated with domain being closed");
		return -FI_EBUSY;
	}

	uet_domain_free(uet_dom);
	return FI_SUCCESS;
}

#if ENABLE_VERBS
int uet_endpoint(uet_domain_handle_t domain_handle,
		 struct fi_info *info, struct fid_ep *ep,
		 void *context, uet_ep_handle_t *ep_handle,
		 uint16_t pid_on_fep, uint16_t resource_index,
		 uint32_t initiator_id, uint32_t job_id,
		 bool absolute, bool is_ipv6)
#else
int uet_endpoint(uet_domain_handle_t domain_handle,
		 struct fi_info *info, struct fid_ep *ep,
		 void *context, uet_ep_handle_t *ep_handle)
#endif
{
	int rc;
	size_t i;
	struct uet_domain *uet_dom;
	struct uet_ep *uet_ep;
	struct uet_pds *pds;

	uet_dom = (struct uet_domain *) domain_handle;
	pds = &uet_dom->uet->pds;

	/* allocate memory for ep object */
	uet_ep = calloc(1, sizeof(struct uet_ep));
	if (uet_ep == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		rc = -FI_ENOMEM;
		goto err_exit;
	}

	pthread_mutex_init(&uet_ep->data_lock, NULL);

	/* init ep object */
	memcpy(&uet_ep->uet_addr, info->src_addr, info->src_addrlen);
#if ENABLE_VERBS
	uet_ep->uet_addr.pid_on_fep = pid_on_fep;
	uet_ep->uet_addr.num_indices = 1;
	uet_ep->uet_addr.start_index = resource_index;
	uet_ep->uet_addr.initiator_id = initiator_id;
	uet_ep->uet_addr.flags |= (UET_ADDR_PID_ON_FEP_V | UET_ADDR_INDEX_V |
				    UET_ADDR_INITIATOR_V);
	uet_ep->job_id = job_id;
	uet_ep->absolute = absolute;
	if (absolute)
		uet_ep->uet_addr.flags |= UET_ADDR_ABSOLUTE_MODE;

	/* dual-stack: bind the endpoint to the specified address family */
	uet_ep->uet_addr.flags &= ~(UET_ADDR_IPV4 | UET_ADDR_IPV6);
	memset(&uet_ep->uet_addr.fa, 0, sizeof(struct uet_fa));
	if (is_ipv6) {
		uet_ep->uet_addr.flags |= UET_ADDR_IPV6;
		memcpy(uet_ep->uet_addr.fa.v6, uet_dom->uet->nic.ipv6_addr, 16);
	} else {
		uet_ep->uet_addr.flags |= UET_ADDR_IPV4;
		uet_ep->uet_addr.fa.v4 = uet_dom->uet->nic.ipv4_addr;
	}
#else
	rc = uet_addr_resolution(&uet_ep->uet_addr, &uet_ep->job_id);
	if (rc != FI_SUCCESS) {
		UET_API_ERR("uet_addr_resolution");
		goto err_exit;
	}
#endif
	memcpy(&uet_ep->ip_addr, &uet_ep->uet_addr.fa, sizeof(struct uet_fa));

	uet_ep->num_rx_desc = info->rx_attr->size;
	uet_ep->rx_desc = calloc(uet_ep->num_rx_desc,
				 sizeof(struct uet_rx_desc));
	if (uet_ep->rx_desc == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		rc = -FI_ENOMEM;
		goto err_exit;
	}

	dlist_init(&uet_ep->rx_desc_list_head);
	dlist_init(&uet_ep->rx_desc_active_list_head);
	dlist_init(&uet_ep->mr_list_head);

	for (i = 0; i < uet_ep->num_rx_desc; i++) {
		uet_ep->rx_desc[i].uet_ep = uet_ep;
		uet_rx_desc_list_insert(&uet_ep->rx_desc[i]);
	}

	uet_ep->num_tx_desc = info->tx_attr->size;
	uet_ep->tx_desc = calloc(uet_ep->num_tx_desc,
				 sizeof(struct uet_tx_desc));
	if (uet_ep->tx_desc == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		rc = -FI_ENOMEM;
		goto err_exit;
	}

	dlist_init(&uet_ep->tx_desc_list_head);
	dlist_init(&uet_ep->tx_desc_defer_list_head);
	dlist_init(&uet_ep->tx_desc_buf_rtr_list_head);
	dlist_init(&uet_ep->tx_desc_buf_tag_rtr_list_head);

	for (i = 0; i < uet_ep->num_tx_desc; i++) {
		uet_ep->tx_desc[i].uet_ep = uet_ep;
		uet_tx_desc_list_insert(&uet_ep->tx_desc[i]);
	}

	rc = uet_ring_init(&uet_ep->rx_ring,
			   sizeof(struct uet_rx_desc_ring_entry),
			   uet_ep->num_rx_desc);
	if (rc != FI_SUCCESS) {
		UET_API_ERR("uet_ring_init");
		goto err_exit;
	}

	rc = uet_ring_init(&uet_ep->tx_ring,
			   sizeof(struct uet_tx_desc_ring_entry),
			   uet_ep->num_tx_desc);
	if (rc != FI_SUCCESS) {
		UET_API_ERR("uet_ring_init");
		goto err_exit;
	}

	uet_ep->uet_domain = uet_dom;
	uet_ep->info = info;
	uet_ep->ep = ep;
	uet_ep->context = context;
	uet_ep->send_cq.cq_state = UET_CQ_DOWN;
	uet_ep->recv_cq.cq_state = UET_CQ_DOWN;

	if (uet_ep->uet_addr.flags & UET_ADDR_IPV6)
		uet_ep->ep_key.ipv6_addr = true;
	memcpy(&uet_ep->ep_key.ip_addr, &uet_ep->ip_addr,
	       sizeof(struct uet_fa));
	uet_ep->ep_key.pid_on_fep = uet_ep->uet_addr.pid_on_fep;
	uet_ep->ep_key.index = uet_ep->uet_addr.start_index;
	uet_ep_hash_insert(uet_ep);
	uet_ep->entropy = uet_ep_entropy_init(uet_ep);

	switch (info->tx_attr->tclass) {
	case FI_TC_BEST_EFFORT:
	case FI_TC_UNSPEC:
		uet_ep->msg_ip_tos = uet_dom->uet->default_msg_ip_tos;
		break;
	default:
		uet_ep->msg_ip_tos = uet_dscp_to_tos(info->tx_attr->tclass);
		break;
	}

	pds->downcall.ep_initialize(uet_ep);
	uet_ep->ep_state = UET_EP_DISABLED;

	/* insert object into ep list */
	uet_ep_insert(uet_ep);

	*ep_handle = uet_ep;
	return FI_SUCCESS;

err_exit:
	if (uet_ep) {
		uet_desc_free(uet_ep);
		free(uet_ep);
	}
	return rc;
}

int uet_getname(uet_ep_handle_t ep_handle, struct uet_addr *uet_addr)
{
	struct uet_ep *uet_ep;

	uet_ep = (struct uet_ep *) ep_handle;
	*uet_addr = uet_ep->uet_addr;

	return FI_SUCCESS;
}

int uet_ep_bind_cq(uet_ep_handle_t ep_handle, struct fi_cq_attr *attr,
		   struct fid_cq *cq, uint64_t flags, void *context,
		   uet_cq_handle_t *cq_handle)
{
	struct uet_ep *uet_ep;
	size_t num_desc, num_cq_entries, cq_entry_size;
	struct uet_cq *uet_cq;
	int rc, both_flags = FI_SEND | FI_RECV;

	uet_ep = (struct uet_ep *) ep_handle;

	/* check flags to determine cq type                      */
	/*   - one and only one of FI_SEND & FI_RECV must be set */
	if (flags & FI_SELECTIVE_COMPLETION) {
		UET_API_ERR("Selective Completion Not Supported");
		return -FI_EINVAL;
	}
	if (!(flags & both_flags) ||
	    ((flags & both_flags) == both_flags)) {
		UET_API_ERR("Shared TX/RX CQ Not Supported");
		return -FI_EINVAL;
	}
	if (flags & FI_SEND) {
		if (uet_ep_has_send_cq(uet_ep)) {
			UET_API_ERR("Multiple TX CQs per EP Not Supported");
			return -FI_EINVAL;
		}
		uet_cq = &uet_ep->send_cq;
		num_desc = uet_ep->num_tx_desc;
	} else {
		if (uet_ep_has_recv_cq(uet_ep)) {
			UET_API_ERR("Multiple RX CQs per EP Not Supported");
			return -FI_EINVAL;
		}
		uet_cq = &uet_ep->recv_cq;
		num_desc = uet_ep->num_rx_desc;
	}

	/* determine cq entry size */
	switch (attr->format) {
	case FI_CQ_FORMAT_CONTEXT:
	case FI_CQ_FORMAT_UNSPEC:
		cq_entry_size = sizeof(struct fi_cq_entry);
		break;
	case FI_CQ_FORMAT_MSG:
		cq_entry_size = sizeof(struct fi_cq_msg_entry);
		break;
	case FI_CQ_FORMAT_DATA:
		cq_entry_size = sizeof(struct fi_cq_data_entry);
		break;
	case FI_CQ_FORMAT_TAGGED:
		cq_entry_size = sizeof(struct fi_cq_tagged_entry);
		break;
	default:
		UET_API_ERR("Unknown CQ Format = %d", attr->format);
		return -FI_EINVAL;
	}

	/* determine number of cq entries                                    */
	/*   - make sure there is a cq entry for every outstanding operation */
	num_cq_entries = uet_max(attr->size, num_desc);

	/* init cq */
	rc = uet_ring_init(&uet_cq->ring, sizeof(struct uet_cq_ring_entry),
			   num_cq_entries);
	if (rc != FI_SUCCESS) {
		UET_API_ERR("uet_ring_init");
		return rc;
	}
	uet_cq->cq_state = UET_CQ_UP;
	uet_cq->uet_ep = uet_ep;
	uet_cq->attr = attr;
	uet_cq->fid_cq = cq;
	uet_cq->flags = flags;
	uet_cq->context = context;
	uet_cq->format = attr->format;
	uet_cq->format_size = cq_entry_size;

	*cq_handle = uet_cq;
	return FI_SUCCESS;
}

int uet_mr_disable(uet_mr_handle_t mr_handle)
{
	struct uet_mr_desc *mr_desc;

	mr_desc = (struct uet_mr_desc *) mr_handle;

	if (mr_desc->state != UET_MR_DESC_STATE_ENABLED) {
		UET_API_ERR("Bad MR state for disable");
		return -FI_EINVAL;
	}

	/* Remove just this MR from the lookup space that matches its key's
	 * origin (mirrors uet_mr_enable's per-MR insert): user keys use the
	 * per-endpoint hash, provider keys use the index-space list. Return
	 * the MR to the registered state so it can be re-bound/re-enabled or
	 * closed. A subsequent RX request no longer finds it (access revoked).
	 */
	if (mr_desc->user_key)
		uet_mr_hash_remove(mr_desc);
	else
		uet_mr_list_remove(mr_desc);

	mr_desc->state = UET_MR_DESC_STATE_DISABLED_REG;
	mr_desc->uet_ep = NULL;

	return FI_SUCCESS;
}

int uet_ep_enable(uet_ep_handle_t ep_handle)
{
	struct uet_ep *uet_ep;

	uet_ep = (struct uet_ep *) ep_handle;
	uet_ep->ep_state = UET_EP_ENABLED;

	return FI_SUCCESS;
}

int uet_ep_reset(uet_ep_handle_t ep_handle)
{
	struct uet_ep *uet_ep;

	uet_ep = (struct uet_ep *) ep_handle;

	/* Teturn the endpoint to the pre-enable state and clear the transient
	 * generation state so a subsequent uet_ep_enable() gives a clean,
	 * usable endpoint (verbs QP error recovery: ERR -> RST -> RTS).
	 */
	uet_ep->ep_state = UET_EP_DISABLED;
	uet_ep->untagged_gen_disabled = false;
	uet_ep->tagged_gen_disabled = false;

	return FI_SUCCESS;
}

int uet_ep_close(uet_ep_handle_t ep_handle)
{
	struct uet_ep *uet_ep;
	struct uet_pds *pds;

	uet_ep = (struct uet_ep *) ep_handle;
	pds = &uet_ep->uet_domain->uet->pds;

	/* Error if there are outstanding msg transmits */
	if ((uet_ep->num_active_sends)) {
		UET_API_ERR("Outstanding sends associated with EP being closed");
		return -FI_EBUSY;
	}

	if (uet_ep->uet_domain->info->domain_attr->mr_mode & FI_MR_PROV_KEY)
		uet_mr_list_finalize(uet_ep);
	else
		uet_mr_hash_finalize(uet_ep);

	pds->downcall.ep_close_wait(uet_ep);

	uet_ep_hash_remove(uet_ep);

	uet_ep_free(uet_ep);

	return FI_SUCCESS;
}

uint32_t uet_cq_read_src_id(uet_cq_handle_t cq_handle)
{
	struct uet_cq *cq = (struct uet_cq *) cq_handle;

	return cq->last_src_id;
}

/*
 * run one progress cycle for an endpoint
 *
 * Ages idle receive messages and receive sync groups, drives one receive
 * packet through the PDS, drives pending transmits, and retries deferred
 * transmit messages.
 *
 * NOTE: the caller MUST hold uet_ep->data_lock
 */
static void uet_ep_progress_locked(struct uet_ep *uet_ep)
{
	int rc;
	uet_pkt_handle_t err_pkt_handle;
	struct uet_pds *pds;

	pds = &uet_ep->uet_domain->uet->pds;

	uet_msg_age(uet_ep);
	uet_rx_sync_grp_age(uet_ep);

	pds->downcall.progress_rx(uet_ep->uet_domain->uet);

	rc = pds->downcall.progress_tx(uet_ep, &err_pkt_handle);
	switch (rc) {
	case FI_SUCCESS:
	case -FI_EAGAIN:
		break;
	default:
		break;
	}

	uet_tx_msg_try(uet_ep);
}

int uet_ep_progress(uet_ep_handle_t ep_handle)
{
	struct uet_ep *uet_ep = (struct uet_ep *) ep_handle;

	if (uet_ep == NULL)
		return -FI_EINVAL;

	pthread_mutex_lock(&uet_ep->data_lock);
	uet_ep_progress_locked(uet_ep);
	pthread_mutex_unlock(&uet_ep->data_lock);

	return FI_SUCCESS;
}

int uet_progress(uet_domain_handle_t domain_handle)
{
	struct uet_domain *uet_dom = (struct uet_domain *) domain_handle;
	struct uet_ep *uet_ep;
	struct dlist_entry *head, *item;

	if (uet_dom == NULL)
		return -FI_EINVAL;

	head = &uet_dom->ep_list_head;

	uet_rw_lock(&uet_dom->ep_lock, UET_RW_LOCK_RD_ACCESS);

	dlist_foreach(head, item) {
		uet_ep = container_of(item, struct uet_ep, ep_list_entry);

		pthread_mutex_lock(&uet_ep->data_lock);
		uet_ep_progress_locked(uet_ep);
		pthread_mutex_unlock(&uet_ep->data_lock);
	}

	uet_rw_unlock(&uet_dom->ep_lock, UET_RW_LOCK_RD_ACCESS);

	return FI_SUCCESS;
}

ssize_t uet_cq_read(uet_cq_handle_t cq_handle, void *buf, size_t count)
{
	struct uet_cq *cq;
	struct uet_ep *uet_ep;
	struct uet_ring *ring;
	ssize_t cq_count, rd_count, max_rd_count;
	char *buffer = buf;

	cq = (struct uet_cq *) cq_handle;
	uet_ep = cq->uet_ep;

	pthread_mutex_lock(&uet_ep->data_lock);

	uet_ep_progress_locked(uet_ep);

	ring = &cq->ring;
	cq_count = uet_ring_entry_cnt(ring);
	if (cq_count == 0) {
		pthread_mutex_unlock(&uet_ep->data_lock);
		return 0;
	}

	max_rd_count = uet_min(cq_count, count);
	for (rd_count = 0; rd_count < max_rd_count; rd_count++) {
		if (uet_cq_is_err_state(ring)) {
			if (rd_count == 0)
				rd_count = -FI_EAVAIL;
			break;
		}
		if (cq == &uet_ep->send_cq)
			uet_tx_cq_read_entry(&buffer[rd_count*cq->format_size],
					     ring);
		else
			uet_rx_cq_read_entry(&buffer[rd_count*cq->format_size],
					     ring);
	}

	pthread_mutex_unlock(&uet_ep->data_lock);
	return rd_count;
}

ssize_t uet_cq_readerr(uet_cq_handle_t cq_handle,
		       struct fi_cq_err_entry *buf)
{
	struct uet_cq *cq;
	struct uet_ep *uet_ep;
	struct uet_ring *ring;
	struct uet_cq_ring_entry *ring_entry;
	struct fi_cq_err_entry *err_entry;

	cq = (struct uet_cq *) cq_handle;
	ring = &cq->ring;
	uet_ep = cq->uet_ep;

	pthread_mutex_lock(&uet_ep->data_lock);

	if (!uet_cq_is_err_state(ring)) {
		pthread_mutex_unlock(&uet_ep->data_lock);
		return -FI_EAGAIN;
	}

	ring_entry = &(((struct uet_cq_ring_entry *) (ring->base))[ring->tail]);
	err_entry = (struct fi_cq_err_entry *) ring_entry->cq_entry;
	*buf = *err_entry;

	if (cq == &uet_ep->send_cq)
		uet_tx_desc_list_insert(ring_entry->desc.tx);
	else
		uet_rx_desc_list_insert(ring_entry->desc.rx);

	uet_ring_tail_advance(ring);

	pthread_mutex_unlock(&uet_ep->data_lock);
	return 1;
}

int uet_cq_close(uet_cq_handle_t cq_handle)
{
	/*
	 * The libfrabric programmer's guide states the following:
	 *
	 * 'The fi_close call releases all resources associated with a completion
	 *  queue. Any completions which remain on the CQ when it is closed
	 *  are lost. When closing the CQ, there must be no opened endpoints,
	 *  transmit contexts, or receive contexts associated with the CQ.
	 *  If resources are still associated with the CQ when attempting to
	 *  close, the call will return -FI_EBUSY.'
	 *
	 *  However, in this implementation, CQ resources are embedded in
	 *  the endpoint resources. The CQ resources are released when the
	 *  endpoint is closed. As a result, the uet_cq_close() function does
	 *  not need to release any resources.
	 */

	return FI_SUCCESS;
}

int uet_av_insert(uet_domain_handle_t domain_handle,
		  struct uet_addr *uet_addr,
		  uet_addr_handle_t *addr_handle)
{
	int rc;
	struct uet_instance *uet;
	struct uet_domain *uet_dom;
	struct uet_av_entry *av_entry;

	uet_dom = (struct uet_domain *) domain_handle;
	uet = uet_dom->uet;

	/* allocate memory for av object */
	av_entry = calloc(1, sizeof(struct uet_av_entry));
	if (av_entry == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		return -FI_ENOMEM;
	}

	/* initialize av entry */
	av_entry->addr = uet_addr;
	rc = uet_nic_get_nh(UET_NIC(uet), &uet_addr->fa,
			    uet_addr_is_ipv6(uet_addr),
			    av_entry->nh_mac_addr);
	if (rc == FI_SUCCESS)
		av_entry->flags |= UET_NH_MAC_ADDR_V;

	/* insert av object in list of av entries for domain */
	uet_dom = (struct uet_domain *) domain_handle;
	uet_av_entry_insert(uet_dom, av_entry);

	*addr_handle = av_entry;
	return FI_SUCCESS;
}

int uet_av_remove(uet_addr_handle_t addr_handle)
{
	struct uet_av_entry *av_entry;

	av_entry = (struct uet_av_entry *) addr_handle;

	/* fail if there are outstanding operations using the av */
	if (av_entry->num_active_ops) {
		UET_API_ERR("Outstanding ops associated with AV being removed");
		return -FI_EBUSY;
	}

	uet_av_entry_free(av_entry);

	return -FI_SUCCESS;
}

#if !ENABLE_VERBS
ssize_t uet_recv(uet_ep_handle_t ep_handle, uint32_t job_id,
		 void *buf, size_t len, uet_mr_handle_t mr_handle,
		 uet_addr_handle_t src_addr_handle, void *context)
{

	struct iovec iov;

	iov.iov_base = (void *) buf;
	iov.iov_len = len;

	return (uet_recv_api_common(UET_RECV_API, ep_handle, job_id, &iov, 1,
				    mr_handle, src_addr_handle, UET_NO_TAG,
				    UET_NO_IGNORE_BITS, context, NULL, 0));
}

ssize_t uet_recvv(
	uet_ep_handle_t ep_handle, uint32_t job_id, const struct iovec *iov,
	size_t count, uet_mr_handle_t mr_handle,
	uet_addr_handle_t src_addr_handle, void *context)
{
	return (uet_recv_api_common(UET_RECV_API, ep_handle, job_id, iov, count,
				    mr_handle, src_addr_handle, UET_NO_TAG,
				    UET_NO_IGNORE_BITS, context, NULL, 0));
}

#else

ssize_t uet_recv(uet_ep_handle_t ep_handle, uint32_t job_id,
		 void *buf, size_t len, uet_mr_handle_t mr_handle,
		 uet_addr_handle_t src_addr_handle, void *context)
{

	struct iovec iov;

	iov.iov_base = (void *) buf;
	iov.iov_len = len;

	return (uet_recv_api_common(UET_RECV_API, ep_handle, job_id, &iov, 1,
				    mr_handle, src_addr_handle, UET_NO_TAG,
				    UET_NO_IGNORE_BITS, context, NULL, 0));
}

ssize_t uet_recvv(
	uet_ep_handle_t ep_handle, uint32_t job_id, const struct iovec *iov,
	size_t count, uet_mr_handle_t mr_handle,
	uet_addr_handle_t src_addr_handle, void *context)
{
	return (uet_recv_api_common(UET_RECV_API, ep_handle, job_id, iov,
				    count, mr_handle, src_addr_handle,
				    UET_NO_TAG, UET_NO_IGNORE_BITS, context,
				    NULL, 0));
}

#endif /* ENABLE_VERBS */

ssize_t uet_trecvv(uet_ep_handle_t ep_handle, uint32_t job_id,
		  const struct iovec *iov, size_t count,
		  uet_mr_handle_t mr_handle, uet_addr_handle_t src_addr_handle,
		  uint64_t tag,
		  uint64_t ignore, void *context)
{
	return (uet_recv_api_common(UET_TRECV_API, ep_handle, job_id, iov,
				    count, mr_handle, src_addr_handle, tag,
				    ignore, context, NULL, 0));
}

#if !ENABLE_VERBS
ssize_t uet_send(uet_ep_handle_t ep_handle, uint32_t job_id,
		 void *buf, size_t len, uet_mr_handle_t mr_handle,
		 uet_addr_handle_t dst_addr_handle, void *context)
{
	struct iovec iov;

	iov.iov_base = (void *) buf;
	iov.iov_len = len;

	return (uet_send_req_api_common(
			UET_SEND_API, ep_handle, job_id, &iov, 1, mr_handle,
			dst_addr_handle, UET_NO_TAG, UET_NO_IMM_DATA,
			UET_NO_REMOTE_MEM_ADDR, UET_NO_REMOTE_KEY,
			NULL, context, NULL, 0));
}

ssize_t uet_sendv(
	uet_ep_handle_t ep_handle, uint32_t job_id, const struct iovec *iov,
	size_t count, uet_mr_handle_t mr_handle,
	uet_addr_handle_t dst_addr_handle, void *context)
{
	return (uet_send_req_api_common(
			UET_SEND_API, ep_handle, job_id, iov, count, mr_handle,
			dst_addr_handle, UET_NO_TAG, UET_NO_IMM_DATA,
			UET_NO_REMOTE_MEM_ADDR, UET_NO_REMOTE_KEY,
			NULL, context, NULL, 0));
}

#else
ssize_t uet_send(uet_ep_handle_t ep_handle, uint32_t job_id,
		 void *buf, size_t len, uet_mr_handle_t mr_handle,
		 uet_addr_handle_t dst_addr_handle, void *context,
		 uint16_t resource_index)
{
	struct iovec iov;

	iov.iov_base = (void *) buf;
	iov.iov_len = len;

	return (uet_send_req_api_common(
			UET_SEND_API, ep_handle, job_id, &iov, 1, mr_handle,
			dst_addr_handle, UET_NO_TAG, UET_NO_IMM_DATA,
			UET_NO_REMOTE_MEM_ADDR, UET_NO_REMOTE_KEY,
			NULL, context, resource_index, NULL, 0));
}

ssize_t uet_sendv(
	uet_ep_handle_t ep_handle, uint32_t job_id, const struct iovec *iov,
	size_t count, uet_mr_handle_t mr_handle,
	uet_addr_handle_t dst_addr_handle, void *context,
	uint16_t resource_index)
{
	return (uet_send_req_api_common(
			UET_SEND_API, ep_handle, job_id, iov, count, mr_handle,
			dst_addr_handle, UET_NO_TAG, UET_NO_IMM_DATA,
			UET_NO_REMOTE_MEM_ADDR, UET_NO_REMOTE_KEY,
			NULL, context, resource_index, NULL, 0));
}

ssize_t uet_send_imm(uet_ep_handle_t ep_handle, uint32_t job_id,
		     void *buf, size_t len, uet_mr_handle_t mr_handle,
		     uet_addr_handle_t dst_addr_handle, uint64_t *imm_data,
		     void *context, uint16_t resource_index)
{
	struct iovec iov;

	iov.iov_base = (void *) buf;
	iov.iov_len = len;

	return (uet_send_req_api_common(
			UET_SEND_API, ep_handle, job_id, &iov, 1, mr_handle,
			dst_addr_handle, UET_NO_TAG, imm_data,
			UET_NO_REMOTE_MEM_ADDR, UET_NO_REMOTE_KEY,
			NULL, context, resource_index, NULL, 0));
}

ssize_t uet_sendv_imm(uet_ep_handle_t ep_handle, uint32_t job_id,
		      const struct iovec *iov, size_t count,
		      uet_mr_handle_t mr_handle,
		      uet_addr_handle_t dst_addr_handle, uint64_t *imm_data,
		      void *context, uint16_t resource_index)
{
	return (uet_send_req_api_common(
			UET_SEND_API, ep_handle, job_id, iov, count, mr_handle,
			dst_addr_handle, UET_NO_TAG, imm_data,
			UET_NO_REMOTE_MEM_ADDR, UET_NO_REMOTE_KEY,
			NULL, context, resource_index, NULL, 0));
}
#endif /* ENABLE_VERBS */

#if !ENABLE_VERBS
ssize_t uet_tsendv(
	uet_ep_handle_t ep_handle, uint32_t job_id, const struct iovec *iov,
	size_t count, uet_mr_handle_t mr_handle,
	uet_addr_handle_t dst_addr_handle, uint64_t tag, void *context)
{
	return (uet_send_req_api_common(
			UET_TSEND_API, ep_handle, job_id, iov, count, mr_handle,
			dst_addr_handle, tag, UET_NO_IMM_DATA,
			UET_NO_REMOTE_MEM_ADDR, UET_NO_REMOTE_KEY,
			NULL, context, NULL, 0));
}
#endif

ssize_t uet_trecv(uet_ep_handle_t ep_handle, uint32_t job_id,
		  void *buf, size_t len, uet_mr_handle_t mr_handle,
		  uet_addr_handle_t src_addr_handle, uint64_t tag,
		  uint64_t ignore, void *context)
{
	struct iovec iov;

	iov.iov_base = (void *) buf;
	iov.iov_len = len;

	return (uet_recv_api_common(UET_TRECV_API, ep_handle, job_id, &iov, 1,
				    mr_handle, src_addr_handle, tag, ignore,
				    context, NULL, 0));
}

#if !ENABLE_VERBS
ssize_t uet_tsend(uet_ep_handle_t ep_handle, uint32_t job_id,
		  void *buf, size_t len, uet_mr_handle_t mr_handle,
		  uet_addr_handle_t dst_addr_handle, uint64_t tag,
		  void *context)
{
	struct iovec iov;

	iov.iov_base = (void *) buf;
	iov.iov_len = len;

	return (uet_send_req_api_common(
			UET_TSEND_API, ep_handle, job_id, &iov, 1, mr_handle,
			dst_addr_handle, tag, UET_NO_IMM_DATA,
			UET_NO_REMOTE_MEM_ADDR, UET_NO_REMOTE_KEY,
			NULL, context, NULL, 0));
}
#endif

uint64_t uet_mr_format_key(uint64_t rkey, bool idempotent_safe)
{
	uint64_t formatted_key;

	if (rkey > UET_MR_KEY_MAX_RKEY)
		return FI_KEY_NOTAVAIL;

	if (rkey > UET_MR_KEY_OPTIMIZED_MAX_RKEY)
		formatted_key = (rkey << UET_MR_KEY_RKEY_SHIFT);
	else
		formatted_key = (UET_MR_KEY_OPTIMIZED |
				 (rkey << UET_MR_KEY_OPTIMIZED_RKEY_SHIFT));

	if (idempotent_safe)
		formatted_key |= UET_MR_KEY_IDEMPOTENT_SAFE;

	return formatted_key;
}

int uet_mr_reg(uet_domain_handle_t domain_handle, const void *buf, size_t len,
	       uint64_t access, uint64_t requested_key, uint64_t flags,
	       void *context, uet_mr_handle_t *mr_handle)
{
	struct iovec iov;

	iov.iov_base = (void *)buf;
	iov.iov_len = len;
	return uet_mr_regv(domain_handle, &iov, 1, access, requested_key,
			   flags, context, mr_handle);
}

/* log2 of a power-of-two page size */
static unsigned int uet_log2(uint32_t v)
{
	unsigned int n = 0;

	while ((v >>= 1) != 0)
		n++;

	return n;
}

/*
 * allocate a memory region key and descriptor index
 *
 * Shared by every registration entry point, the key spaces and the
 * descriptor index are independent of how the region's memory is
 * described.
 */
static int uet_mr_alloc_key(struct uet_domain *uet_dom, uint64_t requested_key,
			    uint64_t flags, uint64_t *out_key,
			    uint64_t *out_rkey, size_t *out_mr_index)
{
	int rc;
	uint64_t key, rkey;
	bool desc_allocated;
	size_t mr_index;

	/*
	 * The provider maintains two independent memory-region lookup spaces:
	 * - provider-assigned keys are resolved via the index space and carry
	 *   the VENDOR_SPECIFIC provider-space marker so the receiver selects
	 *   the index lookup
	 * - user-assigned keys (UET_MR_FLAG_USER_KEY) are resolved via the
	 *   hash space and MUST have VENDOR_SPECIFIC == 0
	 */
	key = requested_key & UET_MR_KEY_IDEMPOTENT_SAFE;
	if (!(flags & UET_MR_FLAG_USER_KEY)) {
		desc_allocated = false;
		if (requested_key & UET_MR_KEY_OPTIMIZED) {
			if (uet_alloc_opt_mr_desc(uet_dom, &mr_index) ==
			    FI_SUCCESS) {
				desc_allocated = true;
				key |= (UET_MR_KEY_OPTIMIZED |
					(mr_index <<
					 UET_MR_KEY_OPTIMIZED_RKEY_SHIFT));
			}
		}
		if (!desc_allocated) {
			rc = uet_alloc_mr_desc(uet_dom, &mr_index);
			if (rc != FI_SUCCESS)
				return rc;
			key |= (mr_index << UET_MR_KEY_RKEY_SHIFT);
		}
		key |= UET_MR_KEY_VENDOR_PROV_SPACE;
		rkey = mr_index;
	} else {
		/*
		 * User-assigned keys: VENDOR_SPECIFIC MUST be 0. Both the
		 * standard and optimized formats are supported and the
		 * requested RKEY/INDEX is preserved verbatim and resolved
		 * via the hash space.
		 */
		if (requested_key & UET_MR_KEY_VENDOR) {
			UET_API_ERR(
			"user-assigned key must have VENDOR_SPECIFIC == 0");
			return -FI_EINVAL;
		}

		if (requested_key & UET_MR_KEY_OPTIMIZED) {
			rkey = (requested_key &
				UET_MR_KEY_OPTIMIZED_RKEY_MASK) >>
				UET_MR_KEY_OPTIMIZED_RKEY_SHIFT;
			if (rkey > UET_MR_KEY_OPTIMIZED_MAX_RKEY) {
				UET_API_ERR(
				"Requested key too large for optimized format");
				return -FI_EINVAL;
			}
			key |= (UET_MR_KEY_OPTIMIZED |
				(rkey << UET_MR_KEY_OPTIMIZED_RKEY_SHIFT));
		} else {
			rkey = (requested_key & UET_MR_KEY_RKEY_MASK) >>
				UET_MR_KEY_RKEY_SHIFT;
			if (rkey > UET_MR_KEY_MAX_RKEY) {
				UET_API_ERR("Requested key too large");
				return -FI_EINVAL;
			}
			key |= rkey << UET_MR_KEY_RKEY_SHIFT;
		}
		rc = uet_alloc_mr_desc(uet_dom, &mr_index);
		if (rc != FI_SUCCESS)
			return rc;
	}

	*out_key = key;
	*out_rkey = rkey;
	*out_mr_index = mr_index;
	return FI_SUCCESS;
}

int uet_mr_reg_pbl(uet_domain_handle_t domain_handle, uet_dma_addr_t pbl_root,
		   uint32_t page_size, uet_pbl_level_t level,
		   uint32_t page_offset, uint64_t base_va, size_t len,
		   uint64_t access, uint64_t requested_key, uint64_t flags,
		   void *context, uet_mr_handle_t *mr_handle)
{
	int rc;
	uint64_t key, rkey;
	size_t mr_index;
	struct uet_domain *uet_dom;
	struct uet_mr_desc *mr_desc;

	uet_dom = (struct uet_domain *)domain_handle;

	/* a page size must be a non-zero power of two */
	if ((page_size == 0) || ((page_size & (page_size - 1)) != 0)) {
		UET_API_ERR("PBL page size must be a power of 2");
		return -FI_EINVAL;
	}

	if (page_offset >= page_size) {
		UET_API_ERR("PBL page offset must be within the first page");
		return -FI_EINVAL;
	}

	switch (level) {
	case UET_PBL_LEVEL_0:
	case UET_PBL_LEVEL_1:
	case UET_PBL_LEVEL_2:
		break;
	default:
		UET_API_ERR("Invalid PBL level");
		return -FI_EINVAL;
	}

	rc = uet_mr_alloc_key(uet_dom, requested_key, flags, &key, &rkey,
			      &mr_index);
	if (rc != FI_SUCCESS)
		return rc;

	mr_desc = &uet_dom->mr_desc[mr_index];
	memset(mr_desc, 0, sizeof(struct uet_mr_desc));
	mr_desc->state = UET_MR_DESC_STATE_DISABLED_REG;
	mr_desc->uet_dom = uet_dom;

	/*
	 * buf stays NULL: a page list has no single base address. len is the
	 * region's length in its flattened address space, which every bounds
	 * check in the rma paths already tests against.
	 */
	mr_desc->buf_desc.type = UET_MR_BUF_TYPE_PBL;
	mr_desc->buf_desc.len = len;
	mr_desc->buf_desc.pbl.root = pbl_root;
	mr_desc->buf_desc.pbl.page_size = page_size;
	mr_desc->buf_desc.pbl.page_offset = page_offset;
	mr_desc->buf_desc.pbl.page_shift = (uint8_t)uet_log2(page_size);
	mr_desc->buf_desc.pbl.level = level;

	mr_desc->access = access;
	mr_desc->flags = flags;
	mr_desc->context = context;
	mr_desc->full_key = key;
	mr_desc->hash_key.rkey = rkey;
	mr_desc->user_key = !!(flags & UET_MR_FLAG_USER_KEY);
	mr_desc->base_va = base_va;

	*mr_handle = mr_desc;

	return FI_SUCCESS;
}

int uet_mr_regv(uet_domain_handle_t domain_handle, const struct iovec *iov,
		size_t iov_count, uint64_t access, uint64_t requested_key,
		uint64_t flags, void *context, uet_mr_handle_t *mr_handle)
{
	int rc;
	uint64_t key, rkey;
	size_t mr_index, tot_len = 0;
	struct uet_domain *uet_dom;
	struct uet_mr_desc *mr_desc;
	struct iovec *iov_handle = NULL;

	uet_dom = (struct uet_domain *)domain_handle;

	rc = uet_mr_alloc_key(uet_dom, requested_key, flags, &key, &rkey,
			      &mr_index);
	if (rc != FI_SUCCESS)
		return rc;

	for (int i = 0; i < iov_count; i++)
		tot_len += iov[i].iov_len;

	/* Only a multi-entry region needs a private copy of the vector; a
	 * single-entry region is recorded as a contiguous buffer and keeps
	 * no vector at all
	 */
	if (iov_count > 1) {
		iov_handle = calloc(iov_count, sizeof(struct iovec));
		if (iov_handle == NULL) {
			uet_dealloc_mr_desc(uet_dom,
					    &uet_dom->mr_desc[mr_index]);
			return -FI_ENOMEM;
		}

		for (int i = 0; i < iov_count; i++)
			iov_handle[i] = iov[i];
	}

	/* init memory region descriptor */
	mr_desc = &uet_dom->mr_desc[mr_index];
	memset(mr_desc, 0, sizeof(struct uet_mr_desc));
	mr_desc->state = UET_MR_DESC_STATE_DISABLED_REG;
	mr_desc->uet_dom = uet_dom;
	if (iov_count == 1) {
		mr_desc->buf_desc.type = UET_MR_BUF_TYPE_CONTIG;
		mr_desc->buf_desc.buf = iov->iov_base;
		mr_desc->buf_desc.len = iov->iov_len;
	} else {
		mr_desc->buf_desc.type = UET_MR_BUF_TYPE_IOV;
		mr_desc->buf_desc.len = tot_len;
		mr_desc->buf_desc.iov.iov = iov_handle;
		mr_desc->buf_desc.iov.iov_count = iov_count;
	}
	mr_desc->access = access;
	mr_desc->flags = flags;
	mr_desc->context = context;
	mr_desc->full_key = key;
	mr_desc->hash_key.rkey = rkey;
	mr_desc->user_key = !!(flags & UET_MR_FLAG_USER_KEY);

	/* zero-based: addresses naming this region are offsets */
	mr_desc->base_va = 0;

	*mr_handle = mr_desc;

	return FI_SUCCESS;
}

/*
 * Register a derived memory region that is wholly contained within an
 * existing (parent) region. A derived region shares the parent's domain
 * and may carry different access rights. This reference implementation
 * registers the sub-range as an independent region. A vendor may instead
 * share the parent's page mappings (derived regions are an optional
 * optimization).
 */
int uet_mr_derive(uet_domain_handle_t domain_handle,
		  uet_mr_handle_t parent_mr_handle,
		  const void *buf, size_t len, uint64_t access,
		  uint64_t requested_key, uint64_t flags,
		  uint32_t job_id, bool job_restricted,
		  void *context, uet_mr_handle_t *mr_handle)
{
	struct uet_mr_desc *parent = (struct uet_mr_desc *) parent_mr_handle;
	const uint8_t *pbase, *cbase;

	if ((parent == NULL) ||
	    (parent->buf_desc.type != UET_MR_BUF_TYPE_CONTIG)) {
		UET_API_ERR("derived MR parent must be a contiguous region");
		return -FI_EINVAL;
	}

	pbase = parent->buf_desc.buf;
	cbase = buf;

	if ((cbase < pbase) ||
	    ((cbase + len) > (pbase + parent->buf_desc.len))) {
		UET_API_ERR("derived MR must be contained in the parent region");
		return -FI_EINVAL;
	}

	/* A derived MR is a normal registration of a sub-range contained in
	 * the parent. The requested key, user-key flag, and job restriction
	 * all still apply. Route through the job-restricted path when asked.
	 */
	if (job_restricted)
		return uet_mr_reg_job(domain_handle, buf, len, access,
				      requested_key, flags, job_id, context,
				      mr_handle);

	return uet_mr_reg(domain_handle, buf, len, access, requested_key,
			  flags, context, mr_handle);
}

/*
 * Register a memory region restricted to a specific JobID. Only incoming
 * requests within that job are allowed to access the region.
 */
int uet_mr_reg_job(uet_domain_handle_t domain_handle, const void *buf,
		   size_t len, uint64_t access, uint64_t requested_key,
		   uint64_t flags, uint32_t job_id, void *context,
		   uet_mr_handle_t *mr_handle)
{
	int rc;

	rc = uet_mr_reg(domain_handle, buf, len, access, requested_key,
			flags, context, mr_handle);
	if (rc == FI_SUCCESS) {
		struct uet_mr_desc *mr_desc = (struct uet_mr_desc *) *mr_handle;

		mr_desc->job_id = job_id;
		mr_desc->job_restricted = true;
	}

	return rc;
}

uint64_t uet_mr_key(uet_mr_handle_t mr_handle)
{
	struct uet_mr_desc *mr_desc;

	mr_desc = (struct uet_mr_desc *) mr_handle;

	if (mr_desc->state == UET_MR_DESC_STATE_INACTIVE)
		return FI_KEY_NOTAVAIL;

	return mr_desc->full_key;
}

int uet_ep_bind_mr(uet_ep_handle_t ep_handle,
		   uet_mr_handle_t mr_handle, uint64_t flags)
{
	struct uet_ep *uet_ep;
	struct uet_mr_desc *mr_desc;

	uet_ep = (struct uet_ep *) ep_handle;
	mr_desc = (struct uet_mr_desc *) mr_handle;

	if (mr_desc->state != UET_MR_DESC_STATE_DISABLED_REG) {
		UET_API_ERR("Bad MR state for EP bind");
		return -FI_EINVAL;
	}

	mr_desc->state = UET_MR_DESC_STATE_DISABLED_BIND;
	mr_desc->uet_ep = uet_ep;

	return FI_SUCCESS;
}

int uet_mr_enable(uet_mr_handle_t mr_handle)
{
	int rc;
	struct uet_mr_desc *mr_desc;

	mr_desc = (struct uet_mr_desc *) mr_handle;

	if (mr_desc->state != UET_MR_DESC_STATE_DISABLED_BIND) {
		UET_API_ERR("Bad MR state for enable");
		return -FI_EINVAL;
	}

	switch (mr_desc->buf_desc.type) {
	case UET_MR_BUF_TYPE_CONTIG:
		mr_desc->buf_desc.contig.dma_addr =
			(uet_dma_addr_t)mr_desc->buf_desc.buf;
		break;

	case UET_MR_BUF_TYPE_IOV:
	case UET_MR_BUF_TYPE_PBL:
		/* A scattered region has no single base address, so
		 * buf_desc.buf stays NULL and every consumer must branch on
		 * buf_desc.type rather than dereference it. Per-entry
		 * addresses live in buf_desc.iov or buf_desc.pbl.
		 */
		break;

	default:
		UET_API_ERR("MR reg only supported for contiguous and iov "
			    "buf types");
		return -FI_EINVAL;
	}

	/*
	 * Insert into the lookup space that matches the key's origin: user
	 * keys use the per-endpoint hash table, provider keys use the index
	 * space (tracked on a list for enumeration/cleanup).
	 */
	if (mr_desc->user_key)
		uet_mr_hash_insert(mr_desc->uet_ep, mr_desc);
	else
		uet_mr_list_insert(mr_desc);

	mr_desc->state = UET_MR_DESC_STATE_ENABLED;

	if (mr_desc->uet_ep->untagged_gen_disabled) {
		/* re-enable generation */
		mr_desc->uet_ep->untagged_gen++;
		mr_desc->uet_ep->untagged_gen_disabled = false;
	}

	return FI_SUCCESS;
}

int uet_mr_close(uet_mr_handle_t mr_handle)
{
	struct uet_mr_desc *mr_desc;

	mr_desc = (struct uet_mr_desc *) mr_handle;

	switch (mr_desc->state) {
	case UET_MR_DESC_STATE_INACTIVE:
		UET_API_ERR("Can not close unregistered MR");
		return -FI_EINVAL;
	case UET_MR_DESC_STATE_DISABLED_BIND:
		/* Binding is a control-plane association and has no outstanding
		 * dataplane state until enable. Permit normal libfabric cleanup of
		 * a registered-and-bound MR that was never enabled.
		 */
		mr_desc->uet_ep = NULL;
		break;
	case UET_MR_DESC_STATE_ENABLED:
		UET_API_ERR("Can not close MR that is bound to EP");
		return -FI_EINVAL;
	default:
		break;
	}

	uet_dealloc_mr_desc(mr_desc->uet_dom, mr_desc);

	return FI_SUCCESS;
}

#if !ENABLE_VERBS
ssize_t uet_write(uet_ep_handle_t ep_handle, uint32_t job_id, void *buf,
		  size_t len, uint64_t *data, uet_mr_handle_t mr_handle,
		  uet_addr_handle_t dst_addr_handle,
		  uint64_t remote_mem_addr, uint64_t remote_key,
		  void *context)
{
	struct iovec iov;

	iov.iov_base = (void *) buf;
	iov.iov_len = len;

	return (uet_send_req_api_common(
			UET_WRITE_API, ep_handle, job_id, &iov, 1, mr_handle,
			dst_addr_handle, UET_NO_TAG, data, remote_mem_addr,
			remote_key, NULL, context, NULL, 0));
}

ssize_t uet_write_sync(uet_ep_handle_t ep_handle, uint32_t job_id, void *buf,
		       size_t len, uint64_t *data, uet_mr_handle_t mr_handle,
		       uet_addr_handle_t dst_addr_handle,
		       uint64_t remote_mem_addr, uint64_t remote_key,
		       void *context)
{
	struct iovec iov;

	iov.iov_base = (void *) buf;
	iov.iov_len = len;

	return (uet_send_req_api_common(
			UET_WRITE_SYNC_API, ep_handle, job_id, &iov, 1,
			mr_handle, dst_addr_handle, UET_NO_TAG, data,
			remote_mem_addr, remote_key, NULL, context, NULL, 0));
}

ssize_t uet_read(uet_ep_handle_t ep_handle, uint32_t job_id, void *buf,
		 size_t len, uet_mr_handle_t mr_handle,
		 uet_addr_handle_t uet_addr_handle,
		 uint64_t remote_mem_addr, uint64_t remote_key, void *context)
{
	struct iovec iov;

	iov.iov_base = (void *) buf;
	iov.iov_len = len;

	return (uet_send_req_api_common(
			UET_READ_API, ep_handle, job_id, &iov, 1, mr_handle,
			uet_addr_handle, UET_NO_TAG, UET_NO_IMM_DATA,
			remote_mem_addr, remote_key, NULL, context, NULL, 0));
}

#else
ssize_t uet_write(uet_ep_handle_t ep_handle, uint32_t job_id, void *buf,
		  size_t len, uint64_t *data, uet_mr_handle_t mr_handle,
		  uet_addr_handle_t dst_addr_handle,
		  uint64_t remote_mem_addr, uint64_t remote_key,
		  void *context, uint16_t resource_index)
{
	struct iovec iov;

	iov.iov_base = (void *) buf;
	iov.iov_len = len;

	return (uet_send_req_api_common(
			UET_WRITE_API, ep_handle, job_id, &iov, 1, mr_handle,
			dst_addr_handle, UET_NO_TAG, data, remote_mem_addr,
			remote_key, NULL, context, resource_index, NULL, 0));
}

ssize_t uet_write_sync(uet_ep_handle_t ep_handle, uint32_t job_id, void *buf,
		       size_t len, uint64_t *data, uet_mr_handle_t mr_handle,
		       uet_addr_handle_t dst_addr_handle,
		       uint64_t remote_mem_addr, uint64_t remote_key,
		       void *context, uint16_t resource_index)
{
	struct iovec iov;

	iov.iov_base = (void *) buf;
	iov.iov_len = len;

	return (uet_send_req_api_common(
			UET_WRITE_SYNC_API, ep_handle, job_id, &iov, 1,
			mr_handle, dst_addr_handle, UET_NO_TAG, data,
			remote_mem_addr, remote_key, NULL, context,
			resource_index, NULL, 0));
}

ssize_t uet_read(uet_ep_handle_t ep_handle, uint32_t job_id, void *buf,
		 size_t len, uet_mr_handle_t mr_handle,
		 uet_addr_handle_t uet_addr_handle,
		 uint64_t remote_mem_addr, uint64_t remote_key, void *context,
		 uint16_t resource_index)
{
	struct iovec iov;

	iov.iov_base = (void *) buf;
	iov.iov_len = len;

	return (uet_send_req_api_common(
			UET_READ_API, ep_handle, job_id, &iov, 1, mr_handle,
			uet_addr_handle, UET_NO_TAG, UET_NO_IMM_DATA,
			remote_mem_addr, remote_key, NULL, context,
			resource_index, NULL, 0));
}

ssize_t uet_writev(uet_ep_handle_t ep_handle, uint32_t job_id,
		   const struct iovec *iov, size_t count, uint64_t *data,
		   uet_mr_handle_t mr_handle, uet_addr_handle_t dst_addr_handle,
		   uint64_t remote_mem_addr, uint64_t remote_key,
		   void *context, uint16_t resource_index)
{
	return (uet_send_req_api_common(
			UET_WRITE_API, ep_handle, job_id, iov, count, mr_handle,
			dst_addr_handle, UET_NO_TAG, data, remote_mem_addr,
			remote_key, NULL, context, resource_index, NULL, 0));
}

ssize_t uet_readv(uet_ep_handle_t ep_handle, uint32_t job_id,
		  const struct iovec *iov, size_t count,
		  uet_mr_handle_t mr_handle, uet_addr_handle_t uet_addr_handle,
		  uint64_t remote_mem_addr, uint64_t remote_key,
		  void *context, uint16_t resource_index)
{
	return (uet_send_req_api_common(
			UET_READ_API, ep_handle, job_id, iov, count, mr_handle,
			uet_addr_handle, UET_NO_TAG, UET_NO_IMM_DATA,
			remote_mem_addr, remote_key, NULL, context,
			resource_index, NULL, 0));
}
#endif /* ENABLE_VERBS */

/*
 * Segment-list variants. The local buffer is described by memory regions
 * rather than by addresses in this process, everything else matches the
 * corresponding iov form.
 */
#if !ENABLE_VERBS
ssize_t uet_sendseg(uet_ep_handle_t ep_handle, uint32_t job_id,
		    const struct uet_mr_seg *seg, size_t seg_count,
		    uet_addr_handle_t dst_addr_handle, void *context)
{
	return (uet_send_req_api_common(
			UET_SEND_API, ep_handle, job_id, NULL, 0, NULL,
			dst_addr_handle, UET_NO_TAG, UET_NO_IMM_DATA,
			UET_NO_REMOTE_MEM_ADDR, UET_NO_REMOTE_KEY,
			NULL, context, seg, seg_count));
}

ssize_t uet_sendseg_imm(uet_ep_handle_t ep_handle, uint32_t job_id,
			const struct uet_mr_seg *seg, size_t seg_count,
			uint64_t *data, uet_addr_handle_t dst_addr_handle,
			void *context)
{
	return (uet_send_req_api_common(
			UET_SEND_API, ep_handle, job_id, NULL, 0, NULL,
			dst_addr_handle, UET_NO_TAG, data,
			UET_NO_REMOTE_MEM_ADDR, UET_NO_REMOTE_KEY,
			NULL, context, seg, seg_count));
}

ssize_t uet_writeseg(uet_ep_handle_t ep_handle, uint32_t job_id,
		     const struct uet_mr_seg *seg, size_t seg_count,
		     uint64_t *data, uet_addr_handle_t dst_addr_handle,
		     uint64_t remote_mem_addr, uint64_t remote_key,
		     void *context)
{
	return (uet_send_req_api_common(
			UET_WRITE_API, ep_handle, job_id, NULL, 0, NULL,
			dst_addr_handle, UET_NO_TAG, data, remote_mem_addr,
			remote_key, NULL, context, seg, seg_count));
}

ssize_t uet_readseg(uet_ep_handle_t ep_handle, uint32_t job_id,
		    const struct uet_mr_seg *seg, size_t seg_count,
		    uet_addr_handle_t uet_addr_handle,
		    uint64_t remote_mem_addr, uint64_t remote_key,
		    void *context)
{
	return (uet_send_req_api_common(
			UET_READ_API, ep_handle, job_id, NULL, 0, NULL,
			uet_addr_handle, UET_NO_TAG, UET_NO_IMM_DATA,
			remote_mem_addr, remote_key, NULL, context,
			seg, seg_count));
}
#else
ssize_t uet_sendseg(uet_ep_handle_t ep_handle, uint32_t job_id,
		    const struct uet_mr_seg *seg, size_t seg_count,
		    uet_addr_handle_t dst_addr_handle, void *context,
		    uint16_t resource_index)
{
	return (uet_send_req_api_common(
			UET_SEND_API, ep_handle, job_id, NULL, 0, NULL,
			dst_addr_handle, UET_NO_TAG, UET_NO_IMM_DATA,
			UET_NO_REMOTE_MEM_ADDR, UET_NO_REMOTE_KEY,
			NULL, context, resource_index, seg, seg_count));
}

ssize_t uet_sendseg_imm(uet_ep_handle_t ep_handle, uint32_t job_id,
			const struct uet_mr_seg *seg, size_t seg_count,
			uint64_t *data, uet_addr_handle_t dst_addr_handle,
			void *context, uint16_t resource_index)
{
	return (uet_send_req_api_common(
			UET_SEND_API, ep_handle, job_id, NULL, 0, NULL,
			dst_addr_handle, UET_NO_TAG, data,
			UET_NO_REMOTE_MEM_ADDR, UET_NO_REMOTE_KEY,
			NULL, context, resource_index, seg, seg_count));
}

ssize_t uet_writeseg(uet_ep_handle_t ep_handle, uint32_t job_id,
		     const struct uet_mr_seg *seg, size_t seg_count,
		     uint64_t *data, uet_addr_handle_t dst_addr_handle,
		     uint64_t remote_mem_addr, uint64_t remote_key,
		     void *context, uint16_t resource_index)
{
	return (uet_send_req_api_common(
			UET_WRITE_API, ep_handle, job_id, NULL, 0, NULL,
			dst_addr_handle, UET_NO_TAG, data, remote_mem_addr,
			remote_key, NULL, context, resource_index,
			seg, seg_count));
}

ssize_t uet_readseg(uet_ep_handle_t ep_handle, uint32_t job_id,
		    const struct uet_mr_seg *seg, size_t seg_count,
		    uet_addr_handle_t uet_addr_handle,
		    uint64_t remote_mem_addr, uint64_t remote_key,
		    void *context, uint16_t resource_index)
{
	return (uet_send_req_api_common(
			UET_READ_API, ep_handle, job_id, NULL, 0, NULL,
			uet_addr_handle, UET_NO_TAG, UET_NO_IMM_DATA,
			remote_mem_addr, remote_key, NULL, context,
			resource_index, seg, seg_count));
}
#endif /* ENABLE_VERBS */

ssize_t uet_recvseg(uet_ep_handle_t ep_handle, uint32_t job_id,
		    const struct uet_mr_seg *seg, size_t seg_count,
		    uet_addr_handle_t src_addr_handle, void *context)
{
	return (uet_recv_api_common(UET_RECV_API, ep_handle, job_id, NULL, 0,
				    NULL, src_addr_handle, UET_NO_TAG,
				    UET_NO_IGNORE_BITS, context,
				    seg, seg_count));
}

int uet_query_atomic(uet_domain_handle_t domain_handle,
		     enum fi_datatype datatype, enum fi_op op,
		     struct fi_atomic_attr *attr, uint64_t flags)
{
	bool valid = false;

	if ((datatype == FI_UINT64) && (op == FI_SUM) &&
	    ((flags == FI_ATOMIC) || (flags == FI_FETCH_ATOMIC)))
		valid = true;

	if ((datatype == FI_UINT64) && (op == FI_CSWAP) &&
	    (flags == FI_COMPARE_ATOMIC))
		valid = true;

	if (!valid)
		return -FI_EOPNOTSUPP;

	attr->count = 1;
	attr->size = sizeof(uint64_t);

	return FI_SUCCESS;
}

/* convert libfabric atomic datatype to uet atomic datatype */
static uint8_t uet_atomic_datatype(enum fi_datatype datatype)
{
	return UET_TYPE_UINT64;
}

/* convert libfabric atomic op to uet atomic opcode */
static uint8_t uet_atomic_opcode(enum fi_op op)
{
	if (op == FI_SUM)
		return UET_AMO_SUM;
	return UET_AMO_CSWAP;
}

static int uet_atomic_common(uet_ep_handle_t ep_handle,
			     const void *local_op_buf, size_t count,
		             uet_mr_handle_t op_mr_handle,
		             const void *compare_buf,
		             uet_mr_handle_t compare_mr_handle,
		             void *result_buf,
		             uet_mr_handle_t result_mr_handle,
		             enum fi_datatype datatype,
		             enum fi_op op, uint64_t query_flags,
			     struct iovec *iov,
		             struct uet_atomic_parms *parms)
{
	int rc;
	uet_domain_handle_t domain_handle;
	struct uet_ep *uet_ep;
	struct fi_atomic_attr attr;

	uet_ep = (struct uet_ep *) ep_handle;
        domain_handle = (uet_domain_handle_t) uet_ep->uet_domain;

	if (count != 1)
		return -FI_EOPNOTSUPP;

	rc = uet_query_atomic(domain_handle, datatype, op,
			      &attr, query_flags);

	if (rc)
		return rc;

	if (count > attr.count)
		return -FI_EMSGSIZE;

	iov->iov_base = (void *) local_op_buf;
	iov->iov_len = attr.size;

	parms->opcode = uet_atomic_opcode(op);
	parms->data_type = uet_atomic_datatype(datatype);
	parms->data_size = attr.size;
	parms->compare_buf = compare_buf;
	parms->result_buf = result_buf;

	return FI_SUCCESS;
}

#if !ENABLE_VERBS
ssize_t uet_atomic(uet_ep_handle_t ep_handle, uint32_t job_id,
		   const void *local_op_buf, size_t count,
		   uet_mr_handle_t mr_handle,
		   uet_addr_handle_t dst_addr_handle,
		   uint64_t remote_mem_addr, uint64_t remote_key,
		   enum fi_datatype datatype, enum fi_op op,
		   void *context)
{
        int rc;
        struct iovec iov;
        struct uet_atomic_parms parms;

        rc = uet_atomic_common(ep_handle, local_op_buf, count,
                               mr_handle, NULL, UET_NULL_HANDLE,
                               NULL, UET_NULL_HANDLE, datatype,
                               op, FI_ATOMIC, &iov, &parms);

        if (rc)
                return rc;

        return (uet_send_req_api_common(
                        UET_ATOMIC_API, ep_handle, job_id, &iov, 1,
                        mr_handle, dst_addr_handle, UET_NO_TAG,
                        UET_NO_IMM_DATA, remote_mem_addr, remote_key,
                        &parms, context, NULL, 0));
}
#else
ssize_t uet_atomic(uet_ep_handle_t ep_handle, uint32_t job_id,
		   const void *local_op_buf, size_t count,
		   uet_mr_handle_t mr_handle,
		   uet_addr_handle_t dst_addr_handle,
		   uint64_t remote_mem_addr, uint64_t remote_key,
		   enum fi_datatype datatype, enum fi_op op,
		   void *context, uint16_t resource_index)
{
        int rc;
        struct iovec iov;
        struct uet_atomic_parms parms;

        rc = uet_atomic_common(ep_handle, local_op_buf, count,
                               mr_handle, NULL, UET_NULL_HANDLE,
                               NULL, UET_NULL_HANDLE, datatype,
                               op, FI_ATOMIC, &iov, &parms);

        if (rc)
                return rc;

        return (uet_send_req_api_common(
                        UET_ATOMIC_API, ep_handle, job_id, &iov, 1,
                        mr_handle, dst_addr_handle, UET_NO_TAG,
                        UET_NO_IMM_DATA, remote_mem_addr, remote_key,
                        &parms, context, resource_index, NULL, 0));
}
#endif

#if !ENABLE_VERBS
ssize_t uet_atomic_sync(uet_ep_handle_t ep_handle, uint32_t job_id,
			const void *local_op_buf, size_t count,
			uet_mr_handle_t mr_handle,
			uet_addr_handle_t dst_addr_handle,
			uint64_t remote_mem_addr, uint64_t remote_key,
			enum fi_datatype datatype, enum fi_op op,
			void *context)
{
	int rc;
	struct iovec iov;
	struct uet_atomic_parms parms;

	rc = uet_atomic_common(ep_handle, local_op_buf, count,
			       mr_handle, NULL, UET_NULL_HANDLE,
			       NULL, UET_NULL_HANDLE, datatype,
			       op, FI_ATOMIC, &iov, &parms);

	if (rc)
		return rc;

	return (uet_send_req_api_common(
			UET_ATOMIC_SYNC_API, ep_handle, job_id, &iov, 1,
			mr_handle, dst_addr_handle, UET_NO_TAG,
			UET_NO_IMM_DATA, remote_mem_addr, remote_key,
			&parms, context, NULL, 0));
}
#else
ssize_t uet_atomic_sync(uet_ep_handle_t ep_handle, uint32_t job_id,
			const void *local_op_buf, size_t count,
			uet_mr_handle_t mr_handle,
			uet_addr_handle_t dst_addr_handle,
			uint64_t remote_mem_addr, uint64_t remote_key,
			enum fi_datatype datatype, enum fi_op op,
			void *context, uint16_t resource_index)
{
	int rc;
	struct iovec iov;
	struct uet_atomic_parms parms;

	rc = uet_atomic_common(ep_handle, local_op_buf, count,
			       mr_handle, NULL, UET_NULL_HANDLE,
			       NULL, UET_NULL_HANDLE, datatype,
			       op, FI_ATOMIC, &iov, &parms);

	if (rc)
		return rc;

	return (uet_send_req_api_common(
			UET_ATOMIC_SYNC_API, ep_handle, job_id, &iov, 1,
			mr_handle, dst_addr_handle, UET_NO_TAG,
			UET_NO_IMM_DATA, remote_mem_addr, remote_key,
			&parms, context, resource_index, NULL, 0));
}
#endif

#if !ENABLE_VERBS
ssize_t uet_fetch_atomic(uet_ep_handle_t ep_handle, uint32_t job_id,
			 const void *local_op_buf,
			 size_t count, uet_mr_handle_t op_mr_handle,
			 void *result_buf,
			 uet_mr_handle_t result_mr_handle,
			 uet_addr_handle_t dst_addr_handle,
			 uint64_t remote_mem_addr,
			 uint64_t remote_key,
			 enum fi_datatype datatype, enum fi_op op,
			 void *context)
{
	int rc;
	struct iovec iov;
	struct uet_atomic_parms parms;

	rc = uet_atomic_common(ep_handle, local_op_buf, count,
		               op_mr_handle, NULL, UET_NULL_HANDLE,
		               result_buf, result_mr_handle, datatype,
		               op, FI_FETCH_ATOMIC, &iov, &parms);

	if (rc)
		return rc;

	return (uet_send_req_api_common(
			UET_FETCH_ATOMIC_API, ep_handle, job_id, &iov, 1,
			op_mr_handle, dst_addr_handle, UET_NO_TAG,
			UET_NO_IMM_DATA, remote_mem_addr, remote_key,
			&parms, context, NULL, 0));
}
#else
ssize_t uet_fetch_atomic(uet_ep_handle_t ep_handle, uint32_t job_id,
			 const void *local_op_buf,
			 size_t count, uet_mr_handle_t op_mr_handle,
			 void *result_buf,
			 uet_mr_handle_t result_mr_handle,
			 uet_addr_handle_t dst_addr_handle,
			 uint64_t remote_mem_addr,
			 uint64_t remote_key,
			 enum fi_datatype datatype, enum fi_op op,
			 void *context, uint16_t resource_index)
{
	int rc;
	struct iovec iov;
	struct uet_atomic_parms parms;

	rc = uet_atomic_common(ep_handle, local_op_buf, count,
		               op_mr_handle, NULL, UET_NULL_HANDLE,
		               result_buf, result_mr_handle, datatype,
		               op, FI_FETCH_ATOMIC, &iov, &parms);

	if (rc)
		return rc;


	return (uet_send_req_api_common(
			UET_FETCH_ATOMIC_API, ep_handle, job_id, &iov, 1,
			op_mr_handle, dst_addr_handle, UET_NO_TAG,
			UET_NO_IMM_DATA, remote_mem_addr, remote_key,
			&parms, context, resource_index, NULL, 0));
}
#endif /* ENABLE_VERBS */

#if !ENABLE_VERBS
ssize_t uet_compare_atomic(uet_ep_handle_t ep_handle, uint32_t job_id,
			   const void *local_op_buf, size_t count,
			   uet_mr_handle_t op_mr_handle,
			   const void *compare_buf,
			   uet_mr_handle_t compare_mr_handle,
			   void *result_buf,
			   uet_mr_handle_t result_mr_handle,
			   uet_addr_handle_t dst_addr_handle,
			   uint64_t remote_mem_addr,
			   uint64_t remote_key,
			   enum fi_datatype datatype,
			   enum fi_op op, void *context)
{
	int rc;
	struct iovec iov;
	struct uet_atomic_parms parms;

	rc = uet_atomic_common(ep_handle, local_op_buf, count,
		               op_mr_handle, compare_buf, compare_mr_handle,
		               result_buf, result_mr_handle, datatype,
		               op, FI_COMPARE_ATOMIC, &iov, &parms);
	if (rc)
		return rc;

	return (uet_send_req_api_common(
			UET_COMPARE_ATOMIC_API, ep_handle, job_id, &iov, 1,
			op_mr_handle, dst_addr_handle, UET_NO_TAG,
			UET_NO_IMM_DATA, remote_mem_addr, remote_key,
			&parms, context, NULL, 0));
}
#else
ssize_t uet_compare_atomic(uet_ep_handle_t ep_handle, uint32_t job_id,
			   const void *local_op_buf, size_t count,
			   uet_mr_handle_t op_mr_handle,
			   const void *compare_buf,
			   uet_mr_handle_t compare_mr_handle,
			   void *result_buf,
			   uet_mr_handle_t result_mr_handle,
			   uet_addr_handle_t dst_addr_handle,
			   uint64_t remote_mem_addr,
			   uint64_t remote_key,
			   enum fi_datatype datatype, enum fi_op op,
			   void *context, uint16_t resource_index)
{
	int rc;
	struct iovec iov;
	struct uet_atomic_parms parms;

	rc = uet_atomic_common(ep_handle, local_op_buf, count,
		               op_mr_handle, compare_buf, compare_mr_handle,
		               result_buf, result_mr_handle, datatype,
		               op, FI_COMPARE_ATOMIC, &iov, &parms);

	if (rc)
		return rc;

	return (uet_send_req_api_common(
			UET_COMPARE_ATOMIC_API, ep_handle, job_id, &iov, 1,
			op_mr_handle, dst_addr_handle, UET_NO_TAG,
			UET_NO_IMM_DATA, remote_mem_addr, remote_key,
			&parms, context, resource_index, NULL, 0));
}
#endif /* ENABLE_VERBS */

/*********************************************************************
 * Below API functions have not been implemented yet
 *********************************************************************/

int uet_mr_regattr(uet_domain_handle_t domain_handle, uint32_t job_id,
		   const struct fi_mr_attr *attr, uint64_t flags,
		   uet_mr_handle_t *mr_handle)
{
	return -FI_ENOSYS;
}

int uet_mr_bind_cntr(uet_mr_handle_t mr_handle, uint64_t flags,
		     uet_cntr_handle_t *cntr_handle)
{
	struct uet_mr_desc *mr_desc = (struct uet_mr_desc *) mr_handle;

	/* A completion counter MUST NOT be bound to a memory region marked
	 * IDEMPOTENT_SAFE. RUDI keeps no target state and may deliver an
	 * idempotent op more than once, so a bound counter would over-count.
	 * Fail the bind.
	 */
	if (mr_desc && (mr_desc->full_key & UET_MR_KEY_IDEMPOTENT_SAFE))
		return -FI_EINVAL;

	return -FI_ENOSYS;
}

uint64_t uet_mr_refresh(uet_mr_handle_t mr_handle,
			const struct iovec *iov,
			size_t count, uint64_t flags)
{
	return -FI_ENOSYS;
}

int uet_scalable_ep(uet_domain_handle_t domain_handle,
		    struct fi_info *info, struct fid_ep *ep,
		    void *context, uet_ep_handle_t *sep_handle)
{
	return -FI_ENOSYS;
}

int uet_tx_context(uet_ep_handle_t sep_handle, int index,
		   struct fi_tx_attr *attr, void *context,
		   uet_ep_handle_t *tx_ep_handle)
{
	return -FI_ENOSYS;
}

int uet_rx_context(uet_ep_handle_t sep_handle, int index,
		   struct fi_rx_attr *attr, void *context,
		   uet_ep_handle_t *rx_ep_handle)
{
	return -FI_ENOSYS;
}

int uet_stx_context(uet_domain_handle_t domain_handle,
		    struct fi_tx_attr *attr,
		    void *context, uet_sctx_handle_t *stx_handle)
{
	return -FI_ENOSYS;
}

int uet_srx_context(uet_domain_handle_t domain_handle,
		    struct fi_rx_attr *attr, void *context,
		    uet_ep_handle_t *rx_ep_handle,
		    uet_sctx_handle_t *srx_handle)
{
	return -FI_ENOSYS;
}

int uet_ep_bind_sctx(uet_ep_handle_t ep_handle,
		     uet_sctx_handle_t sctx_handle)
{
	return -FI_ENOSYS;
}

int uet_ep_bind_cntr(uet_ep_handle_t ep_handle, uint64_t flags,
		     uet_cntr_handle_t *cntr_handle)
{
	return -FI_ENOSYS;
}

int uet_cancel(uet_ep_handle_t ep_handle, void *context)
{
	return -FI_ENOSYS;
}

int uet_ep_alias(uet_ep_handle_t ep_handle,
		 uet_ep_handle_t *alias_ep_handle)
{
	return -FI_ENOSYS;
}

int uet_ep_control(uet_ep_handle_t ep_handle, int command, void *arg)
{
	return -FI_ENOSYS;
}

int uet_ep_setopt(uet_ep_handle_t ep_handle, int level, int optname,
		  const void *optval, size_t optlen)
{
	return -FI_ENOSYS;
}

int uet_cntr_read(uet_cntr_handle_t cntr_handle, uint64_t *value)
{
	return -FI_ENOSYS;
}

int uet_cntr_readerr(uet_cntr_handle_t cntr_handle,
		     uint64_t *error_value)
{
	return -FI_ENOSYS;
}

int uet_cntr_add(uet_cntr_handle_t cntr_handle, uint64_t value)
{
	return -FI_ENOSYS;
}

int uet_cntr_adderr(uet_cntr_handle_t cntr_handle,
		    uint64_t error_value)
{
	return -FI_ENOSYS;
}

int uet_cntr_set(uet_cntr_handle_t cntr_handle, uint64_t value)
{
	return -FI_ENOSYS;
}

int uet_cntr_seterr(uet_cntr_handle_t cntr_handle,
		    uint64_t error_value)
{
	return -FI_ENOSYS;
}

int uet_cntr_close(uet_cntr_handle_t cntr_handle)
{
	return -FI_ENOSYS;
}

ssize_t uet_recvmsg(uet_ep_handle_t ep_handle, uint32_t job_id,
		    const struct fi_msg *msg, uint64_t flags,
		    uet_mr_handle_t *mr_handle)
{
	return -FI_ENOSYS;
}

ssize_t uet_sendmsg(uet_ep_handle_t ep_handle, uint32_t job_id,
		    const struct fi_msg *msg, uint64_t flags,
		    uet_addr_handle_t dst_addr_handle,
		    uet_mr_handle_t *mr_handle)
{
	return -FI_ENOSYS;
}

ssize_t uet_trecvmsg(uet_ep_handle_t ep_handle, uint32_t job_id,
		     const struct fi_msg *msg, uint64_t flags,
		     uet_mr_handle_t *mr_handle)
{
	return -FI_ENOSYS;
}

ssize_t uet_tsendmsg(uet_ep_handle_t ep_handle, uint32_t job_id,
		     const struct fi_msg *msg, uint64_t flags,
		     uet_addr_handle_t dst_addr_handle,
		     uet_mr_handle_t *mr_handle)
{
	return -FI_ENOSYS;
}

ssize_t uet_writemsg(uet_ep_handle_t ep_handle, uint32_t job_id,
		     const struct fi_msg_rma *msg, uint64_t flags,
		     uet_addr_handle_t dst_addr_handle,
		     uet_mr_handle_t *mr_handle)
{
	return -FI_ENOSYS;
}

ssize_t uet_readmsg(uet_ep_handle_t ep_handle, uint32_t job_id,
		    const struct fi_msg_rma *msg, uint64_t flags,
		    uet_addr_handle_t uet_addr_handle,
		    uet_mr_handle_t *mr_handle)
{
	return -FI_ENOSYS;
}

ssize_t uet_atomicmsg(uet_ep_handle_t ep_handle, uint32_t job_id,
		      const struct fi_msg_atomic *msg,
		      uint64_t flags, uet_addr_handle_t dst_addr_handle,
		      uet_mr_handle_t *mr_handle)
{
	return -FI_ENOSYS;
}

ssize_t uet_fetch_atomicmsg(uet_ep_handle_t ep_handle,
			    uint32_t job_id,
			    const struct fi_msg_atomic *msg,
			    uet_mr_handle_t *msg_mr_handle,
			    struct fi_ioc *resultv,
			    uet_mr_handle_t *result_mr_handle,
			    size_t result_count, uint64_t flags,
			    uet_addr_handle_t dst_addr_handle)
{
	return -FI_ENOSYS;
}

ssize_t uet_compare_atomicmsg(uet_ep_handle_t ep_handle,
			      uint32_t job_id,
			      const struct fi_msg_atomic *msg,
			      uet_mr_handle_t *msg_mr_handle,
			      struct fi_ioc *comparev,
			      uet_mr_handle_t *compare_mr_handle,
			      size_t compare_count,
			      struct fi_ioc *resultv,
			      uet_mr_handle_t *result_mr_handle,
			      size_t result_count,
			      uint64_t flags,
			      uet_addr_handle_t dst_addr_handle)
{
	return -FI_ENOSYS;
}
