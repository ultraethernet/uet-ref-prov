
#include <linux/types.h>

#include "uet_pkt_hdr.h"
//#include "uet_sec.h"
#include "uet_util.h"
#include "uet_api_private.h"

/* get pds mode for an endpoint */
static uet_pds_mode_t uet_get_pds_mode(struct uet_ep *uet_ep)
{
	return uet_ep->pds_mode;
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
 *      0 on success
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
			return 0;
		}
		if (++next_mr_index == uet_dom->num_mr)
			next_mr_index = 0;
		state = &uet_dom->mr_desc_alloc_cb.state[next_mr_index];
	}

	UET_API_ERR("Mem Region Descriptor Unavailable");
	return -EBUSY;
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
 *      0 on success
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
			return 0;
		}
		if (next_mr_index == max_index)
			next_mr_index = 0;
		else
			next_mr_index++;
		state = &uet_dom->mr_desc_alloc_cb.state[next_mr_index];
	}

	UET_API_ERR("Optimized Mem Region Descriptor Unavailable");
	return -EBUSY;
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
	ptrdiff_t offset;
	size_t mr_index;

	mr_desc->state = UET_MR_DESC_STATE_INACTIVE;

	offset = ((uint8_t *) mr_desc) - ((uint8_t *) uet_dom->mr_desc);
	mr_index = ((size_t) offset) / sizeof(struct uet_mr_desc);
	uet_dom->mr_desc_alloc_cb.state[mr_index] = UET_MR_DESC_AVAILABLE;
}

/*
 * allocate message id
 *
 * parms:
 *      uet    - ptr to uet instance struct
 *      msg_id - ptr to location where allocated message id is returned
 *
 * returns:
 *      0 on success
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
			return 0;
		}
		if (++next_msg_id > UET_MAX_MSG_ID)
			next_msg_id = 0;
		state = &uet->msg_id_cb.state[next_msg_id];
	}

	UET_API_ERR("No Msg ID Available");
	return -EBUSY;
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
	if (tx_desc->cq_flags & UET_ACCESS_FLAG_TAGGED)
		uet_list_insert_tail(
			&tx_desc->list_entry,
			&tx_desc->uet_ep->tx_desc_buf_tag_rtr_list_head);
	else
		uet_list_insert_tail(
			&tx_desc->list_entry,
			&tx_desc->uet_ep->tx_desc_buf_rtr_list_head);
	tx_desc->uet_ep->num_buf_rtr_list_entries++;
}

/* remove entry from list of buffered rtr tx descriptors for an endpoint */
static void uet_tx_desc_buf_rtr_list_remove(struct uet_tx_desc *tx_desc)
{
	if (tx_desc->desc_flags & UET_TX_DESC_FLAG_RTR_REQ) {
		uet_list_remove(&tx_desc->list_entry);
		tx_desc->uet_ep->num_buf_rtr_list_entries--;
	}
}

/* insert entry into list of deferred tx descriptors for an endpoint */
static void uet_tx_desc_defer_list_insert(struct uet_tx_desc *tx_desc)
{
	tx_desc->desc_flags |= UET_TX_DESC_FLAG_IN_DSEND_LIST;
	uet_gettime(&tx_desc->defer_time);
	uet_list_insert_tail(&tx_desc->list_entry,
			  &tx_desc->uet_ep->tx_desc_defer_list_head);
}

/* remove entry from list of deferred tx descriptors for an endpoint */
static void uet_tx_desc_defer_list_remove(struct uet_tx_desc *tx_desc)
{
	if (tx_desc->desc_flags & UET_TX_DESC_FLAG_IN_DSEND_LIST) {
		uet_list_remove(&tx_desc->list_entry);
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
 *      0 on success
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
			return 0;
		}
		if (++next_token > UET_MAX_RTR_TOKEN)
			next_token = 0;
		state = &cb->state[next_token];
	}

	UET_API_ERR("No TX Restart Token Available");
	return -EBUSY;
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

/* init key for ipv4 endpoint lookup from packet contents */
static void uet_ipv4_ep_key_init(struct uet_ipv4_ep_key *key,
				 struct uet_parsed_pkt *pp)
{
	struct iphdr *ipv4;
	struct uet_ses_req_std *ses;

	ipv4 = (struct iphdr *) pp->ip;
	ses = (struct uet_ses_req_std *) pp->ses;

	memset(key, 0, sizeof(struct uet_ipv4_ep_key));
	key->ipv4_addr = ipv4->daddr;
	key->pid_on_fep =
		(ntohs(ses->cmn.rsvd_pid_on_fep) & UET_SES_REQ_PID_ON_FEP_MASK)
		>> UET_SES_REQ_PID_ON_FEP_SHIFT;
	key->index =
		(ntohs(ses->cmn.rsvd_res_index) & UET_SES_REQ_RES_INDEX_MASK) >>
		UET_SES_REQ_RES_INDEX_SHIFT;
}

/* insert entry into ipv4 endpoint hash table */
static void uet_ipv4_ep_hash_insert(struct uet_ep *uet_ep)
{
	struct uet_instance *uet;

	uet = uet_ep->uet_domain->uet;

	uet_rw_lock(&uet->ipv4_ep_lkup_lock, UET_RW_LOCK_WR_ACCESS);
	HASH_ADD(ipv4_ep_hh, uet->ipv4_ep_hash_table, ipv4_ep_key,
		 sizeof(struct uet_ipv4_ep_key), uet_ep);
	uet_rw_unlock(&uet->ipv4_ep_lkup_lock, UET_RW_LOCK_WR_ACCESS);
}

/* remove entry from ipv4 endpoint hash table */
static void uet_ipv4_ep_hash_remove(struct uet_ep *uet_ep)
{
	struct uet_instance *uet;

	uet = uet_ep->uet_domain->uet;

	uet_rw_lock(&uet->ipv4_ep_lkup_lock, UET_RW_LOCK_WR_ACCESS);
	HASH_DELETE(ipv4_ep_hh, uet->ipv4_ep_hash_table, uet_ep);
	uet_rw_unlock(&uet->ipv4_ep_lkup_lock, UET_RW_LOCK_WR_ACCESS);
}

/* remove all entries from ipv4 endpoint hash table and free associated mem */
static void uet_ipv4_ep_hash_finalize(struct uet_instance *uet)
{
	uet_rw_lock(&uet->ipv4_ep_lkup_lock, UET_RW_LOCK_WR_ACCESS);
	HASH_CLEAR(ipv4_ep_hh, uet->ipv4_ep_hash_table);
	uet_rw_unlock(&uet->ipv4_ep_lkup_lock, UET_RW_LOCK_WR_ACCESS);
}

/* ipv4 endpoint hash table lookup */
static struct uet_ep *uet_ipv4_ep_hash_lookup(struct uet_instance *uet,
					      struct uet_ipv4_ep_key *key)
{
	struct uet_ep *uet_ep;

	uet_rw_lock(&uet->ipv4_ep_lkup_lock, UET_RW_LOCK_RD_ACCESS);
	HASH_FIND(ipv4_ep_hh, uet->ipv4_ep_hash_table, key,
		  sizeof(struct uet_ipv4_ep_key), uet_ep);
	uet_rw_unlock(&uet->ipv4_ep_lkup_lock, UET_RW_LOCK_RD_ACCESS);

	return uet_ep;
}

/* init key for rx msg lookup from packet contents */
static void uet_rx_msg_key_init(struct uet_rx_msg_key *key,
				struct uet_parsed_pkt *pp)
{
	struct uet_ses_req_std *ses;

	ses = (struct uet_ses_req_std *) pp->ses;

	memset(key, 0, sizeof(struct uet_rx_msg_key));
	key->initiator = ses->initiator;
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

/* remove all entries from mr hash table and free associated memory */
static void uet_mr_hash_finalize(struct uet_ep *uet_ep)
{
	struct uet_mr_desc *curr, *tmp;

	HASH_ITER(mr_hh, uet_ep->mr_hash_table, curr, tmp) {
		HASH_DELETE(mr_hh, uet_ep->mr_hash_table, curr);
		uet_nic_mr_dereg(UET_NIC(uet_ep->uet_domain->uet),
				 curr->nic_mr_handle);
		curr->state = UET_MR_DESC_STATE_DISABLED_REG;
		curr->uet_ep = NULL;
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
	ring->base = kcalloc(num_entries+1, entry_size, GFP_KERNEL);
	if (ring->base == NULL) {
		UET_API_PRINT_ERRNO("kcalloc");
		return -ENOMEM;
	}

	ring->num_entries = num_entries+1;
	ring->entry_size = entry_size;
	ring->head = 0;
	ring->tail = 0;
	return 0;
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
		kfree(ring->base);
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
	uet_list_insert_head(&rx_desc->list_entry,
			  &rx_desc->uet_ep->rx_desc_list_head);
}

/* remove entry from head of available rx descriptors list */
static struct uet_rx_desc *uet_rx_desc_list_pop(struct uet_ep *uet_ep)
{
	struct uet_rx_desc *rx_desc;

	if (uet_list_empty(&uet_ep->rx_desc_list_head))
		return NULL;

	rx_desc = container_of(uet_ep->rx_desc_list_head.next,
			       struct uet_rx_desc, list_entry);
	uet_list_remove(uet_ep->rx_desc_list_head.next);
	return rx_desc;
}

/* insert entry into list of active rx descriptors for an endpoint */
static void uet_rx_desc_active_list_insert(struct uet_rx_desc *rx_desc)
{
	rx_desc->desc_flags |= UET_RX_DESC_FLAG_ACTIVE;
	uet_gettime(&rx_desc->prev_pkt_time);
	uet_list_insert_tail(&rx_desc->list_entry,
			  &rx_desc->uet_ep->rx_desc_active_list_head);
}

/* move entry to tail of active rx descriptors list */
static void uet_rx_desc_active_list_move_to_tail(struct uet_ep *uet_ep,
						 struct uet_rx_desc *rx_desc)
{
	uet_list_remove(&rx_desc->list_entry);
	uet_gettime(&rx_desc->prev_pkt_time);
	uet_list_insert_tail(&rx_desc->list_entry,
			  &uet_ep->rx_desc_active_list_head);
}

/* remove entry from active rx descriptors list */
static void uet_rx_desc_active_list_remove(struct uet_rx_desc *rx_desc)
{
	if (rx_desc->desc_flags & UET_RX_DESC_FLAG_ACTIVE) {
		uet_list_remove(&rx_desc->list_entry);
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
	tx_desc->state = UET_TX_DESC_STATE_INACTIVE;
	tx_desc->desc_flags = UET_TX_DESC_FLAG_NONE;
	uet_list_insert_head(&tx_desc->list_entry,
			  &tx_desc->uet_ep->tx_desc_list_head);
}

/* remove entry from head of available tx descriptors list */
static struct uet_tx_desc *uet_tx_desc_list_pop(struct uet_ep *uet_ep)
{
	struct uet_tx_desc *tx_desc;

	if (uet_list_empty(&uet_ep->tx_desc_list_head))
		return NULL;

	tx_desc = container_of(uet_ep->tx_desc_list_head.next,
			       struct uet_tx_desc, list_entry);
	uet_list_remove(uet_ep->tx_desc_list_head.next);
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
	uet_list_insert_head(&mr_desc->list_entry,
			  &mr_desc->uet_ep->mr_list_head);
}

/* remove entry from head of memory region list */
static struct uet_mr_desc *uet_mr_list_pop(struct uet_ep *uet_ep)
{
	struct uet_mr_desc *mr_desc;

	if (uet_list_empty(&uet_ep->mr_list_head))
		return NULL;

	mr_desc = container_of(uet_ep->mr_list_head.next,
			       struct uet_mr_desc, list_entry);
	uet_list_remove(uet_ep->mr_list_head.next);
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

	if (uet_ep == NULL)
		return;

	if (uet_ep->rx_desc)
		kfree(uet_ep->rx_desc);

	if (uet_ep->tx_desc) {
		for (i = 0; i < uet_ep->num_tx_desc; i++) {
			tx_desc = &uet_ep->tx_desc[i];
			if (tx_desc->desc_flags &
			    UET_TX_DESC_FLAG_MSG_ID_ALLOCATED)
				uet_dealloc_msg_id(uet_ep->uet_domain->uet,
						   tx_desc->msg_id);
			uet_dealloc_tx_rtr_token(tx_desc);
			uet_tx_desc_buf_rtr_list_remove(tx_desc);
		}
		kfree(uet_ep->tx_desc);
	}

	uet_desc_ring_free(uet_ep);
}

/* insert entry into list of endpoints */
static void uet_ep_insert(struct uet_ep *uet_ep)
{
	uet_rw_lock(&uet_ep->uet_domain->ep_lock, UET_RW_LOCK_WR_ACCESS);
	uet_list_insert_head(&uet_ep->ep_list_entry,
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

/* determine if there are completion q's associated with endpoint */
static bool uet_ep_has_cq(struct uet_ep *uet_ep)
{
	return (uet_ep_has_send_cq(uet_ep) ||
		uet_ep_has_recv_cq(uet_ep));
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

	ring_entry = &(((struct uet_cq_ring_entry *) (ring->base))[ring->tail]);

	memcpy(buf, &ring_entry->entry, sizeof(struct uet_cq_entry));

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
	struct uet_cq_entry *cq_entry;

	uet_ep = tx_desc->uet_ep;
	cq = &uet_ep->send_cq;
	ring = &cq->ring;

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

	cq_entry = (struct uet_cq_entry *) &ring_entry->entry;
	cq_entry->op_context = tx_desc->context;
	if (cq->cq_type != UET_CQ_TYPE_CONTEXT && 
		cq->cq_type != UET_CQ_TYPE_UNSPEC)
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
	uint64_t backoff;
	struct uet_av_entry *av_entry;

	/* check for max retransmits */
	tx_desc->retransmit_cnt++;
	max_retx = tx_desc->uet_ep->uet_domain->uet->max_msg_retransmits;
	if ((max_retx != UET_MSG_RETRANSMIT_MAX_INFINITY) &&
	    (tx_desc->retransmit_cnt > max_retx)) {
		uet_tx_desc_set_err(tx_desc, EIO,
				    UET_TX_DESC_STATE_ERR_COMPLETE);
		return -EIO;
	}

	/* set descriptor fields to retransmit message from start */
	tx_desc->remaining_bytes = tx_desc->buf_desc.len;
	tx_desc->buf_desc.buf_off = 0;

	/* set earliest retransmit time */
	uet_gettime(&tx_desc->tx_time);
	if (delay_retx) {
		/* exponential backoff */
		backoff = 
		 /*((uint64_t) lrand48()) % */(tx_desc->backoff_max + 1);
		tx_desc->tx_time += backoff;
	}

	if (tx_desc->pds_mode == UET_PDS_MODE_ROD) {
		av_entry = (struct uet_av_entry *) tx_desc->dst_addr_handle;
		uet_set_av_msg_tx_seq_num(av_entry, tx_desc->seq_num);
	}

	return 0;
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
		if (tx_desc->remaining_bytes)
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
			}
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
			}
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
		}
		rc = uet_retx_msg(tx_desc, tx_desc->delay_retx);
		if (rc == 0)
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
		if (rc == 0)
			tx_desc->state = UET_TX_DESC_STATE_ACTIVE;
		else
			tx_desc->state = UET_TX_DESC_STATE_ERR_COMPLETE;
		break;
	case UET_TX_DESC_STATE_ERR:
		if (tx_desc->unack_pkts)
			break;
		if (tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_REQ) {
			if (tx_desc->rx_desc->expected_rd_rsp)
				break;
			pds->downcall.msg_cmpl_ind(
				uet_ep, tx_desc->dst_addr_handle,
				tx_desc->pds_mode, tx_desc->msg_id);
		}
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
	struct uet_cq_entry *err_entry;

	uet_ep = tx_desc->uet_ep;
	cq = &uet_ep->send_cq;
	cq_ring = &cq->ring;

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

	err_entry = (struct uet_cq_entry *) &cq_ring_entry->entry;
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

	ring_entry = &(((struct uet_cq_ring_entry *) (ring->base))[ring->tail]);

	memcpy(buf, &ring_entry->entry, sizeof(struct uet_cq_entry));

	uet_rx_desc_list_insert(ring_entry->desc.rx);

	uet_ring_tail_advance(ring);
}

/* post an entry to a rx completion queue */
static void uet_rx_cq_post_entry(struct uet_rx_desc *rx_desc)
{
	struct uet_ep *uet_ep;
	struct uet_cq *cq;
	struct uet_ring *ring;
	struct uet_cq_ring_entry *ring_entry;
	struct uet_cq_entry *cq_entry;

	if (!(rx_desc->desc_flags & UET_RX_DESC_FLAG_POST_CQ)) {
		uet_rx_desc_recycle(rx_desc, true);
		return;
	}

	uet_ep = rx_desc->uet_ep;
	cq = &uet_ep->recv_cq;
	ring = &cq->ring;

	ring_entry = &(((struct uet_cq_ring_entry *) (ring->base))[ring->head]);
	memset(ring_entry, 0, ring->entry_size);
	ring_entry->desc.rx = rx_desc;

	cq_entry = (struct uet_cq_entry *) &ring_entry->entry;
	cq_entry->op_context = rx_desc->context;
	if (cq->cq_type > UET_CQ_TYPE_CONTEXT) {
		cq_entry->flags = rx_desc->cq_flags;
		cq_entry->len = rx_desc->msg_len;
	}
	if (cq->cq_type > UET_CQ_TYPE_MSG) {
		cq_entry->buf = rx_desc->buf_desc.buf;
		if (rx_desc->desc_flags & UET_RX_DESC_FLAG_WRITE_IMM)
			cq_entry->data = rx_desc->imm_data;
	}
	if ((cq->cq_type > UET_CQ_TYPE_DATA) && (rx_desc->cq_flags & UET_ACCESS_FLAG_TAGGED)) {
		cq_entry->tag = ntohll(rx_desc->tag_key.tag);
	}

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
	struct uet_cq_entry *err_entry;

	if ((rx_desc->desc_flags & UET_RX_DESC_FLAG_WRITE) ||
	    (rx_desc->desc_flags & UET_RX_DESC_FLAG_ERR_TRACK) ||
	    (rx_desc->desc_flags & UET_RX_DESC_FLAG_DSEND)) {
		uet_rx_desc_recycle(rx_desc, true);
		return;
	}

	uet_ep = rx_desc->uet_ep;
	cq = &uet_ep->recv_cq;
	ring = &cq->ring;

	ring_entry = &(((struct uet_cq_ring_entry *) (ring->base))[ring->head]);
	memset(ring_entry, 0, ring->entry_size);
	ring_entry->err = true;
	ring_entry->desc.rx = rx_desc;

	err_entry = (struct uet_cq_entry *) &ring_entry->entry;
	err_entry->op_context = rx_desc->context;
	err_entry->flags = rx_desc->cq_flags;
	err_entry->err = err_code;
	if (rx_desc->desc_flags & UET_RX_DESC_FLAG_WRITE_IMM)
		err_entry->data = rx_desc->imm_data;
	if (rx_desc->cq_flags & UET_ACCESS_FLAG_TAGGED)
		err_entry->tag = ntohll(rx_desc->tag_key.tag);
	err_entry->buf = rx_desc->buf_desc.buf;
	uet_rx_desc_recycle(rx_desc, false);

	uet_ring_head_advance(ring);
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
	struct uet_list_entry *item;
	struct uet_pds *pds = &uet_ep->uet_domain->uet->pds;

	uet_rx_msg_hash_finalize(uet_ep);
	uet_tag_initiator_hash_finalize(uet_ep);

	uet_desc_free(uet_ep);

	uet_cq_free(uet_ep);

	pds->downcall.ep_finalize(uet_ep);

	item = &uet_ep->ep_list_entry;
	uet_rw_lock(&uet_ep->uet_domain->ep_lock, UET_RW_LOCK_WR_ACCESS);
	uet_list_remove(item);
	uet_rw_unlock(&uet_ep->uet_domain->ep_lock, UET_RW_LOCK_WR_ACCESS);

	kfree(uet_ep);
}

/* free resources associated with all endpoints of a domain */
static void uet_ep_free_all(struct uet_domain *uet_dom)
{
	struct uet_list_entry *head, *item;
	struct uet_ep *uet_ep;

	head = &uet_dom->ep_list_head;
	uet_list_foreach(head, item) {
		uet_ep = container_of(item, struct uet_ep,
				      ep_list_entry);
		uet_list_remove(item);
		item = head;
		uet_ep_free(uet_ep);
	}
}

/* insert entry into list of address vector entries for domain */
static void uet_av_entry_insert(struct uet_domain *uet_dom,
				struct uet_av_entry *av_entry)
{
	uet_list_insert_head(&av_entry->av_list_entry,
			  &uet_dom->av_list_head);
}

/* free resources associated with an address vector entry */
static void uet_av_entry_free(struct uet_av_entry *av_entry)
{
	struct uet_list_entry *item;

	item = &av_entry->av_list_entry;
	uet_list_remove(item);
	kfree(av_entry);
}

/* free resources associated with all address vector entries of a domain */
static void uet_av_free_all(struct uet_domain *uet_dom)
{
	struct uet_list_entry *head, *item;
	struct uet_av_entry *av_entry;

	head = &uet_dom->av_list_head;
	uet_list_foreach(head, item) {
		av_entry = container_of(item, struct uet_av_entry,
					av_list_entry);
		uet_list_remove(item);
		item = head;
		kfree(av_entry);
	}
}

/* insert entry into list of domains */
static void uet_domain_insert(struct uet_domain *uet_dom)
{
	uet_list_insert_head(&uet_dom->domain_list_entry,
			  &uet_dom->uet->domain_list_head);
}

/* determine if there are endpoints associated with a domain */
static bool uet_domain_has_ep(struct uet_domain *uet_dom)
{
	return (!((bool) uet_list_empty(&uet_dom->ep_list_head)));
}

/* free resources associated with a domain */
static void uet_domain_free(struct uet_domain *uet_dom)
{
	struct uet_list_entry *item;

	item = &uet_dom->domain_list_entry;
	uet_list_remove(item);
	if (uet_dom->mr_desc_alloc_cb.state)
		kfree(uet_dom->mr_desc_alloc_cb.state);
	if (uet_dom->mr_desc)
		kfree(uet_dom->mr_desc);
	kfree(uet_dom);
}

/* free resources associated with all domains */
static void uet_domain_free_all(struct uet_instance *uet)
{
	struct uet_list_entry *head, *item;
	struct uet_domain *uet_dom;

	head = &uet->domain_list_head;
	uet_list_foreach(head, item) {
		uet_dom = container_of(item, struct uet_domain,
				       domain_list_entry);
		uet_list_remove(item);
		item = head;
		uet_ep_free_all(uet_dom);
		uet_av_free_all(uet_dom);
		uet_domain_free(uet_dom);
	}
}

/* free most resources associated with uet instance */
static void uet_finalize_core(struct uet_instance *uet)
{
	uet_ipv4_ep_hash_finalize(uet);
	uet_nic_finalize(UET_NIC(uet));
	uet_domain_free_all(uet);
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

	msg_off = ((ntohll(ses->msg_off_payload_len) &
		    UET_SES_REQ_STD_MSG_OFF_MASK) >>
		   UET_SES_REQ_STD_MSG_OFF_SHIFT);
	if (msg_off < rx_desc->msg_len) {
		truncated_bytes = rx_desc->msg_len - msg_off;
		if (truncated_bytes > rx_desc->remaining_bytes)
			return -ENODATA;
		else if (truncated_bytes == rx_desc->remaining_bytes) {
			rx_desc->remaining_bytes = 0;
			*msg_complete = true;
		} else
			rx_desc->remaining_bytes -= truncated_bytes;
	} else
		return -ENODATA;

	return 0;
}

/* handle rx message error */
static uet_ses_rc_t uet_rx_msg_err(
	struct uet_ep *uet_ep, struct uet_parsed_pkt *pp,
	struct uet_rx_desc *rx_desc, uet_ses_rc_t ses_rc, bool *gtd_del)
{
	int rc;
	bool msg_complete;
	struct uet_ses_req_std *ses;

	ses = (struct uet_ses_req_std *) pp->ses;

	if (rx_desc == NULL) {
		*gtd_del = true;
		rx_desc = uet_rx_desc_list_pop(uet_ep);
		if (rx_desc == NULL) {
			UET_API_ERR("RX: No Descriptor to Track Errored Msg");
			return ses_rc;
		}
		memset(rx_desc, 0, sizeof(struct uet_rx_desc));
		uet_init_err_rx_desc(uet_ep, pp, rx_desc, ses_rc);
	} else if (rx_desc->ses_rc == UET_RC_OK) {
		rx_desc->ses_rc = ses_rc;
		*gtd_del = true;
	}

	if (rx_desc->desc_flags & UET_RX_DESC_FLAG_DSEND) {
		if ((ses->cmn.eom_opcode & UET_SES_EOM_MASK) &&
		    (pp->ses_payload_len == 0)) {
			rc = uet_rx_msg_truncate(pp, rx_desc, &msg_complete);
			if ((rc != 0) || (msg_complete == true)) {
				if (rc != 0)
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
	uet_rx_cq_post_err(rx_desc, EIO);
	return ses_rc;
}

/* find mr descriptor associated with key */
static struct uet_mr_desc *uet_get_mr_desc(struct uet_ep *uet_ep,
				    struct uet_parsed_pkt *pp)
{
	struct uet_domain *uet_dom;
	struct uet_mr_desc *mr_desc;
	struct uet_mr_key mr_key;

	uet_dom = uet_ep->uet_domain;
	uet_mr_key_init(&mr_key, pp);
	if (uet_dom->mr_mode & UET_MR_MODE_PROV_KEY) {
		if (mr_key.rkey >= uet_dom->num_mr)
			mr_desc = NULL;
		else {
			mr_desc = &uet_dom->mr_desc[mr_key.rkey];
			if (mr_desc->state != UET_MR_DESC_STATE_ENABLED)
				mr_desc = NULL;
		}
	} else
		mr_desc = uet_mr_hash_lookup(uet_ep, &mr_key);

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
 *      ses_rc      - ses return code, UET_RC_OK => not errored message
 *      msg_key     - ptr to location where key from message lookup is
 *                    to be returned
 *      rx_desc     - ptr to location where ptr to rx descriptor is
 *                    to be returned
 *      first_msg_pkt - ptr to location where first message packet
 *                      indication is to be returned
 *      gtd_del       - ptr to location where ses indicates whether pds
 *                      needs to maintain ses response state, may be
 *                      set to true to indicate pds needs to guarantee
 *                      delivery of ses response state
 *
 * returns:
 *   - ses return code
 */
static uet_ses_rc_t uet_get_rx_desc(
	struct uet_ep *uet_ep, struct uet_parsed_pkt *pp, bool write,
	uet_ses_rc_t ses_rc, struct uet_rx_msg_key *msg_key,
	struct uet_rx_desc **rx_desc, bool *first_msg_pkt, bool *gtd_del)
{
	struct uet_mr_desc *mr_desc;

	/* lookup rx descriptor for msg */
	uet_rx_msg_key_init(msg_key, pp);
	*rx_desc = uet_rx_msg_hash_lookup(uet_ep, msg_key);
	if (*rx_desc != NULL) {
		*first_msg_pkt = false;
		uet_rx_desc_active_list_move_to_tail(uet_ep, *rx_desc);
		if ((*rx_desc)->ses_rc != UET_RC_OK)
			ses_rc = (*rx_desc)->ses_rc;
		if (ses_rc != UET_RC_OK)
			return (uet_rx_msg_err(
					uet_ep, pp, *rx_desc, ses_rc, gtd_del));
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
		*gtd_del = true;
		return ses_rc;
	}

	/* init base rx descriptor fields */
	memset(*rx_desc, 0, sizeof(struct uet_rx_desc));
	(*rx_desc)->uet_ep = uet_ep;
	if (write)
		(*rx_desc)->desc_flags = UET_RX_DESC_FLAG_WRITE;
	if (ses_rc != UET_RC_OK)
		goto err_exit;

	/* operation is rma, find mr associated with key */
	mr_desc = uet_get_mr_desc(uet_ep, pp);
	if (mr_desc == NULL) {
		UET_API_ERR("RX: Invalid RMA Key");
		ses_rc = UET_RC_OP_VIOLATION;
		goto err_exit;
	}

	/* more init of rx descriptor for rma operation */
	(*rx_desc)->buf_desc.type = UET_MSG_BUF_TYPE_CONTIG;
	(*rx_desc)->buf_desc.buf = mr_desc->buf_desc.buf;
	(*rx_desc)->buf_desc.len = mr_desc->buf_desc.len;
	(*rx_desc)->context = mr_desc->context;
	(*rx_desc)->mr_desc = mr_desc;
	(*rx_desc)->ses_rc = ses_rc;

	return UET_RC_OK;

err_exit:
	uet_init_err_rx_desc(uet_ep, pp, *rx_desc, ses_rc);
	return uet_rx_msg_err(uet_ep, pp, *rx_desc, ses_rc, gtd_del);
}

/* init tx descriptor ephemeral address vector */
static void uet_init_tx_desc_ephemeral_av(struct uet_tx_desc *tx_desc,
					  struct uet_parsed_pkt *pp)
{
	struct ethhdr *eth;
	struct iphdr *ipv4;
	struct uet_av_entry *av;

	eth = (struct ethhdr *) pp->eth;
	ipv4 = (struct iphdr *) pp->ip;

	uet_init_uet_addr_ipv4(&tx_desc->ephemeral_av.uet_addr,
			       ntohl(ipv4->saddr));
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
	tx_desc->cq_flags = UET_ACCESS_FLAG_RMA | UET_ACCESS_FLAG_REMOTE_READ;
	tx_desc->desc_flags = UET_TX_DESC_FLAG_READ_RSP;
	tx_desc->buf_desc.type = UET_MSG_BUF_TYPE_CONTIG;
	tx_desc->buf_desc.buf = (void *)
		(((uint8_t *) mr_desc->buf_desc.buf) + buf_off);
	tx_desc->buf_desc.len = pp->ses_payload_len;
	tx_desc->remaining_bytes = pp->ses_payload_len;
	tx_desc->remote_msg_off = msg_off;
	tx_desc->mr_desc = mr_desc;

	tx_desc->rd_rsp.mod_len = req_len;
	tx_desc->rd_rsp.pds_info = *pds_info;

	uet_init_tx_desc_ephemeral_av(tx_desc, pp);

	tx_desc->job_id = uet_get_std_req_job_id(ses);
	tx_desc->msg_id = ntohs(ses->cmn.msg_id);
	tx_desc->uet_ep = uet_ep;
	tx_desc->backoff_max = UET_INITIAL_BACKOFF_MAX;
	tx_desc->pds_mode = uet_get_pds_mode(uet_ep);
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
	uint64_t msg_off_payload_len;
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
		msg_off_payload_len = ntohll(ses->msg_off_payload_len);
		msg_off = (msg_off_payload_len &
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
	rx_gen = (uint32_t)((ntohl(ses->cmn.index_gen_job_id) &
			     UET_SES_REQ_INDEX_GEN_MASK) >>
			    UET_SES_REQ_INDEX_GEN_SHIFT);
	ep_gen = (uint32_t) uet_ep->untagged_gen;
	if (rx_gen != ep_gen) {
		UET_API_ERR("RX: Read Req: Bad Generation");
		return UET_RC_BAD_GENERATION;
	}

	/* find mr descriptor associated with key */
	mr_desc = uet_get_mr_desc(uet_ep, pp);
	if (mr_desc == NULL) {
		UET_API_ERR("RX: Read Req: Invalid Key");
		return UET_RC_OP_VIOLATION;
	}

	/* check mr permissions */
	if (!(mr_desc->access & UET_ACCESS_FLAG_REMOTE_READ)) {
		UET_API_ERR("RX: Read Req: No Remote Read Permission");
		return UET_RC_OP_VIOLATION;
	}

	/* validate requested data is within memory region */
	if ((buf_off + pp->ses_payload_len) > mr_desc->buf_desc.len) {
		UET_API_ERR("RX: Read Req: Invalid Buffer Offset");
		return UET_RC_BAD_ADDR;
	}

	/* check if data is to be carried in ack */
	max_ack_data = uet_ep->uet_domain->uet->pds.max_ack_data;
	if ((uet_ep->uet_domain->uet->max_payload_len == max_ack_data) ||
	    (req_len <= max_ack_data)) {
		ack_d_info->valid = true;
		ack_d_info->payload_len = pp->ses_payload_len;
		ack_d_info->msg_off = msg_off;
		ack_d_info->buf = ((uint8_t *) mr_desc->buf_desc.buf) + buf_off;
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
	uint16_t msg_id;
	uint64_t remote_token;
	uint64_t now;
	struct uet_instance *uet;
	struct uet_ses_req_std *ses;
	struct uet_tx_desc *tx_desc;

	uet = uet_ep->uet_domain->uet;
	ses = (struct uet_ses_req_std *) pp->ses;

	/* only buffer dsend's for rud pdc's */
	if (uet_get_pds_mode(uet_ep) != UET_PDS_MODE_RUD)
		return UET_RC_NO_MATCH;

	/* check for max buffered dsend's */
	if (uet_ep->num_buf_rtr_list_entries == uet->max_rtr_q_entries)
		return UET_RC_NO_MATCH;

	/* allocate msg id for rtr */
	rc = uet_alloc_msg_id(uet, &msg_id);
	if (rc != 0)
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
	tx_desc->backoff_max = UET_INITIAL_BACKOFF_MAX;
	tx_desc->pds_mode = UET_PDS_MODE_RUD;
	uet_gettime(&now);
	tx_desc->tx_time = now;
	tx_desc->defer_time = now;
	tx_desc->local_rtr_token = UET_TARGET_RTR_TOKEN;
	remote_token =
		(ntohll(ses->restart_token) & UET_SES_REQ_STD_SRC_TOKEN_MASK) >>
		UET_SES_REQ_STD_SRC_TOKEN_SHIFT;
	tx_desc->remote_rtr_token = (uint32_t) remote_token;
	if (tagged) {
		tx_desc->cq_flags = UET_ACCESS_FLAG_TAGGED;
		tx_desc->ephemeral_av.uet_addr.flags |= UET_ADDR_INITIATOR_V;
		tx_desc->ephemeral_av.uet_addr.initiator_id =
						ntohl(tag_key->initiator);
		tx_desc->tag_or_immdata = ntohll(tag_key->tag);
	} else
		tx_desc->cq_flags = UET_ACCESS_FLAG_MSG;

	/* insert tx desc in appropriate rtr list */
	uet_tx_desc_buf_rtr_list_insert(tx_desc);

	*list = UET_OVERFLOW;
	return UET_RC_DEFER_SEND;
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
 *      gtd_del - ptr to location where ses indicates whether pds
 *                needs to maintain ses response state,
 *                true => pds needs to guarantee delivery of ses
 *                response state
 *
 * returns:
 *   - ses return code
 */
static uet_ses_rc_t uet_rx_req_pkt(
	struct uet_ep *uet_ep, struct uet_parsed_pkt *pp, uet_ses_list_t *list,
	bool tagged, bool write, bool *gtd_del)
{
	uet_ses_rc_t ses_rc;
	uint16_t max_payload_len;
	size_t start_off, buf_off;
	uint32_t req_len, rx_gen, ep_gen;
	uint64_t msg_off_payload_len;
	bool ep_gen_disabled, first_msg_pkt = false,
	     invalid_payload_len = false;
	void *buf_ptr;
	struct uet_ses_req_std *ses;
	struct uet_ring *ring;
	struct uet_rx_desc *rx_desc;
	struct uet_rx_msg_key msg_key;
	struct uet_tag_initiator_key tag_key, tag_only_key;

	ses = (struct uet_ses_req_std *) pp->ses;

	*list = UET_EXPECTED; /* overflow list not supported */
	*gtd_del = false;
	max_payload_len = uet_ep->uet_domain->uet->max_payload_len;
	req_len = ntohl(ses->req_len);
	if (write)
		start_off = ntohll(ses->buf_off);
	else
		start_off = 0;

	/* get rx descriptor for message */
	ses_rc = uet_get_rx_desc(uet_ep, pp, write, UET_RC_OK, &msg_key,
				 &rx_desc, &first_msg_pkt, gtd_del);
	if (ses_rc != UET_RC_OK)
		return ses_rc;

	/* check for start of message */
	if (ses->cmn.ver_flags & UET_SES_REQ_FLAG_SOM) {
		/* check if rx completion queue is available */
		if (!(write) || (ses->cmn.ver_flags & UET_SES_REQ_FLAG_HD)) {
			if (uet_ep->recv_cq.cq_state == UET_CQ_DOWN) {
				UET_API_ERR("RX: Completion Q DOWN");
				return (uet_rx_msg_err(uet_ep, pp, rx_desc,
						UET_RC_DISABLED, gtd_del));
			}
		}

		/* process header data */
		if (write && (ses->cmn.ver_flags & UET_SES_REQ_FLAG_HD)) {
			/* check cq format */
			if (uet_ep->recv_cq.cq_type < UET_CQ_TYPE_DATA) {
				UET_API_ERR("RX: No CQ Support for Write Imm");
				return (uet_rx_msg_err(
						uet_ep, pp, rx_desc,
						UET_RC_OP_VIOLATION, gtd_del));
			}
			rx_desc->imm_data = ntohll(ses->cmpl_data);
			rx_desc->desc_flags |= (UET_RX_DESC_FLAG_WRITE_IMM |
						UET_RX_DESC_FLAG_POST_CQ);
		}

		/* set buffer offset length and check payload length */
		buf_off = start_off;
		if (((pp->ses_payload_len != req_len) &&
		     (pp->ses_payload_len != max_payload_len)) ||
		    (pp->ses_payload_len > pp->pkt_payload_len)) {
			pr_info("[tmp][%s:%d] pp->ses_payload_len: %u pp->pkt_payload_len: %u max_payload_len: %u req_len: %u\n",
				__func__, __LINE__, pp->ses_payload_len, pp->pkt_payload_len, max_payload_len, req_len);
			invalid_payload_len = true;
		}
	} else {
		/* set buffer offset and check payload length */
		msg_off_payload_len = ntohll(ses->msg_off_payload_len);
		buf_off = (start_off + ((msg_off_payload_len &
					 UET_SES_REQ_STD_MSG_OFF_MASK) >>
					UET_SES_REQ_STD_MSG_OFF_SHIFT));
		if (pp->ses_payload_len > pp->pkt_payload_len)
			invalid_payload_len = true;
	}

	/* handle invalid payload length */
	if (invalid_payload_len) {
		UET_API_ERR("RX: Invalid Payload Len");
		return (uet_rx_msg_err(uet_ep, pp, rx_desc,
				       UET_RC_OP_VIOLATION, gtd_del));
	}

	/* handle first and non-first packets of message differently */
	if (!first_msg_pkt) {
		if (write) {
			/* check for proper mr key and permissions */
			if (rx_desc->mr_desc == NULL) {
				UET_API_ERR("RX: RMA Op for Non-RMA Message");
				return (uet_rx_msg_err(
					uet_ep, pp, rx_desc,
					UET_RC_OP_VIOLATION, gtd_del));
			}
			if (!(rx_desc->desc_flags & UET_RX_DESC_FLAG_WRITE)) {
				UET_API_ERR("RX: Write for Non-Write Message");
				return (uet_rx_msg_err(
					uet_ep, pp, rx_desc,
					UET_RC_OP_VIOLATION, gtd_del));
			}
			if (rx_desc->mr_desc->full_key !=
			    ntohll(ses->match_bits)) {
				UET_API_ERR("RX: RMA Op with Changed Key");
				return (uet_rx_msg_err(
					uet_ep, pp, rx_desc,
					UET_RC_PERM_VIOLATION, gtd_del));
			}
		}
	} else { /* first packet of message */
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
					UET_RC_DISABLED_GEN, gtd_del));
		}

		/* check for correct generation */
		rx_gen = (uint32_t)((ntohl(ses->cmn.index_gen_job_id) &
				     UET_SES_REQ_INDEX_GEN_MASK) >>
				    UET_SES_REQ_INDEX_GEN_SHIFT);
		if (rx_gen != ep_gen) {
			UET_API_ERR("RX: Bad Generation");
			return (uet_rx_msg_err(uet_ep, pp, rx_desc,
					UET_RC_BAD_GENERATION, gtd_del));
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
				if (uet_get_pds_mode(uet_ep) ==
				    UET_PDS_MODE_ROD)
					uet_ep->tagged_gen_disabled = true;
				return (uet_rx_msg_err(uet_ep, pp, rx_desc,
						       ses_rc, gtd_del));
			}

			/* check if rx buffer is big enough for message */
			if ((buf_off + req_len) > rx_desc->buf_desc.len) {
				UET_API_ERR("RX: Tagged Buffer Too Small");
				return (uet_rx_msg_err(uet_ep, pp, rx_desc,
						UET_RC_UNSUPPORTED_SIZE,
						gtd_del));
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
				if (uet_get_pds_mode(uet_ep) ==
				    UET_PDS_MODE_ROD)
					uet_ep->untagged_gen_disabled = true;
				return (uet_rx_msg_err(uet_ep, pp, rx_desc,
						       ses_rc, gtd_del));
			}

			/* check if rx buffer is big enough for message */
			rx_desc = (struct uet_rx_desc *)
				  (((struct uet_rx_desc_ring_entry *)
				    (ring->base))[ring->tail].rx_desc);
			if ((buf_off + req_len) > rx_desc->buf_desc.len) {
				UET_API_ERR("RX: Buffer Too Small");
				return (uet_rx_msg_err(uet_ep, pp, rx_desc,
						UET_RC_UNSUPPORTED_SIZE,
						gtd_del));
			}

			/* remove descriptor from ring */
			uet_rx_desc_ring_remove(rx_desc);
		} else { /* handle rma */
			/* check mr permissions */
			if (!(rx_desc->mr_desc->access & UET_ACCESS_FLAG_REMOTE_WRITE)) {
				UET_API_ERR("RX: No Remote Write Permission");
				return (uet_rx_msg_err(uet_ep, pp, rx_desc,
						UET_RC_OP_VIOLATION, gtd_del));
			}

			/* check if mr buffer is big enough for message */
			if ((buf_off + req_len) >
			    rx_desc->mr_desc->buf_desc.len) {
				UET_API_ERR("RX: MR Buffer Too Small");
				return (uet_rx_msg_err(uet_ep, pp, rx_desc,
						UET_RC_UNSUPPORTED_SIZE,
						gtd_del));
			}
		}

		/* insert rx desc into active list and rx msg lookup tbl */
		rx_desc->msg_len = req_len;
		rx_desc->remaining_bytes = req_len;
		uet_rx_desc_active_list_insert(rx_desc);
		uet_rx_msg_key_init(&rx_desc->msg_key, pp);
		uet_rx_msg_hash_insert(uet_ep, rx_desc);
	}

	/* validate pkt fits in buffer */
	if ((buf_off + pp->ses_payload_len) > rx_desc->buf_desc.len) {
		UET_API_ERR("RX: Invalid Buffer Offset");
		return (uet_rx_msg_err(uet_ep, pp, rx_desc,
				       UET_RC_BAD_ADDR, gtd_del));
	}

	/* validate payload length doesn't exceed request length */
	if (pp->ses_payload_len > rx_desc->remaining_bytes) {
		UET_API_ERR("RX: Payload Len Exceeds Request Len");
		return (uet_rx_msg_err(uet_ep, pp, rx_desc,
				       UET_RC_OP_VIOLATION, gtd_del));
	}

	/* check for initiator error */
	if (ses->cmn.ver_flags & UET_SES_REQ_FLAG_IE) {
		UET_API_ERR("RX: Initiator Error");
		return (uet_rx_msg_err(uet_ep, pp, rx_desc,
				       UET_RC_INITIATOR_ERR, gtd_del));
	}

	/* copy packet to rx buffer */
	buf_ptr =  (void *) (((size_t) rx_desc->buf_desc.buf) + buf_off);
	memcpy(buf_ptr, pp->payload, pp->ses_payload_len);

	/* check for message completion */
	rx_desc->remaining_bytes -= pp->ses_payload_len;
	pr_info("[%s:%d] remaining_bytes: %lu ses_payload_len: %d\n",
		__func__, __LINE__, rx_desc->remaining_bytes, pp->ses_payload_len);
	if (rx_desc->remaining_bytes == 0) {
		/* post rx completion queue entry */
		pr_info("uet: posting in recv cq.\n");
		uet_rx_cq_post_entry(rx_desc);
	}

	return UET_RC_OK;
}

/*
 * process a received message cancel packet (UET_MSG_ERR opcode)
 *
 * parms:
 *      uet_ep  - ptr to uet endpoint struct
 *      pp      - ptr to parsed packet struct
 *      gtd_del - ptr to location where ses indicates whether pds
 *                needs to maintain ses response state,
 *                true => pds needs to guarantee delivery of ses response state
 *
 * returns:
 *   - ses return code
 */
static uet_ses_rc_t uet_rx_cancel_pkt(
	struct uet_ep *uet_ep, struct uet_parsed_pkt *pp, bool *gtd_del)
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
	if (rx_desc->ses_rc == UET_RC_OK) {
		UET_API_ERR("RX: Unexpected UET_MSG_ERR");
		pp->ses_payload_len = 0;
		uet_rx_msg_err(uet_ep, pp, rx_desc,
			       UET_RC_INITIATOR_ERR, gtd_del);
		ses_rc = UET_RC_INITIATOR_ERR;
		*gtd_del = true;
	} else if (rx_desc->desc_flags & UET_RX_DESC_FLAG_CANCELLED) {
		UET_API_ERR("RX: Unexpected Multiple UET_MSG_ERR");
		goto post_err_exit;
	}
	rx_desc->desc_flags |= UET_RX_DESC_FLAG_CANCELLED;

	if (ses->cmn.ver_flags & UET_SES_REQ_FLAG_SOM) {
		UET_API_ERR("RX: Unexpected SOM on UET_MSG_ERR");
		goto post_err_exit;
	} else if (!(ses->cmn.eom_opcode & UET_SES_EOM_MASK)) {
		UET_API_ERR("RX: No EOM on UET_MSG_ERR");
		goto post_err_exit;
	} else {
		rc = uet_rx_msg_truncate(pp, rx_desc, &msg_complete);
		if ((rc != 0) || (msg_complete == true)) {
			if (rc != 0)
				UET_API_ERR("RX: Invalid UET_MSG_ERR Offset");
			goto post_err_exit;
		}
	}

	return ses_rc;

post_err_exit:
	uet_rx_cq_post_err(rx_desc, EIO);

err_exit:
	*gtd_del = true;
	return UET_RC_OP_VIOLATION;
}

/* process received ready to restart request */
static uet_ses_rc_t uet_rx_rtr_req_pkt(
	    struct uet_instance *uet, struct uet_parsed_pkt *pp,
	    struct uet_ep **uet_ep, bool *gtd_del)
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

	tx_desc->remote_rtr_token =
		(full_token & UET_SES_REQ_STD_SRC_TOKEN_MASK) >>
		UET_SES_REQ_STD_SRC_TOKEN_SHIFT;
	uet_tx_desc_defer_list_remove(tx_desc);
	tx_desc->desc_flags |= UET_TX_DESC_FLAG_GOT_RTR;

	*uet_ep = token_uet_ep;
	return UET_RC_OK;

err_exit:
	UET_API_ERR("RX: Invalid Restart Token");
	*gtd_del = true;
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

	/* copy the data */
	buf_ptr =  (void *) (((size_t) rx_desc->buf_desc.buf) + msg_off);
	memcpy(buf_ptr, ses->payload, pp->ses_payload_len);

	return UET_RC_OK;
}

/*
 * pds upcall to ses when request packet is received
 *
 * parms:
 *      rx_pkt_handle   - handle assigned to received packet by pds
 *      uet              - ptr to uet instance struct
 *      pp              - ptr to parsed packet struct
 *      pds_info        - ptr to info that needs to be echoed back to pds when
 *                        read data is transmitted
 *      req_ses_hdr     - ptr to ses header in request packet
 *      rsp_next_hdr    - address of location where identifer of ses header
 *                        format for response is to be returned, return
 *                        contents are only valid when function 0
 *      rsp_ses_hdr     - ptr to buffer where ses header for response is to
 *                        be returned, return contents are only valid
 *                        when function returns 0, buffer must be
 *                        large enough to hold maximum size ses response
 *      rsp_ses_hdr_len - address of location where length of ses header
 *                        for response is to be returned, return contents
 *                        are only valid when function returns 0
 *      ses_nack        - ptr to location where ses indicates whether pds
 *                        should send pds nack instead of pds ack, return
 *                        contents are only valid when function returns
 *                        0, true => pds must send nack
 *                        ses response state
 *      gtd_del         - ptr to location where ses indicates whether pds
 *                        needs to maintain ses response state, return
 *                        contents are only valid when function returns
 *                        0, true => pds must guarantee delivery of
 *                        ses response state
 *
 * returns:
 *   - 0 when ses response is to be returned to initiator
 *   - negative value corresponding to fabric errno on error
 */
static int uet_pds_to_ses_rx_req(uet_pkt_handle_t rx_pkt_handle,
				 struct uet_instance *uet,
				 struct uet_parsed_pkt *pp,
				 struct uet_pds_info *pds_info,
				 uet_next_hdr_t *rsp_next_hdr,
				 void *rsp_ses_hdr, size_t *rsp_ses_hdr_len,
				 bool *ses_nack, bool *gtd_del)
{
	uet_ses_rc_t ses_rc;
	uint16_t payload_len;
	uint32_t gen, ep_gen, job_id;
	bool first_msg_pkt;
	uet_ses_list_t list;
	struct uet_ep *uet_ep;
	struct uet_ses_req_std *ses_std_req;
	struct uet_ses_rsp *ses_rsp;
	struct uet_ses_rsp_d *rx_ses_rsp_d, *ses_rsp_d;
	struct uet_ipv4_ep_key ipv4_ep_key;
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
	ses_rsp->cmn.index_gen_job_id = ses_std_req->cmn.index_gen_job_id;

	switch (pp->next_hdr) {
	case UET_HDR_REQ_STD:
		ses_rsp->mod_len = ses_std_req->req_len;
		job_id = uet_get_std_req_job_id(ses_std_req);
		if (pp->ses_opcode != UET_DEFER_RTR) {
			uet_ipv4_ep_key_init(&ipv4_ep_key, pp);
			uet_ep = uet_ipv4_ep_hash_lookup(uet, &ipv4_ep_key);
			if (uet_ep == NULL) {
				UET_API_ERR("RX: Unknown Endpoint");
				ses_rc = UET_RC_UNDELIVERABLE;
				*gtd_del = true;
				goto build_response;
			}
		} else
			ses_rc = uet_rx_rtr_req_pkt(uet, pp, &uet_ep, gtd_del);
		if (uet_ep->job_id != job_id) {
			UET_API_ERR("RX: Bad Job ID");
			ses_rc = UET_RC_BAD_JOB_ID;
			*gtd_del = true;
			goto build_response;
		}
		break;
	case UET_HDR_RSP_DATA:
		rx_desc = uet_get_msg_id_rx_desc(
				uet, ntohs(rx_ses_rsp_d->cmn.msg_id));
		if (rx_desc == NULL) {
			UET_API_ERR("Read Rsp: Unknown Message ID");
			ses_rc = UET_RC_UNDELIVERABLE;
			*gtd_del = true;
			goto build_response;
		}
		uet_ep = rx_desc->uet_ep;
		job_id = (ntohl(rx_ses_rsp_d->cmn.index_gen_job_id) &
			  UET_SES_RSP_JOB_ID_MASK) >> UET_SES_RSP_JOB_ID_SHIFT;
		if (uet_ep->job_id != job_id) {
			UET_API_ERR("RX: Bad Job ID");
			ses_rc = UET_RC_BAD_JOB_ID;
			*gtd_del = true;
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
		return -EINVAL;
	}

	switch (pp->ses_opcode) {
	case UET_SEND:
	case UET_DEFER_SEND:
		ses_rc = uet_rx_req_pkt(uet_ep, pp, &list,
					false, false, gtd_del);
		ep_gen = (uint32_t) uet_ep->untagged_gen;
		break;
	case UET_TAGGED_SEND:
	case UET_DEFER_TSEND:
		ses_rc = uet_rx_req_pkt(uet_ep, pp, &list,
					true, false, gtd_del);
		ep_gen = (uint32_t) uet_ep->tagged_gen;
		break;
	case UET_DEFER_RTR:
		break;
	case UET_WRITE:
		ses_rc = uet_rx_req_pkt(uet_ep, pp, &list,
					false, true, gtd_del);
		if (ses_rc == UET_RC_UNCOR_TRNSNT)
			*ses_nack = true;
		ep_gen = (uint32_t) uet_ep->untagged_gen;
		break;
	case UET_READ:
		ses_rc = uet_rx_rd_req_pkt(uet_ep, pp, &list,
					   pds_info, &ack_d_info);
		if (ses_rc != UET_RC_OK) {
			*gtd_del = true;
			if (ses_rc == UET_RC_UNCOR_TRNSNT)
				*ses_nack = true;
		} else if (ack_d_info.valid)
			goto build_response_w_data;
		ep_gen = (uint32_t) uet_ep->untagged_gen;
		break;
	case UET_MSG_ERR:
		ses_rc = uet_rx_cancel_pkt(uet_ep, pp, gtd_del);
		break;
	default:
		UET_API_ERR("RX: Unsupported Opcode = 0x%x", pp->ses_opcode);
		ses_rc = uet_get_rx_desc(
				uet_ep, pp, false, UET_RC_UNSUPPORTED_OP,
				&msg_key, &rx_desc, &first_msg_pkt, gtd_del);
		break;
	}

build_response:
	if (ses_rc != UET_RC_OK) {
		ses_rsp->mod_len = 0;
		if (ses_rc == UET_RC_DEFER_SEND)
			ses_rc = UET_RC_OK;
	}
	ses_rsp->cmn.list_opcode = ((list << UET_SES_RSP_LIST_SHIFT) |
				    (UET_RESPONSE << UET_SES_OPCODE_SHIFT));
	ses_rsp->cmn.ver_ret_code = ((UET_SES_VER << UET_SES_VER_SHIFT) |
				     (ses_rc << UET_SES_RSP_RET_CODE_SHIFT));
	if (ses_rc == UET_RC_BAD_GENERATION) {
		/* return correct generation */
		gen = (ep_gen << UET_SES_RSP_INDEX_GEN_SHIFT);
		ses_rsp->cmn.index_gen_job_id = htonl(gen | job_id);
	}

	*rsp_ses_hdr_len = sizeof(struct uet_ses_rsp);
	*rsp_next_hdr = UET_HDR_RSP;

	return 0;

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
	ses_rsp_d->rsvd = 0;
	ses_rsp_d->payload_len = htons(payload_len);
	ses_rsp_d->mod_len = ses_std_req->req_len;
	ses_rsp_d->msg_off = htonl(ack_d_info.msg_off);

	memcpy(ses_rsp_d->payload, ack_d_info.buf, ack_d_info.payload_len);

	*rsp_ses_hdr_len =
		sizeof(struct uet_ses_rsp_d) + ack_d_info.payload_len;
	*rsp_next_hdr = UET_HDR_RSP_DATA;

	return 0;
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
 *      0 on success
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
	ses->cmn.index_gen_job_id = htonl(tx_desc->job_id <<
					  UET_SES_RSP_JOB_ID_SHIFT);
	ses->rsvd_payload_len = htonl(payload_len <<
				      UET_SES_RSP_D_PAYLOAD_LEN_SHIFT);
	pr_info("[%s][%d] rsvd_payload_len: %u payload_len: %lu\n",
		__func__, __LINE__, ses->rsvd_payload_len, payload_len);
	ses->mod_len = htonl(tx_desc->rd_rsp.mod_len);
	ses->msg_off = htonl(tx_desc->remote_msg_off);

	return 0;
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
 * build rtr request ses header for packet to be transmitted
 *
 * parms:
 *      tx_desc - transmit descriptor for message
 *      ses     - ptr to location where ses header is to be built
 *
 * returns:
 *      0 on success
 *      negative value corresponding to fabric errno on error
 */
static int uet_build_rtr_req_ses_hdr(struct uet_tx_desc *tx_desc,
				     struct uet_ses_req_std *ses)
{
	uint64_t local_token, remote_token;

	memset(ses, 0, sizeof(struct uet_ses_req_std));
	ses->cmn.eom_opcode = UET_SES_EOM_MASK |
			     (UET_DEFER_RTR << UET_SES_OPCODE_SHIFT);
	ses->cmn.ver_flags = (UET_SES_VER << UET_SES_VER_SHIFT) |
		UET_SES_REQ_FLAG_REL | UET_SES_REQ_FLAG_SOM;
	ses->cmn.msg_id = htons(tx_desc->msg_id);
	ses->cmn.index_gen_job_id =
		htonl(tx_desc->job_id << UET_SES_REQ_JOB_ID_SHIFT);
	ses->initiator = htonl(tx_desc->uet_ep->uet_addr.initiator_id);
	local_token = tx_desc->local_rtr_token;
	remote_token = tx_desc->remote_rtr_token;
	ses->restart_token_rtr = uet_build_ses_rtr_token(local_token,
							 remote_token);

	return 0;
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
 *      0 on success
 *      negative value corresponding to fabric errno on error
 */
static int uet_build_ses_hdr(struct uet_tx_desc *tx_desc, size_t pkt_len,
			     void *ses_hdr)
{
	struct uet_ses_req_std *ses;
	struct uet_av_entry *av;
	struct uet_ep *uet_ep;
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
		ses->msg_off_payload_len =
			htonll(((tx_desc->buf_desc.buf_off <<
				 UET_SES_REQ_STD_MSG_OFF_SHIFT) &
				UET_SES_REQ_STD_MSG_OFF_MASK) |
			       ((payload_len <<
				 UET_SES_REQ_STD_PAYLOAD_LEN_SHIFT) &
				UET_SES_REQ_STD_PAYLOAD_LEN_MASK));
	}

	if ((som && (payload_len == req_len)) ||
	    (!som && (payload_len == tx_desc->remaining_bytes)))
		eom = UET_SES_EOM_FLAG;

#if 0 // TODO: RAKHA
	if (tx_desc->op_flags & FI_DELIVERY_COMPLETE)
		dc = UET_SES_REQ_FLAG_DC;
#endif

	ses->cmn.ver_flags = (UET_SES_VER << UET_SES_VER_SHIFT) | dc |
		UET_SES_REQ_FLAG_REL | som;

	ses->cmn.index_gen_job_id = htonl(
		(av->untagged_gen << UET_SES_REQ_INDEX_GEN_SHIFT) |
		(tx_desc->job_id << UET_SES_REQ_JOB_ID_SHIFT));

	ses->buf_off = htonll(tx_desc->remote_start_off);

	if (tx_desc->cq_flags & UET_ACCESS_FLAG_MSG) {
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
	} else if (tx_desc->cq_flags & UET_ACCESS_FLAG_TAGGED) {
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
		ses->cmn.index_gen_job_id =
			htonl((av->tagged_gen << UET_SES_REQ_INDEX_GEN_SHIFT) |
			      (tx_desc->job_id << UET_SES_REQ_JOB_ID_SHIFT));
	} else if (tx_desc->cq_flags & UET_ACCESS_FLAG_WRITE) {
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
			if (tx_desc->cq_flags & UET_ACCESS_FLAG_MSG)
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
		ses->msg_off_payload_len =
			htonll((tx_desc->buf_desc.buf_off <<
				UET_SES_REQ_STD_MSG_OFF_SHIFT) &
			       UET_SES_REQ_STD_MSG_OFF_MASK);
		eom = UET_SES_EOM_FLAG;
	}

	ses->cmn.eom_opcode =
		(eom << UET_SES_EOM_SHIFT) | (opcode << UET_SES_OPCODE_SHIFT);
	ses->cmn.rsvd_res_index = htons(av->addr->start_index <<
					UET_SES_REQ_RES_INDEX_SHIFT);
	ses->cmn.rsvd_pid_on_fep = htons(av->addr->pid_on_fep <<
					 UET_SES_REQ_PID_ON_FEP_SHIFT);
	ses->cmn.msg_id = htons(tx_desc->msg_id);
	ses->initiator = htonl(uet_ep->uet_addr.initiator_id);
	ses->req_len = htonl((uint32_t) req_len);
	pr_info("[%s:%d][TX] req_len: %lu\n", __func__, __LINE__, req_len);

	return 0;
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
 *      0 when ack processed
 *      negative value corresponding to fabric errno on error
 */
static int uet_pds_to_ses_rx_rsp(uet_pkt_handle_t tx_pkt_handle,
				 struct uet_parsed_pkt *rsp_pp)
{
	uint8_t opcode;
	uint32_t mod_len, rx_gen;
	uet_ses_rc_t ses_rc;
	struct uet_ses_rsp *ses_rsp;
	struct uet_ses_rsp_d *ses_rsp_d;
	struct uet_tx_desc *tx_desc;
	struct uet_av_entry *av_entry;

	tx_desc = (struct uet_tx_desc *) tx_pkt_handle;
	ses_rsp = (struct uet_ses_rsp *) rsp_pp->ses;
	ses_rsp_d = (struct uet_ses_rsp_d *) rsp_pp->ses;
	opcode = rsp_pp->ses_opcode;

	ses_rc = ((ses_rsp->cmn.ver_ret_code & UET_SES_RSP_RET_CODE_MASK) >>
		  UET_SES_RSP_RET_CODE_SHIFT);

	tx_desc->unack_pkts--;

	if (tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_REQ) {
		if ((opcode == UET_RESPONSE_W_DATA) ||
		    ((opcode == UET_RESPONSE) && (ses_rc != UET_RC_OK)))
			tx_desc->rx_desc->expected_rd_rsp--;
	}

	switch (tx_desc->state) {
	case UET_TX_DESC_STATE_ACTIVE:
	case UET_TX_DESC_STATE_WAIT:
		break;
	default:
		return 0;
	}

	/* check opcode */
	switch (opcode) {
	case UET_RESPONSE:
		mod_len = ntohl(ses_rsp->mod_len);
		break;
	case UET_RESPONSE_W_DATA:
		mod_len = ntohl(ses_rsp_d->mod_len);
		break;
	case UET_NO_RESPONSE:
	case UET_DEFAULT_RESPONSE:
		return 0;
	default:
		UET_API_ERR("Msg Rsp: Unsupported Opcode = 0x%x", opcode);
		goto err_exit;
	}

	/* check return code */
	switch (ses_rc) {
	case UET_RC_OK:
		if (opcode == UET_RESPONSE_W_DATA) {
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
			((ntohl(ses_rsp->cmn.index_gen_job_id) &
			  UET_SES_RSP_INDEX_GEN_MASK) >>
			 UET_SES_RSP_INDEX_GEN_SHIFT);
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
	case UET_RC_BAD_ADDR:
		UET_API_ERR("Msg Rsp: Bad Address");
		goto err_exit;
	case UET_RC_UNDELIVERABLE:
		UET_API_ERR("Msg Rsp: Undeliverable");
		goto err_exit;
	case UET_RC_DROPPED:
		UET_API_ERR("Msg Rsp: Dropped by Dest");
		goto err_exit;
	case UET_RC_UNCOR_TRNSNT:
		UET_API_ERR("Msg Rsp: Transient Error");
		goto err_exit;
	default:
		UET_API_ERR("Msg Rsp: SES RC = 0x%x", ses_rc);
		goto err_exit;
	}

	return 0;

defer_exit:
	tx_desc->desc_flags |= UET_TX_DESC_FLAG_CANCEL_PENDING;
	tx_desc->state = UET_TX_DESC_STATE_DEFER;
	return 0;

retx_exit:
	if ((tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_RSP) ||
	    (tx_desc->desc_flags & UET_TX_DESC_FLAG_RTR_REQ))
		goto err_exit;
	tx_desc->desc_flags |= UET_TX_DESC_FLAG_CANCEL_PENDING;
	tx_desc->state = UET_TX_DESC_STATE_RETX;
	return 0;

err_exit:
	tx_desc->err_code = EIO;
	if (!((tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_RSP) ||
	      (tx_desc->desc_flags & UET_TX_DESC_FLAG_RTR_REQ)))
		tx_desc->desc_flags |= UET_TX_DESC_FLAG_CANCEL_PENDING;
	tx_desc->state = UET_TX_DESC_STATE_ERR;
	return 0;
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
 *      0 on success
 *      negative value corresponding to fabric errno on error
 */
static int uet_pds_to_ses_pds_err(uet_pkt_handle_t tx_pkt_handle,
				  uet_pds_err_code_t reason)
{
	return 0;
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
 *      0 on success
 *      negative value corresponding to fabric errno on error
 */
static int uet_addr_resolution(struct uet_addr *uet_addr, uint32_t *job_id)
{
	uet_addr->pid_on_fep = UET_ADDR_DEF_PID_ON_FEP;
	uet_addr->num_indices = 1;
	uet_addr->start_index = UET_ADDR_DEF_INDEX;
	uet_addr->initiator_id = UET_ADDR_DEF_INITIATOR_ID;

	uet_addr->flags |= (UET_ADDR_PID_ON_FEP_V | UET_ADDR_INDEX_V |
			    UET_ADDR_INITIATOR_V);

	*job_id = UET_DEF_JOB_ID;

	return 0;
}

/* send cancel message */
static int uet_tx_cancel(struct uet_tx_desc *tx_desc)
{
	int rc;
	struct uet_ses_req_std ses;
	struct uet_pds *pds = &tx_desc->uet_ep->uet_domain->uet->pds;

	if (tx_desc->remaining_bytes == 0) {
		tx_desc->desc_flags &= ~UET_TX_DESC_FLAG_CANCEL_PENDING;
		return 0;
	}

	uet_build_ses_hdr(tx_desc, 0, &ses);

	rc = pds->downcall.tx_pkt((uet_pkt_handle_t) tx_desc, tx_desc->uet_ep,
				  tx_desc->dst_addr_handle, tx_desc->pds_mode,
				  UET_PDS_FLAG_EOM, NULL, tx_desc->msg_id,
				  UET_HDR_REQ_STD, &ses,
				  sizeof(struct uet_ses_req_std),
				  NULL, 0, false);

	if (rc == 0) {
		tx_desc->unack_pkts++;
		tx_desc->desc_flags &= ~UET_TX_DESC_FLAG_CANCEL_PENDING;

	} else if (rc != -EAGAIN) {
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

	rc = pds->downcall.tx_pkt((uet_pkt_handle_t) tx_desc, tx_desc->uet_ep,
				  tx_desc->dst_addr_handle, tx_desc->pds_mode,
				  UET_PDS_FLAG_SOM | UET_PDS_FLAG_EOM, NULL,
				  tx_desc->msg_id, UET_HDR_REQ_STD, &ses,
				  sizeof(struct uet_ses_req_std),
				  NULL, 0, false);

	if (rc == 0) {
		tx_desc->unack_pkts++;
		tx_desc->state = UET_TX_DESC_STATE_WAIT;
	} else if (rc != -EAGAIN)
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

	if (uet_get_pds_mode(tx_desc->uet_ep) != UET_PDS_MODE_RUD)
		return;

	if (!((tx_desc->cq_flags & UET_ACCESS_FLAG_MSG) || (tx_desc->cq_flags & UET_ACCESS_FLAG_TAGGED)))
		return;

	uet = tx_desc->uet_ep->uet_domain->uet;
	req_len = tx_desc->buf_desc.len;

	if (tx_desc->cq_flags & UET_ACCESS_FLAG_MSG) {
		if (req_len < uet->msg_rndz_size)
			return;
	} else {
		if (req_len < uet->tag_rndz_size)
			return;
	}

	if (uet_alloc_tx_rtr_token(uet,
				   &tx_desc->local_rtr_token) != 0)
		return;

	uet_init_tx_rtr_token(uet, tx_desc);
}

/* uet message transmission */
static int uet_tx_msg(struct uet_tx_desc *tx_desc)
{
	int rc;
	struct uet_ep *uet_ep;
	struct uet_pds *pds;
	struct uet_ses_req_std ses_req;
	struct uet_ses_rsp_d ses_rsp_d;
	uet_pds_tx_flags_t flags;
	size_t payload_len, max_payload_len, ses_len, pkt_len;
	void *ses, *pkt_buf;
	uet_next_hdr_t next_hdr;
	struct uet_pds_info *pds_info;

	uet_ep = tx_desc->uet_ep;
	pds = &uet_ep->uet_domain->uet->pds;

	if (tx_desc->remaining_bytes == tx_desc->buf_desc.len) {
		flags = UET_PDS_FLAG_SOM;
		uet_dsend_init(tx_desc);
	} else
		flags = UET_PDS_FLAG_NONE;

	max_payload_len = uet_ep->uet_domain->uet->max_payload_len;
	while (tx_desc->remaining_bytes) {
		if (tx_desc->remaining_bytes > max_payload_len)
			payload_len = max_payload_len;
		else {
			payload_len = tx_desc->remaining_bytes;
			flags |= UET_PDS_FLAG_EOM;
		}

		if (tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_REQ) {
			pkt_len = 0;
			if (flags & UET_PDS_FLAG_SOM)
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
			pds_info = NULL;
			next_hdr = UET_HDR_REQ_STD;
			ses = &ses_req;
			ses_len = sizeof(struct uet_ses_req_std);
		}

		/* TODO: add support for iov and dma'able buffers */
		pkt_buf = (void *) (((size_t) tx_desc->buf_desc.buf) +
				    tx_desc->buf_desc.buf_off);
		uet_build_ses_hdr(tx_desc, pkt_len, ses);
		rc = pds->downcall.tx_pkt((uet_pkt_handle_t) tx_desc, uet_ep,
					  tx_desc->dst_addr_handle,
					  tx_desc->pds_mode,
					  flags, pds_info, tx_desc->msg_id,
					  next_hdr, ses, ses_len,
					  pkt_buf, pkt_len, false);
		if (rc == 0) {
			tx_desc->unack_pkts++;
			/* TODO: add iov support */
			tx_desc->buf_desc.buf_off += payload_len;
			tx_desc->remaining_bytes -= payload_len;
			if (tx_desc->desc_flags & UET_TX_DESC_FLAG_READ_REQ)
				tx_desc->rx_desc->expected_rd_rsp++;
		} else {
			if (rc != -EAGAIN)
				uet_tx_desc_set_err(tx_desc, -rc,
					UET_TX_DESC_STATE_ERR_COMPLETE);
			break;
		}
	}

	return rc;
}

/* transmit message data if available */
static void uet_tx_msg_try(struct uet_ep *uet_ep)
{
	int rc;
	size_t i;
	uint64_t now;
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

		uet_tx_desc_state_transition(tx_desc);

		switch (tx_desc->state) {
		case UET_TX_DESC_STATE_ACTIVE:
			rc = uet_tx_msg(tx_desc);
			if (rc == -EAGAIN) {
				uet_tx_desc_ring_rotate(tx_desc);
				continue;
			} else if ((rc != 0) &&
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
			pr_info("uet: posting in send cq.\n");
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
static void uet_rx_msg_age(struct uet_ep *uet_ep, uint64_t now)
{
	struct uet_rx_desc *rx_desc;
	uint64_t idle_time;

	while (1) {
		if (uet_list_empty(&uet_ep->rx_desc_active_list_head))
			return;
		rx_desc = container_of(uet_ep->rx_desc_active_list_head.next,
				       struct uet_rx_desc, list_entry);
		idle_time = now - rx_desc->prev_pkt_time;
		if (idle_time < uet_ep->uet_domain->uet->idle_rx_msg_timeout)
			break;
		if (rx_desc->desc_flags & UET_RX_DESC_FLAG_READ_RSP) {
			UET_API_ERR("Read Response Timeout");
			uet_rx_desc_active_list_remove(rx_desc);
			uet_tx_desc_set_err(rx_desc->tx_desc, EIO,
					    UET_TX_DESC_STATE_ERR_COMPLETE);
		} else {
			UET_API_ERR("RX Message Timeout");
			uet_rx_cq_post_err(rx_desc, EIO);
		}
	}
}

/* age out deferred send messages that have gone idle */
static void uet_dsend_msg_age(struct uet_ep *uet_ep, uint64_t now)
{
	struct uet_tx_desc *tx_desc;
	uint64_t idle_time;

	while (1) {
		if (uet_list_empty(&uet_ep->tx_desc_defer_list_head))
			return;
		tx_desc = container_of(uet_ep->tx_desc_defer_list_head.next,
				       struct uet_tx_desc, list_entry);
		idle_time = now - tx_desc->defer_time;
		if (idle_time < uet_ep->uet_domain->uet->idle_dsend_msg_timeout)
			break;
		UET_API_ERR("Deferred Send Message Timeout");
		uet_tx_cq_post_err(tx_desc, EIO);
	}
}

/* common code for aging list of rtr messages */
static void uet_rtr_msg_age_common(struct uet_ep *uet_ep,
				   struct uet_list_entry *list_head, uint64_t now)
{
	struct uet_instance *uet;
	struct uet_tx_desc *tx_desc;
	uint64_t idle_time, timeout;

	uet = uet_ep->uet_domain->uet;
	timeout = uet->idle_rtr_msg_timeout;

	while (1) {
		if (uet_list_empty(list_head))
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
static void uet_rtr_msg_age(struct uet_ep *uet_ep, uint64_t now)
{
	uet_rtr_msg_age_common(uet_ep,
			       &uet_ep->tx_desc_buf_rtr_list_head, now);
	uet_rtr_msg_age_common(uet_ep,
			       &uet_ep->tx_desc_buf_tag_rtr_list_head, now);
}

/* age out messages that have gone idle to reclaim stranded resources */
static void uet_msg_age(struct uet_ep *uet_ep)
{
	uint64_t now;

	uet_gettime(&now);

	uet_rx_msg_age(uet_ep, now);
	uet_dsend_msg_age(uet_ep, now);
	uet_rtr_msg_age(uet_ep, now);
}

/* initiate transmit of ready to restart if appropriate */
static void uet_tx_rtr_try(struct uet_ep *uet_ep, struct uet_rx_desc *rx_desc,
			   uet_recv_api_t recv_api)
{
	struct uet_tx_desc *tx_desc;
	struct uet_list_entry *head, *item;

	switch (recv_api) {
	case UET_RECV_API:
		head = &uet_ep->tx_desc_buf_rtr_list_head;
		if (!uet_list_empty(head)) {
			tx_desc = container_of(head->next, struct uet_tx_desc,
					       list_entry);
			goto initiate_rtr;
		}
		break;
	case UET_TRECV_API:
		head = &uet_ep->tx_desc_buf_tag_rtr_list_head;
		uet_list_foreach(head, item) {
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

/* common function for recv api's                    */
/*   - the recv_api determines which parms are valid */
ssize_t uet_recv_api_common(uet_recv_api_t recv_api, 
		uet_ep_handle_t ep_handle, uint32_t job_id, 
		void *buf, size_t len, uet_mr_handle_t mr_handle, 
		uet_addr_handle_t src_addr_handle, uint64_t tag, 
		uint64_t ignore, void *context)
{
	struct uet_ep *uet_ep;
	struct uet_rx_desc *rx_desc;
	struct uet_av_entry *av_entry;

	uet_ep = (struct uet_ep *) ep_handle;

	/* check that rx completion queue is bound to endpoint */
	if (uet_ep->recv_cq.cq_state == UET_CQ_DOWN) {
		UET_API_ERR("No RX Completion Q");
		return -EIO;
	}

	if (recv_api == UET_TRECV_API) {
		/* check that ignore bits are not specified */
		if (ignore != UET_EXACT_MATCH) {
			UET_API_ERR(
				"Wildcard Tags Not Supported for uet_trecv()");
			return -EINVAL;
		}
	}

	/* allocate rx descriptor */
	rx_desc = uet_rx_desc_list_pop(uet_ep);
	if (rx_desc == NULL)
		return -EAGAIN;

	/* init msg descriptor */
	memset(rx_desc, 0, sizeof(struct uet_rx_desc));
	rx_desc->desc_flags = UET_RX_DESC_FLAG_POST_CQ;
	rx_desc->buf_desc.type = UET_MSG_BUF_TYPE_CONTIG;
	rx_desc->buf_desc.buf = buf;
	rx_desc->buf_desc.len = len;
	rx_desc->context = context;
	rx_desc->ses_rc = UET_RC_OK;
	rx_desc->uet_ep = uet_ep;

	switch (recv_api) {
	case UET_RECV_API:
		rx_desc->cq_flags = UET_ACCESS_FLAG_RECV | UET_ACCESS_FLAG_MSG;

		/* insert msg descriptor in rx ring of endpoint */
		uet_rx_desc_ring_insert(rx_desc);

		if (uet_ep->untagged_gen_disabled) {
			/* re-enable generation */
			uet_ep->untagged_gen++;
			uet_ep->untagged_gen_disabled = false;
		}
		break;
	case UET_TRECV_API:
		rx_desc->cq_flags = UET_ACCESS_FLAG_RECV | UET_ACCESS_FLAG_TAGGED;

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

	return 0;
}

/* common function for api's that send requests          */
/*   - the send_req_api determines which parms are valid */
ssize_t uet_send_req_api_common(
	uet_send_req_api_t send_req_api, 
	uet_ep_handle_t ep_handle, uint32_t job_id, void *buf, 
	size_t len, uet_mr_handle_t mr_handle, 
	uet_addr_handle_t dst_addr_handle, uint64_t tag, 
	uint64_t *imm_data, uint64_t remote_mem_addr, 
	uint64_t remote_key, void *context)
{
	int rc;
	uint16_t msg_id;
	struct uet_instance *uet;
	struct uet_ep *uet_ep;
	struct uet_tx_desc *tx_desc;
	struct uet_rx_desc *rx_desc;
	struct uet_av_entry *av_entry;

	uet_ep = (struct uet_ep *) ep_handle;
	uet = uet_ep->uet_domain->uet;
	av_entry = (struct uet_av_entry *) dst_addr_handle;

	/* check that tx completion queue is bound to endpoint */
	if (uet_ep->send_cq.cq_state == UET_CQ_DOWN) {
		UET_API_ERR("No TX Completion Q");
		return -EIO;
	}

	/* check next-hop mac address */
	if (!(av_entry->flags & UET_NH_MAC_ADDR_V)) {
		rc = uet_nic_get_ipv4_nh(UET_NIC(uet), av_entry->addr->fa.v4,
					 av_entry->nh_mac_addr);
		if (rc != 0)
			return rc;
		av_entry->flags |= UET_NH_MAC_ADDR_V;
	}

	/* allocate msg id */
	rc = uet_alloc_msg_id(uet, &msg_id);
	if (rc != 0)
		return rc;

	/* allocate tx descriptor */
	tx_desc = uet_tx_desc_list_pop(uet_ep);
	if (tx_desc == NULL) {
		uet_dealloc_msg_id(uet, msg_id);
		return -EAGAIN;
	}

	/* allocate rx descriptor for read */
	if (send_req_api == UET_READ_API) {
		rx_desc = uet_rx_desc_list_pop(uet_ep);
		if (rx_desc == NULL) {
			uet_dealloc_msg_id(uet, msg_id);
			uet_tx_desc_list_insert(tx_desc);
			return -EAGAIN;
		}
		/* init rx descriptor */
		memset(rx_desc, 0, sizeof(struct uet_rx_desc));
		rx_desc->desc_flags =
			UET_RX_DESC_FLAG_POST_CQ | UET_RX_DESC_FLAG_READ_RSP;
		rx_desc->buf_desc.type = UET_MSG_BUF_TYPE_CONTIG;
		rx_desc->buf_desc.buf = buf;
		rx_desc->buf_desc.len = len;
		rx_desc->msg_len = len;
		rx_desc->remaining_bytes = len;
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
	tx_desc->buf_desc.type = UET_MSG_BUF_TYPE_CONTIG;
	tx_desc->buf_desc.buf = buf;
	tx_desc->buf_desc.len = len;
	tx_desc->remaining_bytes = len;
	tx_desc->context = context;
	tx_desc->dst_addr_handle = dst_addr_handle;
	tx_desc->job_id = job_id;
	tx_desc->msg_id = msg_id;
	tx_desc->uet_ep = uet_ep;
	tx_desc->backoff_max = UET_INITIAL_BACKOFF_MAX;
	tx_desc->pds_mode = uet_get_pds_mode(uet_ep);
	if (tx_desc->pds_mode == UET_PDS_MODE_ROD)
		tx_desc->seq_num = uet_alloc_av_msg_seq_num(av_entry);
	uet_gettime(&tx_desc->tx_time);

	switch (send_req_api) {
	case UET_SEND_API:
		tx_desc->cq_flags = UET_ACCESS_FLAG_SEND | UET_ACCESS_FLAG_MSG;
		break;
	case UET_TSEND_API:
		tx_desc->cq_flags = UET_ACCESS_FLAG_SEND | UET_ACCESS_FLAG_TAGGED;
		tx_desc->tag_or_immdata = tag;
		break;
	case UET_WRITE_API:
		if (imm_data) {
			tx_desc->desc_flags |= UET_TX_DESC_FLAG_IMM_DATA_VALID;
			tx_desc->tag_or_immdata = *imm_data;
		}
		tx_desc->cq_flags = UET_ACCESS_FLAG_RMA | UET_ACCESS_FLAG_WRITE;
		tx_desc->remote_start_off = remote_mem_addr;
		tx_desc->remote_key = remote_key;
		break;
	case UET_READ_API:
		tx_desc->desc_flags |= UET_TX_DESC_FLAG_READ_REQ;
		tx_desc->cq_flags = UET_ACCESS_FLAG_RMA | UET_ACCESS_FLAG_READ;
		tx_desc->remote_start_off = remote_mem_addr;
		tx_desc->remote_key = remote_key;
		tx_desc->rx_desc = rx_desc;
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

	return 0;
}

static void uet_instance_task(struct tasklet_struct *task)
{
	struct uet_instance *uet = 
		container_of(task, struct uet_instance, task);
	unsigned long flags;

	spin_lock_irqsave(&uet->biglock, flags);

	spin_unlock_irqrestore(&uet->biglock, flags);
}

int uet_initialize_internal(uet_handle_t *handle)
{
	int rc;
	struct uet_instance *uet;

	uet = kcalloc(1, sizeof(struct uet_instance), GFP_KERNEL);
	if (uet == NULL) {
		UET_API_PRINT_ERRNO("kcalloc");
		rc = -ENOMEM;
		goto err_return;
	}

	uet_list_init(&uet->domain_list_head);

	uet->uet_ipproto = UET_IPPROTO;
	uet->uet_udp_port = UET_UDP_PORT;
	uet->idle_rx_msg_timeout = UET_IDLE_RX_MSG_TIMEOUT;
	uet->idle_dsend_msg_timeout = UET_IDLE_DSEND_MSG_TIMEOUT;
	uet->idle_rtr_msg_timeout = UET_IDLE_RTR_MSG_TIMEOUT;
	uet->max_rtr_q_entries = UET_RTR_Q_ENTRIES_MAX;
	uet->max_msg_retransmits = UET_MSG_RETRANSMIT_MAX;
	uet->default_msg_ip_tos = uet_dscp_to_tos(UET_IP_DEFAULT_MSG_DSCP);
	uet->msg_rndz_size = UET_MSG_RENDEZVOUS_SIZE;
	uet->tag_rndz_size = UET_TAG_RENDEZVOUS_SIZE;

	uet->pds.upcall.rx_req = uet_pds_to_ses_rx_req;
	uet->pds.upcall.rx_rsp = uet_pds_to_ses_rx_rsp;
	uet->pds.upcall.pds_err = uet_pds_to_ses_pds_err;

	uet_rw_lock_init(&uet->ipv4_ep_lkup_lock);

	spin_lock_init(&uet->biglock);
	tasklet_setup(&uet->task, uet_instance_task);

	rc = uet_pds_init(uet);
	if (rc != 0)
		goto err_return;

	UET_NIC(uet)->uet_ipproto = uet->uet_ipproto;
	rc = uet_nic_initialize(UET_NIC(uet));
	if (rc != 0)
		goto err_return;

	uet->max_payload_len = UET_DEFAULT_MAX_PAYLOAD_LEN;

	*handle = uet;
	return 0;

err_return:
	if (uet != NULL)
		kfree(uet);
	return rc;
}

int uet_finalize_internal(uet_handle_t handle)
{
	struct uet_instance *uet;

	uet = (struct uet_instance *) handle;
	uet_finalize_core(uet);
	kfree(uet);

	return 0;
}

int uet_nic_getinfo_internal(uet_handle_t handle, 
		struct uet_nic_info *nic_info)
{
	int rc;
	struct uet_instance *uet;

	uet = (struct uet_instance *) handle;

	rc = uet_nic_getinfo(UET_NIC(uet), nic_info);

	return rc;
}

int uet_get_nic_addr_ipv4_internal(uet_handle_t handle, 
		uint32_t *ipv4_addr)
{
	struct uet_instance *uet;
	uet = (struct uet_instance *) handle;
	memcpy(ipv4_addr, &uet->nic.ipv4_addr, sizeof(uint32_t));
	return 0;
}

int uet_domain_internal(uet_handle_t handle, size_t mr_cnt, 
		int mr_mode, void *context, 
		uet_domain_handle_t *domain_handle)
{
	int rc;
	struct uet_instance *uet;
	struct uet_domain *uet_dom;

	uet = (struct uet_instance *) handle;

	/* allocate memory for domain object */
	uet_dom = kcalloc(1, sizeof(struct uet_domain), GFP_KERNEL);
	if (uet_dom == NULL) {
		UET_API_PRINT_ERRNO("kcalloc");
		rc = -ENOMEM;
		goto err_exit;
	}

	/* check requested memory region count */
	if (mr_cnt > UET_MR_KEY_MAX_RKEY) {
		UET_API_ERR("Requested memory region count exceeds max");
		rc = -EINVAL;
		goto err_exit;
	}

	/* allocate memory for memory region descriptors */
	if (mr_cnt > UET_DEF_MR_CNT)
		uet_dom->num_mr = mr_cnt;
	else
		uet_dom->num_mr = UET_DEF_MR_CNT;
	uet_dom->mr_desc = kcalloc(uet_dom->num_mr,
				 sizeof(struct uet_mr_desc), GFP_KERNEL);
	if (uet_dom->mr_desc == NULL) {
		UET_API_PRINT_ERRNO("kcalloc");
		rc = -ENOMEM;
		goto err_exit;
	}

	/* allocate memory for memory region allocation state */
	uet_dom->mr_desc_alloc_cb.state = kcalloc(uet_dom->num_mr,
						 sizeof(uint8_t), GFP_KERNEL);
	if (uet_dom->mr_desc_alloc_cb.state == NULL) {
		UET_API_PRINT_ERRNO("kcalloc");
		rc = -ENOMEM;
		goto err_exit;
	}

	/* init memory region allocation state */
	if (uet_dom->num_mr > (UET_MR_KEY_OPTIMIZED_MAX_RKEY + 1))
		uet_dom->mr_desc_alloc_cb.next_mr_index =
					UET_MR_KEY_OPTIMIZED_MAX_RKEY + 1;

	/* init domain object */
	uet_dom->uet = uet;
	uet_dom->mr_mode = mr_mode;
	uet_dom->context = context;
	uet_list_init(&uet_dom->ep_list_head);
	uet_list_init(&uet_dom->av_list_head);
	uet_rw_lock_init(&uet_dom->ep_lock);

	/* insert object into domain list */
	uet_domain_insert(uet_dom);

	*domain_handle = uet_dom;
	return 0;

err_exit:
	if (uet_dom) {
		if (uet_dom->mr_desc_alloc_cb.state)
			kfree(uet_dom->mr_desc_alloc_cb.state);
		if (uet_dom->mr_desc)
			kfree(uet_dom->mr_desc);
		kfree(uet_dom);
	}
	return rc;
}

int uet_domain_close_internal(uet_domain_handle_t domain_handle)
{
	struct uet_domain *uet_dom;
	struct uet_pds *pds;

	uet_dom = (struct uet_domain *) domain_handle;
	pds = &uet_dom->uet->pds;

	pds->downcall.finalize(uet_dom->uet);

	if (uet_domain_has_ep(uet_dom)) {
		UET_API_ERR("EPs associated with domain being closed");
		return -EBUSY;
	}

	uet_domain_free(uet_dom);
	return 0;
}

int uet_endpoint_internal(uet_domain_handle_t domain_handle,
	void *src_addr, int32_t src_addrlen, int32_t num_rx_desc, 
	int32_t num_tx_desc, uet_pds_mode_t pds_mode,
	uint32_t tclass, int use_default_tos, void *context, 
	uet_ep_handle_t *ep_handle)
{
	int rc;
	size_t i;
	struct uet_domain *uet_dom;
	struct uet_ep *uet_ep;
	struct uet_pds *pds;

	uet_dom = (struct uet_domain *) domain_handle;
	pds = &uet_dom->uet->pds;

	/* allocate memory for ep object */
	uet_ep = kcalloc(1, sizeof(struct uet_ep), GFP_KERNEL);
	if (uet_ep == NULL) {
		UET_API_PRINT_ERRNO("kcalloc");
		rc = -ENOMEM;
		goto err_exit;
	}

	/* init ep object */
	memcpy(&uet_ep->uet_addr, src_addr, src_addrlen);
	rc = uet_addr_resolution(&uet_ep->uet_addr, &uet_ep->job_id);
	if (rc != 0) {
		UET_API_ERR("uet_addr_resolution");
		goto err_exit;
	}
	uet_ep->ipv4_addr = uet_ep->uet_addr.fa.v4;

	uet_ep->num_rx_desc = num_rx_desc;
	uet_ep->rx_desc = kcalloc(uet_ep->num_rx_desc,
				 sizeof(struct uet_rx_desc), GFP_KERNEL);
	if (uet_ep->rx_desc == NULL) {
		UET_API_PRINT_ERRNO("kcalloc");
		rc = -ENOMEM;
		goto err_exit;
	}

	uet_list_init(&uet_ep->rx_desc_list_head);
	uet_list_init(&uet_ep->rx_desc_active_list_head);
	uet_list_init(&uet_ep->mr_list_head);

	for (i = 0; i < uet_ep->num_rx_desc; i++) {
		uet_ep->rx_desc[i].uet_ep = uet_ep;
		uet_rx_desc_list_insert(&uet_ep->rx_desc[i]);
	}

	uet_ep->num_tx_desc = num_tx_desc;
	uet_ep->tx_desc = kcalloc(uet_ep->num_tx_desc,
				 sizeof(struct uet_tx_desc), GFP_KERNEL);
	if (uet_ep->tx_desc == NULL) {
		UET_API_PRINT_ERRNO("kcalloc");
		rc = -ENOMEM;
		goto err_exit;
	}

	uet_list_init(&uet_ep->tx_desc_list_head);
	uet_list_init(&uet_ep->tx_desc_defer_list_head);
	uet_list_init(&uet_ep->tx_desc_buf_rtr_list_head);
	uet_list_init(&uet_ep->tx_desc_buf_tag_rtr_list_head);

	for (i = 0; i < uet_ep->num_tx_desc; i++) {
		uet_ep->tx_desc[i].uet_ep = uet_ep;
		uet_tx_desc_list_insert(&uet_ep->tx_desc[i]);
	}

	rc = uet_ring_init(&uet_ep->rx_ring,
			   sizeof(struct uet_rx_desc_ring_entry),
			   uet_ep->num_rx_desc);
	if (rc != 0) {
		UET_API_ERR("uet_ring_init");
		goto err_exit;
	}

	rc = uet_ring_init(&uet_ep->tx_ring,
			   sizeof(struct uet_tx_desc_ring_entry),
			   uet_ep->num_tx_desc);
	if (rc != 0) {
		UET_API_ERR("uet_ring_init");
		goto err_exit;
	}

	uet_ep->uet_domain = uet_dom;
	uet_ep->pds_mode = pds_mode;
	uet_ep->context = context;
	uet_ep->send_cq.cq_state = UET_CQ_DOWN;
	uet_ep->recv_cq.cq_state = UET_CQ_DOWN;

	uet_ep->ipv4_ep_key.ipv4_addr = uet_ep->ipv4_addr;
	uet_ep->ipv4_ep_key.pid_on_fep = uet_ep->uet_addr.pid_on_fep;
	uet_ep->ipv4_ep_key.index = uet_ep->uet_addr.start_index;
	uet_ipv4_ep_hash_insert(uet_ep);

	if (use_default_tos)
		uet_ep->msg_ip_tos = uet_dom->uet->default_msg_ip_tos;
	else
		uet_ep->msg_ip_tos = uet_dscp_to_tos(tclass);

	pds->downcall.ep_initialize(uet_ep);
	uet_ep->ep_state = UET_EP_DISABLED;

	/* insert object into ep list */
	uet_ep_insert(uet_ep);

	*ep_handle = uet_ep;
	return 0;

err_exit:
	if (uet_ep) {
		uet_desc_free(uet_ep);
		kfree(uet_ep);
	}
	return rc;
}

int uet_getname_internal(uet_ep_handle_t ep_handle, 
			struct uet_addr *uet_addr)
{
	struct uet_ep *uet_ep;

	uet_ep = (struct uet_ep *) ep_handle;
	*uet_addr = uet_ep->uet_addr;

	return 0;
}

int uet_ep_bind_cq_internal(uet_ep_handle_t ep_handle, 
		uint64_t cq_flags, enum uet_cq_type cq_type, 
		size_t cq_size, void *context, 
		uet_cq_handle_t *cq_handle)
{
	struct uet_ep *uet_ep;
	size_t num_desc, num_cq_entries;
	struct uet_cq *uet_cq;
	int rc, both_flags = UET_ACCESS_FLAG_SEND | UET_ACCESS_FLAG_RECV;

	uet_ep = (struct uet_ep *) ep_handle;

	/* check cq_flags to determine cq type                      */
	/*   - one and only one of FI_SEND & FI_RECV must be set */
	if (cq_flags & UET_ACCESS_FLAG_SELECTIVE_COMPLETION) {
		UET_API_ERR("Selective Completion Not Supported");
		return -EINVAL;
	}
	if (!(cq_flags & both_flags) ||
	    ((cq_flags & both_flags) == both_flags)) {
		UET_API_ERR("Shared TX/RX CQ Not Supported");
		return -EINVAL;
	}
	if (cq_flags & UET_ACCESS_FLAG_SEND) {
		if (uet_ep_has_send_cq(uet_ep)) {
			UET_API_ERR("Multiple TX CQs per EP Not Supported");
			return -EINVAL;
		}
		uet_cq = &uet_ep->send_cq;
		num_desc = uet_ep->num_tx_desc;
	} else {
		if (uet_ep_has_recv_cq(uet_ep)) {
			UET_API_ERR("Multiple RX CQs per EP Not Supported");
			return -EINVAL;
		}
		uet_cq = &uet_ep->recv_cq;
		num_desc = uet_ep->num_rx_desc;
	}

	/* determine number of cq entries                                    */
	/*   - make sure there is a cq entry for every outstanding operation */
	num_cq_entries = uet_max(cq_size, num_desc);

	/* init cq */
	rc = uet_ring_init(&uet_cq->ring, sizeof(struct uet_cq_ring_entry),
			   num_cq_entries);
	if (rc != 0) {
		UET_API_ERR("uet_ring_init");
		return rc;
	}
	uet_cq->cq_state = UET_CQ_UP;
	uet_cq->uet_ep = uet_ep;
	uet_cq->context = context;
	uet_cq->cq_type = cq_type;

	*cq_handle = uet_cq;
	return 0;
}

int uet_ep_enable_internal(uet_ep_handle_t ep_handle)
{
	struct uet_ep *uet_ep;

	uet_ep = (struct uet_ep *) ep_handle;
	uet_ep->ep_state = UET_EP_ENABLED;

	return 0;
}


int uet_ep_close_internal(uet_ep_handle_t ep_handle)
{
	struct uet_ep *uet_ep;
	struct uet_pds *pds;

	uet_ep = (struct uet_ep *) ep_handle;
	pds = &uet_ep->uet_domain->uet->pds;

	if (uet_ep_has_cq(uet_ep)) {
		UET_API_ERR("Completion Q is associated with EP being closed");
		return -EBUSY;
	}

	if (uet_ep->uet_domain->mr_mode & UET_MR_MODE_PROV_KEY)
		uet_mr_list_finalize(uet_ep);
	else
		uet_mr_hash_finalize(uet_ep);

	pds->downcall.ep_close_wait(uet_ep);

	uet_ipv4_ep_hash_remove(uet_ep);

	uet_ep_free(uet_ep);

	return 0;
}

ssize_t uet_cq_read_internal(uet_cq_handle_t cq_handle, 
			void *buf, size_t count)
{
	int rc;
	uet_pkt_handle_t err_pkt_handle;
	struct uet_cq *cq;
	struct uet_ep *uet_ep;
	struct uet_pds *pds;
	struct uet_ring *ring;
	ssize_t cq_count, rd_count, max_rd_count;
	char *buffer = buf;

	cq = (struct uet_cq *) cq_handle;
	uet_ep = cq->uet_ep;
	pds = &uet_ep->uet_domain->uet->pds;

	uet_msg_age(uet_ep);

	pds->downcall.progress_rx(uet_ep->uet_domain->uet);

	rc = pds->downcall.progress_tx(uet_ep, &err_pkt_handle);
	switch (rc) {
	case 0:
	case -EAGAIN:
		break;
	default:
		uet_tx_desc_set_err((struct uet_tx_desc *) err_pkt_handle,
				ETIMEDOUT, UET_TX_DESC_STATE_ERR_COMPLETE);
		break;
	}

	uet_tx_msg_try(uet_ep);

	ring = &cq->ring;
	cq_count = uet_ring_entry_cnt(ring);
	if (cq_count == 0)
		return 0;

	max_rd_count = uet_min(cq_count, count);
	for (rd_count = 0; rd_count < max_rd_count; rd_count++) {
		if (uet_cq_is_err_state(ring)) {
			if (rd_count == 0)
				rd_count = -EINVAL;
			break;
		}
		if (cq == &uet_ep->send_cq)
			uet_tx_cq_read_entry(&buffer[rd_count * sizeof(struct uet_cq_entry)],
					     ring);
		else
			uet_rx_cq_read_entry(&buffer[rd_count * sizeof(struct uet_cq_entry)],
					     ring);
	}

	pr_info("uet: cq read entry count: %lu\n", rd_count);

	return rd_count;
}

ssize_t uet_cq_readerr_internal(uet_cq_handle_t cq_handle,
		       struct uet_cq_entry *buf)
{
	struct uet_cq *cq;
	struct uet_ep *uet_ep;
	struct uet_ring *ring;
	struct uet_cq_ring_entry *ring_entry;
	struct uet_cq_entry *err_entry;

	cq = (struct uet_cq *) cq_handle;
	ring = &cq->ring;
	uet_ep = cq->uet_ep;

	if (!uet_cq_is_err_state(ring))
		return -EAGAIN;

	ring_entry = &(((struct uet_cq_ring_entry *) (ring->base))[ring->tail]);
	err_entry = (struct uet_cq_entry *) &ring_entry->entry;
	*buf = *err_entry;

	if (cq == &uet_ep->send_cq)
		uet_tx_desc_list_insert(ring_entry->desc.tx);
	else
		uet_rx_desc_list_insert(ring_entry->desc.rx);

	uet_ring_tail_advance(ring);

	return 1;
}

int uet_cq_close_internal(uet_cq_handle_t cq_handle)
{
	struct uet_cq *uet_cq;
	struct uet_ep *uet_ep;

	uet_cq = (struct uet_cq *) cq_handle;
	uet_ep = uet_cq->uet_ep;

	/* fail if closing tx cq & there are outstanding msg transmits */
	if ((uet_cq == &uet_ep->send_cq) && (uet_ep->num_active_sends)) {
		UET_API_ERR("Outstanding sends associated with CQ being closed");
		return -EBUSY;
	}

	uet_cq->cq_state = UET_CQ_DOWN;
	uet_ring_free_entries(&uet_cq->ring);

	return 0;
}

int uet_av_insert_internal(uet_domain_handle_t domain_handle,
		  struct uet_addr *uet_addr,
		  uet_addr_handle_t *addr_handle)
{
	int rc;
	struct uet_instance *uet;
	struct uet_domain *uet_dom;
	struct uet_av_entry *av_entry;
	struct uet_addr *addr;

	uet_dom = (struct uet_domain *) domain_handle;
	uet = uet_dom->uet;

	/* TODO: only support ipv4 addresses for now */
	if (uet_addr->flags & UET_ADDR_IPV6) {
		UET_API_ERR("IPv6 not supported");
		return -ENOSYS;
	}

	addr = kcalloc(1, sizeof(struct uet_addr), GFP_KERNEL);
	memcpy(addr, uet_addr, sizeof(struct uet_addr));
	pr_info("uet: [%s] dst ip: %u.%u.%u.%u\n", __func__, UET_NIPQUAD(addr->fa.v4));

	/* allocate memory for av object */
	av_entry = kcalloc(1, sizeof(struct uet_av_entry), GFP_KERNEL);
	if (av_entry == NULL) {
		UET_API_PRINT_ERRNO("kcalloc");
		return -ENOMEM;
	}

	/* initialize av entry */
	av_entry->addr = addr;
	rc = uet_nic_get_ipv4_nh(UET_NIC(uet), addr->fa.v4,
				 av_entry->nh_mac_addr);
	if (rc == 0)
		av_entry->flags |= UET_NH_MAC_ADDR_V;

	/* insert av object in list of av entries for domain */
	uet_dom = (struct uet_domain *) domain_handle;
	uet_av_entry_insert(uet_dom, av_entry);

	*addr_handle = av_entry;
	pr_info("uet: [%s] av_entry: %llx\n", __func__, (uint64_t )av_entry);
	return 0;
}

int uet_av_remove_internal(uet_addr_handle_t addr_handle)
{
	struct uet_av_entry *av_entry;

	av_entry = (struct uet_av_entry *) addr_handle;

	/* fail if there are outstanding operations using the av */
	if (av_entry->num_active_ops) {
		UET_API_ERR("Outstanding ops associated with AV being removed");
		return -EBUSY;
	}

	uet_av_entry_free(av_entry);

	return 0;
}

int uet_mr_reg_internal(uet_domain_handle_t domain_handle, 
		void *buf, size_t len, uint64_t access, 
		uint64_t requested_key, uint64_t flags, 
		void *context, uet_mr_handle_t *mr_handle)
{
	int rc;
	uint64_t key, rkey;
	bool desc_allocated;
	size_t mr_index;
	struct uet_domain *uet_dom;
	struct uet_mr_desc *mr_desc;

	uet_dom = (struct uet_domain *) domain_handle;

	/* allocate descriptor for memory region */
	key = requested_key & UET_MR_KEY_IDEMPOTENT_SAFE;
	if (uet_dom->mr_mode & UET_MR_MODE_PROV_KEY) {
		desc_allocated = false;
		if (requested_key & UET_MR_KEY_OPTIMIZED) {
			if (uet_alloc_opt_mr_desc(uet_dom, &mr_index) ==
			    0) {
				desc_allocated = true;
				key |= (UET_MR_KEY_OPTIMIZED |
					(mr_index <<
					 UET_MR_KEY_OPTIMIZED_RKEY_SHIFT));
			}
		}
		if (!desc_allocated) {
			rc = uet_alloc_mr_desc(uet_dom, &mr_index);
			if (rc != 0)
				return rc;
			key |= (mr_index << UET_MR_KEY_RKEY_SHIFT);
		}
		rkey = mr_index;
	} else {
		if (requested_key & UET_MR_KEY_OPTIMIZED) {
			rkey = (requested_key &
				UET_MR_KEY_OPTIMIZED_RKEY_MASK) >>
				UET_MR_KEY_OPTIMIZED_RKEY_SHIFT;
			if (rkey > UET_MR_KEY_OPTIMIZED_MAX_RKEY) {
				UET_API_ERR(
				"Requested key too large for optimized format");
				return -EINVAL;
			}
			key |= (UET_MR_KEY_OPTIMIZED |
				(rkey << UET_MR_KEY_OPTIMIZED_RKEY_SHIFT));
		} else {
			rkey = (requested_key & UET_MR_KEY_RKEY_MASK) >>
				UET_MR_KEY_RKEY_SHIFT;
			if (rkey > UET_MR_KEY_MAX_RKEY) {
				UET_API_ERR("Requested key too large");
				return -EINVAL;
			}
			key |= rkey << UET_MR_KEY_RKEY_SHIFT;
		}
		rc = uet_alloc_mr_desc(uet_dom, &mr_index);
		if (rc != 0)
			return rc;
	}

	/* init memory region descriptor */
	mr_desc = &uet_dom->mr_desc[mr_index];
	memset(mr_desc, 0, sizeof(struct uet_mr_desc));
	mr_desc->state = UET_MR_DESC_STATE_DISABLED_REG;
	mr_desc->uet_dom = uet_dom;
	mr_desc->buf_desc.type = UET_MR_BUF_TYPE_CONTIG;
	mr_desc->buf_desc.buf = buf;
	mr_desc->buf_desc.len = len;
	mr_desc->access = access;
	mr_desc->flags = flags;
	mr_desc->context = context;
	mr_desc->full_key = key;
	mr_desc->hash_key.rkey = rkey;

	*mr_handle = mr_desc;
	return 0;
}

uint64_t uet_mr_key_internal(uet_mr_handle_t mr_handle)
{
	struct uet_mr_desc *mr_desc;

	mr_desc = (struct uet_mr_desc *) mr_handle;

	if (mr_desc->state == UET_MR_DESC_STATE_INACTIVE)
		return -ENOENT;

	return mr_desc->full_key;
}

int uet_ep_bind_mr_internal(uet_ep_handle_t ep_handle,
		   uet_mr_handle_t mr_handle)
{
	struct uet_ep *uet_ep;
	struct uet_mr_desc *mr_desc;

	uet_ep = (struct uet_ep *) ep_handle;
	mr_desc = (struct uet_mr_desc *) mr_handle;

	if (mr_desc->state != UET_MR_DESC_STATE_DISABLED_REG) {
		UET_API_ERR("Bad MR state for EP bind");
		return -EINVAL;
	}

	mr_desc->state = UET_MR_DESC_STATE_DISABLED_BIND;
	mr_desc->uet_ep = uet_ep;

	return 0;
}

int uet_mr_enable_internal(uet_mr_handle_t mr_handle)
{
	int rc;
	struct uet_mr_desc *mr_desc;

	mr_desc = (struct uet_mr_desc *) mr_handle;

	if (mr_desc->state != UET_MR_DESC_STATE_DISABLED_BIND) {
		UET_API_ERR("Bad MR state for enable");
		return -EINVAL;
	}

	rc = uet_nic_mr_reg(UET_NIC(mr_desc->uet_ep->uet_domain->uet),
			    &mr_desc->buf_desc, &mr_desc->nic_mr_handle);
	if (rc != 0)
		return rc;

	if (mr_desc->uet_ep->uet_domain->mr_mode &
	    UET_MR_MODE_PROV_KEY)
		uet_mr_list_insert(mr_desc);
	else
		uet_mr_hash_insert(mr_desc->uet_ep, mr_desc);

	mr_desc->state = UET_MR_DESC_STATE_ENABLED;

	if (mr_desc->uet_ep->untagged_gen_disabled) {
		/* re-enable generation */
		mr_desc->uet_ep->untagged_gen++;
		mr_desc->uet_ep->untagged_gen_disabled = false;
	}

	return 0;
}

int uet_mr_close_internal(uet_mr_handle_t mr_handle)
{
	struct uet_mr_desc *mr_desc;

	mr_desc = (struct uet_mr_desc *) mr_handle;

	switch (mr_desc->state) {
	case UET_MR_DESC_STATE_INACTIVE:
		UET_API_ERR("Can not close unregistered MR");
		return -EINVAL;
	case UET_MR_DESC_STATE_DISABLED_BIND:
	case UET_MR_DESC_STATE_ENABLED:
		UET_API_ERR("Can not close MR that is bound to EP");
		return -EINVAL;
	default:
		break;
	}

	uet_dealloc_mr_desc(mr_desc->uet_dom, mr_desc);

	return 0;
}



