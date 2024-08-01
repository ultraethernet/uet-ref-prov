/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
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
 *   - no support for ipv6
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

#include "uet_api.h"

/* nic operation close function */
static int uet_nic_close(struct fid *fid)
{
	struct fid_nic *fnic;

	fnic = (struct fid_nic *)fid;
	if (fnic != NULL) {
		if (fnic->device_attr != NULL) {
			free(fnic->device_attr);
			fnic->device_attr = NULL;
		}
		if (fnic->link_attr != NULL) {
			free(fnic->link_attr);
			fnic->link_attr = NULL;
		}
		if (fnic->fid.ops != NULL) {
			free(fnic->fid.ops);
			fnic->fid.ops = NULL;
		}

		free(fnic);
	}

	return FI_SUCCESS;
}

/*********************************************************************
 * Below functions implement UET APIs
 *********************************************************************/

int uet_initialize(uet_handle_t *handle)
{
	int rc;

	return uet_initialize_internal(handle);
}

int uet_finalize(uet_handle_t handle)
{
	uet_finalize_internal(handle);
	return 0;
}

int uet_getinfo(uet_handle_t handle, struct uet_addr *node,
		const struct fi_info *hints, struct fi_info **info)
{
	int rc;
	uint32_t ipv4_addr;
	struct fi_info *new_info;
	struct fid_nic *nic = NULL;
	struct uet_addr *src_addr;
	struct uet_nic_info nic_info;

	new_info = fi_allocinfo();
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
	nic->fid.fclass = FI_CLASS_NIC;
	nic->fid.context = handle;

	nic->fid.ops = calloc(1, sizeof(sizeof(struct fi_ops)));
	nic->fid.ops->size = sizeof(struct fi_ops);
	if (nic->fid.ops == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		rc = -FI_ENOMEM;
		goto err_return;
	}
	nic->fid.ops->close = uet_nic_close;

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
	
	rc = uet_nic_getinfo_internal(handle, &nic_info);
	if (rc != FI_SUCCESS) {
		UET_API_ERR("uet_nic_getinfo");
		goto err_return;
	}

	/* init from the NIC info */
	nic->device_attr->name		= nic_info.name;
	nic->link_attr->mtu		= nic_info.mtu;
	nic->link_attr->network_type	= nic_info.network_type;
	nic->link_attr->address	= nic_info.mac_addr_str;
	
	if (nic_info.state == UET_NIC_STATE_UP) {
		nic->link_attr->state = FI_LINK_UP;
	} else {
		nic->link_attr->state = FI_LINK_DOWN;
	}

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
			 FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE;

	src_addr = calloc(1, sizeof(struct uet_addr));
	if (src_addr == NULL) {
		UET_API_PRINT_ERRNO("calloc");
		rc = -FI_ENOMEM;
		goto err_return;
	}
	rc = uet_get_nic_addr_ipv4_internal(handle, &ipv4_addr);
	if (rc) {
		UET_API_PRINT_ERRNO("uet_get_nic_addr_ipv4_internal");
		rc = -ENOENT;
		goto err_return;
	}
	uet_init_uet_addr_ipv4(src_addr, ipv4_addr);

	new_info->dest_addrlen = 0;
	new_info->src_addrlen = sizeof(struct uet_addr);
	new_info->src_addr = src_addr;

	new_info->nic = nic;

	*info = new_info;
	return FI_SUCCESS;

err_return:
	if (nic->device_attr) {
		free(nic->device_attr);
		nic->device_attr = NULL;
	}
	if (nic->link_attr) {
		free(nic->link_attr);
		nic->link_attr = NULL;
	}
	if (nic->fid.ops) {
		free(nic->fid.ops);
		nic->fid.ops = NULL;
	}
	if (nic != NULL)
		free(nic);
	if (new_info != NULL)
		fi_freeinfo(new_info);
	return rc;
}

int uet_domain(uet_handle_t handle, struct fid_fabric *fabric,
	       struct fi_info *info, struct fid_domain *domain,
	       void *context, uet_eq_callback_t eq_callback,
	       uet_eq_err_callback_t eq_err_callback,
	       uet_domain_handle_t *domain_handle)
{
	int rc;
	size_t num_mr;
	int mr_mode = 0;

	/* check that memory regions are associated with endpoints */
	if (!(info->domain_attr->mr_mode & FI_MR_ENDPOINT)) {
		UET_API_ERR("FI_MR_ENDPOINT must be set");
		return -FI_EINVAL;
	}

	/* check requested memory region count */
	if (info->domain_attr->mr_cnt > UET_MR_KEY_MAX_RKEY) {
		UET_API_ERR("Requested memory region count exceeds max");
		rc = -FI_EINVAL;
		goto err_exit;
	}

	num_mr = info->domain_attr->mr_cnt;
	if (info->domain_attr->mr_mode & FI_MR_ENDPOINT)
		mr_mode |= UET_MR_MODE_ENDPOINT;
	if (info->domain_attr->mr_mode & FI_MR_PROV_KEY)
		mr_mode |= UET_MR_MODE_PROV_KEY;

	return uet_domain_internal(handle, num_mr, mr_mode, context, domain_handle);

err_exit:
	return rc;
}

int uet_domain_close(uet_domain_handle_t domain_handle)
{
	return uet_domain_close_internal(domain_handle);
}


int uet_endpoint(uet_domain_handle_t domain_handle,
		 struct fi_info *info, struct fid_ep *ep,
		 void *context, uet_ep_handle_t *ep_handle)
{
	void *src_addr;
	int32_t src_addrlen, num_rx_desc, num_tx_desc;
	uet_pds_mode_t pds_mode;
	uint32_t tclass;
	bool use_default_tos = false;

	src_addr = info->src_addr;
	src_addrlen = info->src_addrlen;
	num_rx_desc = info->rx_attr->size;

	num_tx_desc = info->tx_attr->size;
	pds_mode = 
	   (info->tx_attr->msg_order & UET_SEND_ORDERING) ? 
		UET_PDS_MODE_ROD : UET_PDS_MODE_RUD;

	switch (info->tx_attr->tclass) {
	case FI_TC_BEST_EFFORT:
	case FI_TC_UNSPEC:
		use_default_tos = true;
		break;
	default:
		tclass = info->tx_attr->tclass;
		break;
	}

	return uet_endpoint_internal(domain_handle, src_addr, 
			src_addrlen, num_rx_desc, num_tx_desc, 
			pds_mode, tclass, use_default_tos, 
			context, ep_handle);

}

int uet_getname(uet_ep_handle_t ep_handle, struct uet_addr *uet_addr)
{
	return uet_getname_internal(ep_handle, uet_addr);
}

int uet_ep_bind_cq(uet_ep_handle_t ep_handle, struct fi_cq_attr *attr,
		   struct fid_cq *cq, uint64_t flags, void *context,
		   uet_cq_handle_t *cq_handle)
{
	uint64_t cq_flags = 0;
	enum uet_cq_type cq_type;
	size_t cq_size;
	int rc;

	if (flags & FI_TAGGED)
		cq_flags |= UET_ACCESS_FLAG_TAGGED;
	if (flags & FI_RMA)
		cq_flags |= UET_ACCESS_FLAG_RMA;
	if (flags & FI_REMOTE_READ)
		cq_flags |= UET_ACCESS_FLAG_REMOTE_READ;
	if (flags & FI_MSG)
		cq_flags |= UET_ACCESS_FLAG_MSG;
	if (flags & FI_WRITE)
		cq_flags |= UET_ACCESS_FLAG_WRITE;
	if (flags & FI_RECV)
		cq_flags |= UET_ACCESS_FLAG_RECV;
	if (flags & FI_SEND)
		cq_flags |= UET_ACCESS_FLAG_SEND;
	if (flags & FI_READ)
		cq_flags |= UET_ACCESS_FLAG_READ;
	if (flags & FI_SELECTIVE_COMPLETION)
		cq_flags |= UET_ACCESS_FLAG_SELECTIVE_COMPLETION;
	if (flags & FI_REMOTE_WRITE)
		cq_flags |= UET_ACCESS_FLAG_REMOTE_WRITE;

	/* determine cq entry size */
	switch (attr->format) {
	case FI_CQ_FORMAT_CONTEXT:
		cq_type = UET_CQ_TYPE_CONTEXT;
		break;
	case FI_CQ_FORMAT_UNSPEC:
		cq_type = UET_CQ_TYPE_UNSPEC;
		break;
	case FI_CQ_FORMAT_MSG:
		cq_type = UET_CQ_TYPE_MSG;
		break;
	case FI_CQ_FORMAT_DATA:
		cq_type = UET_CQ_TYPE_DATA;
		break;
	case FI_CQ_FORMAT_TAGGED:
		cq_type = UET_CQ_TYPE_TAGGED;
		break;
	default:
		UET_API_ERR("Unknown CQ Format = %d", attr->format);
		return -EINVAL;
	}

	cq_size = attr->size;

	return uet_ep_bind_cq_internal(ep_handle, cq_flags, cq_type, 
		cq_size, context, cq_handle);
}

int uet_ep_enable(uet_ep_handle_t ep_handle)
{
	return uet_ep_enable_internal(ep_handle);
}

int uet_ep_close(uet_ep_handle_t ep_handle)
{
	return uet_ep_close_internal(ep_handle);
}

ssize_t uet_cq_read(uet_cq_handle_t cq_handle, void *buf, size_t count)
{
	struct uet_cq_entry entries[UET_CQ_READ_MAX_ENTRIES];
	char *buffer = buf;
	ssize_t rd_count;
	int i;

	count = uet_min(count, UET_CQ_READ_MAX_ENTRIES);

	rd_count = uet_cq_read_internal(cq_handle, (void *)&entries[0], count);
	if (rd_count == -EINVAL)
		return -FI_EAVAIL;

	for (i = 0; i < rd_count; i++) {
		struct fi_cq_data_entry *cq_entry = 
			(struct fi_cq_data_entry *)&buffer[i * sizeof(struct fi_cq_data_entry)];
		struct uet_cq_entry *entry = &entries[i];

		cq_entry->flags = 0;
		if (entry->flags & UET_ACCESS_FLAG_TAGGED)
			cq_entry->flags |= FI_TAGGED;
		if (entry->flags & UET_ACCESS_FLAG_RMA)
			cq_entry->flags |= FI_RMA;
		if (entry->flags & UET_ACCESS_FLAG_REMOTE_READ)
			cq_entry->flags |= FI_REMOTE_READ;
		if (entry->flags & UET_ACCESS_FLAG_MSG)
			cq_entry->flags |= FI_MSG;
		if (entry->flags & UET_ACCESS_FLAG_WRITE)
			cq_entry->flags |= FI_WRITE;
		if (entry->flags & UET_ACCESS_FLAG_RECV)
			cq_entry->flags |= FI_RECV;
		if (entry->flags & UET_ACCESS_FLAG_SEND)
			cq_entry->flags |= FI_SEND;
		if (entry->flags & UET_ACCESS_FLAG_READ)
			cq_entry->flags |= FI_READ;
		if (entry->flags & UET_ACCESS_FLAG_SELECTIVE_COMPLETION)
			cq_entry->flags |= FI_SELECTIVE_COMPLETION;
		if (entry->flags & UET_ACCESS_FLAG_REMOTE_WRITE)
			cq_entry->flags |= FI_REMOTE_WRITE;

		cq_entry->op_context = entry->op_context;
		cq_entry->len = entry->len;
		cq_entry->buf = entry->buf;
		cq_entry->data = entry->data;
	}

	return rd_count;
}

ssize_t uet_cq_readerr(uet_cq_handle_t cq_handle,
			struct fi_cq_err_entry *buf)
{
	struct uet_cq_entry err_entry;
	ssize_t ret;

	ret = uet_cq_readerr_internal(cq_handle, &err_entry);
	if (ret == 1) {
		buf->err = err_entry.err;
	}

	return ret;
}


int uet_cq_close(uet_cq_handle_t cq_handle)
{
	return uet_cq_close_internal(cq_handle);
}

int uet_av_insert(uet_domain_handle_t domain_handle, 
		  struct uet_addr *uet_addr, uet_addr_handle_t *addr_handle)
{
	return uet_av_insert_internal(domain_handle, uet_addr, addr_handle);
}

int uet_av_remove(uet_addr_handle_t addr_handle)
{
	return uet_av_remove_internal(addr_handle);
}

ssize_t uet_recv(uet_ep_handle_t ep_handle, uint32_t job_id,
		 void *buf, size_t len, uet_mr_handle_t mr_handle,
		 uet_addr_handle_t src_addr_handle, void *context)
{
	return (uet_recv_api_common(UET_RECV_API, ep_handle, job_id, buf, len,
				    mr_handle, src_addr_handle, UET_NO_TAG,
				    UET_NO_IGNORE_BITS, context));
}

ssize_t uet_send(uet_ep_handle_t ep_handle, uint32_t job_id,
		 void *buf, size_t len, uet_mr_handle_t mr_handle,
		 uet_addr_handle_t dst_addr_handle, void *context)
{
	return (uet_send_req_api_common(
			UET_SEND_API, ep_handle, job_id, buf, len, mr_handle,
			dst_addr_handle, UET_NO_TAG, UET_NO_IMM_DATA,
			UET_NO_REMOTE_MEM_ADDR, UET_NO_REMOTE_KEY, context));
}

ssize_t uet_trecv(uet_ep_handle_t ep_handle, uint32_t job_id,
		  void *buf, size_t len, uet_mr_handle_t mr_handle,
		  uet_addr_handle_t src_addr_handle, uint64_t tag,
		  uint64_t ignore, void *context)
{
	return (uet_recv_api_common(UET_TRECV_API, ep_handle, job_id, buf, len,
				    mr_handle, src_addr_handle, tag, ignore,
				    context));
}

ssize_t uet_tsend(uet_ep_handle_t ep_handle, uint32_t job_id,
		  void *buf, size_t len, uet_mr_handle_t mr_handle,
		  uet_addr_handle_t dst_addr_handle, uint64_t tag,
		  void *context)
{
	return (uet_send_req_api_common(
			UET_TSEND_API, ep_handle, job_id, buf, len, mr_handle,
			dst_addr_handle, tag, UET_NO_IMM_DATA,
			UET_NO_REMOTE_MEM_ADDR, UET_NO_REMOTE_KEY, context));
}

uint64_t uet_mr_format_key(uint64_t rkey, bool idempotent_safe)
{
	uint64_t formatted_key;

	if (rkey > UET_MR_KEY_MAX_RKEY)
		return FI_KEY_NOTAVAIL;

	if (rkey > UET_MR_KEY_OPTIMIZED_MAX_RKEY)
		formatted_key = rkey < UET_MR_KEY_RKEY_SHIFT;
	else
		formatted_key = (UET_MR_KEY_OPTIMIZED |
				 (rkey < UET_MR_KEY_OPTIMIZED_RKEY_SHIFT));

	if (idempotent_safe)
		formatted_key |= UET_MR_KEY_OPTIMIZED;

	return formatted_key;
}

int uet_mr_reg(uet_domain_handle_t domain_handle, void *buf, size_t len,
	       uint64_t access, uint64_t requested_key, uint64_t flags,
	       void *context, uet_mr_handle_t *mr_handle)
{
	uint64_t uet_access_flags = 0;

	if (access & FI_TAGGED)
		uet_access_flags |= UET_ACCESS_FLAG_TAGGED;
	if (access & FI_RMA)
		uet_access_flags |= UET_ACCESS_FLAG_RMA;
	if (access & FI_REMOTE_READ)
		uet_access_flags |= UET_ACCESS_FLAG_REMOTE_READ;
	if (access & FI_MSG)
		uet_access_flags |= UET_ACCESS_FLAG_MSG;
	if (access & FI_WRITE)
		uet_access_flags |= UET_ACCESS_FLAG_WRITE;
	if (access & FI_RECV)
		uet_access_flags |= UET_ACCESS_FLAG_RECV;
	if (access & FI_SEND)
		uet_access_flags |= UET_ACCESS_FLAG_SEND;
	if (access & FI_READ)
		uet_access_flags |= UET_ACCESS_FLAG_READ;
	if (access & FI_SELECTIVE_COMPLETION)
		uet_access_flags |= UET_ACCESS_FLAG_SELECTIVE_COMPLETION;
	if (access & FI_REMOTE_WRITE)
		uet_access_flags |= UET_ACCESS_FLAG_REMOTE_WRITE;

	return uet_mr_reg_internal(domain_handle, buf, len, uet_access_flags,
			requested_key, flags, context, mr_handle);
}

uint64_t uet_mr_key(uet_mr_handle_t mr_handle)
{
	return uet_mr_key_internal(mr_handle);
}

int uet_ep_bind_mr(uet_ep_handle_t ep_handle,
		   uet_mr_handle_t mr_handle, uint64_t flags)
{
	return uet_ep_bind_mr_internal(ep_handle, mr_handle);
}

int uet_mr_enable(uet_mr_handle_t mr_handle)
{
	return uet_mr_enable_internal(mr_handle);
}

int uet_mr_close(uet_mr_handle_t mr_handle)
{
	return uet_mr_close_internal(mr_handle);
}

ssize_t uet_write(uet_ep_handle_t ep_handle, uint32_t job_id, void *buf,
		  size_t len, uint64_t *data, uet_mr_handle_t mr_handle,
		  uet_addr_handle_t dst_addr_handle,
		  uint64_t remote_mem_addr, uint64_t remote_key,
		  void *context)
{
	return (uet_send_req_api_common(
			UET_WRITE_API, ep_handle, job_id, buf, len, mr_handle,
			dst_addr_handle, UET_NO_TAG, data, remote_mem_addr,
			remote_key, context));
}

ssize_t uet_read(uet_ep_handle_t ep_handle, uint32_t job_id, void *buf,
		 size_t len, uet_mr_handle_t mr_handle,
		 uet_addr_handle_t uet_addr_handle,
		 uint64_t remote_mem_addr, uint64_t remote_key, void *context)
{
	return (uet_send_req_api_common(
			UET_READ_API, ep_handle, job_id, buf, len, mr_handle,
			uet_addr_handle, UET_NO_TAG, UET_NO_IMM_DATA,
			remote_mem_addr, remote_key, context));
}

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

ssize_t uet_atomic(uet_ep_handle_t ep_handle, uint32_t job_id,
		   const void *local_op_buf, size_t count,
		   uet_mr_handle_t mr_handle,
		   uet_addr_handle_t dst_addr_handle,
		   uint64_t remote_mem_addr, uint64_t remote_key,
		   enum fi_datatype datatype, enum fi_op op,
		   void *context)
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

int uet_query_atomic(uet_domain_handle_t domain_handle,
		     enum fi_datatype datatype, enum fi_op op,
		     struct fi_atomic_attr *attr, uint64_t flags)
{
	return -FI_ENOSYS;
}

