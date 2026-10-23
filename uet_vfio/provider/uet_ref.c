// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

/*
 * Copyright (c) 2026 Broadcom. All rights reserved. The term Broadcom
 * refers to Broadcom Inc. and/or its subsidiaries.
 */

/*
 * uet_ref - userspace provider for the UET reference device.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include <util/mmio.h>
#include <util/util.h>
#include <util/udma_barrier.h>

#include <infiniband/cmd_ioctl.h>
#include <infiniband/cmd_write.h>
#include <infiniband/driver.h>

#include <uet_ref-abi.h>

#include "uet_ref_hw.h"

#include "uet_ref.h"
#include "uet_ref_ring_cons.h"

static const struct verbs_match_ent hca_table[] = {
	VERBS_DRIVER_ID(RDMA_DRIVER_UET_REF),
	VERBS_PCI_MATCH(UET_REF_PCI_VENDOR_ID, UET_REF_PCI_DEVICE_ID, NULL),
	{},
};

static int uet_ref_query_device_ex(struct ibv_context *ibctx,
				   const struct ibv_query_device_ex_input *in,
				   struct ibv_device_attr_ex *attr,
				   size_t attr_size)
{
	struct ib_uverbs_ex_query_device_resp resp;
	size_t resp_size = sizeof(resp);
	int ret;

	ret = ibv_cmd_query_device_any(ibctx, in, attr, attr_size, &resp,
				       &resp_size);
	if (ret)
		return ret;

	return 0;
}

static int uet_ref_query_port(struct ibv_context *ibctx,
			      uint8_t port,
			      struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(ibctx, port, attr, &cmd, sizeof(cmd));
}

static struct ibv_pd *uet_ref_alloc_pd(struct ibv_context *ibctx)
{
	struct ib_uverbs_alloc_pd_resp resp;
	struct ibv_alloc_pd cmd;
	struct ibv_pd *pd;

	pd = calloc(1, sizeof(*pd));
	if (!pd)
		return NULL;

	if (ibv_cmd_alloc_pd(ibctx, pd, &cmd, sizeof(cmd), &resp,
			     sizeof(resp))) {
		free(pd);
		return NULL;
	}

	return pd;
}

static int uet_ref_dealloc_pd(struct ibv_pd *pd)
{
	int ret;

	ret = ibv_cmd_dealloc_pd(pd);
	if (ret)
		return ret;

	free(pd);

	return 0;
}

static void uet_ref_free_context(struct ibv_context *ibctx)
{
	struct uet_ref_context *ctx = to_uet_ref_ctx(ibctx);

	if (ctx->db) {
		munmap(ctx->db, sysconf(_SC_PAGESIZE));
		ctx->db = NULL;
	}

	verbs_uninit_context(&ctx->vctx);
	free(ctx);
}

static struct ibv_job *uet_ref_alloc_job(struct ibv_context *ibctx,
					 struct ibv_job_attr *attr,
					 void *user_context)
{
	struct ib_uverbs_attr *handle;
	struct uet_ref_job *job;

	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_JOB,
			       UVERBS_METHOD_JOB_ALLOC, 5);

	if (!attr) {
		errno = EINVAL;
		return NULL;
	}

	job = calloc(1, sizeof(*job));
	if (!job)
		return NULL;

	handle = fill_attr_out_obj(cmd, UVERBS_ATTR_ALLOC_JOB_HANDLE);

	fill_attr_in_uint32(cmd, UVERBS_ATTR_ALLOC_JOB_ID, attr->id);

	if (attr->comp_mask & IBV_JOB_ATTR_MAX_ADDR_ENTRIES) {
		fill_attr_in_uint32(cmd,
				    UVERBS_ATTR_ALLOC_JOB_MAX_ADDR_ENTRIES,
				    attr->max_addr_entries);
	}

	if (attr->comp_mask & IBV_JOB_ATTR_PORT_NUM) {
		fill_attr_in_uint32(cmd, UVERBS_ATTR_ALLOC_JOB_PORT_NUM,
				    attr->port_num);
	}

	if (attr->comp_mask & IBV_JOB_ATTR_SGID_INDEX) {
		fill_attr_in(cmd, UVERBS_ATTR_ALLOC_JOB_SGID_INDEX,
			     &attr->sgid_index, sizeof(attr->sgid_index));
	}

	if (execute_ioctl(ibctx, cmd)) {
		free(job);
		return NULL;
	}

	job->vjob.context = ibctx;
	job->vjob.user_context = user_context;
	job->vjob.handle = read_attr_obj(UVERBS_ATTR_ALLOC_JOB_HANDLE,
					 handle);

	return &job->vjob;
}

static int uet_ref_dealloc_job(struct ibv_job *vjob)
{
	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_JOB,
			       UVERBS_METHOD_JOB_DEALLOC, 1);

	fill_attr_in_obj(cmd, UVERBS_ATTR_DEALLOC_JOB_HANDLE, vjob->handle);

	if (execute_ioctl(vjob->context, cmd))
		return errno;

	free(container_of(vjob, struct uet_ref_job, vjob));

	return 0;
}

static int uet_ref_query_job(struct ibv_job *vjob,
			     struct ibv_job_attr *attr)
{
	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_JOB,
			       UVERBS_METHOD_JOB_QUERY, 5);

	if (!attr)
		return EINVAL;

	fill_attr_in_obj(cmd, UVERBS_ATTR_QUERY_JOB_HANDLE, vjob->handle);
	fill_attr_out_ptr(cmd, UVERBS_ATTR_QUERY_JOB_ID, &attr->id);
	fill_attr_out_ptr(cmd, UVERBS_ATTR_QUERY_JOB_MAX_ADDR_ENTRIES,
			  &attr->max_addr_entries);
	fill_attr_out_ptr(cmd, UVERBS_ATTR_QUERY_JOB_PORT_NUM,
			  &attr->port_num);
	fill_attr_out_ptr(cmd, UVERBS_ATTR_QUERY_JOB_SGID_INDEX,
			  &attr->sgid_index);

	if (execute_ioctl(vjob->context, cmd))
		return errno;

	attr->comp_mask = (IBV_JOB_ATTR_ID |
			   IBV_JOB_ATTR_MAX_ADDR_ENTRIES |
			   IBV_JOB_ATTR_PORT_NUM |
			   IBV_JOB_ATTR_SGID_INDEX);

	return 0;
}

static int uet_ref_export_job(struct ibv_job *vjob,
			      int *fd)
{
	struct ib_uverbs_attr *fd_attr;

	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_JOB,
			       UVERBS_METHOD_JOB_EXPORT, 2);

	if (!fd)
		return EINVAL;

	fill_attr_in_obj(cmd, UVERBS_ATTR_EXPORT_JOB_HANDLE, vjob->handle);
	fd_attr = fill_attr_out_fd(cmd, UVERBS_ATTR_EXPORT_JOB_FD, 0);

	if (execute_ioctl(vjob->context, cmd))
		return errno;

	*fd = read_attr_fd(UVERBS_ATTR_EXPORT_JOB_FD, fd_attr);

	return 0;
}

static int uet_ref_import_job(struct ibv_context *ibctx,
			      int fd,
			      struct ibv_job **out)
{
	struct ib_uverbs_attr *handle;
	struct uet_ref_job *job;

	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_JOB,
			       UVERBS_METHOD_JOB_IMPORT, 2);

	if (!out)
		return EINVAL;

	job = calloc(1, sizeof(*job));
	if (!job)
		return ENOMEM;

	handle = fill_attr_out_obj(cmd, UVERBS_ATTR_IMPORT_JOB_HANDLE);

	fill_attr_in_fd(cmd, UVERBS_ATTR_IMPORT_JOB_FD, fd);

	if (execute_ioctl(ibctx, cmd)) {
		int err = errno;
		free(job);
		return err;
	}

	job->vjob.context = ibctx;
	job->vjob.handle = read_attr_obj(UVERBS_ATTR_IMPORT_JOB_HANDLE,
					 handle);

	*out = &job->vjob;

	return 0;
}

static int uet_ref_insert_addr(struct ibv_job *vjob,
			       struct ibv_ah_attr_ex *ah_attr,
			       unsigned int addr_idx)
{
	struct ib_uverbs_ah_attr_ex uah;

	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_JOB,
			       UVERBS_METHOD_JOB_ADDR_INSERT, 3);

	if (!ah_attr)
		return EINVAL;

	memset(&uah, 0, sizeof(uah));
	memcpy(uah.ah_attr.grh.dgid, ah_attr->ah_attr.grh.dgid.raw,
	       sizeof(uah.ah_attr.grh.dgid));
	uah.ah_attr.grh.flow_label = ah_attr->ah_attr.grh.flow_label;
	uah.ah_attr.grh.sgid_index = ah_attr->ah_attr.grh.sgid_index;
	uah.ah_attr.grh.hop_limit = ah_attr->ah_attr.grh.hop_limit;
	uah.ah_attr.grh.traffic_class = ah_attr->ah_attr.grh.traffic_class;
	uah.ah_attr.dlid = ah_attr->ah_attr.dlid;
	uah.ah_attr.sl = ah_attr->ah_attr.sl;
	uah.ah_attr.src_path_bits = ah_attr->ah_attr.src_path_bits;
	uah.ah_attr.static_rate = ah_attr->ah_attr.static_rate;
	uah.ah_attr.is_global = ah_attr->ah_attr.is_global;
	uah.ah_attr.port_num = ah_attr->ah_attr.port_num;
	uah.remote_qpn = ah_attr->remote_qpn;

	fill_attr_in_obj(cmd, UVERBS_ATTR_JOB_ADDR_INSERT_HANDLE,
			 vjob->handle);
	fill_attr_in_uint32(cmd, UVERBS_ATTR_JOB_ADDR_INSERT_INDEX, addr_idx);
	fill_attr_in(cmd, UVERBS_ATTR_JOB_ADDR_INSERT_AH_ATTR_EX, &uah,
		     sizeof(uah));

	if (execute_ioctl(vjob->context, cmd))
		return errno;

	return 0;
}

static int uet_ref_remove_addr(struct ibv_job *vjob,
			       unsigned int addr_idx)
{
	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_JOB,
			       UVERBS_METHOD_JOB_ADDR_REMOVE, 2);

	fill_attr_in_obj(cmd, UVERBS_ATTR_JOB_ADDR_REMOVE_HANDLE,
			 vjob->handle);
	fill_attr_in_uint32(cmd, UVERBS_ATTR_JOB_ADDR_REMOVE_INDEX, addr_idx);

	if (execute_ioctl(vjob->context, cmd))
		return errno;

	return 0;
}

static int uet_ref_query_addr(struct ibv_job *vjob,
			      unsigned int addr_idx,
			      struct ibv_ah_attr_ex *ah_attr)
{
	struct ib_uverbs_ah_attr_ex uah;

	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_JOB,
			       UVERBS_METHOD_JOB_ADDR_QUERY, 3);

	if (!ah_attr)
		return EINVAL;

	fill_attr_in_obj(cmd, UVERBS_ATTR_JOB_ADDR_QUERY_HANDLE,
			 vjob->handle);
	fill_attr_in_uint32(cmd, UVERBS_ATTR_JOB_ADDR_QUERY_INDEX, addr_idx);
	fill_attr_out_ptr(cmd, UVERBS_ATTR_JOB_ADDR_QUERY_AH_ATTR_EX, &uah);

	if (execute_ioctl(vjob->context, cmd))
		return errno;

	memset(ah_attr, 0, sizeof(*ah_attr));
	memcpy(ah_attr->ah_attr.grh.dgid.raw, uah.ah_attr.grh.dgid,
	       sizeof(uah.ah_attr.grh.dgid));
	ah_attr->ah_attr.grh.flow_label = uah.ah_attr.grh.flow_label;
	ah_attr->ah_attr.grh.sgid_index = uah.ah_attr.grh.sgid_index;
	ah_attr->ah_attr.grh.hop_limit = uah.ah_attr.grh.hop_limit;
	ah_attr->ah_attr.grh.traffic_class = uah.ah_attr.grh.traffic_class;
	ah_attr->ah_attr.sl = uah.ah_attr.sl;
	ah_attr->ah_attr.is_global = uah.ah_attr.is_global;
	ah_attr->ah_attr.port_num = uah.ah_attr.port_num;
	ah_attr->remote_qpn = uah.remote_qpn;

	return 0;
}

static struct ibv_job_key *uet_ref_create_jkey(struct ibv_pd *pd,
					       struct ibv_job *vjob)
{
	struct ib_uverbs_attr *handle;
	struct uet_ref_jkey *jkey;

	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_JKEY,
			       UVERBS_METHOD_JKEY_CREATE, 4);

	jkey = calloc(1, sizeof(*jkey));
	if (!jkey)
		return NULL;

	handle = fill_attr_out_obj(cmd, UVERBS_ATTR_CREATE_JKEY_HANDLE);

	fill_attr_in_obj(cmd, UVERBS_ATTR_CREATE_JKEY_PD_HANDLE, pd->handle);
	fill_attr_in_obj(cmd, UVERBS_ATTR_CREATE_JKEY_JOB_HANDLE,
			 vjob->handle);
	fill_attr_out_ptr(cmd, UVERBS_ATTR_CREATE_JKEY_JKEY, &jkey->vjkey.jkey);

	if (execute_ioctl(pd->context, cmd)) {
		free(jkey);
		return NULL;
	}

	jkey->vjkey.pd = pd;
	jkey->vjkey.handle = read_attr_obj(UVERBS_ATTR_CREATE_JKEY_HANDLE,
					   handle);

	return &jkey->vjkey;
}

static int uet_ref_destroy_jkey(struct ibv_job_key *vjkey)
{
	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_JKEY,
			       UVERBS_METHOD_JKEY_DESTROY, 1);

	fill_attr_in_obj(cmd, UVERBS_ATTR_DESTROY_JKEY_HANDLE,
			 vjkey->handle);

	if (execute_ioctl(vjkey->pd->context, cmd))
		return errno;

	free(container_of(vjkey, struct uet_ref_jkey, vjkey));

	return 0;
}

static struct ibv_mr *uet_ref_reg_mr_ex(struct ibv_pd *pd,
					struct ibv_mr_init_attr *attr)
{
	struct verbs_mr *vmr;

	vmr = calloc(1, sizeof(*vmr));
	if (!vmr)
		return NULL;

	if (ibv_cmd_reg_mr_ex(pd, vmr, attr)) {
		free(vmr);
		return NULL;
	}

	return &vmr->ibv_mr;
}

static struct ibv_mr *uet_ref_reg_mr(struct ibv_pd *pd,
				     void *addr,
				     size_t length,
				     uint64_t hca_va,
				     int access)
{
	struct uet_ref_reg_mr_resp resp = {};
	struct ibv_reg_mr cmd;
	struct verbs_mr *vmr;

	vmr = calloc(1, sizeof(*vmr));
	if (!vmr)
		return NULL;

	if (ibv_cmd_reg_mr(pd, addr, length, hca_va, access, vmr, &cmd,
			   sizeof(cmd), &resp.ibv_resp, sizeof(resp))) {
		free(vmr);
		return NULL;
	}

	vmr->ibv_mr.lkey64 = uet_ref_key64(&resp.uet);
	vmr->ibv_mr.rkey64 = vmr->ibv_mr.lkey64;

	return &vmr->ibv_mr;
}

static int uet_ref_dereg_mr(struct verbs_mr *vmr)
{
	int ret;

	ret = ibv_cmd_dereg_mr(vmr);
	if (ret)
		return ret;

	free(vmr);

	return 0;
}

/* round up to a power of two, which is what the ring index assumes */
static uint32_t uet_ref_ring_depth(uint32_t want)
{
	uint32_t n = 1;

	while (n < want)
		n <<= 1;

	return n;
}

static int uet_ref_ring_alloc(struct uet_ref_ring *ring,
			      uint32_t entries,
			      uint32_t entry_size)
{
	long page = sysconf(_SC_PAGESIZE);

	ring->entries = uet_ref_ring_depth(entries);
	ring->entry_size = entry_size;
	ring->prod = 0;
	ring->cons = 0;
	ring->phase = 1;

	if (posix_memalign(&ring->buf, page,
			   (size_t)ring->entries * entry_size)) {
		ring->buf = NULL;
		return -1;
	}

	memset(ring->buf, 0, (size_t)ring->entries * entry_size);

	return 0;
}

static void uet_ref_ring_free(struct uet_ref_ring *ring)
{
	free(ring->buf);

	ring->buf = NULL;
	ring->entries = 0;
}

/* Ring a doorbell. The descriptor must be visible to the device before
 * the doorbell that announces it, hence the barrier.
 */
static void uet_ref_db(struct uet_ref_context *ctx,
		       unsigned int reg,
		       uint64_t value)
{
	udma_to_device_barrier();
	mmio_write64(((uint8_t *)ctx->db) + reg, value);
}

static struct ibv_cq *uet_ref_create_cq(struct ibv_context *ibctx,
					int cqe,
					struct ibv_comp_channel *channel,
					int comp_vector)
{
	struct uet_ref_context *ctx = to_uet_ref_ctx(ibctx);
	struct uet_ref_create_cq_cmd cmd = {};
	struct uet_ref_create_cq_resp resp = {};
	struct uet_ref_cq *cq;

	cq = calloc(1, sizeof(*cq));
	if (!cq)
		return NULL;

	if (uet_ref_ring_alloc(&cq->ring, cqe,
			       (ctx->cqe_size) ? ctx->cqe_size
					       : UET_REF_HW_CQE_SIZE))
		goto err;

	cmd.uet.ring_addr = (uintptr_t)cq->ring.buf;
	cmd.uet.ring_entries = cq->ring.entries;

	if (ibv_cmd_create_cq(ibctx, cqe, channel, comp_vector, &cq->vcq.cq,
			      &cmd.ibv_cmd, sizeof(cmd), &resp.ibv_resp,
			      sizeof(resp)))
		goto err_ring;

	cq->handle = resp.uet.cq_handle;

	return &cq->vcq.cq;

err_ring:
	uet_ref_ring_free(&cq->ring);
err:
	free(cq);
	return NULL;
}

static int uet_ref_destroy_cq(struct ibv_cq *ibcq)
{
	struct uet_ref_cq *cq = to_uet_ref_cq(ibcq);
	int ret;

	ret = ibv_cmd_destroy_cq(ibcq);
	if (ret)
		return ret;

	uet_ref_ring_free(&cq->ring);
	free(cq->qps);
	free(cq);

	return 0;
}

/* defined with the completion reader, which is where they belong */
static int uet_ref_cq_attach_qp(struct uet_ref_cq *cq, struct uet_ref_qp *qp);
static void uet_ref_cq_detach_qp(struct uet_ref_cq *cq, struct uet_ref_qp *qp);

static struct ibv_ah *uet_ref_create_ah_ex(struct ibv_pd *ibpd,
					   struct ibv_ah_attr_ex *attr)
{
	struct uet_ref_ib_create_ah_resp resp = {};
	struct ib_uverbs_ah_attr_ex uah = {};
	struct uet_ref_ah *ah;
	struct ib_uverbs_attr *handle;

	DECLARE_COMMAND_BUFFER(cmd, UVERBS_OBJECT_AH,
			       UVERBS_METHOD_AH_EX_CREATE, 4);

	ah = calloc(1, sizeof(*ah));
	if (!ah)
		return NULL;

	memcpy(uah.ah_attr.grh.dgid, attr->ah_attr.grh.dgid.raw,
	       sizeof(uah.ah_attr.grh.dgid));
	uah.ah_attr.grh.flow_label = attr->ah_attr.grh.flow_label;
	uah.ah_attr.grh.sgid_index = attr->ah_attr.grh.sgid_index;
	uah.ah_attr.grh.hop_limit = attr->ah_attr.grh.hop_limit;
	uah.ah_attr.grh.traffic_class = attr->ah_attr.grh.traffic_class;
	uah.ah_attr.dlid = attr->ah_attr.dlid;
	uah.ah_attr.sl = attr->ah_attr.sl;
	uah.ah_attr.src_path_bits = attr->ah_attr.src_path_bits;
	uah.ah_attr.static_rate = attr->ah_attr.static_rate;
	uah.ah_attr.is_global = attr->ah_attr.is_global;
	uah.ah_attr.port_num = attr->ah_attr.port_num;
	uah.remote_qpn = attr->remote_qpn;

	handle = fill_attr_out_obj(cmd, UVERBS_ATTR_CREATE_AH_EX_HANDLE);

	fill_attr_in_obj(cmd, UVERBS_ATTR_CREATE_AH_EX_PD_HANDLE, ibpd->handle);
	fill_attr_in(cmd, UVERBS_ATTR_CREATE_AH_EX_AH_ATTR_EX, &uah,
		     sizeof(uah));
	fill_attr_out_ptr(cmd, UVERBS_ATTR_UHW_OUT, &resp);

	if (execute_ioctl(ibpd->context, cmd)) {
		free(ah);
		return NULL;
	}

	/* Two different numbers, not to be confused. The object ID names
	 * this handle to the kernel and is what destroy uses. ah_handle
	 * is what the device calls it, and is the only one a work request
	 * may carry.
	 */
	ah->ah_ex.ah_base.handle = read_attr_obj(UVERBS_ATTR_CREATE_AH_EX_HANDLE,
						 handle);
	ah->handle = resp.ah_handle;
	ah->ah_ex.remote_qpn = attr->remote_qpn;
	ah->ah_ex.ah_base.context = ibpd->context;
	ah->ah_ex.ah_base.pd = ibpd;

	return &ah->ah_ex.ah_base;
}

static int uet_ref_destroy_ah(struct ibv_ah *ibah)
{
	struct uet_ref_ah *ah = to_uet_ref_ah(ibah);
	int ret;

	ret = ibv_cmd_destroy_ah(ibah);
	if (ret)
		return ret;

	free(ah);

	return 0;
}

static void uet_ref_fill_qp_ex(struct uet_ref_qp *qp);

static struct ibv_qp *uet_ref_create_qp_ex(struct ibv_context *ibctx,
					   struct ibv_qp_init_attr_ex *attr)
{
	struct uet_ref_context *ctx = to_uet_ref_ctx(ibctx);
	struct uet_ref_create_qp_resp resp = {};
	struct uet_ref_create_qp_cmd cmd = {};
	struct uet_ref_qp *qp;

	if (attr->qp_type != IBV_QPT_RU) {
		errno = EOPNOTSUPP;
		return NULL;
	}

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		return NULL;

	if (attr->cap.max_send_wr &&
	    uet_ref_ring_alloc(&qp->sq, attr->cap.max_send_wr,
			       ctx->wqe_size ? ctx->wqe_size
					     : UET_REF_HW_WQE_SIZE))
		goto err;

	if (attr->cap.max_recv_wr &&
	    uet_ref_ring_alloc(&qp->rq, attr->cap.max_recv_wr,
			       ctx->wqe_size ? ctx->wqe_size
					     : UET_REF_HW_WQE_SIZE))
		goto err;

	cmd.uet.sq_addr = (uintptr_t)qp->sq.buf;
	cmd.uet.sq_entries = qp->sq.entries;
	cmd.uet.rq_addr = (uintptr_t)qp->rq.buf;
	cmd.uet.rq_entries = qp->rq.entries;

	if (ibv_cmd_create_qp_ex2(ibctx, &qp->vqp, attr, &cmd.ibv_cmd,
				  sizeof(cmd), &resp.ibv_resp, sizeof(resp),
				  NULL))
		goto err;

	qp->handle = resp.uet.qp_handle;

	if (attr->comp_mask & IBV_QP_INIT_ATTR_SEND_OPS_FLAGS) {
		uet_ref_fill_qp_ex(qp);
		qp->vqp.comp_mask |= VERBS_QP_EX;
	}

	if (attr->send_cq)
		qp->send_cq = to_uet_ref_cq(attr->send_cq);

	if (attr->recv_cq)
		qp->recv_cq = to_uet_ref_cq(attr->recv_cq);

	if (uet_ref_cq_attach_qp(qp->send_cq, qp) ||
	    uet_ref_cq_attach_qp(qp->recv_cq, qp)) {
		uet_ref_cq_detach_qp(qp->send_cq, qp);
		uet_ref_cq_detach_qp(qp->recv_cq, qp);
		ibv_cmd_destroy_qp(&qp->vqp.qp);
		errno = ENOMEM;
		goto err;
	}

	return &qp->vqp.qp;

err:
	uet_ref_ring_free(&qp->sq);
	uet_ref_ring_free(&qp->rq);
	free(qp);
	return NULL;
}

static int uet_ref_destroy_qp(struct ibv_qp *ibqp)
{
	struct uet_ref_qp *qp = to_uet_ref_qp(ibqp);
	int ret;

	ret = ibv_cmd_destroy_qp(ibqp);
	if (ret)
		return ret;

	uet_ref_cq_detach_qp(qp->send_cq, qp);
	uet_ref_cq_detach_qp(qp->recv_cq, qp);

	uet_ref_ring_free(&qp->sq);
	uet_ref_ring_free(&qp->rq);

	free(qp);

	return 0;
}

static int uet_ref_fill_wqe(struct uet_ref_hw_wqe *w,
			    struct ibv_send_wr *wr,
			    uint32_t max_sge)
{
	int i;

	if (wr->num_sge > (int)max_sge)
		return EINVAL;

	memset(w, 0, sizeof(*w));

	w->wr_id = wr->wr_id;
	w->num_sge = wr->num_sge;

	if (wr->wr.ru.ah) {
		/* This is an ibv_ah_ex, not an ibv_ah. The UET member of the
		 * work request carries the extended form.
		 */
		w->addr_index = to_uet_ref_ah(&wr->wr.ru.ah->ah_base)->handle;
		w->flags |= UET_REF_HW_WR_AH;
	} else {
		w->addr_index = wr->wr.ru.addr_idx;
	}

	w->jkey = wr->wr.ru.jkey;

	switch (wr->opcode) {
	case IBV_WR_SEND:
		w->opcode = UET_REF_HW_OP_SEND;
		break;
	case IBV_WR_SEND_WITH_IMM:
		w->opcode = UET_REF_HW_OP_SEND_IMM;
		w->imm = be32toh(wr->imm_data);
		break;
	case IBV_WR_RDMA_WRITE:
		w->opcode = UET_REF_HW_OP_RDMA_WRITE;
		w->remote_addr = wr->wr.ru_rdma.remote_addr;
		w->remote_key = wr->wr.ru_rdma.rkey64;
		break;
	case IBV_WR_RDMA_WRITE_WITH_IMM:
		w->opcode = UET_REF_HW_OP_RDMA_WRITE_IMM;
		w->remote_addr = wr->wr.ru_rdma.remote_addr;
		w->remote_key = wr->wr.ru_rdma.rkey64;
		w->imm = be32toh(wr->imm_data);
		break;
	case IBV_WR_RDMA_READ:
		w->opcode = UET_REF_HW_OP_RDMA_READ;
		w->remote_addr = wr->wr.ru_rdma.remote_addr;
		w->remote_key = wr->wr.ru_rdma.rkey64;
		break;
	default:
		return EOPNOTSUPP;
	}

	if (wr->send_flags & IBV_SEND_SIGNALED)
		w->flags |= UET_REF_HW_WR_SIGNALED;

	/* IBV_SEND_SGE64 selects the wide-key segment list. The two lists
	 * are a union, so reading the wrong one results in an error.
	 */
	if (wr->send_flags & IBV_SEND_SGE64) {
		for (i = 0; i < wr->num_sge; i++) {
			w->sge[i].addr = wr->sg64_list[i].addr;
			w->sge[i].key = wr->sg64_list[i].lkey64;
			w->sge[i].len = wr->sg64_list[i].length;
		}
	} else {
		for (i = 0; i < wr->num_sge; i++) {
			w->sge[i].addr = wr->sg_list[i].addr;
			w->sge[i].key = wr->sg_list[i].lkey;
			w->sge[i].len = wr->sg_list[i].length;
		}
	}

	return 0;
}

static int uet_ref_post_send(struct ibv_qp *ibqp,
			     struct ibv_send_wr *wr,
			     struct ibv_send_wr **bad)
{
	struct uet_ref_qp *qp = to_uet_ref_qp(ibqp);
	struct uet_ref_context *ctx = to_uet_ref_ctx(ibqp->context);
	uint32_t max_sge = ctx->max_sge ? ctx->max_sge : UET_REF_HW_MAX_SGE;
	int ret = 0;

	if (!qp->sq.buf) {
		*bad = wr;
		return EINVAL;
	}

	for (; wr; wr = wr->next) {
		struct uet_ref_hw_wqe *w;

		/* the device has not consumed enough for this to fit */
		if ((qp->sq.prod - qp->sq.cons) >= qp->sq.entries) {
			ret = ENOMEM;
			break;
		}

		w = (struct uet_ref_hw_wqe *)((uint8_t *)qp->sq.buf +
					      ((size_t)(qp->sq.prod %
							qp->sq.entries) *
					       qp->sq.entry_size));

		ret = uet_ref_fill_wqe(w, wr, max_sge);
		if (ret)
			break;

		qp->sq.prod++;
	}

	if (ret) {
		*bad = wr;
		return ret;
	}

	uet_ref_db(ctx, UET_REF_HW_DB_SQ,
		   (((uint64_t)qp->handle << UET_REF_HW_DB_HANDLE_SHIFT) |
		    qp->sq.prod));

	return 0;
}

static int uet_ref_post_recv(struct ibv_qp *ibqp,
			     struct ibv_recv_wr *wr,
			     struct ibv_recv_wr **bad)
{
	struct uet_ref_qp *qp = to_uet_ref_qp(ibqp);
	struct uet_ref_context *ctx = to_uet_ref_ctx(ibqp->context);
	uint32_t max_sge = (ctx->max_sge) ? ctx->max_sge : UET_REF_HW_MAX_SGE;
	int ret = 0;

	if (!qp->rq.buf) {
		*bad = wr;
		return EINVAL;
	}

	for (; wr; wr = wr->next) {
		struct uet_ref_hw_wqe *w;
		int i;

		if (wr->num_sge > (int)max_sge) {
			ret = EINVAL;
			break;
		}

		if ((qp->rq.prod - qp->rq.cons) >= qp->rq.entries) {
			ret = ENOMEM;
			break;
		}

		w = (struct uet_ref_hw_wqe *)((uint8_t *)qp->rq.buf +
					      ((size_t)(qp->rq.prod %
							qp->rq.entries) *
					       qp->rq.entry_size));

		memset(w, 0, sizeof(*w));

		w->wr_id = wr->wr_id;
		w->opcode = UET_REF_HW_OP_RECV;
		w->num_sge = wr->num_sge;

		for (i = 0; i < wr->num_sge; i++) {
			w->sge[i].addr = wr->sg_list[i].addr;
			w->sge[i].key = wr->sg_list[i].lkey;
			w->sge[i].len = wr->sg_list[i].length;
		}

		qp->rq.prod++;
	}

	if (ret) {
		*bad = wr;
		return ret;
	}

	uet_ref_db(ctx, UET_REF_HW_DB_RQ,
		   (((uint64_t)qp->handle << UET_REF_HW_DB_HANDLE_SHIFT) |
		    qp->rq.prod));

	return 0;
}

/* Start a new entry in the send ring. The builder API reports one error
 * for a whole batch at wr_complete(). A failure here is recorded and every
 * later call becomes a no-op rather than writing outside the ring.
 */
static struct uet_ref_hw_wqe *uet_ref_wr_begin(struct ibv_qp_ex *ibqpx,
					       uint32_t opcode)
{
	struct uet_ref_qp *qp = to_uet_ref_qp(&ibqpx->qp_base);
	struct uet_ref_hw_wqe *w;

	if (qp->err)
		return NULL;

	if (!qp->sq.buf) {
		qp->err = EINVAL;
		return NULL;
	}

	if ((qp->sq.prod - qp->sq.cons) >= qp->sq.entries) {
		qp->err = ENOMEM;
		return NULL;
	}

	w = (struct uet_ref_hw_wqe *)((uint8_t *)qp->sq.buf +
				      ((size_t)(qp->sq.prod % qp->sq.entries) *
				       qp->sq.entry_size));

	memset(w, 0, sizeof(*w));

	w->wr_id = ibqpx->wr_id;
	w->opcode = opcode;

	if (ibqpx->wr_flags & IBV_SEND_SIGNALED)
		w->flags |= UET_REF_HW_WR_SIGNALED;

	qp->sq.prod++;
	qp->cur = w;

	return w;
}

static void uet_ref_wr_send(struct ibv_qp_ex *ibqpx)
{
	uet_ref_wr_begin(ibqpx, UET_REF_HW_OP_SEND);
}

static void uet_ref_wr_send_imm(struct ibv_qp_ex *ibqpx,
				__be32 imm)
{
	struct uet_ref_hw_wqe *w;

	w = uet_ref_wr_begin(ibqpx, UET_REF_HW_OP_SEND_IMM);
	if (w)
		w->imm = be32toh(imm);
}

static void uet_ref_wr_send_imm64(struct ibv_qp_ex *ibqpx,
				  __be64 imm)
{
	struct uet_ref_hw_wqe *w;

	w = uet_ref_wr_begin(ibqpx, UET_REF_HW_OP_SEND_IMM);
	if (w) {
		w->imm = be64toh(imm);
		w->flags |= UET_REF_HW_WR_IMM64;
	}
}

static void uet_ref_wr_rma(struct ibv_qp_ex *ibqpx,
			   uint32_t opcode,
			   uint64_t rkey,
			   uint64_t remote_addr,
			   uint64_t imm,
			   bool imm64)
{
	struct uet_ref_hw_wqe *w;

	w = uet_ref_wr_begin(ibqpx, opcode);
	if (!w)
		return;

	w->remote_addr = remote_addr;
	w->remote_key = rkey;
	w->imm = imm;

	if (imm64)
		w->flags |= UET_REF_HW_WR_IMM64;
}

/* refuse a work request that use a 32b rkey, this device uses 64b keys */
static bool uet_ref_wr_rkey32_refused(struct ibv_qp_ex *ibqpx)
{
	struct uet_ref_qp *qp = to_uet_ref_qp(&ibqpx->qp_base);

	if (!qp->err)
		qp->err = EOPNOTSUPP;

	return true;
}

static void uet_ref_wr_rdma_write(struct ibv_qp_ex *q,
				  uint32_t rkey,
				  uint64_t addr)
{
	(void)rkey;
	(void)addr;

	uet_ref_wr_rkey32_refused(q);
}

static void uet_ref_wr_rdma_write64(struct ibv_qp_ex *q,
				    uint64_t rkey,
				    uint64_t addr)
{
	uet_ref_wr_rma(q, UET_REF_HW_OP_RDMA_WRITE, rkey, addr, 0, false);
}

static void uet_ref_wr_rdma_read(struct ibv_qp_ex *q,
				 uint32_t rkey,
				 uint64_t addr)
{
	(void)rkey;
	(void)addr;

	uet_ref_wr_rkey32_refused(q);
}

static void uet_ref_wr_rdma_read64(struct ibv_qp_ex *q,
				   uint64_t rkey,
				   uint64_t addr)
{
	uet_ref_wr_rma(q, UET_REF_HW_OP_RDMA_READ, rkey, addr, 0, false);
}

static void uet_ref_wr_rdma_write_imm(struct ibv_qp_ex *q,
				      uint32_t rkey,
				      uint64_t addr,
				      __be32 imm)
{
	(void)rkey;
	(void)addr;
	(void)imm;

	uet_ref_wr_rkey32_refused(q);
}

static void uet_ref_wr_rdma_write_imm64(struct ibv_qp_ex *q,
					uint32_t rkey,
					uint64_t addr,
					__be64 imm)
{
	(void)rkey;
	(void)addr;
	(void)imm;

	uet_ref_wr_rkey32_refused(q);
}

static void uet_ref_wr_rdma_write64_imm(struct ibv_qp_ex *q,
					uint64_t rkey,
					uint64_t addr,
					__be32 imm)
{
	uet_ref_wr_rma(q, UET_REF_HW_OP_RDMA_WRITE_IMM, rkey, addr,
		       be32toh(imm), false);
}

static void uet_ref_wr_rdma_write64_imm64(struct ibv_qp_ex *q,
					  uint64_t rkey,
					  uint64_t addr,
					  __be64 imm)
{
	uet_ref_wr_rma(q, UET_REF_HW_OP_RDMA_WRITE_IMM, rkey, addr,
		       be64toh(imm), true);
}

/* Name the peer as either an address handle or an index into the address
 * table of the job this request names. The device resolves both to the
 * same thing, but the index needs a job to find it.
 */
static void uet_ref_wr_set_ru_addr(struct ibv_qp_ex *ibqpx,
				   struct ibv_ah_ex *ah,
				   unsigned int idx)
{
	struct uet_ref_qp *qp = to_uet_ref_qp(&ibqpx->qp_base);

	if (!qp->cur)
		return;

	if (ah) {
		qp->cur->addr_index = to_uet_ref_ah(&ah->ah_base)->handle;
		qp->cur->flags |= UET_REF_HW_WR_AH;
	} else {
		qp->cur->addr_index = idx;
		qp->cur->flags &= ~UET_REF_HW_WR_AH;
	}
}

static void uet_ref_wr_set_job_key(struct ibv_qp_ex *ibqpx,
				   uint32_t jkey)
{
	struct uet_ref_qp *qp = to_uet_ref_qp(&ibqpx->qp_base);

	if (qp->cur)
		qp->cur->jkey = jkey;
}

static void uet_ref_wr_set_sge64(struct ibv_qp_ex *ibqpx,
				 uint64_t lkey,
				 uint64_t addr,
				 uint32_t length)
{
	struct uet_ref_qp *qp = to_uet_ref_qp(&ibqpx->qp_base);

	if (!qp->cur)
		return;

	qp->cur->num_sge = 1;
	qp->cur->sge[0].addr = addr;
	qp->cur->sge[0].key = lkey;
	qp->cur->sge[0].len = length;
}

static void uet_ref_wr_set_sge(struct ibv_qp_ex *ibqpx,
			       uint32_t lkey,
			       uint64_t addr,
			       uint32_t length)
{
	/* a 32-bit key is the same value narrowed; widening undoes that */
	uet_ref_wr_set_sge64(ibqpx, lkey, addr, length);
}

static void uet_ref_wr_set_sge64_list(struct ibv_qp_ex *ibqpx,
				      size_t num,
				      const struct ibv_sge64 *list)
{
	struct uet_ref_qp *qp = to_uet_ref_qp(&ibqpx->qp_base);
	size_t i;

	if (!qp->cur)
		return;

	if (num > UET_REF_HW_MAX_SGE) {
		qp->err = EINVAL;
		return;
	}

	qp->cur->num_sge = (uint32_t)num;

	for (i = 0; i < num; i++) {
		qp->cur->sge[i].addr = list[i].addr;
		qp->cur->sge[i].key = list[i].lkey64;
		qp->cur->sge[i].len = list[i].length;
	}
}

static void uet_ref_wr_set_sge_list(struct ibv_qp_ex *ibqpx,
				    size_t num,
				    const struct ibv_sge *list)
{
	struct uet_ref_qp *qp = to_uet_ref_qp(&ibqpx->qp_base);
	size_t i;

	if (!qp->cur)
		return;

	if (num > UET_REF_HW_MAX_SGE) {
		qp->err = EINVAL;
		return;
	}

	qp->cur->num_sge = (uint32_t)num;

	for (i = 0; i < num; i++) {
		qp->cur->sge[i].addr = list[i].addr;
		qp->cur->sge[i].key = list[i].lkey;
		qp->cur->sge[i].len = list[i].length;
	}
}

static void uet_ref_wr_start(struct ibv_qp_ex *ibqpx)
{
	struct uet_ref_qp *qp = to_uet_ref_qp(&ibqpx->qp_base);

	qp->err = 0;
	qp->cur = NULL;
	qp->in_batch = true;
}

/* publish the batch, one doorbell for however many requests were built */
static int uet_ref_wr_complete(struct ibv_qp_ex *ibqpx)
{
	struct uet_ref_qp *qp = to_uet_ref_qp(&ibqpx->qp_base);
	struct uet_ref_context *ctx = to_uet_ref_ctx(ibqpx->qp_base.context);

	qp->in_batch = false;
	qp->cur = NULL;

	if (qp->err) {
		int err = qp->err;

		qp->err = 0;
		return err;
	}

	uet_ref_db(ctx, UET_REF_HW_DB_SQ,
		   (((uint64_t)qp->handle << UET_REF_HW_DB_HANDLE_SHIFT) |
		    qp->sq.prod));

	return 0;
}

static void uet_ref_wr_abort(struct ibv_qp_ex *ibqpx)
{
	struct uet_ref_qp *qp = to_uet_ref_qp(&ibqpx->qp_base);

	qp->in_batch = false;
	qp->cur = NULL;
	qp->err = 0;
}

static void uet_ref_fill_qp_ex(struct uet_ref_qp *qp)
{
	struct ibv_qp_ex *x = &qp->vqp.qp_ex;

	x->wr_start = uet_ref_wr_start;
	x->wr_complete = uet_ref_wr_complete;
	x->wr_abort = uet_ref_wr_abort;
	x->wr_send = uet_ref_wr_send;
	x->wr_send_imm = uet_ref_wr_send_imm;
	x->wr_send_imm64 = uet_ref_wr_send_imm64;
	x->wr_rdma_write = uet_ref_wr_rdma_write;
	x->wr_rdma_write64 = uet_ref_wr_rdma_write64;
	x->wr_rdma_read = uet_ref_wr_rdma_read;
	x->wr_rdma_read64 = uet_ref_wr_rdma_read64;
	x->wr_rdma_write_imm = uet_ref_wr_rdma_write_imm;
	x->wr_rdma_write_imm64 = uet_ref_wr_rdma_write_imm64;
	x->wr_rdma_write64_imm = uet_ref_wr_rdma_write64_imm;
	x->wr_rdma_write64_imm64 = uet_ref_wr_rdma_write64_imm64;
	x->wr_set_ru_addr = uet_ref_wr_set_ru_addr;
	x->wr_set_job_key = uet_ref_wr_set_job_key;
	x->wr_set_sge = uet_ref_wr_set_sge;
	x->wr_set_sge64 = uet_ref_wr_set_sge64;
	x->wr_set_sge_list = uet_ref_wr_set_sge_list;
	x->wr_set_sge64_list = uet_ref_wr_set_sge64_list;
}

/* The 64-bit-key receive. Identical to post_recv but for the width of the
 * key in its segment list which is the whole reason struct ibv_sge64
 * exists.
 */
static int uet_ref_post_recv64(struct ibv_qp *ibqp,
			       struct ibv_recv_wr64 *wr,
			       struct ibv_recv_wr64 **bad)
{
	struct uet_ref_qp *qp = to_uet_ref_qp(ibqp);
	struct uet_ref_context *ctx = to_uet_ref_ctx(ibqp->context);
	uint32_t max_sge = ctx->max_sge ? ctx->max_sge : UET_REF_HW_MAX_SGE;
	int ret = 0;

	if (!qp->rq.buf) {
		*bad = wr;
		return EINVAL;
	}

	for (; wr; wr = wr->next) {
		struct uet_ref_hw_wqe *w;
		int i;

		if (wr->num_sge > (int)max_sge) {
			ret = EINVAL;
			break;
		}

		if ((qp->rq.prod - qp->rq.cons) >= qp->rq.entries) {
			ret = ENOMEM;
			break;
		}

		w = (struct uet_ref_hw_wqe *)((uint8_t *)qp->rq.buf +
					      ((size_t)(qp->rq.prod %
							qp->rq.entries) *
					       qp->rq.entry_size));

		memset(w, 0, sizeof(*w));

		w->wr_id = wr->wr_id;
		w->opcode = UET_REF_HW_OP_RECV;
		w->num_sge = wr->num_sge;

		for (i = 0; i < wr->num_sge; i++) {
			w->sge[i].addr = wr->sg_list[i].addr;
			w->sge[i].key = wr->sg_list[i].lkey64;
			w->sge[i].len = wr->sg_list[i].length;
		}

		qp->rq.prod++;
	}

	if (ret) {
		*bad = wr;
		return ret;
	}

	uet_ref_db(ctx, UET_REF_HW_DB_RQ,
		   (((uint64_t)qp->handle << UET_REF_HW_DB_HANDLE_SHIFT) |
		    qp->rq.prod));

	return 0;
}

static enum ibv_wc_status uet_ref_wc_status(uint32_t status)
{
	switch (status) {
	case UET_REF_HW_WC_SUCCESS:
		return IBV_WC_SUCCESS;
	case UET_REF_HW_WC_BAD_KEY:
		return IBV_WC_LOC_PROT_ERR;
	case UET_REF_HW_WC_BAD_ADDR:
		return IBV_WC_LOC_QP_OP_ERR;
	case UET_REF_HW_WC_BAD_JOB:
		return IBV_WC_LOC_ACCESS_ERR;
	case UET_REF_HW_WC_BAD_LOCAL_ADDR:
		return IBV_WC_LOC_PROT_ERR;
	case UET_REF_HW_WC_TOO_LONG:
		return IBV_WC_LOC_LEN_ERR;
	case UET_REF_HW_WC_FLUSHED:
		return IBV_WC_WR_FLUSH_ERR;
	default:
		return IBV_WC_GENERAL_ERR;
	}
}

static int uet_ref_cq_attach_qp(struct uet_ref_cq *cq,
				struct uet_ref_qp *qp)
{
	struct uet_ref_qp **grown;
	uint32_t i;

	if (cq == NULL)
		return 0;

	for (i = 0; i < cq->nqps; i++) {
		if (cq->qps[i] == qp)
			return 0;
	}

	grown = realloc(cq->qps, (cq->nqps + 1) * sizeof(*grown));
	if (grown == NULL)
		return ENOMEM;

	cq->qps = grown;
	cq->qps[cq->nqps++] = qp;

	return 0;
}

static void uet_ref_cq_detach_qp(struct uet_ref_cq *cq,
				 struct uet_ref_qp *qp)
{
	uint32_t i;

	if (cq == NULL)
		return;

	for (i = 0; i < cq->nqps; i++) {
		if (cq->qps[i] != qp)
			continue;

		cq->qps[i] = cq->qps[cq->nqps - 1];
		cq->nqps--;

		return;
	}
}

/* account for one completion against the QP ring it came from */
static void uet_ref_cq_release(struct uet_ref_cq *cq,
			       const struct uet_ref_hw_cqe *c)
{
	uint32_t i;

	for (i = 0; i < cq->nqps; i++) {
		struct uet_ref_qp *qp = cq->qps[i];
		struct uet_ref_ring *ring;

		if (qp->vqp.qp.qp_num != c->qpn)
			continue;

		if ((c->opcode == UET_REF_HW_OP_RECV) ||
		    (c->opcode == UET_REF_HW_OP_RECV_RDMA_IMM))
			ring = &qp->rq;
		else
			ring = &qp->sq;

		/* An older RU completion must not revoke already returned
		 * credits and make a non-full SQ/RQ appear full.
		 */
		ring->cons = uet_ref_ring_cons_advance(ring->cons, c->ring_cons);

		return;
	}
}

/* Read completions. An entry is ours when its valid word matches the lap we
 * are on. The device toggles that each time the ring wraps so nothing has
 * to be cleared between laps. The barrier keeps the rest of the entry from
 * being read before the flag that says it is there.
 */
static int uet_ref_poll_cq(struct ibv_cq *ibcq,
			   int num,
			   struct ibv_wc *wc)
{
	struct uet_ref_cq *cq = to_uet_ref_cq(ibcq);
	struct uet_ref_context *ctx = to_uet_ref_ctx(ibcq->context);
	int n = 0;

	if (!cq->ring.buf)
		return 0;

	while (n < num) {
		struct uet_ref_hw_cqe *c;

		c = (struct uet_ref_hw_cqe *)((uint8_t *)cq->ring.buf +
					      ((size_t)(cq->ring.cons %
							cq->ring.entries) *
					       cq->ring.entry_size));

		if (c->valid != cq->ring.phase)
			break;

		udma_from_device_barrier();

		memset(&wc[n], 0, sizeof(wc[n]));

		wc[n].wr_id = c->wr_id;
		wc[n].status = uet_ref_wc_status(c->status);
		wc[n].byte_len = c->byte_len;
		wc[n].qp_num = c->qpn;
		wc[n].src_qp = c->src_id;
		wc[n].imm_data = htobe32((uint32_t)c->imm);

		switch (c->opcode) {
		case UET_REF_HW_OP_RECV:
			wc[n].opcode = IBV_WC_RECV;
			break;
		case UET_REF_HW_OP_RECV_RDMA_IMM:
			wc[n].opcode = IBV_WC_RECV_RDMA_WITH_IMM;
			break;
		case UET_REF_HW_OP_RDMA_WRITE:
		case UET_REF_HW_OP_RDMA_WRITE_IMM:
			wc[n].opcode = IBV_WC_RDMA_WRITE;
			break;
		case UET_REF_HW_OP_RDMA_READ:
			wc[n].opcode = IBV_WC_RDMA_READ;
			break;
		default:
			wc[n].opcode = IBV_WC_SEND;
			break;
		}

		/* A receive for a send that carried immediate data is opcode
		 * RECV like any other, so the opcode alone cannot say that
		 * imm_data means anything; the device sets a flag for it.
		 */
		if ((c->opcode == UET_REF_HW_OP_SEND_IMM) ||
		    (c->opcode == UET_REF_HW_OP_RDMA_WRITE_IMM) ||
		    (c->opcode == UET_REF_HW_OP_RECV_RDMA_IMM) ||
		    (c->flags & UET_REF_HW_CQE_IMM))
			wc[n].wc_flags |= IBV_WC_WITH_IMM;

		uet_ref_cq_release(cq, c);

		cq->ring.cons++;

		if ((cq->ring.cons % cq->ring.entries) == 0)
			cq->ring.phase ^= 1;

		n++;
	}

	if (n) {
		uet_ref_db(ctx, UET_REF_HW_DB_CQ,
			   (((uint64_t)cq->handle <<
			     UET_REF_HW_DB_HANDLE_SHIFT) |
			    cq->ring.cons));
	}

	return n;
}

/* the entry the cursor is on, or NULL when the ring has nothing fresh */
static struct uet_ref_hw_cqe *uet_ref_cq_peek(struct uet_ref_cq *cq)
{
	struct uet_ref_hw_cqe *c;

	if (!cq->ring.buf)
		return NULL;

	c = (struct uet_ref_hw_cqe *)((uint8_t *)cq->ring.buf +
				      ((size_t)(cq->ring.cons %
						cq->ring.entries) *
				       cq->ring.entry_size));

	if (c->valid != cq->ring.phase)
		return NULL;

	udma_from_device_barrier();

	return c;
}

/* consume the entry the cursor holds */
static void uet_ref_cq_advance(struct uet_ref_cq *cq)
{
	if (cq->cur != NULL)
		uet_ref_cq_release(cq, cq->cur);

	cq->ring.cons++;

	if ((cq->ring.cons % cq->ring.entries) == 0)
		cq->ring.phase ^= 1;

	cq->cur_valid = false;
}

static void uet_ref_cq_set_current(struct uet_ref_cq *cq,
				   struct uet_ref_hw_cqe *c)
{
	cq->cur = c;
	cq->cur_valid = true;
	cq->vcq.cq_ex.status = uet_ref_wc_status(c->status);
	cq->vcq.cq_ex.wr_id = c->wr_id;
}

static int uet_ref_cq_start_poll(struct ibv_cq_ex *ibcq,
				 struct ibv_poll_cq_attr *attr)
{
	struct uet_ref_cq *cq = to_uet_ref_cq(ibv_cq_ex_to_cq(ibcq));
	struct uet_ref_hw_cqe *c = uet_ref_cq_peek(cq);

	if (!c)
		return ENOENT;

	uet_ref_cq_set_current(cq, c);

	return 0;
}

static int uet_ref_cq_next_poll(struct ibv_cq_ex *ibcq)
{
	struct uet_ref_cq *cq = to_uet_ref_cq(ibv_cq_ex_to_cq(ibcq));
	struct uet_ref_hw_cqe *c;

	if (cq->cur_valid)
		uet_ref_cq_advance(cq);

	c = uet_ref_cq_peek(cq);
	if (!c)
		return ENOENT;

	uet_ref_cq_set_current(cq, c);

	return 0;
}

/* the consumer index is published once rather than on every entry */
static void uet_ref_cq_end_poll(struct ibv_cq_ex *ibcq)
{
	struct uet_ref_cq *cq = to_uet_ref_cq(ibv_cq_ex_to_cq(ibcq));
	struct uet_ref_context *ctx = to_uet_ref_ctx(ibcq->context);

	if (cq->cur_valid)
		uet_ref_cq_advance(cq);

	uet_ref_db(ctx, UET_REF_HW_DB_CQ,
		   (((uint64_t)cq->handle << UET_REF_HW_DB_HANDLE_SHIFT) |
		    cq->ring.cons));
}

static enum ibv_wc_opcode uet_ref_cq_read_opcode(struct ibv_cq_ex *ibcq)
{
	struct uet_ref_cq *cq = to_uet_ref_cq(ibv_cq_ex_to_cq(ibcq));

	switch (cq->cur->opcode) {
	case UET_REF_HW_OP_RECV:
		return IBV_WC_RECV;
	case UET_REF_HW_OP_RECV_RDMA_IMM:
		return IBV_WC_RECV_RDMA_WITH_IMM;
	case UET_REF_HW_OP_RDMA_WRITE:
	case UET_REF_HW_OP_RDMA_WRITE_IMM:
		return IBV_WC_RDMA_WRITE;
	case UET_REF_HW_OP_RDMA_READ:
		return IBV_WC_RDMA_READ;
	default:
		return IBV_WC_SEND;
	}
}

static uint32_t uet_ref_cq_read_byte_len(struct ibv_cq_ex *ibcq)
{
	return to_uet_ref_cq(ibv_cq_ex_to_cq(ibcq))->cur->byte_len;
}

static __be32 uet_ref_cq_read_imm_data(struct ibv_cq_ex *ibcq)
{
	return htobe32((uint32_t)to_uet_ref_cq(ibv_cq_ex_to_cq(ibcq))->cur->imm);
}

static __be64 uet_ref_cq_read_imm64_data(struct ibv_cq_ex *ibcq)
{
	return htobe64(to_uet_ref_cq(ibv_cq_ex_to_cq(ibcq))->cur->imm);
}

static uint32_t uet_ref_cq_read_qp_num(struct ibv_cq_ex *ibcq)
{
	return to_uet_ref_cq(ibv_cq_ex_to_cq(ibcq))->cur->qpn;
}

static uint32_t uet_ref_cq_read_src_id(struct ibv_cq_ex *ibcq)
{
	return to_uet_ref_cq(ibv_cq_ex_to_cq(ibcq))->cur->src_id;
}

static uint32_t uet_ref_cq_read_job_id(struct ibv_cq_ex *ibcq)
{
	return to_uet_ref_cq(ibv_cq_ex_to_cq(ibcq))->cur->job_id;
}

static uint32_t uet_ref_cq_read_vendor_err(struct ibv_cq_ex *ibcq)
{
	return to_uet_ref_cq(ibv_cq_ex_to_cq(ibcq))->cur->status;
}

static unsigned int uet_ref_cq_read_wc_flags(struct ibv_cq_ex *ibcq)
{
	struct uet_ref_cq *cq = to_uet_ref_cq(ibv_cq_ex_to_cq(ibcq));

	if ((cq->cur->opcode == UET_REF_HW_OP_SEND_IMM) ||
	    (cq->cur->opcode == UET_REF_HW_OP_RDMA_WRITE_IMM) ||
	    (cq->cur->opcode == UET_REF_HW_OP_RECV_RDMA_IMM) ||
	    (cq->cur->flags & UET_REF_HW_CQE_IMM))
		return IBV_WC_WITH_IMM;

	return 0;
}

static struct ibv_cq_ex *uet_ref_create_cq_ex(struct ibv_context *ibctx,
					      struct ibv_cq_init_attr_ex *attr)
{
	struct uet_ref_context *ctx = to_uet_ref_ctx(ibctx);
	struct uet_ref_create_cq_ex_cmd cmd = {};
	struct uet_ref_create_cq_ex_resp resp = {};
	struct uet_ref_cq *cq;

	cq = calloc(1, sizeof(*cq));
	if (!cq)
		return NULL;

	if (uet_ref_ring_alloc(&cq->ring, attr->cqe,
			       ctx->cqe_size ? ctx->cqe_size
					     : UET_REF_HW_CQE_SIZE))
		goto err;

	cmd.uet.ring_addr = (uintptr_t)cq->ring.buf;
	cmd.uet.ring_entries = cq->ring.entries;

	if (ibv_cmd_create_cq_ex(ibctx, attr, NULL, &cq->vcq, &cmd.ibv_cmd,
				 sizeof(cmd), &resp.ibv_resp, sizeof(resp), 0))
		goto err_ring;

	cq->handle = resp.uet.cq_handle;

	cq->vcq.cq_ex.start_poll = uet_ref_cq_start_poll;
	cq->vcq.cq_ex.next_poll = uet_ref_cq_next_poll;
	cq->vcq.cq_ex.end_poll = uet_ref_cq_end_poll;
	cq->vcq.cq_ex.read_opcode = uet_ref_cq_read_opcode;
	cq->vcq.cq_ex.read_vendor_err = uet_ref_cq_read_vendor_err;
	cq->vcq.cq_ex.read_wc_flags = uet_ref_cq_read_wc_flags;

	/* only what the caller asked for; the rest stay NULL by contract */
	if (attr->wc_flags & IBV_WC_EX_WITH_BYTE_LEN)
		cq->vcq.cq_ex.read_byte_len = uet_ref_cq_read_byte_len;
	if (attr->wc_flags & IBV_WC_EX_WITH_IMM)
		cq->vcq.cq_ex.read_imm_data = uet_ref_cq_read_imm_data;
	if (attr->wc_flags & IBV_WC_EX_WITH_IMM64)
		cq->vcq.cq_ex.read_imm64_data = uet_ref_cq_read_imm64_data;
	if (attr->wc_flags & IBV_WC_EX_WITH_QP_NUM)
		cq->vcq.cq_ex.read_qp_num = uet_ref_cq_read_qp_num;
	if (attr->wc_flags & IBV_WC_EX_WITH_SRC_ID)
		cq->vcq.cq_ex.read_src_id = uet_ref_cq_read_src_id;
	if (attr->wc_flags & IBV_WC_EX_WITH_JOB_ID)
		cq->vcq.cq_ex.read_job_id = uet_ref_cq_read_job_id;

	return &cq->vcq.cq_ex;

err_ring:
	uet_ref_ring_free(&cq->ring);
err:
	free(cq);
	return NULL;
}

/* Arming is one-shot. The device raises one interrupt and disarms itself
 * so a consumer that wants another must ask again.
 */
static int uet_ref_req_notify_cq(struct ibv_cq *ibcq,
				 int solicited_only)
{
	struct uet_ref_cq *cq = to_uet_ref_cq(ibcq);
	struct uet_ref_context *ctx = to_uet_ref_ctx(ibcq->context);

	uet_ref_db(ctx, UET_REF_HW_DB_CQ,
		   (UET_REF_HW_DB_CQ_ARM |
		    ((uint64_t)cq->handle << UET_REF_HW_DB_HANDLE_SHIFT) |
		    cq->ring.cons));

	return 0;
}

static int uet_ref_modify_qp(struct ibv_qp *qp,
			     struct ibv_qp_attr *attr,
			     int attr_mask)
{
	struct ibv_modify_qp cmd = {};

	return ibv_cmd_modify_qp(qp, attr, attr_mask, &cmd, sizeof(cmd));
}

static int uet_ref_query_qp(struct ibv_qp *qp,
			    struct ibv_qp_attr *attr,
			    int attr_mask,
			    struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;

	return ibv_cmd_query_qp(qp, attr, attr_mask, init_attr, &cmd,
				sizeof(cmd));
}

static int uet_ref_attach_mr(struct ibv_qp *qp,
			     struct ibv_mr *mr)
{
	return ibv_cmd_qp_attach_mr(qp, mr);
}

static int uet_ref_detach_mr(struct ibv_qp *qp,
			     struct ibv_mr *mr)
{
	return ibv_cmd_qp_detach_mr(qp, mr);
}

static int uet_ref_query_qp_semantics(struct ibv_context *ibctx,
				      enum ibv_qp_type qp_type,
				      uint32_t port_num,
				      uint8_t sgid_index,
				      struct ibv_qp_semantics *out,
				      size_t qp_semantic_len)
{
	/* the answer does not vary by port or source address here */
	(void)port_num;
	(void)sgid_index;

	return ibv_cmd_query_qp_semantics(ibctx, qp_type, out,
					  qp_semantic_len);
}

static const struct verbs_context_ops uet_ref_ctx_ops = {
	.free_context = uet_ref_free_context,
	.query_device_ex = uet_ref_query_device_ex,
	.query_port = uet_ref_query_port,
	.query_qp_semantics = uet_ref_query_qp_semantics,
	.alloc_pd = uet_ref_alloc_pd,
	.dealloc_pd = uet_ref_dealloc_pd,
	.reg_mr = uet_ref_reg_mr,
	.reg_mr_ex = uet_ref_reg_mr_ex,
	.dereg_mr = uet_ref_dereg_mr,
	.create_ah_ex = uet_ref_create_ah_ex,
	.destroy_ah = uet_ref_destroy_ah,
	.create_cq = uet_ref_create_cq,
	.create_cq_ex = uet_ref_create_cq_ex,
	.post_send = uet_ref_post_send,
	.post_recv = uet_ref_post_recv,
	.post_recv64 = uet_ref_post_recv64,
	.poll_cq = uet_ref_poll_cq,
	.req_notify_cq = uet_ref_req_notify_cq,
	.destroy_cq = uet_ref_destroy_cq,
	.create_qp_ex = uet_ref_create_qp_ex,
	.destroy_qp = uet_ref_destroy_qp,
	.modify_qp = uet_ref_modify_qp,
	.query_qp = uet_ref_query_qp,
	.attach_mr = uet_ref_attach_mr,
	.detach_mr = uet_ref_detach_mr,
	.alloc_job = uet_ref_alloc_job,
	.dealloc_job = uet_ref_dealloc_job,
	.query_job = uet_ref_query_job,
	.export_job = uet_ref_export_job,
	.import_job = uet_ref_import_job,
	.insert_addr = uet_ref_insert_addr,
	.remove_addr = uet_ref_remove_addr,
	.query_addr = uet_ref_query_addr,
	.create_jkey = uet_ref_create_jkey,
	.destroy_jkey = uet_ref_destroy_jkey,
};

static struct verbs_context *uet_ref_alloc_context(struct ibv_device *ibdev,
						   int cmd_fd,
						   void *private_data)
{
	struct uet_ref_context *ctx;

	ctx = verbs_init_and_alloc_context(ibdev, cmd_fd, ctx, vctx,
					   RDMA_DRIVER_UET_REF);
	if (!ctx)
		return NULL;

	verbs_set_ops(&ctx->vctx, &uet_ref_ctx_ops);

	{
		struct uet_ref_get_context_resp resp = {};

		if (ibv_cmd_get_context(&ctx->vctx, NULL, 0, NULL,
					&resp.ibv_resp, sizeof(resp))) {
			verbs_err(&ctx->vctx, "get_context failed: %s\n",
				  strerror(errno));
			goto err;
		}

		ctx->db_page = resp.uet.db_page;
		ctx->max_sge = resp.uet.max_sge;
		ctx->wqe_size = resp.uet.wqe_size;
		ctx->cqe_size = resp.uet.cqe_size;

		/* uet_ref_hw.h mirrors the device's descriptor layout and
		 * the device is built separately from this provider. Ask the
		 * device what it uses and refuse to drive it if the answer
		 * differs.
		 */
		if ((resp.uet.wqe_size != UET_REF_HW_WQE_SIZE) ||
		    (resp.uet.cqe_size != UET_REF_HW_CQE_SIZE)) {
			verbs_err(&ctx->vctx,
				  "device uses %u/%u byte ring entries, this provider was built for %u/%u\n",
				  resp.uet.wqe_size, resp.uet.cqe_size,
				  UET_REF_HW_WQE_SIZE, UET_REF_HW_CQE_SIZE);
			errno = EPROTO;
			goto err;
		}

		/* The doorbell page is the one piece of the device this
		 * process maps.
		 */
		ctx->db = mmap(NULL, sysconf(_SC_PAGESIZE),
			       PROT_READ | PROT_WRITE, MAP_SHARED, cmd_fd,
			       resp.uet.db_mmap_offset);
		if (ctx->db == MAP_FAILED) {
			verbs_err(&ctx->vctx, "doorbell mmap failed: %s\n",
				  strerror(errno));
			ctx->db = NULL;
			goto err;
		}
	}

	return &ctx->vctx;

err:
	verbs_uninit_context(&ctx->vctx);
	free(ctx);

	return NULL;
}

static void uet_ref_uninit_device(struct verbs_device *verbs_device)
{
	struct uet_ref_device *dev = to_uet_ref_dev(&verbs_device->device);

	free(dev);
}

static struct verbs_device *uet_ref_device_alloc(
	struct verbs_sysfs_dev *sysfs_dev)
{
	struct uet_ref_device *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	dev->abi_version = sysfs_dev->abi_ver;

	return &dev->vdev;
}

static const struct verbs_device_ops uet_ref_dev_ops = {
	.name = "uet_ref",
	.match_min_abi_version = UET_REF_UVERBS_ABI_VERSION,
	.match_max_abi_version = UET_REF_UVERBS_ABI_VERSION,
	.match_table = hca_table,
	.alloc_device = uet_ref_device_alloc,
	.uninit_device = uet_ref_uninit_device,
	.alloc_context = uet_ref_alloc_context,
};

PROVIDER_DRIVER(uet_ref, uet_ref_dev_ops);
