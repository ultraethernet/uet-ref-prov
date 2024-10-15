/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* Raw Socket NIC Interface for UET API's */

//#include <rdma/fabric.h>

//#include "uet_api_private.h"
#include "uet_nic.h"
#include "uet_def.h"

/* NIC protocol callbacks */
static int (*uet_nic_getinfo_fn)(struct uet_nic *nic,
			       struct uet_nic_info *nic_info);
static int (*uet_nic_get_ipv4_nh_fn)(struct uet_nic *nic,
				   uint32_t dst_ip,
				   uint8_t *mac);
static int (*uet_nic_tx_pkt_fn)(struct uet_nic *nic,
			      void *pkt,
			      void *iphdr,
			      size_t pkt_size);
static int (*uet_nic_rx_pkt_fn)(struct uet_nic *nic,
			      void *pkt,
			      size_t pkt_buf_size,
			      int *rx_pkt_size);
static int (*uet_nic_rx_poll_fn)(struct uet_nic *nic);
static int (*uet_nic_mr_reg_fn)(struct uet_nic *nic,
			      struct uet_mr_buf_desc *desc,
			      uet_nic_mr_handle_t *handle);
static int (*uet_nic_mr_dereg_fn)(struct uet_nic *nic,
				uet_nic_mr_handle_t handle);
static void (*uet_nic_finalize_fn)(struct uet_nic *nic);
static int (*uet_nic_initialize_fn)(struct uet_nic *nic);

void uet_nic_set_ops(struct uet_nic_ops *ops)
{
	if (ops == NULL) {
		uet_nic_getinfo_fn = NULL;
		uet_nic_get_ipv4_nh_fn = NULL;
		uet_nic_tx_pkt_fn = NULL;
		uet_nic_rx_pkt_fn = NULL;
		uet_nic_rx_poll_fn = NULL;
		uet_nic_mr_reg_fn = NULL;
		uet_nic_mr_dereg_fn = NULL;
		uet_nic_finalize_fn = NULL;
		uet_nic_initialize_fn = NULL;
	}
	uet_nic_getinfo_fn = ops->nic_getinfo;
	uet_nic_get_ipv4_nh_fn = ops->nic_get_ipv4_nh;
	uet_nic_tx_pkt_fn = ops->nic_tx_pkt;
	uet_nic_rx_pkt_fn = ops->nic_rx_pkt;
	uet_nic_rx_poll_fn = ops->nic_rx_poll;
	uet_nic_mr_reg_fn = ops->nic_mr_reg;
	uet_nic_mr_dereg_fn = ops->nic_mr_dereg;
	uet_nic_finalize_fn = ops->nic_finalize;
	uet_nic_initialize_fn = ops->nic_initialize;
}
EXPORT_SYMBOL(uet_nic_set_ops);

/* init nic resources */
int uet_nic_initialize(struct uet_nic *nic)
{
	nic->ops.nic_getinfo     = uet_nic_getinfo_fn;
	nic->ops.nic_get_ipv4_nh = uet_nic_get_ipv4_nh_fn;
	nic->ops.nic_tx_pkt      = uet_nic_tx_pkt_fn;
	nic->ops.nic_rx_pkt      = uet_nic_rx_pkt_fn;
	nic->ops.nic_rx_poll     = uet_nic_rx_poll_fn;
	nic->ops.nic_mr_reg      = uet_nic_mr_reg_fn;
	nic->ops.nic_mr_dereg    = uet_nic_mr_dereg_fn;
	nic->ops.nic_finalize    = uet_nic_finalize_fn;
	nic->ops.nic_initialize  = uet_nic_initialize_fn;

	if (!nic->ops.nic_initialize)
		BUG();

	return nic->ops.nic_initialize(nic);
}

