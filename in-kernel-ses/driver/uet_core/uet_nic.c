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
int (*uet_nic_getinfo_fn)(struct uet_nic *nic,
			       struct uet_nic_info *nic_info);
int (*uet_nic_get_ipv4_nh_fn)(struct uet_nic *nic,
				   uint32_t dst_ip,
				   uint8_t *mac);
int (*uet_nic_tx_pkt_fn)(struct uet_nic *nic,
			      void *pkt,
			      void *iphdr,
			      size_t pkt_size);
int (*uet_nic_rx_pkt_fn)(struct uet_nic *nic,
			      void *pkt,
			      size_t pkt_buf_size,
			      size_t *rx_pkt_size);
int (*uet_nic_rx_poll_fn)(struct uet_nic *nic);
int (*uet_nic_mr_reg_fn)(struct uet_nic *nic,
			      struct uet_mr_buf_desc *desc,
			      uet_nic_mr_handle_t *handle);
int (*uet_nic_mr_dereg_fn)(struct uet_nic *nic,
				uet_nic_mr_handle_t handle);
void (*uet_nic_finalize_fn)(struct uet_nic *nic);
int (*uet_nic_initialize_fn)(struct uet_nic *nic);

EXPORT_SYMBOL(uet_nic_getinfo_fn);
EXPORT_SYMBOL(uet_nic_get_ipv4_nh_fn);
EXPORT_SYMBOL(uet_nic_tx_pkt_fn);
EXPORT_SYMBOL(uet_nic_rx_pkt_fn);
EXPORT_SYMBOL(uet_nic_rx_poll_fn);
EXPORT_SYMBOL(uet_nic_mr_reg_fn);
EXPORT_SYMBOL(uet_nic_mr_dereg_fn);
EXPORT_SYMBOL(uet_nic_finalize_fn);
EXPORT_SYMBOL(uet_nic_initialize_fn);


/* init nic resources */
int uet_nic_initialize(struct uet_nic *nic)
{
	nic->nic_getinfo     = uet_nic_getinfo_fn;
	nic->nic_get_ipv4_nh = uet_nic_get_ipv4_nh_fn;
	nic->nic_tx_pkt      = uet_nic_tx_pkt_fn;
	nic->nic_rx_pkt      = uet_nic_rx_pkt_fn;
	nic->nic_rx_poll     = uet_nic_rx_poll_fn;
	nic->nic_mr_reg      = uet_nic_mr_reg_fn;
	nic->nic_mr_dereg    = uet_nic_mr_dereg_fn;
	nic->nic_finalize    = uet_nic_finalize_fn;
	nic->nic_initialize  = uet_nic_initialize_fn;

	return nic->nic_initialize(nic);
}

