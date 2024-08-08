/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* Raw Socket NIC Interface for UET API's */

//#include <rdma/fabric.h>

//#include "uet_api_private.h"
#include "uet_nic.h"
#include "uet_def.h"

/* Raw Socket NIC protocol callbacks */
extern int uet_nic_getinfo(struct uet_nic *nic,
			       struct uet_nic_info *nic_info);
extern int uet_nic_get_ipv4_nh(struct uet_nic *nic,
				   uint32_t dst_ip,
				   uint8_t *mac);
extern int uet_nic_tx_pkt(struct uet_nic *nic,
			      void *pkt,
			      void *iphdr,
			      size_t pkt_size);
extern int uet_nic_rx_pkt(struct uet_nic *nic,
			      void *pkt,
			      size_t pkt_buf_size,
			      size_t *rx_pkt_size);
extern int uet_nic_rx_poll(struct uet_nic *nic);
extern int uet_nic_mr_reg(struct uet_nic *nic,
			      struct uet_mr_buf_desc *desc,
			      uet_nic_mr_handle_t *handle);
extern int uet_nic_mr_dereg(struct uet_nic *nic,
				uet_nic_mr_handle_t handle);
extern void uet_nic_finalize(struct uet_nic *nic);
extern int uet_nic_initialize(struct uet_nic *nic);

/* init nic resources */
int uet_nic_initialize(struct uet_nic *nic)
{
	nic->nic_getinfo     = uet_nic_getinfo;
	nic->nic_get_ipv4_nh = uet_nic_get_ipv4_nh;
	nic->nic_tx_pkt      = uet_nic_tx_pkt;
	nic->nic_rx_pkt      = uet_nic_rx_pkt;
	nic->nic_rx_poll     = uet_nic_rx_poll;
	nic->nic_mr_reg      = uet_nic_mr_reg;
	nic->nic_mr_dereg    = uet_nic_mr_dereg;
	nic->nic_finalize    = uet_nic_finalize;
	nic->nic_initialize  = uet_nic_initialize;

	return nic->nic_initialize(nic);
}

