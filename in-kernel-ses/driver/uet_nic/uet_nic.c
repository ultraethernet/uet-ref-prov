/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* Raw Socket NIC Interface for UET API's */

#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

//#include <rdma/fabric.h>

//#include "uet_api_private.h"
#include "uet_nic.h"
#include "uet_def.h"

/* Raw Socket NIC protocol callbacks */
extern int nic_rawsock_getinfo(struct uet_nic *nic,
			       struct uet_nic_info *nic_info);
extern int nic_rawsock_get_ipv4_nh(struct uet_nic *nic,
				   uint32_t dst_ip,
				   uint8_t *mac);
extern int nic_rawsock_tx_pkt(struct uet_nic *nic,
			      void *pkt,
			      void *iphdr,
			      size_t pkt_size);
extern int nic_rawsock_rx_pkt(struct uet_nic *nic,
			      void *pkt,
			      size_t pkt_buf_size,
			      size_t *rx_pkt_size);
extern int nic_rawsock_rx_poll(struct uet_nic *nic);
extern int nic_rawsock_mr_reg(struct uet_nic *nic,
			      struct uet_mr_buf_desc *desc,
			      uet_nic_mr_handle_t *handle);
extern int nic_rawsock_mr_dereg(struct uet_nic *nic,
				uet_nic_mr_handle_t handle);
extern void nic_rawsock_finalize(struct uet_nic *nic);
extern int nic_rawsock_initialize(struct uet_nic *nic);

#if ENABLE_XDP
/* XDP NIC protocol callbacks */
extern int nic_xdp_getinfo(struct uet_nic *nic,
			   struct uet_nic_info *nic_info);
extern int nic_xdp_get_ipv4_nh(struct uet_nic *nic,
			       uint32_t dst_ip,
			       uint8_t *mac);
extern int nic_xdp_tx_pkt(struct uet_nic *nic,
			  void *pkt,
			  void *iphdr,
			  size_t pkt_size);
extern int nic_xdp_rx_pkt(struct uet_nic *nic,
			  void *pkt,
			  size_t pkt_buf_size,
			  size_t *rx_pkt_size);
extern int nic_xdp_rx_poll(struct uet_nic *nic);
extern int nic_xdp_mr_reg(struct uet_nic *nic,
			  struct uet_mr_buf_desc *desc,
			  uet_nic_mr_handle_t *handle);
extern int nic_xdp_mr_dereg(struct uet_nic *nic,
			    uet_nic_mr_handle_t handle);
extern void nic_xdp_finalize(struct uet_nic *nic);
extern int nic_xdp_initialize(struct uet_nic *nic);
#endif

/* init nic resources */
int uet_nic_initialize(struct uet_nic *nic)
{
	char *nic_shim;

	/* get interface name from environment variable */
	nic_shim = getenv(UET_NIC_SHIM);

#if ENABLE_XDP
	/* for an XDP build, make its shim the default */
	if (nic_shim == NULL)
		nic_shim = "xdp";
#endif

	if ((nic_shim == NULL) || (strcmp(nic_shim, "rawsock") == 0)) {
		nic->nic_getinfo     = nic_rawsock_getinfo;
		nic->nic_get_ipv4_nh = nic_rawsock_get_ipv4_nh;
		nic->nic_tx_pkt      = nic_rawsock_tx_pkt;
		nic->nic_rx_pkt      = nic_rawsock_rx_pkt;
		nic->nic_rx_poll     = nic_rawsock_rx_poll;
		nic->nic_mr_reg      = nic_rawsock_mr_reg;
		nic->nic_mr_dereg    = nic_rawsock_mr_dereg;
		nic->nic_finalize    = nic_rawsock_finalize;
		nic->nic_initialize  = nic_rawsock_initialize;
#if ENABLE_XDP
	} else if (strcmp(nic_shim, "xdp") == 0) {
		nic->nic_getinfo     = nic_xdp_getinfo;
		nic->nic_get_ipv4_nh = nic_xdp_get_ipv4_nh;
		nic->nic_tx_pkt      = nic_xdp_tx_pkt;
		nic->nic_rx_pkt      = nic_xdp_rx_pkt;
		nic->nic_rx_poll     = nic_xdp_rx_poll;
		nic->nic_mr_reg      = nic_xdp_mr_reg;
		nic->nic_mr_dereg    = nic_xdp_mr_dereg;
		nic->nic_finalize    = nic_xdp_finalize;
		nic->nic_initialize  = nic_xdp_initialize;
#endif
	} else {
		UET_PRINT_ERR("invalid UET_NIC_SHIM environment variable");
		return -ENODEV;
	}

	return nic->nic_initialize(nic);
}

