
#include <linux/module.h>
#include <linux/kernel.h>

#include "uet_nic.h"

static int uet_nic_udptunnel_getinfo(struct uet_nic *nic,
				struct uet_nic_info *nic_info)
{
	return 0;
}

static int uet_nic_udptunnel_get_ipv4_nh(struct uet_nic *nic,
			uint32_t dst_ip, uint8_t *mac)
{
	return 0;
}

static int uet_nic_udptunnel_tx_pkt(struct uet_nic *nic,
			void *pkt, void *iphdr, size_t pkt_size)
{
	return 0;
}

static int uet_nic_udptunnel_rx_pkt(struct uet_nic *nic,
			void *pkt, size_t pkt_buf_size, size_t *rx_pkt_size)
{
	return 0;
}

static int uet_nic_udptunnel_rx_poll(struct uet_nic *nic)
{
	return 0;
}

static int uet_nic_udptunnel_mr_reg(struct uet_nic *nic,
		struct uet_mr_buf_desc *desc, uet_nic_mr_handle_t *handle)
{
	return 0;
}

static int uet_nic_udptunnel_mr_dereg(struct uet_nic *nic,
							uet_nic_mr_handle_t handle)
{
	return 0;
}

static void uet_nic_udptunnel_finalize(struct uet_nic *nic)
{
	return;
}

static int uet_nic_udptunnel_initialize(struct uet_nic *nic)
{
	return 0;
}

static int uet_nic_udptunnel_init(void)
{
	uet_nic_getinfo_fn			= uet_nic_udptunnel_getinfo;
	uet_nic_get_ipv4_nh_fn		= uet_nic_udptunnel_get_ipv4_nh;
	uet_nic_tx_pkt_fn			= uet_nic_udptunnel_tx_pkt;
	uet_nic_rx_pkt_fn			= uet_nic_udptunnel_rx_pkt;
	uet_nic_rx_poll_fn			= uet_nic_udptunnel_rx_poll;
	uet_nic_mr_reg_fn			= uet_nic_udptunnel_mr_reg;
	uet_nic_mr_dereg_fn			= uet_nic_udptunnel_mr_dereg;
	uet_nic_finalize_fn			= uet_nic_udptunnel_finalize;
	uet_nic_initialize_fn		= uet_nic_udptunnel_initialize;

	return 0;
}

static void uet_nic_udptunnel_exit(void)
{
	uet_nic_getinfo_fn			= NULL;
	uet_nic_get_ipv4_nh_fn		= NULL;
	uet_nic_tx_pkt_fn			= NULL;
	uet_nic_rx_pkt_fn			= NULL;
	uet_nic_rx_poll_fn			= NULL;
	uet_nic_mr_reg_fn			= NULL;
	uet_nic_mr_dereg_fn			= NULL;
	uet_nic_finalize_fn			= NULL;
	uet_nic_initialize_fn		= NULL;
}

module_init(uet_nic_udptunnel_init);
module_exit(uet_nic_udptunnel_exit);

MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
MODULE_AUTHOR("Rakhahari Bhunia <rakhahari.bhunia@keysight.com>");
MODULE_DESCRIPTION("UDP tunnel for SoftUET driver");
