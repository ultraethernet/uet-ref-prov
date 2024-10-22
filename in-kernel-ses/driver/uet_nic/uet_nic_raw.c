
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <net/protocol.h>
#include <linux/spinlock.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/inetdevice.h>
#include <net/neighbour.h>
#include <net/arp.h>

#include "uet_api_private.h"
#include "uet_nic.h"
#include "uet_util.h"
#include "uet_pkt_hdr.h"
#include "uet_def.h"

struct uet_raw_nic_dev {
	char ifname[IFNAMSIZ];
	char uetdev[IFNAMSIZ];
	int used;
};

#define UET_DEV_MAX 16

static struct uet_raw_nic_dev uet_devs[UET_DEV_MAX];

struct uet_umem {
	void *addr;
	int len;
};

struct uet_rx_queue {
	struct list_head list;
	struct net_device *dev;
	struct sk_buff_head pkts;
};

struct uet_nic_data {
	struct uet_rx_queue queue;
	struct uet_nic *nic;
};

static spinlock_t rx_queue_lock;
static struct list_head rx_queue;

static int uet_pkt_receiver(struct sk_buff *skb)
{
	unsigned long flags;
	struct list_head *entry;
	struct uet_rx_queue *queue = NULL;
	struct uet_nic_data *p_data = NULL;
	struct uet_instance *uet = NULL;

	pr_info("uet: received uet packet.\n");

	spin_lock_irqsave(&rx_queue_lock, flags);
	list_for_each(entry, &rx_queue) {
		struct uet_rx_queue *tmp = 
			container_of(entry, struct uet_rx_queue, list);
		if (tmp->dev == skb->dev) {
			queue = tmp;
			break;
		}
	}

	if (queue) {
		p_data = container_of(queue, struct uet_nic_data, queue);
	} else {
		pr_info("uet_nic: No UET NIC found.\n");
		kfree_skb(skb);
	}

	spin_unlock_irqrestore(&rx_queue_lock, flags);

	if (p_data && p_data->nic) {
		uet = container_of(p_data->nic, struct uet_instance, nic);
		spin_lock_irqsave(&uet->biglock, flags);
		skb_queue_tail(&queue->pkts, skb);
		tasklet_schedule(&uet->task);
		spin_unlock_irqrestore(&uet->biglock, flags);
	}

	return 0;
}

static int uet_pkt_err_handler(struct sk_buff *skb, u32 info)
{
	pr_debug("uet_nic: err handler\n");
	kfree_skb(skb);
	return 0;
}

static const struct net_protocol uet_protocol = {
	.handler		= uet_pkt_receiver,
	.err_handler	= uet_pkt_err_handler,
	.no_policy		= 1,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,10,0)
	.netns_ok		= 1,
#endif
};

static int uet_nic_raw_getinfo(struct uet_nic *nic,
				struct uet_nic_info *nic_info)
{
	struct uet_nic_data *p_data =
		(struct uet_nic_data *)nic->nic_priv_data;

	strncpy(nic_info->name, nic->ifname, IFNAMSIZ);
	strncpy(nic_info->network_type, "in-kernel-nic-raw", 
			UET_NET_TYPE_SIZE);
	nic_info->mtu = nic->mtu;
	strncpy(nic_info->mac_addr_str, nic->mac_addr_str, 
			ETH_ALEN * 3);
	// FIXME: check state
	nic_info->state = UET_NIC_STATE_UP;

	return 0;
}

static int uet_nic_raw_get_ipv4_nh(struct uet_nic *nic,
			uint32_t dst_ip, uint8_t *mac)
{
	struct uet_nic_data *p_data =
		(struct uet_nic_data *)nic->nic_priv_data;
	struct neighbour *n;
	uint32_t key = htonl(dst_ip);

	n = neigh_lookup(&arp_tbl, &key, p_data->queue.dev);
	if (!n) {
		// FIXME: resolve address
		pr_err("uet_nic: neigh_lookup failed for %u.%u.%u.%u.\n",
				UET_NIPQUAD(dst_ip));
		return -EAGAIN;
	}
	memcpy(mac, n->ha, ETH_ALEN);
	neigh_release(n);

	return 0;
}

static int uet_nic_raw_tx_pkt(struct uet_nic *nic,
			void *pkt, void *iphdr, size_t pkt_size)
{
	struct ethhdr *eth = (struct ethhdr *) pkt;
	struct iphdr *ipv4 = (struct iphdr *) iphdr;
	struct uet_nic_data *p_data =
		(struct uet_nic_data *)nic->nic_priv_data;
	size_t len;
	struct sk_buff* skb = dev_alloc_skb(pkt_size);

	if (!skb)
		return -ENOMEM;

	ipv4->check = 0;
	ipv4->check = uet_ipv4_csum(ipv4);

#ifdef UET_NIC_DEBUG_HEXDUMP
	uet_pkt_hex_dump(pkt, pkt_size, 0, true);
#endif

	skb->dev = p_data->queue.dev;
	skb_reserve(skb, NET_IP_ALIGN);
	skb->data = skb_put(skb, pkt_size);
	memcpy(skb->data, pkt, pkt_size);

	if (dev_queue_xmit(skb) != NET_XMIT_SUCCESS) {
		kfree_skb(skb);
		return -EAGAIN;
	}

	return 0;
}

static int uet_nic_raw_rx_pkt(struct uet_nic *nic,
			void *pkt, size_t pkt_buf_size, int *rx_pkt_size)
{
	struct uet_nic_data *p_data = 
		(struct uet_nic_data *)nic->nic_priv_data;
	struct sk_buff *skb = skb_dequeue(&p_data->queue.pkts);

	if (skb == NULL) {
		pr_info("uet_nic: [%s] RX queue empty.\n", __func__);
		return 0;
	}

	pr_info("uet_nic: [%s] len: %d data_len: %d transport: %d network: %d mac: %d\n", 
			__func__, skb->len, skb->data_len, skb->transport_header, 
			skb->network_header, skb->mac_header);

	memcpy(pkt, skb_mac_header(skb), 
		skb->len + skb->transport_header - skb->mac_header);
	*rx_pkt_size = skb->len + skb->transport_header - skb->mac_header;

	kfree_skb(skb);

	return 1;
}

static int uet_nic_raw_rx_poll(struct uet_nic *nic)
{
	struct uet_nic_data *p_data = 
		(struct uet_nic_data *)nic->nic_priv_data;
	int available = !!skb_peek(&p_data->queue.pkts);

	//pr_info("uet_nic: [%s] available = %d.\n", __func__, available);

	return available;
}

static struct uet_umem *
uet_nic_get_umem(char *start, size_t len, uet_mr_buf_type_t type)
{
	struct uet_umem *umem = kmalloc(sizeof(struct uet_umem), GFP_KERNEL);

	// FIXME: mapping to be done
	umem->addr = kmalloc(len, GFP_KERNEL);
	umem->len = len;

	return umem;
}

static void uet_nic_release_umem(struct uet_umem *umem)
{
	kfree(umem->addr);
	kfree(umem);
}

static int uet_nic_raw_mr_reg(struct uet_nic *nic,
		struct uet_mr_buf_desc *desc, uet_nic_mr_handle_t *handle)
{
	struct uet_nic_data *p_data = 
		(struct uet_nic_data *)nic->nic_priv_data;
	struct uet_umem *umem = NULL;

	if (desc->type != UET_MR_BUF_TYPE_CONTIG) {
		pr_err("uet_nic: Only CONTIG memory is supported.\n");
		return -EINVAL;
	}

	umem = uet_nic_get_umem(desc->buf, desc->len, desc->type);
	*handle = umem;
	desc->contig.dma_addr = (uet_dma_addr_t) umem->addr;

	return 0;
}

static int uet_nic_raw_mr_dereg(struct uet_nic *nic,
							uet_nic_mr_handle_t handle)
{
	struct uet_nic_data *p_data = 
		(struct uet_nic_data *)nic->nic_priv_data;
	struct uet_umem *umem = (struct uet_umem *) handle;

	uet_nic_release_umem(umem);

	return 0;
}

static void uet_nic_raw_finalize(struct uet_nic *nic, int inst_id)
{
	struct uet_nic_data *p_data = 
		(struct uet_nic_data *)nic->nic_priv_data;
	unsigned long flag;

	spin_lock_irqsave(&rx_queue_lock, flag);
	list_del(&p_data->queue.list);
	spin_unlock_irqrestore(&rx_queue_lock, flag);

	skb_queue_purge(&p_data->queue.pkts);
	dev_put(p_data->queue.dev);

	kfree(p_data);

	return;
}

static int uet_nic_raw_initialize(struct uet_nic *nic, int inst_id)
{
	struct uet_nic_data *p_data = NULL;
	unsigned long flag;
	struct net_device *dev = dev_get_by_name(&init_net, uet_devs[inst_id].ifname);
	const struct in_ifaddr *ifa;
	struct in_device *in_dev;
	int rc;

	if (dev == NULL) {
		pr_err("uet_nic: Device not found: %s\n", uet_devs[inst_id].ifname);
		return -ENODEV;
	}

	nic->min_pkt_size = UET_MIN_PKT_SIZE;
	nic->l2_hdr_size = sizeof(struct ethhdr);
	nic->min_ip_pkt_size = (nic->min_pkt_size - nic->l2_hdr_size);
	strncpy(nic->network_type, "in-kernel-nic-raw", UET_NET_TYPE_SIZE);

	strncpy(nic->ifname, uet_devs[inst_id].ifname, IFNAMSIZ);

	p_data = kcalloc(1, sizeof(struct uet_nic_data), GFP_KERNEL);
	if (p_data == NULL) {
		pr_err("uet_nic: Failed to allocate p_data.\n");
		return -ENOMEM;
	}

	skb_queue_head_init(&p_data->queue.pkts);
	p_data->queue.dev = dev;

	spin_lock_irqsave(&rx_queue_lock, flag);
	list_add(&p_data->queue.list, &rx_queue);
	spin_unlock_irqrestore(&rx_queue_lock, flag);

	nic->nic_priv_data = p_data;
	p_data->nic = nic;

	rcu_read_lock();

	in_dev = __in_dev_get_rcu(dev);
	if (!in_dev) {
		rcu_read_unlock();
		rc = -ENODEV;
		goto error;
	}

	for (ifa = (in_dev)->ifa_list; ifa; ifa = ifa->ifa_next) {
		nic->ipv4_addr = ifa->ifa_address;
		break;
	}

	snprintf(nic->ip_addr_str, INET6_ADDRSTRLEN, "%u.%u.%u.%u", 
			UET_NIPQUAD(nic->ipv4_addr));

	memcpy(nic->mac_addr, dev->dev_addr, dev->addr_len);
	uet_mac_addr_to_str(nic->mac_addr_str, nic->mac_addr);
	nic->mtu = (size_t) dev->mtu;
	nic->max_pkt_size = (nic->mtu + nic->l2_hdr_size);

	rcu_read_unlock();

	return 0;

error:

	spin_lock_irqsave(&rx_queue_lock, flag);
	list_del(&p_data->queue.list);
	spin_unlock_irqrestore(&rx_queue_lock, flag);
	dev_put(dev);
	kfree(p_data);

	return rc;
}

static struct uet_nic_ops raw_ops = {
	.nic_getinfo			= uet_nic_raw_getinfo,
	.nic_get_ipv4_nh			= uet_nic_raw_get_ipv4_nh,
	.nic_tx_pkt				= uet_nic_raw_tx_pkt,
	.nic_rx_pkt				= uet_nic_raw_rx_pkt,
	.nic_rx_poll			= uet_nic_raw_rx_poll,
	.nic_mr_reg				= uet_nic_raw_mr_reg,
	.nic_mr_dereg			= uet_nic_raw_mr_dereg,
	.nic_finalize			= uet_nic_raw_finalize,
	.nic_initialize			= uet_nic_raw_initialize,
};

static int uet_nic_open_proc(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t	uet_nic_show_proc(struct file *file, char __user *buf, 
		size_t len, loff_t *offset)
{
	int i, count = 0;

	for (i = 0; i < UET_DEV_MAX; i++) {
		if (uet_devs[i].used)
			count += sprintf(buf + count, "%d %s %s\n", i, 
					uet_devs[i].ifname, uet_devs[i].uetdev);
	}

	return count;
}

static ssize_t uet_nic_add_write_proc(struct file *file, 
		const char __user *buf, size_t len, loff_t *offset)
{
	char ifname[IFNAMSIZ], uetdev[IFNAMSIZ];
	int i;

	sscanf(buf, "%s %s", ifname, uetdev);

	for (i = 0; i < UET_DEV_MAX; i++) {
		if (uet_devs[i].used == 0)
			break;
	}

	strcpy(uet_devs[i].ifname, ifname);
	strcpy(uet_devs[i].uetdev, uetdev);
	uet_devs[i].used = 1;

	return len;
}

static ssize_t uet_nic_del_write_proc(struct file *file, 
		const char __user *buf, size_t len, loff_t *offset)
{
	int idx;

	sscanf(buf, "%d", &idx);
	uet_devs[idx].used = 0;

	return len;
}

static int uet_nic_release_proc(struct inode *inode, struct file *file)
{
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,5)
static struct proc_ops proc_show_fops = {
	.proc_open	= uet_nic_open_proc,
	.proc_read	= uet_nic_show_proc,
	.proc_release	= uet_nic_release_proc,
};

static struct proc_ops proc_add_fops = {
	.proc_open	= uet_nic_open_proc,
	.proc_write	= uet_nic_add_write_proc,
	.proc_release	= uet_nic_release_proc,
};

static struct proc_ops proc_del_fops = {
	.proc_open	= uet_nic_open_proc,
	.proc_write	= uet_nic_add_write_proc,
	.proc_release	= uet_nic_release_proc,
};
#else
static struct file_operations proc_show_fops = {
	.open		= uet_nic_open_proc,
	.read		= uet_nic_show_proc,
	.release	= uet_nic_release_proc,
};

static struct file_operations proc_add_fops = {
	.open		= uet_nic_open_proc,
	.write		= uet_nic_add_write_proc,
	.release	= uet_nic_release_proc,
};

static struct file_operations proc_del_fops = {
	.open		= uet_nic_open_proc,
	.write		= uet_nic_add_write_proc,
	.release	= uet_nic_release_proc,
};
#endif
static struct proc_dir_entry *uet_proc_parent;

static int uet_nic_raw_init(void)
{
	int i;

	uet_nic_set_ops(&raw_ops);

	spin_lock_init(&rx_queue_lock);
	INIT_LIST_HEAD(&rx_queue);

	inet_add_protocol(&uet_protocol, UET_IPPROTO);

	for (i = 0; i < UET_DEV_MAX; i++)
		memset(&uet_devs[i], 0, sizeof(struct uet_raw_nic_dev));

	uet_proc_parent = proc_mkdir("uet",NULL);
	proc_create("show", 0666, uet_proc_parent, &proc_show_fops);
	proc_create("add", 0666, uet_proc_parent, &proc_add_fops);
	proc_create("del", 0666, uet_proc_parent, &proc_del_fops);

	return 0;
}

static void uet_nic_raw_exit(void)
{
	unsigned long flag;
	struct list_head *entry;

	proc_remove(uet_proc_parent);

	inet_del_protocol(&uet_protocol, UET_IPPROTO);

	uet_nic_set_ops(NULL);

	spin_lock_irqsave(&rx_queue_lock, flag);
	list_for_each(entry, &rx_queue) {
		struct uet_rx_queue *queue = 
			container_of(entry, struct uet_rx_queue, list);
		skb_queue_purge(&queue->pkts);
		list_del(entry);
		kfree(queue);
	}
	spin_unlock_irqrestore(&rx_queue_lock, flag);
}

module_init(uet_nic_raw_init);
module_exit(uet_nic_raw_exit);

MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
MODULE_AUTHOR("Rakhahari Bhunia <rakhahari.bhunia@keysight.com>");
MODULE_DESCRIPTION("UDP tunnel for SoftUET driver");
