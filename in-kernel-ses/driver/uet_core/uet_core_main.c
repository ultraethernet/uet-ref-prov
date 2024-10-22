#include <linux/cdev.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <asm/atomic.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/delay.h>
#include <linux/cdev.h>	
#include <linux/uaccess.h>

#include "uet_api_private.h"

/* store the major number extracted by dev_t */

#define UET_MAX_MINOR 16

int uet_major = 0;
int uet_minor = 0;
int uet_num_minor = UET_MAX_MINOR;

#define DEVICE_NAME "softuet"
char* uet_name = DEVICE_NAME;

struct uet_dev {
	int inst_id;
	struct cdev cdev;
	uet_handle_t uet;
	struct semaphore sem;
};

struct uet_dev uet_devs[UET_MAX_MINOR];

static int uet_open(struct inode *inode, struct file *filp)
{
	struct uet_dev *dev;
	int rc = -EBUSY;

	pr_info("uet: (IN) %s\n", __func__);
	dev = container_of(inode->i_cdev, struct uet_dev, cdev);

	down(&dev->sem);

	if (dev->uet) {
		pr_err("uet: device is being used already.\n");
		goto exit;
	}

	rc = uet_initialize_internal(&dev->uet, dev->inst_id);
	if (rc) {
		pr_err("uet: failed to create uet instance.\n");
		goto exit;
	}

	filp->private_data = dev;

exit:
	up(&dev->sem);
	pr_info("uet: (OUT) %s rc = %d\n", __func__, rc);

	return rc;
}

static int uet_release(struct inode *inode, struct file *filp)
{
	struct uet_dev *dev = (struct uet_dev *) filp->private_data;

	pr_info("uet: (IN) %s\n", __func__);
	down(&dev->sem);

	if (dev->uet == NULL) {
		pr_warn("uet: instance closed unexpectedly.\n");
	} else {
		uet_finalize_internal(dev->uet, dev->inst_id);
		dev->uet = NULL;
	}

	up(&dev->sem);
	pr_info("uet: (OUT) %s\n", __func__);

	return 0;
}

static const char *const ioctl_str[] = {
	[UET_IOCTL_INSTANCE_CREATE]		= "UET_IOCTL_INSTANCE_CREATE",
	[UET_IOCTL_INSTANCE_FINALIZE]		= "UET_IOCTL_INSTANCE_FINALIZE",
	[UET_IOCTL_NIC_GET_INFO]		= "UET_IOCTL_NIC_GET_INFO",
	[UET_IOCTL_NIC_GET_ADDR_IPV4]		= "UET_IOCTL_NIC_GET_ADDR_IPV4",
	[UET_IOCTL_DOMAIN_CREATE]		= "UET_IOCTL_DOMAIN_CREATE",
	[UET_IOCTL_DOMAIN_CLOSE]		= "UET_IOCTL_DOMAIN_CLOSE",
	[UET_IOCTL_EP_CREATE]			= "UET_IOCTL_EP_CREATE",
	[UET_IOCTL_EP_GET_NAME]			= "UET_IOCTL_EP_GET_NAME",
	[UET_IOCTL_EP_BIND_CQ]			= "UET_IOCTL_EP_BIND_CQ",
	[UET_IOCTL_EP_ENABLE]			= "UET_IOCTL_EP_ENABLE",
	[UET_IOCTL_EP_CLOSE]			= "UET_IOCTL_EP_CLOSE",
	[UET_IOCTL_CQ_READ]			= "UET_IOCTL_CQ_READ",
	[UET_IOCTL_CQ_READERR]			= "UET_IOCTL_CQ_READERR",
	[UET_IOCTL_CQ_CLOSE]			= "UET_IOCTL_CQ_CLOSE",
	[UET_IOCTL_AV_INSERT]			= "UET_IOCTL_AV_INSERT",
	[UET_IOCTL_AV_REMOVE]			= "UET_IOCTL_AV_REMOVE",
	[UET_IOCTL_MR_REG]			= "UET_IOCTL_MR_REG",
	[UET_IOCTL_MR_KEY]			= "UET_IOCTL_MR_KEY",
	[UET_IOCTL_MR_BIND_EP]			= "UET_IOCTL_MR_BIND_EP",
	[UET_IOCTL_MR_ENABLE]			= "UET_IOCTL_MR_ENABLE",
	[UET_IOCTL_MR_CLOSE]			= "UET_IOCTL_MR_CLOSE",
	[UET_IOCTL_REQ_SEND]			= "UET_IOCTL_REQ_SEND",
	[UET_IOCTL_REQ_RECV]			= "UET_IOCTL_REQ_RECV",
};

static long uet_ioctl(struct file *filp, unsigned int cmd, 
					  unsigned long arg)
{
	struct uet_dev *dev = (struct uet_dev *) filp->private_data;
	int rc = 0;

	if (cmd != UET_IOCTL_CQ_READ)
		pr_info("uet: (IN) %s %s\n", __func__, ioctl_str[cmd]);

	switch (cmd) {
		case UET_IOCTL_INSTANCE_CREATE:
			{
				struct uet_ioctl_inst_init_args args;

				if (copy_from_user(&args, (void *)arg, 
					sizeof(struct uet_ioctl_inst_init_args))) {
					rc = -EFAULT;
					goto exit;
				}

				down(&dev->sem);
				if (dev->uet == NULL) {
					rc = -ENODEV;
					up(&dev->sem);
					goto exit;
				}

				args.out.rc = 0;
				args.out.handle = dev->uet;

				up(&dev->sem);

				if (copy_to_user((void *)arg, &args,
					sizeof(struct uet_ioctl_inst_init_args))) {
					rc = -EFAULT;
					goto exit;
				}
			}
			break;
		case UET_IOCTL_INSTANCE_FINALIZE:
			// FIXME: No need for this ioctl
			break;
		case UET_IOCTL_NIC_GET_INFO:
			{
				struct uet_ioctl_nic_getinfo_args args;

				if (copy_from_user(&args, (void *)arg,
					sizeof(struct uet_ioctl_nic_getinfo_args))) {
					rc = -EFAULT;
					goto exit;
				}

				down(&dev->sem);
				rc = uet_nic_getinfo_internal(args.in.handle, 
						&args.out.nic_info);
				if (rc) {
					pr_err("uet: failed to get nic info.\n");
					up(&dev->sem);
					goto exit;
				}
				args.out.rc = 0;

				up(&dev->sem);

				if (copy_to_user((void *)arg, &args,
					sizeof(struct uet_ioctl_nic_getinfo_args))) {
					rc = -EFAULT;
					goto exit;
				}
			}
			break;
		case UET_IOCTL_NIC_GET_ADDR_IPV4:
			{
				struct uet_ioctl_nic_get_addr_ipv4 args;

				if (copy_from_user(&args, (void *)arg,
					sizeof(struct uet_ioctl_nic_get_addr_ipv4))) {
					rc = -EFAULT;
					goto exit;
				}

				down(&dev->sem);

				rc = uet_get_nic_addr_ipv4_internal(
						args.in.handle, &args.out.ipv4_addr);
				if (rc) {
					pr_err("uet: get_nic_addr_ipv4 failed.\n");
					up(&dev->sem);
					goto exit;
				}
				args.out.rc = 0;

				up(&dev->sem);

				if (copy_to_user((void *)arg, &args,
					sizeof(struct uet_ioctl_nic_get_addr_ipv4))) {
					rc = -EFAULT;
					goto exit;
				}
			}
			break;
		case UET_IOCTL_DOMAIN_CREATE:
			{
				struct uet_ioctl_domain_create_args args;

				if (copy_from_user(&args, (void *)arg,
					sizeof(struct uet_ioctl_domain_create_args))) {
					rc = -EFAULT;
					goto exit;
				}

				down(&dev->sem);

				rc = uet_domain_internal(args.in.handle,
						args.in.mr_cnt, args.in.mr_mode,
						(void *)args.in.context, 
						&args.out.domain_handle);
				if (rc) {
					pr_err("uet: uet_domain failed.\n");
					up(&dev->sem);
					goto exit;
				}
				args.out.rc = 0;

				up(&dev->sem);

				if (copy_to_user((void *)arg, &args,
					sizeof(struct uet_ioctl_domain_create_args))) {
					rc = -EFAULT;
					goto exit;
				}
			}
			break;
		case UET_IOCTL_DOMAIN_CLOSE:
			{
				struct uet_ioctl_domain_close_args args;

				if (copy_from_user(&args, (void *)arg,
					sizeof(struct uet_ioctl_domain_close_args))) {
					rc = -EFAULT;
					goto exit;
				}

				down(&dev->sem);

				rc = uet_domain_close_internal(
						args.in.domain_handle);
				if (rc) {
					pr_err("uet: domain_close failed.\n");
					up(&dev->sem);
					goto exit;
				}
				args.out.rc = 0;

				up(&dev->sem);

				if (copy_to_user((void *)arg, &args,
					sizeof(struct uet_ioctl_domain_close_args))) {
					rc = -EFAULT;
					goto exit;
				}
			}
			break;
		case UET_IOCTL_EP_CREATE:
			{
				struct uet_ioctl_ep_create_args args;

				if (copy_from_user(&args, (void *)arg,
					sizeof(struct uet_ioctl_ep_create_args))) {
					rc = -EFAULT;
					goto exit;
				}

				down(&dev->sem);

				rc = uet_endpoint_internal(args.in.domain_handle,
						&args.in.src_addr, args.in.src_addrlen,
						args.in.num_rx_desc, args.in.num_tx_desc,
						args.in.pds_mode, args.in.tclass,
						args.in.use_default_tos, 
						(void *)args.in.context,
						&args.out.ep_handle);
				if (rc) {
					pr_err("uet: endpoint create failed.\n");
					up(&dev->sem);
					goto exit;
				}
				args.out.rc = 0;

				up(&dev->sem);

				if (copy_to_user((void *)arg, &args,
					sizeof(struct uet_ioctl_ep_create_args))) {
					rc = -EFAULT;
					goto exit;
				}
			}
			break;
		case UET_IOCTL_EP_GET_NAME:
			{
				struct uet_ioctl_ep_get_name_args args;

				if (copy_from_user(&args, (void *)arg,
					sizeof(struct uet_ioctl_ep_get_name_args))) {
					rc = -EFAULT;
					goto exit;
				}

				down(&dev->sem);

				rc = uet_getname_internal(args.in.ep_handle,
						&args.out.uet_addr);
				if (rc) {
					pr_err("uet: getname failed.\n");
					up(&dev->sem);
					goto exit;
				}
				args.out.rc = 0;

				up(&dev->sem);

				if (copy_to_user((void *)arg, &args,
					sizeof(struct uet_ioctl_ep_get_name_args))) {
					rc = -EFAULT;
					goto exit;
				}
			}
			break;
		case UET_IOCTL_EP_BIND_CQ:
			{
				struct uet_ioctl_ep_bind_cq_args args;

				if (copy_from_user(&args, (void *)arg,
					sizeof(struct uet_ioctl_ep_bind_cq_args))) {
					rc = -EFAULT;
					goto exit;
				}

				down(&dev->sem);

				rc = uet_ep_bind_cq_internal(args.in.ep_handle,
						args.in.cq_flags, args.in.cq_type,
						args.in.cq_size, (void *)args.in.context,
						&args.out.cq_handle);
				if (rc) {
					pr_err("uet: ep_bind_cq failed.\n");
					up(&dev->sem);
					goto exit;
				}
				args.out.rc = 0;

				up(&dev->sem);

				if (copy_to_user((void *)arg, &args,
					sizeof(struct uet_ioctl_ep_bind_cq_args))) {
					rc = -EFAULT;
					goto exit;
				}
			}
			break;
		case UET_IOCTL_EP_ENABLE:
			{
				struct uet_ioctl_ep_enable_args args;

				if (copy_from_user(&args, (void *)arg,
					sizeof(struct uet_ioctl_ep_enable_args))) {
					rc = -EFAULT;
					goto exit;
				}

				down(&dev->sem);

				rc = uet_ep_enable_internal(args.in.ep_handle);
				if (rc) {
					pr_err("uet: ep_enable failed.\n");
					up(&dev->sem);
					goto exit;
				}
				args.out.rc = 0;

				up(&dev->sem);

				if (copy_to_user((void *)arg, &args,
					sizeof(struct uet_ioctl_ep_enable_args))) {
					rc = -EFAULT;
					goto exit;
				}
			}
			break;
		case UET_IOCTL_EP_CLOSE:
			{
				struct uet_ioctl_ep_close_args args;

				if (copy_from_user(&args, (void *)arg,
					sizeof(struct uet_ioctl_ep_close_args))) {
					rc = -EFAULT;
					goto exit;
				}

				down(&dev->sem);

				rc = uet_ep_close_internal(args.in.ep_handle);
				if (rc) {
					pr_err("uet: ep_close failed.\n");
					up(&dev->sem);
					goto exit;
				}
				args.out.rc = 0;

				up(&dev->sem);

				if (copy_to_user((void *)arg, &args,
					sizeof(struct uet_ioctl_ep_close_args))) {
					rc = -EFAULT;
					goto exit;
				}
			}
			break;
		case UET_IOCTL_CQ_READ:
			{
				struct uet_ioctl_cq_read_args args;
				size_t count;

				if (copy_from_user(&args, (void *)arg,
					sizeof(struct uet_ioctl_cq_read_args))) {
					rc = -EFAULT;
					goto exit;
				}

				if (args.in.max_count > UET_IOCTL_CQ_READ_MAX) {
					rc = -EINVAL;
					goto exit;
				}

				down(&dev->sem);

				count = uet_cq_read_internal(args.in.cq_handle,
						&args.out.buf[0], args.in.max_count);
				if (count < 0) {
					pr_err("uet: cq_read failed.\n");
					up(&dev->sem);
					rc = count;
				} else {
					up(&dev->sem);
					args.out.count = count;
					args.out.rc = 0;
					if (copy_to_user((void *)arg, &args,
						sizeof(struct uet_ioctl_cq_read_args))) {
						pr_info("uet: %s:%d copy_to_user failed.\n", __func__, __LINE__);
						rc = -EFAULT;
						goto exit;
					}
				}
			}
			break;
		case UET_IOCTL_CQ_READERR:
			{
				struct uet_ioctl_cq_readerr_args args;

				if (copy_from_user(&args, (void *)arg,
					sizeof(struct uet_ioctl_cq_readerr_args))) {
					rc = -EFAULT;
					goto exit;
				}

				down(&dev->sem);

				rc = uet_cq_readerr_internal(args.in.cq_handle,
						&args.out.buf);
				if (rc != 1) {
					up(&dev->sem);
					pr_err("uet: cq_readerr failed.\n");
					goto exit;
				}
				args.out.rc = 1;
				args.out.count = 1;

				up(&dev->sem);

				if (copy_to_user((void *)arg, &args,
					sizeof(struct uet_ioctl_cq_readerr_args))) {
					rc = -EFAULT;
					goto exit;
				}
			}
			break;
		case UET_IOCTL_CQ_CLOSE:
			{
				struct uet_ioctl_cq_close_args args;

				if (copy_from_user(&args, (void *)arg,
					sizeof(struct uet_ioctl_cq_close_args))) {
					rc = -EFAULT;
					goto exit;
				}

				down(&dev->sem);

				rc = uet_cq_close_internal(args.in.cq_handle);
				if (rc) {
					up(&dev->sem);
					pr_err("uet: cq_close failed.\n");
					goto exit;
				}
				args.out.rc = 0;

				up(&dev->sem);

				if (copy_to_user((void *)arg, &args,
					sizeof(struct uet_ioctl_cq_close_args))) {
					rc = -EFAULT;
					goto exit;
				}
			}
			break;
		case UET_IOCTL_AV_INSERT:
			{
				struct uet_ioctl_av_insert_args args;

				if (copy_from_user(&args, (void *)arg,
					sizeof(struct uet_ioctl_av_insert_args))) {
					rc = -EFAULT;
					goto exit;
				}

				down(&dev->sem);

				rc = uet_av_insert_internal(args.in.domain_handle,
						&args.in.uet_addr, &args.out.addr_handle);
				if (rc) {
					pr_err("uet: av_insert failed.\n");
					up(&dev->sem);
					goto exit;
				}
				args.out.rc = 0;

				up(&dev->sem);

				if (copy_to_user((void *)arg, &args,
					sizeof(struct uet_ioctl_av_insert_args))) {
					rc = -EFAULT;
					goto exit;
				}
			}
			break;
		case UET_IOCTL_AV_REMOVE:
			{
				struct uet_ioctl_av_remove_args args;

				if (copy_from_user(&args, (void *)arg,
					sizeof(struct uet_ioctl_av_remove_args))) {
					rc = -EFAULT;
					goto exit;
				}

				down(&dev->sem);

				rc = uet_av_remove_internal(args.in.addr_handle);
				if (rc) {
					pr_err("uet: av_remove failed.\n");
					up(&dev->sem);
					goto exit;
				}
				args.out.rc = 0;

				up(&dev->sem);

				if (copy_to_user((void *)arg, &args,
					sizeof(struct uet_ioctl_av_remove_args))) {
					rc = -EFAULT;
					goto exit;
				}
			}
			break;
		case UET_IOCTL_MR_REG:
			{
				struct uet_ioctl_mr_reg_args args;

				if (copy_from_user(&args, (void *)arg,
					sizeof(struct uet_ioctl_mr_reg_args))) {
					rc = -EFAULT;
					goto exit;
				}

				down(&dev->sem);

				rc = uet_mr_reg_internal(args.in.domain_handle,
					args.in.buf, args.in.len, args.in.access,
					args.in.requested_key, args.in.flags,
					(void *)args.in.context, &args.out.mr_handle);
				if (rc) {
					pr_err("uet: mr_reg failed.\n");
					up(&dev->sem);
					goto exit;
				}
				args.out.rc = 0;

				up(&dev->sem);

				if (copy_to_user((void *)arg, &args,
					sizeof(struct uet_ioctl_mr_reg_args))) {
					rc = -EFAULT;
					goto exit;
				}
			}
			break;
		case UET_IOCTL_MR_KEY:
			{
				struct uet_ioctl_mr_key_args args;

				if (copy_from_user(&args, (void *)arg,
					sizeof(struct uet_ioctl_mr_key_args))) {
					rc = -EFAULT;
					goto exit;
				}

				down(&dev->sem);

				rc = uet_mr_key_internal(args.in.mr_handle);
				if (rc) {
					pr_err("uet: mr_key failed.\n");
					up(&dev->sem);
					goto exit;
				}
				args.out.rc = 0;
				args.out.mr_key = rc;

				up(&dev->sem);

				if (copy_to_user((void *)arg, &args,
					sizeof(struct uet_ioctl_mr_key_args))) {
					rc = -EFAULT;
					goto exit;
				}
			}
			break;
		case UET_IOCTL_MR_BIND_EP:
			{
				struct uet_ioctl_ep_bind_mr_args args;

				if (copy_from_user(&args, (void *)arg,
					sizeof(struct uet_ioctl_ep_bind_mr_args))) {
					rc = -EFAULT;
					goto exit;
				}

				down(&dev->sem);

				rc = uet_ep_bind_mr_internal(args.in.ep_handle,
						args.in.mr_handle);
				if (rc) {
					pr_err("uet: ep_bind_mr failed.\n");
					up(&dev->sem);
					goto exit;
				}
				args.out.rc = 0;

				up(&dev->sem);

				if (copy_to_user((void *)arg, &args,
					sizeof(struct uet_ioctl_ep_bind_mr_args))) {
					rc = -EFAULT;
					goto exit;
				}
			}
			break;
		case UET_IOCTL_MR_ENABLE:
			{
				struct uet_ioctl_mr_enable_args args;

				if (copy_from_user(&args, (void *)arg,
					sizeof(struct uet_ioctl_mr_enable_args))) {
					rc = -EFAULT;
					goto exit;
				}

				down(&dev->sem);

				rc = uet_mr_enable_internal(args.in.mr_handle);
				if (rc) {
					pr_err("uet: mr_enable failed.\n");
					up(&dev->sem);
					goto exit;
				}
				args.out.rc = 0;

				up(&dev->sem);

				if (copy_to_user((void *)arg, &args,
					sizeof(struct uet_ioctl_mr_enable_args))) {
					rc = -EFAULT;
					goto exit;
				}
			}
			break;
		case UET_IOCTL_MR_CLOSE:
			{
				struct uet_ioctl_mr_close_args args;

				if (copy_from_user(&args, (void *)arg,
					sizeof(struct uet_ioctl_mr_close_args))) {
					rc = -EFAULT;
					goto exit;
				}

				down(&dev->sem);

				rc = uet_mr_close_internal(args.in.mr_handle);
				if (rc) {
					pr_err("uet: mr_close failed.\n");
					up(&dev->sem);
					goto exit;
				}
				args.out.rc = 0;

				up(&dev->sem);

				if (copy_to_user((void *)arg, &args,
					sizeof(struct uet_ioctl_mr_close_args))) {
					rc = -EFAULT;
					goto exit;
				}
			}
			break;
		case UET_IOCTL_REQ_SEND:
			{
				struct uet_ioctl_send_req_args args;
				void *buf;

				if (copy_from_user(&args, (void *)arg,
					sizeof(struct uet_ioctl_send_req_args))) {
					rc = -EFAULT;
					goto exit;
				}

				buf = kmalloc(args.in.len, GFP_KERNEL);
				if (buf == NULL) {
					rc = -ENOMEM;
					goto exit;
				}

				down(&dev->sem);

				rc = uet_send_req_api_common(args.in.send_req_api,
						args.in.ep_handle, args.in.job_id, 
						buf, args.in.len, 
						args.in.mr_handle, args.in.dst_addr_handle,
						args.in.tag, args.in.imm_data, 
						args.in.remote_mem_addr, 
						args.in.remote_key, 
						(void *)args.in.context);
				if (rc) {
					pr_err("uet: send_req_api failed.\n");
					up(&dev->sem);
					goto exit;
				}
				args.out.rc = 0;

				up(&dev->sem);

				if (copy_to_user((void *)arg, &args,
					sizeof(struct uet_ioctl_send_req_args))) {
					rc = -EFAULT;
					goto exit;
				}
			}
			break;
		case UET_IOCTL_REQ_RECV:
			{
				struct uet_ioctl_recv_api_args args;
				void *buf;

				if (copy_from_user(&args, (void *)arg,
					sizeof(struct uet_ioctl_recv_api_args))) {
					rc = -EFAULT;
					goto exit;
				}

				buf = kmalloc(args.in.len, GFP_KERNEL);
				if (buf == NULL) {
					rc = -ENOMEM;
					goto exit;
				}

				down(&dev->sem);

				rc = uet_recv_api_common(args.in.recv_api,
						args.in.ep_handle, args.in.job_id,
						buf, args.in.len, 
						args.in.mr_handle, args.in.src_addr_handle,
						args.in.tag, args.in.ignore,
						(void *)args.in.context);
				if (rc) {
					pr_err("uet: recv_api failed.\n");
					up(&dev->sem);
					goto exit;
				}
				args.out.rc = 0;

				up(&dev->sem);

				if (copy_to_user((void *)arg, &args,
					sizeof(struct uet_ioctl_recv_api_args))) {
					rc = -EFAULT;
					goto exit;
				}
			}
			break;
		default:
			break;
	}

	if (cmd != UET_IOCTL_CQ_READ)
		pr_info("uet: (OUT) %s\n", __func__);

	return 0;

exit:
	pr_info("uet: (OUT) %s rc = %d\n", __func__, rc);
	return rc;
}

static unsigned int uet_poll(struct file *filp, struct poll_table_struct *wait)
{
	struct uet_dev *dev = (struct uet_dev *) filp->private_data;
	unsigned int mask = 0;

	pr_info("uet: (IN) %s\n", __func__);
	down(&dev->sem);

	mask = uet_poll_internal(dev->uet, filp, wait);

	up(&dev->sem);
	pr_info("uet: (OUT) %s\n", __func__);

	return mask;
}

struct file_operations uet_fops = {
	.owner = THIS_MODULE,
	.read = NULL,
	.write = NULL,
	.open = uet_open,
	.unlocked_ioctl = uet_ioctl,
	.poll = uet_poll,
	.release = uet_release
};

static void uet_setup_cdev(void)
{
	int i;

	for (i = 0; i < uet_num_minor; i++) {
		dev_t devno = MKDEV(uet_major, i);
		cdev_init(&uet_devs[i].cdev, &uet_fops);
		uet_devs[i].cdev.owner = THIS_MODULE;
		uet_devs[i].cdev.ops = &uet_fops;
		cdev_add(&uet_devs[i].cdev, devno, 1);
		sema_init(&uet_devs[i].sem, 1);
		uet_devs[i].uet = NULL;
		uet_devs[i].inst_id = i;
	}
}

static void uet_destroy_cdev(void)
{
	int i;

	for (i = 0; i < uet_num_minor; i++) {
		down(&uet_devs[i].sem);
		if (uet_devs[i].uet) {
			uet_finalize_internal(uet_devs[i].uet, i);
		}
		up(&uet_devs[i].sem);
		cdev_del(&uet_devs[i].cdev);
	}
}



static int uet_init(void)
{
	dev_t           devno = 0;
	int             result = 0;

	result = alloc_chrdev_region(&devno, uet_minor, 
			uet_num_minor, uet_name);
	uet_major = MAJOR(devno);
	if (result < 0) {
		pr_err("uet: can't get major number %d\n", uet_major);
		goto fail;
	}

	pr_info("uet: uet major: %d minor: %d\n", 
			MAJOR(devno), MINOR(devno));

	uet_setup_cdev();

	pr_info("uet: module loaded\n");
	return 0;

fail:
	return result;
}

static void uet_exit(void)
{
	dev_t devno = MKDEV(uet_major, uet_minor);

	uet_destroy_cdev();
	unregister_chrdev_region(devno, uet_num_minor);

	pr_info("uet: module unloaded\n");
}

module_init(uet_init);
module_exit(uet_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rakhahari Bhunia <rakhahari.bhunia@keysight.com>");
MODULE_DESCRIPTION("SoftUET Driver Core Module");
MODULE_VERSION("0.1");

