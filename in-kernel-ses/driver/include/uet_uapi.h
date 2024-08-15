
#ifndef _UET_UAPI_H_
#define _UET_UAPI_H_

#include <linux/if.h>
#include <linux/if_ether.h>
#include "uet_addr.h"

/* TODO: remove default job id when addr resolutions works */
#define UET_DEF_JOB_ID  1

#define UET_JOB_ID_ANY  0xffffffff  /* match any job id */
#define UET_NULL_HANDLE NULL

#define UET_FLAGS_NONE	0

#define UET_EXACT_MATCH 0           /* no ignore bits */

#define UET_DEF_MR_CNT	16	    /* default number of memory regions */

#define UET_SEC_MODE       "UET_SEC_MODE"
#define UET_SEC_SSI        "UET_SEC_SSI"

#define UET_SEC_SERVER     "UET_SEC_SERVER"
#define UET_SEC_CLIENT_SSI "UET_SEC_CLIENT_SSI"

	/* thresholds for rendezvous sends */
#define UET_MSG_RENDEZVOUS_SIZE		8192
#define UET_TAG_RENDEZVOUS_SIZE		8192

#define UET_MAX_MSG_ID		0xffff
#define UET_MAX_MSG_SIZE	(0xffffffff - 1)

#define UET_MAX_RTR_TOKEN	0xffff
#define UET_RTR_TOKEN_NONE	0
	/* assigning fixed restart token at target */
#define UET_TARGET_RTR_TOKEN	UET_MAX_RTR_TOKEN

#define UET_RTR_Q_ENTRIES_MAX	8  /* max number of deferred send's at target */

	/* timeout for partially received messages that have gone idle */
#define UET_IDLE_RX_MSG_TIMEOUT		5000	/* in msecs */

	/* timeout for deferred send messages that have gone idle */
#define UET_IDLE_DSEND_MSG_TIMEOUT	5000	/* in msecs */

	/* timeout for buffered rtr messages that have gone idle */
#define UET_IDLE_RTR_MSG_TIMEOUT	5000	/* in msecs */

	/* initial max backoff time for msg retransmissions, */
	/* used by exponential backoff algorithm             */
#define UET_INITIAL_BACKOFF_MAX 1	/* in msecs */

	/* max number of times a message can be retransmitted */
#define UET_MSG_RETRANSMIT_MAX		10
#define UET_MSG_RETRANSMIT_MAX_INFINITY	0

#define UET_IOV_LIMIT     8
#define UET_RMA_IOV_LIMIT 8
#if UET_IOV_LIMIT > UET_RMA_IOV_LIMIT
	#define UET_IOV_LIMIT_MAX UET_IOV_LIMIT
#else
	#define UET_IOV_LIMIT_MAX UET_RMA_IOV_LIMIT
#endif

#define UET_MR_MODE_LOCAL		(1 << 2)
#define UET_MR_MODE_RAW		(1 << 3)
#define UET_MR_MODE_VIRT_ADDR		(1 << 4)
#define UET_MR_MODE_ALLOCATED		(1 << 5)
#define UET_MR_MODE_PROV_KEY		(1 << 6)
#define UET_MR_MODE_MMU_NOTIFY	(1 << 7)
#define UET_MR_MODE_RMA_EVENT		(1 << 8)
#define UET_MR_MODE_ENDPOINT		(1 << 9)
#define UET_MR_MODE_HMEM		(1 << 10)
#define UET_MR_MODE_COLLECTIVE	(1 << 11)


	/* definitions for uet memory region key format */
#define UET_MR_KEY_NONE                 ((uint64_t) 0)
#define UET_MR_KEY_IDEMPOTENT_SAFE      0x80000000000000ULL
#define UET_MR_KEY_OPTIMIZED            0x40000000000000ULL
#define UET_MR_KEY_RESERVED             0x3f000000000000ULL
#define UET_MR_KEY_VENDOR               0x00ff0000000000ULL
#define UET_MR_KEY_RKEY_MASK            0x0000ffffffffffULL
#define UET_MR_KEY_RKEY_SHIFT           0
#define UET_MR_KEY_MAX_RKEY             (UET_MR_KEY_RKEY_MASK >> \
					 UET_MR_KEY_RKEY_SHIFT)
#define UET_MR_KEY_OPTIMIZED_RESERVED   0x0000fffffff000ULL
#define UET_MR_KEY_OPTIMIZED_RKEY_MASK  0x00000000000fffULL
#define UET_MR_KEY_OPTIMIZED_RKEY_SHIFT 0
#define UET_MR_KEY_OPTIMIZED_MAX_RKEY   (UET_MR_KEY_OPTIMIZED_RKEY_MASK >> \
					 UET_MR_KEY_OPTIMIZED_RKEY_SHIFT)

#define UET_CQ_READ_MAX_ENTRIES 16

#define UET_ACCESS_FLAG_TAGGED			(1ULL << 1)
#define UET_ACCESS_FLAG_RMA				(1ULL << 2)
#define UET_ACCESS_FLAG_REMOTE_READ			(1ULL << 3)
#define UET_ACCESS_FLAG_MSG				(1ULL << 4)
#define UET_ACCESS_FLAG_WRITE			(1ULL << 5)
#define UET_ACCESS_FLAG_RECV			(1ULL << 6)
#define UET_ACCESS_FLAG_SEND			(1ULL << 7)
#define UET_ACCESS_FLAG_READ			(1ULL << 8)
#define UET_ACCESS_FLAG_SELECTIVE_COMPLETION	(1ULL << 9)
#define UET_ACCESS_FLAG_REMOTE_WRITE		(1ULL << 10)


/* define handle types */
typedef void *uet_handle_t;         /* handle for uet instance */
typedef void *uet_domain_handle_t;  /* handle for domain instance */
typedef void *uet_ep_handle_t;      /* handle for endpoint instance */
typedef void *uet_sctx_handle_t;    /* handle for shared context */
typedef void *uet_cq_handle_t;      /* handle for completion queue */
typedef void *uet_cntr_handle_t;    /* handle for counter instance */
typedef void *uet_addr_handle_t;    /* handle for uet address */
typedef void *uet_mr_handle_t;      /* handle for memory region */

/* event callback functions */
typedef void (*uet_eq_callback_t)(uet_handle_t handle,
				  void *buf);
typedef void (*uet_eq_err_callback_t)(uet_handle_t handle,
				      void *buf);

#ifndef __KERNEL__
#ifndef container_of
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})
#endif
#endif

#define uet_max(a, b)           \
({                              \
	__typeof__(a) _a = (a); \
	__typeof__(b) _b = (b); \
	_a > _b ? _a : _b;      \
})

#define uet_min(a, b)           \
({                              \
	__typeof__(a) _a = (a); \
	__typeof__(b) _b = (b); \
	_a < _b ? _a : _b;      \
})

#define UET_NO_TAG                0
#define UET_NO_IGNORE_BITS        0
#define UET_NO_IMM_DATA           NULL
#define UET_NO_REMOTE_MEM_ADDR    0
#define UET_NO_REMOTE_KEY         0

/* receive api types */
typedef enum {
	UET_RECV_API,
	UET_TRECV_API,
} uet_recv_api_t;

/* send request api types */
typedef enum {
	UET_SEND_API,
	UET_TSEND_API,
	UET_WRITE_API,
	UET_READ_API,
} uet_send_req_api_t;

// RAKHA: Should be moved to uet_uapi.h as inline
/* init portions of uet address with ipv4 fabric address */
static inline void uet_init_uet_addr_ipv4(struct uet_addr *uet_addr,
				   uint32_t ipv4_addr)
{
	uet_addr->ver = UET_ADDR_VERSION;
	uet_addr->flags = (UET_ADDR_FEP_CAP_V     |
			   UET_ADDR_FA_V          |
			   UET_ADDR_RELATIVE_MODE |
			   UET_ADDR_IPV4          |
			   UET_ADDR_BIG_MSG_SIZE);
	uet_addr->fep_cap = UET_FEP_CAP_AI_FULL;
	uet_addr->fa.v4 = ipv4_addr;
}

enum uet_nic_state {
	UET_NIC_STATE_UNKNOWN,
	UET_NIC_STATE_DOWN,
	UET_NIC_STATE_UP,
};

#define UET_NET_TYPE_SIZE 32

struct uet_nic_info {
	char name[IFNAMSIZ];
	size_t mtu;
	char network_type[UET_NET_TYPE_SIZE];
	char mac_addr_str[ETH_ALEN * 3];
	enum uet_nic_state state;
};

/* pds delivery modes */
typedef enum {
	UET_PDS_MODE_UUD,
	UET_PDS_MODE_ROD,
	UET_PDS_MODE_RUD,
	UET_PDS_MODE_RUDI,
} uet_pds_mode_t;

enum uet_cq_type {
	UET_CQ_TYPE_UNSPEC,
	UET_CQ_TYPE_CONTEXT,
	UET_CQ_TYPE_MSG,
	UET_CQ_TYPE_DATA,
	UET_CQ_TYPE_TAGGED,
};

/* CQ entry descriptor */
struct uet_cq_entry {
	void			*op_context;
	uint64_t		flags;
	size_t			len;
	void			*buf;
	uint64_t		data;
	uint64_t		tag;
	size_t			olen;
	int			err;
	int			prov_errno;
	/* err_data is available until the next time the CQ is read */
	void			*err_data;
	size_t			err_data_size;
	uint64_t		src_addr;
};

#define UET_IOCTL_BASE					_IO('U', 0)

#define UET_IOCTL_INSTANCE_CREATE		(UET_IOCTL_BASE + 1)
#define UET_IOCTL_INSTANCE_FINALIZE		(UET_IOCTL_BASE + 2)
#define UET_IOCTL_NIC_GET_INFO			(UET_IOCTL_BASE + 3)
#define UET_IOCTL_NIC_GET_ADDR_IPV4		(UET_IOCTL_BASE + 4)
#define UET_IOCTL_DOMAIN_CREATE			(UET_IOCTL_BASE + 5)
#define UET_IOCTL_DOMAIN_CLOSE			(UET_IOCTL_BASE + 6)
#define UET_IOCTL_EP_CREATE				(UET_IOCTL_BASE + 7)
#define UET_IOCTL_EP_GET_NAME			(UET_IOCTL_BASE + 8)
#define UET_IOCTL_EP_BIND_CQ			(UET_IOCTL_BASE + 9)
#define UET_IOCTL_EP_ENABLE				(UET_IOCTL_BASE + 10)
#define UET_IOCTL_EP_CLOSE				(UET_IOCTL_BASE + 11)
#define UET_IOCTL_CQ_READ				(UET_IOCTL_BASE + 12)
#define UET_IOCTL_CQ_READERR			(UET_IOCTL_BASE + 13)
#define UET_IOCTL_CQ_CLOSE				(UET_IOCTL_BASE + 14)
#define UET_IOCTL_AV_INSERT				(UET_IOCTL_BASE + 15)
#define UET_IOCTL_AV_REMOVE				(UET_IOCTL_BASE + 16)
#define UET_IOCTL_MR_REG				(UET_IOCTL_BASE + 17)
#define UET_IOCTL_MR_KEY				(UET_IOCTL_BASE + 18)
#define UET_IOCTL_MR_BIND_EP			(UET_IOCTL_BASE + 19)
#define UET_IOCTL_MR_ENABLE				(UET_IOCTL_BASE + 20)
#define UET_IOCTL_MR_CLOSE				(UET_IOCTL_BASE + 21)
#define UET_IOCTL_REQ_SEND				(UET_IOCTL_BASE + 22)
#define UET_IOCTL_REQ_RECV				(UET_IOCTL_BASE + 23)
#define UET_IOCTL_MAX					(UET_IOCTL_BASE + 24)

struct uet_ioctl_inst_init_args {
	struct {
		int rc;
		uet_handle_t handle;
	} out;
};

struct uet_ioctl_inst_finalize_args {
	struct {
		uet_handle_t handle;
	} in;
	struct {
		int rc;
	} out;
};

struct uet_ioctl_nic_getinfo_args {
	struct {
		uet_handle_t handle;
	} in;
	struct {
		int rc;
		struct uet_nic_info nic_info;
	} out;
};

struct uet_ioctl_nic_get_addr_ipv4 {
	struct {
		uet_handle_t handle;
	} in;
	struct {
		int rc;
		uint32_t ipv4_addr;
	} out;
};

struct uet_ioctl_domain_create_args {
	struct {
		uet_handle_t handle;
		size_t mr_cnt;
		int mr_mode;
		unsigned long context;
	} in;
	struct {
		int rc;
		uet_domain_handle_t domain_handle;
	} out;
};

struct uet_ioctl_domain_close_args {
	struct {
		uet_domain_handle_t domain_handle;
	} in;
	struct {
		int rc;
	} out;
};

struct uet_ioctl_ep_create_args {
	struct {
		uet_domain_handle_t domain_handle;
		struct uet_addr src_addr;
		int32_t src_addrlen;
		int32_t num_rx_desc;
		int32_t num_tx_desc;
		uet_pds_mode_t pds_mode;
		uint32_t tclass;
		int use_default_tos;
		unsigned long context;
	} in;
	struct {
		int rc;
		uet_ep_handle_t ep_handle;
	} out;
};

struct uet_ioctl_ep_get_name_args {
	struct {
		uet_ep_handle_t ep_handle;
	} in;
	struct {
		int rc;
		struct uet_addr uet_addr;
	} out;
};

struct uet_ioctl_ep_bind_cq_args {
	struct {
		uet_ep_handle_t ep_handle;
		uint64_t cq_flags;
		enum uet_cq_type cq_type;
		size_t cq_size;
		unsigned long context;
	} in;
	struct {
		int rc;
		uet_cq_handle_t cq_handle;
	} out;
};

struct uet_ioctl_ep_enable_args {
	struct {
		uet_ep_handle_t ep_handle;
	} in;
	struct {
		int rc;
	} out;
};

struct uet_ioctl_ep_close_args {
	struct {
		uet_ep_handle_t ep_handle;
	} in;
	struct {
		int rc;
	} out;
};

struct uet_ioctl_cq_read_args {
	struct {
		uet_cq_handle_t cq_handle;
		size_t max_count;
	} in;
	struct {
		int rc;
		size_t count;
		char buf[0];
	} out;
};

struct uet_ioctl_cq_readerr_args {
	struct {
		uet_cq_handle_t cq_handle;
	} in;
	struct {
		int rc;
		size_t count;
		struct uet_cq_entry buf;
	} out;
};

struct uet_ioctl_cq_close_args {
	struct {
		uet_cq_handle_t cq_handle;
	} in;
	struct {
		int rc;
	} out;
};

struct uet_ioctl_av_insert_args {
	struct {
		uet_domain_handle_t domain_handle;
		struct uet_addr uet_addr;
	} in;
	struct {
		int rc;
		uet_addr_handle_t addr_handle;
	} out;
};

struct uet_ioctl_av_remove_args {
	struct {
		uet_addr_handle_t addr_handle;
	} in;
	struct {
		int rc;
	} out;
};

struct uet_ioctl_mr_reg_args {
	struct {
		uet_domain_handle_t domain_handle;
		void *buf;
		size_t len;
		uint64_t access;
		uint64_t requested_key;
		uint64_t flags;
		unsigned long context;
	} in;
	struct {
		int rc;
		uet_mr_handle_t mr_handle;
	} out;
};

struct uet_ioctl_mr_key_args {
	struct {
		uet_mr_handle_t mr_handle;
	} in;
	struct {
		int rc;
		uint64_t mr_key;
	} out;
};

struct uet_ioctl_ep_bind_mr_args {
	struct {
		uet_ep_handle_t ep_handle;
		uet_mr_handle_t mr_handle;
	} in;
	struct {
		int rc;
	} out;
};

struct uet_ioctl_mr_enable_args {
	struct {
		uet_mr_handle_t mr_handle;
	} in;
	struct {
		int rc;
	} out;
};

struct uet_ioctl_mr_close_args {
	struct {
		uet_mr_handle_t mr_handle;
	} in;
	struct {
		int rc;
	} out;
};

struct uet_ioctl_send_req_args {
	struct {
		uet_send_req_api_t send_req_api;
		uet_ep_handle_t ep_handle;
		uint32_t job_id;
		void *buf;
		size_t len;
		uet_mr_handle_t mr_handle;
		uet_addr_handle_t dst_addr_handle;
		uint64_t tag;
		uint64_t *imm_data;
		uint64_t remote_mem_addr;
		uint64_t remote_key;
		unsigned long context;
	} in;
	struct {
		int rc;
	} out;
};

struct uet_ioctl_recv_api_args {
	struct {
		uet_recv_api_t recv_api;
		uet_ep_handle_t ep_handle;
		uint32_t job_id;
		void *buf;
		size_t len;
		uet_mr_handle_t mr_handle;
		uet_addr_handle_t src_addr_handle;
		uint64_t tag;
		uint64_t ignore;
		unsigned long context;
	} in;
	struct {
		int rc;
	} out;
};

#endif
