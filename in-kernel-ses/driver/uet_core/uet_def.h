
#ifndef _UET_DEF_H
#define _UET_DEF_H

#include "uthash.h"
#include "uet_list.h"

typedef uint64_t uet_dma_addr_t;

/* endpoint states */
typedef enum {
	UET_EP_DISABLED = 0,
	UET_EP_ENABLED,
	UET_EP_CLOSE_WAIT,
} uet_ep_state_t;

/* completion queue states */
typedef enum {
	UET_CQ_DOWN = 0,
	UET_CQ_UP,
} uet_cq_state_t;

/* key for memory region hash lookup */
struct uet_mr_key {
	uint64_t rkey;
};

/* memory region descriptor states */
typedef enum {
	UET_MR_DESC_STATE_INACTIVE = 0,
	UET_MR_DESC_STATE_DISABLED_REG,             /* registered with domain */
	UET_MR_DESC_STATE_DISABLED_BIND,                 /* bound to endpoint */
	UET_MR_DESC_STATE_ENABLED,                           /* ready for use */
} uet_mr_desc_state_t;

/* memory region buffer types */
typedef enum {
	UET_MR_BUF_TYPE_CONTIG = 0,
	UET_MR_BUF_TYPE_IOV,
	UET_MR_BUF_TYPE_REGATTR_IOV,
	UET_MR_BUF_TYPE_REGATTR_DMABUF,
} uet_mr_buf_type_t;

/* descriptor for contiguous mr */
struct uet_mr_desc_contig {
	uet_dma_addr_t dma_addr;        /* base dma address for memory region */
};

/* descriptor for iov mr */
struct uet_mr_desc_iov {
	size_t iov_count;                         /* number of entries in iov */
	const struct iovec *iov;                  /* vector for memory region */
			     /* array of base dma addresses for memory region */
	uet_dma_addr_t dma_addr[UET_IOV_LIMIT_MAX];
};

/* descriptor for uet mr attributes */
struct uet_mr_attr {
	// TODO:
};

/* descriptor for mr registered with uet_mr_regattr API */
struct uet_mr_desc_regattr {
	const struct uet_mr_attr *attr;
			     /* array of base dma addresses for memory region */
	uet_dma_addr_t dma_addr[UET_IOV_LIMIT_MAX];
};

/* memory region buffer descriptor */
struct uet_mr_buf_desc {
	void *buf;                    /* ptr to start of memory region buffer */
	size_t len;                /* length of memory region buffer in bytes */
	uet_mr_buf_type_t type;
	union {
		struct uet_mr_desc_contig contig;
		struct uet_mr_desc_iov iov;
		struct uet_mr_desc_regattr regattr;
	};
};

/* memory region descriptor */
struct uet_mr_desc {
	uet_mr_desc_state_t state;                 /* state of the descriptor */
	struct uet_domain *uet_dom;   /* domain descriptor is associated with */
	struct uet_ep *uet_ep;      /* endpoint descriptor is associated with */
	uet_nic_mr_handle_t nic_mr_handle;    /* nic handle for memory region */
	struct uet_mr_buf_desc buf_desc;   /* memory region buffer descriptor */
	uint64_t full_key;                      /* full key for memory region */
	uint64_t access;            /* operations supported for memory region */
	uint64_t flags;                        /* properties of memory region */
	void *context;                                      /* for completion */
	struct uet_mr_key hash_key;                     /* key for hash entry */
	UT_hash_handle mr_hh;                     /* handle for hash function */
	struct uet_list_entry list_entry;               /* for inserting in list */
};

#endif /* _USET_DEF_H_ */
