/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* Private definitions used to implement UET API's */
#ifndef _UET_API_PRIVATE_H_
#define _UET_API_PRIVATE_H_

#include <linux/types.h>

#include "uet_list.h"
#include "uet_uapi.h"
#include "uet_pds.h"
#include "uet_nic.h"
#include "uet_util.h"
#include "uet_def.h"

#define UET_API_ERR(fmt, ...)				\
	pr_err("UET API: %s:%-4d: " fmt "\n",	\
		__FILE__, __LINE__, ##__VA_ARGS__)

#define UET_API_DEBUG_ENABLED false /* true => debug messages enabled */

#define UET_API_DEBUG(fmt, ...)                                              \
	do {                                                                 \
		if (UET_API_DEBUG_ENABLED)                                   \
			pr_debug("UET API: [%s] %s:%-4d: " fmt "\n",  \
				"error", __FILE__, __LINE__, ##__VA_ARGS__); \
	} while (0)

#define UET_API_PRINT_ERRNO(CALL)                                     \
	pr_err("UET_API: %s(): %s:%-4d\n",    \
		(CALL), __FILE__, __LINE__)

/* hash lookup key for received messages */
struct uet_rx_msg_key {
	uint32_t initiator;
	uint16_t msg_id;
};

/* for hash lookup of tagged buffer with {tag, initiator} key */
#define UET_INITIATOR_NONE 0			  /* for lookup on {tag} only */
struct uet_tag_initiator_key {
	uint64_t tag;
	bool initiator_invalid;
	uint32_t initiator;
};

/* message buffer types */
typedef enum {
	UET_MSG_BUF_TYPE_CONTIG = 0,
	UET_MSG_BUF_TYPE_IOV,
} uet_msg_buf_type_t;

/* descriptor for contiguous message buffer */
struct uet_msg_desc_contig {
	uet_dma_addr_t dma_addr;               /* base dma address for buffer */
};

/* descriptor for iov message buffer */
struct uet_msg_desc_iov {
	size_t iov_count;                         /* number of entries in iov */
	const struct iovec *iov;                         /* vector for buffer */
					    /* array of dma addr's for buffer */
	uet_dma_addr_t dma_addr[UET_IOV_LIMIT_MAX];
};

/* message buffer descriptor */
struct uet_msg_buf_desc {
	void *buf;                                  /* ptr to start of buffer */
	size_t len;                              /* length of buffer in bytes */
	size_t buf_off;                /* buffer offset for next pkt, tx only */
	uet_msg_buf_type_t type;
	union {
		struct uet_msg_desc_contig contig;
		struct uet_msg_desc_iov iov;
	};
};

struct uet_tx_desc; /* forward reference */

/* rx msg descriptor */
struct uet_rx_desc {
	struct uet_list_entry list_entry;               /* for inserting in list */
#define UET_RX_DESC_FLAG_NONE		0
#define UET_RX_DESC_FLAG_ACTIVE		(1 << 0)            /* in active list */
#define UET_RX_DESC_FLAG_IN_HASH_TBL	(1 << 1)           /* in msg hash tbl */
#define UET_RX_DESC_FLAG_POST_CQ	(1 << 2)
#define UET_RX_DESC_FLAG_WRITE		(1 << 3)
#define UET_RX_DESC_FLAG_WRITE_IMM	(1 << 4)
#define UET_RX_DESC_FLAG_READ_RSP	(1 << 5)
#define UET_RX_DESC_FLAG_DSEND		(1 << 6)       /* deferred descriptor */
#define UET_RX_DESC_FLAG_CANCELLED	(1 << 7)
#define UET_RX_DESC_FLAG_ERR_TRACK	(1 << 8)
	int desc_flags;                          /* flags for this descriptor */
	uet_ses_rc_t ses_rc;    /* ses return code, for marking errored msg's */
	struct uet_msg_buf_desc buf_desc;                /* buffer descriptor */
	void *context;                                      /* for completion */
	uint64_t cq_flags;                   /* for flags field of completion */
	size_t remaining_bytes;                 /* num msg bytes not received */
	size_t msg_len;                /* length of received message in bytes */
	struct uet_rx_msg_key msg_key;           /* key for rx msg hash entry */
	UT_hash_handle msg_hh;             /* handle for rx msg hash function */
	struct uet_tag_initiator_key tag_key;       /* key for tag hash entry */
	UT_hash_handle tag_hh;                /* handle for tag hash function */
	struct uet_mr_desc *mr_desc;          /* ptr to mr desc if applicable */
	uint64_t imm_data;                        /* data for write immediate */
	struct uet_ep *uet_ep;             /* endpoint msg is associated with */
	uint64_t prev_pkt_time;     /* time most recent pkt of msg was received */
	struct uet_tx_desc *tx_desc;     /* associated tx descriptor for read */
	size_t expected_rd_rsp;          /* number of expected read responses */
};

/* rx msg descriptor ring entry */
struct uet_rx_desc_ring_entry {
	struct uet_rx_desc *rx_desc;
};

/* address vector entry */
struct uet_av_entry {
	struct uet_list_entry av_list_entry; /* for insert in list of av entries */
	struct uet_addr *addr;    /* ptr to uet addr entry is associated with */
#define UET_NH_MAC_ADDR_V (1 << 0)  /* flag bit indicating next-hop mac valid */
	uint16_t flags;
	uint8_t nh_mac_addr[ETH_ALEN];                /* next-hop mac address */
	_Atomic size_t num_active_ops; /* num active operations using this av */
			    /* ses generation for untagged msg's to this dest */
	_Atomic uint32_t untagged_gen;
	_Atomic uint32_t tagged_gen; /* ses gen for tagged msg's to this dest */
		/* sequence numbers are assigned to each msg to be sent to    */
		/* this av, and msg's are sent in sequence number order,      */
		/* needed to maintain order for retransmissions over rod      */
		/* TODO: think about whether these sequence numbers can be    */
		/*       eliminated by leveraging pds queuing for in-order    */
		/*       retransmission over rod                              */
	uint64_t seq_num;               /* next msg sequence number to assign */
	uint64_t next_tx_seq_num;             /* next msg seq num to transmit */
};

/* ephemeral address vector */
struct uet_ephemeral_av {
	struct uet_addr uet_addr;         /* dst addr info needed by tx infra */
	struct uet_av_entry av;         /* dst addr vector needed by tx infra */
};

/* info associated with tx of read response */
struct uet_rd_rsp_info {
	struct uet_pds_info pds_info;     /* pds info echoed in read response */
	uint32_t mod_len;                          /* modified message length */
};

/* tx msg descriptor states */
typedef enum {
	UET_TX_DESC_STATE_INACTIVE = 0,
	UET_TX_DESC_STATE_ACTIVE,                      /* active transmission */
	UET_TX_DESC_STATE_WAIT,                         /* waiting for ack(s) */
	UET_TX_DESC_STATE_RETX,           /* waiting for ack(s) to retransmit */
	UET_TX_DESC_STATE_DEFER,             /* got defer, waiting for ack(s) */
	UET_TX_DESC_STATE_RESTART_WAIT,                /* waiting for restart */
	UET_TX_DESC_STATE_ERR,                  /* transmit encountered error */
	UET_TX_DESC_STATE_ERR_COMPLETE,     /* ready to post error completion */
	UET_TX_DESC_STATE_COMPLETE,               /* ready to post completion */
} uet_tx_desc_state_t;

/* tx msg descriptor */
struct uet_tx_desc {
	struct uet_list_entry list_entry;               /* for inserting in list */
	uet_tx_desc_state_t state;                 /* state of the descriptor */
#define UET_TX_DESC_FLAG_NONE			0
#define UET_TX_DESC_FLAG_POST_CQ		(1 << 0)
#define UET_TX_DESC_FLAG_MSG_ID_ALLOCATED	(1 << 1)
#define UET_TX_DESC_FLAG_IMM_DATA_VALID		(1 << 2)
#define UET_TX_DESC_FLAG_DSEND			(1 << 3)
#define UET_TX_DESC_FLAG_IN_DSEND_LIST		(1 << 4)
#define UET_TX_DESC_FLAG_GOT_RTR		(1 << 5)
#define UET_TX_DESC_FLAG_RTR_REQ		(1 << 6)     /* for tx of rtr */
#define UET_TX_DESC_FLAG_READ_REQ		(1 << 7)
#define UET_TX_DESC_FLAG_READ_RSP		(1 << 8)
#define UET_TX_DESC_FLAG_CANCEL_PENDING		(1 << 9)
	int desc_flags;                          /* flags for this descriptor */
	struct uet_msg_buf_desc buf_desc;                /* buffer descriptor */
	uint64_t tag_or_immdata;           /* tag or immediate data for write */
	uint64_t remote_start_off;              /* remote starting buf offset */
	uint32_t remote_msg_off;                  /* remote offset within msg */
	uint64_t remote_mem_addr;     /* remote mem addr for write, net order */
	uint64_t remote_key;                       /* remote mr key for write */
	void *context;                                      /* for completion */
	uint64_t op_flags;                     /* libfabric operational flags */
	uint64_t cq_flags;                   /* for flags field of completion */
	uet_addr_handle_t dst_addr_handle;     /* destination address for msg */
	uint32_t job_id;                        /* job id associated with msg */
	uint16_t msg_id;                              /* id allocated for msg */
	uet_pds_mode_t pds_mode;                      /* packet delivery mode */
	size_t unack_pkts;        /* number of unacknowledged pkts oustanding */
	size_t remaining_bytes;              /* num msg bytes not transmitted */
	struct uet_mr_desc *mr_desc;          /* ptr to mr desc if applicable */
	struct uet_ep *uet_ep;             /* endpoint msg is associated with */
	uint64_t seq_num;	   /* local sequence number used for ordering */
	uint32_t retransmit_cnt; /* number of time msg has been retransmitted */
	uint64_t backoff_max;      /* max backoff time in msecs for retransmits */
	uint64_t tx_time;		      /* earliest time msg can be transmitted */
	bool delay_retx;          /* parm for deferred message retransmission */
	int err_code;                                           /* error info */
	uint16_t local_rtr_token;		       /* local restart token */
	uint32_t remote_rtr_token;		      /* remote restart token */
	uint64_t defer_time;			     /* time msg was deferred */
	struct uet_rx_desc *rx_desc;     /* associated rx descriptor for read */
	struct uet_rd_rsp_info rd_rsp;             /* info for tx of read rsp */
	struct uet_ephemeral_av ephemeral_av;  /* av for tx of read rsp & rtr */
};

/* tx msg descriptor ring entry */
struct uet_tx_desc_ring_entry {
	struct uet_tx_desc *tx_desc;
};

/* message match info */
struct uet_msg_match_info {
	bool ip_addr_match;
	bool job_id_match;
	bool pid_on_fep_match;
	bool index_match;
	bool msg_id_match;
};

/* message id control block struct */
struct uet_msg_id_cb {
	uint16_t next_msg_id;                   /* used for msg id allocation */
#define UET_MSG_ID_AVAILABLE 0x00                             /* state values */
#define UET_MSG_ID_ALLOCATED 0x01
	uint8_t state[UET_MAX_MSG_ID+1];
	       /* used to lookup rx desc with msg id index for read responses */
	struct uet_rx_desc *rx_desc[UET_MAX_MSG_ID+1];
};

/* tx restart token control block struct */
struct uet_tx_rtr_token_cb {
	uint16_t next_token;                     /* used for token allocation */
#define UET_TX_RTR_TOKEN_AVAILABLE 0x00                       /* state values */
#define UET_TX_RTR_TOKEN_ALLOCATED 0x01
	uint8_t state[UET_MAX_RTR_TOKEN+1];
					 /* used to lookup tx desc with token */
	struct uet_tx_desc *tx_desc[UET_MAX_RTR_TOKEN+1];
	struct uet_ep *uet_ep[UET_MAX_RTR_TOKEN+1];         /* local endpoint */
	uint32_t initiator_id[UET_MAX_RTR_TOKEN+1];    /* remote initiator id */
};

/* key for ipv4 endpoint lookup */
struct uet_ipv4_ep_key {
	uint32_t ipv4_addr;
	uint16_t pid_on_fep;
	uint32_t index;
};

struct uet_ep; /* forward reference */

/* control block for uet instance */
struct uet_instance {
	struct uet_list_entry domain_list_head;          /* domain obj list head */
	struct uet_nic nic;                              /* nic control block */
	uint8_t uet_ipproto;                    /* ip protocol number for uet */
	uint16_t uet_udp_port;                     /* udp port number for uet */
	size_t max_payload_len;                   /* max payload for a packet */
	struct uet_pds pds;			  /* pds control block struct */
	uint8_t default_msg_ip_tos;               /* default ip tos for msg's */
	uint32_t msg_rndz_size;           /* threshold for message rendezvous */
	uint32_t tag_rndz_size;        /* threshold for tagged msg rendezvous */
	uint64_t idle_rx_msg_timeout;           /* timeout for partial rx msg's */
	uint64_t idle_dsend_msg_timeout;     /* timeout for deferred send msg's */
	uint64_t idle_rtr_msg_timeout;        /* timeout for buffered rtr msg's */
	uint32_t max_msg_retransmits;     /* max num retransmissions of a msg */
	uint32_t max_rtr_q_entries;         /* max num of rtr msg's to buffer */
	struct uet_msg_id_cb msg_id_cb;        /* used for assigning msg id's */
				      /* used for assigning tx restart tokens */
	struct uet_tx_rtr_token_cb tx_rtr_token_cb;
	struct uet_rw_lock ipv4_ep_lkup_lock;  /* lock for ipv4 ep lookup tbl */
	struct uet_ep *ipv4_ep_hash_table;        /* ipv4 endpoint hash table */
};

/* memory region descriptor allocation control block struct */
struct uet_mr_desc_alloc_cb {
	size_t next_mr_index;                  /* used for mr desc allocation */
		  /* used for mr desc allocation in range of optimized format */
	size_t next_opt_mr_index;
#define UET_MR_DESC_AVAILABLE 0x00                            /* state values */
#define UET_MR_DESC_ALLOCATED 0x01
	uint8_t *state;                              /* dynamically allocated */
};


/* domain control block */
struct uet_domain {
	struct uet_instance *uet;     /* ptr to associated uet instance */
	struct uet_list_entry domain_list_entry;      /* domain list entry */
	struct uet_list_entry ep_list_head;      /* endpoint obj list head */
	struct uet_list_entry av_list_head;      /* av entry obj list head */
	struct uet_rw_lock ep_lock;      /* lock for accessing ep obj's */
	//struct fid_fabric *fabric;          /* fabric struct for domain */
	//struct fi_info *info;       /* libfabric info struct for domain */
	int mr_mode;
	//struct fid_domain *domain;    /* ptr to libfabric domain struct */
	void *context;           /* user context associated with domain */
	uet_eq_callback_t eq_callback;          /* async event callback */
	uet_eq_err_callback_t eq_err_callback;    /* err event callback */
	size_t num_mr;            /* number of memory regions supported */
	struct uet_mr_desc *mr_desc;  /* ptr to array of mr descriptors */
	   /* used for managing allocation of memory region descriptors */
	struct uet_mr_desc_alloc_cb mr_desc_alloc_cb;
};

/* uet ring */
struct uet_ring {
	size_t num_entries;
	size_t entry_size;  /* in bytes */
	size_t head;
	size_t tail;
	void *base;         /* ptr to 1st entry of ring */
};

struct uet_ep; /* forward declaration */

/* completion queue ring entry */
struct uet_cq_ring_entry {
	bool err; /* true => entry is an error entry */
	union {   /* descriptor completion is for */
		struct uet_rx_desc *rx;
		struct uet_tx_desc *tx;
	} desc;
	/* err entry is largest cq entry format */
	//uint8_t cq_entry[sizeof(struct fi_cq_err_entry)];
	struct uet_cq_entry entry;
};

/* completion queue control block */
struct uet_cq {
	uet_cq_state_t cq_state;                 /* for detecting error state */
	struct uet_ep *uet_ep;                     /* ptr to ep struct for cq */
	//struct fi_cq_attr *attr;            /* ptr to libfabric cq attributes */
	//struct fid_cq *fid_cq;                  /* ptr to libfabric cq struct */
	//uint64_t flags;                              /* flags from fi_ep_bind */
	void *context;                     /* user context associated with cq */
	enum uet_cq_type cq_type;                  /* format of entries in cq */
	size_t format_size;             /* size of each entry in cq, in bytes */
	struct uet_ring ring;           /* ring implementing completion queue */
};

/* endpoint control block */
struct uet_ep {
	uet_ep_state_t ep_state;                         /* state of endpoint */
	struct uet_list_entry ep_list_entry;              /* endpoint list entry */
	UT_hash_handle ipv4_ep_hh;  /* handle for ipv4 endpoint hash function */
	struct uet_domain *uet_domain;                /* ptr to domain struct */
	//struct fi_info *info;                 /* ptr to libfabric info struct */
	uet_pds_mode_t pds_mode;
	//struct fid_ep *ep;                /* ptr to libfabric endpoint struct */
	void *context;               /* user context associated with endpoint */
	struct uet_addr uet_addr;               /* uet addr of ep, host order */
	uint32_t ipv4_addr;                    /* ipv4 addr of ep, host order */
	struct uet_ipv4_ep_key ipv4_ep_key;   /* key for ipv4 endpoint lookup */
	uint8_t msg_ip_tos;                            /* ip tos for messages */
	struct uet_cq send_cq;                       /* send completion queue */
	struct uet_cq recv_cq;                    /* receive completion queue */
	size_t num_tx_desc;                   /* num entries in tx_desc array */
	size_t num_rx_desc;                   /* num entries in rx_desc array */
	struct uet_tx_desc *tx_desc;           /* array of tx msg descriptors */
	struct uet_rx_desc *rx_desc;           /* array of rx msg descriptors */
	struct uet_list_entry tx_desc_list_head;   /* head of avail tx desc list */
					     /* head of deferred tx desc list */
	struct uet_list_entry tx_desc_defer_list_head;
		      /* head of list containing buffered msg restart entries */
	struct uet_list_entry tx_desc_buf_rtr_list_head;
	       /* head of list containing buffered tagged msg restart entries */
	struct uet_list_entry tx_desc_buf_tag_rtr_list_head;
	size_t num_buf_rtr_list_entries;     /* num entries in both rtr lists */
	struct uet_list_entry rx_desc_list_head;   /* head of avail rx desc list */
			   /* head of active list that contains rx desc's for */
			   /* partially received msg's                        */
	struct uet_list_entry rx_desc_active_list_head;
	struct uet_ring rx_ring;                    /* rx msg descriptor ring */
	struct uet_ring tx_ring;                    /* tx msg descriptor ring */
	struct uet_rx_desc *rx_msg_hash_table;           /* rx msg hash table */
	struct uet_rx_desc *tag_initiator_hash_table;       /* tag hash table */
		     /* hash table for memory regions with user-assigned keys */
	struct uet_mr_desc *mr_hash_table;
		  /* head of list containing mr's with provider-assigned keys */
	struct uet_list_entry mr_list_head;
	void *pds;                                               /* pds state */
	uint32_t job_id;                                /* ses job identifier */
	uint8_t untagged_gen;            /* ses generation for untagged msg's */
	bool untagged_gen_disabled;  /* true=>gen disabled for untagged msg's */
	uint8_t tagged_gen;                /* ses generation for tagged msg's */
	bool tagged_gen_disabled;    /* true => gen disabled for tagged msg's */
	size_t num_active_sends;          /* number of active send operations */
};

/* info associated with data to be carried in pds ack */
struct uet_ack_d_info {
	bool valid;                         /* true => data is carried in ack */
	uint32_t payload_len;                        /* size of data in bytes */
	uint32_t msg_off;                               /* msg offset of data */
	void *buf;                                             /* ptr to data */
};


extern int uet_initialize_internal(uet_handle_t *handle);

extern int uet_finalize_internal(uet_handle_t handle);

extern int uet_nic_getinfo_internal(uet_handle_t handle, 
		struct uet_nic_info *nic_info);

extern int uet_get_nic_addr_ipv4_internal(uet_handle_t handle, 
		uint32_t *ipv4_addr);

extern int uet_domain_internal(uet_handle_t handle, size_t mr_cnt, 
		int mr_mode, void *context, 
		uet_domain_handle_t *domain_handle);

extern int uet_domain_close_internal(
		uet_domain_handle_t domain_handle);

extern int uet_endpoint_internal(uet_domain_handle_t domain_handle,
	void *src_addr, int32_t src_addrlen, int32_t num_rx_desc, 
	int32_t num_tx_desc, uet_pds_mode_t pds_mode,
	uint32_t tclass, int use_default_tos, void *context, 
	uet_ep_handle_t *ep_handle);

extern int uet_getname_internal(uet_ep_handle_t ep_handle, 
			struct uet_addr *uet_addr);

extern int uet_ep_bind_cq_internal(uet_ep_handle_t ep_handle, 
		uint64_t cq_flags, enum uet_cq_type cq_type, 
		size_t cq_size, void *context, 
		uet_cq_handle_t *cq_handle);

extern int uet_ep_enable_internal(uet_ep_handle_t ep_handle);

extern int uet_ep_close_internal(uet_ep_handle_t ep_handle);

extern ssize_t uet_cq_read_internal(uet_cq_handle_t cq_handle, 
			void *buf, size_t count);

extern ssize_t uet_cq_readerr_internal(uet_cq_handle_t cq_handle,
		       struct uet_cq_entry *buf);

extern int uet_cq_close_internal(uet_cq_handle_t cq_handle);

extern int uet_av_insert_internal(uet_domain_handle_t domain_handle,
		  struct uet_addr *uet_addr,
		  uet_addr_handle_t *addr_handle);

extern int uet_av_remove_internal(uet_addr_handle_t addr_handle);

extern int uet_mr_reg_internal(uet_domain_handle_t domain_handle, 
		void __user *buf, size_t len, uint64_t access, 
		uint64_t requested_key, uint64_t flags, 
		void *context, uet_mr_handle_t *mr_handle);

extern uint64_t uet_mr_key_internal(uet_mr_handle_t mr_handle);

extern int uet_ep_bind_mr_internal(uet_ep_handle_t ep_handle,
		   uet_mr_handle_t mr_handle);

extern int uet_mr_enable_internal(uet_mr_handle_t mr_handle);

extern int uet_mr_close_internal(uet_mr_handle_t mr_handle);

extern ssize_t uet_send_req_api_common(
	uet_send_req_api_t send_req_api, 
	uet_ep_handle_t ep_handle, uint32_t job_id, void __user *buf, 
	size_t len, uet_mr_handle_t mr_handle, 
	uet_addr_handle_t dst_addr_handle, uint64_t tag, 
	uint64_t __user *imm_data, uint64_t remote_mem_addr, 
	uint64_t remote_key, void *context);

extern ssize_t uet_recv_api_common(uet_recv_api_t recv_api, 
		uet_ep_handle_t ep_handle, uint32_t job_id, 
		void __user *buf, size_t len, uet_mr_handle_t mr_handle, 
		uet_addr_handle_t src_addr_handle, uint64_t tag, 
		uint64_t ignore, void *context);

#endif /* _UET_API_PRIVATE_H_ */
