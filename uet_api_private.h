/*
 * Copyright (c) 2024,2025,2026 Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* Private definitions used to implement UET API's */

#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <uthash.h>
#include <linux/if_ether.h>

#include <ofi_list.h>

#include "uet_api.h"
#include "uet_pds.h"
#include "uet_nic.h"
#include "uet_util.h"

#ifndef _UET_API_PRIVATE_H_
#define _UET_API_PRIVATE_H_

#define UET_IOV_LIMIT     8
#define UET_RMA_IOV_LIMIT 8
#if UET_IOV_LIMIT > UET_RMA_IOV_LIMIT
	#define UET_IOV_LIMIT_MAX UET_IOV_LIMIT
#else
	#define UET_IOV_LIMIT_MAX UET_RMA_IOV_LIMIT
#endif

#define UET_MAX_MSG_ID		0xffff
#define UET_MAX_MSG_SIZE	(0xffffffff - 1)

/*
 * the UET_MAX_SYNC_GRP value was chosen to try and achieve a balance
 * that minimizes failures due to lack of sync group resources while
 * not reserving excessive sync group resources
 */
#define UET_MAX_SYNC_GRP	(UET_MAX_MSG_ID / 2)

#define UET_MAX_RTR_TOKEN	0xffff
#define UET_RTR_TOKEN_NONE	0

#define UET_RTR_Q_ENTRIES_MAX	8  /* max number of deferred send's at target */

#define UET_SEND_ORDERING                                                \
(FI_ORDER_RAS | FI_ORDER_SAR | FI_ORDER_SAS | FI_ORDER_SAW | FI_ORDER_WAS)

#define UET_RW_ORDERING                                                 \
(FI_ORDER_ATOMIC_RAR | FI_ORDER_ATOMIC_RAW | FI_ORDER_ATOMIC_WAR |	\
 FI_ORDER_ATOMIC_WAW | FI_ORDER_RAR | FI_ORDER_RAS | FI_ORDER_RAW |	\
 FI_ORDER_RMA_RAR | FI_ORDER_RMA_RAW | FI_ORDER_RMA_WAR |		\
 FI_ORDER_RMA_WAW | FI_ORDER_SAR | FI_ORDER_SAW | FI_ORDER_WAR |	\
 FI_ORDER_WAS)

#define UET_ORDERING	(UET_SEND_ORDERING | UET_RW_ORDERING)

	/* timeout for partially received messages that have gone idle */
#define UET_IDLE_RX_MSG_TIMEOUT		5000	/* in msecs */

	/* timeout for deferred send messages that have gone idle */
#define UET_IDLE_DSEND_MSG_TIMEOUT	5000	/* in msecs */

	/* timeout for buffered rtr messages that have gone idle */
#define UET_IDLE_RTR_MSG_TIMEOUT	5000	/* in msecs */

	/* max liftime for rx sync group,                             */
	/* protects against abandoned sync groups that have gone idle */
#define UET_RX_SYNC_GRP_MAX_LIFETIME	60000	/* in msecs */

	/* initial min/max backoff times for msg retransmissions */
#define UET_INITIAL_BACKOFF_MIN 50      /* in msecs */
#define UET_INITIAL_BACKOFF_MAX 100     /* in msecs */

	/* max number of times a message can be retransmitted */
#define UET_MSG_RETRANSMIT_MAX		5
#define UET_MSG_RETRANSMIT_MAX_INFINITY	0

	/* thresholds for rendezvous sends */
#define UET_MSG_RENDEZVOUS_SIZE		8192
#define UET_TAG_RENDEZVOUS_SIZE		8192

#define UET_API_ERR(fmt, ...)				\
	fprintf(stdout, "UET API: %s:%-4d: " fmt "\n",	\
		__FILE__, __LINE__, ##__VA_ARGS__)

#define UET_API_DEBUG_ENABLED false /* true => debug messages enabled */

#define UET_API_DEBUG(fmt, ...)                                              \
	do {                                                                 \
		if (UET_API_DEBUG_ENABLED)                                   \
			fprintf(stdout, "UET API: [%s] %s:%-4d: " fmt "\n",  \
				"error", __FILE__, __LINE__, ##__VA_ARGS__); \
	} while (0)

#define UET_API_PRINT_ERRNO(CALL)                                     \
	fprintf(stdout, "UET_API: %s(): %s:%-4d, ret = %d (%s)\n",    \
		(CALL), __FILE__, __LINE__, errno, strerror(errno))

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

/* descriptor for mr registered with uet_mr_regattr API */
struct uet_mr_desc_regattr {
	const struct fi_mr_attr *attr;
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
	struct uet_mr_buf_desc buf_desc;   /* memory region buffer descriptor */
	uint64_t full_key;                      /* full key for memory region */
	uint64_t access;            /* operations supported for memory region */
	uint64_t flags;                        /* properties of memory region */
	uint32_t job_id;                 /* JobID the region is restricted to */
	bool job_restricted;               /* region is restricted to a JobID */
	bool user_key;            /* key is user-assigned (hash space) vs the */
				  /* provider-assigned index space            */
	void *context;                                      /* for completion */
	struct uet_mr_key hash_key;                     /* key for hash entry */
	UT_hash_handle mr_hh;                     /* handle for hash function */
	struct dlist_entry list_entry;               /* for inserting in list */
};

/* hash lookup key for received messages */
struct uet_rx_msg_key {
	bool ipv6_addr;
	struct uet_fa src_ip;
	uint16_t spdcid;
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
	struct dlist_entry list_entry;               /* for inserting in list */
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
	uint32_t src_id;                   /* initiator (SourceID) of the msg */
	uint32_t job_id;             /* posted buffer's authorized JobID (RX) */
	struct uet_ep *uet_ep;             /* endpoint msg is associated with */
	time_t prev_pkt_time;     /* time most recent pkt of msg was received */
	struct uet_tx_desc *tx_desc;     /* associated tx descriptor for read */
	size_t expected_rd_rsp;          /* number of expected read responses */
					/* ptr to sync group info for message */
	struct uet_sync_grp_src_fep_entry *sync_grp_src_fep_entry;
};

/* rx msg descriptor ring entry */
struct uet_rx_desc_ring_entry {
	struct uet_rx_desc *rx_desc;
};

/* address vector entry */
struct uet_av_entry {
	struct dlist_entry av_list_entry; /* for insert in list of av entries */
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
	uint16_t req_msg_id;                    /* message ID of Read request */
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

/* atomic parameters */
struct uet_atomic_parms {
	uint8_t opcode; 				 /* uet atomic opcode */
	uint8_t data_type;	     /* uet type of data for atomic operation */
	uint32_t data_size;	 	 /* size of data for atomic operation */
	const void *compare_buf;	     /* ptr to compare data for cswap */
	void *result_buf;		              /* ptr to result buffer */
};

/* tx msg descriptor */
struct uet_tx_desc {
	struct dlist_entry list_entry;               /* for inserting in list */
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
#define UET_TX_DESC_FLAG_ATOMIC_REQ		(1 << 10)
#define UET_TX_DESC_FLAG_ATOMIC_FETCH_REQ	(1 << 11)
#define UET_TX_DESC_FLAG_ATOMIC_COMPARE_REQ	(1 << 12)
#define UET_TX_DESC_FLAG_SYNC_REQ		(1 << 13)
	int desc_flags;                          /* flags for this descriptor */
	struct uet_msg_buf_desc buf_desc;                /* buffer descriptor */
	uint64_t pkt_cnt;                /* number of pkt tx for this message */
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
	bool transmitted; 		       /* used for zero-byte requests */
	struct uet_mr_desc *mr_desc;          /* ptr to mr desc if applicable */
	struct uet_ep *uet_ep;             /* endpoint msg is associated with */
	uint64_t seq_num;	   /* local sequence number used for ordering */
	uint32_t retransmit_cnt; /* number of time msg has been retransmitted */
	time_t backoff_min;           /* min backoff in msecs for retransmits */
	time_t backoff_max;      /* init max backoff for retransmits in msecs */
	time_t backoff;          /* previous retransmit backoff time in msecs */
	time_t tx_time;		      /* earliest time msg can be transmitted */
	bool delay_retx;          /* parm for deferred message retransmission */
	int err_code;                                           /* error info */
	uint16_t local_rtr_token;		       /* local restart token */
	uint32_t remote_rtr_token;		      /* remote restart token */
	time_t defer_time;			     /* time msg was deferred */
	struct uet_rx_desc *rx_desc;     /* associated rx descriptor for read */
	struct uet_rd_rsp_info rd_rsp;             /* info for tx of read rsp */
	struct uet_ephemeral_av ephemeral_av;  /* av for tx of read rsp & rtr */
	struct uet_atomic_parms atomic_parms;  /* parms for atomic operations */
	uint16_t sync_grp;				 /* sync group number */
#if ENABLE_VERBS
	uint16_t resource_index;       /* for verbs, passing index outside av */
#endif
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

/* sync group av hash table lookup key, used by initiator */
struct uet_sync_grp_av_key {
	uint64_t av_handle;
};

/* sync group av hash table entry, used by initiator */
struct uet_sync_grp_av_entry {
	UT_hash_handle sync_grp_av_hh;         /* handle for sync grp av hash */
	struct uet_sync_grp_av_key sync_grp_av_key;
	uint16_t sync_grp;
};

/* sync group counts */
struct uet_sync_grp_cnts {
	uint16_t cur_cnt;              /* running count of msgs in sync group */
	uint16_t tot_cnt;           /* total number of messages in sync group */
	uint16_t cmpl_cnt;         /* num completions received for sync group */
};

/* sync group control block struct, used by initiator */
struct uet_sync_grp_cb {
	uint16_t next_sync_grp;             /* used for sync group allocation */
#define UET_SYNC_GRP_AVAILABLE 0x00                           /* state values */
#define UET_SYNC_GRP_ALLOCATED 0x02
	uint8_t state[UET_MAX_SYNC_GRP+1];
	struct uet_sync_grp_cnts cnts[UET_MAX_SYNC_GRP+1];
};

/* sync group src fep hash table lookup key, used by target */
struct uet_sync_grp_src_fep_key {
	bool ipv6_addr;
	struct uet_fa src_ip;
	uint16_t sync_grp;
};

/* parms needed for deferred exection of atomic operation */
struct uet_sync_grp_atomic_parms {
        uint8_t opcode;                                  /* uet atomic opcode */
        uint8_t data_type;           /* uet type of data for atomic operation */
	uint64_t *addr; 			     /* target memory address */
	uint64_t data;  			       /* atomic operand data */
};

/* sync group src fep hash table entry, used by target */
struct uet_sync_grp_src_fep_entry {
	UT_hash_handle sync_grp_src_fep_hh;              /* hash table handle */
	struct uet_sync_grp_src_fep_key sync_grp_src_fep_key;     /* hash key */
	struct uet_sync_grp_cnts cnts;                   /* cnts for sync grp */
	bool terminating_atomic;        /* sync group terminated by atomic op */
	                   /* info needed for deferred execution of atomic op */
	struct uet_sync_grp_atomic_parms atomic_parms;
		    /* ptr to rx desc for message that terminates sync group, */
		    /* i.e., the rx desc for a write imm                      */
	struct uet_rx_desc *terminating_rx_desc;
	bool terminating_err;  /* true => err associated with terminating msg */
	int terminating_err_code;             /* err code for terminating msg */
	time_t timeout;         /* timeout for partially received sync groups */
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

/* key for endpoint lookup */
struct uet_ep_key {
	bool ipv6_addr;
	struct uet_fa ip_addr;
	uint16_t pid_on_fep;
	uint16_t index;
};

struct uet_ep; /* forward reference */

/* control block for uet instance */
struct uet_instance {
	struct dlist_entry domain_list_head;          /* domain obj list head */
	struct uet_nic nic;                              /* nic control block */
	uint8_t uet_ipproto;                    /* ip protocol number for uet */
	uint16_t uet_udp_port;                     /* udp port number for uet */
	size_t max_payload_len;                   /* max payload for a packet */
	struct uet_pds pds;			  /* pds control block struct */
	uint8_t default_msg_ip_tos;               /* default ip tos for msg's */
	uint32_t msg_rndz_size;           /* threshold for message rendezvous */
	uint32_t tag_rndz_size;        /* threshold for tagged msg rendezvous */
	time_t idle_rx_msg_timeout;           /* timeout for partial rx msg's */
	time_t idle_dsend_msg_timeout;     /* timeout for deferred send msg's */
	time_t idle_rtr_msg_timeout;        /* timeout for buffered rtr msg's */
	time_t max_rx_sync_grp_lifetime;   /* max lifetime for rx sync groups */
	uint32_t max_msg_retransmits;     /* max num retransmissions of a msg */
	uint32_t max_rtr_q_entries;         /* max num of rtr msg's to buffer */
	struct uet_msg_id_cb msg_id_cb;        /* used for assigning msg id's */
	struct uet_sync_grp_cb sync_grp_cb; /* used for assigning sync groups */
				      /* used for assigning tx restart tokens */
	struct uet_tx_rtr_token_cb tx_rtr_token_cb;
	struct uet_rw_lock ep_lkup_lock;            /* lock for ep lookup tbl */
	struct uet_ep *ep_hash_table;                  /* endpoint hash table */
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
	struct dlist_entry domain_list_entry;      /* domain list entry */
	struct dlist_entry ep_list_head;      /* endpoint obj list head */
	struct dlist_entry av_list_head;      /* av entry obj list head */
	struct uet_rw_lock ep_lock;      /* lock for accessing ep obj's */
	struct fid_fabric *fabric;          /* fabric struct for domain */
	struct fi_info *info;       /* libfabric info struct for domain */
	struct fid_domain *domain;    /* ptr to libfabric domain struct */
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
	uint32_t src_id; /* initiator (SourceID); valid for rx entries */
	/* err entry is largest cq entry format */
	uint8_t cq_entry[sizeof(struct fi_cq_err_entry)];
};

/* completion queue control block */
struct uet_cq {
	uet_cq_state_t cq_state;                 /* for detecting error state */
	struct uet_ep *uet_ep;                     /* ptr to ep struct for cq */
	struct fi_cq_attr *attr;            /* ptr to libfabric cq attributes */
	struct fid_cq *fid_cq;                  /* ptr to libfabric cq struct */
	uint64_t flags;                              /* flags from fi_ep_bind */
	void *context;                     /* user context associated with cq */
	enum fi_cq_format format;                  /* format of entries in cq */
	size_t format_size;             /* size of each entry in cq, in bytes */
	struct uet_ring ring;           /* ring implementing completion queue */
	uint32_t last_src_id;     /* SourceID of the most recently read entry */
};

/* endpoint control block */
struct uet_ep {
	pthread_mutex_t data_lock;        /* lock for data path thread safety */
	uet_ep_state_t ep_state;                         /* state of endpoint */
	struct dlist_entry ep_list_entry;              /* endpoint list entry */
	UT_hash_handle ep_hh;            /* handle for endpoint hash function */
	struct uet_domain *uet_domain;                /* ptr to domain struct */
	struct fi_info *info;                 /* ptr to libfabric info struct */
	struct fid_ep *ep;                /* ptr to libfabric endpoint struct */
	void *context;               /* user context associated with endpoint */
	struct uet_addr uet_addr;               /* uet addr of ep, host order */
	struct uet_fa ip_addr;                   /* ip addr of ep, host order */
	struct uet_ep_key ep_key;                  /* key for endpoint lookup */
	uint8_t msg_ip_tos;                            /* ip tos for messages */
	struct uet_cq send_cq;                       /* send completion queue */
	struct uet_cq recv_cq;                    /* receive completion queue */
	size_t num_tx_desc;                   /* num entries in tx_desc array */
	size_t num_rx_desc;                   /* num entries in rx_desc array */
	struct uet_tx_desc *tx_desc;           /* array of tx msg descriptors */
	struct uet_rx_desc *rx_desc;           /* array of rx msg descriptors */
	struct dlist_entry tx_desc_list_head;   /* head of avail tx desc list */
					     /* head of deferred tx desc list */
	struct dlist_entry tx_desc_defer_list_head;
		      /* head of list containing buffered msg restart entries */
	struct dlist_entry tx_desc_buf_rtr_list_head;
	       /* head of list containing buffered tagged msg restart entries */
	struct dlist_entry tx_desc_buf_tag_rtr_list_head;
	size_t num_buf_rtr_list_entries;     /* num entries in both rtr lists */
	struct dlist_entry rx_desc_list_head;   /* head of avail rx desc list */
			   /* head of active list that contains rx desc's for */
			   /* partially received msg's                        */
	struct dlist_entry rx_desc_active_list_head;
	struct uet_ring rx_ring;                    /* rx msg descriptor ring */
	struct uet_ring tx_ring;                    /* tx msg descriptor ring */
	struct uet_rx_desc *rx_msg_hash_table;           /* rx msg hash table */
	struct uet_rx_desc *tag_initiator_hash_table;       /* tag hash table */
		     /* hash table for memory regions with user-assigned keys */
	struct uet_mr_desc *mr_hash_table;
		  /* head of list containing mr's with provider-assigned keys */
	struct dlist_entry mr_list_head;
	void *pds;                                               /* pds state */
	void *nic_ep_context;                   /* optional NIC endpoint state */
	uint32_t job_id;                                /* ses job identifier */
	uint16_t entropy;             /* stable endpoint entropy value (EV) */
	bool absolute;       /* endpoint uses absolute addressing (any JobID) */
			     /* relative endpoints demux/authorize by JobID   */
	uint8_t untagged_gen;            /* ses generation for untagged msg's */
	bool untagged_gen_disabled;  /* true=>gen disabled for untagged msg's */
	uint8_t tagged_gen;                /* ses generation for tagged msg's */
	bool tagged_gen_disabled;    /* true => gen disabled for tagged msg's */
	size_t num_active_sends;          /* number of active send operations */
					 /* initiator does sync grp av lookup */
	struct uet_sync_grp_av_key sync_grp_av_key;
	struct uet_sync_grp_av_entry *sync_grp_av_hash_table;
			 	       /* target does sync grp src fep lookup */
	struct uet_sync_grp_src_fep_key sync_grp_src_fep_key;
	struct uet_sync_grp_src_fep_entry *sync_grp_src_fep_hash_table;
};

/* info associated with data to be carried in pds ack */
struct uet_ack_d_info {
	bool valid;                         /* true => data is carried in ack */
	uint32_t payload_len;                        /* size of data in bytes */
	uint32_t msg_off;                               /* msg offset of data */
	void *buf;                                             /* ptr to data */
};

#endif /* _UET_API_PRIVATE_H_ */
