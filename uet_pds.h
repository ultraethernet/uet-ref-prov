/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* Definitions for SES-PDS APIs */

#ifndef _UET_PDS_H_
#define _UET_PDS_H_

#include <stdint.h>
#include <stdbool.h>

#include <ofi_list.h>

#include "uet_pkt_hdr.h"
#include "uet_api.h"
#include "uet_util.h"

#define UET_PDS "UET_PDS"

#define UET_DEFAULT_TX_TIMEOUT       5		/* in millisecs */
#define UET_DEFAULT_MAX_TX_RETRIES   5
#define UET_DEFAULT_MSL              2000	/* max seg lifetime in msecs */
#define UET_DEFAULT_PDS_MAX_ACK_DATA 16		/* in bytes */
#define UET_DEFAULT_PDS_PER_PKT_ACK_ENABLED 0
#define UET_DEFAULT_PDS_ACK_GEN_MIN_PKT_ADD 1024 /* in bytes */
#define UET_DEFAULT_PDS_ACK_GEN_PKT_TRIGGER 16384 /* in bytes */

struct uet_ep;     /* forward references */
struct uet_instance;
struct uet_av_entry;
struct uet_tx_desc;

/* pds delivery modes */
typedef enum {
	UET_PDS_MODE_UUD,
	UET_PDS_MODE_ROD,
	UET_PDS_MODE_RUD,
	UET_PDS_MODE_RUDI,
} uet_pds_mode_t;

/* pds error codes */
typedef enum {
	UET_PDS_ERR_NONE,
} uet_pds_err_code_t;

#define UET_PDS_FLAG_NONE 0

/* pds tx flags */
typedef enum {
	UET_PDS_FLAG_SOM          = 0x01, /* start of message */
	UET_PDS_FLAG_EOM          = 0x02, /* end of message */
	UET_PDS_FLAG_EAGER_REQ    = 0x04, /* request eager length predition */
	UET_PDS_FLAG_RETRANSMIT   = 0x08, /* retransmit of pkt  */
	UET_PDS_FLAG_MAINTAIN_PDC = 0x10, /* don't allow PDC teardown */
} uet_pds_tx_flags_t;

/* pds tx som flags */
typedef enum {
	UET_PDS_FLAG_PDC_ID_V = 0x01,  /* pdc id valid */
	UET_PDS_FLAG_BUSY     = 0x02,  /* pdc could not accept pkt */
} uet_pds_tx_som_flags_t;

/* info that pds may need on transmit requests                           */
/*   - the info is only needed when read data is being transmitted       */
/*   - pds provides the info to ses when the read request is received    */
/*   - ses echoes the data back to pds when the read data is transmitted */
struct uet_pds_info {
	uint32_t opsn;  /* original psn from initiator of req */
	uint16_t pdcid;
};

/* function ptr's for pds upcalls to ses */
typedef void *uet_pkt_handle_t;

struct uet_ses_to_pds_funcs {
	/*
	 * initialize pds resources for the uet instance
	 *
	 * parms:
	 *      uet - ptr to uet instance struct that pds is being initialized
	 *            for
	 *
	 * returns:
	 *      0 on success
	 *      negative value corresponding to errno on error
	 */
	int (*initialize)(struct uet_instance *uet);

	/*
	 * free pds resources for the uet instance
	 *
	 * parms:
	 *      uet_dom - ptr to uet instance struct that pds resources are
	 *                associated with
	 */
	void (*finalize)(struct uet_instance *uet);

	/*
	 * initialize pds resources for endpoint
	 *
	 * parms:
	 *      uet_ep - ptr to uet endpoint struct that pds resources are
	 *               being initialized for
	 *
	 * returns:
	 *      0 on success
	 *      negative value corresponding to errno on error
	 */
	int (*ep_initialize)(struct uet_ep *uet_ep);

	/*
	 * free pds resources for endpoint
	 *
	 * parms:
	 *      uet_ep - ptr to uet endpoint struct that pds resources are
	 *               associated with
	 */
	void (*ep_finalize)(struct uet_ep *uet_ep);

	/*
	 * initiate pds transmission of packet
	 *
	 * parms:
	 *      tx_pkt_handle   - handle for packet to be transmitted,
	 *                        assigned by caller
	 *      pkt_cnt         - number of packets previously transmitted
	 *                        using tx_pkt_handle for current message,
	 *                        provided solely to simplify pds debug
	 *      uet_ep          - ptr to uet endpoint struct that packet is
	 *                        associated with
	 *      dst_addr_handle - handle of uet addr that packet is destined for
	 *      mode            - packet delivery mode to be used for packet tx
	 *      flags           - flags for tx operation
	 *        UET_PDS_FLAG_SOM - pkt is start of message
	 *        UET_PDS_FLAG_EOM - pkt is end of message
	 *        UET_PDS_FLAG_EAGER_REQ - request eager length predition,
	 *                                 provided in build_ses_hdr upcall
	 *                                 from pds to ses
	 *        UET_PDS_FLAG_RETRANSMIT - this is retransmit of the packet
	 *        UET_PDS_FLAG_MAINTAIN_PDC - don't allow the pdc selected for
	 *                                    this message to be torn down
	 *                                    until ses indicates all responses
	 *                                    have been received
	 *      pds_info        - ptr to pds info echoed back from read request
	 *      msg_id          - id of message
	 *      next_hdr        - identifies next header following pds header
	 *      ses             - ptr to ses header for pkt
	 *      ses_len         - length of ses header in bytes
	 *      pkt             - ptr to msg payload to be sent
	 *      pkt_len         - length of msg payload to be sent in bytes
	 *      dma_rdy         - true => msg payload buffer can be DMA'ed
	 *
	 * returns:
	 *      0 on success
	 *      negative value corresponding to errno on error
	 *     -EAGAIN indicates caller should queue packet and retry later
	 */
	int (*tx_pkt)(uet_pkt_handle_t tx_pkt_handle, uint64_t pkt_cnt,
		      struct uet_ep *uet_ep,
		      uet_addr_handle_t dst_addr_handle, uet_pds_mode_t mode,
		      uet_pds_tx_flags_t flags,
		      struct uet_pds_info *pds_info, uint16_t msg_id,
		      uet_pds_next_hdr_t next_hdr, void *ses, size_t ses_len,
		      void *pkt, size_t pkt_len, bool dma_rdy);

	/*
	 * indicate message completion
	 *   - called for messages where UET_PDS_FLAG_MAINTAIN_PDC was set
	 *     when message transmission was initiated
	 *
	 * parms:
	 *      ep              - ptr to uet endpoint struct that message is
	 *                        associated with
	 *      dst_addr_handle - handle of uet addr that msg was destined for
	 *      mode            - packet delivery mode used for message
	 *      msg_id          - id of message that has completed
	 *
	 * returns:
	 *      0 on success
	 *      negative value corresponding to errno on error
	 */
	int (*msg_cmpl_ind)(struct uet_ep *uet_ep,
			    uet_addr_handle_t dst_addr_handle,
			    uet_pds_mode_t mode, uint16_t msg_id);

	/*
	 * progress tx operations for endpoint
	 *
	 * parms:
	 *      ep             - ptr to uet endpoint struct
	 *      err_pkt_handle - addr of location where packet handle is
	 *                       returned in err case
	 *
	 * returns:
	 *      0 on success
	 *      negative value corresponding to errno on error
	 */
	int (*progress_tx)(struct uet_ep *uet_ep,
			   uet_pkt_handle_t *err_pkt_handle);

	/*
	 * progress rx operations
	 *
	 * parms:
	 *      uet - ptr to uet instance struct
	 *
	 * returns:
	 *      0 to indicate no error
	 *      negative value corresponding to errno on error
	 */
	int (*progress_rx)(struct uet_instance *uet);

	/*
	 * implement endpoint close wait state
	 *
	 * parms:
	 *      uet_ep - ptr to uet endpoint struct for endpoint that is
	 *               being closed
	 */
	void (*ep_close_wait)(struct uet_ep *uet_ep);

	/*
	 * drop every queued packet that names a ses transmit handle
	 *
	 * called when ses abandons a transmit, a queue pair being
	 * destroyed or work being cancelled, so that nothing the pds still
	 * holds refers to a descriptor ses is about to recycle
	 *
	 * pds must not make the pds_err upcall for what it drops here ad the
	 * caller is already completing that descriptor
	 *
	 * parms:
	 *      uet_ep        - ptr to uet endpoint struct
	 *      tx_pkt_handle - handle assigned to the packets by ses when
	 *                      their transmission was initiated
	 *
	 * returns:
	 *      the number of packets dropped
	 */
	size_t (*drop_tx_pkts)(struct uet_ep *uet_ep,
			       uet_pkt_handle_t tx_pkt_handle);
};

struct uet_pds_to_ses_funcs {
	/*
	 * pds upcall to ses when request packet is received
	 *
	 * parms:
	 *      rx_pkt_handle   - handle assigned to received packet by pds
	 *      uet             - ptr to uet instance struct
	 *      pp              - ptr to parsed packet struct
	 *      pds_info        - info that needs to be echoed back to pds when
	 *                        read data is transmitted
	 *      req_ses_hdr     - ptr to ses header in request packet
	 *      rsp_next_hdr    - address of location where identifer of ses
	 *                        header format for response is to be returned,
	 *                        return contents are only valid when function
	 *                        returns 0
	 *      rsp_ses_hdr     - ptr to buffer where ses header for response
	 *                        is to be returned, return contents are only
	 *                        valid when function returns 0,
	 *                        buffer must be large enough to hold maximum
	 *                        size ses response
	 *      rsp_ses_hdr_len - address of location where length of ses
	 *                        header for response is to be returned, return
	 *                        contents are only valid when function returns
	 *                        0
	 *      ses_nack        - ptr to location where ses indicates whether
	 *                        pds should send pds nack instead of pds ack,
	 *                        return contents are only valid when function
	 *                        returns 0, true => pds must send
	 *                        nack ses response state
	 *      gtd_del         - ptr to location where ses indicates whether
	 *                        pds needs to maintain ses response state,
	 *                        return contents are only valid when function
	 *                        returns 0, true => pds must
	 *                        guarantee delivery of ses response state
	 *
	 * returns:
	 *   - 0 when ses response is to be returned to initiator
	 *   - negative value corresponding to errno on error
	 */
	int (*rx_req)(uet_pkt_handle_t rx_pkt_handle, struct uet_instance *uet,
		      struct uet_parsed_pkt *pp, struct uet_pds_info *pds_info,
		      uet_pds_next_hdr_t *rsp_next_hdr, void *rsp_ses_hdr,
		      size_t *rsp_ses_hdr_len, bool *ses_nack, bool *gtd_del);

	/*
	 * pds upcall to ses when response packet is received
	 *
	 * parms:
	 *      tx_pkt_handle - handle assigned to packet by ses when associated
	 *                      request packet transmission was initiated
	 *      rsp_pp        - ptr to parsed packet struct for response
	 *
	 * returns:
	 *      0 when ack processed
	 *      negative value corresponding to errno on error
	 */
	int (*rx_rsp)(uet_pkt_handle_t tx_pkt_handle,
		      struct uet_parsed_pkt *rsp_pp);

	/*
	 * pds upcall to ses when unrecoverable error occurs
	 *
	 * parms:
	 *      tx_pkt_handle - handle assigned to packet by ses when
	 *                      transmission of packet associated with error
	 *                      was initiated
	 *      reason        - error reason code
	 *
	 * returns:
	 *      0 on success
	 *      negative value corresponding to errno on error
	 */
	int (*pds_err)(uet_pkt_handle_t tx_pkt_handle,
		       uet_pds_err_code_t reason);
};

struct uet_pds_state;

/* pds control block structure - embedded in uet_instance struct */
struct uet_pds {
	struct uet_pds_state *state;	/* instance-owned PDC manager */
	struct uet_ses_to_pds_funcs downcall;     /* ptr's to pds functions */
	struct uet_pds_to_ses_funcs upcall;       /* ptr's to ses functions */
	time_t tx_timeout;               /* retry after this amount of time */
	int    max_tx_retries;             /* max tx retries before failing */
	time_t msl;                    /* max segment lifetime in millisecs */
	uint8_t ack_ip_tos;                             /* ip tos for ack's */
	uint16_t max_ack_data;               /* max data carried in pds ack */
	bool per_pkt_ack_enabled;       /* true=> enable per packet ack mode */
	uint32_t ack_gen_trigger; /* rx bytes threshold for ack triggering */
	uint32_t ack_gen_min_pkt_add; /* min bytes per pkt add to accept_bytes */
	uet_pds_pkt_type_t ack_type; /* UET_PDS_TYPE_ACK / ACK_CC / ACK_CCX */
};

/* initialize the PDS and set the proper downcall function pointers */
int uet_pds_init(struct uet_instance *uet);

#endif /* _UET_PDS_H_ */
