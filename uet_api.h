/*
 * Copyright (c) 2024,2025,2026 Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/* UET API Definitions */

#ifndef _UET_API_H_
#define _UET_API_H_

#include <sys/uio.h> /* get struct iovec */

/* include libfabric data structs */
#include <ofi_mem.h>
#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_atomic.h>

#include "uet_addr.h"

/* TODO: remove default job id when addr resolutions works */
#define UET_DEF_JOB_ID  1

#define UET_JOB_ID_ANY  0xffffffff  /* match any job id */
#define UET_NULL_HANDLE NULL

#define UET_FLAGS_NONE	0

#define UET_EXACT_MATCH 0           /* no ignore bits */

#define UET_DEF_MR_CNT	16	    /* default number of memory regions */

/* definitions for memory region key format (UET spec Table 2-13) */
#define UET_MR_KEY_NONE                 ((uint64_t) 0)
#define UET_MR_KEY_IDEMPOTENT_SAFE      0x8000000000000000ULL /* bit 63 */
#define UET_MR_KEY_OPTIMIZED            0x4000000000000000ULL /* bit 62 */
#define UET_MR_KEY_RESERVED             0x3f00000000000000ULL /* bits 56:61 */
#define UET_MR_KEY_VENDOR               0x00ff000000000000ULL /* bits 48:55 */
#define UET_MR_KEY_RKEY_MASK            0x0000ffffffffffffULL /* bits 0:47 */
#define UET_MR_KEY_RKEY_SHIFT           0
#define UET_MR_KEY_MAX_RKEY             (UET_MR_KEY_RKEY_MASK >> \
					 UET_MR_KEY_RKEY_SHIFT)
#define UET_MR_KEY_OPTIMIZED_RESERVED   0x0000fffffffff000ULL /* bits 12:47 */
#define UET_MR_KEY_OPTIMIZED_RKEY_MASK  0x0000000000000fffULL /* bits 0:11 */
#define UET_MR_KEY_OPTIMIZED_RKEY_SHIFT 0
#define UET_MR_KEY_OPTIMIZED_MAX_RKEY   (UET_MR_KEY_OPTIMIZED_RKEY_MASK >> \
					 UET_MR_KEY_OPTIMIZED_RKEY_SHIFT)

/*
 * Vendor-specific marker selecting the lookup space for a key. Per
 * Table 2-13 the VENDOR_SPECIFIC field MAY be used for provider-assigned
 * keys but MUST be 0 for user-assigned keys. Provider-assigned keys set
 * this bit and are resolved via the index space; user-assigned keys
 * leave it clear and are resolved via the hash space. The two spaces are
 * independent (the same RKEY value MAY exist in both simultaneously).
 */
#define UET_MR_KEY_VENDOR_PROV_SPACE    0x0001000000000000ULL /* bit 48 */

/* flags for uet_mr_reg() / uet_mr_regv() / uet_mr_reg_job() */
#define UET_MR_FLAG_USER_KEY            (1ULL << 0)  /* user-assigned */

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
				  struct fi_eq_entry *eq_entry);
typedef void (*uet_eq_err_callback_t)(uet_handle_t handle,
				      struct fi_eq_err_entry *eq_err_entry);

/*******************************************************************
 * uet_info API family
 *******************************************************************/

/*
 * init uet instance
 *
 * parms:
 *   handle - ptr to location where uet instance handle is returned
 *   is_ipv6 - initialize for IPv6
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_initialize(uet_handle_t *handle, bool is_ipv6);

/*
 * free resources of uet instance
 *
 * parms:
 *   handle - handle identifying uet instance
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_finalize(uet_handle_t handle);

/*
 * discover communication features that are available
 *
 * parms:
 *   handle - handle identifying uet instance
 *   node   - optional ptr to uet address that can be used as a
 *            filter to limit the returned providers based on the
 *            fields of the uet address that are valid, NULL if
 *            the FI_SOURCE flag is not set on the associated
 *            fi_getinfo API call
 *   hints  - optional ptr to fi_info struct that specifies criteria
 *            for selecting the returned fabric information
 *   info   - ptr to location where a ptr to a linked list of fi_info
 *            structures containing response information is returned
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_getinfo(uet_handle_t handle, struct uet_addr *node,
		const struct fi_info *hints, struct fi_info **info);

/* replacements for fi_allocinfo(), fi_dupinfo() and fi_freeinfo() */
/* for Verbs API                                                   */
#if ENABLE_VERBS
struct fi_info *uet_verbs_fi_allocinfo(void);
struct fi_info *uet_verbs_fi_dupinfo(struct fi_info *info);
void uet_verbs_fi_freeinfo(struct fi_info *info);
#endif


/*******************************************************************
 * uet_domain API family
 *******************************************************************/

/*
 * called when a domain is created
 *
 * parms:
 *   handle          - handle identifying uet instance
 *   fabric          - ptr to libfabric fabric struct that domain is
 *                     associated with
 *   info            - ptr to libfabric info struct that domain is
 *                     associated with
 *   domain          - ptr to initialized libfabric domain struct
 *   context         - user specified context associated with domain
 *   eq_callback     - ptr to callback function for successful
 *                     asynchronous event completions
 *   eq_err_callback - ptr to callback function for asynchronous
 *                     error events
 *   domain_handle   - ptr to location where uet domain handle
 *                     is returned
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_domain(uet_handle_t handle, struct fid_fabric *fabric,
	       struct fi_info *info, struct fid_domain *domain,
	       void *context, uet_eq_callback_t eq_callback,
	       uet_eq_err_callback_t eq_err_callback,
	       uet_domain_handle_t *domain_handle);

/*
 * called when a domain is closed
 *
 * parms:
 *   domain_handle - handle identifying uet domain instance
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_domain_close(uet_domain_handle_t domain_handle);

/*******************************************************************
 * uet_mr API family
 *******************************************************************/

/*
 * format a memory region protection key
 *
 * parms:
 *   rkey            - remote key value
 *   idempotent_safe - true => memory region can be used for as target for
 *                             idempotent operations
 *
 * returns:
 *   FI_KEY_NOTAVAIL if rkey is not available,
 *   otherwise: protection key is returned in uet format
 */
uint64_t uet_mr_format_key(uint64_t rkey, bool idempotent_safe);

/*
 * simple API to register a memory region with a domain
 *
 * parms:
 *   domain_handle - handle identifying uet domain instance
 *   buf           - address of memory region buffer
 *   len           - length of memory region buffer in bytes
 *   access        - memory access permissions, see fi_mr
 *   requested_key - requested remote key, ignored if the
 *                   FI_MR_PROV_KEY flag is set in the
 *                   domain mr_mode bits
 *   flags         - operational flags, see fi_mr
 *   context       - user specified context associated with mr
 *   mr_handle     - ptr to location where uet endpoint handle is
 *                   returned, the uet provider can use the mr_handle
 *                   as the memory region descriptor
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - can be used to implement the following libfabric fi_mr api's:
 *     - fi_mr_reg
 */
int uet_mr_reg(uet_domain_handle_t domain_handle, const void *buf, size_t len,
	       uint64_t access, uint64_t requested_key, uint64_t flags,
	       void *context, uet_mr_handle_t *mr_handle);

/*
 * simple API to register a memory region supporting scatter-gather with a
 * domain
 *
 * parms:
 *   domain_handle - handle identifying uet domain instance
 *   iov           - address of scatter-gather list
 *   iov_count     - number of elements in scatter-gather list
 *   access        - memory access permissions, see fi_mr
 *   requested_key - requested remote key, ignored if the
 *                   FI_MR_PROV_KEY flag is set in the
 *                   domain mr_mode bits
 *   flags         - operational flags, see fi_mr
 *   context       - user specified context associated with mr
 *   mr_handle     - ptr to location where uet endpoint handle is
 *                   returned, the uet provider can use the mr_handle
 *                   as the memory region descriptor
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - can be used to implement the following libfabric fi_mr api's:
 *     - fi_mr_reg
 */
int uet_mr_regv(uet_domain_handle_t domain_handle, const struct iovec *iov,
		size_t iov_count, uint64_t access, uint64_t requested_key,
		uint64_t flags, void *context, uet_mr_handle_t *mr_handle);

/*
 * flexible api to register a memory region with a domain
 *
 * parms:
 *   domain_handle - handle identifying uet domain instance
 *   job_id        - job id associated with mr for access
 *                   authorization, UET_JOB_ID_ANY => mr can be
 *                   used by any job id
 *   attr          - ptr to memory region attributes structure,
 *                   see fi_mr
 *   flags         - operational flags, see fi_mr
 *   context       - user specified context associated with mr
 *   mr_handle     - ptr to location where uet endpoint handle is
 *                   returned, the uet provider can use the mr_handle
 *                   as the memory region descriptor
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - can be used to implement the following libfabric fi_mr api's:
 *     - fi_mr_regv
 *     - fi_mr_regattr
 */
int uet_mr_regattr(uet_domain_handle_t domain_handle, uint32_t job_id,
		   const struct fi_mr_attr *attr, uint64_t flags,
		   uet_mr_handle_t *mr_handle);

/*
 * register a derived memory region contained within an existing region
 *
 * parms:
 *   domain_handle     - handle identifying uet domain instance
 *   parent_mr_handle  - handle of the existing (parent) memory region
 *   buf               - start of the derived region (within the parent)
 *   len               - length of the derived region
 *   access            - operations supported for the derived region
 *   requested_key     - requested key (UET_MR_KEY_NONE for provider key)
 *   flags             - UET_MR_FLAG_* (e.g. UET_MR_FLAG_USER_KEY)
 *   job_id            - JobID to restrict the region to (if job_restricted)
 *   job_restricted    - if true, restrict the derived region to job_id
 *   context           - user specified context associated with the region
 *   mr_handle         - ptr to location where the derived region handle
 *                       is returned
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_mr_derive(uet_domain_handle_t domain_handle,
		  uet_mr_handle_t parent_mr_handle,
		  const void *buf, size_t len, uint64_t access,
		  uint64_t requested_key, uint64_t flags,
		  uint32_t job_id, bool job_restricted, void *context,
		  uet_mr_handle_t *mr_handle);

/*
 * register a memory region restricted to a specific JobID
 *
 * parms:
 *   domain_handle - handle identifying uet domain instance
 *   buf           - start of the region
 *   len           - length of the region
 *   access        - operations supported for the region
 *   requested_key - requested key (UET_MR_KEY_NONE for provider key)
 *   flags         - registration flags
 *   job_id        - JobID the region is restricted to
 *   context       - user specified context associated with the region
 *   mr_handle     - ptr to location where the region handle is returned
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_mr_reg_job(uet_domain_handle_t domain_handle, const void *buf,
		   size_t len, uint64_t access, uint64_t requested_key,
		   uint64_t flags, uint32_t job_id, void *context,
		   uet_mr_handle_t *mr_handle);

/*
 * register a memory region restricted to a specific Resource Index, and
 * optionally to a JobID as well.
 *
 * parms:
 *   domain_handle - handle identifying uet domain instance
 *   buf           - start of the region
 *   len           - length of the region
 *   access        - operations supported for the region
 *   requested_key - requested key (UET_MR_KEY_NONE for provider key)
 *   flags         - registration flags
 *   job_id        - JobID to also restrict to, or UET_JOB_ID_ANY for RI-only
 *   resource_index - Resource Index the region is restricted to
 *   context       - user specified context associated with the region
 *   mr_handle     - ptr to location where the region handle is returned
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_mr_reg_ri(uet_domain_handle_t domain_handle, const void *buf,
		  size_t len, uint64_t access, uint64_t requested_key,
		  uint64_t flags, uint32_t job_id, uint16_t resource_index,
		  void *context, uet_mr_handle_t *mr_handle);

/*
 * get memory region protection key
 *
 * parms:
 *   mr_handle - handle identifying uet memory region instance
 *
 * returns:
 *   FI_KEY_NOTAVAIL if key is not available,
 *   otherwise: protection key is returned
 */
uint64_t uet_mr_key(uet_mr_handle_t mr_handle);

/*
 * create and bind counter to memory region
 *
 * parms:
 *   mr_handle   - handle identifying uet memory region instance
 *   flags       - operational flags, see fi_mr_bind
 *   cntr_handle - ptr to location where uet counter handle
 *                 is returned
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - this is useful when the memory region is bound to the domain
 *   - data plane does not need to know about counter until it is
 *     bound to a resource
 */
int uet_mr_bind_cntr(uet_mr_handle_t mr_handle, uint64_t flags,
		     uet_cntr_handle_t *cntr_handle);

/*
 * refresh memory region page table entries
 *
 * parms:
 *   mr_handle - handle identifying uet memory region instance
 *   iov       - ptr to array of buffer descriptors
 *   count     - number of entries in 'iov' array
 *   flags     - operational flags, see fi_mr
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
uint64_t uet_mr_refresh(uet_mr_handle_t mr_handle,
			const struct iovec *iov,
			size_t count, uint64_t flags);

/*
 * enable a memory region
 *
 * parms:
 *   mr_handle - handle identifying uet memory region instance
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_mr_enable(uet_mr_handle_t mr_handle);

/*
 * disable MR state and remove all entries
 *
 * parms:
 *   mr_handle - handle identifying uet memory region instance
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_mr_disable(uet_mr_handle_t mr_handle);

/*
 * close a memory region
 *
 * parms:
 *   mr_handle - handle identifying uet memory region instance
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_mr_close(uet_mr_handle_t mr_handle);

/*******************************************************************
 * uet_endpoint API family
 *******************************************************************/

/*
 * called when an endpoint is created
 *
 * parms:
 *   domain_handle - handle identifying uet domain instance
 *   info          - ptr to libfabric info struct that ep is
 *                   associated with
 *   ep            - ptr to initialized libfabric ep struct
 *   context       - user specified context associated with ep
 *   ep_handle     - ptr to location where uet endpoint handle
 *                   is returned
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
#if !ENABLE_VERBS
int uet_endpoint(uet_domain_handle_t domain_handle,
		 struct fi_info *info, struct fid_ep *ep,
		 void *context, uet_ep_handle_t *ep_handle);
#else
int uet_endpoint(uet_domain_handle_t domain_handle,
		 struct fi_info *info, struct fid_ep *ep,
		 void *context, uet_ep_handle_t *ep_handle,
		 uint16_t pid_on_fep, uint16_t resource_index,
		 uint32_t initiator_id, uint32_t job_id,
		 bool absolute);
#endif

/*
 * called to get uet address of an endpoint
 *
 * parms:
 *   ep_handle - handle identifying uet endpoint instance
 *   uet_addr  - ptr to location where uet address is to be returned
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_getname(uet_ep_handle_t ep_handle, struct uet_addr *uet_addr);

/*
 * called when a scalable endpoint is created
 *
 * parms:
 *   domain_handle - handle identifying uet domain instance
 *   info          - ptr to libfabric info struct that ep is
 *                   associated with
 *   ep            - ptr to initialized libfabric ep struct
 *   context       - user specified context associated with ep
 *   sep_handle    - ptr to location where uet scalable endpoint
 *                   handle is returned
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_scalable_ep(uet_domain_handle_t domain_handle,
		    struct fi_info *info, struct fid_ep *ep,
		    void *context, uet_ep_handle_t *sep_handle);

/*
 * open transmit context of a scalable endpoint
 *
 * parms:
 *   sep_handle   - handle identifying uet scalable endpoint instance
 *   index        - index of transmit context
 *   attr         - ptr to libfabric attributes struct associated with
 *                  the transmit context
 *   context      - user specified context associated with the
 *                  transmit endpoint
 *   tx_ep_handle - ptr to location where uet endpoint handle for the
 *                  transmit context is returned
 *                  - this handle is used to transmit on the context
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_tx_context(uet_ep_handle_t sep_handle, int index,
		   struct fi_tx_attr *attr, void *context,
		   uet_ep_handle_t *tx_ep_handle);

/*
 * open receive context of a scalable endpoint
 *
 * parms:
 *   sep_handle   - handle identifying uet scalable endpoint instance
 *   index        - index of receive context
 *   attr         - ptr to libfabric attributes struct associated
 *                  with receive context
 *   context      - user specified context associated with the
 *                  receive endpoint
 *   rx_ep_handle - ptr to location where uet endpoint handle for the
 *                  receive context is returned
 *                  - this handle is used to receive on the context
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_rx_context(uet_ep_handle_t sep_handle, int index,
		   struct fi_rx_attr *attr, void *context,
		   uet_ep_handle_t *rx_ep_handle);

/*
 * open shared transmit context for a domain
 *
 * parms:
 *   domain_handle - handle identifying uet domain instance
 *   attr          - ptr to libfabric attributes struct associated
 *                   with the shared transmit context
 *   context       - user specified context associated with the
 *                   shared transmit context
 *   stx_handle    - ptr to location where uet shared context handle
 *                   is returned
 *                   - this handle is used to bind the shared context
 *                     to an endpoint
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_stx_context(uet_domain_handle_t domain_handle,
		    struct fi_tx_attr *attr,
		    void *context, uet_sctx_handle_t *stx_handle);

/*
 * open shared receive context for a domain
 *
 * parms:
 *   domain_handle - handle identifying uet domain instance
 *   attr          - ptr to libfabric attributes struct associated
 *                   with the shared receive context
 *   context       - user specified context associated with the
 *                   shared receive context
 *   rx_ep_handle  - ptr to location where uet endpoint handle for
 *                   the shared receive context is returned
 *                   - this handle is used to post rx buffers on the
 *                     shared receive context
 *   srx_handle    - ptr to location where uet shared context handle
 *                   is returned
 *                   - this handle is used to bind the shared context
 *                     to an endpoint
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_srx_context(uet_domain_handle_t domain_handle,
		    struct fi_rx_attr *attr, void *context,
		    uet_ep_handle_t *rx_ep_handle,
		    uet_sctx_handle_t *srx_handle);

/*
 * bind shared context to an endpoint
 *
 * parms:
 *   ep_handle   - handle identifying uet endpoint instance
 *   sctx_handle - handle identifying uet shared context instance
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - an endpoint that supports shared rx/tx contexts is created
 *     by setting the info->ep_attr->rx_ctx_cnt/tx_ctx_cnt field(s)
 *     to FI_SHARED_CONTEXT when the uet_endpoint API is called
 */
int uet_ep_bind_sctx(uet_ep_handle_t ep_handle,
		     uet_sctx_handle_t sctx_handle);

/*
 * create and bind a completion queue to an endpoint
 *
 * parms:
 *   ep_handle - handle identifying uet endpoint instance
 *   attr      - ptr to libfabric cq attributes struct
 *   cq        - ptr to initialized libfabric cq struct
 *   flags     - flags from fi_ep_bind
 *   context   - user specified context associated with cq
 *   cq_handle - ptr to location where uet cq handle is returned
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - data plane does not need to know about completion queue until
 *     it is bound to a resource
 */
int uet_ep_bind_cq(uet_ep_handle_t ep_handle, struct fi_cq_attr *attr,
		   struct fid_cq *cq, uint64_t flags, void *context,
		   uet_cq_handle_t *cq_handle);

/*
 * create and bind a counter to an endpoint
 *
 * parms:
 *   ep_handle   - handle identifying uet endpoint instance
 *   flags       - flags from fi_ep_bind
 *   cntr_handle - ptr to location where uet counter handle is
 *                 returned
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - data plane does not need to know about counter until it is
 *     bound to a resource
 */
int uet_ep_bind_cntr(uet_ep_handle_t ep_handle, uint64_t flags,
		     uet_cntr_handle_t *cntr_handle);

/*
 * bind memory region to an endpoint
 *
 * parms:
 *   ep_handle - handle identifying uet endpoint instance
 *   mr_handle - handle identifying uet memory region instance
 *   flags     - operational flags, see fi_mr_bind
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_ep_bind_mr(uet_ep_handle_t ep_handle,
		   uet_mr_handle_t mr_handle, uint64_t flags);

/*
 * enable an endpoint
 *
 * parms:
 *   ep_handle - handle identifying uet endpoint instance
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_ep_enable(uet_ep_handle_t ep_handle);

/*
 * reset an endpoint back to the pre-enable (disabled) state so it can be
 * re-enabled, e.g. to recover a verbs QP through the ERR -> RST -> RTS path
 *
 * parms:
 *   ep_handle - handle identifying uet endpoint instance
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_ep_reset(uet_ep_handle_t ep_handle);

/*
 * cancel a pending asynchronous data transfer
 *
 * parms:
 *   ep_handle - handle identifying uet endpoint instance
 *   context   - user specified context identifying data transfer
 *               to cancel
 *
 * returns:
 *   0 when cancel request was submitted for processing,
 *   negative value corresponding to fabric errno on error
 */
int uet_cancel(uet_ep_handle_t ep_handle, void *context);

/*
 * create alias for an endpoint
 *
 * parms:
 *   parent_ep_handle - handle identifying parent uet endpoint
 *                      instance
 *   alias_ep_handle  - ptr to location where uet endpoint handle for
 *                      alias endpoint is returned
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - an alias endpoint differs from its parent endpoint only by its
 *     default data transfer flags, see fi_msg for description of
 *     data transfer flags
 *   - the uet_control api can be used to set the default data
 *     transfer flags for the alias endpoint
 */
int uet_ep_alias(uet_ep_handle_t ep_handle,
		 uet_ep_handle_t *alias_ep_handle);

/*
 * adjust default behavior of an endpoint
 *
 * parms:
 *   ep_handle - handle identifying uet endpoint instance
 *   command   - control command, see fi_control api of fi_endpoint
 *   arg       - command specific arg, see fi_control api of
 *               fi_endpoint
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - currently, the only ‘command’ that must be supported is
 *     FI_SETOPSFLAG, which is used to set the default data transfer
 *     operation flags associated with an endpoint
 */
int uet_ep_control(uet_ep_handle_t ep_handle, int command, void *arg);

/*
 * adjust low-level protocol and implementation-specific details
 * of an endpoint
 *
 * parms:
 *   ep_handle - handle identifying uet endpoint instance
 *   level     - option level, see fi_setopt api of fi_endpoint
 *   optname   - option name, see fi_setopt api of fi_endpoint
 *   optval    - ptr to option value to set
 *   optlen    - length of option value in bytes
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - the only ‘level’ that must be supported is
 *     FI_OPT_ENDPOINT, and the only ‘optname’ that should be
 *     supported is FI_OPT_MIN_MULTI_RECV, which has a value of
 *     type size_t
 *   - a multi-receive buffer is released when the available buffer
 *     space falls below a specified minimum, FI_OPT_MIN_MULTI_RECV
 *     adjusts that minimum
 *   - FI_OPT_MIN_MULTI_RECV is applicable in conjunction with the
 *     FI_MULTI_RECV data transfer operation flag
 */
int uet_ep_setopt(uet_ep_handle_t ep_handle, int level, int optname,
		  const void *optval, size_t optlen);

/*
 * called when an endpoint is closed
 *
 * parms:
 *   ep_handle - handle identifying uet endpoint instance
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_ep_close(uet_ep_handle_t ep_handle);

/*******************************************************************
 * uet_cq API family
 *******************************************************************/

/*
 * non-blocking read of completion queue
 *
 * parms:
 *   cq_handle - handle identifying uet completion queue instance
 *   buf       - ptr to buffer to write completions into
 *   count     - max number of completions to read
 *
 * returns:
 *   number of entries read on success,
 *   negative value corresponding to fabric errno on error
 *   (fabric errno values are defined in <rdma/fi_errno.h>,
 *    -FI_EAVAIL indicates cq is in error state and
 *    uet_cq_readerr should be called)
 */
ssize_t uet_cq_read(uet_cq_handle_t cq_handle, void *buf,
		    size_t count);

/*
 * get the initiator (SourceID) of the most recently read completion
 *
 * parms:
 *   cq_handle - handle identifying uet completion queue instance
 *
 * returns:
 *   the SES initiator value of the last entry read via uet_cq_read
 */
uint32_t uet_cq_read_src_id(uet_cq_handle_t cq_handle);

/*
 * non-blocking read of completion queue error
 *
 * parms:
 *   cq_handle - handle identifying uet completion queue instance
 *   buf       - ptr to buffer to write cq error struct into
 *
 * returns:
 *   number of entries read on success,
 *   negative value corresponding to fabric errno on error
 */
ssize_t uet_cq_readerr(uet_cq_handle_t cq_handle,
		       struct fi_cq_err_entry *buf);

/*
 * called when a completion queue is closed
 *
 * parms:
 *   cq_handle - handle identifying uet completion queue instance
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_cq_close(uet_cq_handle_t cq_handle);

/*******************************************************************
 * uet_cntr API family
 *******************************************************************/

/*
 * read value of counter instance
 *
 * parms:
 *   cntr_handle - handle identifying uet counter instance
 *   value       - ptr to location where counter value is returned
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_cntr_read(uet_cntr_handle_t cntr_handle, uint64_t *value);

/*
 * read error value of counter instance
 *
 * parms:
 *   cntr_handle - handle identifying uet counter instance
 *   error_value - ptr to location where error value of counter
 *                 is returned
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - a counter instance includes a counter value and an
 *     error counter value, see fi_cntr
 */
int uet_cntr_readerr(uet_cntr_handle_t cntr_handle,
		     uint64_t *error_value);

/*
 * add value to counter instance
 *
 * parms:
 *   cntr_handle - handle identifying uet counter instance
 *   value       - value to add to counter
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_cntr_add(uet_cntr_handle_t cntr_handle, uint64_t value);

/*
 * add to error value of counter instance
 *
 * parms:
 *   cntr_handle - handle identifying uet counter instance
 *   error_value - amount to add to error value of counter
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_cntr_adderr(uet_cntr_handle_t cntr_handle,
		    uint64_t error_value);

/*
 * set value of counter instance
 *
 * parms:
 *   cntr_handle - handle identifying uet counter instance
 *   value       - value to set
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_cntr_set(uet_cntr_handle_t cntr_handle, uint64_t value);

/*
 * set error value of counter instance
 *
 * parms:
 *   cntr_handle - handle identifying uet counter instance
 *   error_value - error value to set
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_cntr_seterr(uet_cntr_handle_t cntr_handle,
		    uint64_t error_value);

/*
 * close a counter instance
 *
 * parms:
 *   cntr_handle - handle identifying uet counter instance
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_cntr_close(uet_cntr_handle_t cntr_handle);

/*******************************************************************
 * uet_av API family
 *******************************************************************/

/*
 * insert entry for uet address in address vector
 *
 * parms:
 *   domain_handle - handle identifying uet domain instance
 *   uet_addr      - ptr to uet address to insert
 *   addr_handle   - ptr to location where uet addr handle is returned
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - intended to establish binding between uet address and associated
 *     L2 header
 */
int uet_av_insert(uet_domain_handle_t domain_handle,
		  struct uet_addr *uet_addr,
		  uet_addr_handle_t *addr_handle);

/*
 * remove address vector entry for uet address
 *
 * parms:
 *   addr_handle – handle identifying uet address
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
int uet_av_remove(uet_addr_handle_t addr_handle);

/*******************************************************************
 * uet_msg API family
 *******************************************************************/

/*
 * simple api to post buffer to receive queue of an endpoint
 *
 * parms:
 *   ep_handle       - handle identifying uet endpoint instance
 *   job_id          - job id associated with buffer for access
 *                     authorization, UET_JOB_ID_ANY => buffer can be used
 *                     by any job id
 *   buf             - ptr to buffer being posted
 *   len             - length of buffer in bytes
 *   mr_handle       - handle identifying memory region associated with
 *                     buffer, may be UET_NULL_HANDLE
 *   src_addr_handle - handle identifying source uet address to receive from,
 *                     may be UET_NULL_HANDLE
 *   context         - user specified pointer to associate with the operation
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - can be used to implement the following libfabric fi_msg api’s:
 *     - fi_recv
 *   - if FI_MSG_PREFIX mode is configured, the buffer prefix
 *     contains frame headers on completion
 */
#if !ENABLE_VERBS
ssize_t uet_recv(uet_ep_handle_t ep_handle, uint32_t job_id,
		 void *buf, size_t len, uet_mr_handle_t mr_handle,
		 uet_addr_handle_t src_addr_handle, void *context);
#else
ssize_t uet_recv(uet_ep_handle_t ep_handle, uint32_t job_id,
		 void *buf, size_t len, uet_mr_handle_t mr_handle,
		 uet_addr_handle_t src_addr_handle, void *context);
#endif

/*
 * simple api to post iov to receive queue of an endpoint
 *
 * parms:
 *   ep_handle       - handle identifying uet endpoint instance
 *   job_id          - job id associated with buffer for access
 *                     authorization, UET_JOB_ID_ANY => buffer can be used
 *                     by any job id
 *   iov             - Pointer to an array of IO vectors that describe the
 *                     memory buffers for receiving data.
 *   iov_count       - Number of IO vectors in the iov array.
 *   mr_handle       - handle identifying memory region associated with
 *                     buffer, may be UET_NULL_HANDLE
 *   src_addr_handle - handle identifying source uet address to receive from,
 *                     may be UET_NULL_HANDLE
 *   context         - user specified pointer to associate with the operation
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
#if !ENABLE_VERBS
ssize_t uet_recvv(
	uet_ep_handle_t ep_handle, uint32_t job_id, const struct iovec *iov,
	size_t iov_count, uet_mr_handle_t mr_handle,
	uet_addr_handle_t src_addr_handle, void *context);
#else
ssize_t uet_recvv(
	uet_ep_handle_t ep_handle, uint32_t job_id, const struct iovec *iov,
	size_t iov_count, uet_mr_handle_t mr_handle,
	uet_addr_handle_t src_addr_handle, void *context);
#endif

/*
 * flexible api to post buffer to receive queue of an endpoint
 *
 * parms:
 *   ep_handle - handle identifying uet endpoint instance
 *   job_id    - job id associated with buffer for access
 *               authorization, UET_JOB_ID_ANY => buffer can be used
 *               by any job id
 *   msg       - ptr to message buffer descriptor, see fi_msg
 *   flags     - operational flags, see fi_msg
 *   mr_handle – ptr to array of handles identifying memory regions
 *               associated with buffer
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - can be used to implement the following libfabric fi_msg api’s:
 *     - fi_recvv
 *     - fi_recvmsg
 *   - if FI_MSG_PREFIX mode is configured, the buffer prefix
 *     contains frame headers on completion
 */
ssize_t uet_recvmsg(uet_ep_handle_t ep_handle, uint32_t job_id,
		    const struct fi_msg *msg, uint64_t flags,
		    uet_mr_handle_t *mr_handle);

/*
 * simple api for transmission of a message to an endpoint
 *
 * parms:
 *   ep_handle       - handle identifying local uet endpoint instance
 *   job_id          - job id associated with message
 *   buf             - ptr to buffer containing message
 *   len             - length of buffer in bytes
 *   mr_handle       - handle identifying memory region associated with
 *                     buffer, may be UET_NULL_HANDLE
 *   dst_addr_handle - handle identifying uet destination address
 *   context         - user specified pointer to associate with the operation
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - can be used to implement the following libfabric fi_msg api’s:
 *     - fi_send
 */
#if !ENABLE_VERBS
ssize_t uet_send(uet_ep_handle_t ep_handle, uint32_t job_id,
		 void *buf, size_t len, uet_mr_handle_t mr_handle,
		 uet_addr_handle_t dst_addr_handle, void *context);
#else
ssize_t uet_send(uet_ep_handle_t ep_handle, uint32_t job_id,
		 void *buf, size_t len, uet_mr_handle_t mr_handle,
		 uet_addr_handle_t dst_addr_handle, void *context,
		 uint16_t resource_index);
#endif

/*
 * transmit a message to an endpoint with immediate (remote CQ) data
 *
 * Behaves like uet_send() but carries a 64-bit immediate value that is
 * delivered to the peer's receive completion as remote CQ data. The verbs
 * layer decides how many bits of the immediate are meaningful (32 or 64),
 * so a single 64-bit-capable entry point serves both immediate sizes.
 *
 * parms:
 *   as uet_send(), plus:
 *   imm_data        - pointer to the 64-bit immediate value to send
 *
 * returns:
 *   as uet_send()
 */
#if ENABLE_VERBS
ssize_t uet_send_imm(uet_ep_handle_t ep_handle, uint32_t job_id,
		     void *buf, size_t len, uet_mr_handle_t mr_handle,
		     uet_addr_handle_t dst_addr_handle, uint64_t *imm_data,
		     void *context, uint16_t resource_index);
#endif

/*
 * simple vector api for transmission of a message to an endpoint
 *
 * parms:
 *   ep_handle       - handle identifying local uet endpoint instance
 *   job_id          - job id associated with message
 *   iov             - Pointer to an array of IO vectors that describe the
 *                     memory buffers for sending data.
 *   iov_count       - Number of IO vectors in the iov array.
 *   mr_handle       - handle identifying memory region associated with
 *                     buffer, may be UET_NULL_HANDLE
 *   dst_addr_handle - handle identifying uet destination address
 *   context         - user specified pointer to associate with the operation
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - can be used to implement the following libfabric fi_msg api’s:
 *     - fi_send
 */
#if !ENABLE_VERBS
ssize_t uet_sendv(
	uet_ep_handle_t ep_handle, uint32_t job_id, const struct iovec *iov,
	size_t iov_count, uet_mr_handle_t mr_handle,
	uet_addr_handle_t dst_addr_handle, void *context);
#else
ssize_t uet_sendv(
	uet_ep_handle_t ep_handle, uint32_t job_id, const struct iovec *iov,
	size_t iov_count, uet_mr_handle_t mr_handle,
	uet_addr_handle_t dst_addr_handle, void *context,
	uint16_t resource_index);
#endif

/*
 * flexible api for transmission of a message to an endpoint
 *
 * parms:
 *   ep_handle - handle identifying local uet endpoint instance
 *   job_id    - job id associated with message
 *   msg       - ptr to message buffer descriptor, see fi_msg
 *   flags     - operational flags, see fi_msg
 *   dst_addr  – handle identifying uet destination address
 *   mr_handle – ptr to array of handles identifying memory regions
 *               associated with message
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - can be used to implement the following libfabric fi_msg api’s:
 *     - fi_sendv
 *     - fi_sendmsg
 *     - fi_inject
 *     - fi_senddata
 *     - fi_injectdata
 */
ssize_t uet_sendmsg(uet_ep_handle_t ep_handle, uint32_t job_id,
		    const struct fi_msg *msg, uint64_t flags,
		    uet_addr_handle_t dst_addr,
		    uet_mr_handle_t *mr_handle);

/*******************************************************************
 * uet_tagged API family
 *******************************************************************/

/*
 * simple api to post tagged buffer to receive queue of an endpoint
 *
 * parms:
 *   ep_handle       - handle identifying uet endpoint instance
 *   job_id          - job id associated with buffer for access
 *                     authorization, UET_JOB_ID_ANY => buffer can be used
 *                     by any job id
 *   buf             - ptr to buffer being posted
 *   len             - length of buffer in bytes
 *   mr_handle       - handle identifying memory region associated with
 *                     buffer, may be UET_NULL_HANDLE
 *   src_addr_handle - handle identifying source uet address to receive from
 *   tag             - tag associated with message
 *   ignore          - mask of bits to ignore applied to the tag
 *   context         - user specified pointer to associate with the operation
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - can be used to implement the following libfabric fi_tagged
 *     api’s:
 *     - fi_trecv
 *   - if FI_MSG_PREFIX mode is configured, the buffer prefix
 *     contains frame headers on completion
 */
ssize_t uet_trecv(uet_ep_handle_t ep_handle, uint32_t job_id,
		  void *buf, size_t len, uet_mr_handle_t mr_handle,
		  uet_addr_handle_t src_addr_handle, uint64_t tag,
		  uint64_t ignore, void *context);

/*
 * simple api to post tagged iov to receive queue of an endpoint
 *
 * parms:
 *   ep_handle       - handle identifying uet endpoint instance
 *   job_id          - job id associated with buffer for access
 *                     authorization, UET_JOB_ID_ANY => buffer can be used
 *                     by any job id
 *   iov             - Pointer to an array of IO vectors that describe
 *                     the memory buffers for receiving data.
 *   iov_count       - Number of IO vectors in the iov array.
 *   mr_handle       - handle identifying memory region associated with
 *                     buffer, may be UET_NULL_HANDLE
 *   src_addr_handle - handle identifying source uet address to receive from
 *   tag             - tag associated with message
 *   ignore          - mask of bits to ignore applied to the tag
 *   context         - user specified pointer to associate with the operation
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 */
ssize_t uet_trecvv(
	uet_ep_handle_t ep_handle, uint32_t job_id, const struct iovec *iov,
	size_t iov_count, uet_mr_handle_t mr_handle,
	uet_addr_handle_t src_addr_handle, uint64_t tag, uint64_t ignore,
	void *context);
/*
 * flexible api to post tagged buffer to receive queue of an endpoint
 *
 * parms:
 *   ep_handle - handle identifying uet endpoint instance
 *   job_id    - job id associated with buffer for access
 *               authorization, UET_JOB_ID_ANY => buffer can be used
 *               by any job id
 *   msg       - ptr to message buffer descriptor, see fi_msg
 *   flags     - operational flags, see fi_msg
 *   mr_handle – ptr to array of handles identifying memory regions
 *               associated with buffer
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - can be used to implement the following libfabric fi_msg api’s:
 *     - fi_recvv
 *     - fi_recvmsg
 *   - if FI_MSG_PREFIX mode is configured, the buffer prefix
 *     contains frame headers on completion
 */
ssize_t uet_trecvmsg(uet_ep_handle_t ep_handle, uint32_t job_id,
		     const struct fi_msg *msg, uint64_t flags,
		     uet_mr_handle_t *mr_handle);

/*
 * simple api for transmission of a tagged message to an endpoint
 *
 * parms:
 *   ep_handle       - handle identifying local uet endpoint instance
 *   job_id          - job id associated with message
 *   buf             - ptr to buffer containing message
 *   len             - length of buffer in bytes
 *   mr_handle       - handle identifying memory region associated with
 *                     buffer, may be UET_NULL_HANDLE
 *   dst_addr_handle - handle identifying uet destination address
 *   tag             - tag associated with message
 *   context         - user specified pointer to associate with the operation
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - can be used to implement the following libfabric fi_msg api’s:
 *     - fi_send
 */
ssize_t uet_tsend(uet_ep_handle_t ep_handle, uint32_t job_id,
		  void *buf, size_t len, uet_mr_handle_t mr_handle,
		  uet_addr_handle_t dst_addr_handle, uint64_t tag,
		  void *context);

/*
 * simple api for transmission of a tagged message to an endpoint
 *
 * parms:
 *   ep_handle       - handle identifying local uet endpoint instance
 *   job_id          - job id associated with message
 *   iov             - Pointer to an array of IO vectors that describe
 *                     the memory buffers for receiving data.
 *   iov_count       - Number of IO vectors in the iov array
 *   mr_handle       - handle identifying memory region associated with
 *                     buffer, may be UET_NULL_HANDLE
 *   dst_addr_handle - handle identifying uet destination address
 *   tag             - tag associated with message
 *   context         - user specified pointer to associate with the operation
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 */
ssize_t uet_tsendv(
	uet_ep_handle_t ep_handle, uint32_t job_id, const struct iovec *iov,
	size_t iov_count, uet_mr_handle_t mr_handle,
	uet_addr_handle_t dst_addr_handle, uint64_t tag, void *context);

/*
 * flexible api for transmission of a tagged message to an endpoint
 *
 * parms:
 *   ep_handle       - handle identifying local uet endpoint instance
 *   job_id          - job id associated with message
 *   msg             - ptr to message buffer descriptor, see fi_msg
 *   flags           - operational flags, see fi_msg
 *   dst_addr_handle - handle identifying uet destination address
 *   mr_handle       - ptr to array of handles identifying memory regions
 *                     associated with message
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - can be used to implement the following libfabric fi_msg api’s:
 *     - fi_sendv
 *     - fi_sendmsg
 *     - fi_inject
 *     - fi_senddata
 *     - fi_injectdata
 */
ssize_t uet_tsendmsg(uet_ep_handle_t ep_handle, uint32_t job_id,
		     const struct fi_msg *msg, uint64_t flags,
		     uet_addr_handle_t dst_addr_handle,
		     uet_mr_handle_t *mr_handle);

/*******************************************************************
 * uet_rma API family
 *******************************************************************/

/*
 * simple api for rma write
 *
 * parms:
 *   ep_handle        - handle identifying local uet endpoint instance
 *   job_id           - job id associated with operation
 *   buf              - ptr to data buffer to write from
 *   len              - length of data buffer in bytes
 *   data             - ptr to immediate data, NULL => no imediate data
 *   mr_handle        - handle identifying memory region associated with
 *                      ‘buf’, may be UET_NULL_HANDLE, required when
 *                      FI_MR_LOCAL mode bit is set, see fi_rma
 *   dst_addr_handle  - handle identifying destination uet address
 *   remote_mem_addr  - remote memory address
 *   remote_key       - remote protection key
 *   context          - user specified pointer to associate with the operation
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - can be used to implement the following libfabric fi_rma api’s:
 *     - fi_write, fi_writedata
 */
#if !ENABLE_VERBS
ssize_t uet_write(uet_ep_handle_t ep_handle, uint32_t job_id,
		  void *buf, size_t len, uint64_t *data,
		  uet_mr_handle_t mr_handle,
		  uet_addr_handle_t dst_addr_handle,
		  uint64_t remote_mem_addr, uint64_t remote_key,
		  void *context);
#else
ssize_t uet_write(uet_ep_handle_t ep_handle, uint32_t job_id,
		  void *buf, size_t len, uint64_t *data,
		  uet_mr_handle_t mr_handle,
		  uet_addr_handle_t dst_addr_handle,
		  uint64_t remote_mem_addr, uint64_t remote_key,
		  void *context, uint16_t resource_index);
#endif

/*
 * simple api for sync rma write
 *
 * parms:
 *   ep_handle        - handle identifying local uet endpoint instance
 *   job_id           - job id associated with operation
 *   buf              - ptr to data buffer to write from
 *   len              - length of data buffer in bytes
 *   data             - ptr to immediate data, NULL => no imediate data
 *   mr_handle        - handle identifying memory region associated with
 *                      ‘buf’, may be UET_NULL_HANDLE, required when
 *                      FI_MR_LOCAL mode bit is set, see fi_rma
 *   dst_addr_handle  - handle identifying destination uet address
 *   remote_mem_addr  - remote memory address
 *   remote_key       - remote protection key
 *   context          - user specified pointer to associate with the operation
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - can be used to implement the following libfabric fi_rma api’s:
 *     - fi_write, fi_writedata
 */
#if !ENABLE_VERBS
ssize_t uet_write_sync(uet_ep_handle_t ep_handle, uint32_t job_id,
		       void *buf, size_t len, uint64_t *data,
		       uet_mr_handle_t mr_handle,
		       uet_addr_handle_t dst_addr_handle,
		       uint64_t remote_mem_addr, uint64_t remote_key,
		       void *context);
#else
ssize_t uet_write_sync(uet_ep_handle_t ep_handle, uint32_t job_id,
		       void *buf, size_t len, uint64_t *data,
		       uet_mr_handle_t mr_handle,
		       uet_addr_handle_t dst_addr_handle,
		       uint64_t remote_mem_addr, uint64_t remote_key,
		       void *context, uint16_t resource_index);
#endif

/*
 * flexible api for rma write
 *
 * parms:
 *   ep_handle        - handle identifying local uet endpoint instance
 *   job_id           - job id associated with operation
 *   msg              - ptr to buffer descriptor struct for write operation,
 *                      see fi_rma
 *   flags            - operational flags, see fi_rma
 *   dst_addr_handle  - handle identifying destination uet address
 *   mr_handle        - ptr to array of handles identifying memory regions
 *                      associated with message
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - can be used to implement the following libfabric fi_rma api’s:
 *     - fi_writev
 *     - fi_writemsg
 *     - fi_inject_write
 *     - fi_inject_writedata
 */
ssize_t uet_writemsg(uet_ep_handle_t ep_handle, uint32_t job_id,
		     const struct fi_msg_rma *msg, uint64_t flags,
		     uet_addr_handle_t dst_addr_handle,
		     uet_mr_handle_t *mr_handle);

/*
 * simple api for rma read
 *
 * parms:
 *   ep_handle       - handle identifying local uet endpoint instance
 *   job_id          - job id associated with operation
 *   buf             - ptr to data buffer for read
 *   len             - length of data buffer in bytes
 *   mr_handle       - handle identifying memory region associated with
 *                     ‘buf’, may be UET_NULL_HANDLE, required when
 *                     FI_MR_LOCAL mode bit is set, see fi_rma
 *   uet_addr_handle - handle identifying uet address to read from
 *   remote_mem_addr - remote memory address
 *   remote_key      - remote protection key
 *   context         - user specified pointer to associate with the
 *                     operation
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - can be used to implement the following libfabric fi_rma api’s:
 *     - fi_read
 */
#if !ENABLE_VERBS
ssize_t uet_read(uet_ep_handle_t ep_handle, uint32_t job_id, void *buf,
		 size_t len, uet_mr_handle_t mr_handle,
		 uet_addr_handle_t uet_addr_handle,
		 uint64_t remote_mem_addr, uint64_t remote_key, void *context);
#else
ssize_t uet_read(uet_ep_handle_t ep_handle, uint32_t job_id, void *buf,
		 size_t len, uet_mr_handle_t mr_handle,
		 uet_addr_handle_t uet_addr_handle,
		 uint64_t remote_mem_addr, uint64_t remote_key, void *context,
		 uint16_t resource_index);
#endif

/*
 * flexible api for rma read
 *
 * parms:
 *   ep_handle       - handle identifying local uet endpoint instance
 *   job_id          - job id associated with operation
 *   msg             - ptr to buffer descriptor struct for read operation,
 *                     see fi_rma
 *   flags           - operational flags, see fi_rma
 *   uet_addr_handle - handle identifying uet address to read from
 *   mr_handle       - ptr to array of handles identifying memory regions
 *                     associated with message
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - can be used to implement the following libfabric fi_rma api’s:
 *     - fi_readv
 *     - fi_readmsg
 */
ssize_t uet_readmsg(uet_ep_handle_t ep_handle, uint32_t job_id,
		    const struct fi_msg_rma *msg, uint64_t flags,
		    uet_addr_handle_t uet_addr_handle,
		    uet_mr_handle_t *mr_handle);

/*******************************************************************
 * uet_atomic API family
 *******************************************************************/

/*
 * simple api for base atomic operation
 *
 * parms:
 *   ep_handle       - handle identifying local uet endpoint instance
 *   job_id          - job id associated with operation
 *   local_op_buf    - ptr to local data buffer containing array of
 *                     operands for the atomic operation, see fi_atomic
 *   count           - number of entries in ‘local_op_buf’
 *   mr_handle       - handle identifying memory region associated with
 *                     ‘local_op_buf’, may be UET_NULL_HANDLE, required
 *                     when FI_MR_LOCAL mode bit is set, see fi_rma
 *   dst_addr_handle - handle identifying uet destination address
 *   remote_mem_addr - remote memory address
 *   remote_key      - remote protection key
 *   datatype        - data type associated with atomic operands,
 *                     see fi_atomic
 *   op              - atomic operation to perform, see fi_atomic
 *   context         - user specified pointer to associate with the
 *                     operation
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - used to implement the following libfabric fi_atomic api’s:
 *     - fi_atomic
 */
#if !ENABLE_VERBS
ssize_t uet_atomic(uet_ep_handle_t ep_handle, uint32_t job_id,
		   const void *local_op_buf, size_t count,
		   uet_mr_handle_t mr_handle,
		   uet_addr_handle_t dst_addr_handle,
		   uint64_t remote_mem_addr, uint64_t remote_key,
		   enum fi_datatype datatype, enum fi_op op,
		   void *context);
#else
ssize_t uet_atomic(uet_ep_handle_t ep_handle, uint32_t job_id,
		   const void *local_op_buf, size_t count,
		   uet_mr_handle_t mr_handle,
		   uet_addr_handle_t dst_addr_handle,
		   uint64_t remote_mem_addr, uint64_t remote_key,
		   enum fi_datatype datatype, enum fi_op op,
		   void *context, uint16_t resource_index);
#endif

/*
 * simple api for sync atomic operation
 *
 * parms:
 *   ep_handle       - handle identifying local uet endpoint instance
 *   job_id          - job id associated with operation
 *   local_op_buf    - ptr to local data buffer containing array of
 *                     operands for the atomic operation, see fi_atomic
 *   count           - number of entries in ‘local_op_buf’
 *   mr_handle       - handle identifying memory region associated with
 *                     ‘local_op_buf’, may be UET_NULL_HANDLE, required
 *                     when FI_MR_LOCAL mode bit is set, see fi_rma
 *   dst_addr_handle - handle identifying uet destination address
 *   remote_mem_addr - remote memory address
 *   remote_key      - remote protection key
 *   datatype        - data type associated with atomic operands,
 *                     see fi_atomic
 *   op              - atomic operation to perform, see fi_atomic
 *   context         - user specified pointer to associate with the
 *                     operation
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - used to implement the following libfabric fi_atomic api’s:
 *     - fi_atomic
 */
#if !ENABLE_VERBS
ssize_t uet_atomic_sync(uet_ep_handle_t ep_handle, uint32_t job_id,
		        const void *local_op_buf, size_t count,
		        uet_mr_handle_t mr_handle,
		        uet_addr_handle_t dst_addr_handle,
		        uint64_t remote_mem_addr, uint64_t remote_key,
		        enum fi_datatype datatype, enum fi_op op,
		        void *context);
#else
ssize_t uet_atomic_sync(uet_ep_handle_t ep_handle, uint32_t job_id,
		        const void *local_op_buf, size_t count,
		        uet_mr_handle_t mr_handle,
		        uet_addr_handle_t dst_addr_handle,
		        uint64_t remote_mem_addr, uint64_t remote_key,
		        enum fi_datatype datatype, enum fi_op op,
		        void *context, uint16_t resource_index);
#endif

/*
 * flexible api for base atomic operation
 *
 * parms:
 *   ep_handle       - handle identifying local uet endpoint instance
 *   job_id          - job id associated with operation
 *   msg             - ptr to descriptor for atomic operations,
 *                     see fi_atomic
 *   flags           - data transfer operation flags, see fi_atomic
 *   dst_addr_handle - handle identifying uet destination address
 *   mr_handle       - ptr to array of handles identifying memory regions
 *                     associated with operation
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - used to implement the following libfabric fi_atomic api’s:
 *     - fi_atomicicv
 *     - fi_atomicmsg
 *     - fi_atomic_inject
 */
ssize_t uet_atomicmsg(uet_ep_handle_t ep_handle, uint32_t job_id,
		      const struct fi_msg_atomic *msg,
		      uint64_t flags, uet_addr_handle_t dst_addr_handle,
		      uet_mr_handle_t *mr_handle);

/*
 * simple api for fetch atomic operation
 *
 * parms:
 *   ep_handle        - handle identifying local uet endpoint instance
 *   job_id           - job id associated with operation
 *   local_op_buf     - ptr to local data buffer containing array of
 *                      operands for the atomic operation, see fi_atomic
 *   count            - number of entries in ‘local_op_buf’ array
 *   op_mr_handle     - handle identifying memory region associated with
 *                      ‘local_op_buf’, may be UET_NULL_HANDLE,
 *                      required when FI_MR_LOCAL mode bit is set,
 *                      see fi_rma
 *   result_buf       - ptr to local data buffer where initial value of
 *                      remote buffer is stored
 *   result_mr_handle - handle identifying memory region associated
 *                      with ‘result_buf’
 *   dst_addr_handle  - handle identifying uet destination address
 *   remote_mem_addr  - remote memory address
 *   remote_key       - remote protection key
 *   datatype         - data type associated with atomic operands,
 *                      see fi_atomic
 *   op               - atomic operation to perform, see fi_atomic
 *   context          - user specified pointer to associate with the
 *                      operation
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - used to implement the following libfabric fi_atomic api’s:
 *     - fi_fetch_atomic
 */
#if !ENABLE_VERBS
ssize_t uet_fetch_atomic(uet_ep_handle_t ep_handle, uint32_t job_id,
			 const void *local_op_buf,
			 size_t count, uet_mr_handle_t op_mr_handle,
			 void *result_buf,
			 uet_mr_handle_t result_mr_handle,
			 uet_addr_handle_t dst_addr_handle,
			 uint64_t remote_mem_addr,
			 uint64_t remote_key,
			 enum fi_datatype datatype, enum fi_op op,
			 void *context);
#else
ssize_t uet_fetch_atomic(uet_ep_handle_t ep_handle, uint32_t job_id,
			 const void *local_op_buf,
			 size_t count, uet_mr_handle_t op_mr_handle,
			 void *result_buf,
			 uet_mr_handle_t result_mr_handle,
			 uet_addr_handle_t dst_addr_handle,
			 uint64_t remote_mem_addr,
			 uint64_t remote_key,
			 enum fi_datatype datatype, enum fi_op op,
			 void *context, uint16_t resource_index);
#endif

/*
 * flexible api for fetch atomic operation
 *
 * parms:
 *   ep_handle        - handle identifying local uet endpoint instance
 *   job_id           - job id associated with operation
 *   msg              - ptr to descriptor for atomic operations,
 *                      see fi_atomic
 *   msg_mr_handle    - ptr to array of handles identifying memory
 *                      regions associated with ‘msg’
 *   resultv          - ptr to array of local data buffers where initial
 *                      values of remote buffers are stored
 *   result_mr_handle - ptr to array of handles identifying memory
 *                      regions associated with ‘resultv’ array
 *   result_count     - number of entries in ‘resultv’ array
 *   flags            - data transfer operation flags, see fi_atomic
 *   dst_addr_handle  - handle identifying uet destination address
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - used to implement the following libfabric fi_atomic api’s:
 *     - fi_fetch_atomicicv
 *     - fi_fetch_atomicmsg
 */
ssize_t uet_fetch_atomicmsg(uet_ep_handle_t ep_handle,
			    uint32_t job_id,
			    const struct fi_msg_atomic *msg,
			    uet_mr_handle_t *msg_mr_handle,
			    struct fi_ioc *resultv,
			    uet_mr_handle_t *result_mr_handle,
			    size_t result_count, uint64_t flags,
			    uet_addr_handle_t dst_addr_handle);

/*
 * simple api for compare atomic operation
 *
 * parms:
 *   ep_handle        - handle identifying local uet endpoint instance
 *   job_id           - job id associated with operation
 *   local_op_buf     - ptr to local data buffer containing array of
 *                      operands for the atomic operation, see fi_atomic
 *   count            - number of entries in ‘local_op_buf’ array
 *   op_mr_handle     - handle identifying memory region associated with
 *                      ‘local_op_buf’, may be UET_NULL_HANDLE, required
 *                       when FI_MR_LOCAL mode bit is set, see fi_rma
 *   compare_buf       - local buffer containing comparison data
 *   compare_mr_handle - handle identifying memory region associated
 *                       with ‘compare_buf’
 *   result_buf        - ptr to local data buffer where initial value
 *                       of remote buffer is stored
 *   result_mr_handle  - handle identifying memory region associated
 *                       with ‘result_buf’
 *   dst_addr_handle   - handle identifying uet destination address
 *   remote_mem_addr   - remote memory address
 *   remote_key        - remote protection key
 *   datatype          - data type associated with atomic operands,
 *                       see fi_atomic
 *   op                - atomic operation to perform, see fi_atomic
 *   context           - user specified pointer to associate with the
 *                       operation
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - used to implement the following libfabric fi_atomic api’s:
 *     - fi_compare_atomic
 */
#if !ENABLE_VERBS
ssize_t uet_compare_atomic(uet_ep_handle_t ep_handle, uint32_t job_id,
			   const void *local_op_buf, size_t count,
			   uet_mr_handle_t op_mr_handle,
			   const void *compare_buf,
			   uet_mr_handle_t compare_mr_handle,
			   void *result_buf,
			   uet_mr_handle_t result_mr_handle,
			   uet_addr_handle_t dst_addr_handle,
			   uint64_t remote_mem_addr,
			   uint64_t remote_key,
			   enum fi_datatype datatype,
			   enum fi_op op, void *context);
#else
ssize_t uet_compare_atomic(uet_ep_handle_t ep_handle, uint32_t job_id,
			   const void *local_op_buf, size_t count,
			   uet_mr_handle_t op_mr_handle,
			   const void *compare_buf,
			   uet_mr_handle_t compare_mr_handle,
			   void *result_buf,
			   uet_mr_handle_t result_mr_handle,
			   uet_addr_handle_t dst_addr_handle,
			   uint64_t remote_mem_addr,
			   uint64_t remote_key,
			   enum fi_datatype datatype, enum fi_op op,
			   void *context, uint16_t resource_index);
#endif

/*
 * flexible api for compare atomic operation
 *
 * parms:
 *   ep_handle        - handle identifying local uet endpoint instance
 *   job_id           - job id associated with operation
 *   msg              - ptr to descriptor for atomic operations,
 *                      see fi_atomic
 *   msg_mr_handle    - ptr to array of handles identifying memory
 *                      regions associated with ‘msg’
 *   comparev         - ptr to array of local data buffers containing
 *                      comparison data
 *   compare_mr_handle - ptr to array of handles identifying memory
 *                       regions associated with ‘comparev’ array
 *   compare_count     - number of entries in ‘comparev’ array
 *   resultv           - ptr to array of local data buffers where
 *                       initial values of remote buffers are stored
 *   result_mr_handle  - ptr to array of handles identifying memory
 *                       regions associated with ‘resultv’ array
 *   result_count      - number of entries in ‘resultv’ array
 *   flags             - data transfer operation flags, see fi_atomic
 *   dst_addr_handle   - handle identifying uet destination address
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - used to implement the following libfabric fi_atomic api’s:
 *     - fi_compare_atomicicv
 *     - fi_compare_atomicmsg
 */
ssize_t uet_compare_atomicmsg(uet_ep_handle_t ep_handle,
			      uint32_t job_id,
			      const struct fi_msg_atomic *msg,
			      uet_mr_handle_t *msg_mr_handle,
			      struct fi_ioc *comparev,
			      uet_mr_handle_t *compare_mr_handle,
			      size_t compare_count,
			      struct fi_ioc *resultv,
			      uet_mr_handle_t *result_mr_handle,
			      size_t result_count,
			      uint64_t flags,
			      uet_addr_handle_t dst_addr_handle);

/*
 * query supported atomic operation
 *
 * parms:
 *   domain_handle - handle identifying uet domain instance
 *   datatype      - data type associated with atomic operand,
 *                   see fi_atomic
 *   op            - atomic operation, see fi_atomic
 *   attr          - ptr to libfabric struct containing atomic
 *                   attributes on return, see fi_atomic
 *   flags         - flags identifying class of atomic operation,
 *                   see fi_atomic
 *
 * returns:
 *   0 on success,
 *   negative value corresponding to fabric errno on error
 *
 * notes:
 *   - used to implement the following libfabric fi_atomic api’s:
 *     - fi_atomicvalid
 *     - fi_fetch_atomicvalid
 *     - fi_compare_atomicvalid
 *     - fi_query_atomicvalid
 */
int uet_query_atomic(uet_domain_handle_t domain_handle,
		     enum fi_datatype datatype, enum fi_op op,
		     struct fi_atomic_attr *attr, uint64_t flags);

#endif /* _UET_API_H_ */
