/*
 * Copyright (c) 2024, Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/*
 * Simple client-server ping-pong application using UET APIs
 *   - supports message and RMA data transfers
 *   - supports both untagged and tagged messages
 *   - supports test option that covers untagged message data transfers,
 *     tagged message data transfers, RMA (read and write) data transfers,
 *     unexpected message handling for untagged/tagged messages, and
 *     deferred send for untagged/tagged messages
 *
 * Description of message operation (applies to both untagged and
 *                                   tagged messages):
 *   - the server is started first with the IP address of the
 *     client as a command line arg
 *   - the client is then started with the IP address of the
 *     server as a command line arg
 *   - the client sends a message to the server
 *   - the server receives the message and then sends it back
 *     to the client
 *
 * Description of RMA operation:
 *   - the server is started first with the IP address of the
 *     client as a command line arg
 *   - the client is then started with the IP address of the
 *     server as a command line arg
 *   - the client sends a control message to the server that identifies the
 *     address and key of its' RMA buffer
 *   - the server receives the control message and then sends a control message
 *     to the client with the address and key of its' RMA buffer
 *   - the client receives the control message and initiates a RMA write of the
 *     data message to the server's buffer
 *     - the write includes completion data that generates a completion
 *       at the server
 *   - the server receives the write completion and writes the data message from
 *     its' buffer to the client's buffer
 *     - the write includes completion data that generates a completion
 *       at the client
 *   - the client receives the write completion to complete the ping pong
 *     data message exchange
 *
 * The number of messages to exchange, UET_NUM_ITERATIONS, is defined at
 * compile time
 *
 * Usage:
 *   ./uet <server | client>
 *	<rma | sync_rma | untag | tag | tag_any_src | unexp_untag | unexp_tag |
 *       defer_send | defer_tag | defer_tag_any_src | atomic |
 *       sync_atomic | all>
 *	<remote IP address>
 *
 *   the penultimate arg specifies the test suite to execute,
 *   'all' executes all of the test suites
 *
 * Server Usage Example:
 *   ./uet server all 192.168.1.18
 *
 * Client Usage Example:
 *   ./uet client all 192.168.1.24
 */

#include <stdio.h>
#include <stdint.h>

#include "uet_api.h"
#include "uet_api_private.h"
#include "uet_sec.h"

#define UET_NUM_ITERATIONS	100
#define UET_MSG_SIZE		4096	/* in bytes */
#define UET_MIN_ATOMIC_MSG_SIZE 24
#define UET_NUM_BUFS		((size_t) 8)
#define UET_DEFAULT_TAG		((uint64_t) 1)
#define UET_WRITE_IMM_DATA	((uint64_t) 0x0CAA)

#define UET_MAX_ARGS		4

/* return codes */
typedef enum {
	UET_ERR_RC     = -1,
	UET_SUCCESS_RC =  0
} uet_rc_t;

#ifndef UET_PACKED
#define UET_PACKED __attribute__((__packed__))
#endif

#define UET_WARN(fmt, ...)                                                     \
	fprintf(stdout, "[%s] %s:%-4d: " fmt "\n", "warning",                  \
		__FILE__, __LINE__, ##__VA_ARGS__)

#define UET_ERR(fmt, ...)                                                      \
	fprintf(stdout, "[%s] %s:%-4d: " fmt "\n", "error",                    \
		__FILE__, __LINE__, ##__VA_ARGS__)

#define UET_PRINT_ERRNO(CALL)                                                  \
	fprintf(stdout, "%s(): %s:%-4d, ret = %d (%s)\n",                      \
		(CALL), __FILE__, __LINE__, errno, strerror(errno))

void UET_USAGE(char *cmd)
{
	fprintf(stdout,
	        "Usage: %s <server|client> <command> <remote IPv4 addr>\n"
	         "  <command>: rma\n"
	         "             sync_rma\n"
	         "             untag\n"
	         "             tag\n"
	         "             tag_any_src\n"
	         "             unexp_untag\n"
	         "             unexp_tag\n"
	         "             defer_send\n"
	         "             defer_tag\n"
	         "             defer_tag_any_src\n"
	         "             atomic\n"
	         "             sync_atomic\n",
	         cmd);
}

/* config parm struct */
struct uet_cfg {
	char *prog_name;                               /* ptr to program name */
	bool client;                /* true => operate as client, else server */
	bool tag;                              /* true => use tagged messages */
	bool tag_any_src;          /* true => tagged buffers match any source */
	bool rma;                               /* true => use rma operations */
	bool sync_rma;               /* true => use sync group rma operations */
	bool atomic;                         /* true => use atomic operations */
	bool sync_atomic;         /* true => use sync group atomic operations */
	bool unexpected_msg_test;  /* true => this is unexpected message test */
	bool dsend_test;			/* true => this is dsend test */
	bool iov_test;				     /* true => test uses iov */
	int num_iterations;                 /* number of messages to exchange */
	size_t msg_size;                         /* size of messages in bytes */
	char *peer_ip_addr_string;             /* peer ip addr in string form */
	struct uet_fa peer_ip_addr;                             /* host order */
	bool is_ipv6;
	struct uet_addr peer_uet_addr;                    /* peer uet address */
	uint32_t job_id;                                    /* id of this job */
};

/* memory region info */
struct UET_PACKED uet_mem_region_info {
	uint64_t rma_buf_addr; /* RMA buffer address */
	uint64_t key         ; /* key for memory region */
};

/* control message exchanged between client and server */
#define uet_ctrl_msg uet_mem_region_info

/* primary control block struct for application */
struct uet_context {
	struct uet_cfg cfg;
	struct uet_addr local_uet_addr;
	uet_handle_t uet_handle;
	uet_domain_handle_t domain_handle;
	uet_ep_handle_t ep_handle;
	uet_cq_handle_t tx_cq_handle;
	uet_cq_handle_t rx_cq_handle;
	uet_addr_handle_t peer_addr_handle;
	struct uet_fa local_ip_addr;                       /* host byte order */
	struct fid_fabric fabric;
	struct fid_domain domain;
	struct fid_ep ep;
	struct fi_info *info;
	struct fi_rx_attr *rx_attr;
	struct fi_cq_attr cq_attr;
	struct fid_cq cq;
	uint8_t *tx_msg;                      /* ptr to uet tx message buffer */
	uint8_t *rx_msg;                      /* ptr to uet rx message buffer */
	uint8_t *mr_buf;                /* ptr to local memory region bufffer */
	struct iovec *tx_iov;
	uint8_t tx_count;
	struct iovec *rx_iov;
	uint8_t rx_count;
	uet_mr_handle_t mr_handle;           /*handle for local memory region */
	/* buf addr and key for memory regions */
	struct uet_mem_region_info local_mr, remote_mr;
};

struct uet_context uet_ctx;

bool first;

/* callback function for successful asynchronous event completions */
static void uet_eq_callback(uet_handle_t handle,
			    struct fi_eq_entry *eq_entry)
{
	UET_ERR("Unexpected %s", __func__);
}

/* callback function for asynchronous error events */
static void uet_eq_err_callback(uet_handle_t handle,
				struct fi_eq_err_entry *eq_err_entry)
{
	UET_ERR("Unexpected %s", __func__);
}

/* free resources */
static void uet_free_res(struct uet_context *ctx)
{
	int rc;

	if (ctx->peer_addr_handle != UET_NULL_HANDLE) {
		rc = uet_av_remove(ctx->peer_addr_handle);
		if (rc)
			UET_ERR("uet_av_remove: %s", fi_strerror(-rc));
		ctx->peer_addr_handle = UET_NULL_HANDLE;
	}

	if (ctx->ep_handle != UET_NULL_HANDLE) {
		rc = uet_ep_close(ctx->ep_handle);
		if (rc)
			UET_ERR("uet_endpoint_close: %s", fi_strerror(-rc));
		ctx->ep_handle = UET_NULL_HANDLE;
	}

	if (ctx->tx_cq_handle != UET_NULL_HANDLE) {
		rc = uet_cq_close(ctx->tx_cq_handle);
		if (rc)
			UET_ERR("uet_cq_close: %s", fi_strerror(-rc));
		ctx->tx_cq_handle = UET_NULL_HANDLE;
	}

	if (ctx->rx_cq_handle != UET_NULL_HANDLE) {
		rc = uet_cq_close(ctx->rx_cq_handle);
		if (rc)
			UET_ERR("uet_cq_close: %s", fi_strerror(-rc));
		ctx->rx_cq_handle = UET_NULL_HANDLE;
	}

	if (ctx->mr_handle != UET_NULL_HANDLE) {
		rc = uet_mr_close(ctx->mr_handle);
		if (rc)
			UET_ERR("uet_mr_close: %s", fi_strerror(-rc));
		ctx->mr_handle = UET_NULL_HANDLE;
	}

	if (ctx->domain_handle != UET_NULL_HANDLE) {
		rc = uet_domain_close(ctx->domain_handle);
		if (rc)
			UET_ERR("uet_domain_close: %s", fi_strerror(-rc));
		ctx->domain_handle = UET_NULL_HANDLE;
	}

	if (ctx->info) {
		fi_freeinfo(ctx->info);
		ctx->info = NULL;
	}

	if (ctx->uet_handle != UET_NULL_HANDLE) {
		rc = uet_finalize(ctx->uet_handle);
		if (rc)
			UET_ERR("uet_finalize: %s", fi_strerror(-rc));
		ctx->uet_handle = UET_NULL_HANDLE;
	}

	if (ctx->info) {
		fi_freeinfo(ctx->info);
		ctx->info = NULL;
	}

	if (ctx->tx_msg) {
		free(ctx->tx_msg);
		ctx->tx_msg = NULL;
	}

	if (ctx->rx_msg) {
		free(ctx->rx_msg);
		ctx->rx_msg = NULL;
	}

	if (ctx->mr_buf) {
		free(ctx->mr_buf);
		ctx->mr_buf = NULL;
	}

	if (ctx->tx_iov) {

		for (int i = 0; i < ctx->tx_count; i++)
			free(ctx->tx_iov[i].iov_base);

		free(ctx->tx_iov);
		ctx->tx_iov = NULL;
	}

	if (ctx->rx_iov) {

		for (int i = 0; i < ctx->rx_count; i++)
			free(ctx->rx_iov[i].iov_base);

		free(ctx->rx_iov);
		ctx->rx_iov = NULL;
	}
}

/* initialize config parms */
static uet_rc_t uet_init_cfg(int argc, char *argv[],
			     struct uet_context *ctx)
{
	struct in_addr peer_in_addr;
	struct in6_addr peer_in6_addr;
	struct uet_addr *addr;

	ctx->cfg.job_id = UET_DEF_JOB_ID;

	if ((argc != 3) && (argc != 4))  {
		UET_ERR("Invalid usage: wrong number of args");
		return UET_ERR_RC;
	}

	if (strcmp(argv[1], "client") == 0) {
		ctx->cfg.client = true;
	} else if (strcmp(argv[1], "server") != 0) {
		UET_ERR("Invalid usage: 1st arg must be 'client' "
			"or 'server'");
		return UET_ERR_RC;
	}

	ctx->cfg.prog_name = argv[0];

	if (argc == 4) {
		if (strcmp(argv[2], "tag") != 0) {
			if ((strcmp(argv[2], "rma") != 0) &&
			    (strcmp(argv[2], "sync_rma") != 0) &&
			    (strcmp(argv[2], "atomic") != 0) &&
			    (strcmp(argv[2], "sync_atomic") != 0)) {
				UET_ERR("Invalid usage: bad test arg");
				return UET_ERR_RC;
			}
			if (strcmp(argv[2], "rma") == 0)
				ctx->cfg.rma = true;
			else if (strcmp(argv[2], "sync_rma") == 0)
				ctx->cfg.sync_rma = true;
			else if (strcmp(argv[2], "atomic") == 0)
				ctx->cfg.atomic = true;
			else
				ctx->cfg.sync_atomic = true;
		} else {
			ctx->cfg.tag = true;
		}
		ctx->cfg.peer_ip_addr_string = argv[3];
	} else {
		ctx->cfg.peer_ip_addr_string = argv[2];
	}

	memset(&ctx->cfg.peer_ip_addr, 0, sizeof(struct uet_fa));

	if (inet_pton(AF_INET6, ctx->cfg.peer_ip_addr_string,
		      &peer_in6_addr) == 1) {
		memcpy(ctx->cfg.peer_ip_addr.v6, &peer_in6_addr, 16);
		ctx->cfg.is_ipv6 = true;
	} else if (inet_pton(AF_INET, ctx->cfg.peer_ip_addr_string,
			     &peer_in_addr) == 1) {
		ctx->cfg.peer_ip_addr.v4 = ntohl(peer_in_addr.s_addr);
		ctx->cfg.is_ipv6 = false;
	} else {
		UET_PRINT_ERRNO("Invalid usage: bad IP address");
		return UET_ERR_RC;
	}

	addr = &ctx->cfg.peer_uet_addr;
	addr->ver = UET_ADDR_VERSION;
	addr->flags = (UET_ADDR_FEP_CAP_V     |
		       UET_ADDR_FA_V          |
		       UET_ADDR_PID_ON_FEP_V  |
		       UET_ADDR_INDEX_V       |
		       UET_ADDR_INITIATOR_V   |
		       UET_ADDR_RELATIVE_MODE |
		       (ctx->cfg.is_ipv6 ? UET_ADDR_IPV6 : UET_ADDR_IPV4) |
		       UET_ADDR_BIG_MSG_SIZE);
	addr->fep_cap = UET_FEP_CAP_AI_FULL;
	memcpy(&addr->fa, &ctx->cfg.peer_ip_addr, sizeof(struct uet_fa));
	addr->pid_on_fep = UET_ADDR_DEF_PID_ON_FEP;
	addr->num_indices = 1;
	addr->start_index = UET_ADDR_DEF_INDEX;
	addr->initiator_id = UET_ADDR_DEF_INITIATOR_ID;

	ctx->cfg.num_iterations = UET_NUM_ITERATIONS;
	if (ctx->cfg.dsend_test) {
		if (ctx->cfg.tag)
			ctx->cfg.msg_size = UET_TAG_RENDEZVOUS_SIZE * 2;
		else
			ctx->cfg.msg_size = UET_MSG_RENDEZVOUS_SIZE * 2;
	} else {
		ctx->cfg.msg_size = UET_MSG_SIZE;
	}

	return UET_SUCCESS_RC;
}

/* initialize message buffer contents */
static void uet_init_msg_buf(struct uet_context *ctx, uint8_t *buf)
{
	size_t i;

	for (i = 0; i < ctx->cfg.msg_size; i++)
		buf[i] = (uint8_t) i;
}

/* initialize IO vector`s buffer contents */
static void uet_init_iov_buf(size_t size, uint8_t *buf)
{
	size_t i;

	for (i = 0; i < size; i++)
		buf[i] = (uint8_t) i;
}


/* validate message buffer contents */
static uet_rc_t uet_validate_msg(struct uet_context *ctx, uint8_t *buf)
{
	size_t i;

	for (i = 0; i < ctx->cfg.msg_size; i++) {
		if (buf[i] != (uint8_t) i)
			return UET_ERR_RC;
	}

	return UET_SUCCESS_RC;
}

static uet_rc_t uet_validate_iov_msg(struct uet_context *ctx)
{
	size_t rx_idx = 0, tx_idx = 0;
	size_t rx_offset = 0, tx_offset = 0;
	uint8_t *rx_buf = ctx->rx_iov[rx_idx].iov_base;
	uint8_t *tx_buf = ctx->tx_iov[tx_idx].iov_base;

	while (rx_idx < ctx->rx_count && tx_idx < ctx->tx_count) {
		if (rx_buf[rx_offset] != tx_buf[tx_offset])
			return UET_ERR_RC;

		rx_offset++;
		tx_offset++;
		if (rx_offset >= ctx->rx_iov[rx_idx].iov_len) {
			rx_offset = 0;
			rx_idx++;
			rx_buf = ctx->rx_iov[rx_idx].iov_base;
		}
		if (tx_offset >= ctx->tx_iov[tx_idx].iov_len) {
			tx_offset = 0;
			tx_idx++;
			tx_buf = ctx->tx_iov[tx_idx].iov_base;
		}
	}

	/* Ensure both buffers were fully validated */
	if (rx_idx < ctx->rx_count || tx_idx < ctx->tx_count)
		return UET_ERR_RC;

	return UET_SUCCESS_RC;
}

/* initialize uet transport */
static uet_rc_t uet_init_transport(struct uet_context *ctx)
{
	int ret;
	char ip_addr_str[INET6_ADDRSTRLEN];
	void *context = NULL;
	struct fi_info *hints = NULL, *info;
	struct uet_addr *uet_addr;
	uet_rc_t rc = UET_ERR_RC;
	ssize_t remaining_size;

	/* FIXME: Hack used to configure client/server security mode */
	if (!ctx->cfg.client)
		setenv(UET_SEC_SERVER, "1", 1);

	ret = uet_initialize(&ctx->uet_handle, ctx->cfg.is_ipv6);
	if (ret) {
		UET_ERR("uet_initialize: %s", fi_strerror(-ret));
		goto exit;
	}

	hints = fi_allocinfo();
	if (hints == NULL) {
		UET_ERR("fi_allocinfo");
		goto exit;
	}

	if (ctx->cfg.tag)
		hints->caps |= FI_TAGGED;
	else if (ctx->cfg.rma || ctx->cfg.sync_rma)
		hints->caps |= (FI_MSG | FI_RMA);
	else if (ctx->cfg.atomic || ctx->cfg.sync_atomic)
		hints->caps |= (FI_ATOMIC | FI_RMA);
	else
		hints->caps |= FI_MSG;

	ret = uet_getinfo(ctx->uet_handle, NULL, hints, &ctx->info);
	if (ret) {
		UET_ERR("uet_getinfo: %s", fi_strerror(-ret));
		goto exit;
	}

	for (info = ctx->info; info; info = info->next) {
		printf("UET device name:   %s\n",
		       info->nic->device_attr->name);
		printf("  Network type:    %s\n",
		       info->nic->link_attr->network_type);
		printf("  MAC Address:     %s\n",
		       info->nic->link_attr->address);
		printf("  MTU:             %ld\n",
		       info->nic->link_attr->mtu);
		printf("  Interface state: ");
		if (info->nic->link_attr->state == FI_LINK_UP)
			printf("UP\n");
		else if (info->nic->link_attr->state == FI_LINK_DOWN)
			printf("DOWN\n");
		else
			printf("UNKNOWN\n");
		uet_addr = (struct uet_addr *) info->src_addr;
		uet_ip_addr_to_str(&uet_addr->fa,
				   uet_addr_is_ipv6(uet_addr),
				   ip_addr_str);
		printf("  IP Address:      %s\n", ip_addr_str);
	}

	if (ctx->cfg.msg_size > ctx->info->ep_attr->max_msg_size) {
		UET_ERR("Max message size too small: %lu", ctx->cfg.msg_size);
		goto exit;
	}

	if (ctx->cfg.tag) {
		if (!(ctx->info->caps & FI_TAGGED)) {
			UET_ERR("Tagged messages not supported");
			goto exit;
		}
	} else {
		if (ctx->cfg.rma || ctx->cfg.sync_rma) {
			if (!(ctx->info->caps & FI_RMA)) {
				UET_ERR("RMA operations not supported");
				goto exit;
			}
		}
		if (ctx->cfg.atomic || ctx->cfg.sync_atomic) {
			if (!(ctx->info->caps & FI_ATOMIC)) {
				UET_ERR("Atomic operations not supported");
				goto exit;
			}
		}
		if (!(ctx->info->caps & FI_MSG)) {
			UET_ERR("Message operations not supported");
			goto exit;
		}
	}


	ret = uet_domain(ctx->uet_handle, &ctx->fabric, ctx->info,
			 &ctx->domain, context, uet_eq_callback,
			 uet_eq_err_callback, &ctx->domain_handle);
	if (ret) {
		UET_ERR("uet_domain: %s", fi_strerror(-ret));
		goto exit;
	}

	if (ctx->cfg.rma || ctx->cfg.sync_rma ||
	    ctx->cfg.atomic || ctx->cfg.sync_atomic) {
		ctx->mr_buf = malloc(ctx->cfg.msg_size);
		if (ctx->mr_buf == NULL) {
			UET_PRINT_ERRNO("malloc");
			UET_ERR("Error allocating memory region buffer");
			goto exit;
		}

		if (!ctx->cfg.client)
			uet_init_msg_buf(ctx, ctx->mr_buf);

		ctx->info->domain_attr->mr_mode |= FI_MR_PROV_KEY;

		ret = uet_mr_reg(ctx->domain_handle, ctx->mr_buf,
				 ctx->cfg.msg_size,
				 FI_WRITE | FI_REMOTE_WRITE |
				 FI_READ  | FI_REMOTE_READ | FI_ATOMIC,
				 UET_MR_KEY_NONE, UET_FLAGS_NONE, context,
				 &ctx->mr_handle);
		if (ret) {
			UET_ERR("uet_mr_reg: %s", fi_strerror(-ret));
			goto exit;
		}

		ctx->local_mr.rma_buf_addr = 0;
		ctx->local_mr.key = uet_mr_key(ctx->mr_handle);
	}

	ctx->info->rx_attr->size = UET_NUM_BUFS;
	ctx->info->tx_attr->size = UET_NUM_BUFS;
	if (ctx->cfg.unexpected_msg_test)
		ctx->info->tx_attr->msg_order = FI_ORDER_NONE;
	else
		ctx->info->tx_attr->msg_order = FI_ORDER_SAS;

	ret = uet_endpoint(ctx->domain_handle, ctx->info, &ctx->ep,
			   context, &ctx->ep_handle);
	if (ret) {
		UET_ERR("uet_endpoint: %s", fi_strerror(-ret));
		goto exit;
	}

	ret = uet_getname(ctx->ep_handle, &ctx->local_uet_addr);
	if (ret) {
		UET_ERR("uet_getname: %s", fi_strerror(-ret));
		goto exit;
	}

	uet_print_uet_addr(&ctx->local_uet_addr);

	if (ctx->cfg.rma || ctx->cfg.sync_rma ||
	    ctx->cfg.atomic || ctx->cfg.sync_atomic) {
		ret = uet_ep_bind_mr(ctx->ep_handle, ctx->mr_handle,
				     UET_FLAGS_NONE);
		if (ret) {
			UET_ERR("uet_ep_bind_mr: %s", fi_strerror(-ret));
			goto exit;
		}
	}

	ret = uet_av_insert(ctx->domain_handle, &ctx->cfg.peer_uet_addr,
			    &ctx->peer_addr_handle);
	if (ret) {
		UET_ERR("uet_av_insert: %s", fi_strerror(-ret));
		goto exit;
	}

	ctx->cq_attr.format = FI_CQ_FORMAT_DATA;
	ctx->cq_attr.size = UET_NUM_BUFS * 2;
	ret = uet_ep_bind_cq(ctx->ep_handle, &ctx->cq_attr, &ctx->cq,
			     FI_SEND, context, &ctx->tx_cq_handle);
	if (ret) {
		UET_ERR("uet_cq_bind: %s", fi_strerror(-ret));
		goto exit;
	}

	ret = uet_ep_bind_cq(ctx->ep_handle, &ctx->cq_attr, &ctx->cq,
			     FI_RECV, context, &ctx->rx_cq_handle);
	if (ret) {
		UET_ERR("uet_cq_bind: %s", fi_strerror(-ret));
		goto exit;
	}

	if (ctx->cfg.rma || ctx->cfg.sync_rma ||
	    ctx->cfg.atomic || ctx->cfg.sync_atomic) {
		ret = uet_mr_enable(ctx->mr_handle);
		if (ret) {
			UET_ERR("uet_mr_enable: %s", fi_strerror(-ret));
			goto exit;
		}
	}

	ret = uet_ep_enable(ctx->ep_handle);
	if (ret) {
		UET_ERR("uet_endpoint_enable: %s", fi_strerror(-ret));
		goto exit;
	}

	ctx->tx_msg = malloc(ctx->cfg.msg_size);
	if (ctx->tx_msg == NULL) {
		UET_PRINT_ERRNO("malloc");
		UET_ERR("Error allocating message buffer");
		goto exit;
	}

	if (!ctx->cfg.rma && !ctx->cfg.sync_rma &&
            !ctx->cfg.atomic && !ctx->cfg.sync_atomic && ctx->cfg.client)
		uet_init_msg_buf(ctx, ctx->tx_msg);

	ctx->rx_msg = malloc(ctx->cfg.msg_size);
	if (ctx->rx_msg == NULL) {
		UET_PRINT_ERRNO("malloc");
		UET_ERR("Error allocating message buffer");
		goto exit;
	}

	/* Allocate IO Vectors for Transmit */
	ctx->tx_iov = calloc(UET_IOV_LIMIT_MAX, sizeof(struct iovec));
	if (ctx->tx_iov == NULL) {
		UET_PRINT_ERRNO("calloc");
		UET_ERR("Error allocating IO vector");
		goto exit;
	}
	remaining_size = ctx->cfg.msg_size;
	while (remaining_size > 0 && ctx->tx_count < UET_IOV_LIMIT_MAX) {
		size_t buffer_size = lrand48() % (remaining_size) + 1;

		/* if last IOV, allocate all remaining data in this last IOV */
		if (ctx->tx_count == UET_IOV_LIMIT_MAX - 1)
			buffer_size = remaining_size;

		remaining_size -= buffer_size;

		ctx->tx_iov[ctx->tx_count].iov_base =
			calloc(buffer_size, sizeof(char));

		if (ctx->tx_iov[ctx->tx_count].iov_base == NULL) {
			UET_PRINT_ERRNO("calloc");
			UET_ERR("Error allocating IO vector");
			goto exit;
		}

		ctx->tx_iov[ctx->tx_count].iov_len = buffer_size;


		if (!ctx->cfg.rma && !ctx->cfg.sync_rma &&
		    !ctx->cfg.atomic && !ctx->cfg.sync_atomic &&
		    ctx->cfg.client) {
			uet_init_iov_buf(
				buffer_size,
				ctx->tx_iov[ctx->tx_count].iov_base);
		}

		ctx->tx_count++;
	}

	/* Allocate IO Vectors for Receive */
	ctx->rx_iov = calloc(UET_IOV_LIMIT_MAX, sizeof(struct iovec));
	if (ctx->rx_iov == NULL) {
		UET_PRINT_ERRNO("calloc");
		UET_ERR("Error allocating IO vector");
		goto exit;
	}
	remaining_size = ctx->cfg.msg_size;
	while (remaining_size > 0 && ctx->rx_count < UET_IOV_LIMIT_MAX) {
		size_t buffer_size = lrand48() % (remaining_size) + 1;
		/* if last IOV, allocate all remaining data in this last IOV */
		if (ctx->rx_count == UET_IOV_LIMIT_MAX - 1)
			buffer_size = remaining_size;

		remaining_size -= buffer_size;

		ctx->rx_iov[ctx->rx_count].iov_base =
			calloc(buffer_size, sizeof(char));

		if (ctx->rx_iov[ctx->rx_count].iov_base == NULL) {
			UET_PRINT_ERRNO("calloc");
			UET_ERR("Error allocating IO vector");
			goto exit;
		}

		ctx->rx_iov[ctx->rx_count].iov_len = buffer_size;

		ctx->rx_count++;
	}

	rc = UET_SUCCESS_RC;

exit:
	if (hints)
		fi_freeinfo(hints);

	return rc;
}

/* wait for completion */
static uet_rc_t uet_compl_wait(uet_cq_handle_t cq_handle,
			       struct fi_cq_data_entry *cq_entry)
{
	ssize_t rc;
	struct fi_cq_err_entry err_entry;

	while (1) {
		rc = uet_cq_read(cq_handle, cq_entry, 1);
		if (rc < 0) {
			UET_ERR("uet_cq_read: %s", fi_strerror(-rc));
			if (rc == -FI_EAVAIL) {
				rc = uet_cq_readerr(cq_handle, &err_entry);
				if (rc < 0)
					UET_ERR("uet_cq_readerr: %s",
						fi_strerror(-rc));
				else if (rc == 0)
					UET_ERR("uet_cq_readerr: did "
						"not return entry");
				else
					UET_ERR("cq read err: %s",
						fi_strerror(
						       err_entry.err));
			}
			return UET_ERR_RC;
		} else if (rc == 1)
			break;
	}

	return UET_SUCCESS_RC;
}

/*
 * perform client rma control message exchange as follows:
 *   - post rx buffer
 *   - send control message to server containing address and key for client's
 *     RMA buffer
 *   - wait for tx completion
 *   - wait for rx completion to receive message back from server containing
 *     address and key for server's RMA buffer
 *
 * returns:
 *   UET_SUCCESS_RC
 *   UET_ERROR_RC
 */
static uet_rc_t uet_rma_client_ctrl_exchange(struct uet_context *ctx)
{
	int ret;
	void *context = NULL;
	struct uet_ctrl_msg *ctrl_msg;
	struct fi_cq_data_entry cq_entry;

	ret = uet_recv(ctx->ep_handle, UET_JOB_ID_ANY, ctx->rx_msg,
		       ctx->cfg.msg_size, UET_NULL_HANDLE,
		       UET_NULL_HANDLE, context);
	if (ret != FI_SUCCESS) {
		UET_ERR("uet_recv: %s", fi_strerror(-ret));
		return UET_ERR_RC;
	}

	ctrl_msg = (struct uet_ctrl_msg *) ctx->tx_msg;
	*ctrl_msg = ctx->local_mr;

	ret = uet_send(ctx->ep_handle, ctx->cfg.job_id,
		       ctrl_msg, sizeof(struct uet_ctrl_msg),
		       UET_NULL_HANDLE, ctx->peer_addr_handle,
		       context);
	if (ret < 0) {
		UET_ERR("uet_send: %s", fi_strerror(-ret));
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->rx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	ctrl_msg = (struct uet_ctrl_msg *) ctx->rx_msg;
	ctx->remote_mr = *ctrl_msg;

	return UET_SUCCESS_RC;
}

/*
 * perform server rma control message exchange as follows:
 *   - post rx buffer
 *   - wait for rx completion to receive message from client containing
 *     address and key for client's RMA buffer
 *   - send message back to client containing address and key for server's
 *     RMA buffer
 *   - wait for tx completion
 *
 * returns:
 *   UET_SUCCESS_RC
 *   UET_ERROR_RC
 */
static uet_rc_t uet_rma_server_ctrl_exchange(struct uet_context *ctx)
{
	int ret;
	void *context = NULL;
	struct uet_ctrl_msg *ctrl_msg;
	struct fi_cq_data_entry cq_entry;

	ret = uet_recv(ctx->ep_handle, UET_JOB_ID_ANY, ctx->rx_msg,
		       ctx->cfg.msg_size, UET_NULL_HANDLE,
		       UET_NULL_HANDLE, context);
	if (ret != FI_SUCCESS) {
		UET_ERR("uet_recv: %s", fi_strerror(-ret));
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->rx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	ctrl_msg = (struct uet_ctrl_msg *) ctx->rx_msg;
	ctx->remote_mr = *ctrl_msg;

	ctrl_msg = (struct uet_ctrl_msg *) ctx->tx_msg;
	*ctrl_msg = ctx->local_mr;
	ret = uet_send(ctx->ep_handle, ctx->cfg.job_id,
		       ctrl_msg, sizeof(struct uet_ctrl_msg),
		       UET_NULL_HANDLE, ctx->peer_addr_handle,
		       context);
	if (ret < 0) {
		UET_ERR("uet_send: %s", fi_strerror(-ret));
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	return UET_SUCCESS_RC;
}

/*
 * perform client RMA data transfer exchange as follows:
 *   - read data from server RMA buffer
 *   - wait for read completion
 *   - write to server RMA buffer
 *     - include immediate data to generate completion at server
 *   - wait for write completion
 *   - wait for remote write completion to indicate data has been written
 *     back to client's RMA buffer by server
 *   - validate data is correct
 *
 * returns:
 *   UET_SUCCESS_RC
 *   UET_ERROR_RC
 */
static uet_rc_t uet_rma_client(struct uet_context *ctx)
{
	ssize_t ret;
	void *context = NULL;
	uint64_t imm_data = UET_WRITE_IMM_DATA;
	struct fi_cq_data_entry cq_entry;

	ret = uet_read(ctx->ep_handle, ctx->cfg.job_id, ctx->mr_buf,
			ctx->cfg.msg_size, ctx->mr_handle,
			ctx->peer_addr_handle, ctx->remote_mr.rma_buf_addr,
			ctx->remote_mr.key, context);
	if (ret < 0) {
		UET_ERR("uet_read: %s", fi_strerror(-ret));
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	ret = uet_write(ctx->ep_handle, ctx->cfg.job_id, ctx->mr_buf,
			ctx->cfg.msg_size, &imm_data, ctx->mr_handle,
			ctx->peer_addr_handle, ctx->remote_mr.rma_buf_addr,
			ctx->remote_mr.key, context);
	if (ret < 0) {
		UET_ERR("uet_write: %s", fi_strerror(-ret));
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->rx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	if (uet_validate_msg(ctx, ctx->mr_buf) != UET_SUCCESS_RC) {
		UET_ERR("Invalid buffer contents");
		return UET_ERR_RC;
	}

	return UET_SUCCESS_RC;
}

/*
 * perform server RMA data transfer exchange as follows:
 *   - wait for remote write completion to indicate data has been written to
 *     the server RMA buffer by the client
 *   - validate data is correct
 *   - write data back to client RMA buffer
 *     - include immediate data to generate completion at client
 *   - wait for write completion
 *
 * returns:
 *   UET_SUCCESS_RC
 *   UET_ERROR_RC
 */
static uet_rc_t uet_rma_server(struct uet_context *ctx)
{
	ssize_t ret;
	void *context = NULL;
	uint64_t imm_data = UET_WRITE_IMM_DATA;
	struct fi_cq_data_entry cq_entry;

	if (uet_compl_wait(ctx->rx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	if (uet_validate_msg(ctx, ctx->mr_buf) != UET_SUCCESS_RC) {
		UET_ERR("Invalid buffer contents");
		return UET_ERR_RC;
	}

	ret = uet_write(ctx->ep_handle, ctx->cfg.job_id, ctx->mr_buf,
			ctx->cfg.msg_size, &imm_data, ctx->mr_handle,
			ctx->peer_addr_handle, ctx->remote_mr.rma_buf_addr,
			ctx->remote_mr.key, context);
	if (ret < 0) {
		UET_ERR("uet_write: %s", fi_strerror(-ret));
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	return UET_SUCCESS_RC;
}

/*
 * perform client sync group RMA data transfer exchange as follows:
 *   - read data from server RMA buffer
 *   - wait for read completion
 *   - write to server RMA buffer
 *     - write is series of sync write operations followed by sync write
 *       with immediate data to generate completion at server
 *   - wait for write completion
 *   - wait for remote write completion to indicate data has been written
 *     back to client's RMA buffer by server
 *   - validate data is correct
 *
 * returns:
 *   UET_SUCCESS_RC
 *   UET_ERROR_RC
 */
static uet_rc_t uet_sync_rma_client(struct uet_context *ctx)
{
	ssize_t ret;
	void *context = NULL;
	uint64_t imm_data = UET_WRITE_IMM_DATA;
	size_t msg1_sz, msg2_sz, msg3_sz;
	struct fi_cq_data_entry cq_entry;

	ret = uet_read(ctx->ep_handle, ctx->cfg.job_id, ctx->mr_buf,
			ctx->cfg.msg_size, ctx->mr_handle,
			ctx->peer_addr_handle, ctx->remote_mr.rma_buf_addr,
			ctx->remote_mr.key, context);
	if (ret < 0) {
		UET_ERR("uet_read: %s", fi_strerror(-ret));
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	msg1_sz = ctx->cfg.msg_size / 3;
	msg2_sz = msg1_sz;
	msg3_sz = (ctx->cfg.msg_size - msg1_sz) - msg2_sz;

	ret = uet_write_sync(ctx->ep_handle, ctx->cfg.job_id, ctx->mr_buf,
			     msg1_sz, NULL, ctx->mr_handle,
			     ctx->peer_addr_handle, ctx->remote_mr.rma_buf_addr,
			     ctx->remote_mr.key, context);
	if (ret < 0) {
		UET_ERR("uet_write sync: %s", fi_strerror(-ret));
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	ret = uet_write_sync(ctx->ep_handle, ctx->cfg.job_id,
			     ctx->mr_buf + msg1_sz,
			     msg2_sz, NULL, ctx->mr_handle,
			     ctx->peer_addr_handle,
			     ctx->remote_mr.rma_buf_addr + msg1_sz,
			     ctx->remote_mr.key, context);
	if (ret < 0) {
		UET_ERR("uet_write_sync: %s", fi_strerror(-ret));
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	ret = uet_write_sync(ctx->ep_handle, ctx->cfg.job_id,
			     ctx->mr_buf + msg1_sz + msg2_sz,
			     msg3_sz, &imm_data, ctx->mr_handle,
			     ctx->peer_addr_handle,
			     ctx->remote_mr.rma_buf_addr + msg1_sz + msg2_sz,
			     ctx->remote_mr.key, context);
	if (ret < 0) {
		UET_ERR("uet_write_sync: %s", fi_strerror(-ret));
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->rx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	if (uet_validate_msg(ctx, ctx->mr_buf) != UET_SUCCESS_RC) {
		UET_ERR("Invalid buffer contents");
		return UET_ERR_RC;
	}

	return UET_SUCCESS_RC;
}

/*
 * perform server sync RMA data transfer exchange
 */
static uet_rc_t uet_sync_rma_server(struct uet_context *ctx)
{
	return uet_rma_server(ctx);
}

#define ATOMIC_SUM_VALUE	2

/*
 * perform client atomic data transfer exchange as follows:
 *   - query support for atomic operation that is expected to be unsupported
 *   - query support for atomic operations that are expected to be supported
 *   - do atomic fetch add of 0 to get current value from server RMA buffer
 *   - wait for atomic fetch completion
 *   - do atomic non-fetch add of known constant to server RMA buffer
 *   - wait for atomic completion
 *   - validate result
 *   - do atomic fetch add of known constant to server RMA buffer
 *   - wait for atomic fetch completion
 *   - validate result
 *   - do atomic fetch add of known constant to server RMA buffer
 *   - validate result
 *   - do atomic cswap using value that is expected to fail compare
 *   - wait for atomic cswap completion
 *   - validate result
 *   - do atomic cswap using value that is expected to swap
 *   - wait for atomic cswap completion
 *   - validate result
 *   - write to server RMA buffer
 *     - include immediate data to generate completion at server
 *   - wait for write completion
 *
 * returns:
 *   UET_SUCCESS_RC
 *   UET_ERROR_RC
 */
static uet_rc_t uet_atomic_client(struct uet_context *ctx)
{
	int query_ret;
	ssize_t ret;
	struct fi_atomic_attr attr;
	uint64_t *local_op_buf, *result_buf, *compare_buf, val;
	void *context = NULL;
	uint64_t imm_data = UET_WRITE_IMM_DATA;
	struct fi_cq_data_entry cq_entry;

	query_ret = uet_query_atomic(ctx->domain_handle, FI_UINT32, FI_SUM,
				     &attr, FI_FETCH_ATOMIC);
	if (query_ret != -FI_EOPNOTSUPP) {
		UET_ERR("uet_query_atomic: %s", fi_strerror(-query_ret));
		return UET_ERR_RC;
	}

	query_ret = uet_query_atomic(ctx->domain_handle, FI_UINT64, FI_SUM,
				     &attr, FI_ATOMIC);
	if (query_ret < 0) {
		UET_ERR("uet_query_atomic: %s", fi_strerror(-query_ret));
		return UET_ERR_RC;
	}

	if ((attr.count != 1) || (attr.size != sizeof(uint64_t))) {
		UET_ERR("uet_query_atomic: bad attr");
		return UET_ERR_RC;
	}

	query_ret = uet_query_atomic(ctx->domain_handle, FI_UINT64, FI_SUM,
				     &attr, FI_FETCH_ATOMIC);
	if (query_ret < 0) {
		UET_ERR("uet_query_atomic: %s", fi_strerror(-query_ret));
		return UET_ERR_RC;
	}

	if ((attr.count != 1) || (attr.size != sizeof(uint64_t))) {
		UET_ERR("uet_query_atomic: bad attr");
		return UET_ERR_RC;
	}

	query_ret = uet_query_atomic(ctx->domain_handle, FI_UINT64, FI_CSWAP,
				     &attr, FI_COMPARE_ATOMIC);
	if (query_ret != FI_SUCCESS) {
		UET_ERR("uet_query_atomic: %s", fi_strerror(-query_ret));
		return UET_ERR_RC;
	}

	if ((attr.count != 1) || (attr.size != sizeof(uint64_t))) {
		UET_ERR("uet_query_atomic: bad attr");
		return UET_ERR_RC;
	}

	if (ctx->cfg.msg_size < UET_MIN_ATOMIC_MSG_SIZE) {
		UET_ERR("atomic test requires min msg size of %d",
	                UET_MIN_ATOMIC_MSG_SIZE);
		return UET_ERR_RC;
	}

	local_op_buf = (uint64_t *) ctx->mr_buf;
	result_buf = local_op_buf + 1;
	compare_buf = result_buf + 1;

	*local_op_buf = 0;

	ret = uet_fetch_atomic(ctx->ep_handle, ctx->cfg.job_id, local_op_buf,
			       attr.count, ctx->mr_handle, result_buf,
			       ctx->mr_handle, ctx->peer_addr_handle,
			       ctx->remote_mr.rma_buf_addr, ctx->remote_mr.key,
			       FI_UINT64, FI_SUM, context);
	if (ret < 0) {
		UET_ERR("uet_fetch_atomic: %s", fi_strerror(-ret));
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	val = *result_buf;

	*local_op_buf = (uint64_t) ATOMIC_SUM_VALUE;

	ret = uet_atomic(ctx->ep_handle, ctx->cfg.job_id, local_op_buf,
		         attr.count, ctx->mr_handle, ctx->peer_addr_handle,
			 ctx->remote_mr.rma_buf_addr, ctx->remote_mr.key,
			 FI_UINT64, FI_SUM, context);
	if (ret < 0) {
		UET_ERR("uet_atomic: %s", fi_strerror(-ret));
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	val += *local_op_buf;

	ret = uet_fetch_atomic(ctx->ep_handle, ctx->cfg.job_id, local_op_buf,
			       attr.count, ctx->mr_handle, result_buf,
			       ctx->mr_handle, ctx->peer_addr_handle,
			       ctx->remote_mr.rma_buf_addr, ctx->remote_mr.key,
			       FI_UINT64, FI_SUM, context);
	if (ret < 0) {
		UET_ERR("uet_fetch_atomic: %s", fi_strerror(-ret));
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	if (*result_buf != val) {
		UET_ERR("uet_fetch_atomic: bad result %lu", *result_buf);
		return UET_ERR_RC;
	}

	ret = uet_fetch_atomic(ctx->ep_handle, ctx->cfg.job_id, local_op_buf,
			       attr.count, ctx->mr_handle, result_buf,
			       ctx->mr_handle, ctx->peer_addr_handle,
			       ctx->remote_mr.rma_buf_addr, ctx->remote_mr.key,
			       FI_UINT64, FI_SUM, context);
	if (ret < 0) {
		UET_ERR("uet_fetch_atomic: %s", fi_strerror(-ret));
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	val += *local_op_buf;

	if (*result_buf != val) {
		UET_ERR("uet_fetch_atomic: bad result %lu", *result_buf);
		return UET_ERR_RC;
	}

	val += *local_op_buf;
	*local_op_buf = val + 1;
	*compare_buf = val - 1;

	ret = uet_compare_atomic(ctx->ep_handle, ctx->cfg.job_id, local_op_buf,
				 attr.count, ctx->mr_handle, compare_buf,
				 ctx->mr_handle, result_buf, ctx->mr_handle,
				 ctx->peer_addr_handle,
				 ctx->remote_mr.rma_buf_addr,
				 ctx->remote_mr.key,
				 FI_UINT64, FI_CSWAP, context);
	if (ret < 0) {
		UET_ERR("uet_compare_atomic: %s", fi_strerror(-ret));
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	if (*result_buf != val) {
		UET_ERR("uet_compare_atomic: bad result %lu", *result_buf);
		return UET_ERR_RC;
	}

	*compare_buf = val;

	ret = uet_compare_atomic(ctx->ep_handle, ctx->cfg.job_id, local_op_buf,
				 attr.count, ctx->mr_handle, compare_buf,
				 ctx->mr_handle, result_buf, ctx->mr_handle,
				 ctx->peer_addr_handle,
				 ctx->remote_mr.rma_buf_addr,
				 ctx->remote_mr.key,
				 FI_UINT64, FI_CSWAP, context);
	if (ret < 0) {
		UET_ERR("uet_compare_atomic: %s", fi_strerror(-ret));
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	if (*result_buf != *local_op_buf) {
		UET_ERR("uet_compare_atomic: bad result %lu", *result_buf);
		return UET_ERR_RC;
	}

	ret = uet_write(ctx->ep_handle, ctx->cfg.job_id, ctx->mr_buf,
			ctx->cfg.msg_size, &imm_data, ctx->mr_handle,
			ctx->peer_addr_handle, ctx->remote_mr.rma_buf_addr,
			ctx->remote_mr.key, context);
	if (ret < 0) {
		UET_ERR("uet_write: %s", fi_strerror(-ret));
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	return UET_SUCCESS_RC;
}

/*
 * perform server atomic data transfer exchange as follows:
 *   - wait for remote write completion to indicate client has completed atomic
 *     operation tests
 *
 * returns:
 *   UET_SUCCESS_RC
 *   UET_ERROR_RC
 */
static uet_rc_t uet_atomic_server(struct uet_context *ctx)
{
	struct fi_cq_data_entry cq_entry;

	if (uet_compl_wait(ctx->rx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	return UET_SUCCESS_RC;
}

/*
 * perform client sync atomic data transfer exchange as follows:
 *   - query support for atomic operation that is expected to be unsupported
 *   - query support for atomic operations that are expected to be supported
 *   - do sync write of known constant to server RMA buffer
 *   - wait for write completion
 *   - do sync atomic add of known constant to server RMA buffer
 *   - wait for sync atomic completion
 *   - do atomic fetch add of 0 to server RMA buffer
 *   - wait for atomic fetch completion
 *   - validate result
 *   - do 0-byte write to server RMA buffer
 *     - include immediate data to generate completion at server
 *   - wait for write completion
 *
 * returns:
 *   UET_SUCCESS_RC
 *   UET_ERROR_RC
 */
static uet_rc_t uet_sync_atomic_client(struct uet_context *ctx)
{
	int query_ret;
	ssize_t ret;
	struct fi_atomic_attr attr;
	uint64_t *local_op_buf, *result_buf, val;
	void *context = NULL;
	uint64_t imm_data = UET_WRITE_IMM_DATA;
	struct fi_cq_data_entry cq_entry;

	query_ret = uet_query_atomic(ctx->domain_handle, FI_UINT32, FI_SUM,
				     &attr, FI_FETCH_ATOMIC);
	if (query_ret != -FI_EOPNOTSUPP) {
		UET_ERR("uet_query_atomic: %s", fi_strerror(-query_ret));
		return UET_ERR_RC;
	}

	query_ret = uet_query_atomic(ctx->domain_handle, FI_UINT64, FI_SUM,
				     &attr, FI_ATOMIC);
	if (query_ret < 0) {
		UET_ERR("uet_query_atomic: %s", fi_strerror(-query_ret));
		return UET_ERR_RC;
	}

	if ((attr.count != 1) || (attr.size != sizeof(uint64_t))) {
		UET_ERR("uet_query_atomic: bad attr");
		return UET_ERR_RC;
	}

	query_ret = uet_query_atomic(ctx->domain_handle, FI_UINT64, FI_SUM,
				     &attr, FI_FETCH_ATOMIC);
	if (query_ret < 0) {
		UET_ERR("uet_query_atomic: %s", fi_strerror(-query_ret));
		return UET_ERR_RC;
	}

	if ((attr.count != 1) || (attr.size != sizeof(uint64_t))) {
		UET_ERR("uet_query_atomic: bad attr");
		return UET_ERR_RC;
	}

	query_ret = uet_query_atomic(ctx->domain_handle, FI_UINT64, FI_CSWAP,
				     &attr, FI_COMPARE_ATOMIC);
	if (query_ret != FI_SUCCESS) {
		UET_ERR("uet_query_atomic: %s", fi_strerror(-query_ret));
		return UET_ERR_RC;
	}

	if ((attr.count != 1) || (attr.size != sizeof(uint64_t))) {
		UET_ERR("uet_query_atomic: bad attr");
		return UET_ERR_RC;
	}

	if (ctx->cfg.msg_size < UET_MIN_ATOMIC_MSG_SIZE) {
		UET_ERR("atomic test requires min msg size of %d",
	                UET_MIN_ATOMIC_MSG_SIZE);
		return UET_ERR_RC;
	}

	local_op_buf = (uint64_t *) ctx->mr_buf;
	*local_op_buf = (uint64_t) ATOMIC_SUM_VALUE;
	val = *local_op_buf;

	ret = uet_write_sync(ctx->ep_handle, ctx->cfg.job_id, local_op_buf,
			     sizeof(uint64_t), NULL, ctx->mr_handle,
			     ctx->peer_addr_handle, ctx->remote_mr.rma_buf_addr,
			     ctx->remote_mr.key, context);
	if (ret < 0) {
		UET_ERR("uet_write_sync: %s", fi_strerror(-ret));
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	ret = uet_atomic_sync(ctx->ep_handle, ctx->cfg.job_id, local_op_buf,
		              attr.count, ctx->mr_handle, ctx->peer_addr_handle,
			      ctx->remote_mr.rma_buf_addr, ctx->remote_mr.key,
			      FI_UINT64, FI_SUM, context);
	if (ret < 0) {
		UET_ERR("uet_atomic_sync: %s", fi_strerror(-ret));
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	val += *local_op_buf;
	*local_op_buf = 0;
	result_buf = local_op_buf + 1;

	ret = uet_fetch_atomic(ctx->ep_handle, ctx->cfg.job_id, local_op_buf,
			       attr.count, ctx->mr_handle, result_buf,
			       ctx->mr_handle, ctx->peer_addr_handle,
			       ctx->remote_mr.rma_buf_addr, ctx->remote_mr.key,
			       FI_UINT64, FI_SUM, context);
	if (ret < 0) {
		UET_ERR("uet_fetch_atomic: %s", fi_strerror(-ret));
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	if (*result_buf != val) {
		UET_ERR("uet_fetch_atomic: bad result %lu", *result_buf);
		return UET_ERR_RC;
	}

	ret = uet_write_sync(ctx->ep_handle, ctx->cfg.job_id, ctx->mr_buf,
			     0, &imm_data, ctx->mr_handle,
			     ctx->peer_addr_handle, ctx->remote_mr.rma_buf_addr,
			     ctx->remote_mr.key, context);
	if (ret < 0) {
		UET_ERR("uet_write_sync: %s", fi_strerror(-ret));
		return UET_ERR_RC;
	}

	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	return UET_SUCCESS_RC;
}

/*
 * perform server sync atomic data transfer exchange as follows:
 *   - wait for remote write completion to client has completed atomic
 *     operation tests
 *
 * returns:
 *   UET_SUCCESS_RC
 *   UET_ERROR_RC
 */
static uet_rc_t uet_sync_atomic_server(struct uet_context *ctx)
{
	struct fi_cq_data_entry cq_entry;

	if (uet_compl_wait(ctx->rx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	return UET_SUCCESS_RC;
}

/*
 * perform client message data transfer for unexpected message test
 *   - send message to server
 *   - wait for message to be echoed back
 */
static uet_rc_t uet_msg_client_unexpected(struct uet_context *ctx)
{
	ssize_t ret;
	time_t start, now, delta;
	struct fi_cq_data_entry cq_entry;
	uet_addr_handle_t addr_handle;
	int prev_descr_count, attempt_count;
	struct dlist_entry *active_list;
	struct dlist_entry *dummy_item;
	int descr_count;

	if (ctx->cfg.iov_test) {
		if (ctx->cfg.tag) {
			if (ctx->cfg.tag_any_src)
				addr_handle = UET_NULL_HANDLE;
			else
				addr_handle = ctx->peer_addr_handle;

			if (!first) {
				/* post tagged rx buffer */
				ret = uet_trecvv(ctx->ep_handle, UET_JOB_ID_ANY,
						ctx->rx_iov, ctx->rx_count,
						UET_NULL_HANDLE, addr_handle,
						UET_DEFAULT_TAG, UET_EXACT_MATCH, NULL);
				if (ret < 0) {
					UET_ERR("uet_trecvv: %s", fi_strerror(-ret));
					return UET_ERR_RC;
				}
			}
			ret = uet_tsendv(ctx->ep_handle, ctx->cfg.job_id,
					ctx->tx_iov, ctx->tx_count,
					UET_NULL_HANDLE, ctx->peer_addr_handle,
					UET_DEFAULT_TAG, NULL);
			if (ret < 0) {
				UET_ERR("uet_tsendv: %s", fi_strerror(-ret));
				return UET_ERR_RC;
			}
		} else {
			if (!first) {
				/* post rx buffer */
				ret = uet_recvv(ctx->ep_handle, UET_JOB_ID_ANY,
						ctx->rx_iov, ctx->rx_count,
						UET_NULL_HANDLE, UET_NULL_HANDLE, NULL);
				if (ret < 0) {
					UET_ERR("uet_recvv: %s", fi_strerror(-ret));
					return UET_ERR_RC;
				}
			}
			ret = uet_sendv(ctx->ep_handle, ctx->cfg.job_id,
					ctx->tx_iov, ctx->tx_count,
					UET_NULL_HANDLE, ctx->peer_addr_handle,
					NULL);
			if (ret < 0) {
				UET_ERR("uet_sendv: %s", fi_strerror(-ret));
				return UET_ERR_RC;
			}
		}
	} else {
		if (ctx->cfg.tag) {
			if (ctx->cfg.tag_any_src)
				addr_handle = UET_NULL_HANDLE;
			else
				addr_handle = ctx->peer_addr_handle;
			if (!first) {
				ret = uet_trecv(ctx->ep_handle, UET_JOB_ID_ANY,
						ctx->rx_msg, ctx->cfg.msg_size,
						UET_NULL_HANDLE, addr_handle,
						UET_DEFAULT_TAG, UET_EXACT_MATCH, NULL);
				if (ret < 0) {
					UET_ERR("uet_trecv: %s", fi_strerror(-ret));
					return UET_ERR_RC;
				}
			}
			ret = uet_tsend(ctx->ep_handle, ctx->cfg.job_id,
						ctx->tx_msg, ctx->cfg.msg_size,
						UET_NULL_HANDLE, ctx->peer_addr_handle,
						UET_DEFAULT_TAG, NULL);
			if (ret < 0) {
				UET_ERR("uet_send: %s", fi_strerror(-ret));
				return UET_ERR_RC;
			}
		} else {
			if (!first) {
				ret = uet_recv(ctx->ep_handle, UET_JOB_ID_ANY,
							ctx->rx_msg, ctx->cfg.msg_size,
							UET_NULL_HANDLE, UET_NULL_HANDLE, NULL);
				if (ret < 0) {
					UET_ERR("uet_recv: %s", fi_strerror(-ret));
					return UET_ERR_RC;
				}
			}
			ret = uet_send(ctx->ep_handle, ctx->cfg.job_id,
						ctx->tx_msg, ctx->cfg.msg_size,
						UET_NULL_HANDLE, ctx->peer_addr_handle,
						NULL);
				if (ret < 0) {
					UET_ERR("uet_send: %s", fi_strerror(-ret));
					return UET_ERR_RC;
				}
		}
	}

	/* wait for tx completion */
	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	if (first) {

		/*
		 * NOTE: Previous behavior and error (bug) description:
		 *
		 * After the client completes TX, the server echoes the message
		 * back. The packet is unexpected at the client since we did not
		 * call uet_recv.
		 * Now, we call uet_cq_read periodically to mimic the client
		 * waiting for the TX packet completion.
		 *
		 * After the first packet of the echoed message arrives, the
		 * client parses it, checks that since there is no matching read
		 * descriptor in the ring buffer, client sends a NO_MATCH
		 * notification to the server, but creates an active RX
		 * descriptor for the first packet.
		 *
		 * The server receives the client's notification and sends a
		 * MSG_ERROR back to ask the client to terminate the message.
		 *
		 * Then, the client removes the active descriptor and notifies
		 * the server.
		 * The server tries to retransmit the message, and the whole
		 * cycle repeats.
		 *
		 * The client side waits for up to 3ms in this cycle and then
		 * calls uet_recv, putting the appropriate read descriptor in
		 * the ring buffer, so the message is not unexpected anymore
		 * and gets properly received.
		 *
		 * The server tries to retransmit up to 10 times, then gives up.
		 * This breaks the test logic on fast computers if the cycle
		 * happens more than 10 times within 3ms.
		 *
		 * NOTE: FIX description
		 * To avoid test failure, we now count MSG_ERROR arrivals by
		 * counting the number of active RX descriptors and detecting
		 * the removal of an active descriptor. After the fifth
		 * MSG_ERROR arrival, we break the loop even if 3ms have not
		 * passed yet.
		 */

		uet_gettime(&start);
#define UNEXPECTED_MSG_TEST_DELAY 3 /* msecs */
		prev_descr_count = 0;
		attempt_count = 0;
		for (now = start, delta = 0;
		     delta < UNEXPECTED_MSG_TEST_DELAY;
		     delta = now - start) {
			uet_cq_read(ctx->tx_cq_handle, &cq_entry, 1);

			active_list = &(((struct uet_ep *)(ctx->ep_handle))->
						rx_desc_active_list_head);

			/* count active RX descriptors			*/
			descr_count = 0;
			dlist_foreach(active_list, dummy_item)
				descr_count++;

			/* is descriptor removed from the active list? */
			if (descr_count < prev_descr_count)
				attempt_count++; /* a MSG_ERROR arrived */

			prev_descr_count = descr_count;

			if (attempt_count >= 5)
				break;

			uet_gettime(&now);
		}
		first = false;

		if (ctx->cfg.iov_test) {
			if (ctx->cfg.tag) {
				/* post tagged rx buffer */
				ret = uet_trecvv(ctx->ep_handle, UET_JOB_ID_ANY,
						ctx->rx_iov, ctx->rx_count,
						UET_NULL_HANDLE, addr_handle,
						UET_DEFAULT_TAG, UET_EXACT_MATCH, NULL);
				if (ret < 0) {
					UET_ERR("uet_trecvv: %s", fi_strerror(-ret));
					return UET_ERR_RC;
				}
			} else {
				/* post rx buffer */
				ret = uet_recvv(ctx->ep_handle, UET_JOB_ID_ANY,
						ctx->rx_iov, ctx->rx_count,
						UET_NULL_HANDLE, UET_NULL_HANDLE, NULL);
				if (ret < 0) {
					UET_ERR("uet_recvv: %s", fi_strerror(-ret));
					return UET_ERR_RC;
				}
			}
		} else {
			if (ctx->cfg.tag) {
				/* post tagged rx buffer */
				ret = uet_trecv(ctx->ep_handle, UET_JOB_ID_ANY,
						ctx->rx_msg, ctx->cfg.msg_size,
						UET_NULL_HANDLE, addr_handle,
						UET_DEFAULT_TAG, UET_EXACT_MATCH, NULL);
				if (ret < 0) {
					UET_ERR("uet_trecv: %s", fi_strerror(-ret));
					return UET_ERR_RC;
				}
			} else {
				ret = uet_recv(ctx->ep_handle, UET_JOB_ID_ANY,
				       ctx->rx_msg, ctx->cfg.msg_size,
				       UET_NULL_HANDLE, UET_NULL_HANDLE, NULL);
				if (ret < 0) {
					UET_ERR("uet_recv: %s", fi_strerror(-ret));
					return UET_ERR_RC;
				}
			}
		}
	}

	/* wait for rx completion */
	if (uet_compl_wait(ctx->rx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	/* Message validation for IOV*/
	if (ctx->cfg.iov_test) {
		if (uet_validate_iov_msg(ctx) != UET_SUCCESS_RC) {
			UET_ERR("Invalid iov data in RX-iov");
			return UET_ERR_RC;
		}
	}

	if (cq_entry.len != ctx->cfg.msg_size) {
		UET_ERR("Received bad message size = %lu", cq_entry.len);
		return UET_ERR_RC;
	}

	return UET_SUCCESS_RC;
}

/*
 * perform client message data transfer as follows:
 *   - send message to server
 *   - wait for message to be echoed back
 */
static uet_rc_t uet_msg_client(struct uet_context *ctx)
{
	ssize_t ret;
	struct fi_cq_data_entry cq_entry;
	uet_addr_handle_t addr_handle;

	if (ctx->cfg.iov_test) {
		if (ctx->cfg.tag) {
			if (ctx->cfg.tag_any_src)
				addr_handle = UET_NULL_HANDLE;
			else
				addr_handle = ctx->peer_addr_handle;

			/* post tagged rx buffer */
			ret = uet_trecvv(ctx->ep_handle, UET_JOB_ID_ANY,
					ctx->rx_iov, ctx->rx_count,
					UET_NULL_HANDLE, addr_handle,
					UET_DEFAULT_TAG, UET_EXACT_MATCH, NULL);
			if (ret < 0) {
				UET_ERR("uet_trecvv: %s", fi_strerror(-ret));
				return UET_ERR_RC;
			}

			/* transmit tagged message to server */
			ret = uet_tsendv(ctx->ep_handle, ctx->cfg.job_id,
					ctx->tx_iov, ctx->tx_count,
					UET_NULL_HANDLE, ctx->peer_addr_handle,
					UET_DEFAULT_TAG, NULL);
			if (ret < 0) {
				UET_ERR("uet_tsendv: %s", fi_strerror(-ret));
				return UET_ERR_RC;
			}
		} else {
			/* post rx buffer */
			ret = uet_recvv(ctx->ep_handle, UET_JOB_ID_ANY,
					ctx->rx_iov, ctx->rx_count,
					UET_NULL_HANDLE, UET_NULL_HANDLE, NULL);
			if (ret < 0) {
				UET_ERR("uet_recvv: %s", fi_strerror(-ret));
				return UET_ERR_RC;
			}

			/* transmit message to server */
			ret = uet_sendv(ctx->ep_handle, ctx->cfg.job_id,
					ctx->tx_iov, ctx->tx_count,
					UET_NULL_HANDLE, ctx->peer_addr_handle,
					NULL);
			if (ret < 0) {
				UET_ERR("uet_sendv: %s", fi_strerror(-ret));
				return UET_ERR_RC;
			}
		}
	} else {
		if (ctx->cfg.tag) {
			if (ctx->cfg.tag_any_src)
				addr_handle = UET_NULL_HANDLE;
			else
				addr_handle = ctx->peer_addr_handle;

			/* post tagged rx buffer */
			ret = uet_trecv(ctx->ep_handle, UET_JOB_ID_ANY, ctx->rx_msg,
					ctx->cfg.msg_size, UET_NULL_HANDLE,
					addr_handle, UET_DEFAULT_TAG,
					UET_EXACT_MATCH, NULL);
			if (ret < 0) {
				UET_ERR("uet_trecv: %s", fi_strerror(-ret));
				return UET_ERR_RC;
			}

			/* transmit tagged message to server */
			ret = uet_tsend(ctx->ep_handle, ctx->cfg.job_id,
					ctx->tx_msg, ctx->cfg.msg_size,
					UET_NULL_HANDLE, ctx->peer_addr_handle,
					UET_DEFAULT_TAG, NULL);
			if (ret < 0) {
				UET_ERR("uet_tsend: %s", fi_strerror(-ret));
				return UET_ERR_RC;
			}
		} else {
			/* post rx buffer */
			ret = uet_recv(ctx->ep_handle, UET_JOB_ID_ANY, ctx->rx_msg,
					ctx->cfg.msg_size, UET_NULL_HANDLE,
					UET_NULL_HANDLE, NULL);
			if (ret < 0) {
				UET_ERR("uet_recv: %s", fi_strerror(-ret));
				return UET_ERR_RC;
			}

			/* transmit message to server */
			ret = uet_send(ctx->ep_handle, ctx->cfg.job_id,
					ctx->tx_msg, ctx->cfg.msg_size,
					UET_NULL_HANDLE, ctx->peer_addr_handle,
					NULL);
			if (ret < 0) {
				UET_ERR("uet_send: %s", fi_strerror(-ret));
				return UET_ERR_RC;
			}
		}
	}

	/* wait for tx completion */
	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	/* wait for rx completion */
	if (uet_compl_wait(ctx->rx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	/* Message validation for IOV*/
	if (ctx->cfg.iov_test) {
		if (uet_validate_iov_msg(ctx) != UET_SUCCESS_RC) {
			UET_ERR("Invalid iov data in RX-iov");
			return UET_ERR_RC;
		}
	}

	if (cq_entry.len != ctx->cfg.msg_size) {
		UET_ERR("Received bad message size = %lu", cq_entry.len);
		return UET_ERR_RC;
	}

	return UET_SUCCESS_RC;
}

/*
 * perform server message data transfer as follows:
 *   - wait for message from client
 *   - validate data is correct
 *   - echo message back to server
 */
static uet_rc_t uet_msg_server(struct uet_context *ctx)
{
	ssize_t ret;
	struct fi_cq_data_entry cq_entry;
	uet_addr_handle_t addr_handle;

	if (ctx->cfg.iov_test) {
		if (ctx->cfg.tag) {
			if (ctx->cfg.tag_any_src)
				addr_handle = UET_NULL_HANDLE;
			else
				addr_handle = ctx->peer_addr_handle;

			/* post tagged rx buffer */
			ret = uet_trecvv(ctx->ep_handle, UET_JOB_ID_ANY,
					ctx->rx_iov, ctx->rx_count,
					UET_NULL_HANDLE, addr_handle,
					UET_DEFAULT_TAG, UET_EXACT_MATCH, NULL);
			if (ret < 0) {
				UET_ERR("uet_trecvv: %s", fi_strerror(-ret));
				return UET_ERR_RC;
			}
		} else {
			/* post rx buffer */
			ret = uet_recvv(ctx->ep_handle, UET_JOB_ID_ANY,
					ctx->rx_iov, ctx->rx_count,
					UET_NULL_HANDLE, UET_NULL_HANDLE, NULL);
			if (ret < 0) {
				UET_ERR("uet_recvv: %s", fi_strerror(-ret));
				return UET_ERR_RC;
			}
		}
	} else {
		if (ctx->cfg.tag) {
			if (ctx->cfg.tag_any_src)
				addr_handle = UET_NULL_HANDLE;
			else
				addr_handle = ctx->peer_addr_handle;

			/* post tagged rx buffer */
			ret = uet_trecv(ctx->ep_handle, UET_JOB_ID_ANY, ctx->rx_msg,
					ctx->cfg.msg_size, UET_NULL_HANDLE,
					addr_handle, UET_DEFAULT_TAG,
					UET_EXACT_MATCH, NULL);
			if (ret < 0) {
				UET_ERR("uet_trecv: %s", fi_strerror(-ret));
				return UET_ERR_RC;
			}
		} else {
			/* post rx buffer */
			ret = uet_recv(ctx->ep_handle, UET_JOB_ID_ANY, ctx->rx_msg,
					ctx->cfg.msg_size, UET_NULL_HANDLE,
					UET_NULL_HANDLE, NULL);
			if (ret < 0) {
				UET_ERR("uet_recv: %s", fi_strerror(-ret));
				return UET_ERR_RC;
			}
		}
	}

	/* wait for rx completion */
	if (uet_compl_wait(ctx->rx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	/* validate buffer contents */
	/* IOV message validation will be in the CLIENT side*/
	if (!ctx->cfg.iov_test) {
		if (uet_validate_msg(ctx, ctx->rx_msg) != UET_SUCCESS_RC) {
			UET_ERR("Invalid buffer contents");
			return UET_ERR_RC;
		}
	}

	if (ctx->cfg.iov_test) {
		if (ctx->cfg.tag) {
			/* echo tagged message back to client */
			ret = uet_tsendv(ctx->ep_handle, ctx->cfg.job_id,
					ctx->rx_iov, ctx->rx_count,
					UET_NULL_HANDLE, ctx->peer_addr_handle,
					UET_DEFAULT_TAG, NULL);
			if (ret < 0) {
				UET_ERR("uet_tsendv: %s", fi_strerror(-ret));
				return UET_ERR_RC;
			}
		} else {
			/* echo message back to client */
			ret = uet_sendv(ctx->ep_handle, ctx->cfg.job_id,
					ctx->rx_iov, ctx->rx_count,
					UET_NULL_HANDLE, ctx->peer_addr_handle,
					NULL);
			if (ret < 0) {
				UET_ERR("uet_sendv: %s", fi_strerror(-ret));
				return UET_ERR_RC;
			}
		}
	} else {
		if (ctx->cfg.tag) {
			/* echo tagged message back to client */
			ret = uet_tsend(ctx->ep_handle, ctx->cfg.job_id,
					ctx->rx_msg, cq_entry.len,
					UET_NULL_HANDLE, ctx->peer_addr_handle,
					UET_DEFAULT_TAG, NULL);
			if (ret < 0) {
				UET_ERR("uet_tsend: %s", fi_strerror(-ret));
				return UET_ERR_RC;
			}
		} else {
			/* echo message back to client */
			ret = uet_send(ctx->ep_handle, ctx->cfg.job_id,
					ctx->rx_msg, cq_entry.len, UET_NULL_HANDLE,
					ctx->peer_addr_handle, NULL);
			if (ret < 0) {
				UET_ERR("uet_send: %s", fi_strerror(-ret));
				return UET_ERR_RC;
			}
		}
	}

	/* wait for tx completion */
	if (uet_compl_wait(ctx->tx_cq_handle, &cq_entry) != UET_SUCCESS_RC) {
		UET_ERR("uet_compl_wait");
		return UET_ERR_RC;
	}

	return UET_SUCCESS_RC;
}

/* do one run */
static int uet_run(int argc, char *argv[], struct uet_context *ctx)
{
	uet_rc_t rc;
	int iteration = 0;
	int use_iov = 0;
	char *pds;

	/* init config parms */
	rc = uet_init_cfg(argc, argv, ctx);
	if (rc != UET_SUCCESS_RC) {
		UET_USAGE(argv[0]);
		goto exit;
	}

	/* init transport */
	rc = uet_init_transport(ctx);
	if (rc != UET_SUCCESS_RC)
		goto exit;

	/*
	 * Give the server time to finish NIC initialization before the client
	 * starts sending. i.e., XDP initialization (BPF program load, attach,
	 * UMEM setup, socket creation, xsks_map config) takes significantly
	 * longer than rawsock. Without this delay the client can blast
	 * packets before the server's AF_XDP path is fully ready, causing
	 * missed packets and retransmits.
	 */
	if (ctx->cfg.client)
		sleep(1);

	for (use_iov = 0; use_iov <= 1; use_iov++) {
		pds = getenv(UET_PDS);
		/* TODO: IOV support for SNG mode */
		if (((pds == NULL) || (strcmp(pds, "sng") == 0)) &&
				      (use_iov == 1)) {
			continue;
		}

		ctx->cfg.iov_test = (use_iov == 1);
		printf("Starting in %s\n",
				(use_iov == 1) ? "iov_mode" : "buf_mode");

		/* perform control message exchange */
		if (ctx->cfg.rma || ctx->cfg.sync_rma ||
		    ctx->cfg.atomic || ctx->cfg.sync_atomic) {
			if (ctx->cfg.client) {
				rc = uet_rma_client_ctrl_exchange(ctx);
				if (rc != UET_SUCCESS_RC)
					goto exit;
			} else {
				rc = uet_rma_server_ctrl_exchange(ctx);
				if (rc != UET_SUCCESS_RC)
					goto exit;
			}
		}

		/* perform data transfer */
		for (iteration = 0; iteration < ctx->cfg.num_iterations;
		     iteration++) {
			if (ctx->cfg.client) {
				if (ctx->cfg.rma) {
					rc = uet_rma_client(ctx);
					if (rc != UET_SUCCESS_RC)
						goto exit;
				} else if (ctx->cfg.sync_rma) {
					rc = uet_sync_rma_client(ctx);
					if (rc != UET_SUCCESS_RC)
						goto exit;
				} else if (ctx->cfg.atomic) {
					rc = uet_atomic_client(ctx);
					if (rc != UET_SUCCESS_RC)
						goto exit;
				} else if (ctx->cfg.sync_atomic) {
					rc = uet_sync_atomic_client(ctx);
					if (rc != UET_SUCCESS_RC)
						goto exit;
				} else {
					if (ctx->cfg.unexpected_msg_test)
						rc = uet_msg_client_unexpected(
									   ctx);
					else
						rc = uet_msg_client(ctx);
					if (rc != UET_SUCCESS_RC)
						goto exit;
				}
			} else { /* server */
				if (ctx->cfg.rma) {
					rc = uet_rma_server(ctx);
					if (rc != UET_SUCCESS_RC)
						goto exit;
				} else if (ctx->cfg.sync_rma) {
					rc = uet_sync_rma_server(ctx);
					if (rc != UET_SUCCESS_RC)
						goto exit;
				} else if (ctx->cfg.atomic) {
					rc = uet_atomic_server(ctx);
					if (rc != UET_SUCCESS_RC)
						goto exit;
				} else if (ctx->cfg.sync_atomic) {
					rc = uet_sync_atomic_server(ctx);
					if (rc != UET_SUCCESS_RC)
						goto exit;
				} else {
					rc = uet_msg_server(ctx);
					if (rc != UET_SUCCESS_RC)
						goto exit;
				}
			}
		}
	}

exit:
	printf("Completed %d iterations\n", iteration);
	uet_free_res(ctx); /* free resources */
	return rc;
}

int main(int argc, char *argv[])
{
	int rc, test_argc;
	char *test_argv[UET_MAX_ARGS+1];
	struct uet_context *ctx = &uet_ctx;
	bool do_all = false;
	char *cmd, *c_s, *test, *ip;

	if (argc != 4)  {
		UET_ERR("Invalid usage: wrong number of args");
		UET_USAGE(argv[0]);
		return UET_ERR_RC;
	}

	if (strcmp(argv[1], "client") == 0)
		ctx->cfg.client = true;

	if (strcmp(argv[2], "all") == 0)
		do_all = true;

	cmd  = argv[0];
	c_s  = argv[1];
	test = argv[2];
	ip   = argv[3];

	if (do_all || (strcmp(test, "rma") == 0)) {
		printf("\nRMA Test\n");
		printf(  "========\n");
		test_argc = 4;
		test_argv[0] = cmd;
		test_argv[1] = c_s;
		test_argv[2] = "rma";
		test_argv[3] = ip;
		test_argv[4] = NULL;
		memset(ctx, 0, sizeof(struct uet_context));

		rc = uet_run(test_argc, test_argv, ctx);
		if (rc != UET_SUCCESS_RC)
			exit(rc);
	}

	if (do_all || (strcmp(test, "sync_rma") == 0)) {
		printf("\nSync Group RMA Test\n");
		printf(  "===================\n");
		test_argc = 4;
		test_argv[0] = cmd;
		test_argv[1] = c_s;
		test_argv[2] = "sync_rma";
		test_argv[3] = ip;
		test_argv[4] = NULL;
		memset(ctx, 0, sizeof(struct uet_context));

		rc = uet_run(test_argc, test_argv, ctx);
		if (rc != UET_SUCCESS_RC)
			exit(rc);
	}

	if (do_all || (strcmp(test, "untag") == 0)) {
		printf("\nUntagged Message Test\n");
		printf(  "=====================\n");
		test_argc = 3;
		test_argv[0] = cmd;
		test_argv[1] = c_s;
		test_argv[2] = ip;
		test_argv[3] = NULL;
		memset(ctx, 0, sizeof(struct uet_context));

		rc = uet_run(test_argc, test_argv, ctx);
		if (rc != UET_SUCCESS_RC)
			exit(rc);
	}

	if (do_all || (strcmp(test, "tag") == 0)) {
		printf("\nTagged Message Test\n");
		printf(  "===================\n");
		test_argc = 4;
		test_argv[0] = cmd;
		test_argv[1] = c_s;
		test_argv[2] = "tag";
		test_argv[3] = ip;
		test_argv[4] = NULL;
		memset(ctx, 0, sizeof(struct uet_context));

		rc = uet_run(test_argc, test_argv, ctx);
		if (rc != UET_SUCCESS_RC)
			exit(rc);
	}

	if (do_all || (strcmp(test, "tag_any_src") == 0)) {
		printf("\nTagged Message Test (Any Source)\n");
		printf(  "================================\n");
		test_argc = 4;
		test_argv[0] = cmd;
		test_argv[1] = c_s;
		test_argv[2] = "tag";
		test_argv[3] = ip;
		test_argv[4] = NULL;
		memset(ctx, 0, sizeof(struct uet_context));
		ctx->cfg.tag_any_src = true;

		rc = uet_run(test_argc, test_argv, ctx);
		if (rc != UET_SUCCESS_RC)
			exit(rc);
	}

	if (do_all || (strcmp(test, "unexp_untag") == 0)) {
		printf("\nUnexpected Untagged Message Test\n");
		printf(  "================================\n");
		test_argc = 3;
		test_argv[0] = cmd;
		test_argv[1] = c_s;
		test_argv[2] = ip;
		test_argv[3] = NULL;
		memset(ctx, 0, sizeof(struct uet_context));
		first = true;
		ctx->cfg.unexpected_msg_test = true;

		rc = uet_run(test_argc, test_argv, ctx);
		if (rc != UET_SUCCESS_RC)
			exit(rc);
	}

	if (do_all || (strcmp(test, "unexp_tag") == 0)) {
		printf("\nUnexpected Tagged Message Test\n");
		printf(  "==============================\n");
		test_argc = 4;
		test_argv[0] = cmd;
		test_argv[1] = c_s;
		test_argv[2] = "tag";
		test_argv[3] = ip;
		test_argv[4] = NULL;
		memset(ctx, 0, sizeof(struct uet_context));
		first = true;
		ctx->cfg.unexpected_msg_test = true;

		rc = uet_run(test_argc, test_argv, ctx);
		if (rc != UET_SUCCESS_RC)
			exit(rc);
	}

	if (do_all || (strcmp(test, "defer_send") == 0)) {
		printf("\nDeferred Send Message Test\n");
		printf(  "==========================\n");
		test_argc = 3;
		test_argv[0] = cmd;
		test_argv[1] = c_s;
		test_argv[2] = ip;
		test_argv[3] = NULL;
		memset(ctx, 0, sizeof(struct uet_context));
		first = true;
		ctx->cfg.unexpected_msg_test = true;
		ctx->cfg.dsend_test = true;

		rc = uet_run(test_argc, test_argv, ctx);
		if (rc != UET_SUCCESS_RC)
			exit(rc);
	}

	if (do_all || (strcmp(test, "defer_tag") == 0)) {
		printf("\nDeferred Tagged Send Message Test\n");
		printf(  "=================================\n");
		test_argc = 4;
		test_argv[0] = cmd;
		test_argv[1] = c_s;
		test_argv[2] = "tag";
		test_argv[3] = ip;
		test_argv[4] = NULL;
		memset(ctx, 0, sizeof(struct uet_context));
		first = true;
		ctx->cfg.unexpected_msg_test = true;
		ctx->cfg.dsend_test = true;

		rc = uet_run(test_argc, test_argv, ctx);
		if (rc != UET_SUCCESS_RC)
			exit(rc);
	}

	if (do_all || (strcmp(test, "defer_tag_any_src") == 0)) {
		printf("\nDeferred Tagged Send Message Test (Any Source)\n");
		printf(  "==============================================\n");
		test_argc = 4;
		test_argv[0] = cmd;
		test_argv[1] = c_s;
		test_argv[2] = "tag";
		test_argv[3] = ip;
		test_argv[4] = NULL;
		memset(ctx, 0, sizeof(struct uet_context));
		first = true;
		ctx->cfg.unexpected_msg_test = true;
		ctx->cfg.dsend_test = true;
		ctx->cfg.tag_any_src = true;

		rc = uet_run(test_argc, test_argv, ctx);
		if (rc != UET_SUCCESS_RC)
			exit(rc);
	}

	if (do_all || (strcmp(test, "atomic") == 0)) {
		printf("\nAtomic Test\n");
		printf(  "===========\n");
		test_argc = 4;
		test_argv[0] = cmd;
		test_argv[1] = c_s;
		test_argv[2] = "atomic";
		test_argv[3] = ip;
		test_argv[4] = NULL;
		memset(ctx, 0, sizeof(struct uet_context));

		rc = uet_run(test_argc, test_argv, ctx);
		if (rc != UET_SUCCESS_RC)
			exit(rc);
	}

	if (do_all || (strcmp(test, "sync_atomic") == 0)) {
		printf("\nSync Group Atomic Test\n");
		printf(  "======================\n");
		test_argc = 4;
		test_argv[0] = cmd;
		test_argv[1] = c_s;
		test_argv[2] = "sync_atomic";
		test_argv[3] = ip;
		test_argv[4] = NULL;
		memset(ctx, 0, sizeof(struct uet_context));

		rc = uet_run(test_argc, test_argv, ctx);
		if (rc != UET_SUCCESS_RC)
			exit(rc);
	}

	exit(0);
}
