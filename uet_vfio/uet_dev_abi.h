/*
 * Copyright (c) 2026 Broadcom. All rights reserved. The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 */

/*
 * UET reference device ABI
 *
 * The programming interface a driver sees. This header is the contract
 * between the device model and anything that drives it (i.e., kernel driver),
 * so it deliberately includes nothing beyond <stdint.h>.
 */

#ifndef _UET_DEV_ABI_H_
#define _UET_DEV_ABI_H_

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

/* ---------------------------------------------------------------- */
/* PCI identity                                                     */
/* ---------------------------------------------------------------- */

#define UET_DEV_PCI_VENDOR_ID		0x14e4	/* Broadcom */
#define UET_DEV_PCI_DEVICE_ID		0x4242  /* THE answer squared! */

#define UET_DEV_PCI_CLASS		0x02	/* network controller */
#define UET_DEV_PCI_SUBCLASS		0x80	/* other */

/* ---------------------------------------------------------------- */
/* BAR0 - status region, read only                                  */
/* ---------------------------------------------------------------- */

#define UET_DEV_BAR0_SIZE		0x1000	/* 4 KiB */

/* identification */
#define UET_DEV_REG_MAGIC		0x000
#define UET_DEV_MAGIC			0x55455444u	/* "UETD" */

/* The contract between this device model and its driver. The driver refuses
 * a device whose major differs or whose minor is below its own, so bump the
 * minor on any change to the register map, the admin command set, or a
 * shared structure (additive changes included). Bump the major only for a
 * change a minor cannot express, meaning one where an older driver would be
 * wrong rather than simply out of date.
 */
#define UET_DEV_REG_ABI_VERSION		0x004
#define UET_DEV_ABI_MAJOR		1
#define UET_DEV_ABI_MINOR		0
#define UET_DEV_ABI_VERSION \
	(((uint32_t)UET_DEV_ABI_MAJOR << 16) | (uint32_t)UET_DEV_ABI_MINOR)

#define UET_DEV_REG_CAPS		0x008
#define UET_DEV_CAP_INSTANCE		(1u << 0) /* a uet instance exists */
#define UET_DEV_CAP_PROGRESS_THREAD	(1u << 1) /* progress thread running */
#define UET_DEV_CAP_SECURITY		(1u << 2) /* tss enabled */
#define UET_DEV_CAP_IMPAIRMENT		(1u << 3) /* impairment shim on */
#define UET_DEV_CAP_FORCE_RUDI		(1u << 4)
#define UET_DEV_CAP_FORCE_UUD		(1u << 5)
	/* Which memory region access classes this device implements. Reported
	 * so a driver can refuse an unsupported restriction at registration
	 * instead of accepting one and leaving a region that quietly never
	 * matches.
	 */
#define UET_DEV_CAP_MR_UNRESTRICTED	(1u << 6)
#define UET_DEV_CAP_MR_JOB_RESTRICTED	(1u << 7)
#define UET_DEV_CAP_MR_RI_RESTRICTED	(1u << 8)
#define UET_DEV_CAP_MR_RI_JOB_RESTRICTED (1u << 9)

#define UET_DEV_REG_STATE		0x00c
#define UET_DEV_STATE_INIT		0
#define UET_DEV_STATE_READY		1
#define UET_DEV_STATE_ERROR		2

#define UET_DEV_REG_PDS_MODE		0x040
#define UET_DEV_PDS_MODE_SNG		0
#define UET_DEV_PDS_MODE_PDS		1

#define UET_DEV_REG_SEC_MODE		0x044
#define UET_DEV_SEC_MODE_NONE		0
#define UET_DEV_SEC_MODE_DIRECT		1
#define UET_DEV_SEC_MODE_CLUSTER	2
#define UET_DEV_SEC_MODE_SERVER		3

#define UET_DEV_REG_NIC_SHIM		0x048
#define UET_DEV_NIC_SHIM_RAWSOCK	0
#define UET_DEV_NIC_SHIM_XDP		1
#define UET_DEV_NIC_SHIM_VPP		2

#define UET_DEV_REG_MAX_PAYLOAD		0x04c
#define UET_DEV_REG_PORT_PROTO		0x050	/* udp port 15:0, proto 23:16 */
#define UET_DEV_REG_MAX_TX_RETRIES	0x054
#define UET_DEV_REG_TX_TIMEOUT		0x058	/* msecs */
#define UET_DEV_REG_PKT_DROP_THRESH	0x05c
#define UET_DEV_REG_SEC_SSI		0x060
#define UET_DEV_REG_IOV_LIMIT		0x064

/* The largest message, not the largest packet. A message is segmented
 * across as many packets as it needs, so this is orders of magnitude
 * above UET_DEV_REG_MAX_PAYLOAD, and a driver reporting the transport's
 * message limit reports this.
 */
#define UET_DEV_REG_MAX_MSG_SIZE	0x068

/* Which encapsulation the instance puts UET on the wire in. UET verbs
 * identifies the transport under the SES and PDS headers by GID type and an
 * application picks the protocol by picking a GID entry, so a driver
 * reporting a GID type needs this.
 */
#define UET_DEV_REG_GID_TYPE		0x06c
#define UET_DEV_GID_TYPE_UDP		0	/* UET over UDP/IP */
#define UET_DEV_GID_TYPE_IP		1	/* UET over IP + entropy header */
#define UET_DEV_GID_TYPE_UFH		2	/* UET over UFH, for ULN */

/* interface identity */
#define UET_DEV_REG_IFNAME		0x080	/* 16 bytes, nul padded ascii */
#define UET_DEV_IFNAME_LEN		16
#define UET_DEV_REG_MAC_LO		0x090	/* mac bytes 0..3 */
#define UET_DEV_REG_MAC_HI		0x094	/* mac bytes 4..5 in 15:0 */
#define UET_DEV_REG_IP_VER		0x098	/* 4 or 6 */
/* 16 bytes of address, as octets in address order: byte 0 is the leading
 * octet. A v4 address uses the first 4 and leaves the rest zero. Not a
 * host-order integer, a driver can print these bytes directly.
 */
#define UET_DEV_REG_IPADDR		0x09c
#define UET_DEV_IPADDR_LEN		16

/* live counters - these change while the guest watches */
#define UET_DEV_REG_PROGRESS_ALIVE	0x100
#define UET_DEV_REG_PROGRESS_ITERS_LO	0x104
#define UET_DEV_REG_PROGRESS_ITERS_HI	0x108
#define UET_DEV_REG_UPTIME_MS		0x10c
#define UET_DEV_REG_BAR0_READS		0x110
#define UET_DEV_REG_BAR0_WRITES		0x114	/* writes ignored, counted */
#define UET_DEV_REG_DOORBELLS		0x118	/* user doorbell writes seen */
#define UET_DEV_REG_IRQS_FIRED		0x11c	/* MSI-X triggers attempted */

/* L2 ring counters - see the BAR2 ring block */
#define UET_DEV_REG_TX_CONS		0x130	/* device's TX consumer index */
#define UET_DEV_REG_RX_CONS		0x134	/* device's RX consumer index */
#define UET_DEV_REG_TX_FRAMES		0x138	/* frames sent to the wire */
#define UET_DEV_REG_TX_ERRORS		0x13c
#define UET_DEV_REG_RX_FRAMES		0x140	/* frames delivered to guest */
#define UET_DEV_REG_RX_DROPPED		0x144	/* no RX buffer was posted */
#define UET_DEV_REG_RX_UET_FRAMES	0x148	/* went to the uet instance */

/* Admin queue counters - see the BAR2 ring block */
#define UET_DEV_REG_ADMIN_SQ_CONS	0x14c	/* device consumed to here */
#define UET_DEV_REG_ADMIN_CQ_PROD	0x150	/* device produced to here */
#define UET_DEV_REG_ADMIN_CMDS		0x154	/* commands completed */
#define UET_DEV_REG_ADMIN_ERRORS	0x158	/* commands completed !OK */
#define UET_DEV_REG_JOBS_LIVE		0x15c	/* job objects allocated */
#define UET_DEV_REG_JKEYS_LIVE		0x160	/* job keys allocated */
#define UET_DEV_REG_MRS_LIVE		0x164	/* memory regions registered */
#define UET_DEV_REG_QPS_LIVE		0x168	/* queue pairs created */
#define UET_DEV_REG_CQS_LIVE		0x16c	/* completion queues created */

/* datapath stats */
#define UET_DEV_REG_SQ_POSTED		0x170	/* work requests accepted */
#define UET_DEV_REG_RQ_POSTED		0x174
#define UET_DEV_REG_CQ_POSTED		0x178	/* completions written */
#define UET_DEV_REG_CQ_OVERRUNS		0x17c	/* no room in the ring */
#define UET_DEV_REG_DB_REJECTED		0x180	/* doorbell, unowned handle */
#define UET_DEV_REG_QPS_CLOSING		0x184	/* destroyed, still draining */
     /* Failures the guest cannot see any other way. A ring the device
      * could not read or a completion it could not write is a request
      * that never completes, so without these the only symptom is a
      * transfer that hangs with nothing logged on either side.
      */
#define UET_DEV_REG_SQ_ERRORS		0x188	/* send ring unreadable */
#define UET_DEV_REG_RQ_ERRORS		0x18c	/* receive ring unreadable */
#define UET_DEV_REG_CQ_ERRORS		0x190	/* completion unwritable */
#define UET_DEV_REG_FLUSHED		0x194	/* abandoned on a retiring pair */

/* ---------------------------------------------------------------- */
/* BAR1 - MSI-X table and PBA                                       */
/* ---------------------------------------------------------------- */

#define UET_DEV_BAR1_SIZE		0x1000
#define UET_DEV_MSIX_NUM_VECTORS	UET_DEV_NUM_VECTORS
#define UET_DEV_MSIX_TABLE_OFF		0x0
#define UET_DEV_MSIX_PBA_OFF		0x800

#define UET_DEV_TX_VECTOR		0	/* TX frames consumed */
#define UET_DEV_RX_VECTOR		1	/* RX frames delivered */
#define UET_DEV_ADMIN_VECTOR		2	/* admin command completed */
#define UET_DEV_CQ_VECTOR_BASE		3	/* first data completion vector */
#define UET_DEV_NUM_VECTORS		4

/* ---------------------------------------------------------------- */
/* BAR2 - control region                                            */
/* ---------------------------------------------------------------- */

#define UET_DEV_BAR2_SIZE		0x1000

/*
 * L2 ring configuration (guest writable)
 *
 * Two rings of uet_dev_desc carry ordinary Ethernet frames between the guest
 * and the wire, so the device can host a netdev beside the UET datapath.
 * The device demultiplexes its interface. UET traffic goes to the uet
 * instance, everything else (ARP, ICMP, ND, DHCP, etc) crosses these rings.
 *
 * Index discipline, the same for both rings:
 *
 *   - The guest owns the producer index and publishes it by writing
 *     TX_PROD/RX_PROD in this BAR. That write is the doorbell and the
 *     value is the new producer index.
 *   - The device owns the consumer index and publishes it in BAR0
 *     TX_CONS/RX_CONS, then raises the ring's MSI-X vector.
 *   - A slot is owned by the device when (cons != prod).
 *
 * Indices are free running u32 counters, not wrapped. The slot is
 * (index % entries), entries must be a power of two and no more than
 * UET_DEV_RING_MAX_ENTRIES.
 *
 * TX: The guest fills addr/len with a frame to send. The device reads the
 * frame and writes it to the wire. Nothing is written back to the descriptor,
 * TX_CONS is the completion.
 *
 * RX: The guest posts empty buffers, len being the capacity. The device
 * writes a received frame into addr, then writes the descriptor back with
 * len set to the actual frame length and UET_DEV_DESC_DONE set. Frames
 * larger than the posted buffer are dropped and counted, never truncated.
 *
 * Rings must be physically contiguous and are only read while the ring's
 * ENABLE bit is set. Disabling a ring is how a driver takes its memory back.
 */

#define UET_DEV_TX_RING_BASE_LO		0x000
#define UET_DEV_TX_RING_BASE_HI		0x004
#define UET_DEV_TX_RING_ENTRIES		0x008
#define UET_DEV_TX_RING_CTRL		0x00c
#define UET_DEV_TX_PROD			0x010	/* doorbell */

#define UET_DEV_RX_RING_BASE_LO		0x040
#define UET_DEV_RX_RING_BASE_HI		0x044
#define UET_DEV_RX_RING_ENTRIES		0x048
#define UET_DEV_RX_RING_CTRL		0x04c
#define UET_DEV_RX_PROD			0x050	/* doorbell */

#define UET_DEV_RING_CTRL_ENABLE	(1u << 0)

#define UET_DEV_RING_MAX_ENTRIES	1024
#define UET_DEV_MTU			1500
#define UET_DEV_MAX_FRAME		2048	/* buffer size a driver posts */

/* one ring slot: 16 bytes, little endian, as a driver lays it out */
struct uet_dev_desc {
	uint64_t addr;		/* guest address of the frame buffer */
	uint32_t len;		/* TX: frame length. RX: capacity in,
				   received length out */
	uint32_t flags;		/* UET_DEV_DESC_* */
};

#define UET_DEV_DESC_DONE	(1u << 0) /* device finished the slot */

/*
 * Admin queue configuration (guest writable)
 *
 * The UET slowpath, resource management commands from the driver.
 *
 * Two rings, not one. The driver produces commands into the command ring
 * and consumes responses from the completion ring. The device does the
 * reverse. Neither side writes a ring the other owns.
 *
 * The command set mirrors the object model for UET Verbs.
 *
 * Protection domain management is owned by the driver. The device is told
 * the PD only when a memory region or queue pair is created, and its job is
 * to enforce the match when data is read or written.
 *
 * Results of one or two words ride back in the completion entry. Anything
 * larger uses a buffer the driver names in the command (buf_addr / buf_len).
 */

#define UET_DEV_ADMIN_SQ_BASE_LO	0x080
#define UET_DEV_ADMIN_SQ_BASE_HI	0x084
#define UET_DEV_ADMIN_SQ_ENTRIES	0x088
#define UET_DEV_ADMIN_SQ_CTRL		0x08c
#define UET_DEV_ADMIN_SQ_PROD		0x090	/* doorbell: commands ready */

#define UET_DEV_ADMIN_CQ_BASE_LO	0x0a0
#define UET_DEV_ADMIN_CQ_BASE_HI	0x0a4
#define UET_DEV_ADMIN_CQ_ENTRIES	0x0a8
#define UET_DEV_ADMIN_CQ_CTRL		0x0ac
#define UET_DEV_ADMIN_CQ_CONS		0x0b0	/* doorbell: entries reclaimed */

#define UET_DEV_ADMIN_MAX_ENTRIES	64

/* one command: 64 bytes */
struct uet_dev_admin_cmd {
	uint16_t opcode;	/* UET_DEV_ADMIN_* */
	uint16_t flags;
	uint32_t rsvd;
	uint64_t cookie;	/* from driver, echoed back in the response */
	uint64_t param[4];	/* opcode specific */
	uint64_t buf_addr;	/* large payload, or 0 */
	uint32_t buf_len;	/* payload length */
	uint32_t rsvd2;
};

/* one completion: 32 bytes */
struct uet_dev_admin_cqe {
	uint64_t cookie;	/* copied from the command */
	uint16_t opcode;	/* copied from the command */
	uint16_t flags;		/* UET_DEV_CQE_* */
	uint32_t status;	/* UET_DEV_ADMIN_ST_* */
	uint64_t result[2];	/* small results, or [0] = bytes written */
};

/* The device sets VALID when an entry is written. A driver may wait for
 * the admin MSI-X vector or watch this flag; the flag is what makes an
 * entry safe to read, and it is cleared by the driver when it reclaims
 * the slot.
 */
#define UET_DEV_ADMIN_CQE_VALID		(1u << 0)

/* Opcodes, grouped by the object they act on, leaving room in each group. */

#define UET_DEV_ADMIN_NOP		0x0000
#define UET_DEV_ADMIN_DEV_INFO		0x0001	/* -> uet_dev_admin_dev_info */

/* Jobs. A job is a device level object and the JobID it carries goes into SES
 * headers. It also contains an address table that turns an address index in
 * a work request into the peer to send to.
 *
 * A JobID maps to exactly one job object. Allocating one that is already
 * live is refused. Sharing a job between processes is the driver's job,
 * done by handing out a reference rather than by allocating twice.
 */
#define UET_DEV_ADMIN_JOB_ALLOC		0x0020
#define UET_DEV_ADMIN_JOB_FREE		0x0021
#define UET_DEV_ADMIN_JOB_QUERY		0x0022

/* Job Keys. A job imported into a protection domain, named by a jkey. */
#define UET_DEV_ADMIN_JKEY_CREATE	0x0030
#define UET_DEV_ADMIN_JKEY_DESTROY	0x0031

/* Job address table entries, indexed by the caller. */
#define UET_DEV_ADMIN_ADDR_INSERT	0x0040
#define UET_DEV_ADMIN_ADDR_REMOVE	0x0041
#define UET_DEV_ADMIN_ADDR_QUERY	0x0042

/* Memory regions. The driver describes the guest's pages as a page buffer
 * list and passes its root. The device registers that with the reference
 * implementation, so the region really is the guest's memory rather than a
 * copy of it, and the keys come from the library rather than being invented
 * here.
 */
#define UET_DEV_ADMIN_MR_REG		0x0050
#define UET_DEV_ADMIN_MR_DEREG		0x0051
#define UET_DEV_ADMIN_MR_ATTACH		0x0053
#define UET_DEV_ADMIN_MR_DETACH		0x0054

/* Completion queues. */
#define UET_DEV_ADMIN_CQ_CREATE		0x0060
#define UET_DEV_ADMIN_CQ_DESTROY	0x0061

/* Address handles. A job address table names peers by index and address
 * handles names peers directly. The device keeps a flat table of address
 * handles and both resolve to the same thing.
 */
#define UET_DEV_ADMIN_AH_CREATE		0x0080
#define UET_DEV_ADMIN_AH_DESTROY	0x0081

/* Queue pairs. A queue pair is a UET service at a Resource Index, so it
 * becomes an endpoint. The QPN carries the addressing mode, the Resource
 * Index, and the PIDonFEP that identify it.
 *
 * QP_MODIFY: param[0] handle, param[1] next state (UET_DEV_QPS_*), param[2]
 * path MTU in bytes, zero to leave it as it is. The path MTU can only be set
 * by the modify from RESET to RTS, as the queue pair is enabled. An RTS to RTS
 * modify that names a different one is refused.
 */
#define UET_DEV_ADMIN_QP_CREATE		0x0070
#define UET_DEV_ADMIN_QP_DESTROY	0x0071
#define UET_DEV_ADMIN_QP_MODIFY		0x0072

/* The states a queue pair can be in (refined state machine). A UET queue pair
 * is created RESET and goes straight to RTS on its first modify, so there is
 * no INIT and no RTR. A queue pair that has failed can be taken to ERROR,
 * RESET, and brought back which lets an application recover without
 * destroying and rebuilding everything hanging off the queue pair.
 *
 *     create
 *       |
 *       v
 *     RESET -------> RTS <----------------.
 *                     | (modify in place)  \
 *                     |                     \
 *                     v                      \
 *                    ERROR ---------------> RESET
 *
 * Asking for INIT or RTR is refused. A caller that walks the full QP state
 * machine sequence is doing something this device will not honor.
 */
#define UET_DEV_QPS_RESET		0
#define UET_DEV_QPS_RTS			1
#define UET_DEV_QPS_ERR			2

#define UET_DEV_ADMIN_ST_OK		0
#define UET_DEV_ADMIN_ST_EINVAL		1
#define UET_DEV_ADMIN_ST_ENOSPC		2
#define UET_DEV_ADMIN_ST_EOPNOTSUPP	3
#define UET_DEV_ADMIN_ST_ETOOSMALL	4
#define UET_DEV_ADMIN_ST_EEXIST		5
#define UET_DEV_ADMIN_ST_ENOENT		6
#define UET_DEV_ADMIN_ST_EBUSY		7

/* Device limits reported by DEV_INFO. They live here so that a driver learns
 * and reports what the device actually supports.
 */
#define UET_DEV_MAX_JOB_IDS		256
#define UET_DEV_MAX_JOB_KEYS		256
#define UET_DEV_MAX_ADDR_ENTRIES	4096
#define UET_DEV_MAX_PDS_ADVISORY	1024
#define UET_DEV_MAX_MRS			1024
#define UET_DEV_MAX_QPS			256
#define UET_DEV_MAX_CQS			256
#define UET_DEV_MAX_AHS			256

/* Address table slots a job gets when it asks for none. */
#define UET_DEV_DEF_ADDR_ENTRIES	16

/* Outstanding transmits abandoned per progress sweep when a queue pair is
 * being retired. Bounded because each one posts a completion into a ring
 * with no overflow protection, and the guest's completions are drained
 * between sweeps rather than during one.
 */
#define UET_DEV_FLUSH_PER_SWEEP		8

/* Error completions turned into guest completions per progress sweep.
 * Bounded for the same reason as UET_DEV_FLUSH_PER_SWEEP, and for one
 * more, the drain runs on the progress thread which also services the
 * datapath and the L2 rings. A drain cut short resumes on the next sweep.
 */
#define UET_DEV_ERRS_PER_SWEEP		8

/* Descriptors an endpoint gets when its queue pair asked for none. */
#define UET_DEV_DEF_QUEUE_DEPTH		64
#define UET_DEV_CQ_MAX_ENTRIES		4096

/* payload of UET_DEV_ADMIN_DEV_INFO, written to buf_addr */
struct uet_dev_admin_dev_info {
	uint64_t caps;
	uint32_t max_job_ids;
	uint32_t max_job_keys;
	uint32_t max_addr_entries;
	uint32_t max_imm_size;
	uint32_t max_pds;
	uint32_t rsvd;
};

/* Page list levels. */
#define UET_DEV_PBL_LEVEL_0		0	/* pages are contiguous */
#define UET_DEV_PBL_LEVEL_1		1	/* root is a page directory */
#define UET_DEV_PBL_LEVEL_2		2	/* root is a directory of those */

/* Access rights. */
#define UET_DEV_MR_ACCESS_LOCAL_READ	(1u << 0)
#define UET_DEV_MR_ACCESS_LOCAL_WRITE	(1u << 1)
#define UET_DEV_MR_ACCESS_REMOTE_READ	(1u << 2)
#define UET_DEV_MR_ACCESS_REMOTE_WRITE	(1u << 3)
#define UET_DEV_MR_ACCESS_REMOTE_ATOMIC	(1u << 4)

/* How a region may be reached, from the UET verbs MR access table. The
 * region is always scoped to its protection domain. The class says what
 * else an incoming request must match:
 *
 *   UNRESTRICTED       { Device, PD }             any QP
 *   RI_RESTRICTED      { Device, PD, QP }         one QP
 *   JOB_RESTRICTED     { Device, PD, JobID }      any QP, one Job
 *   RI_JOB_RESTRICTED  { Device, PD, QP, JobID }  one QP, one Job
 *
 * The RI classes reach a queue pair through MR_ATTACH.
 *
 * The Job classes take their JobID from jkey_handle, which must name a job
 * key in the same protection domain. Job restriction is meaningful only
 * under absolute addressing, since relative addressing already carries the
 * JobID.
 */
#define UET_DEV_MR_CLASS_UNRESTRICTED		0
#define UET_DEV_MR_CLASS_RI_RESTRICTED		1
#define UET_DEV_MR_CLASS_JOB_RESTRICTED		2
#define UET_DEV_MR_CLASS_RI_JOB_RESTRICTED	3

/* Bits the library carries inside a memory key. */
#define UET_DEV_MR_KEY_IDEMPOTENT_SAFE	(1ULL << 63)

/* flags of struct uet_dev_admin_mr_reg */
#define UET_DEV_MR_FLAG_USER_KEY	(1u << 0)	/* use requested_key */

/* payload of UET_DEV_ADMIN_MR_REG, written in buf_addr */
struct uet_dev_admin_mr_reg {
	uint64_t access;	/* UET_DEV_MR_ACCESS_* */
	uint64_t requested_key;
	uint32_t page_offset;
	uint32_t pd;
	uint32_t jkey_handle;	/* 0 for a region not bound to a job */
	uint32_t flags;		/* UET_DEV_MR_FLAG_* */
	uint32_t access_class;	/* UET_DEV_MR_CLASS_* */
	     /* The job key by value, as the caller holds it. Either this or
	      * jkey_handle names the job.
	      */
	uint32_t jkey;
};

/* QPN format, as the UET verbs specification defines it:
 *   [ ABS/REL 1b | reserved 7b | Resource Index 12b | PIDonFEP 12b ]
 * The top bit set means absolute addressing.
 */
#define UET_DEV_QPN_ABSOLUTE		(1u << 31)
#define UET_DEV_QPN_RI_SHIFT		12
#define UET_DEV_QPN_RI_MASK		(0xfffu << UET_DEV_QPN_RI_SHIFT)
#define UET_DEV_QPN_PIDONFEP_MASK	0xfffu

/* A ring the guest owns and the device reads: a page list, exactly as a
 * memory region is used. The device walks it on every descriptor fetch rather
 * than assuming the ring is physically contiguous.
 */
struct uet_dev_ring_desc {
	uint64_t pbl_root;
	uint32_t page_size;
	uint32_t level;		/* UET_DEV_PBL_LEVEL_* */
	uint32_t page_offset;
	uint32_t entries;	/* a power of two */
};

/* Work request and completion sizes (ring entry). A fixed entry size makes
 * walking easier. */
#define UET_DEV_WQE_SIZE		256
#define UET_DEV_CQE_SIZE		64
#define UET_DEV_MAX_SGE			8

/* work request opcodes... */
/* Send/Receive. */
#define UET_DEV_WR_SEND			0
#define UET_DEV_WR_SEND_IMM		1
#define UET_DEV_WR_RECV			2
/* RMA. */
#define UET_DEV_WR_RDMA_WRITE		3
#define UET_DEV_WR_RDMA_WRITE_IMM	4
#define UET_DEV_WR_RDMA_READ		5
/* Receive WRITE_IMM immediate without having to post a receive work request.
 * Completion only, never a work request. An RDMA write carrying immediate
 * data produces a completion at the target. It needs an opcode of its own
 * as this is a completion on the target side.
 */
#define UET_DEV_WR_RECV_RDMA_IMM	6

/* work request flags */
#define UET_DEV_WR_F_SIGNALED		(1u << 0)
	/* Set by the provider when the immediate is 64 bits rather than
	 * 32. This device does not read it: the immediate always travels
	 * in the WQE's 64-bit field and the consumer decides the width
	 * it wants, so the flag is informational here. A device that
	 * packs the two differently would need it.
	 */
#define UET_DEV_WR_F_IMM64		(1u << 1)
#define UET_DEV_WR_F_AH			(1u << 2) /* addr_index is an AH handle */

/* A segment names a key, not a region handle. The device resolves it
 * against its own region table, so an invalid key becomes a completion
 * error rather than a bad pointer inside the device.
 */
struct uet_dev_sge {
	uint64_t addr;
	uint64_t key;
	uint32_t len;
	uint32_t rsvd;
};

/* work request queue entry */
struct uet_dev_wqe {
	uint64_t wr_id;		/* handed back in the completion */
	uint32_t opcode;	/* UET_DEV_WR_* */
	uint32_t flags;		/* UET_DEV_WR_F_* */
	uint32_t num_sge;
	     /* Where this is going. An index into the job's address table,
	      * or, with UET_DEV_WR_F_AH set, an address handle.
	      */
	uint32_t addr_index;
	     /* The job key value the application was given, not a JobID.
	      * Zero means the one the queue pair was created with.
	      */
	uint32_t jkey;
	uint32_t rsvd0;
	uint64_t imm;
	uint64_t remote_addr;
	uint64_t remote_key;
	uint64_t rsvd1;
	struct uet_dev_sge sge[UET_DEV_MAX_SGE];
};

/* completion flags */
/* A receive completion with immediate data. */
#define UET_DEV_CQE_F_IMM		(1u << 0)

/* completion status */
#define UET_DEV_WC_SUCCESS		0
#define UET_DEV_WC_GENERAL_ERR		1
#define UET_DEV_WC_BAD_KEY		2
#define UET_DEV_WC_BAD_ADDR		3
#define UET_DEV_WC_TOO_LONG		4
#define UET_DEV_WC_FLUSHED		5
#define UET_DEV_WC_BAD_JOB		6
#define UET_DEV_WC_BAD_LOCAL_ADDR	7

/* completion queue entry */
struct uet_dev_cqe {
	uint64_t wr_id;
	uint64_t imm;
	uint32_t status;	/* UET_DEV_WC_* */
	uint32_t opcode;	/* the UET_DEV_WR_* that produced it */
	uint32_t byte_len;
	uint32_t flags;
	uint32_t qpn;
	uint32_t src_id;
	uint32_t job_id;
	     /* How far the device has consumed the ring this request came
	      * from. It is the only way the driver can know a WQE ring slot
	      * is reusable.
	      */
	uint32_t ring_cons;
	     /* Written last and checked first. The guest sees a complete
	      * entry or none of it. Toggles each time the ring wraps.
	      */
	uint32_t valid;
	uint32_t rsvd1[3];
};

/* payload of UET_DEV_ADMIN_CQ_CREATE, written in buf_addr */
struct uet_dev_admin_cq_create {
	struct uet_dev_ring_desc ring;
	uint32_t db_page;	/* which doorbell page may ring this queue */
	uint32_t vector;	/* MSI-X vector to raise, when armed */
};

/* The ring walk indexes by these sizes, so a field added without adjusting
 * the reserved space would silently shift every entry after the first (ERR!).
 */
#ifndef __KERNEL__
_Static_assert(sizeof(struct uet_dev_wqe) == UET_DEV_WQE_SIZE,
	       "work request entry must stay UET_DEV_WQE_SIZE");
_Static_assert(sizeof(struct uet_dev_cqe) == UET_DEV_CQE_SIZE,
	       "completion entry must stay UET_DEV_CQE_SIZE");
#endif

/* payload of UET_DEV_ADMIN_QP_CREATE, written in buf_addr */
struct uet_dev_admin_qp_create {
	uint32_t qpn;		/* [ABS 1b | rsvd 7b | RI 12b | PIDonFEP 12b] */
	uint32_t pd;		/* the protection domain id */
	uint32_t send_cq;	/* device completion queue handles */
	uint32_t recv_cq;
	uint32_t src_id;	/* SES initiator field */
	uint32_t jkey_handle;	/* relative = job, absolute = 0 */
	uint32_t flags;
	uint32_t max_send_wr;
	uint32_t max_recv_wr;
	uint32_t max_send_sge;
	uint32_t max_recv_sge;
	uint32_t db_page;	/* which doorbell page may ring this qp */
	     /* Largest payload this QP puts in a packet, in bytes. Normally
	      * zero: the modify to RTS sets it, as the queue pair is enabled.
	      * Zero takes the instance's. A queue pair may ask for less than
	      * the link allows, never more, and asking for more is an error.
	      */
	uint32_t path_mtu;
	     /* The send and receive rings, allocated by the guest and read
	      * by the device.
	      */
	struct uet_dev_ring_desc sq;
	struct uet_dev_ring_desc rq;
};

/* payload of UET_DEV_ADMIN_JOB_QUERY, written in buf_addr */
struct uet_dev_admin_job_info {
	uint32_t job_id;
	uint32_t max_addr_entries;
	uint32_t flags;
	uint8_t port_num;
	uint8_t sgid_index;
	uint16_t rsvd;
};

/* One address table entry. The network half of an extended address handle
 * plus the transport half as a remote QPN, which is where the addressing
 * mode, resource index and PIDonFEP live.
 */
struct uet_dev_admin_addr {
	uint8_t dgid[16];
	uint32_t remote_qpn;
	uint32_t flow_label;
	uint8_t dmac[6];
	uint8_t sl;
	uint8_t traffic_class;
	uint8_t hop_limit;
	uint8_t sgid_index;
	uint8_t port_num;
	uint8_t is_global;
	uint32_t rsvd;
};

/* ---------------------------------------------------------------- */
/* BAR3 - user doorbell pages                                       */
/* ---------------------------------------------------------------- */

/* One 4 KiB page per ucontext, mapped into the owning process. Every
 * doorbell is a single 64-bit write, so the handle and the index can never
 * be observed apart. The device refuses a doorbell whose handle is not
 * owned by the context the page belongs to.
 *
 * Note that these doorbells should not be confused with those doorbells
 * exposed in BAR2 for the L2 rings and the admin queue. Those are written
 * only by the kernel driver.
 */
#define UET_DEV_DB_PAGE_SIZE		0x1000
#define UET_DEV_MAX_DB_PAGES		64
#define UET_DEV_BAR3_SIZE		(UET_DEV_MAX_DB_PAGES * \
					 UET_DEV_DB_PAGE_SIZE)

#define UET_DEV_DB_SQ			0x00 /* ((qp << 32) | prod_idx) */
#define UET_DEV_DB_RQ			0x08 /* ((qp << 32) | prod_idx) */
#define UET_DEV_DB_CQ			0x10 /* (arm | (cq << 32) | cons_idx) */

#define UET_DEV_DB_HANDLE_SHIFT		32
#define UET_DEV_DB_INDEX_MASK		0xffffffffULL
#define UET_DEV_DB_CQ_ARM		(1ULL << 63)
#define UET_DEV_DB_CQ_HANDLE_MASK	0x7fffffffULL

#endif /* _UET_DEV_ABI_H_ */

