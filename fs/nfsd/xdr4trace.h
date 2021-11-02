/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Tracepoints for server-side NFSv4 XDR functions
 *
 * Author: Chuck Lever <chuck.lever@oracle.com>
 *
 * Copyright (c) 2021, Oracle and/or its affiliates.
 */

#include "xdr4.h"

/**
 ** Helper macros
 **/

#define TRACE_NFS4_STATEID_FIELDS \
		__field(u32, cl_boot) \
		__field(u32, cl_id) \
		__field(u32, si_id) \
		__field(u32, si_generation)

#define TRACE_NFS4_STATEID_ASSIGNS(stp) \
		do { \
			__entry->cl_boot = (stp)->si_opaque.so_clid.cl_boot; \
			__entry->cl_id = (stp)->si_opaque.so_clid.cl_id; \
			__entry->si_id = (stp)->si_opaque.so_id; \
			__entry->si_generation = (stp)->si_generation; \
		} while (0)

#define TRACE_NFS4_STATEID_FORMAT \
		"client=%08x:%08x stateid=%08x:%08x "

#define TRACE_NFS4_STATEID_VARARGS \
		__entry->cl_boot, __entry->cl_id, \
		__entry->si_id, __entry->si_generation


/**
 ** Event classes
 **/


/**
 ** Error reports
 **/

TRACE_EVENT_CONDITION(nfsd_compound_decode_err,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_op *op
	),
	TP_ARGS(argp, op),
	TP_CONDITION(op->status != nfs_ok),
	TP_STRUCT__entry(
		__field(unsigned int, netns_ino)
		__field(u32, xid)
		__field(unsigned long, status)
		__array(unsigned char, server, sizeof(struct sockaddr_in6))
		__array(unsigned char, client, sizeof(struct sockaddr_in6))
		__field(u32, opcnt)
		__field(u32, cur_op)
		__string(opname, nfsd4_op_name(op->opnum))
	),
	TP_fast_assign(
		const struct svc_rqst *rqstp = argp->rqstp;
		const struct svc_xprt *xprt = rqstp->rq_xprt;

		__entry->netns_ino = xprt->xpt_net->ns.inum;
		__entry->xid = be32_to_cpu(rqstp->rq_xid);
		__entry->status = be32_to_cpu(op->status);
		memcpy(__entry->server, &xprt->xpt_local, xprt->xpt_locallen);
		memcpy(__entry->client, &xprt->xpt_remote, xprt->xpt_remotelen);
		__entry->opcnt = argp->opcnt;
		__entry->cur_op = argp->opidx + 1;
		__assign_str(opname, nfsd4_op_name(op->opnum));
	),
	TP_printk("xid=0x%08x %s (%u/%u): status=%s",
		__entry->xid, __get_str(opname),
		__entry->cur_op, __entry->opcnt,
		show_nfs4_status(__entry->status)
	)
);

TRACE_EVENT_CONDITION(nfsd_compound_encode_err,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_op *op
	),
	TP_ARGS(resp, op),
	TP_CONDITION(op->status != nfs_ok),
	TP_STRUCT__entry(
		__field(unsigned int, netns_ino)
		__field(u32, xid)
		__field(unsigned long, status)
		__array(unsigned char, server, sizeof(struct sockaddr_in6))
		__array(unsigned char, client, sizeof(struct sockaddr_in6))
		__field(u32, opcnt)
		__field(u32, cur_op)
		__string(opname, nfsd4_op_name(op->opnum))
	),
	TP_fast_assign(
		const struct svc_rqst *rqstp = resp->rqstp;
		const struct svc_xprt *xprt = rqstp->rq_xprt;
		const struct nfsd4_compoundargs *argp = rqstp->rq_argp;

		__entry->netns_ino = xprt->xpt_net->ns.inum;
		__entry->xid = be32_to_cpu(rqstp->rq_xid);
		__entry->status = be32_to_cpu(op->status);
		memcpy(__entry->server, &xprt->xpt_local, xprt->xpt_locallen);
		memcpy(__entry->client, &xprt->xpt_remote, xprt->xpt_remotelen);
		__entry->opcnt = argp->opcnt;
		__entry->cur_op = resp->opcnt;
		__assign_str(opname, nfsd4_op_name(op->opnum));
	),
	TP_printk("xid=0x%08x %s (%u/%u): status=%s",
		__entry->xid, __get_str(opname),
		__entry->cur_op, __entry->opcnt,
		show_nfs4_status(__entry->status)
	)
);


/**
 ** Server-side argument decoding tracepoints
 **/


/**
 ** Server-side result encoding tracepoints
 **/


/**
 ** FATTR4 tracepoints
 **/

