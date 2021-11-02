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

TRACE_EVENT(nfsd_compound_decode_err,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		u32 args_opcnt,
		u32 resp_opcnt,
		u32 opnum,
		__be32 status
	),
	TP_ARGS(rqstp, args_opcnt, resp_opcnt, opnum, status),
	TP_STRUCT__entry(
		__field(unsigned int, netns_ino)
		__field(u32, xid)
		__field(unsigned long, status)
		__array(unsigned char, server, sizeof(struct sockaddr_in6))
		__array(unsigned char, client, sizeof(struct sockaddr_in6))
		__field(u32, args_opcnt)
		__field(u32, resp_opcnt)
		__field(u32, opnum)
	),
	TP_fast_assign(
		const struct svc_xprt *xprt = rqstp->rq_xprt;

		__entry->netns_ino = xprt->xpt_net->ns.inum;
		__entry->xid = be32_to_cpu(rqstp->rq_xid);
		__entry->status = be32_to_cpu(status);
		memcpy(__entry->server, &xprt->xpt_local, xprt->xpt_locallen);
		memcpy(__entry->client, &xprt->xpt_remote, xprt->xpt_remotelen);
		__entry->args_opcnt = args_opcnt;
		__entry->resp_opcnt = resp_opcnt;
		__entry->opnum = opnum;
	),
	TP_printk("op=%u/%u opnum=%u status=%lu",
		__entry->resp_opcnt, __entry->args_opcnt,
		__entry->opnum, __entry->status)
);

TRACE_EVENT(nfsd_compound_encode_err,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		u32 opnum,
		__be32 status
	),
	TP_ARGS(rqstp, opnum, status),
	TP_STRUCT__entry(
		__field(unsigned int, netns_ino)
		__field(u32, xid)
		__field(unsigned long, status)
		__array(unsigned char, server, sizeof(struct sockaddr_in6))
		__array(unsigned char, client, sizeof(struct sockaddr_in6))
		__field(u32, opnum)
	),
	TP_fast_assign(
		const struct svc_xprt *xprt = rqstp->rq_xprt;

		__entry->netns_ino = xprt->xpt_net->ns.inum;
		__entry->xid = be32_to_cpu(rqstp->rq_xid);
		__entry->status = be32_to_cpu(status);
		memcpy(__entry->server, &xprt->xpt_local, xprt->xpt_locallen);
		memcpy(__entry->client, &xprt->xpt_remote, xprt->xpt_remotelen);
		__entry->opnum = opnum;
	),
	TP_printk("opnum=%u status=%lu",
		__entry->opnum, __entry->status)
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

