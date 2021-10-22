/* SPDX-License-Identifier: GPL-2.0 */
/*
 * XDR tracepoints for nfsd
 *
 * Author: Chuck Lever <chuck.lever@oracle.com>
 *
 * Copyright (c) 2021, Oracle and/or its affiliates.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM nfsd_xdr

#if !defined(_NFSD_XDR_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _NFSD_XDR_TRACE_H

#include <linux/tracepoint.h>

#include <trace/events/fs.h>
#include <trace/events/nfs.h>

#define TRACE_SVC_XDR_FIELDS(r) \
		__field(u32, xid) \
		__field(u32, program) \
		__field(u32, version) \
		__field(u32, procedure) \
		__string(procname, svc_proc_name(r))

#define TRACE_SVC_XDR_ASSIGNS(r) \
		do { \
			__entry->xid = be32_to_cpu((r)->rq_xid); \
			__entry->program = (r)->rq_prog; \
			__entry->version = (r)->rq_vers; \
			__entry->procedure = (r)->rq_proc; \
			__assign_str(procname, svc_proc_name(r)); \
		} while (0)

#define TRACE_XDR_FORMAT	"xid=0x%08x %s: "

#define TRACE_XDR_VARARGS	__entry->xid, __get_str(procname)


DECLARE_EVENT_CLASS(svc_xdr_err_class,
	TP_PROTO(
		const struct svc_rqst *rqstp
	),
	TP_ARGS(rqstp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(unsigned int, netns_ino)
		__sockaddr(server, rqstp->rq_xprt->xpt_locallen)
		__sockaddr(client, rqstp->rq_xprt->xpt_remotelen)
	),
	TP_fast_assign(
		const struct svc_xprt *xprt = rqstp->rq_xprt;

		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->netns_ino = xprt->xpt_net->ns.inum;
		__assign_sockaddr(server, &xprt->xpt_local, xprt->xpt_locallen);
		__assign_sockaddr(client, &xprt->xpt_remote, xprt->xpt_remotelen);
	),
	TP_printk("xid=0x%08x NFSv%u %s",
		__entry->xid, __entry->version, __get_str(procname)
	)
);

#define DEFINE_SVC_XDR_ERR_EVENT(name) \
DEFINE_EVENT(svc_xdr_err_class, name, \
	TP_PROTO(const struct svc_rqst *rqstp), \
	TP_ARGS(rqstp))

DEFINE_SVC_XDR_ERR_EVENT(nfsd_garbage_args_err);
DEFINE_SVC_XDR_ERR_EVENT(nfsd_cant_encode_err);

#endif /* _NFSD_XDR_TRACE_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../fs/nfsd
#define TRACE_INCLUDE_FILE xdrtrace

#include <trace/define_trace.h>
