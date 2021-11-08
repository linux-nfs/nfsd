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

#endif /* _NFSD_XDR_TRACE_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../fs/nfsd
#define TRACE_INCLUDE_FILE xdrtrace

#include <trace/define_trace.h>
