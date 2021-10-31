/* SPDX-License-Identifier: GPL-2.0 */
/*
 * XDR tracepoints for lockd
 *
 * Author: Chuck Lever <chuck.lever@oracle.com>
 *
 * Copyright (c) 2021, Oracle and/or its affiliates.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM lockd_xdr

#if !defined(_LOCKD_XDR_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _LOCKD_XDR_TRACE_H

#include <linux/tracepoint.h>

#include <linux/lockd/nlm.h>
#include <linux/lockd/xdr.h>
#include <linux/sunrpc/svc.h>
#include <linux/sunrpc/svc_xprt.h>

#include <trace/events/fs.h>
#include <trace/events/nfs.h>

/**
 ** Helpers
 **/

TRACE_DEFINE_ENUM(NLM_LCK_GRANTED);
TRACE_DEFINE_ENUM(NLM_LCK_DENIED);
TRACE_DEFINE_ENUM(NLM_LCK_DENIED_NOLOCKS);
TRACE_DEFINE_ENUM(NLM_LCK_BLOCKED);
TRACE_DEFINE_ENUM(NLM_LCK_DENIED_GRACE_PERIOD);
#ifdef CONFIG_LOCKD_V4
TRACE_DEFINE_ENUM(NLM_DEADLCK);
TRACE_DEFINE_ENUM(NLM_ROFS);
TRACE_DEFINE_ENUM(NLM_STALE_FH);
TRACE_DEFINE_ENUM(NLM_FBIG);
TRACE_DEFINE_ENUM(NLM_FAILED);
#endif /* CONFIG_LOCKD_V4 */

#ifndef CONFIG_LOCKD_V4
#define show_nlm_status(x) \
	__print_symbolic(x, \
		{ NLM_LCK_GRANTED,		"GRANTED" }, \
		{ NLM_LCK_DENIED,		"DENIED" }, \
		{ NLM_LCK_DENIED_NOLOCKS,	"DENIED_NOLOCKS" }, \
		{ NLM_LCK_BLOCKED,		"BLOCKED" }, \
		{ NLM_LCK_DENIED_GRACE_PERIOD,	"DENIED_GRACE_PERIOD" })
#else
#define show_nlm_status(x) \
	__print_symbolic(x, \
		{ NLM_LCK_GRANTED,		"GRANTED" }, \
		{ NLM_LCK_DENIED,		"DENIED" }, \
		{ NLM_LCK_DENIED_NOLOCKS,	"DENIED_NOLOCKS" }, \
		{ NLM_LCK_BLOCKED,		"BLOCKED" }, \
		{ NLM_LCK_DENIED_GRACE_PERIOD,	"DENIED_GRACE_PERIOD" }, \
		{ NLM_DEADLCK,			"DEADLCK" }, \
		{ NLM_ROFS,			"ROFS" }, \
		{ NLM_STALE_FH,			"STALE_FH" }, \
		{ NLM_FBIG,			"FBIG" }, \
		{ NLM_FAILED,			"FAILED" })
#endif /* CONFIG_LOCKD_V4 */

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


/**
 ** Event classes
 **/

DECLARE_EVENT_CLASS(svc_xdr_void_class,
	TP_PROTO(
		const struct svc_rqst *rqstp
	),
	TP_ARGS(rqstp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);
	),
	TP_printk(TRACE_XDR_FORMAT, TRACE_XDR_VARARGS)
);
#define DEFINE_SVC_XDR_VOID_EVENT(name) \
DEFINE_EVENT(svc_xdr_void_class, name, \
	TP_PROTO(const struct svc_rqst *rqstp), \
	TP_ARGS(rqstp))

DEFINE_SVC_XDR_VOID_EVENT(dec_nlm_voidargs);


/**
 ** Server-side argument decoding tracepoints
 **/

TRACE_EVENT(dec_cancargs,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nlm_args *args
	),
	TP_ARGS(rqstp, args),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, cookie_hash)
		__field(bool, block)
		__field(bool, exclusive)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->cookie_hash = nfs_cookie_hash(&args->cookie);
		__entry->exclusive = (args->lock.fl.fl_type == F_WRLCK);
		__entry->block = args->block;
	),
	TP_printk(TRACE_XDR_FORMAT "cookie_hash=0x%08x%s block=%s",
		TRACE_XDR_VARARGS, __entry->cookie_hash,
		__entry->exclusive ? " (exclusive)" : "",
		__entry->block ? "yes" : "no"
	)
);

TRACE_EVENT(dec_grantedargs,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nlm_res *args
	),
	TP_ARGS(rqstp, args),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, cookie_hash)
		__field(unsigned long, status)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->cookie_hash = nfs_cookie_hash(&args->cookie);
		__entry->status = be32_to_cpu(args->status);
	),
	TP_printk(TRACE_XDR_FORMAT "cookie_hash=0x%08x status=%s",
		TRACE_XDR_VARARGS,
		__entry->cookie_hash, show_nlm_status(__entry->status)
	)
);

TRACE_EVENT(dec_lockargs,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nlm_args *args
	),
	TP_ARGS(rqstp, args),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, cookie_hash)
		__field(u32, nsm_state)
		__field(bool, block)
		__field(bool, reclaim)
		__field(bool, exclusive)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->cookie_hash = nfs_cookie_hash(&args->cookie);
		__entry->nsm_state = args->state;
		__entry->exclusive = (args->lock.fl.fl_type == F_WRLCK);
		__entry->block = args->block;
		__entry->reclaim = args->reclaim;
	),
	TP_printk(TRACE_XDR_FORMAT "cookie_hash=0x%08x%s "
		"block=%s reclaim=%s nsm_state=%u",
		TRACE_XDR_VARARGS, __entry->cookie_hash,
		__entry->exclusive ? " (exclusive)" : "",
		__entry->block ? "yes" : "no", __entry->reclaim ? "yes" : "no",
		__entry->nsm_state
	)
);

TRACE_EVENT(dec_nlm_lock_arg,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nlm_lock *lock,
		s64 start,
		s64 len
	),
	TP_ARGS(rqstp, lock, start, len),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, fh_hash)
		__field(u32, uppid)
		__field(loff_t, offset)
		__field(loff_t, len)
		__field(unsigned long, type)
		__string_len(caller, caller, lock->len)
		__string_len(owner, owner, lock->oh.len)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->fh_hash = nfs_fhandle_hash(&lock->fh);
		__entry->uppid = lock->svid;
		__entry->offset = start;
		__entry->len = len;
		__assign_str_len(caller, lock->caller, lock->len);
		__assign_str_len(owner, lock->oh.data, lock->oh.len);
	),
	TP_printk(TRACE_XDR_FORMAT
		"fh_hash=0x%08x uppid=%x offset=%lld len=%lld",
		TRACE_XDR_VARARGS,
		__entry->fh_hash, __entry->uppid, __entry->offset, __entry->len
	)
);

TRACE_EVENT(dec_testargs,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nlm_args *args
	),
	TP_ARGS(rqstp, args),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, cookie_hash)
		__field(bool, exclusive)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->cookie_hash = nfs_cookie_hash(&args->cookie);
		__entry->exclusive = (args->lock.fl.fl_type == F_WRLCK);
	),
	TP_printk(TRACE_XDR_FORMAT "cookie_hash=0x%08x%s",
		TRACE_XDR_VARARGS, __entry->cookie_hash,
		__entry->exclusive ? " (exclusive)" : ""
	)
);

TRACE_EVENT(dec_unlockargs,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nlm_args *args
	),
	TP_ARGS(rqstp, args),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, cookie_hash)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->cookie_hash = nfs_cookie_hash(&args->cookie);
	),
	TP_printk(TRACE_XDR_FORMAT "cookie_hash=0x%08x",
		TRACE_XDR_VARARGS, __entry->cookie_hash
	)
);


/**
 ** Server-side result encoding tracepoints
 **/


#endif /* _LOCKD_XDR_TRACE_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../fs/lockd
#define TRACE_INCLUDE_FILE xdrtrace

#include <trace/define_trace.h>
