/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Tracepoints for server-side NFSv3 XDR functions
 *
 * Author: Chuck Lever <chuck.lever@oracle.com>
 *
 * Copyright (c) 2021, Oracle and/or its affiliates.
 */

#include "xdr3.h"

/**
 ** Helpers
 **/


/**
 ** Event classes
 **/

DECLARE_EVENT_CLASS(svc_xdr_server_time3_class,
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
	TP_printk(TRACE_XDR_FORMAT,
		TRACE_XDR_VARARGS
	)
);
#define DEFINE_XDR_SERVER_TIME3_EVENT(name) \
DEFINE_EVENT(svc_xdr_server_time3_class, name, \
	TP_PROTO( \
		const struct svc_rqst *rqstp \
	), \
	TP_ARGS(rqstp))

DEFINE_XDR_SERVER_TIME3_EVENT(dec_sattr3_server_atime);
DEFINE_XDR_SERVER_TIME3_EVENT(dec_sattr3_server_mtime);


/**
 ** Server-side argument decoding tracepoints
 **/

TRACE_EVENT(dec_access3args,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_accessargs *args
	),
	TP_ARGS(rqstp, args),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, fh_hash)
		__field(unsigned long, access)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->fh_hash = knfsd_fh_hash(&args->fh.fh_handle);
		__entry->access = args->access;
	),
	TP_printk(TRACE_XDR_FORMAT "fh_hash=0x%08x access=%s",
		TRACE_XDR_VARARGS,
		__entry->fh_hash, show_nfs3_access_flags(__entry->access)
	)
);

TRACE_EVENT(dec_dirop3args,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_diropargs *args
	),
	TP_ARGS(rqstp, args),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, fh_hash)
		__string_len(name, name, args->len)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->fh_hash = knfsd_fh_hash(&args->fh.fh_handle);
		__assign_str_len(name, args->name, args->len);
	),
	TP_printk(TRACE_XDR_FORMAT "fh_hash=0x%08x name=%s",
		TRACE_XDR_VARARGS,
		__entry->fh_hash, __get_str(name)
	)
);

TRACE_EVENT(dec_fhandle3args,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd_fhandle *args
	),
	TP_ARGS(rqstp, args),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, fh_hash)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->fh_hash = knfsd_fh_hash(&args->fh.fh_handle);
	),
	TP_printk(TRACE_XDR_FORMAT "fh_hash=0x%08x",
		TRACE_XDR_VARARGS, __entry->fh_hash
	)
);

TRACE_EVENT(dec_sattr3args,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_sattrargs *args
	),
	TP_ARGS(rqstp, args),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, fh_hash)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->fh_hash = knfsd_fh_hash(&args->fh.fh_handle);
	),
	TP_printk(TRACE_XDR_FORMAT "fh_hash=0x%08x",
		TRACE_XDR_VARARGS, __entry->fh_hash
	)
);

TRACE_EVENT(dec_sattr3_mode,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct iattr *iap
	),
	TP_ARGS(rqstp, iap),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, mode)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->mode = iap->ia_mode;
	),
	TP_printk(TRACE_XDR_FORMAT "mode=%o",
		TRACE_XDR_VARARGS, __entry->mode
	)
);

TRACE_EVENT(dec_sattr3_uid,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct iattr *iap
	),
	TP_ARGS(rqstp, iap),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, uid)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->uid = (u32)iap->ia_uid.val;
	),
	TP_printk(TRACE_XDR_FORMAT "uid=%u",
		TRACE_XDR_VARARGS, __entry->uid
	)
);

TRACE_EVENT(dec_sattr3_gid,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct iattr *iap
	),
	TP_ARGS(rqstp, iap),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, gid)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->gid = (u32)iap->ia_gid.val;
	),
	TP_printk(TRACE_XDR_FORMAT "gid=%u",
		TRACE_XDR_VARARGS, __entry->gid
	)
);

TRACE_EVENT(dec_sattr3_size,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct iattr *iap
	),
	TP_ARGS(rqstp, iap),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(long long, size)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->size = iap->ia_size;
	),
	TP_printk(TRACE_XDR_FORMAT "size=%lld",
		TRACE_XDR_VARARGS, __entry->size
	)
);

TRACE_EVENT(dec_sattr3_atime,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct iattr *iap
	),
	TP_ARGS(rqstp, iap),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(s64, atime_sec)
		__field(long, atime_nsec)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->atime_sec = iap->ia_atime.tv_sec;
		__entry->atime_nsec = iap->ia_atime.tv_nsec;
	),
	TP_printk(TRACE_XDR_FORMAT "atime=[%llx, %lx]",
		TRACE_XDR_VARARGS,
		__entry->atime_sec, __entry->atime_nsec
	)
);

TRACE_EVENT(dec_sattr3_mtime,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct iattr *iap
	),
	TP_ARGS(rqstp, iap),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(s64, mtime_sec)
		__field(long, mtime_nsec)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->mtime_sec = iap->ia_mtime.tv_sec;
		__entry->mtime_nsec = iap->ia_mtime.tv_nsec;
	),
	TP_printk(TRACE_XDR_FORMAT "mtime=[%llx, %lx]",
		TRACE_XDR_VARARGS,
		__entry->mtime_sec, __entry->mtime_nsec
	)
);

TRACE_EVENT(dec_sattrguard3,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		u32 guardtime
	),
	TP_ARGS(rqstp, guardtime),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(s64, obj_ctime_sec)
		__field(long, obj_ctime_nsec)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->obj_ctime_sec = guardtime;
		__entry->obj_ctime_nsec = 0;
	),
	TP_printk(TRACE_XDR_FORMAT "obj_ctime=[%llx, %lx]",
		TRACE_XDR_VARARGS,
		__entry->obj_ctime_sec, __entry->obj_ctime_nsec
	)
);


/**
 ** Server-side result encoding tracepoints
 **/

