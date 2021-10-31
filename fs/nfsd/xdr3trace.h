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

DECLARE_EVENT_CLASS(svc_xdr_create3args_class,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_createargs *args
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
#define DEFINE_SVC_XDR_CREATE3ARGS_EVENT(name) \
DEFINE_EVENT(svc_xdr_create3args_class, name, \
	TP_PROTO( \
		const struct svc_rqst *rqstp, \
		const struct nfsd3_createargs *args \
	), \
	TP_ARGS(rqstp, args))

DEFINE_SVC_XDR_CREATE3ARGS_EVENT(dec_create3args_unchecked);
DEFINE_SVC_XDR_CREATE3ARGS_EVENT(dec_create3args_guarded);
DEFINE_SVC_XDR_CREATE3ARGS_EVENT(dec_mkdir3args);

DECLARE_EVENT_CLASS(svc_xdr_fattr3_class,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct svc_fh *fhp,
		const struct kstat *stat
	),
	TP_ARGS(rqstp, fhp, stat),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, fh_hash)
		__field(unsigned long, type)
		__field(unsigned int, mode)
		__field(u32, uid)
		__field(u32, gid)
		__field(s64, atime_sec)
		__field(long, atime_nsec)
		__field(s64, mtime_sec)
		__field(long, mtime_nsec)
		__field(s64, ctime_sec)
		__field(long, ctime_nsec)
	),
	TP_fast_assign(
		struct user_namespace *userns = nfsd_user_namespace(rqstp);

		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->fh_hash = knfsd_fh_hash(&fhp->fh_handle);
		__entry->type = stat->mode & S_IFMT;
		__entry->mode = stat->mode & S_IALLUGO;
		__entry->uid = (u32)from_kuid_munged(userns, stat->uid);
		__entry->gid = (u32)from_kgid_munged(userns, stat->gid);
		__entry->atime_sec = stat->atime.tv_sec;
		__entry->atime_nsec = stat->atime.tv_nsec;
		__entry->mtime_sec = stat->mtime.tv_sec;
		__entry->mtime_nsec = stat->mtime.tv_nsec;
		__entry->ctime_sec = stat->ctime.tv_sec;
		__entry->ctime_nsec = stat->ctime.tv_nsec;
	),
	TP_printk(TRACE_XDR_FORMAT
		"fh_hash=0x%08x mtime=[%llx, %lx] ctime=[%llx, %lx] "
		"type=%s mode=%o uid=%u gid=%u",
		TRACE_XDR_VARARGS,
		__entry->fh_hash,
		__entry->mtime_sec, __entry->mtime_nsec,
		__entry->ctime_sec, __entry->ctime_nsec,
		show_fs_file_type(__entry->type),
		__entry->mode, __entry->uid, __entry->gid
	)
);
#define DEFINE_SVC_XDR_FATTR3_EVENT(name) \
DEFINE_EVENT(svc_xdr_fattr3_class, name, \
	TP_PROTO( \
		const struct svc_rqst *rqstp, \
		const struct svc_fh *fhp, \
		const struct kstat *stat \
	), \
	TP_ARGS(rqstp, fhp, stat))

DEFINE_SVC_XDR_FATTR3_EVENT(enc_getattr3resok);
DEFINE_SVC_XDR_FATTR3_EVENT(enc_post_op_attr);
DEFINE_SVC_XDR_FATTR3_EVENT(enc_wcc_data_post_attr);

DECLARE_EVENT_CLASS(svc_xdr_resfail_class,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		__be32 status
	),
	TP_ARGS(rqstp, status),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(unsigned long, status)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->status = be32_to_cpu(status);
	),
	TP_printk(TRACE_XDR_FORMAT "status=%s",
		TRACE_XDR_VARARGS, show_nfs_status(__entry->status)
	)
);
#define DEFINE_SVC_XDR_RESFAIL_EVENT(name) \
DEFINE_EVENT(svc_xdr_resfail_class, name, \
	TP_PROTO( \
		const struct svc_rqst *rqstp, \
		__be32 status \
	), \
	TP_ARGS(rqstp, status))

DEFINE_SVC_XDR_RESFAIL_EVENT(enc_access3resfail);
DEFINE_SVC_XDR_RESFAIL_EVENT(enc_commit3resfail);
DEFINE_SVC_XDR_RESFAIL_EVENT(enc_create3resfail);
DEFINE_SVC_XDR_RESFAIL_EVENT(enc_fsinfo3resfail);
DEFINE_SVC_XDR_RESFAIL_EVENT(enc_fsstat3resfail);
DEFINE_SVC_XDR_RESFAIL_EVENT(enc_getacl3resfail);
DEFINE_SVC_XDR_RESFAIL_EVENT(enc_getattr3resfail);
DEFINE_SVC_XDR_RESFAIL_EVENT(enc_link3resfail);
DEFINE_SVC_XDR_RESFAIL_EVENT(enc_lookup3resfail);
DEFINE_SVC_XDR_RESFAIL_EVENT(enc_pathconf3resfail);
DEFINE_SVC_XDR_RESFAIL_EVENT(enc_read3resfail);
DEFINE_SVC_XDR_RESFAIL_EVENT(enc_readdir3resfail);
DEFINE_SVC_XDR_RESFAIL_EVENT(enc_readlink3resfail);
DEFINE_SVC_XDR_RESFAIL_EVENT(enc_rename3resfail);
DEFINE_SVC_XDR_RESFAIL_EVENT(enc_setacl3resfail);
DEFINE_SVC_XDR_RESFAIL_EVENT(enc_wccstat3resfail);
DEFINE_SVC_XDR_RESFAIL_EVENT(enc_write3resfail);

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

TRACE_EVENT(dec_commit3args,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_commitargs *args
	),
	TP_ARGS(rqstp, args),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, fh_hash)
		__field(u32, count)
		__field(u64, offset)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->fh_hash = knfsd_fh_hash(&args->fh.fh_handle);
		__entry->count = args->count;
		__entry->offset = args->offset;
	),
	TP_printk(TRACE_XDR_FORMAT "fh_hash=0x%08x count=%u offset=%llu",
		TRACE_XDR_VARARGS,
		__entry->fh_hash, __entry->count, __entry->offset
	)
);

TRACE_EVENT(dec_create3args_exclusive,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_createargs *args
	),
	TP_ARGS(rqstp, args),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, fh_hash)
		__array(u8, createverf, NFS3_CREATEVERFSIZE)
		__string_len(name, name, args->len)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->fh_hash = knfsd_fh_hash(&args->fh.fh_handle);
		memcpy(__entry->createverf, args->verf, NFS3_CREATEVERFSIZE);
		__assign_str_len(name, args->name, args->len);
	),
	TP_printk(TRACE_XDR_FORMAT "fh_hash=0x%08x name=%s createverf=%s",
		TRACE_XDR_VARARGS, __entry->fh_hash, __get_str(name),
		__print_hex(__entry->createverf, NFS3_CREATEVERFSIZE)
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

TRACE_EVENT(dec_getacl3args,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_getaclargs *args
	),
	TP_ARGS(rqstp, args),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, fh_hash)
		__field(u32, mask)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->fh_hash = knfsd_fh_hash(&args->fh.fh_handle);
		__entry->mask = args->mask;
	),
	TP_printk(TRACE_XDR_FORMAT "fh_hash=0x%08x mask=%s",
		TRACE_XDR_VARARGS,
		__entry->fh_hash, show_nfs3_acl_mask(__entry->mask)
	)
);

TRACE_EVENT(dec_link3args,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_linkargs *args
	),
	TP_ARGS(rqstp, args),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, from_fh_hash)
		__field(u32, to_fh_hash)
		__string_len(to_name, to_name, args->tlen)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->from_fh_hash = knfsd_fh_hash(&args->ffh.fh_handle);
		__entry->to_fh_hash = knfsd_fh_hash(&args->tfh.fh_handle);
		__assign_str_len(to_name, args->tname, args->tlen);
	),
	TP_printk(TRACE_XDR_FORMAT
		"from_fh_hash=0x%08x to_fh_hash=0x%08x to_name=%s",
		TRACE_XDR_VARARGS,
		__entry->from_fh_hash,
		__entry->to_fh_hash, __get_str(to_name)
	)
);

TRACE_EVENT(dec_mknod3args,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_mknodargs *args
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

TRACE_EVENT(dec_read3args,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_readargs *args
	),
	TP_ARGS(rqstp, args),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, fh_hash)
		__field(u32, count)
		__field(u64, offset)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->fh_hash = knfsd_fh_hash(&args->fh.fh_handle);
		__entry->count = args->count;
		__entry->offset = args->offset;
	),
	TP_printk(TRACE_XDR_FORMAT "fh_hash=0x%08x count=%u offset=%llu",
		TRACE_XDR_VARARGS,
		__entry->fh_hash, __entry->count, __entry->offset
	)
);

TRACE_EVENT(dec_readdir3args,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_readdirargs *args
	),
	TP_ARGS(rqstp, args),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, fh_hash)
		__field(u32, count)
		__field(u64, cookie)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->fh_hash = knfsd_fh_hash(&args->fh.fh_handle);
		__entry->count = args->count;
		__entry->cookie = args->cookie;
	),
	TP_printk(TRACE_XDR_FORMAT "fh_hash=0x%08x count=%u cookie=%llu",
		TRACE_XDR_VARARGS,
		__entry->fh_hash, __entry->count, __entry->cookie
	)
);

TRACE_EVENT(dec_rename3args,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_renameargs *args
	),
	TP_ARGS(rqstp, args),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, from_fh_hash)
		__string_len(from_name, from_name, args->flen)
		__field(u32, to_fh_hash)
		__string_len(to_name, to_name, args->tlen)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->from_fh_hash = knfsd_fh_hash(&args->ffh.fh_handle);
		__assign_str_len(from_name, args->fname, args->flen);
		__entry->to_fh_hash = knfsd_fh_hash(&args->tfh.fh_handle);
		__assign_str_len(to_name, args->tname, args->tlen);
	),
	TP_printk(TRACE_XDR_FORMAT
		"from_fh_hash=0x%08x from_name=%s "
		"to_fh_hash=0x%08x to_name=%s",
		TRACE_XDR_VARARGS,
		__entry->from_fh_hash, __get_str(from_name),
		__entry->to_fh_hash, __get_str(to_name)
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

TRACE_EVENT(dec_setacl3args,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_setaclargs *args
	),
	TP_ARGS(rqstp, args),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, fh_hash)
		__field(u32, mask)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->fh_hash = knfsd_fh_hash(&args->fh.fh_handle);
		__entry->mask = args->mask;
	),
	TP_printk(TRACE_XDR_FORMAT "fh_hash=0x%08x mask=%s",
		TRACE_XDR_VARARGS,
		__entry->fh_hash, show_nfs3_acl_mask(__entry->mask)
	)
);

TRACE_EVENT(dec_specdata3,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_mknodargs *args

	),
	TP_ARGS(rqstp, args),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, major)
		__field(u32, minor)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->major = args->major;
		__entry->minor = args->minor;
	),
	TP_printk(TRACE_XDR_FORMAT "rdev=(%u, %u)",
		TRACE_XDR_VARARGS, __entry->major, __entry->minor
	)
);

TRACE_EVENT(dec_symlink3args,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_symlinkargs *args
	),
	TP_ARGS(rqstp, args),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, fh_hash)
		__field(u32, symlink_len)
		__string_len(symlink_name, symlink_name, args->flen)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->fh_hash = knfsd_fh_hash(&args->ffh.fh_handle);
		__entry->symlink_len = args->tlen;
		__assign_str_len(symlink_name, args->fname, args->flen);
	),
	TP_printk(TRACE_XDR_FORMAT
		"fh_hash=0x%08x symlink_name=%s symlink_len=%u",
		TRACE_XDR_VARARGS,
		__entry->fh_hash, __get_str(symlink_name), __entry->symlink_len
	)
);

TRACE_EVENT(dec_write3args,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_writeargs *args
	),
	TP_ARGS(rqstp, args),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, fh_hash)
		__field(u32, count)
		__field(u64, offset)
		__field(unsigned long, stable)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->fh_hash = knfsd_fh_hash(&args->fh.fh_handle);
		__entry->count = args->count;
		__entry->offset = args->offset;
		__entry->stable = args->stable
	),
	TP_printk(TRACE_XDR_FORMAT
		"fh_hash=0x%08x count=%u offset=%llu stable=%s",
		TRACE_XDR_VARARGS,
		__entry->fh_hash, __entry->count, __entry->offset,
		show_nfs_stable_how(__entry->stable)
	)
);


/**
 ** Server-side result encoding tracepoints
 **/

TRACE_EVENT(enc_access3resok,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_accessres *resp
	),
	TP_ARGS(rqstp, resp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(unsigned long, access)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->access = resp->access;
	),
	TP_printk(TRACE_XDR_FORMAT "access=%s",
		TRACE_XDR_VARARGS, show_nfs3_access_flags(__entry->access)
	)
);

TRACE_EVENT(enc_commit3resok,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_commitres *resp
	),
	TP_ARGS(rqstp, resp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__array(u8, writeverf, NFS3_WRITEVERFSIZE)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		memcpy(__entry->writeverf, resp->verf, NFS3_WRITEVERFSIZE);
	),
	TP_printk(TRACE_XDR_FORMAT "writeverf=%s",
		TRACE_XDR_VARARGS,
		__print_hex(__entry->writeverf, NFS3_WRITEVERFSIZE)
	)
);

TRACE_EVENT(enc_create3resok,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_diropres *resp
	),
	TP_ARGS(rqstp, resp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, fh_hash)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->fh_hash = knfsd_fh_hash(&resp->fh.fh_handle);
	),
	TP_printk(TRACE_XDR_FORMAT "fh_hash=0x%08x",
		TRACE_XDR_VARARGS, __entry->fh_hash
	)
);

TRACE_EVENT(enc_fsinfo3resok,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_fsinfores *resp
	),
	TP_ARGS(rqstp, resp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u64, rtmax)
		__field(u64, rtpref)
		__field(u64, rtmult)
		__field(u64, wtmax)
		__field(u64, wtpref)
		__field(u64, wtmult)
		__field(u32, dtpref)
		__field(u64, maxfilesize)
		__field(s64, time_delta_sec)
		__field(long, time_delta_nsec)
		__field(unsigned long, properties)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->rtmax = resp->f_rtmax;
		__entry->rtpref = resp->f_rtpref;
		__entry->rtmult = resp->f_rtmult;
		__entry->wtmax = resp->f_wtmax;
		__entry->wtpref = resp->f_wtpref;
		__entry->wtmult = resp->f_wtmult;
		__entry->dtpref = resp->f_dtpref;
		__entry->maxfilesize = resp->f_maxfilesize;
		__entry->properties = resp->f_properties;
	),
	TP_printk(TRACE_XDR_FORMAT
		"rt=%llu/%llu/%llu wt=%llu/%llu/%llu dt=%u maxfile=%llu prop=%s",
		TRACE_XDR_VARARGS,
		__entry->rtmax, __entry->rtpref, __entry->rtmult,
		__entry->wtmax, __entry->wtpref, __entry->wtmult,
		__entry->dtpref, __entry->maxfilesize,
		show_nfs3_fsf_properties(__entry->properties)
	)
);

TRACE_EVENT(enc_fsstat3resok,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_fsstatres *resp
	),
	TP_ARGS(rqstp, resp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u64, tbytes)
		__field(u64, fbytes)
		__field(u64, abytes)
		__field(u64, tfiles)
		__field(u64, ffiles)
		__field(u64, afiles)
		__field(u32, invarsec)
	),
	TP_fast_assign(
		const struct kstatfs *s = &resp->stats;
		u64 bs = s->f_bsize;

		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->tbytes = bs * s->f_blocks;
		__entry->fbytes = bs * s->f_bfree;
		__entry->abytes = bs * s->f_bavail;
		__entry->tfiles = s->f_files;
		__entry->ffiles = s->f_ffree;
		__entry->afiles = s->f_ffree;
		__entry->invarsec = resp->invarsec;
	),
	TP_printk(TRACE_XDR_FORMAT
		"bytes=%llu/%llu/%llu files=%llu/%llu/%llu invarsec=%u",
		TRACE_XDR_VARARGS,
		__entry->tbytes, __entry->fbytes, __entry->abytes,
		__entry->tfiles, __entry->ffiles, __entry->afiles,
		__entry->invarsec
	)
);

TRACE_EVENT(enc_getacl3resok,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_getaclres *resp
	),
	TP_ARGS(rqstp, resp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, mask)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->mask = resp->mask;
	),
	TP_printk(TRACE_XDR_FORMAT "mask=%s",
		TRACE_XDR_VARARGS,
		show_nfs3_acl_mask(__entry->mask)
	)
);

TRACE_EVENT(enc_lookup3resok,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_diropres *resp
	),
	TP_ARGS(rqstp, resp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, fh_hash)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->fh_hash = knfsd_fh_hash(&resp->fh.fh_handle);
	),
	TP_printk(TRACE_XDR_FORMAT "fh_hash=0x%08x",
		TRACE_XDR_VARARGS, __entry->fh_hash
	)
);

TRACE_EVENT(enc_pathconf3resok,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_pathconfres *resp
	),
	TP_ARGS(rqstp, resp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, linkmax)
		__field(u32, name_max)
		__field(bool, no_trunc)
		__field(bool, chown_restricted)
		__field(bool, case_insensitive)
		__field(bool, case_preserving)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->linkmax = resp->p_link_max;
		__entry->name_max = resp->p_name_max;
		__entry->no_trunc = !!resp->p_no_trunc;
		__entry->chown_restricted = !!resp->p_chown_restricted;
		__entry->case_insensitive = !!resp->p_case_insensitive;
		__entry->case_preserving = !!resp->p_case_preserving;
	),
	TP_printk(TRACE_XDR_FORMAT "linkmax=%u name_max=%u",
		TRACE_XDR_VARARGS, __entry->linkmax, __entry->name_max
	)
);

TRACE_EVENT(enc_read3resok,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_readres *resp
	),
	TP_ARGS(rqstp, resp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, count)
		__field(bool, eof)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->count = resp->count;
		__entry->eof = !!resp->eof;
	),
	TP_printk(TRACE_XDR_FORMAT "count=%u%s",
		TRACE_XDR_VARARGS,
		__entry->count, __entry->eof ? " (eof)" : ""
	)
);

TRACE_EVENT(enc_readdir3resok,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_readdirres *resp
	),
	TP_ARGS(rqstp, resp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, len)
		__field(bool, eof)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->len = resp->dirlist.len;
		__entry->eof = resp->common.err == nfserr_eof;
	),
	TP_printk(TRACE_XDR_FORMAT "len=%u%s",
		TRACE_XDR_VARARGS,
		__entry->len, __entry->eof ? " (eof)" : ""
	)
);

TRACE_EVENT(enc_entry3,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		 u64 ino,
		 const char *name,
		 int len),
	TP_ARGS(rqstp, ino, name, len),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u64, ino)
		__string_len(name, name, len)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->ino = ino;
		__assign_str_len(name, name, len)
	),
	TP_printk(TRACE_XDR_FORMAT "ino=%llu name=%s",
		TRACE_XDR_VARARGS, __entry->ino, __get_str(name)
	)
);

TRACE_EVENT(enc_entry3plus,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct svc_fh *fhp,
		 u64 ino,
		 const char *name,
		 int len),
	TP_ARGS(rqstp, fhp, ino, name, len),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, fh_hash)
		__field(u64, ino)
		__string_len(name, name, len)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->fh_hash = knfsd_fh_hash(&fhp->fh_handle);
		__entry->ino = ino;
		__assign_str_len(name, name, len)
	),
	TP_printk(TRACE_XDR_FORMAT "fh_hash=0x%08x ino=%llu name=%s",
		TRACE_XDR_VARARGS,
		__entry->fh_hash, __entry->ino, __get_str(name)
	)
);

TRACE_EVENT(enc_readlink3resok,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_readlinkres *resp
	),
	TP_ARGS(rqstp, resp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, len)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->len = resp->len;
	),
	TP_printk(TRACE_XDR_FORMAT "len=%u",
		TRACE_XDR_VARARGS, __entry->len
	)
);

TRACE_EVENT(enc_wcc_data_pre_attr,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct svc_fh *fhp
	),
	TP_ARGS(rqstp, fhp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, fh_hash)
		__field(u64, size)
		__field(s64, mtime_sec)
		__field(long, mtime_nsec)
		__field(s64, ctime_sec)
		__field(long, ctime_nsec)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->fh_hash = knfsd_fh_hash(&fhp->fh_handle);
		__entry->size = fhp->fh_pre_size;
		__entry->mtime_sec = fhp->fh_pre_mtime.tv_sec;
		__entry->mtime_nsec = fhp->fh_pre_mtime.tv_nsec;
		__entry->ctime_sec = fhp->fh_pre_ctime.tv_sec;
		__entry->ctime_nsec = fhp->fh_pre_ctime.tv_nsec;
	),
	TP_printk(TRACE_XDR_FORMAT "fh_hash=0x%08x "
		"mtime=[%llx, %lx] ctime=[%llx, %lx] size=%llu",
		TRACE_XDR_VARARGS,
		__entry->fh_hash,
		__entry->mtime_sec, __entry->mtime_nsec,
		__entry->ctime_sec, __entry->ctime_nsec,
		__entry->size
	)
);

TRACE_EVENT(enc_write3resok,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd3_writeres *resp
	),
	TP_ARGS(rqstp, resp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_FIELDS(rqstp)

		__field(u32, count)
		__field(unsigned long, committed)
		__array(u8, writeverf, NFS3_WRITEVERFSIZE)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_ASSIGNS(rqstp);

		__entry->count = resp->count;
		__entry->committed = resp->committed;
		memcpy(__entry->writeverf, resp->verf, NFS3_WRITEVERFSIZE);
	),
	TP_printk(TRACE_XDR_FORMAT
		"count=%u committed=%s writeverf=%s",
		TRACE_XDR_VARARGS,
		__entry->count, show_nfs_stable_how(__entry->committed),
		__print_hex(__entry->writeverf, NFS3_WRITEVERFSIZE)
	)
);

