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

#define TRACE_SVC_XDR_CMPD_FIELDS \
		__field(u32, xid) \
		__field(u32, opcnt) \
		__field(u32, cur_op) \
		__field(u32, minorversion)

#define TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(a) \
		do { \
			const struct svc_rqst *rqstp = (a)->rqstp; \
			__entry->xid = be32_to_cpu(rqstp->rq_xid); \
			__entry->opcnt = (a)->opcnt; \
			__entry->cur_op = (a)->opidx + 1; \
			__entry->minorversion = (a)->minorversion; \
		} while (0)

#define TRACE_SVC_XDR_CMPD_RES_ASSIGNS(r) \
		do { \
			const struct svc_rqst *rqstp = (r)->rqstp; \
			const struct nfsd4_compoundargs *argp = rqstp->rq_argp; \
			__entry->xid = be32_to_cpu(rqstp->rq_xid); \
			__entry->opcnt = argp->opcnt; \
			__entry->cur_op = resp->opcnt; \
			__entry->minorversion = argp->minorversion; \
		} while (0)

#define TRACE_XDR_CMPD_FORMAT \
		"xid=0x%08x (%u/%u): "

#define TRACE_XDR_CMPD_VARARGS \
		__entry->xid, __entry->cur_op, __entry->opcnt

#define TRACE_NFS4_BITMAP_FIELDS \
		__field(unsigned long, word0) \
		__field(unsigned long, word1) \
		__field(unsigned long, word2)

#define TRACE_NFS4_BITMAP_ASSIGNS(b) \
		do { \
			__entry->word0 = (b)[0]; \
			__entry->word1 = (b)[1]; \
			__entry->word2 = (b)[2]; \
		} while (0)

#define TRACE_NFS4_BITMAP_FORMAT \
		"word0=%s word1=%s word2=%s "

#define TRACE_NFS4_BITMAP_VARARGS \
		show_nfs4_fattr4_bm_word0(__entry->word0), \
		show_nfs4_fattr4_bm_word1(__entry->word1), \
		show_nfs4_fattr4_bm_word2(__entry->word2)

#define TRACE_NFS4_CINFO_FIELDS \
		__field(bool, atomic) \
		__field(u64, before) \
		__field(u64, after)

#define TRACE_NFS4_CINFO_ASSIGNS(c) \
		do { \
			__entry->atomic = !!(c).atomic; \
			__entry->before = (c).before_change; \
			__entry->after = (c).after_change; \
		} while (0)

#define TRACE_NFS4_CINFO_FORMAT \
		"cinfo-delta=%llu%s "

#define TRACE_NFS4_CINFO_VARARGS \
		(__entry->after - __entry->before), \
		(__entry->atomic ? " (atomic)" : "")

#define TRACE_NFS4_CLID_FIELDS \
		__field(u32, cl_boot) \
		__field(u32, cl_id)

#define TRACE_NFS4_CLID_ASSIGNS(clid) \
		do { \
			__entry->cl_boot = (clid).cl_boot; \
			__entry->cl_id = (clid).cl_id; \
		} while (0)

#define TRACE_NFS4_CLID_FORMAT \
		"client=%08x:%08x "

#define TRACE_NFS4_CLID_VARARGS \
		__entry->cl_boot, __entry->cl_id

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

#define TRACE_NFS4_VERIFIER_FIELD \
		__array(u8, verifier, NFS4_VERIFIER_SIZE)

#define TRACE_NFS4_VERIFIER_ASSIGN(verf) \
		memcpy(__entry->verifier, (verf).data, NFS4_VERIFIER_SIZE)

#define TRACE_NFS4_VERIFIER_FORMAT \
		"verifier=%s "

#define TRACE_NFS4_VERIFIER_VARARG \
		show_nfs4_verifier(__entry->verifier)

/**
 ** Event classes
 **/

DECLARE_EVENT_CLASS(svc_xdr_noop4args_class,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp
	),
	TP_ARGS(argp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT, TRACE_XDR_CMPD_VARARGS
	)
);
#define DEFINE_SVC_XDR_NOOP4ARGS_EVENT(name) \
DEFINE_EVENT(svc_xdr_noop4args_class, name, \
	TP_PROTO( \
		const struct nfsd4_compoundargs *argp \
	), \
	TP_ARGS(argp))

DEFINE_SVC_XDR_NOOP4ARGS_EVENT(dec_getfh4args);
DEFINE_SVC_XDR_NOOP4ARGS_EVENT(dec_lookupp4args);
DEFINE_SVC_XDR_NOOP4ARGS_EVENT(dec_putpubfh4args);
DEFINE_SVC_XDR_NOOP4ARGS_EVENT(dec_putrootfh4args);
DEFINE_SVC_XDR_NOOP4ARGS_EVENT(dec_readlink4args);
DEFINE_SVC_XDR_NOOP4ARGS_EVENT(dec_restorefh4args);
DEFINE_SVC_XDR_NOOP4ARGS_EVENT(dec_savefh4args);

DECLARE_EVENT_CLASS(svc_xdr_noop4res_class,
	TP_PROTO(
		const struct nfsd4_compoundres *resp
	),
	TP_ARGS(resp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT, TRACE_XDR_CMPD_VARARGS
	)
);
#define DEFINE_SVC_XDR_NOOP4RES_EVENT(name) \
DEFINE_EVENT(svc_xdr_noop4res_class, name, \
	TP_PROTO( \
		const struct nfsd4_compoundres *resp \
	), \
	TP_ARGS(resp))

DEFINE_SVC_XDR_NOOP4RES_EVENT(enc_allocate4resok);
DEFINE_SVC_XDR_NOOP4RES_EVENT(enc_backchannel_ctl4resok);
DEFINE_SVC_XDR_NOOP4RES_EVENT(enc_clone4resok);
DEFINE_SVC_XDR_NOOP4RES_EVENT(enc_deallocate4resok);
DEFINE_SVC_XDR_NOOP4RES_EVENT(enc_delegreturn4resok);
DEFINE_SVC_XDR_NOOP4RES_EVENT(enc_destroy_clientid4resok);
DEFINE_SVC_XDR_NOOP4RES_EVENT(enc_destroy_session4resok);
DEFINE_SVC_XDR_NOOP4RES_EVENT(enc_free_stateid4resok);
DEFINE_SVC_XDR_NOOP4RES_EVENT(enc_lookup4resok);
DEFINE_SVC_XDR_NOOP4RES_EVENT(enc_lookupp4resok);
DEFINE_SVC_XDR_NOOP4RES_EVENT(enc_nverify4resok);
DEFINE_SVC_XDR_NOOP4RES_EVENT(enc_offload_cancel4resok);
DEFINE_SVC_XDR_NOOP4RES_EVENT(enc_putfh4resok);
DEFINE_SVC_XDR_NOOP4RES_EVENT(enc_putpubfh4resok);
DEFINE_SVC_XDR_NOOP4RES_EVENT(enc_putrootfh4resok);
DEFINE_SVC_XDR_NOOP4RES_EVENT(enc_reclaim_complete4resok);
DEFINE_SVC_XDR_NOOP4RES_EVENT(enc_release_lockowner4resok);
DEFINE_SVC_XDR_NOOP4RES_EVENT(enc_renew4resok);
DEFINE_SVC_XDR_NOOP4RES_EVENT(enc_restorefh4resok);
DEFINE_SVC_XDR_NOOP4RES_EVENT(enc_savefh4resok);

DECLARE_EVENT_CLASS(svc_xdr_enc_u64_class,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		u64 value
	),
	TP_ARGS(resp, value),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u64, value)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->value = value;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "%llu",
		TRACE_XDR_CMPD_VARARGS, __entry->value
	)
);
#define DEFINE_SVC_XDR_ENC_U64_EVENT(name) \
DEFINE_EVENT(svc_xdr_enc_u64_class, name, \
	TP_PROTO( \
		const struct nfsd4_compoundres *resp, \
		u64 value \
	), \
	TP_ARGS(resp, value))

DEFINE_SVC_XDR_ENC_U64_EVENT(enc_fattr4_change);
DEFINE_SVC_XDR_ENC_U64_EVENT(enc_fattr4_size);
DEFINE_SVC_XDR_ENC_U64_EVENT(enc_fattr4_files_avail);
DEFINE_SVC_XDR_ENC_U64_EVENT(enc_fattr4_files_free);
DEFINE_SVC_XDR_ENC_U64_EVENT(enc_fattr4_files_total);
DEFINE_SVC_XDR_ENC_U64_EVENT(enc_fattr4_maxfilesize);
DEFINE_SVC_XDR_ENC_U64_EVENT(enc_fattr4_maxread);
DEFINE_SVC_XDR_ENC_U64_EVENT(enc_fattr4_maxwrite);
DEFINE_SVC_XDR_ENC_U64_EVENT(enc_fattr4_space_avail);
DEFINE_SVC_XDR_ENC_U64_EVENT(enc_fattr4_space_free);
DEFINE_SVC_XDR_ENC_U64_EVENT(enc_fattr4_space_total);
DEFINE_SVC_XDR_ENC_U64_EVENT(enc_fattr4_space_used);

DECLARE_EVENT_CLASS(svc_xdr_enc_time4_class,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct timespec64 *time
	),
	TP_ARGS(resp, time),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(s64, time_sec)
		__field(long, time_nsec)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->time_sec = time->tv_sec;
		__entry->time_nsec = time->tv_nsec;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "time=[%llx, %lx]",
		TRACE_XDR_CMPD_VARARGS,
		__entry->time_sec, __entry->time_nsec
	)
);
#define DEFINE_SVC_XDR_ENC_TIME4_EVENT(name) \
DEFINE_EVENT(svc_xdr_enc_time4_class, name, \
	TP_PROTO( \
		const struct nfsd4_compoundres *resp, \
		const struct timespec64 *time \
	), \
	TP_ARGS(resp, time))

DEFINE_SVC_XDR_ENC_TIME4_EVENT(enc_fattr4_time_access);
DEFINE_SVC_XDR_ENC_TIME4_EVENT(enc_fattr4_time_delta);
DEFINE_SVC_XDR_ENC_TIME4_EVENT(enc_fattr4_time_metadata);
DEFINE_SVC_XDR_ENC_TIME4_EVENT(enc_fattr4_time_modify);


/**
 ** Error reports
 **/

TRACE_EVENT_CONDITION(compound_status,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		const struct nfsd4_op *op
	),
	TP_ARGS(rqstp, op),
	TP_CONDITION(op->status != nfs_ok),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(unsigned long, status)
		__string(name, nfsd4_op_name(op->opnum))
	),
	TP_fast_assign(
		const struct nfsd4_compoundargs *argp = rqstp->rq_argp;
		const struct nfsd4_compoundres *resp = rqstp->rq_resp;

		__entry->xid = be32_to_cpu(rqstp->rq_xid);
		__entry->opcnt = argp->opcnt;
		__entry->cur_op = resp->opcnt;
		__entry->minorversion = argp->minorversion;
		__entry->status = be32_to_cpu(op->status);
		__assign_str(name, nfsd4_op_name(op->opnum));
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "op=%s status=%s",
		TRACE_XDR_CMPD_VARARGS, __get_str(name),
		show_nfs4_status(__entry->status)
	)
)

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

TRACE_EVENT(dec_access4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_access *access
	),
	TP_ARGS(argp, access),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(unsigned long, access)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		__entry->access = access->ac_req_access;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "access=%s",
		TRACE_XDR_CMPD_VARARGS,
		show_nfs3_access_flags(__entry->access)
	)
);

TRACE_EVENT(dec_allocate4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_fallocate *fallocate
	),
	TP_ARGS(argp, fallocate),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS

		__field(u64, offset)
		__field(u64, length)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_STATEID_ASSIGNS(&fallocate->falloc_stateid);

		__entry->offset = fallocate->falloc_offset;
		__entry->length = fallocate->falloc_length;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT
		"offset=%llu length=%llu",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS,
		__entry->offset, __entry->length
	)
);

/* XXX: More needed */
TRACE_EVENT(dec_backchannel_ctl4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_backchannel_ctl *bc
	),
	TP_ARGS(argp, bc),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u32, cb_program)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		__entry->cb_program = bc->bc_cb_program;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "cb_program=%u",
		TRACE_XDR_CMPD_VARARGS, __entry->cb_program
	)
);

TRACE_EVENT(dec_bind_conn_to_session4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_bind_conn_to_session *bcts
	),
	TP_ARGS(argp, bcts),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(unsigned long, dir_from_client)
		__array(u8, sessionid, NFS4_MAX_SESSIONID_LEN)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		__entry->dir_from_client = bcts->dir;
		memcpy(__entry->sessionid, &bcts->sessionid,
		       NFS4_MAX_SESSIONID_LEN);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "sessionid=%s dir_from_client=%s",
		TRACE_XDR_CMPD_VARARGS,
		show_nfs4_sessionid(__entry->sessionid),
		show_nfs4_channel_dir_from_client(__entry->dir_from_client)
	)
);

TRACE_EVENT(dec_clone4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_clone *clone
	),
	TP_ARGS(argp, clone),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u32, src_cl_boot)
		__field(u32, src_cl_id)
		__field(u32, src_si_id)
		__field(u32, src_si_generation)
		__field(u64, src_offset)

		__field(u32, dst_cl_boot)
		__field(u32, dst_cl_id)
		__field(u32, dst_si_id)
		__field(u32, dst_si_generation)
		__field(u64, dst_offset)

		__field(u64, count)
	),
	TP_fast_assign(
		const stateid_t *stp;

		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		stp = &clone->cl_src_stateid;
		__entry->src_cl_boot = stp->si_opaque.so_clid.cl_boot;
		__entry->src_cl_id = stp->si_opaque.so_clid.cl_id;
		__entry->src_si_id = stp->si_opaque.so_id;
		__entry->src_si_generation = stp->si_generation;
		__entry->src_offset = clone->cl_src_pos;

		stp = &clone->cl_dst_stateid;
		__entry->dst_cl_boot = stp->si_opaque.so_clid.cl_boot;
		__entry->dst_cl_id = stp->si_opaque.so_clid.cl_id;
		__entry->dst_si_id = stp->si_opaque.so_id;
		__entry->dst_si_generation = stp->si_generation;
		__entry->dst_offset = clone->cl_dst_pos;

		__entry->count = clone->cl_count;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT
		"src: client=%08x:%08x stateid=%08x:%08x offset=%llu "
		"dst: client=%08x:%08x stateid=%08x:%08x offset=%llu "
		"count=%llu",
		TRACE_XDR_CMPD_VARARGS,
		__entry->src_cl_boot, __entry->src_cl_id,
		__entry->src_si_id, __entry->src_si_generation,
		__entry->src_offset,
		__entry->dst_cl_boot, __entry->dst_cl_id,
		__entry->dst_si_id, __entry->dst_si_generation,
		__entry->dst_offset, __entry->count
	)
);

TRACE_EVENT(dec_close4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_close *close
	),
	TP_ARGS(argp, close),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS

		__field(u32, seqid)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_STATEID_ASSIGNS(&close->cl_stateid);

		__entry->seqid = close->cl_seqid;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT
		TRACE_NFS4_STATEID_FORMAT "seqid=%u",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS,
		__entry->seqid
	)
);

TRACE_EVENT(dec_commit4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_commit *commit
	),
	TP_ARGS(argp, commit),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u64, offset)
		__field(u32, count)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		__entry->offset = commit->co_offset;
		__entry->count = commit->co_count;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "offset=%llu count=%u",
		TRACE_XDR_CMPD_VARARGS, __entry->offset, __entry->count
	)
);

TRACE_EVENT(dec_copy4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		struct nfsd4_copy *copy
	),
	TP_ARGS(argp, copy),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u32, src_cl_boot)
		__field(u32, src_cl_id)
		__field(u32, src_si_id)
		__field(u32, src_si_generation)
		__field(u64, src_offset)

		__field(u32, dst_cl_boot)
		__field(u32, dst_cl_id)
		__field(u32, dst_si_id)
		__field(u32, dst_si_generation)
		__field(u64, dst_offset)

		__field(u64, count)
	),
	TP_fast_assign(
		const stateid_t *stp;

		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		stp = &copy->cp_src_stateid;
		__entry->src_cl_boot = stp->si_opaque.so_clid.cl_boot;
		__entry->src_cl_id = stp->si_opaque.so_clid.cl_id;
		__entry->src_si_id = stp->si_opaque.so_id;
		__entry->src_si_generation = stp->si_generation;
		__entry->src_offset = copy->cp_src_pos;

		stp = &copy->cp_dst_stateid;
		__entry->dst_cl_boot = stp->si_opaque.so_clid.cl_boot;
		__entry->dst_cl_id = stp->si_opaque.so_clid.cl_id;
		__entry->dst_si_id = stp->si_opaque.so_id;
		__entry->dst_si_generation = stp->si_generation;
		__entry->dst_offset = copy->cp_dst_pos;

		__entry->count = copy->cp_count;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT
		"src: client=%08x:%08x stateid=%08x:%08x offset=%llu "
		"dst: client=%08x:%08x stateid=%08x:%08x offset=%llu "
		"count=%llu",
		TRACE_XDR_CMPD_VARARGS,
		__entry->src_cl_boot, __entry->src_cl_id,
		__entry->src_si_id, __entry->src_si_generation,
		__entry->src_offset,
		__entry->dst_cl_boot, __entry->dst_cl_id,
		__entry->dst_si_id, __entry->dst_si_generation,
		__entry->dst_offset, __entry->count
	)
);

TRACE_EVENT(dec_copy_notify4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_copy_notify *cn
	),
	TP_ARGS(argp, cn),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_STATEID_ASSIGNS(&cn->cpn_src_stateid);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS
	)
);

TRACE_EVENT(dec_create4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_create *create
	),
	TP_ARGS(argp, create),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(unsigned long, type)
		__string_len(name, name, create->cr_namelen)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		__entry->type = create->cr_type;
		__assign_str_len(name, create->cr_name, create->cr_namelen);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "name=%s type=%s",
		TRACE_XDR_CMPD_VARARGS,
		__get_str(name), show_nfs4_file_type(__entry->type)
	)
);

TRACE_EVENT(dec_create_session4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_create_session *cr_ses
	),
	TP_ARGS(argp, cr_ses),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_CLID_FIELDS

		__field(unsigned long, flags)
		__field(u32, seqid)
		__field(u32, cb_program)

		__field(u32, fore_maxreqsz)
		__field(u32, fore_maxrespsz)
		__field(u32, fore_maxresp_cached)
		__field(u32, fore_maxops)
		__field(u32, fore_maxreps)

		__field(u32, back_maxreqsz)
		__field(u32, back_maxrespsz)
		__field(u32, back_maxresp_cached)
		__field(u32, back_maxops)
		__field(u32, back_maxreps)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_CLID_ASSIGNS(cr_ses->clientid);

		__entry->flags = cr_ses->flags;
		__entry->seqid = cr_ses->seqid;
		__entry->cb_program = cr_ses->callback_prog;

		__entry->fore_maxreqsz = cr_ses->fore_channel.maxreq_sz;
		__entry->fore_maxrespsz = cr_ses->fore_channel.maxresp_sz;
		__entry->fore_maxresp_cached = cr_ses->fore_channel.maxresp_cached;
		__entry->fore_maxops = cr_ses->fore_channel.maxops;
		__entry->fore_maxreps = cr_ses->fore_channel.maxreqs;

		__entry->back_maxreqsz = cr_ses->back_channel.maxreq_sz;
		__entry->back_maxrespsz = cr_ses->back_channel.maxresp_sz;
		__entry->back_maxresp_cached = cr_ses->back_channel.maxresp_cached;
		__entry->back_maxops = cr_ses->back_channel.maxops;
		__entry->back_maxreps = cr_ses->back_channel.maxreqs;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_CLID_FORMAT
		"seqid=%u cb_program=%u flags=%s",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_CLID_VARARGS,
		__entry->seqid, __entry->cb_program,
		show_nfs4_csa_flags(__entry->flags)
	)
);

TRACE_EVENT(dec_deallocate4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_fallocate *deallocate
	),
	TP_ARGS(argp, deallocate),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS

		__field(u64, offset)
		__field(u64, length)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_STATEID_ASSIGNS(&deallocate->falloc_stateid);

		__entry->offset = deallocate->falloc_offset;
		__entry->length = deallocate->falloc_length;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT
		"offset=%llu length=%llu",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS,
		__entry->offset, __entry->length
	)
);

TRACE_EVENT(dec_delegreturn4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_delegreturn *dr
	),
	TP_ARGS(argp, dr),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_STATEID_ASSIGNS(&dr->dr_stateid);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS
	)
);

TRACE_EVENT(dec_destroy_clientid4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_destroy_clientid *dc
	),
	TP_ARGS(argp, dc),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_CLID_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_CLID_ASSIGNS(dc->clientid);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_CLID_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_CLID_VARARGS
	)
);

TRACE_EVENT(dec_destroy_session4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_destroy_session *destroy_session
	),
	TP_ARGS(argp, destroy_session),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__array(u8, sessionid, NFS4_MAX_SESSIONID_LEN)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		memcpy(__entry->sessionid, &destroy_session->sessionid,
		       NFS4_MAX_SESSIONID_LEN);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "sessionid=%s",
		TRACE_XDR_CMPD_VARARGS, show_nfs4_sessionid(__entry->sessionid)
	)
);

/* XXX: More needed */
TRACE_EVENT(dec_exchange_id4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_exchange_id *exid
	),
	TP_ARGS(argp, exid),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_VERIFIER_FIELD

		__field(unsigned long, flags)
		__field(unsigned long, spa_how)
		__string_len(owner, owner, exid->clname.len)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_VERIFIER_ASSIGN(exid->verifier);

		__entry->flags = exid->flags;
		__entry->spa_how = exid->spa_how;
		__assign_str_len(owner, exid->clname.data, exid->clname.len);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_VERIFIER_FORMAT
		"owner=%s flags=%s spa_how=%s",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_VERIFIER_VARARG,
		__get_str(owner),
		show_nfs4_exchgid4_flags(__entry->flags),
		show_nfs4_exchid4_spa_how(__entry->spa_how)
	)
);

TRACE_EVENT(dec_free_stateid4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_free_stateid *free_stateid
	),
	TP_ARGS(argp, free_stateid),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_STATEID_ASSIGNS(&free_stateid->fr_stateid);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS
	)
);

TRACE_EVENT(dec_getattr4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_getattr *getattr
	),
	TP_ARGS(argp, getattr),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_BITMAP_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_BITMAP_ASSIGNS(getattr->ga_bmval);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_BITMAP_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_BITMAP_VARARGS
	)
);

TRACE_EVENT(dec_getdeviceinfo4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_getdeviceinfo *gdp
	),
	TP_ARGS(argp, gdp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(unsigned long, layout_type)
		__field(unsigned long, notify_types)
		__field(u64, dev_idx)
		__field(u32, dev_gen)
		__field(u32, maxcount)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		__entry->layout_type = gdp->gd_layout_type;
		__entry->notify_types = gdp->gd_notify_types;
		__entry->dev_idx = gdp->gd_devid.fsid_idx;
		__entry->dev_gen = gdp->gd_devid.generation;
		__entry->maxcount = gdp->gd_maxcount;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT
		"layout_type=%s dev_id=[0x%llx:0x%x] "
		"maxcount=%u notify_types=%s",
		TRACE_XDR_CMPD_VARARGS,
		show_pnfs_layout_type(__entry->layout_type),
		__entry->dev_idx, __entry->dev_gen, __entry->maxcount,
		show_pnfs_notify_types(__entry->notify_types)
	)
);

TRACE_EVENT(dec_layoutcommit4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_layoutcommit *lcp
	),
	TP_ARGS(argp, lcp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u64, offset)
		__field(u64, length)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		__entry->offset = lcp->lc_seg.offset;
		__entry->length = lcp->lc_seg.length;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "offset=%llu length=%llu",
		TRACE_XDR_CMPD_VARARGS, __entry->offset, __entry->length
	)
);

TRACE_EVENT(dec_layoutget4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_layoutget *lgp
	),
	TP_ARGS(argp, lgp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS

		__field(bool, layout_avail)
		__field(unsigned long, layout_type)
		__field(unsigned long, iomode)
		__field(u64, offset)
		__field(u64, length)
		__field(u64, minlength)
		__field(u32, maxcount)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_STATEID_ASSIGNS(&lgp->lg_sid);

		__entry->layout_avail = !!lgp->lg_signal;
		__entry->layout_type = lgp->lg_layout_type;
		__entry->iomode = lgp->lg_seg.iomode;
		__entry->offset = lgp->lg_seg.offset;
		__entry->length = lgp->lg_seg.length;
		__entry->minlength = lgp->lg_minlength;
		__entry->maxcount = lgp->lg_maxcount;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT
		"type=%s iomode=%s offset=%llu length=%llu%s",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS,
		show_pnfs_layout_type(__entry->layout_type),
		show_pnfs_layout_iomode(__entry->iomode),
		__entry->offset, __entry->length,
		__entry->layout_avail ? " (available)" : ""
	)
);

TRACE_EVENT(dec_layoutreturn4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_layoutreturn *lrp
	),
	TP_ARGS(argp, lrp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(unsigned long, layout_type)
		__field(u64, offset)
		__field(u64, length)
		__field(unsigned long, return_type)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		__entry->layout_type = lrp->lr_layout_type;
		__entry->offset = lrp->lr_seg.offset;
		__entry->length = lrp->lr_seg.length;
		__entry->return_type = lrp->lr_return_type;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT
		"layout_type=%s offset=%llu length=%llu return_type=%s",
		TRACE_XDR_CMPD_VARARGS,
		show_pnfs_layout_type(__entry->layout_type),
		__entry->offset, __entry->length,
		show_pnfs_return_type(__entry->return_type)
	)
);

TRACE_EVENT(dec_link4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_link *link
	),
	TP_ARGS(argp, link),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__string_len(name, name, link->li_namelen)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		__assign_str_len(name, link->li_name, link->li_namelen);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "name=%s",
		TRACE_XDR_CMPD_VARARGS, __get_str(name)
	)
);

TRACE_EVENT(dec_open_to_lockowner4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_lock *lock
	),
	TP_ARGS(argp, lock),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS

		__field(u32, open_seqid)
		__field(u32, lock_seqid)
		__string_len(owner, owner, lock->lk_new_owner.len)
		__field(unsigned long, type)
		__field(u64, offset)
		__field(u64, length)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_STATEID_ASSIGNS(&lock->lk_new_open_stateid);

		__entry->open_seqid = lock->lk_new_open_seqid;
		__entry->lock_seqid = lock->lk_new_lock_seqid;
		__assign_str_len(owner, lock->lk_new_owner.data,
				 lock->lk_new_owner.len);
		__entry->type = lock->lk_type;
		__entry->offset = lock->lk_offset;
		__entry->length = lock->lk_length;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT
		"open_seqid=%u lock_seqid=%u owner=%s "
		"type=%s offset=%llu length=%llu",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS,
		__entry->open_seqid, __entry->lock_seqid,
		__get_str(owner), show_nfs4_lock_type(__entry->type),
		__entry->offset, __entry->length
	)
);

TRACE_EVENT(dec_exist_lock_owner4,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_lock *lock
	),
	TP_ARGS(argp, lock),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS

		__field(u32, seqid)
		__field(unsigned long, type)
		__field(u64, offset)
		__field(u64, length)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_STATEID_ASSIGNS(&lock->lk_old_lock_stateid);

		__entry->seqid = lock->lk_old_lock_seqid;
		__entry->type = lock->lk_type;
		__entry->offset = lock->lk_offset;
		__entry->length = lock->lk_length;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT
		"seqid=%u type=%s offset=%llu length=%llu",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS,
		__entry->seqid, show_nfs4_lock_type(__entry->type),
		__entry->offset, __entry->length
	)
);

TRACE_EVENT(dec_lockt4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_lockt *lockt
	),
	TP_ARGS(argp, lockt),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(unsigned long, type)
		__field(u64, offset)
		__field(u64, length)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		__entry->type = lockt->lt_type;
		__entry->offset = lockt->lt_offset;
		__entry->length = lockt->lt_length;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT
		"type=%s offset=%llu length=%llu",
		TRACE_XDR_CMPD_VARARGS,
		show_nfs4_lock_type(__entry->type), __entry->offset,
		__entry->length
	)
);

TRACE_EVENT(dec_locku4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_locku *locku
	),
	TP_ARGS(argp, locku),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u32, seqid)
		__field(unsigned long, type)
		__field(u64, offset)
		__field(u64, length)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		__entry->seqid = locku->lu_seqid;
		__entry->type = locku->lu_type;
		__entry->offset = locku->lu_offset;
		__entry->length = locku->lu_length;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT
		"seqid=%u type=%s offset=%Lu length=%Lu",
		TRACE_XDR_CMPD_VARARGS,
		__entry->seqid, show_nfs4_lock_type(__entry->type),
		__entry->offset, __entry->length
	)
);

TRACE_EVENT(dec_lookup4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_lookup *lookup
	),
	TP_ARGS(argp, lookup),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__string_len(name, name, lookup->lo_len)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		__assign_str_len(name, lookup->lo_name, lookup->lo_len);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "name=%s",
		TRACE_XDR_CMPD_VARARGS, __get_str(name)
	)
);

TRACE_EVENT(dec_nverify4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_verify *nverify
	),
	TP_ARGS(argp, nverify),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_BITMAP_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_BITMAP_ASSIGNS(nverify->ve_bmval);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_BITMAP_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_BITMAP_VARARGS
	)
);

TRACE_EVENT(dec_offload_cancel4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_offload_status *os
	),
	TP_ARGS(argp, os),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_STATEID_ASSIGNS(&os->stateid);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS
	)
);

TRACE_EVENT(dec_offload_status4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_offload_status *os
	),
	TP_ARGS(argp, os),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_STATEID_ASSIGNS(&os->stateid);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS
	)
);

TRACE_EVENT(dec_createhow4_verifier,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_open *open
	),
	TP_ARGS(argp, open),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_VERIFIER_FIELD
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_VERIFIER_ASSIGN(open->op_verf);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_VERIFIER_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_VERIFIER_VARARG
	)
);

TRACE_EVENT(dec_claim4_null,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_open *open
	),
	TP_ARGS(argp, open),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__string_len(name, open->op_fname, open->op_fnamelen)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		__assign_str_len(name, open->op_fname, open->op_fnamelen);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "name=%s",
		TRACE_XDR_CMPD_VARARGS, __get_str(name)
	)
);

TRACE_EVENT(dec_claim4_previous,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_open *open
	),
	TP_ARGS(argp, open),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(unsigned long, delegate_type)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		__entry->delegate_type = open->op_delegate_type;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "delegate_type=%s",
		TRACE_XDR_CMPD_VARARGS,
		show_nfs4_delegation_type(__entry->delegate_type)
	)
);

TRACE_EVENT(dec_claim4_delegcur,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_open *open
	),
	TP_ARGS(argp, open),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS

		__string_len(name, open->op_fname, open->op_fnamelen)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_STATEID_ASSIGNS(&open->op_delegate_stateid);

		__assign_str_len(name, open->op_fname, open->op_fnamelen);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT "name=%s",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS,
		__get_str(name)
	)
);

TRACE_EVENT(dec_claim4_delegcurfh,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_open *open
	),
	TP_ARGS(argp, open),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_STATEID_ASSIGNS(&open->op_delegate_stateid);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS
	)
);

TRACE_EVENT(dec_open4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_open *open
	),
	TP_ARGS(argp, open),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u32, seqid)
		__field(unsigned long, create)
		__field(unsigned long, claim)
		__field(unsigned long, share)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		__entry->seqid = open->op_seqid;
		__entry->create = open->op_create;
		__entry->claim = open->op_claim_type;
		__entry->share = open->op_share_access;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT
		"seqid=%u type=%s claim=%s share=%s",
		TRACE_XDR_CMPD_VARARGS,
		__entry->seqid, show_nfs4_open_create(__entry->create),
		show_nfs4_open_claimtype(__entry->claim),
		show_nfs4_open_sharedeny_flags(__entry->share)
	)
);

TRACE_EVENT(dec_open_confirm4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_open_confirm *oc
	),
	TP_ARGS(argp, oc),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS

		__field(u32, seqid)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_STATEID_ASSIGNS(&oc->oc_req_stateid);

		__entry->seqid = oc->oc_seqid;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT
		"seqid=%u",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS,
		__entry->seqid
	)
);

TRACE_EVENT(dec_open_downgrade4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_open_downgrade *od
	),
	TP_ARGS(argp, od),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS

		__field(u32, seqid)
		__field(unsigned long, share)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_STATEID_ASSIGNS(&od->od_stateid);

		__entry->seqid = od->od_seqid;
		__entry->share = od->od_share_access;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT
		"seqid=%u share=%s",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS,
		__entry->seqid, show_nfs4_open_sharedeny_flags(__entry->share)
	)
);

TRACE_EVENT(dec_putfh4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_putfh *putfh
	),
	TP_ARGS(argp, putfh),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u32, fh_hash)
	),
	TP_fast_assign(
		struct knfsd_fh fh_handle;

		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		fh_handle.fh_size = putfh->pf_fhlen;
		memcpy(&fh_handle.fh_raw, putfh->pf_fhval, putfh->pf_fhlen);
		__entry->fh_hash = knfsd_fh_hash(&fh_handle);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "fh_hash=0x%08x",
		TRACE_XDR_CMPD_VARARGS, __entry->fh_hash
	)
);

TRACE_EVENT(dec_read4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_read *read
	),
	TP_ARGS(argp, read),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS

		__field(u32, count)
		__field(u64, offset)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_STATEID_ASSIGNS(&read->rd_stateid);

		__entry->count = read->rd_length;
		__entry->offset = read->rd_offset;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT
		"count=%u offset=%llu",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS,
		__entry->count, __entry->offset
	)
);

TRACE_EVENT(dec_read_plus4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_read *read
	),
	TP_ARGS(argp, read),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS

		__field(u32, count)
		__field(u64, offset)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_STATEID_ASSIGNS(&read->rd_stateid);

		__entry->count = read->rd_length;
		__entry->offset = read->rd_offset;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT
		"count=%u offset=%llu",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS,
		__entry->count, __entry->offset
	)
);

TRACE_EVENT(dec_readdir4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_readdir *readdir
	),
	TP_ARGS(argp, readdir),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_BITMAP_FIELDS

		__field(u64, cookie)
		__field(u32, dircount)
		__field(u32, maxcount)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_BITMAP_ASSIGNS(readdir->rd_bmval);

		__entry->cookie = readdir->rd_cookie;
		__entry->dircount = readdir->rd_dircount;
		__entry->maxcount = readdir->rd_maxcount;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT
		"cookie=0x%llx dircount=%u maxcount=%u "
		TRACE_NFS4_BITMAP_FORMAT,
		TRACE_XDR_CMPD_VARARGS,
		__entry->cookie, __entry->dircount, __entry->maxcount,
		TRACE_NFS4_BITMAP_VARARGS
	)
);

TRACE_EVENT(dec_reclaim_complete4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_reclaim_complete *rc
	),
	TP_ARGS(argp, rc),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(bool, one_fs)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		__entry->one_fs = !!rc->rca_one_fs;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "one_fs=%s",
		TRACE_XDR_CMPD_VARARGS,
		__entry->one_fs ? "true" : "false"
	)
);

TRACE_EVENT(dec_release_lockowner4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_release_lockowner *rlockowner
	),
	TP_ARGS(argp, rlockowner),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_CLID_FIELDS

		__string_len(owner, owner, rlockowner->rl_owner.len)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_CLID_ASSIGNS(rlockowner->rl_clientid);

		__assign_str_len(owner, rlockowner->rl_owner.data,
				 rlockowner->rl_owner.len);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_CLID_FORMAT "owner=%s",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_CLID_VARARGS,
		__get_str(owner)
	)
);

TRACE_EVENT(dec_remove4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_remove *remove
	),
	TP_ARGS(argp, remove),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__string_len(name, name, remove->rm_namelen)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		__assign_str_len(name, remove->rm_name, remove->rm_namelen);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "name=%s",
		TRACE_XDR_CMPD_VARARGS, __get_str(name)
	)
);

TRACE_EVENT(dec_rename4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_rename *rename
	),
	TP_ARGS(argp, rename),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__string_len(from_name, from_name, rename->rn_snamelen + 1)
		__string_len(to_name, to_name, rename->rn_tnamelen + 1)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		__assign_str_len(from_name, rename->rn_sname,
				 rename->rn_snamelen);
		__assign_str_len(to_name, rename->rn_tname,
				 rename->rn_tnamelen);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "from_name=%s to_name=%s",
		TRACE_XDR_CMPD_VARARGS,
		__get_str(from_name), __get_str(to_name)
	)
);

TRACE_EVENT(dec_renew4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const clientid_t *clid
	),
	TP_ARGS(argp, clid),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_CLID_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_CLID_ASSIGNS(*clid);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_CLID_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_CLID_VARARGS
	)
);

TRACE_EVENT(dec_secinfo4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_secinfo *secinfo
	),
	TP_ARGS(argp, secinfo),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__string_len(name, name, secinfo->si_namelen)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		__assign_str_len(name, secinfo->si_name, secinfo->si_namelen);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "name=%s",
		TRACE_XDR_CMPD_VARARGS, __get_str(name)
	)
);

TRACE_EVENT(dec_secinfo_no_name4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		struct nfsd4_secinfo_no_name *sin
	),
	TP_ARGS(argp, sin),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(unsigned long, style)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		__entry->style = sin->sin_style;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "style=%s",
		TRACE_XDR_CMPD_VARARGS,
		show_nfs4_secinfo_style(__entry->style)
	)
);

TRACE_EVENT(dec_seek4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_seek *seek
	),
	TP_ARGS(argp, seek),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS

		__field(u64, offset)
		__field(unsigned long, what)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);
		TRACE_NFS4_STATEID_ASSIGNS(&seek->seek_stateid);

		__entry->offset = seek->seek_offset;
		__entry->what = seek->seek_whence;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT
		"offset=%llu what=%s",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS,
		__entry->offset, show_nfs4_data_content(__entry->what)
	)
);

TRACE_EVENT(dec_sequence4args,
	TP_PROTO(
		const struct nfsd4_compoundargs *argp,
		const struct nfsd4_sequence *seq
	),
	TP_ARGS(argp, seq),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__array(u8, sessionid, NFS4_MAX_SESSIONID_LEN)
		__field(u32, seqid)
		__field(u32, slotid)
		__field(u32, maxslots)
		__field(bool, cachethis)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_ARG_ASSIGNS(argp);

		memcpy(__entry->sessionid, seq->sessionid.data,
		       NFS4_MAX_SESSIONID_LEN);
		__entry->seqid = seq->seqid;
		__entry->slotid = seq->slotid;
		__entry->maxslots = seq->maxslots;
		__entry->cachethis = !!seq->cachethis;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "sessionid=%s seqid=%u slot=%u/%u%s",
		TRACE_XDR_CMPD_VARARGS,
		show_nfs4_sessionid(__entry->sessionid),
		__entry->seqid, __entry->slotid, __entry->maxslots,
		__entry->cachethis ?  " (cachethis)" : ""
	)
);


/**
 ** Server-side result encoding tracepoints
 **/

TRACE_EVENT(enc_access4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_access *access
	),
	TP_ARGS(resp, access),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(unsigned long, access)
		__field(unsigned long, supported)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->access = access->ac_resp_access;
		__entry->supported = access->ac_supported;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "access=%s supported=%s",
		TRACE_XDR_CMPD_VARARGS,
		show_nfs3_access_flags(__entry->access),
		show_nfs3_access_flags(__entry->supported)
	)
);

TRACE_EVENT(enc_bind_conn_to_session4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_bind_conn_to_session *bcts
	),
	TP_ARGS(resp, bcts),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(unsigned long, dir_from_server)
		__array(u8, sessionid, NFS4_MAX_SESSIONID_LEN)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->dir_from_server = bcts->dir;
		memcpy(__entry->sessionid, &bcts->sessionid,
		       NFS4_MAX_SESSIONID_LEN);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "sessionid=%s dir_from_server=%s",
		TRACE_XDR_CMPD_VARARGS,
		show_nfs4_sessionid(__entry->sessionid),
		show_nfs4_channel_dir_from_server(__entry->dir_from_server)
	)
);

TRACE_EVENT(enc_close4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_close *close
	),
	TP_ARGS(resp, close),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
		TRACE_NFS4_STATEID_ASSIGNS(&close->cl_stateid);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS
	)
);

TRACE_EVENT(enc_commit4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_commit *commit
	),
	TP_ARGS(resp, commit),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_VERIFIER_FIELD
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
		TRACE_NFS4_VERIFIER_ASSIGN(commit->co_verf);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_VERIFIER_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_VERIFIER_VARARG
	)
);

TRACE_EVENT(enc_copy4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_copy *copy
	),
	TP_ARGS(resp, copy),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS
		TRACE_NFS4_VERIFIER_FIELD

		__field(u64, count)
		__field(unsigned long, stable)
	),
	TP_fast_assign(
		const struct nfsd42_write_res *write = &copy->cp_res;

		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
		TRACE_NFS4_STATEID_ASSIGNS(&write->cb_stateid);
		TRACE_NFS4_VERIFIER_ASSIGN(write->wr_verifier);

		__entry->count = write->wr_bytes_written;
		__entry->stable = write->wr_stable_how;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT
		"count=%llu stable=%s " TRACE_NFS4_VERIFIER_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS,
		__entry->count, show_nfs_stable_how(__entry->stable),
		TRACE_NFS4_VERIFIER_VARARG
	)
);

TRACE_EVENT(enc_copy_notify4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_copy_notify *cn
	),
	TP_ARGS(resp, cn),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS

		__field(u64, lease_sec)
		__field(u32, lease_nsec)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
		TRACE_NFS4_STATEID_ASSIGNS(&cn->cpn_cnr_stateid);

		__entry->lease_sec = cn->cpn_sec;
		__entry->lease_nsec = cn->cpn_nsec;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT
		"lease_time=[%llx, %x]",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS,
		__entry->lease_sec, __entry->lease_nsec
	)
);

TRACE_EVENT(enc_create4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_create *create
	),
	TP_ARGS(resp, create),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_CINFO_FIELDS
		TRACE_NFS4_BITMAP_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
		TRACE_NFS4_CINFO_ASSIGNS(create->cr_cinfo);
		TRACE_NFS4_BITMAP_ASSIGNS(create->cr_bmval);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_CINFO_FORMAT
		TRACE_NFS4_BITMAP_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_CINFO_VARARGS,
		TRACE_NFS4_BITMAP_VARARGS
	)
);

TRACE_EVENT(enc_create_session4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_create_session *cr_ses
	),
	TP_ARGS(resp, cr_ses),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__array(u8, sessionid, NFS4_MAX_SESSIONID_LEN)
		__field(u32, seqid)
		__field(unsigned long, flags)

		__field(u32, fore_maxreqsz)
		__field(u32, fore_maxrespsz)
		__field(u32, fore_maxresp_cached)
		__field(u32, fore_maxops)
		__field(u32, fore_maxreps)

		__field(u32, back_maxreqsz)
		__field(u32, back_maxrespsz)
		__field(u32, back_maxresp_cached)
		__field(u32, back_maxops)
		__field(u32, back_maxreps)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		memcpy(__entry->sessionid, &cr_ses->sessionid,
		       NFS4_MAX_SESSIONID_LEN);
		__entry->seqid = cr_ses->seqid;
		__entry->flags = cr_ses->flags;

		__entry->fore_maxreqsz = cr_ses->fore_channel.maxreq_sz;
		__entry->fore_maxrespsz = cr_ses->fore_channel.maxresp_sz;
		__entry->fore_maxresp_cached = cr_ses->fore_channel.maxresp_cached;
		__entry->fore_maxops = cr_ses->fore_channel.maxops;
		__entry->fore_maxreps = cr_ses->fore_channel.maxreqs;

		__entry->back_maxreqsz = cr_ses->back_channel.maxreq_sz;
		__entry->back_maxrespsz = cr_ses->back_channel.maxresp_sz;
		__entry->back_maxresp_cached = cr_ses->back_channel.maxresp_cached;
		__entry->back_maxops = cr_ses->back_channel.maxops;
		__entry->back_maxreps = cr_ses->back_channel.maxreqs;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "sessionid=%s seqid=%u flags=%s",
		TRACE_XDR_CMPD_VARARGS,
		show_nfs4_sessionid(__entry->sessionid),
		__entry->seqid, show_nfs4_csa_flags(__entry->flags)
	)
);

TRACE_EVENT(enc_exchange_id4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_exchange_id *exid
	),
	TP_ARGS(resp, exid),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_CLID_FIELDS

		__field(u32, seqid)
		__field(unsigned long, flags)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
		TRACE_NFS4_CLID_ASSIGNS(exid->clientid);

		__entry->seqid = exid->seqid;
		__entry->flags = exid->flags;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_CLID_FORMAT
		"seqid=%u flags=%s",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_CLID_VARARGS,
		__entry->seqid, show_nfs4_exchgid4_flags(__entry->flags)
	)
);

TRACE_EVENT(enc_getattr4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_getattr *getattr
	),
	TP_ARGS(resp, getattr),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_BITMAP_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
		TRACE_NFS4_BITMAP_ASSIGNS(getattr->ga_bmval);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_BITMAP_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_BITMAP_VARARGS
	)
);

TRACE_EVENT(enc_getdeviceinfo4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_getdeviceinfo *gdp
	),
	TP_ARGS(resp, gdp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(unsigned long, layout_type)
		__field(unsigned long, notification)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->layout_type = gdp->gd_layout_type;
		__entry->notification = gdp->gd_notify_types;
		/* The device_addr4 is layout_type-specific,
		 * and thus is reported separately. */
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "layout_type=%s notification=%s",
		TRACE_XDR_CMPD_VARARGS,
		show_pnfs_layout_type(__entry->layout_type),
		show_pnfs_notify_types(__entry->notification)
	)
);

TRACE_EVENT(enc_getfh4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct svc_fh *fhp
	),
	TP_ARGS(resp, fhp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u32, fh_hash)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->fh_hash = knfsd_fh_hash(&fhp->fh_handle);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "fh_hash=0x%08x",
		TRACE_XDR_CMPD_VARARGS, __entry->fh_hash
	)
);

TRACE_EVENT(enc_layoutcommit4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_layoutcommit *lcp
	),
	TP_ARGS(resp, lcp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u64, newsize)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->newsize = lcp->lc_newsize;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "newsize=%llu",
		TRACE_XDR_CMPD_VARARGS, __entry->newsize
	)
);

TRACE_EVENT(enc_layoutget4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_layoutget *lgp
	),
	TP_ARGS(resp, lgp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS

		__field(u64, offset)
		__field(u64, length)
		__field(unsigned long, iomode)
		__field(unsigned long, layout_type)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
		TRACE_NFS4_STATEID_ASSIGNS(&lgp->lg_sid);

		__entry->offset = lgp->lg_seg.offset;
		__entry->length = lgp->lg_seg.length;
		__entry->iomode = lgp->lg_seg.iomode;
		__entry->layout_type = lgp->lg_layout_type;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT
		"type=%s iomode=%s offset=%llu length=%llu",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS,
		show_pnfs_layout_type(__entry->layout_type),
		show_pnfs_layout_iomode(__entry->iomode),
		__entry->offset, __entry->length
	)
);

TRACE_EVENT(enc_layoutreturn4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_layoutreturn *lrp
	),
	TP_ARGS(resp, lrp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS

		__field(bool, present)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
		TRACE_NFS4_STATEID_ASSIGNS(&lrp->lr_sid);

		__entry->present = !!lrp->lrs_present;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT "%s",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS,
		__entry->present ? " (present)" : ""
	)
);

TRACE_EVENT(enc_link4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_link *link
	),
	TP_ARGS(resp, link),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_CINFO_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
		TRACE_NFS4_CINFO_ASSIGNS(link->li_cinfo);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_CINFO_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_CINFO_VARARGS
	)
);

TRACE_EVENT_CONDITION(enc_lock4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		__be32 nfserr,
		const struct nfsd4_lock *lock
	),
	TP_ARGS(resp, nfserr, lock),
	TP_CONDITION(nfserr == nfs_ok),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
		TRACE_NFS4_STATEID_ASSIGNS(&lock->lk_resp_stateid);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS
	)
);

TRACE_EVENT_CONDITION(enc_lock4resdenied,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		__be32 nfserr,
		const struct nfsd4_lock_denied *ld
	),
	TP_ARGS(resp, nfserr, ld),
	TP_CONDITION(nfserr == nfserr_denied),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_CLID_FIELDS

		__string_len(owner, owner, ld->ld_owner.len)
		__field(unsigned long, type)
		__field(u64, start)
		__field(u64, length)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->type = ld->ld_type;
		__entry->start = ld->ld_start;
		__entry->length = ld->ld_length;
		if (ld->ld_owner.len) {
			TRACE_NFS4_CLID_ASSIGNS(ld->ld_clientid);
			__assign_str_len(owner, ld->ld_owner.data,
					 ld->ld_owner.len);
		} else {
			__entry->cl_boot = 0;
			__entry->cl_id = 0;
		}
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_CLID_FORMAT
		"owner=%s type=%s start=%llu offset=%llu",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_CLID_VARARGS,
		__get_str(owner), show_nfs4_lock_type(__entry->type),
		__entry->start, __entry->length
	)
);

TRACE_EVENT(enc_lockt4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_lockt *lockt
	),
	TP_ARGS(resp, lockt),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT, TRACE_XDR_CMPD_VARARGS
	)
);

TRACE_EVENT_CONDITION(enc_lockt4resdenied,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		__be32 nfserr,
		const struct nfsd4_lock_denied *ld
	),
	TP_ARGS(resp, nfserr, ld),
	TP_CONDITION(nfserr == nfserr_denied),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_CLID_FIELDS

		__string_len(owner, owner, ld->ld_owner.len)
		__field(unsigned long, type)
		__field(u64, start)
		__field(u64, length)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->type = ld->ld_type;
		__entry->start = ld->ld_start;
		__entry->length = ld->ld_length;
		if (ld->ld_owner.len) {
			TRACE_NFS4_CLID_ASSIGNS(ld->ld_clientid);
			__assign_str_len(owner, ld->ld_owner.data,
					 ld->ld_owner.len);
		} else {
			__entry->cl_boot = 0;
			__entry->cl_id = 0;
		}
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_CLID_FORMAT
		"owner=%s type=%s start=%llu offset=%llu",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_CLID_VARARGS,
		__get_str(owner), show_nfs4_lock_type(__entry->type),
		__entry->start, __entry->length
	)
);

TRACE_EVENT(enc_locku4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_locku *locku
	),
	TP_ARGS(resp, locku),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
		TRACE_NFS4_STATEID_ASSIGNS(&locku->lu_stateid);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS
	)
);

TRACE_EVENT(enc_offload_status4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_offload_status *os
	),
	TP_ARGS(resp, os),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u64, count)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->count = os->count;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "count=%Lu",
		TRACE_XDR_CMPD_VARARGS, __entry->count
	)
);

TRACE_EVENT(enc_open4_delegread,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_open *open
	),
	TP_ARGS(resp, open),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS

		__field(bool, recall)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
		TRACE_NFS4_STATEID_ASSIGNS(&open->op_delegate_stateid);

		__entry->recall = !!open->op_recall;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT "%s",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS,
		__entry->recall ? " (recall)" : ""
	)
);

TRACE_EVENT(enc_open4_delegwrite,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_open *open
	),
	TP_ARGS(resp, open),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS

		__field(bool, recall)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
		TRACE_NFS4_STATEID_ASSIGNS(&open->op_delegate_stateid);

		__entry->recall = !!open->op_recall;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT "%s",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS,
		__entry->recall ? " (recall)" : ""
	)
);

TRACE_EVENT(enc_open4_delegnoneext,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_open *open
	),
	TP_ARGS(resp, open),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(unsigned long, why_no_deleg)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->why_no_deleg = open->op_why_no_deleg;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "why_no_deleg=%s",
		TRACE_XDR_CMPD_VARARGS,
		show_nfs4_why_no_delegation(__entry->why_no_deleg)

	)
);

TRACE_EVENT(enc_open4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_open *open
	),
	TP_ARGS(resp, open),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS
		TRACE_NFS4_CINFO_FIELDS
		TRACE_NFS4_BITMAP_FIELDS

		__field(unsigned long, rflags)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
		TRACE_NFS4_STATEID_ASSIGNS(&open->op_stateid);
		TRACE_NFS4_CINFO_ASSIGNS(open->op_cinfo);
		TRACE_NFS4_BITMAP_ASSIGNS(open->op_bmval);

		__entry->rflags = open->op_rflags;

	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT
		TRACE_NFS4_CINFO_FORMAT TRACE_NFS4_BITMAP_FORMAT
		"rflags=%s",
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS,
		TRACE_NFS4_CINFO_VARARGS, TRACE_NFS4_BITMAP_VARARGS,
		show_nfs4_open_result(__entry->rflags)
	)
);

TRACE_EVENT(enc_open_confirm4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_open_confirm *oc
	),
	TP_ARGS(resp, oc),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
		TRACE_NFS4_STATEID_ASSIGNS(&oc->oc_resp_stateid);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS
	)
);

TRACE_EVENT(enc_open_downgrade4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_open_downgrade *od
	),
	TP_ARGS(resp, od),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_STATEID_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
		TRACE_NFS4_STATEID_ASSIGNS(&od->od_stateid);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_STATEID_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_STATEID_VARARGS
	)
);

TRACE_EVENT(enc_read4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_read *read
	),
	TP_ARGS(resp, read),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(bool, eof)
		__field(u32, count)
		__field(u64, offset)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->eof = !!read->rd_eof;
		__entry->count = read->rd_length;
		__entry->offset = read->rd_offset;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "count=%u offset=%llu%s",
		TRACE_XDR_CMPD_VARARGS, __entry->count, __entry->offset,
		__entry->eof ? " (eof)" : ""
	)
);

TRACE_EVENT(enc_read_plus_data4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_read *read,
		unsigned long count,
		u32 eof
	),
	TP_ARGS(resp, read, count, eof),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(bool, eof)
		__field(u32, count)
		__field(u64, offset)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->eof = !!eof;
		__entry->count = count;
		__entry->offset = read->rd_offset;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "count=%u offset=%llu%s",
		TRACE_XDR_CMPD_VARARGS, __entry->count, __entry->offset,
		__entry->eof ? " (eof)" : ""
	)
);

TRACE_EVENT(enc_read_plus_hole4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_read *read,
		unsigned long count,
		u32 eof
	),
	TP_ARGS(resp, read, count, eof),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(bool, eof)
		__field(u32, count)
		__field(u64, offset)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->eof = !!eof;
		__entry->count = count;
		__entry->offset = read->rd_offset;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "count=%u offset=%llu%s",
		TRACE_XDR_CMPD_VARARGS, __entry->count, __entry->offset,
		__entry->eof ? " (eof)" : ""
	)
);

TRACE_EVENT(enc_readdir4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_readdir *readdir
	),
	TP_ARGS(resp, readdir),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u32, len)
		__field(bool, eof)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->eof = readdir->common.err == nfserr_eof;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "len=%u%s",
		TRACE_XDR_CMPD_VARARGS, __entry->len,
		__entry->eof ? " (eof)" : ""
	)
);

TRACE_EVENT(enc_entry4,
	TP_PROTO(
		const struct svc_rqst *rqstp,
		 u64 fileid,
		 const char *name,
		 int len),
	TP_ARGS(rqstp, fileid, name, len),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u64, fileid)
		__string_len(name, name, len)
	),
	TP_fast_assign(
		const struct nfsd4_compoundargs *argp = rqstp->rq_argp;
		const struct nfsd4_compoundres *resp = rqstp->rq_resp;

		__entry->xid = be32_to_cpu(rqstp->rq_xid);
		__entry->opcnt = argp->opcnt;
		__entry->cur_op = resp->opcnt;
		__entry->minorversion = argp->minorversion;

		__entry->fileid = fileid;
		__assign_str_len(name, name, len)
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "fileid=%llu name=%s",
		TRACE_XDR_CMPD_VARARGS, __entry->fileid, __get_str(name)
	)
);

TRACE_EVENT(enc_readlink4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_readlink *readlink,
		int count
	),
	TP_ARGS(resp, readlink, count),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u32, count)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->count = count;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "count=%u",
		TRACE_XDR_CMPD_VARARGS, __entry->count
	)
);

TRACE_EVENT(enc_remove4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_remove *remove
	),
	TP_ARGS(resp, remove),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_CINFO_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
		TRACE_NFS4_CINFO_ASSIGNS(remove->rm_cinfo);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_CINFO_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_CINFO_VARARGS
	)
);

TRACE_EVENT(enc_rename4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_rename *rename
	),
	TP_ARGS(resp, rename),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(bool, source_atomic)
		__field(u64, source_before)
		__field(u64, source_after)
		__field(bool, target_atomic)
		__field(u64, target_before)
		__field(u64, target_after)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->source_atomic = !!rename->rn_sinfo.atomic;
		__entry->source_before = rename->rn_sinfo.before_change;
		__entry->source_after = rename->rn_sinfo.after_change;
		__entry->target_atomic = !!rename->rn_tinfo.atomic;
		__entry->target_before = rename->rn_tinfo.before_change;
		__entry->target_after = rename->rn_tinfo.after_change;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT
		"source: before=%llu after=%llu%s "
		"target: before=%llu after=%llu%s",
		TRACE_XDR_CMPD_VARARGS,
		__entry->source_before, __entry->source_after,
		__entry->source_atomic ? " (atomic)" : "",
		__entry->target_before, __entry->target_after,
		__entry->target_atomic ? " (atomic)" : ""
	)
);

/* XXX: More needed */
TRACE_EVENT(enc_secinfo4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_secinfo *secinfo
	),
	TP_ARGS(resp, secinfo),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT,
		TRACE_XDR_CMPD_VARARGS
	)
);

/* XXX: More needed */
TRACE_EVENT(enc_secinfo_no_name4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_secinfo_no_name *secinfo
	),
	TP_ARGS(resp, secinfo),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT,
		TRACE_XDR_CMPD_VARARGS
	)
);

TRACE_EVENT(enc_seek4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_seek *seek
	),
	TP_ARGS(resp, seek),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u64, offset)
		__field(bool, eof)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->offset = seek->seek_pos;
		__entry->eof = !!seek->seek_eof;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "offset=%llu%s",
		TRACE_XDR_CMPD_VARARGS,
		__entry->offset, __entry->eof ? " (eof)" : ""
	)
);

TRACE_EVENT(enc_sequence4resok,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfsd4_sequence *seq
	),
	TP_ARGS(resp, seq),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__array(u8, sessionid, NFS4_MAX_SESSIONID_LEN)
		__field(u32, seqid)
		__field(u32, slotid)
		__field(u32, maxslots)
		__field(unsigned long, flags)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		memcpy(__entry->sessionid, seq->sessionid.data,
		       NFS4_MAX_SESSIONID_LEN);
		__entry->seqid = seq->seqid;
		__entry->slotid = seq->slotid;
		__entry->maxslots = seq->maxslots;
		__entry->flags = seq->status_flags;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT
		"sessionid=%s seqid=%u slot=%u/%u flags=%s",
		TRACE_XDR_CMPD_VARARGS,
		show_nfs4_sessionid(__entry->sessionid),
		__entry->seqid, __entry->slotid, __entry->maxslots,
		show_nfs4_seq4_status(__entry->flags)
	)
);


/**
 ** FATTR4 tracepoints
 **/

TRACE_EVENT(enc_fattr4_supported_attrs,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const u32 *supp
	),
	TP_ARGS(resp, supp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_BITMAP_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
		TRACE_NFS4_BITMAP_ASSIGNS(supp);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_BITMAP_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_BITMAP_VARARGS
	)
);

TRACE_EVENT(enc_fattr4_type,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		u32 type
	),
	TP_ARGS(resp, type),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(unsigned long, type)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->type = type;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "type=%s",
		TRACE_XDR_CMPD_VARARGS,
		show_nfs4_file_type(__entry->type)
	)
);

TRACE_EVENT(enc_fattr4_fh_expire_type,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		u32 fh_expire_type
	),
	TP_ARGS(resp, fh_expire_type),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(unsigned long, fh_expire_type)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->fh_expire_type = fh_expire_type;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "fh_expire_type=%s",
		TRACE_XDR_CMPD_VARARGS,
		show_nfs4_fh_expire_type(__entry->fh_expire_type)
	)
);

TRACE_EVENT(enc_fattr4_fsid,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const __be32 *fsid
	),
	TP_ARGS(resp, fsid),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__array(u8, fsid, 16)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		memcpy(__entry->fsid, fsid, 16);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "fsid=%s",
		TRACE_XDR_CMPD_VARARGS,
		__print_hex_str(__entry->fsid, 16)
	)
);

TRACE_EVENT(enc_fattr4_lease_time,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		u32 lease_time
	),
	TP_ARGS(resp, lease_time),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u32, lease_time)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->lease_time = lease_time;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "lease_time=%u",
		TRACE_XDR_CMPD_VARARGS, __entry->lease_time
	)
);

TRACE_EVENT(enc_fattr4_rdattr_err,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		u32 rdattr_err
	),
	TP_ARGS(resp, rdattr_err),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(unsigned long, rdattr_err)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->rdattr_err = rdattr_err;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "rd_attr_err=%s",
		TRACE_XDR_CMPD_VARARGS, show_nfs4_status(__entry->rdattr_err)
	)
);

TRACE_EVENT(enc_fattr4_ace,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const struct nfs4_ace *ace
	),
	TP_ARGS(resp, ace),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(unsigned long, type)
		__field(unsigned long, flags)
		__field(unsigned long, access_mask)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->type = ace->type;
		__entry->flags = ace->flag;
		__entry->access_mask = ace->access_mask & NFS4_ACE_MASK_ALL;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "type=%s flags=%s access_mask=%s",
		TRACE_XDR_CMPD_VARARGS,
		show_nfs4_ace4_access_type(__entry->type),
		show_nfs4_ace4_flags(__entry->flags),
		show_nfs4_ace4_access_mask(__entry->access_mask)
	)
);

TRACE_EVENT(enc_fattr4_aclsupport,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		u32 aclsupport
	),
	TP_ARGS(resp, aclsupport),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(unsigned long, aclsupport)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->aclsupport = aclsupport;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "support=%s",
		TRACE_XDR_CMPD_VARARGS,
		show_nfs4_aclsupport(__entry->aclsupport)
	)
);

TRACE_EVENT(enc_fattr4_filehandle,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const svc_fh *fhp
	),
	TP_ARGS(resp, fhp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u32, fh_hash)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->fh_hash = knfsd_fh_hash(&fhp->fh_handle);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "fh_hash=0x%08x",
		TRACE_XDR_CMPD_VARARGS, __entry->fh_hash
	)
);

TRACE_EVENT(enc_fattr4_fileid,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		u64 fileid
	),
	TP_ARGS(resp, fileid),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u64, fileid)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->fileid = fileid;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "fileid=%llu",
		TRACE_XDR_CMPD_VARARGS, __entry->fileid
	)
);

TRACE_EVENT(enc_fattr4_maxname,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		u32 maxname
	),
	TP_ARGS(resp, maxname),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u32, maxname)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->maxname = maxname;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "maxname=%u",
		TRACE_XDR_CMPD_VARARGS, __entry->maxname
	)
);

TRACE_EVENT(enc_fattr4_mode,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		umode_t mode
	),
	TP_ARGS(resp, mode),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(unsigned long, mode)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->mode = mode;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "mode=%lo %s",
		TRACE_XDR_CMPD_VARARGS,
		__entry->mode, show_fs_umode(__entry->mode)
	)
);

TRACE_EVENT(enc_fattr4_numlinks,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		u32 numlinks
	),
	TP_ARGS(resp, numlinks),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u32, numlinks)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->numlinks = numlinks;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "numlinks=%u",
		TRACE_XDR_CMPD_VARARGS, __entry->numlinks
	)
);

TRACE_EVENT(enc_fattr4_owner,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		kuid_t uid
	),
	TP_ARGS(resp, uid),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u32, uid)
	),
	TP_fast_assign(
		struct user_namespace *userns =
				nfsd_user_namespace(resp->rqstp);

		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->uid = (u32)from_kuid_munged(userns, uid);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "uid=%u",
		TRACE_XDR_CMPD_VARARGS, __entry->uid
	)
);

TRACE_EVENT(enc_fattr4_group,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		kgid_t gid
	),
	TP_ARGS(resp, gid),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u32, gid)
	),
	TP_fast_assign(
		struct user_namespace *userns =
				nfsd_user_namespace(resp->rqstp);

		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->gid = (u32)from_kgid_munged(userns, gid);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "gid=%u",
		TRACE_XDR_CMPD_VARARGS, __entry->gid
	)
);

TRACE_EVENT(enc_fattr4_rawdev,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		dev_t rdev
	),
	TP_ARGS(resp, rdev),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u32, major)
		__field(u32, minor)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->major = (u32)MAJOR(rdev);
		__entry->minor = (u32)MINOR(rdev);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "rdev=(%u, %u)",
		TRACE_XDR_CMPD_VARARGS, __entry->major, __entry->minor
	)
);

TRACE_EVENT(enc_fattr4_mounted_on_fileid,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		u64 fileid
	),
	TP_ARGS(resp, fileid),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(u64, fileid)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->fileid = fileid;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "fileid=%llu",
		TRACE_XDR_CMPD_VARARGS, __entry->fileid
	)
);

TRACE_EVENT(enc_fattr4_suppattr_exclcreat,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		const u32 *supp
	),
	TP_ARGS(resp, supp),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS
		TRACE_NFS4_BITMAP_FIELDS
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);
		TRACE_NFS4_BITMAP_ASSIGNS(supp);
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT TRACE_NFS4_BITMAP_FORMAT,
		TRACE_XDR_CMPD_VARARGS, TRACE_NFS4_BITMAP_VARARGS
	)
);

TRACE_EVENT(enc_fattr4_xattr_support,
	TP_PROTO(
		const struct nfsd4_compoundres *resp,
		bool supported
	),
	TP_ARGS(resp, supported),
	TP_STRUCT__entry(
		TRACE_SVC_XDR_CMPD_FIELDS

		__field(bool, supported)
	),
	TP_fast_assign(
		TRACE_SVC_XDR_CMPD_RES_ASSIGNS(resp);

		__entry->supported = supported;
	),
	TP_printk(TRACE_XDR_CMPD_FORMAT "xattrs %ssupported",
		TRACE_XDR_CMPD_VARARGS,
		__entry->supported ? "" : "un"
	)
);

