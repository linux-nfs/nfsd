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


/**
 ** FATTR4 tracepoints
 **/

