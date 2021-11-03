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


/**
 ** FATTR4 tracepoints
 **/

