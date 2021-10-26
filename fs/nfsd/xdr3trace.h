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


/**
 ** Server-side argument decoding tracepoints
 **/

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


/**
 ** Server-side result encoding tracepoints
 **/

