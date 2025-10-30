/* SPDX-License-Identifier: GPL-2.0 */
/*
 * XDR types for NFSv3 in nfsd.
 *
 * Copyright (C) 1996-1998, Olaf Kirch <okir@monad.swb.de>
 */

#ifndef _LINUX_NFSD_XDR3_H
#define _LINUX_NFSD_XDR3_H

#include "xdr.h"
#include "nfs3xdr_gen.h"

struct nfsd3_getattrargs {
	struct GETATTR3args	xdrgen;
	struct svc_fh		fh;
};

static_assert(offsetof(struct nfsd3_getattrargs, xdrgen) == 0);

struct nfsd3_setattrargs {
	struct SETATTR3args	xdrgen;
	struct timespec64	guard;
	struct svc_fh		fh;
	struct iattr		iattrs;
};

static_assert(offsetof(struct nfsd3_setattrargs, xdrgen) == 0);

struct nfsd3_lookupargs {
	struct LOOKUP3args	xdrgen;
	struct svc_fh		fh;
};

static_assert(offsetof(struct nfsd3_lookupargs, xdrgen) == 0);

struct nfsd3_accessargs {
	struct ACCESS3args	xdrgen;
	struct svc_fh		fh;

	/* used by NFS_ACL v2 */
	__u32			access;
};

static_assert(offsetof(struct nfsd3_accessargs, xdrgen) == 0);

struct nfsd3_readlinkargs {
	struct READLINK3args	xdrgen;
	struct svc_fh		fh;
};

static_assert(offsetof(struct nfsd3_readlinkargs, xdrgen) == 0);

struct nfsd3_readargs {
	struct READ3args	xdrgen;
	struct svc_fh		fh;
};

static_assert(offsetof(struct nfsd3_readargs, xdrgen) == 0);

struct nfsd3_writeargs {
	struct WRITE3args	xdrgen;
	svc_fh			fh;
	struct xdr_buf		payload;
};

static_assert(offsetof(struct nfsd3_writeargs, xdrgen) == 0);

struct nfsd3_createargs {
	struct CREATE3args	xdrgen;
	struct svc_fh		fh;
	struct iattr		attrs;
};

static_assert(offsetof(struct nfsd3_createargs, xdrgen) == 0);

struct nfsd3_mkdirargs {
	struct MKDIR3args	xdrgen;
	struct svc_fh		fh;
	struct iattr		attrs;
};

static_assert(offsetof(struct nfsd3_mkdirargs, xdrgen) == 0);

struct nfsd3_symlinkargs {
	struct SYMLINK3args	xdrgen;
	struct svc_fh		ffh;
	struct iattr		attrs;
};

static_assert(offsetof(struct nfsd3_symlinkargs, xdrgen) == 0);

struct nfsd3_mknodargs {
	struct MKNOD3args	xdrgen;
	struct svc_fh		fh;
	struct iattr		attrs;
};

static_assert(offsetof(struct nfsd3_mknodargs, xdrgen) == 0);

struct nfsd3_removeargs {
	struct REMOVE3args	xdrgen;
	struct svc_fh		fh;
};

static_assert(offsetof(struct nfsd3_removeargs, xdrgen) == 0);

struct nfsd3_rmdirargs {
	struct RMDIR3args	xdrgen;
	struct svc_fh		fh;
};

static_assert(offsetof(struct nfsd3_rmdirargs, xdrgen) == 0);

struct nfsd3_renameargs {
	struct RENAME3args	xdrgen;
	struct svc_fh		ffh;
	struct svc_fh		tfh;
};

static_assert(offsetof(struct nfsd3_renameargs, xdrgen) == 0);

struct nfsd3_linkargs {
	struct svc_fh		ffh;
	struct svc_fh		tfh;
	char *			tname;
	unsigned int		tlen;
};

struct nfsd3_readdirargs {
	struct svc_fh		fh;
	__u64			cookie;
	__u32			count;
	__be32 *		verf;
};

struct nfsd3_commitargs {
	struct svc_fh		fh;
	__u64			offset;
	__u32			count;
};

struct nfsd3_getaclargs {
	struct svc_fh		fh;
	__u32			mask;
};

struct posix_acl;
struct nfsd3_setaclargs {
	struct svc_fh		fh;
	__u32			mask;
	struct posix_acl	*acl_access;
	struct posix_acl	*acl_default;
};

struct nfsd3_attrstat {
	__be32			status;
	struct svc_fh		fh;
};

struct nfsd3_getattrres {
	struct GETATTR3res	xdrgen;
	struct kstat            stat;
};

static_assert(offsetof(struct nfsd3_getattrres, xdrgen) == 0);

struct nfsd3_setattrres {
	struct SETATTR3res	xdrgen;
};

static_assert(offsetof(struct nfsd3_setattrres, xdrgen) == 0);

struct nfsd3_lookupres {
	struct LOOKUP3res	xdrgen;
	u8                      fh_data[NFS3_FHSIZE];
	struct svc_fh		fh;
};

static_assert(offsetof(struct nfsd3_lookupres, xdrgen) == 0);

struct nfsd3_accessres {
	struct ACCESS3res	xdrgen;
	struct svc_fh		fh;

	/* used by NFS_ACL v2 */
	__be32			status;
	__u32			access;
	struct kstat		stat;
};

static_assert(offsetof(struct nfsd3_accessres, xdrgen) == 0);

struct nfsd3_readlinkres {
	struct READLINK3res	xdrgen;
	struct page		**pages;
};

static_assert(offsetof(struct nfsd3_readlinkres, xdrgen) == 0);

struct nfsd3_readres {
	struct READ3res		xdrgen;
	struct page		**pages;
};

static_assert(offsetof(struct nfsd3_readres, xdrgen) == 0);

struct nfsd3_writeres {
	struct WRITE3res	xdrgen;
};

static_assert(offsetof(struct nfsd3_writeres, xdrgen) == 0);

struct nfsd3_createres {
	struct CREATE3res	xdrgen;
	u8			fh_data[NFS3_FHSIZE];
	struct svc_fh		fh;
};

static_assert(offsetof(struct nfsd3_createres, xdrgen) == 0);

struct nfsd3_mkdirres {
	struct MKDIR3res	xdrgen;
	u8			fh_data[NFS3_FHSIZE];
	struct svc_fh		fh;
};

static_assert(offsetof(struct nfsd3_mkdirres, xdrgen) == 0);

struct nfsd3_symlinkres {
	struct SYMLINK3res	xdrgen;
	u8			fh_data[NFS3_FHSIZE];
	struct svc_fh		fh;
};

static_assert(offsetof(struct nfsd3_symlinkres, xdrgen) == 0);

struct nfsd3_mknodres {
	struct MKNOD3res	xdrgen;
	u8			fh_data[NFS3_FHSIZE];
	struct svc_fh		fh;
};

static_assert(offsetof(struct nfsd3_mknodres, xdrgen) == 0);

struct nfsd3_removeres {
	struct REMOVE3res	xdrgen;
};

static_assert(offsetof(struct nfsd3_removeres, xdrgen) == 0);

struct nfsd3_rmdirres {
	struct RMDIR3res	xdrgen;
};

static_assert(offsetof(struct nfsd3_rmdirres, xdrgen) == 0);

struct nfsd3_renameres {
	struct RENAME3res	xdrgen;
};

static_assert(offsetof(struct nfsd3_renameres, xdrgen) == 0);

struct nfsd3_linkres {
	__be32			status;
	struct svc_fh		tfh;
	struct svc_fh		fh;
};

struct nfsd3_readdirres {
	/* Components of the reply */
	__be32			status;
	struct svc_fh		fh;
	__be32			verf[2];

	/* Used to encode the reply's entry list */
	struct xdr_stream	xdr;
	struct xdr_buf		dirlist;
	struct svc_fh		scratch;
	struct readdir_cd	common;
	unsigned int		cookie_offset;
	struct svc_rqst *	rqstp;

};

struct nfsd3_fsstatres {
	__be32			status;
	struct kstatfs		stats;
	__u32			invarsec;
};

struct nfsd3_fsinfores {
	__be32			status;
	__u32			f_rtmax;
	__u32			f_rtpref;
	__u32			f_rtmult;
	__u32			f_wtmax;
	__u32			f_wtpref;
	__u32			f_wtmult;
	__u32			f_dtpref;
	__u64			f_maxfilesize;
	__u32			f_properties;
};

struct nfsd3_pathconfres {
	__be32			status;
	__u32			p_link_max;
	__u32			p_name_max;
	__u32			p_no_trunc;
	__u32			p_chown_restricted;
	__u32			p_case_insensitive;
	__u32			p_case_preserving;
};

struct nfsd3_commitres {
	__be32			status;
	struct svc_fh		fh;
	__be32			verf[2];
};

struct nfsd3_getaclres {
	__be32			status;
	struct svc_fh		fh;
	int			mask;
	struct posix_acl	*acl_access;
	struct posix_acl	*acl_default;
	struct kstat		stat;
};

/* dummy type for release */
struct nfsd3_fhandle_pair {
	__u32			dummy;
	struct svc_fh		fh1;
	struct svc_fh		fh2;
};

/*
 * Storage requirements for XDR arguments and results.
 */
union nfsd3_xdrstore {
	struct nfsd3_getattrargs	getattrargs;
	struct nfsd3_setattrargs	setattrargs;
	struct nfsd3_lookupargs		lookupargs;
	struct nfsd3_accessargs		accessargs;
	struct nfsd3_readlinkargs	readlinkargs;
	struct nfsd3_readargs		readargs;
	struct nfsd3_writeargs		writeargs;
	struct nfsd3_createargs		createargs;
	struct nfsd3_mkdirargs		mkdirargs;
	struct nfsd3_symlinkargs	symlinkargs;
	struct nfsd3_mknodargs		mknodargs;
	struct nfsd3_removeargs		removeargs;
	struct nfsd3_rmdirargs		rmdirargs;
	struct nfsd3_renameargs		renameargs;
	struct nfsd3_linkargs		linkargs;
	struct nfsd3_readdirargs	readdirargs;

	struct nfsd3_getattrres		getattrres;
	struct nfsd3_setattrres		setattrres;
	struct nfsd3_lookupres		lookupres;
	struct nfsd3_accessres		accessres;
	struct nfsd3_readlinkres	readlinkres;
	struct nfsd3_readres		readres;
	struct nfsd3_writeres		writeres;
	struct nfsd3_createres		createres;
	struct nfsd3_mkdirres		mkdirres;
	struct nfsd3_symlinkres		symlinkres;
	struct nfsd3_mknodres		mknodres;
	struct nfsd3_removeres		removeres;
	struct nfsd3_rmdirres		rmdirres;
	struct nfsd3_renameres		renameres;
	struct nfsd3_linkres		linkres;
	struct nfsd3_readdirres		readdirres;
	struct nfsd3_fsstatres		fsstatres;
	struct nfsd3_fsinfores		fsinfores;
	struct nfsd3_pathconfres	pathconfres;
	struct nfsd3_commitres		commitres;
	struct nfsd3_getaclres		getaclres;
};

#define NFS3_SVC_XDRSIZE		sizeof(union nfsd3_xdrstore)

bool nfs3svc_decode_fhandleargs(struct svc_rqst *rqstp, struct xdr_stream *xdr);
bool nfs_svc_decode_write3arg(struct svc_rqst *rqstp, struct xdr_stream *xdr);
bool nfs3svc_decode_linkargs(struct svc_rqst *rqstp, struct xdr_stream *xdr);
bool nfs3svc_decode_readdirargs(struct svc_rqst *rqstp, struct xdr_stream *xdr);
bool nfs3svc_decode_readdirplusargs(struct svc_rqst *rqstp, struct xdr_stream *xdr);
bool nfs3svc_decode_commitargs(struct svc_rqst *rqstp, struct xdr_stream *xdr);

bool nfs_svc_encode_readlink3res(struct svc_rqst *rqstp, struct xdr_stream *xdr);
bool nfs_svc_encode_read3res(struct svc_rqst *rqstp, struct xdr_stream *xdr);
bool nfs3svc_encode_linkres(struct svc_rqst *rqstp, struct xdr_stream *xdr);
bool nfs3svc_encode_readdirres(struct svc_rqst *rqstp, struct xdr_stream *xdr);
bool nfs3svc_encode_fsstatres(struct svc_rqst *rqstp, struct xdr_stream *xdr);
bool nfs3svc_encode_fsinfores(struct svc_rqst *rqstp, struct xdr_stream *xdr);
bool nfs3svc_encode_pathconfres(struct svc_rqst *rqstp, struct xdr_stream *xdr);
bool nfs3svc_encode_commitres(struct svc_rqst *rqstp, struct xdr_stream *xdr);

void nfs3svc_release_fhandle(struct svc_rqst *);
void nfs3svc_release_fhandle2(struct svc_rqst *);

void nfs3svc_encode_cookie3(struct nfsd3_readdirres *resp, u64 offset);
int nfs3svc_encode_entry3(void *data, const char *name, int namlen,
			  loff_t offset, u64 ino, unsigned int d_type);
int nfs3svc_encode_entryplus3(void *data, const char *name, int namlen,
			      loff_t offset, u64 ino, unsigned int d_type);
/* Helper functions for NFSv3 ACL code */
bool svcxdr_decode_nfs_fh3(struct xdr_stream *xdr, struct svc_fh *fhp);
bool svcxdr_encode_nfsstat3(struct xdr_stream *xdr, __be32 status);
bool svcxdr_encode_post_op_attr(struct svc_rqst *rqstp, struct xdr_stream *xdr,
				const struct svc_fh *fhp);

#endif /* _LINUX_NFSD_XDR3_H */
