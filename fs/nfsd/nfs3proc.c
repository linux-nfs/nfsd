// SPDX-License-Identifier: GPL-2.0
/*
 * Process version 3 NFS requests.
 *
 * Copyright (C) 1996, 1997, 1998 Olaf Kirch <okir@monad.swb.de>
 */

#include <linux/fs.h>
#include <linux/ext2_fs.h>
#include <linux/magic.h>
#include <linux/namei.h>

#include "cache.h"
#include "xdr3.h"
#include "vfs.h"
#include "filecache.h"
#include "trace.h"

#define NFSDDBG_FACILITY		NFSDDBG_PROC

static int nfsd3_ftype3_to_mode(ftype3 ftype)
{
	switch (ftype) {
	case NF3REG:  return S_IFREG;
	case NF3DIR:  return S_IFDIR;
	case NF3BLK:  return S_IFBLK;
	case NF3CHR:  return S_IFCHR;
	case NF3LNK:  return S_IFLNK;
	case NF3SOCK: return S_IFSOCK;
	case NF3FIFO: return S_IFIFO;
	default:
		return 0;
	}
}

static __be32 nfsd3_map_status(__be32 status)
{
	switch (status) {
	case nfs_ok:
		break;
	case nfserr_nofilehandle:
		status = nfserr_badhandle;
		break;
	case nfserr_wrongsec:
	case nfserr_file_open:
		status = nfserr_acces;
		break;
	case nfserr_symlink_not_dir:
		status = nfserr_notdir;
		break;
	case nfserr_symlink:
	case nfserr_wrong_type:
		status = nfserr_inval;
		break;
	}
	return status;
}

/* XDR decoding has already checked that the FH length is valid */
static __always_inline void
nfsd3_fh3_to_svc_fh(struct svc_fh *fhp, const struct nfs_fh3 *fh3)
{
	fh_init(fhp, NFS3_FHSIZE);
	fhp->fh_handle.fh_size = fh3->data.len;
	memcpy(&fhp->fh_handle.fh_raw, fh3->data.data, fh3->data.len);
}

static __always_inline void
nfsd3_svc_fh_to_fh3(struct nfs_fh3 *fh3, const struct svc_fh *fhp, u8 *scratch)
{
	memcpy(scratch, fhp->fh_handle.fh_raw, fhp->fh_handle.fh_size);
	fh3->data.data = scratch;
	fh3->data.len = fhp->fh_handle.fh_size;
}

static __always_inline void
nfsd3_timespec64_to_nfstime3(struct nfstime3 *dst,
			     const struct timespec64 *src)
{
	dst->seconds = src->tv_sec;
	dst->nseconds = src->tv_nsec;
}

static __be32
nfsd3_check_filename(const unsigned char *name, u32 len)
{
	u32 i;

	if (len == 0)
		return nfserr_inval;
	if (len > NFS3_MAXNAMLEN)
		return nfserr_nametoolong;
	for (i = 0; i < len; i++) {
		if (name[i] == '\0' || name[i] == '/')
			return nfserr_inval;
	}
	return nfs_ok;
}

static u32
nfsd3_mode_to_ftype3(umode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFREG:  return NF3REG;
	case S_IFDIR:  return NF3DIR;
	case S_IFBLK:  return NF3BLK;
	case S_IFCHR:  return NF3CHR;
	case S_IFLNK:  return NF3LNK;
	case S_IFSOCK: return NF3SOCK;
	case S_IFIFO:  return NF3FIFO;
	}

	pr_warn_once("NFSD: unexpected file type: mode=0%o\n", mode);
	return NF3REG;
}

static __always_inline void
nfsd3_nfstime3_to_timespec64(struct timespec64 *dst,
			     const struct nfstime3 *src)
{
	dst->tv_sec = src->seconds;
	dst->tv_nsec = src->nseconds;
}

static void
nfsd3_stat_to_fattr3(struct svc_rqst *rqstp, struct fattr3 *fattr,
		     const struct kstat *stat, const struct svc_fh *fhp)
{
	struct user_namespace *userns = nfsd_user_namespace(rqstp);

	fattr->type = nfsd3_mode_to_ftype3(stat->mode);
	fattr->mode = stat->mode & S_IALLUGO;
	fattr->nlink = stat->nlink;
	fattr->uid = from_kuid_munged(userns, stat->uid);
	fattr->gid = from_kgid_munged(userns, stat->gid);
	if (S_ISLNK(stat->mode) && stat->size > NFS3_MAXPATHLEN)
		fattr->size = NFS3_MAXPATHLEN;
	else
		fattr->size = stat->size;
	fattr->used = stat->blocks << 9;
	fattr->rdev.specdata1 = MAJOR(stat->rdev);
	fattr->rdev.specdata2 = MINOR(stat->rdev);

	switch (fsid_source(fhp)) {
	case FSIDSOURCE_FSID:
		fattr->fsid = (u64)fhp->fh_export->ex_fsid;
		break;
	case FSIDSOURCE_UUID:
		fattr->fsid = ((u64 *)fhp->fh_export->ex_uuid)[0];
		fattr->fsid ^= ((u64 *)fhp->fh_export->ex_uuid)[1];
		break;
	default:
		fattr->fsid = (u64)huge_encode_dev(fhp->fh_dentry->d_sb->s_dev);
	}
	fattr->fileid = stat->ino;

	nfsd3_timespec64_to_nfstime3(&fattr->atime, &stat->atime);
	nfsd3_timespec64_to_nfstime3(&fattr->mtime, &stat->mtime);
	nfsd3_timespec64_to_nfstime3(&fattr->ctime, &stat->ctime);
}

static void
nfsd3_fill_wcc_data(struct svc_rqst *rqstp, struct wcc_data *wcc,
		    const struct svc_fh *fhp)
{
	wcc->before.attributes_follow = fhp->fh_pre_saved;
	if (fhp->fh_pre_saved) {
		struct wcc_attr *wattr = &wcc->before.u.attributes;

		wattr->size = fhp->fh_pre_size;
		nfsd3_timespec64_to_nfstime3(&wattr->mtime, &fhp->fh_pre_mtime);
		nfsd3_timespec64_to_nfstime3(&wattr->ctime, &fhp->fh_pre_ctime);
	}

	wcc->after.attributes_follow = fhp->fh_post_saved;
	if (fhp->fh_post_saved)
		nfsd3_stat_to_fattr3(rqstp, &wcc->after.u.attributes,
				     &fhp->fh_post_attr, fhp);
}

static void
nfsd3_sattr3_to_iattr(struct svc_rqst *rqstp, struct iattr *iap,
		      const struct sattr3 *sattr)
{
	iap->ia_valid = 0;

	if (sattr->mode.set_it) {
		iap->ia_valid |= ATTR_MODE;
		iap->ia_mode = sattr->mode.u.mode;
	}
	if (sattr->uid.set_it) {
		iap->ia_uid = make_kuid(nfsd_user_namespace(rqstp),
					sattr->uid.u.uid);
		if (uid_valid(iap->ia_uid))
			iap->ia_valid |= ATTR_UID;
	}
	if (sattr->gid.set_it) {
		iap->ia_gid = make_kgid(nfsd_user_namespace(rqstp),
					sattr->gid.u.gid);
		if (gid_valid(iap->ia_gid))
			iap->ia_valid |= ATTR_GID;
	}
	if (sattr->size.set_it) {
		iap->ia_valid |= ATTR_SIZE;
		iap->ia_size = sattr->size.u.size;
	}
	switch (sattr->atime.set_it) {
	case DONT_CHANGE:
		break;
	case SET_TO_SERVER_TIME:
		iap->ia_valid |= ATTR_ATIME;
		break;
	case SET_TO_CLIENT_TIME:
		nfsd3_nfstime3_to_timespec64(&iap->ia_atime,
					     &sattr->atime.u.atime);
		iap->ia_valid |= ATTR_ATIME | ATTR_ATIME_SET;
		break;
	}
	switch (sattr->mtime.set_it) {
	case DONT_CHANGE:
		break;
	case SET_TO_SERVER_TIME:
		iap->ia_valid |= ATTR_MTIME;
		break;
	case SET_TO_CLIENT_TIME:
		nfsd3_nfstime3_to_timespec64(&iap->ia_mtime,
					     &sattr->mtime.u.mtime);
		iap->ia_valid |= ATTR_MTIME | ATTR_MTIME_SET;
		break;
	}
}

/*
 * struct kstat is pretty huge. To reduce stack utilization, reuse @fhp's
 * fh_post_attr field as the stat buffer passed to fh_getattr.
 *
 * This is safe to do as long as proc functions that need both WCC and
 * post_op_attrs invoke nfsd3_fill_wcc_data() before invoking
 * nfsd3_fill_post_op_attr() on the same fhp argument.
 */
static void
nfsd3_fill_post_op_attr(struct svc_rqst *rqstp, struct post_op_attr *attr,
			struct svc_fh *fhp)
{
	struct kstat *statp = &fhp->fh_post_attr;
	struct dentry *dentry = fhp->fh_dentry;

	/*
	 * The inode may be NULL if the call failed because of a stale
	 * file handle. In this case, no attributes are returned.
	 */
	if (fhp->fh_no_wcc || !dentry || !d_really_is_positive(dentry))
		goto no_post_op_attrs;
	if (fh_getattr(fhp, statp) != nfs_ok)
		goto no_post_op_attrs;

	attr->attributes_follow = true;
	lease_get_mtime(d_inode(dentry), &statp->mtime);
	nfsd3_stat_to_fattr3(rqstp, &attr->u.attributes, statp, fhp);
	return;

no_post_op_attrs:
	attr->attributes_follow = false;
}

static void
nfsd3_fill_post_op_fh3(struct post_op_fh3 *post_op_fh,
		       const struct svc_fh *fhp, u8 *data)
{
	if (fhp->fh_handle.fh_size != 0) {
		post_op_fh->handle_follows = true;
		nfsd3_svc_fh_to_fh3(&post_op_fh->u.handle, fhp, data);
	} else {
		post_op_fh->handle_follows = false;
	}
}

/*
 * A full specification of each of the following NFSv3 procedures is
 * available in RFC 1813 Section 3.3.
 */

/**
 * nfsd3_proc_null - NFSv3 NULL - Do nothing
 * @rqstp: RPC transaction context
 *
 * Returns an RPC accept_stat value in network byte order.
 */
static __be32
nfsd3_proc_null(struct svc_rqst *rqstp)
{
	return rpc_success;
}

/**
 * nfsd3_proc_getattr - NFSv3 GETATTR - Get file attributes
 * @rqstp: RPC transaction context
 *
 * Returns an RPC accept_stat value in network byte order.
 */
static __be32
nfsd3_proc_getattr(struct svc_rqst *rqstp)
{
	struct nfsd3_getattrargs *argp = rqstp->rq_argp;
	struct nfsd3_getattrres *resp = rqstp->rq_resp;
	struct kstat *statp = &resp->stat;
	struct svc_fh *fhp = &argp->fh;

	nfsd3_fh3_to_svc_fh(fhp, &argp->xdrgen.object);
	trace_nfsd_vfs_getattr(rqstp, fhp);
	resp->xdrgen.status = fh_verify(rqstp, fhp, 0, NFSD_MAY_NOP |
					NFSD_MAY_BYPASS_GSS_ON_ROOT);
	if (resp->xdrgen.status != nfs_ok)
		goto out;

	resp->xdrgen.status = fh_getattr(fhp, statp);

out:
	if (resp->xdrgen.status == nfs_ok) {
		lease_get_mtime(d_inode(fhp->fh_dentry), &statp->mtime);
		nfsd3_stat_to_fattr3(rqstp, &resp->xdrgen.u.resok.obj_attributes,
				     statp, fhp);
	} else {
		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
	}

	fh_put(fhp);
	return rpc_success;
}

/**
 * nfsd3_proc_setattr - NFSv3 SETATTR - Set file attributes
 * @rqstp: RPC transaction context
 *
 * Returns an RPC accept_stat value in network byte order.
 */
static __be32
nfsd3_proc_setattr(struct svc_rqst *rqstp)
{
	struct nfsd3_setattrargs *argp = rqstp->rq_argp;
	struct nfsd3_setattrres *resp = rqstp->rq_resp;
	const struct timespec64 *guardtime = NULL;
	struct svc_fh *fhp = &argp->fh;
	struct nfsd_attrs nattrs = {
		.na_iattr	= &argp->iattrs,
	};

	nfsd3_fh3_to_svc_fh(fhp, &argp->xdrgen.object);
	nfsd3_sattr3_to_iattr(rqstp, &argp->iattrs, &argp->xdrgen.new_attributes);
	if (argp->xdrgen.guard.check) {
		nfsd3_nfstime3_to_timespec64(&argp->guard,
					     &argp->xdrgen.guard.u.obj_ctime);
		guardtime = &argp->guard;
	}

	resp->xdrgen.status = nfsd_setattr(rqstp, fhp, &nattrs, guardtime);

	if (resp->xdrgen.status == nfs_ok) {
		nfsd3_fill_wcc_data(rqstp, &resp->xdrgen.u.resok.obj_wcc, fhp);
	} else {
		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		nfsd3_fill_wcc_data(rqstp, &resp->xdrgen.u.resfail.obj_wcc, fhp);
	}

	fh_put(fhp);
	return rpc_success;
}

/**
 * nfsd3_proc_lookup - NFSv3 LOOKUP - Lookup filename
 * @rqstp: RPC transaction context
 *
 * Returns an RPC accept_stat value in network byte order.
 */
static __be32
nfsd3_proc_lookup(struct svc_rqst *rqstp)
{
	struct nfsd3_lookupargs *argp = rqstp->rq_argp;
	struct nfsd3_lookupres *resp = rqstp->rq_resp;
	struct diropargs3 *what = &argp->xdrgen.what;
	struct svc_fh *dirfhp = &argp->fh;
	struct svc_fh *fhp = &resp->fh;

	nfsd3_fh3_to_svc_fh(dirfhp, &what->dir);

	fh_init(fhp, NFS3_FHSIZE);
	resp->xdrgen.status = nfsd_lookup(rqstp, dirfhp,
					  (char *)what->name.data,
					  what->name.len, fhp);

	if (resp->xdrgen.status == nfs_ok) {
		struct LOOKUP3resok *resok = &resp->xdrgen.u.resok;

		nfsd3_svc_fh_to_fh3(&resok->object, fhp, resp->fh_data);
		nfsd3_fill_post_op_attr(rqstp, &resok->obj_attributes, fhp);
		nfsd3_fill_post_op_attr(rqstp, &resok->dir_attributes, dirfhp);
	} else {
		struct LOOKUP3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		nfsd3_fill_post_op_attr(rqstp, &resfail->dir_attributes, dirfhp);
	}

	fh_put(fhp);
	fh_put(dirfhp);
	return rpc_success;
}

/**
 * nfsd3_proc_access - NFSv3 ACCESS - Check access permission
 * @rqstp: RPC transaction context
 *
 * Returns an RPC accept_stat value in network byte order.
 */
static __be32
nfsd3_proc_access(struct svc_rqst *rqstp)
{
	struct nfsd3_accessargs *argp = rqstp->rq_argp;
	struct nfsd3_accessres *resp = rqstp->rq_resp;
	struct svc_fh *fhp = &argp->fh;

	nfsd3_fh3_to_svc_fh(fhp, &argp->xdrgen.object);

	resp->xdrgen.status = nfsd_access(rqstp, fhp, &argp->xdrgen.access,
					  NULL);

	if (resp->xdrgen.status == nfs_ok) {
		struct ACCESS3resok *resok = &resp->xdrgen.u.resok;

		resok->access = argp->xdrgen.access;
		nfsd3_fill_post_op_attr(rqstp, &resok->obj_attributes, fhp);
	} else {
		struct ACCESS3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		nfsd3_fill_post_op_attr(rqstp, &resfail->obj_attributes, fhp);
	}

	fh_put(fhp);
	return rpc_success;
}

/**
 * nfsd3_proc_readlink - NFSv3 READLINK - Read from symbolic link
 * @rqstp: RPC transaction context
 *
 * Returns an RPC accept_stat value in network byte order.
 */
static __be32
nfsd3_proc_readlink(struct svc_rqst *rqstp)
{
	struct nfsd3_readlinkargs *argp = rqstp->rq_argp;
	struct nfsd3_readlinkres *resp = rqstp->rq_resp;
	struct svc_fh *fhp = &argp->fh;
	u32 len;

	nfsd3_fh3_to_svc_fh(fhp, &argp->xdrgen.symlink);

	len = NFS3_MAXPATHLEN;
	resp->pages = rqstp->rq_next_page++;
	resp->xdrgen.status = nfsd_readlink(rqstp, fhp,
					    page_address(*resp->pages), &len);

	if (resp->xdrgen.status == nfs_ok) {
		struct READLINK3resok *resok = &resp->xdrgen.u.resok;

		resok->data.len = len;
		nfsd3_fill_post_op_attr(rqstp, &resok->symlink_attributes, fhp);
	} else {
		struct READLINK3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		nfsd3_fill_post_op_attr(rqstp, &resfail->symlink_attributes,
					fhp);
	}

	fh_put(fhp);
	return rpc_success;
}

/**
 * nfsd3_proc_read - NFSv3 READ - Read from file
 * @rqstp: RPC transaction context
 *
 * Returns an RPC accept_stat value in network byte order.
 */
static __be32
nfsd3_proc_read(struct svc_rqst *rqstp)
{
	struct nfsd3_readargs *argp = rqstp->rq_argp;
	struct nfsd3_readres *resp = rqstp->rq_resp;
	unsigned long count = argp->xdrgen.count;
	u64 offset = argp->xdrgen.offset;
	struct svc_fh *fhp = &argp->fh;
	u32 eof;

	nfsd3_fh3_to_svc_fh(fhp, &argp->xdrgen.file);
	count = min_t(u32, count, svc_max_payload(rqstp));
	count = min_t(u32, count, rqstp->rq_res.buflen);
	if (offset > (u64)OFFSET_MAX)
		offset = (u64)OFFSET_MAX;
	if (offset + count > (u64)OFFSET_MAX)
		count = (u64)OFFSET_MAX - offset;

	/*
	 * Obtain buffer pointer for payload.
	 * 1 (status) + 22 (post_op_attr) + 1 (count) + 1 (eof)
	 * + 1 (xdr opaque byte count) = 26
	 */
	svc_reserve_auth(rqstp, ((1 + NFS3_POST_OP_ATTR_WORDS + 3) << 2) +
			 count + 4);
	resp->pages = rqstp->rq_next_page;
	resp->xdrgen.status = nfsd_read(rqstp, fhp, offset, &count, &eof);

	if (resp->xdrgen.status == nfs_ok) {
		struct READ3resok *resok = &resp->xdrgen.u.resok;

		resok->count = count;
		resok->eof = !!eof;
		nfsd3_fill_post_op_attr(rqstp, &resok->file_attributes, fhp);
	} else {
		struct READ3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		nfsd3_fill_post_op_attr(rqstp, &resfail->file_attributes, fhp);
	}

	fh_put(fhp);
	return rpc_success;
}

/**
 * nfsd3_proc_write - NFSv3 WRITE - Write to file
 * @rqstp: RPC transaction context
 *
 * Returns an RPC accept_stat value in network byte order.
 */
static __be32
nfsd3_proc_write(struct svc_rqst *rqstp)
{
	struct nfsd3_writeargs *argp = rqstp->rq_argp;
	struct nfsd3_writeres *resp = rqstp->rq_resp;
	struct svc_fh *fhp = &argp->fh;
	unsigned long count;

	nfsd3_fh3_to_svc_fh(fhp, &argp->xdrgen.file);
	if (argp->xdrgen.count != argp->xdrgen.data.len) {
		resp->xdrgen.status = nfserr_inval;
		goto out;
	}
	count = argp->xdrgen.count;
	if (argp->xdrgen.offset > (u64)OFFSET_MAX ||
	    argp->xdrgen.offset + count > (u64)OFFSET_MAX) {
		resp->xdrgen.status = nfserr_fbig;
		goto out;
	}

	resp->xdrgen.status = nfsd_write(rqstp, fhp, argp->xdrgen.offset,
					 &argp->payload, &count,
					 argp->xdrgen.stable,
					 (__be32 *)resp->xdrgen.u.resok.verf);

out:
	if (resp->xdrgen.status == nfs_ok) {
		struct WRITE3resok *resok = &resp->xdrgen.u.resok;

		resok->count = count;
		resok->committed = argp->xdrgen.stable;
		nfsd3_fill_wcc_data(rqstp, &resok->file_wcc, fhp);
		nfsd3_fill_post_op_attr(rqstp, &resok->file_wcc.after, fhp);
	} else {
		struct WRITE3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		nfsd3_fill_wcc_data(rqstp, &resfail->file_wcc, fhp);
		nfsd3_fill_post_op_attr(rqstp, &resfail->file_wcc.after, fhp);
	}

	fh_put(fhp);
	return rpc_success;
}

/*
 * Implement NFSv3's unchecked, guarded, and exclusive CREATE
 * semantics for regular files. Except for the created file,
 * this operation is stateless on the server.
 */
static __be32
nfsd3_create_file(struct svc_rqst *rqstp, struct svc_fh *dirfhp,
		  struct svc_fh *resfhp, struct nfsd3_createargs *argp)
{
	struct diropargs3 *where = &argp->xdrgen.where;
	struct createhow3 *how = &argp->xdrgen.how;

	struct iattr *iattrs = &argp->attrs;
	struct dentry *parent, *child;
	__u32 v_mtime, v_atime;
	struct inode *inode;
	struct nfsd_attrs nattrs = {
		.na_iattr	= iattrs,
	};
	__be32 status;
	int host_err;

	status = nfsd3_check_filename(where->name.data, where->name.len);
	if (status != nfs_ok)
		return status;

	trace_nfsd_vfs_create(rqstp, dirfhp, S_IFREG, (char *)where->name.data,
			      where->name.len);

	if (isdotent(where->name.data, where->name.len))
		return nfserr_exist;

	if (how->mode != EXCLUSIVE) {
		nfsd3_sattr3_to_iattr(rqstp, iattrs,
				      &how->u.obj_attributes);
		if (!(iattrs->ia_valid & ATTR_MODE))
			iattrs->ia_mode = 0;
	} else {
		memset(iattrs, 0, sizeof(*iattrs));
	}

	status = fh_verify(rqstp, dirfhp, S_IFDIR, NFSD_MAY_EXEC);
	if (status != nfs_ok)
		return status;

	parent = dirfhp->fh_dentry;
	inode = d_inode(parent);

	host_err = fh_want_write(dirfhp);
	if (host_err)
		return nfserrno(host_err);

	inode_lock_nested(inode, I_MUTEX_PARENT);

	child = lookup_one(&nop_mnt_idmap,
			   &QSTR_LEN(where->name.data,
				     where->name.len), parent);
	if (IS_ERR(child)) {
		status = nfserrno(PTR_ERR(child));
		goto out;
	}

	if (d_really_is_negative(child)) {
		status = fh_verify(rqstp, dirfhp, S_IFDIR, NFSD_MAY_CREATE);
		if (status != nfs_ok)
			goto out;
	}

	status = fh_compose(resfhp, dirfhp->fh_export, child, dirfhp);
	if (status != nfs_ok)
		goto out;

	v_mtime = 0;
	v_atime = 0;
	if (how->mode == EXCLUSIVE) {
		u32 *verifier = (u32 *)how->u.verf;

		/*
		 * Solaris 7 gets confused (bugid 4218508) if these have
		 * the high bit set, as do xfs filesystems without the
		 * "bigtime" feature. So just clear the high bits.
		 */
		v_mtime = verifier[0] & 0x7fffffff;
		v_atime = verifier[1] & 0x7fffffff;
	}

	if (d_really_is_positive(child)) {
		status = nfs_ok;

		switch (how->mode) {
		case UNCHECKED:
			if (!d_is_reg(child))
				break;
			iattrs->ia_valid &= ATTR_SIZE;
			goto set_attr;
		case GUARDED:
			status = nfserr_exist;
			break;
		case EXCLUSIVE:
			if (inode_get_mtime_sec(d_inode(child)) == v_mtime &&
			    inode_get_atime_sec(d_inode(child)) == v_atime &&
			    d_inode(child)->i_size == 0) {
				break;
			}
			status = nfserr_exist;
		}
		goto out;
	}

	if (!IS_POSIXACL(inode))
		iattrs->ia_mode &= ~current_umask();

	status = fh_fill_pre_attrs(dirfhp);
	if (status != nfs_ok)
		goto out;
	host_err = vfs_create(&nop_mnt_idmap, inode, child, iattrs->ia_mode, true);
	if (host_err < 0) {
		status = nfserrno(host_err);
		goto out;
	}
	fh_fill_post_attrs(dirfhp);

	/* A newly created file already has a file size of zero. */
	if ((iattrs->ia_valid & ATTR_SIZE) && iattrs->ia_size == 0)
		iattrs->ia_valid &= ~ATTR_SIZE;
	if (how->mode == EXCLUSIVE) {
		iattrs->ia_valid = ATTR_MTIME | ATTR_ATIME |
				   ATTR_MTIME_SET | ATTR_ATIME_SET;
		iattrs->ia_mtime.tv_sec = v_mtime;
		iattrs->ia_atime.tv_sec = v_atime;
		iattrs->ia_mtime.tv_nsec = 0;
		iattrs->ia_atime.tv_nsec = 0;
	}

set_attr:
	status = nfsd_create_setattr(rqstp, dirfhp, resfhp, &nattrs);

out:
	inode_unlock(inode);
	if (child && !IS_ERR(child))
		dput(child);
	fh_drop_write(dirfhp);
	return status;
}

/**
 * nfsd3_proc_create - NFSv3 CREATE - Create a file
 * @rqstp: RPC transaction context
 *
 * Returns an RPC accept_stat value in network byte order.
 */
static __be32
nfsd3_proc_create(struct svc_rqst *rqstp)
{
	struct nfsd3_createargs *argp = rqstp->rq_argp;
	struct nfsd3_createres *resp = rqstp->rq_resp;
	struct svc_fh *dirfhp = &argp->fh;
	struct svc_fh *fhp = &resp->fh;

	nfsd3_fh3_to_svc_fh(dirfhp, &argp->xdrgen.where.dir);

	fh_init(fhp, NFS3_FHSIZE);
	resp->xdrgen.status = nfsd3_create_file(rqstp, dirfhp, fhp, argp);

	if (resp->xdrgen.status == nfs_ok) {
		struct CREATE3resok *resok = &resp->xdrgen.u.resok;

		nfsd3_fill_post_op_fh3(&resok->obj, fhp, resp->fh_data);
		nfsd3_fill_post_op_attr(rqstp, &resok->obj_attributes, fhp);
		nfsd3_fill_wcc_data(rqstp, &resok->dir_wcc, dirfhp);
	} else {
		struct CREATE3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		nfsd3_fill_wcc_data(rqstp, &resfail->dir_wcc, dirfhp);
	}

	fh_put(fhp);
	fh_put(dirfhp);
	return rpc_success;
}

/**
 * nfsd3_proc_mkdir - NFSv3 MKDIR - Create a directory
 * @rqstp: RPC transaction context
 *
 * Returns an RPC accept_stat value in network byte order.
 */
static __be32
nfsd3_proc_mkdir(struct svc_rqst *rqstp)
{
	struct nfsd3_mkdirargs *argp = rqstp->rq_argp;
	struct diropargs3 *where = &argp->xdrgen.where;
	struct nfsd3_mkdirres *resp = rqstp->rq_resp;
	struct iattr *iattrs = &argp->attrs;
	struct svc_fh *dirfhp = &argp->fh;
	struct svc_fh *fhp = &resp->fh;
	struct nfsd_attrs nattrs = {
		.na_iattr	= iattrs,
	};

	nfsd3_fh3_to_svc_fh(dirfhp, &where->dir);
	resp->xdrgen.status = nfsd3_check_filename(where->name.data,
						   where->name.len);
	if (resp->xdrgen.status != nfs_ok)
		goto out;
	nfsd3_sattr3_to_iattr(rqstp, iattrs, &argp->xdrgen.attributes);

	fh_init(fhp, NFS3_FHSIZE);
	iattrs->ia_valid &= ~ATTR_SIZE;
	resp->xdrgen.status = nfsd_create(rqstp, dirfhp, (char *)where->name.data,
					  where->name.len, &nattrs, S_IFDIR,
					  0, fhp);

out:
	if (resp->xdrgen.status == nfs_ok) {
		struct MKDIR3resok *resok = &resp->xdrgen.u.resok;

		nfsd3_fill_post_op_fh3(&resok->obj, fhp, resp->fh_data);
		nfsd3_fill_post_op_attr(rqstp, &resok->obj_attributes, fhp);
		nfsd3_fill_wcc_data(rqstp, &resok->dir_wcc, dirfhp);
	} else {
		struct MKDIR3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		nfsd3_fill_wcc_data(rqstp, &resfail->dir_wcc, dirfhp);
	}

	fh_put(fhp);
	fh_put(dirfhp);
	return rpc_success;
}

/**
 * nfsd3_proc_symlink - NFSv3 SYMLINK - Create a symbolic link
 * @rqstp: RPC transaction context
 *
 * Returns an RPC accept_stat value in network byte order.
 */
static __be32
nfsd3_proc_symlink(struct svc_rqst *rqstp)
{
	struct nfsd3_symlinkargs *argp = rqstp->rq_argp;
	struct symlinkdata3 *symlink = &argp->xdrgen.symlink;
	struct diropargs3 *where = &argp->xdrgen.where;
	struct nfsd3_symlinkres *resp = rqstp->rq_resp;
	struct iattr *iattrs = &argp->attrs;
	struct svc_fh *dirfhp = &argp->ffh;
	struct svc_fh *fhp = &resp->fh;
	struct nfsd_attrs nattrs = {
		.na_iattr	= iattrs,
	};
	struct kvec first;
	char *tname;

	fh_init(fhp, NFS3_FHSIZE);
	nfsd3_fh3_to_svc_fh(dirfhp, &where->dir);
	resp->xdrgen.status = nfsd3_check_filename(where->name.data,
						   where->name.len);
	if (resp->xdrgen.status != nfs_ok)
		goto out;
	nfsd3_sattr3_to_iattr(rqstp, iattrs, &symlink->symlink_attributes);
	if (symlink->symlink_data.len == 0) {
		resp->xdrgen.status = nfserr_inval;
		goto out;
	}
	if (symlink->symlink_data.len > NFS3_MAXPATHLEN) {
		resp->xdrgen.status = nfserr_nametoolong;
		goto out;
	}

	first.iov_base = symlink->symlink_data.data;
	first.iov_len = symlink->symlink_data.len;
	tname = svc_fill_symlink_pathname(rqstp, &first, NULL,
					  symlink->symlink_data.len);
	if (IS_ERR(tname)) {
		resp->xdrgen.status = nfserrno(PTR_ERR(tname));
		goto out;
	}
	resp->xdrgen.status = nfsd_symlink(rqstp, dirfhp,
					   (char *)where->name.data,
					   where->name.len, tname,
					   &nattrs, fhp);
	kfree(tname);

out:
	if (resp->xdrgen.status == nfs_ok) {
		struct SYMLINK3resok *resok = &resp->xdrgen.u.resok;

		nfsd3_fill_post_op_fh3(&resok->obj, fhp, resp->fh_data);
		nfsd3_fill_post_op_attr(rqstp, &resok->obj_attributes, fhp);
		nfsd3_fill_wcc_data(rqstp, &resok->dir_wcc, dirfhp);
	} else {
		struct SYMLINK3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		nfsd3_fill_wcc_data(rqstp, &resfail->dir_wcc, dirfhp);
	}

	fh_put(fhp);
	fh_put(dirfhp);
	return rpc_success;
}

/**
 * nfsd3_proc_mknod - NFSv3 MKNOD - Create a special device
 * @rqstp: RPC transaction context
 *
 * Returns an RPC accept_stat value in network byte order.
 */
static __be32
nfsd3_proc_mknod(struct svc_rqst *rqstp)
{
	struct nfsd3_mknodargs *argp = rqstp->rq_argp;
	struct diropargs3 *where = &argp->xdrgen.where;
	struct mknoddata3 *what = &argp->xdrgen.what;
	struct nfsd3_mknodres *resp = rqstp->rq_resp;
	struct iattr *iattrs = &argp->attrs;
	struct svc_fh *dirfhp = &argp->fh;
	struct svc_fh *fhp = &resp->fh;
	struct nfsd_attrs nattrs = {
		.na_iattr	= iattrs,
	};
	dev_t rdev = 0;

	fh_init(fhp, NFS3_FHSIZE);
	nfsd3_fh3_to_svc_fh(dirfhp, &where->dir);
	resp->xdrgen.status = nfsd3_check_filename(where->name.data,
						   where->name.len);
	if (resp->xdrgen.status != nfs_ok)
		goto out;
	memset(iattrs, 0, sizeof(*iattrs));
	switch (what->type) {
	case NF3CHR:
	case NF3BLK:
		rdev = MKDEV(what->u.device.spec.specdata1,
			     what->u.device.spec.specdata2);
		if (MAJOR(rdev) != what->u.device.spec.specdata1 ||
		    MINOR(rdev) != what->u.device.spec.specdata2) {
			resp->xdrgen.status = nfserr_inval;
			goto out;
		}
		nfsd3_sattr3_to_iattr(rqstp, iattrs,
				      &what->u.device.dev_attributes);
		break;
	case NF3SOCK:
	case NF3FIFO:
		nfsd3_sattr3_to_iattr(rqstp, iattrs,
				      &what->u.pipe_attributes);
		break;
	default:
		resp->xdrgen.status = nfserr_badtype;
		goto out;
	}

	resp->xdrgen.status = nfsd_create(rqstp, dirfhp,
					  (char *)where->name.data,
					  where->name.len, &nattrs,
					  nfsd3_ftype3_to_mode(what->type),
					  rdev, fhp);

out:
	if (resp->xdrgen.status == nfs_ok) {
		struct MKNOD3resok *resok = &resp->xdrgen.u.resok;

		nfsd3_fill_post_op_fh3(&resok->obj, fhp, resp->fh_data);
		nfsd3_fill_post_op_attr(rqstp, &resok->obj_attributes, fhp);
		nfsd3_fill_wcc_data(rqstp, &resok->dir_wcc, dirfhp);
	} else {
		struct MKNOD3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		nfsd3_fill_wcc_data(rqstp, &resfail->dir_wcc, dirfhp);
	}

	fh_put(fhp);
	fh_put(dirfhp);
	return rpc_success;
}

/**
 * nfsd3_proc_remove - NFSv3 REMOVE - Remove a file
 * @rqstp: RPC transaction context
 *
 * Returns an RPC accept_stat value in network byte order.
 */
static __be32
nfsd3_proc_remove(struct svc_rqst *rqstp)
{
	struct nfsd3_removeargs *argp = rqstp->rq_argp;
	struct diropargs3 *object = &argp->xdrgen.object;
	struct nfsd3_removeres *resp = rqstp->rq_resp;
	struct svc_fh *fhp = &argp->fh;

	nfsd3_fh3_to_svc_fh(fhp, &object->dir);
	resp->xdrgen.status = nfsd3_check_filename(object->name.data,
						   object->name.len);
	if (resp->xdrgen.status != nfs_ok)
		goto out;

	resp->xdrgen.status = nfsd_unlink(rqstp, fhp, -S_IFDIR,
					  (char *)object->name.data,
					  object->name.len);

out:
	if (resp->xdrgen.status == nfs_ok) {
		struct REMOVE3resok *resok = &resp->xdrgen.u.resok;

		nfsd3_fill_wcc_data(rqstp, &resok->dir_wcc, fhp);
	} else {
		struct REMOVE3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		nfsd3_fill_wcc_data(rqstp, &resfail->dir_wcc, fhp);
	}

	fh_put(fhp);
	return rpc_success;
}

/**
 * nfsd3_proc_rmdir - NFSv3 RMDIR - Remove a directory
 * @rqstp: RPC transaction context
 *
 * Returns an RPC accept_stat value in network byte order.
 */
static __be32
nfsd3_proc_rmdir(struct svc_rqst *rqstp)
{
	struct nfsd3_rmdirargs *argp = rqstp->rq_argp;
	struct diropargs3 *object = &argp->xdrgen.object;
	struct nfsd3_rmdirres *resp = rqstp->rq_resp;
	struct svc_fh *fhp = &argp->fh;

	nfsd3_fh3_to_svc_fh(fhp, &object->dir);
	resp->xdrgen.status = nfsd3_check_filename(object->name.data,
						   object->name.len);
	if (resp->xdrgen.status != nfs_ok)
		goto out;

	resp->xdrgen.status = nfsd_unlink(rqstp, fhp, S_IFDIR,
					  (char *)object->name.data,
					  object->name.len);

out:
	if (resp->xdrgen.status == nfs_ok) {
		struct RMDIR3resok *resok = &resp->xdrgen.u.resok;

		nfsd3_fill_wcc_data(rqstp, &resok->dir_wcc, fhp);
	} else {
		struct RMDIR3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		nfsd3_fill_wcc_data(rqstp, &resfail->dir_wcc, fhp);
	}

	fh_put(fhp);
	return rpc_success;
}

/**
 * nfsd3_proc_rename - NFSv3 RENAME - Rename a file or directory
 * @rqstp: RPC transaction context
 *
 * Returns an RPC accept_stat value in network byte order.
 */
static __be32
nfsd3_proc_rename(struct svc_rqst *rqstp)
{
	struct nfsd3_renameargs *argp = rqstp->rq_argp;
	struct nfsd3_renameres *resp = rqstp->rq_resp;
	struct diropargs3 *from = &argp->xdrgen.from;
	struct diropargs3 *to = &argp->xdrgen.to;
	struct svc_fh *ffhp = &argp->ffh;
	struct svc_fh *tfhp = &argp->tfh;

	nfsd3_fh3_to_svc_fh(ffhp, &from->dir);
	nfsd3_fh3_to_svc_fh(tfhp, &to->dir);
	resp->xdrgen.status = nfsd3_check_filename(from->name.data,
						   from->name.len);
	if (resp->xdrgen.status != nfs_ok)
		goto out;
	resp->xdrgen.status = nfsd3_check_filename(to->name.data,
						   to->name.len);
	if (resp->xdrgen.status != nfs_ok)
		goto out;

	resp->xdrgen.status = nfsd_rename(rqstp, ffhp, (char *)from->name.data,
					  from->name.len, tfhp,
					  (char *)to->name.data,
					  to->name.len);

out:
	if (resp->xdrgen.status == nfs_ok) {
		struct RENAME3resok *resok = &resp->xdrgen.u.resok;

		nfsd3_fill_wcc_data(rqstp, &resok->fromdir_wcc, ffhp);
		nfsd3_fill_wcc_data(rqstp, &resok->todir_wcc, tfhp);
	} else {
		struct RENAME3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		nfsd3_fill_wcc_data(rqstp, &resfail->fromdir_wcc, ffhp);
		nfsd3_fill_wcc_data(rqstp, &resfail->todir_wcc, tfhp);
	}

	fh_put(ffhp);
	fh_put(tfhp);
	return rpc_success;
}

/**
 * nfsd3_proc_link - NFSv3 LINK - Create Link to an object
 * @rqstp: RPC transaction context
 *
 * Returns an RPC accept_stat value in network byte order.
 */
static __be32
nfsd3_proc_link(struct svc_rqst *rqstp)
{
	struct nfsd3_linkargs *argp = rqstp->rq_argp;
	struct diropargs3 *link = &argp->xdrgen.link;
	struct nfsd3_linkres *resp = rqstp->rq_resp;
	struct svc_fh *ffhp = &argp->ffh;
	struct svc_fh *tfhp = &argp->tfh;

	nfsd3_fh3_to_svc_fh(ffhp, &argp->xdrgen.file);
	nfsd3_fh3_to_svc_fh(tfhp, &link->dir);
	resp->xdrgen.status = nfsd3_check_filename(link->name.data,
						   link->name.len);
	if (resp->xdrgen.status != nfs_ok)
		goto out;

	resp->xdrgen.status = nfsd_link(rqstp, tfhp, (char *)link->name.data,
					link->name.len, ffhp);

out:
	if (resp->xdrgen.status == nfs_ok) {
		struct LINK3resok *resok = &resp->xdrgen.u.resok;

		nfsd3_fill_post_op_attr(rqstp, &resok->file_attributes, ffhp);
		nfsd3_fill_wcc_data(rqstp, &resok->linkdir_wcc, tfhp);
	} else {
		struct LINK3resfail *resfail = &resp->xdrgen.u.resfail;

		resp->xdrgen.status = nfsd3_map_status(resp->xdrgen.status);
		nfsd3_fill_post_op_attr(rqstp, &resfail->file_attributes, ffhp);
		nfsd3_fill_wcc_data(rqstp, &resfail->linkdir_wcc, tfhp);
	}

	fh_put(ffhp);
	fh_put(tfhp);
	return rpc_success;
}

static void nfsd3_init_dirlist_pages(struct svc_rqst *rqstp,
				     struct nfsd3_readdirres *resp,
				     u32 count)
{
	struct xdr_buf *buf = &resp->dirlist;
	struct xdr_stream *xdr = &resp->xdr;
	unsigned int sendbuf = min_t(unsigned int, rqstp->rq_res.buflen,
				     svc_max_payload(rqstp));

	memset(buf, 0, sizeof(*buf));

	/* Reserve room for the NULL ptr & eof flag (-2 words) */
	buf->buflen = clamp(count, (u32)(XDR_UNIT * 2), sendbuf);
	buf->buflen -= XDR_UNIT * 2;
	buf->pages = rqstp->rq_next_page;
	rqstp->rq_next_page += (buf->buflen + PAGE_SIZE - 1) >> PAGE_SHIFT;

	xdr_init_encode_pages(xdr, buf);
}

/*
 * Read a portion of a directory.
 */
static __be32
nfsd3_proc_readdir(struct svc_rqst *rqstp)
{
	struct nfsd3_readdirargs *argp = rqstp->rq_argp;
	struct nfsd3_readdirres  *resp = rqstp->rq_resp;
	loff_t		offset;

	trace_nfsd_vfs_readdir(rqstp, &argp->fh, argp->count, argp->cookie);

	nfsd3_init_dirlist_pages(rqstp, resp, argp->count);

	fh_copy(&resp->fh, &argp->fh);
	resp->common.err = nfs_ok;
	resp->cookie_offset = 0;
	resp->rqstp = rqstp;
	offset = argp->cookie;
	resp->status = nfsd_readdir(rqstp, &resp->fh, &offset,
				    &resp->common, nfs3svc_encode_entry3);
	memcpy(resp->verf, argp->verf, 8);
	nfs3svc_encode_cookie3(resp, offset);

	/* Recycle only pages that were part of the reply */
	rqstp->rq_next_page = resp->xdr.page_ptr + 1;

	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Read a portion of a directory, including file handles and attrs.
 * For now, we choose to ignore the dircount parameter.
 */
static __be32
nfsd3_proc_readdirplus(struct svc_rqst *rqstp)
{
	struct nfsd3_readdirargs *argp = rqstp->rq_argp;
	struct nfsd3_readdirres  *resp = rqstp->rq_resp;
	loff_t	offset;

	trace_nfsd_vfs_readdir(rqstp, &argp->fh, argp->count, argp->cookie);

	nfsd3_init_dirlist_pages(rqstp, resp, argp->count);

	fh_copy(&resp->fh, &argp->fh);
	resp->common.err = nfs_ok;
	resp->cookie_offset = 0;
	resp->rqstp = rqstp;
	offset = argp->cookie;

	resp->status = fh_verify(rqstp, &resp->fh, S_IFDIR, NFSD_MAY_NOP);
	if (resp->status != nfs_ok)
		goto out;

	if (resp->fh.fh_export->ex_flags & NFSEXP_NOREADDIRPLUS) {
		resp->status = nfserr_notsupp;
		goto out;
	}

	resp->status = nfsd_readdir(rqstp, &resp->fh, &offset,
				    &resp->common, nfs3svc_encode_entryplus3);
	memcpy(resp->verf, argp->verf, 8);
	nfs3svc_encode_cookie3(resp, offset);

	/* Recycle only pages that were part of the reply */
	rqstp->rq_next_page = resp->xdr.page_ptr + 1;

out:
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Get file system stats
 */
static __be32
nfsd3_proc_fsstat(struct svc_rqst *rqstp)
{
	struct nfsd_fhandle *argp = rqstp->rq_argp;
	struct nfsd3_fsstatres *resp = rqstp->rq_resp;

	resp->status = nfsd_statfs(rqstp, &argp->fh, &resp->stats, 0);
	fh_put(&argp->fh);
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Get file system info
 */
static __be32
nfsd3_proc_fsinfo(struct svc_rqst *rqstp)
{
	struct nfsd_fhandle *argp = rqstp->rq_argp;
	struct nfsd3_fsinfores *resp = rqstp->rq_resp;
	u32	max_blocksize = svc_max_payload(rqstp);

	dprintk("nfsd: FSINFO(3)   %s\n",
				SVCFH_fmt(&argp->fh));

	resp->f_rtmax  = max_blocksize;
	resp->f_rtpref = max_blocksize;
	resp->f_rtmult = PAGE_SIZE;
	resp->f_wtmax  = max_blocksize;
	resp->f_wtpref = max_blocksize;
	resp->f_wtmult = PAGE_SIZE;
	resp->f_dtpref = max_blocksize;
	resp->f_maxfilesize = ~(u32) 0;
	resp->f_properties = NFS3_FSF_DEFAULT;

	resp->status = fh_verify(rqstp, &argp->fh, 0,
				 NFSD_MAY_NOP | NFSD_MAY_BYPASS_GSS_ON_ROOT);

	/* Check special features of the file system. May request
	 * different read/write sizes for file systems known to have
	 * problems with large blocks */
	if (resp->status == nfs_ok) {
		struct super_block *sb = argp->fh.fh_dentry->d_sb;

		/* Note that we don't care for remote fs's here */
		if (sb->s_magic == MSDOS_SUPER_MAGIC) {
			resp->f_properties = NFS3_FSF_BILLYBOY;
		}
		resp->f_maxfilesize = sb->s_maxbytes;
	}

	fh_put(&argp->fh);
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Get pathconf info for the specified file
 */
static __be32
nfsd3_proc_pathconf(struct svc_rqst *rqstp)
{
	struct nfsd_fhandle *argp = rqstp->rq_argp;
	struct nfsd3_pathconfres *resp = rqstp->rq_resp;

	dprintk("nfsd: PATHCONF(3) %s\n",
				SVCFH_fmt(&argp->fh));

	/* Set default pathconf */
	resp->p_link_max = 255;		/* at least */
	resp->p_name_max = 255;		/* at least */
	resp->p_no_trunc = 0;
	resp->p_chown_restricted = 1;
	resp->p_case_insensitive = 0;
	resp->p_case_preserving = 1;

	resp->status = fh_verify(rqstp, &argp->fh, 0, NFSD_MAY_NOP);

	if (resp->status == nfs_ok) {
		struct super_block *sb = argp->fh.fh_dentry->d_sb;

		/* Note that we don't care for remote fs's here */
		switch (sb->s_magic) {
		case EXT2_SUPER_MAGIC:
			resp->p_link_max = EXT2_LINK_MAX;
			resp->p_name_max = EXT2_NAME_LEN;
			break;
		case MSDOS_SUPER_MAGIC:
			resp->p_case_insensitive = 1;
			resp->p_case_preserving  = 0;
			break;
		}
	}

	fh_put(&argp->fh);
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Commit a file (range) to stable storage.
 */
static __be32
nfsd3_proc_commit(struct svc_rqst *rqstp)
{
	struct nfsd3_commitargs *argp = rqstp->rq_argp;
	struct nfsd3_commitres *resp = rqstp->rq_resp;
	struct nfsd_file *nf;

	dprintk("nfsd: COMMIT(3)   %s %u@%Lu\n",
				SVCFH_fmt(&argp->fh),
				argp->count,
				(unsigned long long) argp->offset);

	fh_copy(&resp->fh, &argp->fh);
	resp->status = nfsd_file_acquire_gc(rqstp, &resp->fh, NFSD_MAY_WRITE |
					    NFSD_MAY_NOT_BREAK_LEASE, &nf);
	if (resp->status)
		goto out;
	resp->status = nfsd_commit(rqstp, &resp->fh, nf, argp->offset,
				   argp->count, resp->verf);
	nfsd_file_put(nf);
out:
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}


/*
 * NFSv3 Server procedures.
 * Only the results of non-idempotent operations are cached.
 */
#define nfsd3_readdirplusargs		nfsd3_readdirargs
#define nfsd3_fhandleargs		nfsd_fhandle

#define ST 1		/* status*/
#define AT 21		/* attributes */
#define pAT (1+AT)	/* post attributes - conditional */
#define WC (7+pAT)	/* WCC attributes */

static const struct svc_procedure nfsd_procedures3[22] = {
	[NFSPROC3_NULL] = {
		.pc_func = nfsd3_proc_null,
		.pc_decode = nfs_svc_decode_void,
		.pc_encode = nfs_svc_encode_void,
		.pc_argsize = 0,
		.pc_argzero = 0,
		.pc_ressize = 0,
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = 0,
		.pc_name = "NULL",
	},
	[NFSPROC3_GETATTR] = {
		.pc_func = nfsd3_proc_getattr,
		.pc_decode = nfs_svc_decode_GETATTR3args,
		.pc_encode = nfs_svc_encode_GETATTR3res,
		.pc_argsize = sizeof(struct nfsd3_getattrargs),
		.pc_argzero = 0,
		.pc_ressize = sizeof(struct nfsd3_getattrres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = NFS3_GETATTR3res_sz,
		.pc_name = "GETATTR",
	},
	[NFSPROC3_SETATTR] = {
		.pc_func = nfsd3_proc_setattr,
		.pc_decode = nfs_svc_decode_SETATTR3args,
		.pc_encode = nfs_svc_encode_SETATTR3res,
		.pc_argsize = sizeof(struct nfsd3_setattrargs),
		.pc_argzero = 0,
		.pc_ressize = sizeof(struct nfsd3_setattrres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = NFS3_SETATTR3res_sz,
		.pc_name = "SETATTR",
	},
	[NFSPROC3_LOOKUP] = {
		.pc_func = nfsd3_proc_lookup,
		.pc_decode = nfs_svc_decode_LOOKUP3args,
		.pc_encode = nfs_svc_encode_LOOKUP3res,
		.pc_argsize = sizeof(struct nfsd3_lookupargs),
		.pc_argzero = 0,
		.pc_ressize = sizeof(struct nfsd3_lookupres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = NFS3_LOOKUP3res_sz,
		.pc_name = "LOOKUP",
	},
	[NFSPROC3_ACCESS] = {
		.pc_func = nfsd3_proc_access,
		.pc_decode = nfs_svc_decode_ACCESS3args,
		.pc_encode = nfs_svc_encode_ACCESS3res,
		.pc_argsize = sizeof(struct nfsd3_accessargs),
		.pc_argzero = 0,
		.pc_ressize = sizeof(struct nfsd3_accessres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = NFS3_ACCESS3res_sz,
		.pc_name = "ACCESS",
	},
	[NFSPROC3_READLINK] = {
		.pc_func = nfsd3_proc_readlink,
		.pc_decode = nfs_svc_decode_READLINK3args,
		.pc_encode = nfs_svc_encode_readlink3res,
		.pc_argsize = sizeof(struct nfsd3_readlinkargs),
		.pc_argzero = 0,
		.pc_ressize = sizeof(struct nfsd3_readlinkres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = NFS3_READLINK3res_sz,
		.pc_name = "READLINK",
	},
	[NFSPROC3_READ] = {
		.pc_func = nfsd3_proc_read,
		.pc_decode = nfs_svc_decode_READ3args,
		.pc_encode = nfs_svc_encode_read3res,
		.pc_argsize = sizeof(struct nfsd3_readargs),
		.pc_argzero = 0,
		.pc_ressize = sizeof(struct nfsd3_readres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = NFS3_READ3res_sz,
		.pc_name = "READ",
	},
	[NFSPROC3_WRITE] = {
		.pc_func = nfsd3_proc_write,
		.pc_decode = nfs_svc_decode_write3arg,
		.pc_encode = nfs_svc_encode_WRITE3res,
		.pc_argsize = sizeof(struct nfsd3_writeargs),
		.pc_argzero = 0,
		.pc_ressize = sizeof(struct nfsd3_writeres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = NFS3_WRITE3res_sz,
		.pc_name = "WRITE",
	},
	[NFSPROC3_CREATE] = {
		.pc_func = nfsd3_proc_create,
		.pc_decode = nfs_svc_decode_CREATE3args,
		.pc_encode = nfs_svc_encode_CREATE3res,
		.pc_argsize = sizeof(struct nfsd3_createargs),
		.pc_argzero = 0,
		.pc_ressize = sizeof(struct nfsd3_createres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = NFS3_CREATE3res_sz,
		.pc_name = "CREATE",
	},
	[NFSPROC3_MKDIR] = {
		.pc_func = nfsd3_proc_mkdir,
		.pc_decode = nfs_svc_decode_MKDIR3args,
		.pc_encode = nfs_svc_encode_MKDIR3res,
		.pc_argsize = sizeof(struct nfsd3_mkdirargs),
		.pc_argzero = 0,
		.pc_ressize = sizeof(struct nfsd3_mkdirres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = NFS3_MKDIR3res_sz,
		.pc_name = "MKDIR",
	},
	[NFSPROC3_SYMLINK] = {
		.pc_func = nfsd3_proc_symlink,
		.pc_decode = nfs_svc_decode_SYMLINK3args,
		.pc_encode = nfs_svc_encode_SYMLINK3res,
		.pc_argsize = sizeof(struct nfsd3_symlinkargs),
		.pc_argzero = 0,
		.pc_ressize = sizeof(struct nfsd3_symlinkres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = NFS3_SYMLINK3res_sz,
		.pc_name = "SYMLINK",
	},
	[NFSPROC3_MKNOD] = {
		.pc_func = nfsd3_proc_mknod,
		.pc_decode = nfs_svc_decode_MKNOD3args,
		.pc_encode = nfs_svc_encode_MKNOD3res,
		.pc_argsize = sizeof(struct nfsd3_mknodargs),
		.pc_argzero = 0,
		.pc_ressize = sizeof(struct nfsd3_mknodres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = NFS3_MKNOD3res_sz,
		.pc_name = "MKNOD",
	},
	[NFSPROC3_REMOVE] = {
		.pc_func = nfsd3_proc_remove,
		.pc_decode = nfs_svc_decode_REMOVE3args,
		.pc_encode = nfs_svc_encode_REMOVE3res,
		.pc_argsize = sizeof(struct nfsd3_removeargs),
		.pc_argzero = 0,
		.pc_ressize = sizeof(struct nfsd3_removeres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = NFS3_REMOVE3res_sz,
		.pc_name = "REMOVE",
	},
	[NFSPROC3_RMDIR] = {
		.pc_func = nfsd3_proc_rmdir,
		.pc_decode = nfs_svc_decode_RMDIR3args,
		.pc_encode = nfs_svc_encode_RMDIR3res,
		.pc_argsize = sizeof(struct nfsd3_rmdirargs),
		.pc_argzero = 0,
		.pc_ressize = sizeof(struct nfsd3_rmdirres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = NFS3_RMDIR3res_sz,
		.pc_name = "RMDIR",
	},
	[NFSPROC3_RENAME] = {
		.pc_func = nfsd3_proc_rename,
		.pc_decode = nfs_svc_decode_RENAME3args,
		.pc_encode = nfs_svc_encode_RENAME3res,
		.pc_argsize = sizeof(struct nfsd3_renameargs),
		.pc_argzero = 0,
		.pc_ressize = sizeof(struct nfsd3_renameres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = NFS3_RENAME3res_sz,
		.pc_name = "RENAME",
	},
	[NFSPROC3_LINK] = {
		.pc_func = nfsd3_proc_link,
		.pc_decode = nfs_svc_decode_LINK3args,
		.pc_encode = nfs_svc_encode_LINK3res,
		.pc_argsize = sizeof(struct nfsd3_linkargs),
		.pc_argzero = 0,
		.pc_ressize = sizeof(struct nfsd3_linkres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = NFS3_LINK3res_sz,
		.pc_name = "LINK",
	},
	[NFSPROC3_READDIR] = {
		.pc_func = nfsd3_proc_readdir,
		.pc_decode = nfs3svc_decode_readdirargs,
		.pc_encode = nfs3svc_encode_readdirres,
		.pc_release = nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_readdirargs),
		.pc_argzero = sizeof(struct nfsd3_readdirargs),
		.pc_ressize = sizeof(struct nfsd3_readdirres),
		.pc_cachetype = RC_NOCACHE,
		.pc_name = "READDIR",
	},
	[NFSPROC3_READDIRPLUS] = {
		.pc_func = nfsd3_proc_readdirplus,
		.pc_decode = nfs3svc_decode_readdirplusargs,
		.pc_encode = nfs3svc_encode_readdirres,
		.pc_release = nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_readdirplusargs),
		.pc_argzero = sizeof(struct nfsd3_readdirplusargs),
		.pc_ressize = sizeof(struct nfsd3_readdirres),
		.pc_cachetype = RC_NOCACHE,
		.pc_name = "READDIRPLUS",
	},
	[NFSPROC3_FSSTAT] = {
		.pc_func = nfsd3_proc_fsstat,
		.pc_decode = nfs3svc_decode_fhandleargs,
		.pc_encode = nfs3svc_encode_fsstatres,
		.pc_argsize = sizeof(struct nfsd3_fhandleargs),
		.pc_argzero = sizeof(struct nfsd3_fhandleargs),
		.pc_ressize = sizeof(struct nfsd3_fsstatres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+pAT+2*6+1,
		.pc_name = "FSSTAT",
	},
	[NFSPROC3_FSINFO] = {
		.pc_func = nfsd3_proc_fsinfo,
		.pc_decode = nfs3svc_decode_fhandleargs,
		.pc_encode = nfs3svc_encode_fsinfores,
		.pc_argsize = sizeof(struct nfsd3_fhandleargs),
		.pc_argzero = sizeof(struct nfsd3_fhandleargs),
		.pc_ressize = sizeof(struct nfsd3_fsinfores),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+pAT+12,
		.pc_name = "FSINFO",
	},
	[NFSPROC3_PATHCONF] = {
		.pc_func = nfsd3_proc_pathconf,
		.pc_decode = nfs3svc_decode_fhandleargs,
		.pc_encode = nfs3svc_encode_pathconfres,
		.pc_argsize = sizeof(struct nfsd3_fhandleargs),
		.pc_argzero = sizeof(struct nfsd3_fhandleargs),
		.pc_ressize = sizeof(struct nfsd3_pathconfres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+pAT+6,
		.pc_name = "PATHCONF",
	},
	[NFSPROC3_COMMIT] = {
		.pc_func = nfsd3_proc_commit,
		.pc_decode = nfs3svc_decode_commitargs,
		.pc_encode = nfs3svc_encode_commitres,
		.pc_release = nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_commitargs),
		.pc_argzero = sizeof(struct nfsd3_commitargs),
		.pc_ressize = sizeof(struct nfsd3_commitres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+WC+2,
		.pc_name = "COMMIT",
	},
};

static DEFINE_PER_CPU_ALIGNED(unsigned long,
			      nfsd_count3[ARRAY_SIZE(nfsd_procedures3)]);
const struct svc_version nfsd_version3 = {
	.vs_vers	= 3,
	.vs_nproc	= ARRAY_SIZE(nfsd_procedures3),
	.vs_proc	= nfsd_procedures3,
	.vs_dispatch	= nfsd_dispatch,
	.vs_count	= nfsd_count3,
	.vs_xdrsize	= NFS3_SVC_XDRSIZE,
};
