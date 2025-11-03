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

static int	nfs3_ftypes[] = {
	0,			/* NF3NON */
	S_IFREG,		/* NF3REG */
	S_IFDIR,		/* NF3DIR */
	S_IFBLK,		/* NF3BLK */
	S_IFCHR,		/* NF3CHR */
	S_IFLNK,		/* NF3LNK */
	S_IFSOCK,		/* NF3SOCK */
	S_IFIFO,		/* NF3FIFO */
};

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

/*
 * Write data to a file
 */
static __be32
nfsd3_proc_write(struct svc_rqst *rqstp)
{
	struct nfsd3_writeargs *argp = rqstp->rq_argp;
	struct nfsd3_writeres *resp = rqstp->rq_resp;
	unsigned long cnt = argp->len;

	dprintk("nfsd: WRITE(3)    %s %d bytes at %Lu%s\n",
				SVCFH_fmt(&argp->fh),
				argp->len,
				(unsigned long long) argp->offset,
				argp->stable ? " stable" : "");

	resp->status = nfserr_fbig;
	if (argp->offset > (u64)OFFSET_MAX ||
	    argp->offset + argp->len > (u64)OFFSET_MAX)
		return rpc_success;

	fh_copy(&resp->fh, &argp->fh);
	resp->committed = argp->stable;
	resp->status = nfsd_write(rqstp, &resp->fh, argp->offset,
				  &argp->payload, &cnt,
				  resp->committed, resp->verf);
	resp->count = cnt;
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Implement NFSv3's unchecked, guarded, and exclusive CREATE
 * semantics for regular files. Except for the created file,
 * this operation is stateless on the server.
 *
 * Upon return, caller must release @fhp and @resfhp.
 */
static __be32
nfsd3_create_file(struct svc_rqst *rqstp, struct svc_fh *fhp,
		  struct svc_fh *resfhp, struct nfsd3_createargs *argp)
{
	struct iattr *iap = &argp->attrs;
	struct dentry *parent, *child;
	struct nfsd_attrs attrs = {
		.na_iattr	= iap,
	};
	__u32 v_mtime, v_atime;
	struct inode *inode;
	__be32 status;
	int host_err;

	trace_nfsd_vfs_create(rqstp, fhp, S_IFREG, argp->name, argp->len);

	if (isdotent(argp->name, argp->len))
		return nfserr_exist;
	if (!(iap->ia_valid & ATTR_MODE))
		iap->ia_mode = 0;

	status = fh_verify(rqstp, fhp, S_IFDIR, NFSD_MAY_EXEC);
	if (status != nfs_ok)
		return status;

	parent = fhp->fh_dentry;
	inode = d_inode(parent);

	host_err = fh_want_write(fhp);
	if (host_err)
		return nfserrno(host_err);

	inode_lock_nested(inode, I_MUTEX_PARENT);

	child = lookup_one(&nop_mnt_idmap,
			   &QSTR_LEN(argp->name, argp->len),
			   parent);
	if (IS_ERR(child)) {
		status = nfserrno(PTR_ERR(child));
		goto out;
	}

	if (d_really_is_negative(child)) {
		status = fh_verify(rqstp, fhp, S_IFDIR, NFSD_MAY_CREATE);
		if (status != nfs_ok)
			goto out;
	}

	status = fh_compose(resfhp, fhp->fh_export, child, fhp);
	if (status != nfs_ok)
		goto out;

	v_mtime = 0;
	v_atime = 0;
	if (argp->createmode == EXCLUSIVE) {
		u32 *verifier = (u32 *)argp->verf;

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

		switch (argp->createmode) {
		case UNCHECKED:
			if (!d_is_reg(child))
				break;
			iap->ia_valid &= ATTR_SIZE;
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
		iap->ia_mode &= ~current_umask();

	status = fh_fill_pre_attrs(fhp);
	if (status != nfs_ok)
		goto out;
	host_err = vfs_create(&nop_mnt_idmap, inode, child, iap->ia_mode, true);
	if (host_err < 0) {
		status = nfserrno(host_err);
		goto out;
	}
	fh_fill_post_attrs(fhp);

	/* A newly created file already has a file size of zero. */
	if ((iap->ia_valid & ATTR_SIZE) && (iap->ia_size == 0))
		iap->ia_valid &= ~ATTR_SIZE;
	if (argp->createmode == EXCLUSIVE) {
		iap->ia_valid = ATTR_MTIME | ATTR_ATIME |
				ATTR_MTIME_SET | ATTR_ATIME_SET;
		iap->ia_mtime.tv_sec = v_mtime;
		iap->ia_atime.tv_sec = v_atime;
		iap->ia_mtime.tv_nsec = 0;
		iap->ia_atime.tv_nsec = 0;
	}

set_attr:
	status = nfsd_create_setattr(rqstp, fhp, resfhp, &attrs);

out:
	inode_unlock(inode);
	if (child && !IS_ERR(child))
		dput(child);
	fh_drop_write(fhp);
	return status;
}

static __be32
nfsd3_proc_create(struct svc_rqst *rqstp)
{
	struct nfsd3_createargs *argp = rqstp->rq_argp;
	struct nfsd3_diropres *resp = rqstp->rq_resp;
	svc_fh *dirfhp, *newfhp;

	dirfhp = fh_copy(&resp->dirfh, &argp->fh);
	newfhp = fh_init(&resp->fh, NFS3_FHSIZE);

	resp->status = nfsd3_create_file(rqstp, dirfhp, newfhp, argp);
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Make directory. This operation is not idempotent.
 */
static __be32
nfsd3_proc_mkdir(struct svc_rqst *rqstp)
{
	struct nfsd3_createargs *argp = rqstp->rq_argp;
	struct nfsd3_diropres *resp = rqstp->rq_resp;
	struct nfsd_attrs attrs = {
		.na_iattr	= &argp->attrs,
	};

	argp->attrs.ia_valid &= ~ATTR_SIZE;
	fh_copy(&resp->dirfh, &argp->fh);
	fh_init(&resp->fh, NFS3_FHSIZE);
	resp->status = nfsd_create(rqstp, &resp->dirfh, argp->name, argp->len,
				   &attrs, S_IFDIR, 0, &resp->fh);
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

static __be32
nfsd3_proc_symlink(struct svc_rqst *rqstp)
{
	struct nfsd3_symlinkargs *argp = rqstp->rq_argp;
	struct nfsd3_diropres *resp = rqstp->rq_resp;
	struct nfsd_attrs attrs = {
		.na_iattr	= &argp->attrs,
	};

	if (argp->tlen == 0) {
		resp->status = nfserr_inval;
		goto out;
	}
	if (argp->tlen > NFS3_MAXPATHLEN) {
		resp->status = nfserr_nametoolong;
		goto out;
	}

	argp->tname = svc_fill_symlink_pathname(rqstp, &argp->first,
						page_address(rqstp->rq_arg.pages[0]),
						argp->tlen);
	if (IS_ERR(argp->tname)) {
		resp->status = nfserrno(PTR_ERR(argp->tname));
		goto out;
	}

	fh_copy(&resp->dirfh, &argp->ffh);
	fh_init(&resp->fh, NFS3_FHSIZE);
	resp->status = nfsd_symlink(rqstp, &resp->dirfh, argp->fname,
				    argp->flen, argp->tname, &attrs, &resp->fh);
	kfree(argp->tname);
out:
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Make socket/fifo/device.
 */
static __be32
nfsd3_proc_mknod(struct svc_rqst *rqstp)
{
	struct nfsd3_mknodargs *argp = rqstp->rq_argp;
	struct nfsd3_diropres  *resp = rqstp->rq_resp;
	struct nfsd_attrs attrs = {
		.na_iattr	= &argp->attrs,
	};
	int type;
	dev_t	rdev = 0;

	fh_copy(&resp->dirfh, &argp->fh);
	fh_init(&resp->fh, NFS3_FHSIZE);

	if (argp->ftype == NF3CHR || argp->ftype == NF3BLK) {
		rdev = MKDEV(argp->major, argp->minor);
		if (MAJOR(rdev) != argp->major ||
		    MINOR(rdev) != argp->minor) {
			resp->status = nfserr_inval;
			goto out;
		}
	} else if (argp->ftype != NF3SOCK && argp->ftype != NF3FIFO) {
		resp->status = nfserr_badtype;
		goto out;
	}

	type = nfs3_ftypes[argp->ftype];
	resp->status = nfsd_create(rqstp, &resp->dirfh, argp->name, argp->len,
				   &attrs, type, rdev, &resp->fh);
out:
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Remove file/fifo/socket etc.
 */
static __be32
nfsd3_proc_remove(struct svc_rqst *rqstp)
{
	struct nfsd3_diropargs *argp = rqstp->rq_argp;
	struct nfsd3_attrstat *resp = rqstp->rq_resp;

	/* Unlink. -S_IFDIR means file must not be a directory */
	fh_copy(&resp->fh, &argp->fh);
	resp->status = nfsd_unlink(rqstp, &resp->fh, -S_IFDIR,
				   argp->name, argp->len);
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Remove a directory
 */
static __be32
nfsd3_proc_rmdir(struct svc_rqst *rqstp)
{
	struct nfsd3_diropargs *argp = rqstp->rq_argp;
	struct nfsd3_attrstat *resp = rqstp->rq_resp;

	fh_copy(&resp->fh, &argp->fh);
	resp->status = nfsd_unlink(rqstp, &resp->fh, S_IFDIR,
				   argp->name, argp->len);
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

static __be32
nfsd3_proc_rename(struct svc_rqst *rqstp)
{
	struct nfsd3_renameargs *argp = rqstp->rq_argp;
	struct nfsd3_renameres *resp = rqstp->rq_resp;

	fh_copy(&resp->ffh, &argp->ffh);
	fh_copy(&resp->tfh, &argp->tfh);
	resp->status = nfsd_rename(rqstp, &resp->ffh, argp->fname, argp->flen,
				   &resp->tfh, argp->tname, argp->tlen);
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

static __be32
nfsd3_proc_link(struct svc_rqst *rqstp)
{
	struct nfsd3_linkargs *argp = rqstp->rq_argp;
	struct nfsd3_linkres  *resp = rqstp->rq_resp;

	fh_copy(&resp->fh,  &argp->ffh);
	fh_copy(&resp->tfh, &argp->tfh);
	resp->status = nfsd_link(rqstp, &resp->tfh, argp->tname, argp->tlen,
				 &resp->fh);
	resp->status = nfsd3_map_status(resp->status);
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
#define nfs3svc_encode_wccstatres	nfs3svc_encode_wccstat
#define nfsd3_mkdirargs			nfsd3_createargs
#define nfsd3_readdirplusargs		nfsd3_readdirargs
#define nfsd3_fhandleargs		nfsd_fhandle
#define nfsd3_wccstatres		nfsd3_attrstat

#define ST 1		/* status*/
#define FH 17		/* filehandle with length */
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
		.pc_decode = nfs3svc_decode_writeargs,
		.pc_encode = nfs3svc_encode_writeres,
		.pc_release = nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_writeargs),
		.pc_argzero = sizeof(struct nfsd3_writeargs),
		.pc_ressize = sizeof(struct nfsd3_writeres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+WC+4,
		.pc_name = "WRITE",
	},
	[NFSPROC3_CREATE] = {
		.pc_func = nfsd3_proc_create,
		.pc_decode = nfs3svc_decode_createargs,
		.pc_encode = nfs3svc_encode_createres,
		.pc_release = nfs3svc_release_fhandle2,
		.pc_argsize = sizeof(struct nfsd3_createargs),
		.pc_argzero = sizeof(struct nfsd3_createargs),
		.pc_ressize = sizeof(struct nfsd3_diropres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+(1+FH+pAT)+WC,
		.pc_name = "CREATE",
	},
	[NFSPROC3_MKDIR] = {
		.pc_func = nfsd3_proc_mkdir,
		.pc_decode = nfs3svc_decode_mkdirargs,
		.pc_encode = nfs3svc_encode_createres,
		.pc_release = nfs3svc_release_fhandle2,
		.pc_argsize = sizeof(struct nfsd3_mkdirargs),
		.pc_argzero = sizeof(struct nfsd3_mkdirargs),
		.pc_ressize = sizeof(struct nfsd3_diropres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+(1+FH+pAT)+WC,
		.pc_name = "MKDIR",
	},
	[NFSPROC3_SYMLINK] = {
		.pc_func = nfsd3_proc_symlink,
		.pc_decode = nfs3svc_decode_symlinkargs,
		.pc_encode = nfs3svc_encode_createres,
		.pc_release = nfs3svc_release_fhandle2,
		.pc_argsize = sizeof(struct nfsd3_symlinkargs),
		.pc_argzero = sizeof(struct nfsd3_symlinkargs),
		.pc_ressize = sizeof(struct nfsd3_diropres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+(1+FH+pAT)+WC,
		.pc_name = "SYMLINK",
	},
	[NFSPROC3_MKNOD] = {
		.pc_func = nfsd3_proc_mknod,
		.pc_decode = nfs3svc_decode_mknodargs,
		.pc_encode = nfs3svc_encode_createres,
		.pc_release = nfs3svc_release_fhandle2,
		.pc_argsize = sizeof(struct nfsd3_mknodargs),
		.pc_argzero = sizeof(struct nfsd3_mknodargs),
		.pc_ressize = sizeof(struct nfsd3_diropres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+(1+FH+pAT)+WC,
		.pc_name = "MKNOD",
	},
	[NFSPROC3_REMOVE] = {
		.pc_func = nfsd3_proc_remove,
		.pc_decode = nfs3svc_decode_diropargs,
		.pc_encode = nfs3svc_encode_wccstatres,
		.pc_release = nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_diropargs),
		.pc_argzero = sizeof(struct nfsd3_diropargs),
		.pc_ressize = sizeof(struct nfsd3_wccstatres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+WC,
		.pc_name = "REMOVE",
	},
	[NFSPROC3_RMDIR] = {
		.pc_func = nfsd3_proc_rmdir,
		.pc_decode = nfs3svc_decode_diropargs,
		.pc_encode = nfs3svc_encode_wccstatres,
		.pc_release = nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_diropargs),
		.pc_argzero = sizeof(struct nfsd3_diropargs),
		.pc_ressize = sizeof(struct nfsd3_wccstatres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+WC,
		.pc_name = "RMDIR",
	},
	[NFSPROC3_RENAME] = {
		.pc_func = nfsd3_proc_rename,
		.pc_decode = nfs3svc_decode_renameargs,
		.pc_encode = nfs3svc_encode_renameres,
		.pc_release = nfs3svc_release_fhandle2,
		.pc_argsize = sizeof(struct nfsd3_renameargs),
		.pc_argzero = sizeof(struct nfsd3_renameargs),
		.pc_ressize = sizeof(struct nfsd3_renameres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+WC+WC,
		.pc_name = "RENAME",
	},
	[NFSPROC3_LINK] = {
		.pc_func = nfsd3_proc_link,
		.pc_decode = nfs3svc_decode_linkargs,
		.pc_encode = nfs3svc_encode_linkres,
		.pc_release = nfs3svc_release_fhandle2,
		.pc_argsize = sizeof(struct nfsd3_linkargs),
		.pc_argzero = sizeof(struct nfsd3_linkargs),
		.pc_ressize = sizeof(struct nfsd3_linkres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+pAT+WC,
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
