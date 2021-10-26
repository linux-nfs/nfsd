// SPDX-License-Identifier: GPL-2.0

#include <linux/crc32.h>
#include <linux/nfs.h>
#include <linux/lockd/nlm.h>
#include <linux/lockd/xdr.h>

#ifdef CONFIG_CRC32
static inline u32 nfs_fhandle_hash(const struct nfs_fh *fh)
{
	return ~crc32_le(0xFFFFFFFF, &fh->data[0], fh->size);
}

static inline u32 nfs_cookie_hash(const struct nlm_cookie *cookie)
{
	return ~crc32_le(0xFFFFFFFF, cookie->data, cookie->len);
}
#else
static inline u32 nfs_fhandle_hash(const struct nfs_fh *fh)
{
	return 0;
}

static inline u32 nfs_cookie_hash(const struct nlm_cookie *cookie)
{
	return 0;
}
#endif

#define CREATE_TRACE_POINTS
#include "xdrtrace.h"
