/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Tagsets
 *
 * Copyright (c) 2025, Oracle and/or its affiliates.
 * Author: Chuck Lever <chuck.lever@oracle.com>
 *
 * A tagset is an unordered set of strings. See
 * Documentation/core-api/tagset.rst for how to use tagsets.
 */

#ifndef _LINUX_TAGSET_H
#define _LINUX_TAGSET_H

#include <linux/xarray.h>

struct tagset {
	struct xarray		ts_xa;
};

/**
 * tagset_for_each - Iterate over items in a tagset
 * @set: An initialized tagset containing zero or more items
 * @index: Index of the @tag.
 * @tag: Tag retrieved from the tagset.
 *
 * During the iteration, @tag will have a pointer to the tag stored
 * in the tagset.  You may modify @index during the iteration if you
 * want to skip or reprocess indices. It is safe to modify the set
 * during the iteration. At the end of the iteration, @tag will be
 * set to NULL.
 */
#define tagset_for_each(set, index, tag) \
	xa_for_each(&set->ts_xa, index, tag)

/**
 * tagset_init - Initialize an empty tagset
 * @set: tagset to be initialized
 */
static inline void tagset_init(struct tagset *set)
{
	xa_init_flags(&set->ts_xa, XA_FLAGS_ALLOC);
}

/**
 * tagset_is_empty - Determine if a tagset contains any tags
 * @set: An initialized tagset to be checked
 *
 * Return values:
 *    %true: if @set is empty
 *    %false: if @set contains one or more tags
 */
static inline bool tagset_is_empty(const struct tagset *set)
{
	return xa_empty(&set->ts_xa);
}

/**
 * tagset_is_member - Check if a tag is already a member of a tagset
 * @set: An initialized tagset to be checked
 * @tag: tag string to search for
 *
 * Return values:
 *   %true: if @tag is a member of @set
 *   %false: if @tag is not a member of @set
 */
static inline bool tagset_is_member(struct tagset *set, const char *tag)
{
	unsigned long index;
	bool result = false;
	char *entry;

	rcu_read_lock();
	tagset_for_each(set, index, entry)
		if (strcmp(tag, entry) == 0) {
			result = true;
			break;
		}
	rcu_read_unlock();
	return result;
}

/**
 * tagset_add - Add a tag to a tagset
 * @set: An initialized tagset to be added to
 * @tag: tag string to be added to @set, in kmalloc'd memory
 * @gfp: Memory allocation flags
 *
 * On success, @tag is now owned by @set and will be freed by
 * tagset_release(set).
 *
 * TODO: Prevent adding tags that are already present in @set.
 *
 * Return values:
 *   %true: @tag is now a member of @set
 *   %false: @tag could not be added
 */
static inline bool tagset_add(struct tagset *set, char *tag, gfp_t gfp)
{
	int err;
	u32 id;

	err = xa_alloc(&set->ts_xa, &id, tag, xa_limit_32b, gfp);
	if (err)
		return false;
	return true;
}

/**
 * tagset_add_dup - Add a tag to a tagset
 * @set: An initialized tagset to be added to
 * @tag: tag string to be added to @set
 * @gfp: Memory allocation flags
 *
 * On success, @tag will have been copied into a kmalloc'd
 * buffer. The caller can release @tag immediately.
 *
 * TODO: Prevent adding tags that are already present in @set.
 *
 * Return values:
 *   %true: @tag is now a member of @set
 *   %false: @tag could not be added
 */
static inline bool
tagset_add_dup(struct tagset *set, const char *tag, gfp_t gfp)
{
	char *entry;
	int err;
	u32 id;

	entry = kstrdup(tag, gfp);
	if (!entry)
		return false;
	err = xa_alloc(&set->ts_xa, &id, entry, xa_limit_32b, gfp);
	if (err)
		return false;
	return true;
}

static inline void tagset_release(struct tagset *set)
{
	unsigned long index;
	char *entry;

	tagset_for_each(set, index, entry) {
		xa_erase(&set->ts_xa, index);
		kfree(entry);
	}
}

/**
 * tagset_destroy - Release tagset resources
 * @set: tagset to be destroyed
 */
static inline void tagset_destroy(struct tagset *set)
{
	tagset_release(set);
	xa_destroy(&set->ts_xa);
}

/**
 * tagset_copy - Duplicate tags to another tagset
 * @dest: tagset to be initialized and filled
 * @src: An initialized tagset to be copied from
 * @gfp: Memory allocation flags
 *
 * Any previous content in @dest will be lost.
 *
 * Return values:
 *   %true: All tags in @src were copied to @dest
 *   %false: A failure occurred; @dest is left empty
 */
static inline bool
tagset_copy(struct tagset *dest, struct tagset *src, gfp_t gfp)
{
	unsigned long index;
	char *entry;

	tagset_init(dest);
	rcu_read_lock();
	tagset_for_each(src, index, entry)
		if (!tagset_add(dest, entry, gfp)) {
			rcu_read_unlock();
			tagset_release(dest);
			return false;
		}
	rcu_read_unlock();
	return true;
}

/**
 * tagset_intersection - Report if there are common tags
 * @set1: An initialized tagset
 * @set2: Another initialized tagset
 *
 * Return values:
 *   %true: @set1 and @set2 have at least one common tag
 *   %false: @set1 and @set2 have no tags in common
 */
static inline bool
tagset_intersection(struct tagset *set1, struct tagset *set2)
{
	unsigned long index;
	bool result = false;
	char *entry;

	result = 0;
	rcu_read_lock();
	tagset_for_each(set1, index, entry)
		if (tagset_is_member(set2, entry)) {
			result = true;
			break;
		}
	rcu_read_unlock();
	return result;
}

#endif /* _LINUX_TAGSET_H */
